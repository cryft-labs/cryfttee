//! API handlers for /v1 endpoints

use axum::{
    extract::State,
    Json,
    http::StatusCode,
};
use serde::Serialize;
use serde_json::{json, Value};
use tracing::{info, error, warn};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use crate::wasm_api::staking::{
    BlsRegisterRequest, BlsRegisterResponse, BlsSignRequest, BlsSignResponse,
    TlsRegisterRequest, TlsRegisterResponse, TlsSignRequest, TlsSignResponse,
    StatusResponse, ModuleStatusEntry, Web3SignerStatus, WasmRuntimeStatus,
    parse_key_mode, mode_requires_public_key, mode_is_generation,
    KEY_MODE_VERIFY, KEY_MODE_GENERATE, KEY_MODE_PERSISTENT,
};
use crate::runtime::Dispatcher;
use crate::CRYFTTEE_VERSION;

/// Shared application state - re-imported from mod.rs
pub type AppState = super::AppState;

/// Error response structure
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub details: Option<String>,
}

/// BLS register endpoint
/// 
/// Modes:
/// - "verify": Verify that CryftGo's existing public key exists in Web3Signer
/// - "generate": Generate new key (only if CryftGo has no keys)
/// - "persistent": Alias for generate
/// - "ephemeral": Ephemeral key for testing
/// - "import": Import provided secret key
pub async fn bls_register(
    State(state): State<AppState>,
    Json(request): Json<BlsRegisterRequest>,
) -> Result<Json<BlsRegisterResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("BLS register request: mode={}", request.mode);

    let mode = parse_key_mode(&request.mode)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorResponse {
            error: "Invalid mode".to_string(),
            details: Some(e),
        })))?;

    // Handle verify mode: check that CryftGo's key exists in Web3Signer
    if mode == KEY_MODE_VERIFY {
        let pubkey = request.public_key.as_ref()
            .ok_or_else(|| (StatusCode::BAD_REQUEST, Json(ErrorResponse {
                error: "Missing public key".to_string(),
                details: Some("verify mode requires publicKey field containing the key from CryftGo's local store".to_string()),
            })))?;

        info!("Verifying BLS key exists in Web3Signer: {}...", &pubkey[..std::cmp::min(20, pubkey.len())]);

        let runtime_state = state.runtime_state.read().await;
        let web3signer_url = state.config.get_web3signer_url();

        // First check if Web3Signer is reachable
        if !runtime_state.web3signer_reachable {
            error!("Cannot verify key - Web3Signer not reachable");
            return Err((StatusCode::SERVICE_UNAVAILABLE, Json(ErrorResponse {
                error: "Web3Signer not reachable".to_string(),
                details: runtime_state.web3signer_last_error.clone(),
            })));
        }

        // Verify the key exists in Web3Signer
        runtime_state.verify_bls_pubkey_exists(&web3signer_url, pubkey).await
            .map_err(|e| {
                error!("BLS key verification failed: {}", e);
                (StatusCode::NOT_FOUND, Json(ErrorResponse {
                    error: "Key not found in Web3Signer".to_string(),
                    details: Some(format!(
                        "The BLS key {} from CryftGo's local store was not found in Web3Signer. \
                         This is a critical error - the key may have been lost or Web3Signer \
                         is misconfigured. Node cannot start safely. Error: {}",
                        pubkey, e
                    )),
                }))
            })?;

        info!("BLS key verified successfully in Web3Signer");

        // Return success - key exists, use the provided public key
        return Ok(Json(BlsRegisterResponse {
            key_handle: pubkey.clone(), // Use pubkey as handle for existing keys
            bls_pub_key_b64: BASE64.encode(hex::decode(pubkey.trim_start_matches("0x")).unwrap_or_default()),
            module_id: "bls_tls_signer_v1".to_string(),
            module_version: "1.0.0".to_string(),
        }));
    }

    // Handle generate/persistent mode: only allowed if no keys exist
    if mode_is_generation(mode) {
        // CryftGo should only request generation if it has no keys
        // Log this for audit purposes
        warn!("Key generation requested - CryftGo indicates no existing keys");
        
        // Optionally verify Web3Signer has no keys (extra safety)
        let runtime_state = state.runtime_state.read().await;
        if runtime_state.web3signer_reachable {
            let web3signer_url = state.config.get_web3signer_url();
            match runtime_state.fetch_bls_pubkeys(&web3signer_url).await {
                Ok(existing_keys) if !existing_keys.is_empty() => {
                    warn!(
                        "Generation requested but Web3Signer already has {} BLS keys: {:?}",
                        existing_keys.len(),
                        existing_keys.iter().map(|k| &k[..std::cmp::min(16, k.len())]).collect::<Vec<_>>()
                    );
                    // Don't fail - CryftGo may be initializing with a fresh local store
                    // but Web3Signer has keys from a previous run
                }
                Ok(_) => {
                    info!("Web3Signer has no existing BLS keys, generation is appropriate");
                }
                Err(e) => {
                    warn!("Could not check existing keys in Web3Signer: {}", e);
                }
            }
        }
    }

    // Proceed with key registration through Web3Signer
    let registry = state.registry.read().await;
    let web3signer_url = state.config.get_web3signer_url();
    let dispatcher = Dispatcher::with_web3signer(&registry, &web3signer_url, state.config.web3signer_timeout);

    let key_material = request.ephemeral_key_b64.as_ref()
        .map(|b64| BASE64.decode(b64))
        .transpose()
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorResponse {
            error: "Invalid key material".to_string(),
            details: Some(e.to_string()),
        })))?;

    let result = dispatcher.dispatch_bls_register(
        mode,
        key_material.as_deref(),
        request.module_id.as_deref(),
    ).await
    .map_err(|e| {
        error!("BLS register failed: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "BLS registration failed".to_string(),
            details: Some(e.to_string()),
        }))
    })?;

    Ok(Json(BlsRegisterResponse {
        key_handle: result.key_handle,
        bls_pub_key_b64: BASE64.encode(&result.public_key),
        module_id: result.module_id,
        module_version: result.module_version,
    }))
}

/// BLS sign endpoint
pub async fn bls_sign(
    State(state): State<AppState>,
    Json(request): Json<BlsSignRequest>,
) -> Result<Json<BlsSignResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("BLS sign request: handle={}", request.key_handle);

    let registry = state.registry.read().await;
    let web3signer_url = state.config.get_web3signer_url();
    let dispatcher = Dispatcher::with_web3signer(&registry, &web3signer_url, state.config.web3signer_timeout);

    let message = BASE64.decode(&request.message)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorResponse {
            error: "Invalid message encoding".to_string(),
            details: Some(e.to_string()),
        })))?;

    let result = dispatcher.dispatch_bls_sign(
        &request.key_handle,
        &message,
        request.module_id.as_deref(),
    ).await
    .map_err(|e| {
        error!("BLS sign failed: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "BLS signing failed".to_string(),
            details: Some(e.to_string()),
        }))
    })?;

    Ok(Json(BlsSignResponse {
        signature_b64: BASE64.encode(&result.signature),
        module_id: result.module_id,
        module_version: result.module_version,
    }))
}

/// TLS register endpoint
/// 
/// Modes:
/// - "verify": Verify that CryftGo's existing public key exists in Web3Signer
/// - "generate": Generate new key (only if CryftGo has no keys)
/// - "persistent": Alias for generate
/// - "ephemeral": Ephemeral key for testing
/// - "import": Import provided secret key
pub async fn tls_register(
    State(state): State<AppState>,
    Json(request): Json<TlsRegisterRequest>,
) -> Result<Json<TlsRegisterResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("TLS register request: mode={}", request.mode);

    let mode = parse_key_mode(&request.mode)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorResponse {
            error: "Invalid mode".to_string(),
            details: Some(e),
        })))?;

    // Handle verify mode: check that CryftGo's key exists in Web3Signer
    if mode == KEY_MODE_VERIFY {
        let pubkey = request.public_key.as_ref()
            .ok_or_else(|| (StatusCode::BAD_REQUEST, Json(ErrorResponse {
                error: "Missing public key".to_string(),
                details: Some("verify mode requires publicKey field containing the key from CryftGo's local store".to_string()),
            })))?;

        info!("Verifying TLS key exists in Web3Signer: {}...", &pubkey[..std::cmp::min(20, pubkey.len())]);

        let runtime_state = state.runtime_state.read().await;
        let web3signer_url = state.config.get_web3signer_url();

        // First check if Web3Signer is reachable
        if !runtime_state.web3signer_reachable {
            error!("Cannot verify key - Web3Signer not reachable");
            return Err((StatusCode::SERVICE_UNAVAILABLE, Json(ErrorResponse {
                error: "Web3Signer not reachable".to_string(),
                details: runtime_state.web3signer_last_error.clone(),
            })));
        }

        // Verify the key exists in Web3Signer
        runtime_state.verify_tls_pubkey_exists(&web3signer_url, pubkey).await
            .map_err(|e| {
                error!("TLS key verification failed: {}", e);
                (StatusCode::NOT_FOUND, Json(ErrorResponse {
                    error: "Key not found in Web3Signer".to_string(),
                    details: Some(format!(
                        "The TLS key {} from CryftGo's local store was not found in Web3Signer. \
                         This is a critical error - the key may have been lost or Web3Signer \
                         is misconfigured. Node ID would change if we generated a new key. \
                         Node cannot start safely. Error: {}",
                        pubkey, e
                    )),
                }))
            })?;

        info!("TLS key verified successfully in Web3Signer");

        // Return success - key exists, use the provided public key
        return Ok(Json(TlsRegisterResponse {
            key_handle: pubkey.clone(),
            cert_chain_pem: String::new(), // No cert for verify mode
            module_id: "bls_tls_signer_v1".to_string(),
            module_version: "1.0.0".to_string(),
        }));
    }

    // Handle generate/persistent mode: only allowed if no keys exist
    if mode_is_generation(mode) {
        warn!("TLS key generation requested - CryftGo indicates no existing keys");
        
        let runtime_state = state.runtime_state.read().await;
        if runtime_state.web3signer_reachable {
            let web3signer_url = state.config.get_web3signer_url();
            match runtime_state.fetch_tls_pubkeys(&web3signer_url).await {
                Ok(existing_keys) if !existing_keys.is_empty() => {
                    warn!(
                        "Generation requested but Web3Signer already has {} TLS keys",
                        existing_keys.len()
                    );
                }
                Ok(_) => {
                    info!("Web3Signer has no existing TLS keys, generation is appropriate");
                }
                Err(e) => {
                    warn!("Could not check existing keys in Web3Signer: {}", e);
                }
            }
        }
    }

    // Proceed with key registration through Web3Signer
    let registry = state.registry.read().await;
    let web3signer_url = state.config.get_web3signer_url();
    let dispatcher = Dispatcher::with_web3signer(&registry, &web3signer_url, state.config.web3signer_timeout);

    let key_material = request.ephemeral_key_pem.as_ref()
        .map(|pem| pem.as_bytes().to_vec());

    let result = dispatcher.dispatch_tls_register(
        mode,
        key_material.as_deref(),
        request.csr_pem.as_deref(),
        request.module_id.as_deref(),
    ).await
    .map_err(|e| {
        error!("TLS register failed: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "TLS registration failed".to_string(),
            details: Some(e.to_string()),
        }))
    })?;

    Ok(Json(TlsRegisterResponse {
        key_handle: result.key_handle,
        cert_chain_pem: result.cert_chain_pem,
        module_id: result.module_id,
        module_version: result.module_version,
    }))
}

/// TLS sign endpoint
pub async fn tls_sign(
    State(state): State<AppState>,
    Json(request): Json<TlsSignRequest>,
) -> Result<Json<TlsSignResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("TLS sign request: handle={}", request.key_handle);

    let registry = state.registry.read().await;
    let web3signer_url = state.config.get_web3signer_url();
    let dispatcher = Dispatcher::with_web3signer(&registry, &web3signer_url, state.config.web3signer_timeout);

    let digest = BASE64.decode(&request.digest)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorResponse {
            error: "Invalid digest encoding".to_string(),
            details: Some(e.to_string()),
        })))?;

    let result = dispatcher.dispatch_tls_sign(
        &request.key_handle,
        &digest,
        &request.algorithm,
        request.module_id.as_deref(),
    ).await
    .map_err(|e| {
        error!("TLS sign failed: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "TLS signing failed".to_string(),
            details: Some(e.to_string()),
        }))
    })?;

    Ok(Json(TlsSignResponse {
        signature_b64: BASE64.encode(&result.signature),
        module_id: result.module_id,
        module_version: result.module_version,
    }))
}

/// Status endpoint
pub async fn get_status(
    State(state): State<AppState>,
) -> Json<StatusResponse> {
    let registry = state.registry.read().await;
    let runtime_state = state.runtime_state.read().await;

    let modules: Vec<ModuleStatusEntry> = registry.get_all_modules()
        .iter()
        .map(|m| ModuleStatusEntry {
            id: m.id.clone(),
            version: m.version.clone(),
            min_cryfttee_version: m.min_cryfttee_version.clone(),
            capabilities: m.capabilities.clone(),
            default_for: m.default_for.clone(),
            trusted: m.status.trusted,
            loaded: m.status.loaded,
            compatible: m.status.compatible,
            reason: m.status.reason.clone(),
        })
        .collect();

    Json(StatusResponse {
        cryfttee_version: CRYFTTEE_VERSION.to_string(),
        modules,
        web3_signer: Web3SignerStatus {
            reachable: runtime_state.web3signer_reachable,
            last_error: runtime_state.web3signer_last_error.clone(),
        },
        wasm_runtime: WasmRuntimeStatus {
            healthy: runtime_state.wasm_runtime_healthy,
            last_error: runtime_state.wasm_runtime_last_error.clone(),
        },
    })
}

/// Attestation endpoint
pub async fn get_attestation(
    State(state): State<AppState>,
) -> Json<Value> {
    let runtime_state = state.runtime_state.read().await;

    match &runtime_state.attestation {
        Some(attestation) => Json(serde_json::to_value(attestation).unwrap_or(json!({
            "error": "Failed to serialize attestation"
        }))),
        None => Json(json!({
            "error": "Attestation not yet computed"
        })),
    }
}

/// Schema endpoint
pub async fn get_schema(
    State(_state): State<AppState>,
) -> Json<Value> {
    Json(json!({
        "cryftteeVersion": CRYFTTEE_VERSION,
        "schemaVersion": "1.0.0",
        "manifestSchema": {
            "type": "object",
            "required": ["id", "dir", "file", "version", "minCryftteeVersion", "description", "capabilities", "defaultFor", "publisherId", "hash", "signature"],
            "properties": {
                "id": { "type": "string", "description": "Unique module identifier" },
                "dir": { "type": "string", "description": "Subdirectory under modules/" },
                "file": { "type": "string", "description": "WASM filename" },
                "version": { "type": "string", "pattern": "^\\d+\\.\\d+\\.\\d+(-[a-zA-Z0-9]+)?$" },
                "minCryftteeVersion": { "type": "string", "pattern": "^\\d+\\.\\d+\\.\\d+$" },
                "description": { "type": "string" },
                "capabilities": { "type": "array", "items": { "type": "string" } },
                "defaultFor": { "type": "object", "additionalProperties": { "type": "boolean" } },
                "publisherId": { "type": "string" },
                "hash": { "type": "string", "pattern": "^sha256:[a-f0-9]{64}$" },
                "signature": { "type": "string", "description": "Base64-encoded signature" },
                "hasGui": { "type": "boolean", "description": "Whether module provides a GUI" },
                "guiPath": { "type": "string", "description": "GUI serve path relative to module directory" }
            }
        },
        "capabilitySchemas": {
            "signing": {
                "description": "BLS/TLS signing module ABI",
                "requiredExports": ["bls_register", "bls_sign", "tls_register", "tls_sign"],
                "abiDetails": {
                    "bls_register": {
                        "params": ["mode: u32", "key_material_ptr: u32", "key_material_len: u32", "out_handle_ptr: u32", "out_handle_len_ptr: u32", "out_pubkey_ptr: u32", "out_pubkey_len_ptr: u32"],
                        "returns": "i32 (0 = success, negative = error)",
                        "modes": { "0": "persistent", "1": "ephemeral", "2": "import" }
                    },
                    "bls_sign": {
                        "params": ["handle_ptr: u32", "handle_len: u32", "msg_ptr: u32", "msg_len: u32", "out_sig_ptr: u32", "out_sig_len_ptr: u32"],
                        "returns": "i32 (0 = success, negative = error)"
                    },
                    "tls_register": {
                        "params": ["mode: u32", "key_material_ptr: u32", "key_material_len: u32", "out_handle_ptr: u32", "out_handle_len_ptr: u32", "out_cert_ptr: u32", "out_cert_len_ptr: u32"],
                        "returns": "i32 (0 = success, negative = error)",
                        "modes": { "0": "persistent", "1": "ephemeral", "2": "import" }
                    },
                    "tls_sign": {
                        "params": ["handle_ptr: u32", "handle_len: u32", "digest_ptr: u32", "digest_len: u32", "algo_ptr: u32", "algo_len: u32", "out_sig_ptr: u32", "out_sig_len_ptr: u32"],
                        "returns": "i32 (0 = success, negative = error)"
                    }
                }
            }
        },
        "moduleInterfaces": {
            "statusPanel": {
                "description": "Optional interface for modules to provide dynamic status content for the runtime UI. Modules implementing this interface will have their status displayed in the kiosk status dropdown.",
                "endpoint": "GET /api/modules/{module_id}/status-panel",
                "implementedBy": "Modules with GUI or signing capabilities",
                "responseSchema": {
                    "type": "object",
                    "required": ["module_id", "title", "sections"],
                    "properties": {
                        "module_id": { "type": "string", "description": "Module identifier" },
                        "module_version": { "type": "string", "description": "Module version" },
                        "title": { "type": "string", "description": "Display title for the status panel" },
                        "sections": {
                            "type": "array",
                            "description": "Array of sections to display",
                            "items": {
                                "type": "object",
                                "required": ["heading", "items"],
                                "properties": {
                                    "heading": { "type": "string", "description": "Section heading" },
                                    "items": {
                                        "type": "array",
                                        "items": { "$ref": "#/moduleInterfaces/statusPanel/itemTypes" }
                                    }
                                }
                            }
                        }
                    }
                },
                "itemTypes": {
                    "key_value": {
                        "description": "Simple key-value display",
                        "properties": {
                            "type": { "const": "key_value" },
                            "key": { "type": "string" },
                            "value": { "type": "string" }
                        }
                    },
                    "public_key": {
                        "description": "Display a managed public key with metadata",
                        "properties": {
                            "type": { "const": "public_key" },
                            "key_type": { "type": "string", "enum": ["BLS", "TLS", "ECDSA", "ED25519"] },
                            "public_key": { "type": "string", "description": "Hex-encoded public key" },
                            "label": { "type": "string", "description": "Optional friendly name" },
                            "created": { "type": "string", "format": "date-time" }
                        }
                    },
                    "status_indicator": {
                        "description": "Status indicator with color-coded state",
                        "properties": {
                            "type": { "const": "status_indicator" },
                            "status": { "type": "string", "enum": ["ok", "warning", "error", "pending"] },
                            "message": { "type": "string" }
                        }
                    }
                },
                "example": {
                    "module_id": "bls_tls_signer_v1",
                    "module_version": "1.0.0",
                    "title": "BLS/TLS Signer",
                    "sections": [
                        {
                            "heading": "Managed Keys",
                            "items": [
                                { "type": "public_key", "key_type": "BLS", "public_key": "0x8a4f3b...", "label": "Primary Staking Key" },
                                { "type": "public_key", "key_type": "TLS", "public_key": "0x04a1b2...", "label": "Node Identity" }
                            ]
                        },
                        {
                            "heading": "Web3Signer Connection",
                            "items": [
                                { "type": "key_value", "key": "Endpoint", "value": "http://localhost:9000" },
                                { "type": "status_indicator", "status": "ok", "message": "Connected" }
                            ]
                        }
                    ]
                }
            }
        }
    }))
}

/// Reload modules endpoint
pub async fn reload_modules(
    State(state): State<AppState>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    info!("Admin: reload modules requested");

    let mut registry = state.registry.write().await;
    
    match registry.reload_modules().await {
        Ok(count) => {
            // Recompute attestation
            let mut runtime_state = state.runtime_state.write().await;
            if let Err(e) = runtime_state.compute_attestation(&state.config, &registry) {
                error!("Failed to recompute attestation: {}", e);
            }

            Ok(Json(json!({
                "success": true,
                "modulesLoaded": count,
                "message": format!("Successfully reloaded {} modules", count)
            })))
        }
        Err(e) => {
            error!("Module reload failed: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                error: "Module reload failed".to_string(),
                details: Some(e.to_string()),
            })))
        }
    }
}
