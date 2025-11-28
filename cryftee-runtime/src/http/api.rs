//! API handlers for /v1 endpoints

use axum::{
    extract::State,
    Json,
    http::StatusCode,
};
use serde::Serialize;
use serde_json::{json, Value};
use tracing::{info, error};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use crate::wasm_api::staking::{
    BlsRegisterRequest, BlsRegisterResponse, BlsSignRequest, BlsSignResponse,
    TlsRegisterRequest, TlsRegisterResponse, TlsSignRequest, TlsSignResponse,
    StatusResponse, ModuleStatusEntry, Web3SignerStatus, WasmRuntimeStatus,
    parse_key_mode,
};
use crate::runtime::Dispatcher;
use crate::CRYFTEE_VERSION;

/// Shared application state - re-imported from mod.rs
pub type AppState = super::AppState;

/// Error response structure
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub details: Option<String>,
}

/// BLS register endpoint
pub async fn bls_register(
    State(state): State<AppState>,
    Json(request): Json<BlsRegisterRequest>,
) -> Result<Json<BlsRegisterResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("BLS register request: mode={}", request.mode);

    let registry = state.registry.read().await;
    let dispatcher = Dispatcher::new(&registry);

    let mode = parse_key_mode(&request.mode)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorResponse {
            error: "Invalid mode".to_string(),
            details: Some(e),
        })))?;

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
    let dispatcher = Dispatcher::new(&registry);

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
pub async fn tls_register(
    State(state): State<AppState>,
    Json(request): Json<TlsRegisterRequest>,
) -> Result<Json<TlsRegisterResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("TLS register request: mode={}", request.mode);

    let registry = state.registry.read().await;
    let dispatcher = Dispatcher::new(&registry);

    let mode = parse_key_mode(&request.mode)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorResponse {
            error: "Invalid mode".to_string(),
            details: Some(e),
        })))?;

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
    let dispatcher = Dispatcher::new(&registry);

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
            min_cryftee_version: m.min_cryftee_version.clone(),
            capabilities: m.capabilities.clone(),
            default_for: m.default_for.clone(),
            trusted: m.status.trusted,
            loaded: m.status.loaded,
            compatible: m.status.compatible,
            reason: m.status.reason.clone(),
        })
        .collect();

    Json(StatusResponse {
        cryftee_version: CRYFTEE_VERSION.to_string(),
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
        "cryfteeVersion": CRYFTEE_VERSION,
        "schemaVersion": "1.0.0",
        "manifestSchema": {
            "type": "object",
            "required": ["id", "dir", "file", "version", "minCryfteeVersion", "description", "capabilities", "defaultFor", "publisherId", "hash", "signature"],
            "properties": {
                "id": { "type": "string", "description": "Unique module identifier" },
                "dir": { "type": "string", "description": "Subdirectory under modules/" },
                "file": { "type": "string", "description": "WASM filename" },
                "version": { "type": "string", "pattern": "^\\d+\\.\\d+\\.\\d+(-[a-zA-Z0-9]+)?$" },
                "minCryfteeVersion": { "type": "string", "pattern": "^\\d+\\.\\d+\\.\\d+$" },
                "description": { "type": "string" },
                "capabilities": { "type": "array", "items": { "type": "string" } },
                "defaultFor": { "type": "object", "additionalProperties": { "type": "boolean" } },
                "publisherId": { "type": "string" },
                "hash": { "type": "string", "pattern": "^sha256:[a-f0-9]{64}$" },
                "signature": { "type": "string", "description": "Base64-encoded signature" }
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
