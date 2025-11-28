//! Kiosk UI endpoints

use axum::{
    extract::{State, Path},
    Json,
    http::StatusCode,
    response::Response,
};
use axum::body::Body;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{info, error, warn};
use tokio_util::io::ReaderStream;
use chrono::Utc;
use std::collections::HashMap;

use super::AppState;
use super::api::ErrorResponse;
use crate::CRYFTEE_VERSION;
use crate::signing::{
    SignatureManifest, SignedModule, compute_file_hash, compute_dir_hash,
    get_blockchain_state, PublisherStatus,
};

/// Get runtime context for modules (LLM, etc.)
/// This provides a snapshot of the current runtime state that modules can use
/// Route: GET /api/context
pub async fn get_context(
    State(state): State<AppState>,
) -> Json<Value> {
    let registry = state.registry.read().await;
    let runtime_state = state.runtime_state.read().await;
    
    let modules = registry.get_all_modules();
    let enabled_modules: Vec<_> = modules.iter().filter(|m| m.enabled).collect();
    let loaded_modules: Vec<_> = modules.iter().filter(|m| m.status.loaded).collect();
    
    // Build a concise context for LLM consumption
    let module_summary: Vec<Value> = modules.iter().map(|m| {
        json!({
            "id": m.id,
            "version": m.version,
            "enabled": m.enabled,
            "loaded": m.status.loaded,
            "capabilities": m.capabilities,
            "has_gui": m.has_gui,
            "gui_type": m.gui_type,
        })
    }).collect();
    
    let attestation_summary = runtime_state.attestation.as_ref().map(|a| {
        json!({
            "cryftee_version": a.cryftee_version,
            "timestamp": a.timestamp.to_rfc3339(),
            "modules_count": a.modules.len(),
        })
    });
    
    Json(json!({
        "runtime": {
            "version": CRYFTEE_VERSION,
            "instance": state.config.instance_name,
            "timestamp": Utc::now().to_rfc3339(),
        },
        "modules": {
            "total": modules.len(),
            "enabled": enabled_modules.len(),
            "loaded": loaded_modules.len(),
            "items": module_summary,
        },
        "defaults": {
            "bls": registry.get_default_bls_module(),
            "tls": registry.get_default_tls_module(),
        },
        "attestation": attestation_summary,
        "health": {
            "wasm_runtime": runtime_state.wasm_runtime_healthy,
            "web3signer": runtime_state.web3signer_reachable,
        }
    }))
}

/// Get all modules for kiosk display
pub async fn get_modules(
    State(state): State<AppState>,
) -> Json<Value> {
    let registry = state.registry.read().await;
    let modules = registry.get_all_modules();

    Json(json!({
        "cryfteeVersion": CRYFTEE_VERSION,
        "modules": modules,
        "defaults": {
            "bls": registry.get_default_bls_module(),
            "tls": registry.get_default_tls_module()
        }
    }))
}

/// Get attestation for kiosk display
pub async fn get_attestation(
    State(state): State<AppState>,
) -> Json<Value> {
    let runtime_state = state.runtime_state.read().await;

    match &runtime_state.attestation {
        Some(attestation) => Json(serde_json::to_value(attestation).unwrap_or(json!({
            "error": "Failed to serialize attestation"
        }))),
        None => Json(json!({
            "error": "Attestation not computed"
        })),
    }
}

/// Get module schema for kiosk display
pub async fn get_schema(
    State(_state): State<AppState>,
) -> Json<Value> {
    // Reuse the same schema endpoint logic
    Json(json!({
        "cryfteeVersion": CRYFTEE_VERSION,
        "schemaVersion": "1.0.0",
        "manifestSchema": {
            "type": "object",
            "required": ["id", "dir", "file", "version", "minCryfteeVersion", "description", "capabilities", "defaultFor", "publisherId", "hash", "signature"],
            "properties": {
                "id": { "type": "string" },
                "dir": { "type": "string" },
                "file": { "type": "string" },
                "version": { "type": "string" },
                "minCryfteeVersion": { "type": "string" },
                "description": { "type": "string" },
                "capabilities": { "type": "array", "items": { "type": "string" } },
                "defaultFor": { "type": "object" },
                "publisherId": { "type": "string" },
                "hash": { "type": "string" },
                "signature": { "type": "string" },
                "hasGui": { "type": "boolean", "description": "Whether module provides a GUI" },
                "guiPath": { "type": "string", "description": "GUI serve path relative to module directory" }
            }
        },
        "capabilitySchemas": {
            "signing": {
                "description": "BLS/TLS signing module ABI",
                "requiredExports": ["bls_register", "bls_sign", "tls_register", "tls_sign"]
            }
        }
    }))
}

/// Get raw manifest.json
pub async fn get_manifest(
    State(state): State<AppState>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let manifest_path = state.config.get_manifest_path();

    if !manifest_path.exists() {
        return Err((StatusCode::NOT_FOUND, Json(ErrorResponse {
            error: "Manifest not found".to_string(),
            details: Some(format!("Path: {:?}", manifest_path)),
        })));
    }

    let contents = std::fs::read_to_string(&manifest_path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Failed to read manifest".to_string(),
            details: Some(e.to_string()),
        })))?;

    let manifest: Value = serde_json::from_str(&contents)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Failed to parse manifest".to_string(),
            details: Some(e.to_string()),
        })))?;

    Ok(Json(manifest))
}

/// Reload modules from kiosk
pub async fn reload_modules(
    State(state): State<AppState>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    info!("Kiosk: reload modules requested");

    let mut registry = state.registry.write().await;
    
    match registry.reload_modules().await {
        Ok(count) => {
            // Recompute attestation
            let mut runtime_state = state.runtime_state.write().await;
            if let Err(e) = runtime_state.compute_attestation(&state.config, &registry) {
                error!("Failed to recompute attestation: {}", e);
            }

            let modules = registry.get_all_modules();

            Ok(Json(json!({
                "success": true,
                "modulesLoaded": count,
                "modules": modules,
                "defaults": {
                    "bls": registry.get_default_bls_module(),
                    "tls": registry.get_default_tls_module()
                }
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

/// Enable a module
/// Route: POST /api/modules/:module_id/enable
pub async fn enable_module(
    State(state): State<AppState>,
    Path(module_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    info!("Kiosk: enable module requested: {}", module_id);

    let mut registry = state.registry.write().await;
    
    match registry.enable_module(&module_id).await {
        Ok(_) => {
            let modules = registry.get_all_modules();
            Ok(Json(json!({
                "success": true,
                "module": module_id,
                "enabled": true,
                "modules": modules,
                "defaults": {
                    "bls": registry.get_default_bls_module(),
                    "tls": registry.get_default_tls_module()
                }
            })))
        }
        Err(e) => {
            error!("Failed to enable module {}: {}", module_id, e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                error: format!("Failed to enable module: {}", module_id),
                details: Some(e.to_string()),
            })))
        }
    }
}

/// Disable a module
/// Route: POST /api/modules/:module_id/disable
pub async fn disable_module(
    State(state): State<AppState>,
    Path(module_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    info!("Kiosk: disable module requested: {}", module_id);

    let mut registry = state.registry.write().await;
    
    match registry.disable_module(&module_id) {
        Ok(_) => {
            let modules = registry.get_all_modules();
            Ok(Json(json!({
                "success": true,
                "module": module_id,
                "enabled": false,
                "modules": modules,
                "defaults": {
                    "bls": registry.get_default_bls_module(),
                    "tls": registry.get_default_tls_module()
                }
            })))
        }
        Err(e) => {
            error!("Failed to disable module {}: {}", module_id, e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                error: format!("Failed to disable module: {}", module_id),
                details: Some(e.to_string()),
            })))
        }
    }
}

/// Serve module GUI index.html (base path handler)
/// Route: GET /api/modules/:module_id/gui
pub async fn serve_module_gui_index(
    state: State<AppState>,
    Path(module_id): Path<String>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    serve_module_gui(state, Path((module_id, "index.html".to_string()))).await
}

/// Serve module GUI files
/// Route: GET /api/modules/:module_id/gui/*path
pub async fn serve_module_gui(
    State(state): State<AppState>,
    Path((module_id, path)): Path<(String, String)>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let registry = state.registry.read().await;
    
    // Find the module
    let module = registry.get_module(&module_id)
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(ErrorResponse {
            error: "Module not found".to_string(),
            details: Some(format!("Module '{}' does not exist", module_id)),
        })))?;
    
    // Check if module has GUI and is enabled
    if !module.has_gui {
        return Err((StatusCode::NOT_FOUND, Json(ErrorResponse {
            error: "Module has no GUI".to_string(),
            details: Some(format!("Module '{}' does not provide a GUI", module_id)),
        })));
    }
    
    // Only require the module to be enabled, not necessarily loaded
    // This allows GUI access even if the WASM module failed to load
    if !module.enabled {
        return Err((StatusCode::SERVICE_UNAVAILABLE, Json(ErrorResponse {
            error: "Module not enabled".to_string(),
            details: Some(format!("Module '{}' must be enabled to access its GUI", module_id)),
        })));
    }
    
    // Get the manifest entry to find the gui_path
    let manifest_path = state.config.get_manifest_path();
    let contents = std::fs::read_to_string(&manifest_path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Failed to read manifest".to_string(),
            details: Some(e.to_string()),
        })))?;
    
    let manifest: crate::storage::Manifest = serde_json::from_str(&contents)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Failed to parse manifest".to_string(),
            details: Some(e.to_string()),
        })))?;
    
    let entry = manifest.find_module(&module_id)
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(ErrorResponse {
            error: "Module entry not found".to_string(),
            details: Some(format!("Module '{}' not in manifest", module_id)),
        })))?;
    
    let gui_base = entry.gui_path.as_ref()
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(ErrorResponse {
            error: "No GUI path configured".to_string(),
            details: Some(format!("Module '{}' has hasGui=true but no guiPath", module_id)),
        })))?;
    
    // Construct the full file path
    // Security: ensure the path doesn't escape the module directory
    let sanitized_path = if path.is_empty() || path == "/" {
        "index.html".to_string()
    } else {
        path.trim_start_matches('/').to_string()
    };
    
    // Check for path traversal attacks
    if sanitized_path.contains("..") || sanitized_path.contains("\\..") {
        warn!("Path traversal attempt blocked: {}", sanitized_path);
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse {
            error: "Invalid path".to_string(),
            details: Some("Path traversal not allowed".to_string()),
        })));
    }
    
    let file_path = state.config.module_dir
        .join(&entry.dir)
        .join(gui_base)
        .join(&sanitized_path);
    
    // Ensure file is within module directory
    let module_dir = state.config.module_dir.join(&entry.dir).canonicalize()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Module directory not found".to_string(),
            details: None,
        })))?;
    
    let canonical_file = file_path.canonicalize()
        .map_err(|_| (StatusCode::NOT_FOUND, Json(ErrorResponse {
            error: "File not found".to_string(),
            details: Some(format!("File '{}' not found in module GUI", sanitized_path)),
        })))?;
    
    if !canonical_file.starts_with(&module_dir) {
        warn!("Path escape attempt blocked: {:?}", canonical_file);
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse {
            error: "Invalid path".to_string(),
            details: Some("Path escapes module directory".to_string()),
        })));
    }
    
    // Read and serve the file
    let file = tokio::fs::File::open(&canonical_file).await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(ErrorResponse {
            error: "File not found".to_string(),
            details: Some(format!("Could not open file: {}", sanitized_path)),
        })))?;
    
    // Determine content type
    let content_type = mime_guess::from_path(&canonical_file)
        .first_or_octet_stream()
        .to_string();
    
    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);
    
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", content_type)
        .header("X-Module-Id", &module_id)
        .header("X-Module-Version", &module.version)
        .body(body)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Failed to build response".to_string(),
            details: Some(e.to_string()),
        })))?;
    
    Ok(response)
}

// ============================================================================
// Module Signing API Endpoints
// ============================================================================

/// Request to prepare a module for signing
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareSigningRequest {
    /// Module ID to prepare for signing
    pub module_id: String,
    /// Publisher ID (must match trust.toml)
    pub publisher_id: String,
    /// Additional metadata to include in signature
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Request to sign a prepared manifest
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignModuleRequest {
    /// The signature manifest to sign
    pub manifest: SignatureManifest,
    /// Key handle from Web3Signer (BLS key)
    pub key_handle: String,
    /// Algorithm to use (default: bls)
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
}

fn default_algorithm() -> String {
    "bls".to_string()
}

/// Response containing prepared signing manifest
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareSigningResponse {
    /// The prepared signature manifest
    pub manifest: SignatureManifest,
    /// Canonical JSON representation (what will be signed)
    pub canonical_json: String,
    /// Hash of canonical JSON
    pub signing_hash: String,
}

/// Get list of modules available for signing
/// Route: GET /api/signing/modules
pub async fn get_signable_modules(
    State(state): State<AppState>,
) -> Json<Value> {
    let registry = state.registry.read().await;
    let modules = registry.get_all_modules();
    
    // Return minimal info about modules that can be signed
    let signable: Vec<Value> = modules.iter().map(|m| {
        json!({
            "id": m.id,
            "version": m.version,
            "description": m.description,
            "capabilities": m.capabilities,
            "currentHash": m.hash,
            "publisherId": m.publisher_id,
            "hasGui": m.has_gui,
            "loaded": m.status.loaded,
            "trusted": m.status.trusted,
        })
    }).collect();
    
    Json(json!({
        "modules": signable,
        "cryfteeVersion": CRYFTEE_VERSION,
    }))
}

/// Prepare a module for signing - computes hashes and builds manifest
/// Route: POST /api/signing/prepare
pub async fn prepare_module_signing(
    State(state): State<AppState>,
    Json(request): Json<PrepareSigningRequest>,
) -> Result<Json<PrepareSigningResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Preparing module for signing: {}", request.module_id);
    
    // Verify publisher is registered and verified on blockchain
    let blockchain = get_blockchain_state();
    blockchain.verify_publisher_can_sign(&request.publisher_id)
        .map_err(|e| (StatusCode::FORBIDDEN, Json(ErrorResponse {
            error: "Publisher verification failed".to_string(),
            details: Some(e.to_string()),
        })))?;
    
    let registry = state.registry.read().await;
    
    // Find the module
    let module = registry.get_module(&request.module_id)
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(ErrorResponse {
            error: "Module not found".to_string(),
            details: Some(format!("Module '{}' does not exist", request.module_id)),
        })))?;
    
    // Get manifest entry for additional info
    let manifest_path = state.config.get_manifest_path();
    let contents = std::fs::read_to_string(&manifest_path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Failed to read manifest".to_string(),
            details: Some(e.to_string()),
        })))?;
    
    let manifest: crate::storage::Manifest = serde_json::from_str(&contents)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Failed to parse manifest".to_string(),
            details: Some(e.to_string()),
        })))?;
    
    let entry = manifest.find_module(&request.module_id)
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(ErrorResponse {
            error: "Module entry not found in manifest".to_string(),
            details: None,
        })))?;
    
    // Compute hashes
    let module_dir = state.config.module_dir.join(&entry.dir);
    
    // Hash the WASM file
    let wasm_path = module_dir.join(&entry.file);
    let wasm_hash = compute_file_hash(&wasm_path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Failed to hash WASM file".to_string(),
            details: Some(e.to_string()),
        })))?;
    
    // Hash module.json if it exists
    let module_json_path = module_dir.join("module.json");
    let module_json_hash = if module_json_path.exists() {
        compute_file_hash(&module_json_path)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                error: "Failed to hash module.json".to_string(),
                details: Some(e.to_string()),
            })))?
    } else {
        "sha256:none".to_string()
    };
    
    // Hash GUI directory if module has GUI
    let gui_hash = if entry.has_gui {
        if let Some(gui_path) = &entry.gui_path {
            let gui_dir = module_dir.join(gui_path);
            if gui_dir.exists() {
                Some(compute_dir_hash(&gui_dir)
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                        error: "Failed to hash GUI directory".to_string(),
                        details: Some(e.to_string()),
                    })))?)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };
    
    // Build the signature manifest
    let mut sig_manifest = SignatureManifest::new(
        module.id.clone(),
        module.version.clone(),
        wasm_hash,
        module_json_hash,
        request.publisher_id,
        module.min_cryftee_version.clone(),
        module.capabilities.clone(),
        module.default_for.clone(),
    );
    
    // Add GUI hash if present
    if let Some(hash) = gui_hash {
        sig_manifest = sig_manifest.with_gui_hash(hash);
    }
    
    // Add custom metadata
    for (key, value) in request.metadata {
        sig_manifest = sig_manifest.with_metadata(key, value);
    }
    
    // Generate canonical JSON and hash
    let canonical_json = sig_manifest.canonical_json()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Failed to generate canonical JSON".to_string(),
            details: Some(e.to_string()),
        })))?;
    
    let signing_hash = sig_manifest.signing_hash()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Failed to compute signing hash".to_string(),
            details: Some(e.to_string()),
        })))?;
    
    Ok(Json(PrepareSigningResponse {
        manifest: sig_manifest,
        canonical_json,
        signing_hash,
    }))
}

/// Sign a prepared module manifest using Web3Signer
/// Route: POST /api/signing/sign
pub async fn sign_module(
    State(state): State<AppState>,
    Json(request): Json<SignModuleRequest>,
) -> Result<Json<SignedModule>, (StatusCode, Json<ErrorResponse>)> {
    info!("Signing module: {} with key: {}", request.manifest.module_id, request.key_handle);
    
    // Get the signing hash
    let signing_hash = request.manifest.signing_hash()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Failed to compute signing hash".to_string(),
            details: Some(e.to_string()),
        })))?;
    
    // For now, we'll use the BLS signing capability through the dispatcher
    // The actual signing happens via Web3Signer through the bls_tls_signer module
    let registry = state.registry.read().await;
    let dispatcher = crate::runtime::Dispatcher::new(&registry);
    
    // Decode the signing hash (remove "sha256:" prefix and convert to bytes)
    let hash_bytes = hex::decode(signing_hash.strip_prefix("sha256:").unwrap_or(&signing_hash))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Failed to decode signing hash".to_string(),
            details: Some(e.to_string()),
        })))?;
    
    // Sign using BLS
    let sign_result = dispatcher.dispatch_bls_sign(
        &request.key_handle,
        &hash_bytes,
        None, // Use default BLS module
    ).await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
        error: "Signing failed".to_string(),
        details: Some(e.to_string()),
    })))?;
    
    // Encode signature as base64
    let signature_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &sign_result.signature
    );
    
    Ok(Json(SignedModule {
        manifest: request.manifest,
        signature: signature_b64,
        algorithm: request.algorithm,
        key_id: request.key_handle,
    }))
}

/// Get the trust configuration (publishers) from blockchain state
/// Route: GET /api/signing/trust
pub async fn get_trust_config(
    State(_state): State<AppState>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    // Get publisher information from blockchain state
    let blockchain = get_blockchain_state();
    let chain_info = blockchain.get_chain_info();
    let all_publishers = blockchain.get_all_publishers();
    let verified_publishers = blockchain.get_verified_publishers();
    
    // Transform publishers into response format
    let publishers: Vec<Value> = all_publishers.iter().map(|p| {
        json!({
            "id": p.id,
            "name": p.name,
            "publicKey": p.public_key,
            "algorithm": p.algorithm,
            "status": p.status,
            "registeredAt": p.registered_at.to_rfc3339(),
            "lastUpdated": p.last_updated.to_rfc3339(),
            "stakeAmount": p.stake_amount,
            "reputationScore": p.reputation_score,
            "blockNumber": p.block_number,
            "txHash": p.tx_hash,
        })
    }).collect();
    
    Ok(Json(json!({
        "source": "blockchain",
        "chain": {
            "chainId": chain_info.chain_id,
            "lastSyncBlock": chain_info.last_sync_block,
            "rpcConnected": chain_info.rpc_connected,
        },
        "publishers": publishers,
        "verifiedCount": verified_publishers.len(),
        "totalCount": all_publishers.len(),
        "trust": {
            "minCryfteeVersion": CRYFTEE_VERSION,
            "enforceKnownPublishers": true,
            "enforceSignatures": true,
        }
    })))
}

/// Get blockchain chain info and sync status
/// Route: GET /api/signing/chain
pub async fn get_chain_info(
    State(_state): State<AppState>,
) -> Json<Value> {
    let blockchain = get_blockchain_state();
    let chain_info = blockchain.get_chain_info();
    
    Json(json!({
        "chainId": chain_info.chain_id,
        "lastSyncBlock": chain_info.last_sync_block,
        "rpcConnected": chain_info.rpc_connected,
        "publisherCount": chain_info.publisher_count,
        "verifiedCount": chain_info.verified_count,
    }))
}

/// Verify a publisher's status on the blockchain
/// Route: GET /api/signing/publisher/:publisher_id
pub async fn get_publisher_status(
    Path(publisher_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let blockchain = get_blockchain_state();
    
    match blockchain.get_publisher(&publisher_id) {
        Some(publisher) => {
            Ok(Json(json!({
                "found": true,
                "publisher": {
                    "id": publisher.id,
                    "name": publisher.name,
                    "publicKey": publisher.public_key,
                    "algorithm": publisher.algorithm,
                    "status": publisher.status,
                    "registeredAt": publisher.registered_at.to_rfc3339(),
                    "lastUpdated": publisher.last_updated.to_rfc3339(),
                    "stakeAmount": publisher.stake_amount,
                    "reputationScore": publisher.reputation_score,
                    "blockNumber": publisher.block_number,
                    "txHash": publisher.tx_hash,
                },
                "canSign": publisher.status == PublisherStatus::Verified,
            })))
        }
        None => {
            Ok(Json(json!({
                "found": false,
                "publisherId": publisher_id,
                "status": "unknown",
                "canSign": false,
            })))
        }
    }
}

/// Apply a signed module to the manifest
/// Route: POST /api/signing/apply
pub async fn apply_signed_module(
    State(state): State<AppState>,
    Json(signed): Json<SignedModule>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    info!("Applying signed module: {}", signed.manifest.module_id);
    
    // Read current manifest
    let manifest_path = state.config.get_manifest_path();
    let contents = std::fs::read_to_string(&manifest_path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Failed to read manifest".to_string(),
            details: Some(e.to_string()),
        })))?;
    
    let mut manifest: Value = serde_json::from_str(&contents)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Failed to parse manifest".to_string(),
            details: Some(e.to_string()),
        })))?;
    
    // Find and update the module entry
    let mut found = false;
    if let Some(modules) = manifest.get_mut("modules").and_then(|m| m.as_array_mut()) {
        for module in modules.iter_mut() {
            if module.get("id").and_then(|v| v.as_str()) == Some(&signed.manifest.module_id) {
                // Update hash and signature
                module["hash"] = json!(signed.manifest.wasm_hash);
                module["signature"] = json!(signed.signature);
                module["publisherId"] = json!(signed.manifest.publisher_id);
                found = true;
                break;
            }
        }
    }
    
    if !found {
        return Err((StatusCode::NOT_FOUND, Json(ErrorResponse {
            error: "Module not found in manifest".to_string(),
            details: Some(format!("Module '{}' not found", signed.manifest.module_id)),
        })));
    }
    
    // Write back to file
    let updated = serde_json::to_string_pretty(&manifest)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Failed to serialize manifest".to_string(),
            details: Some(e.to_string()),
        })))?;
    
    std::fs::write(&manifest_path, updated)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Failed to write manifest".to_string(),
            details: Some(e.to_string()),
        })))?;
    
    // Reload modules
    let mut registry = state.registry.write().await;
    if let Err(e) = registry.reload_modules().await {
        error!("Failed to reload modules after signing: {}", e);
    }
    
    Ok(Json(json!({
        "success": true,
        "moduleId": signed.manifest.module_id,
        "hash": signed.manifest.wasm_hash,
        "signature": signed.signature,
    })))
}
