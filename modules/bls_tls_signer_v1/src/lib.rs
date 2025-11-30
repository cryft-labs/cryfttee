//! BLS/TLS Signer WASM Module
//! 
//! Provides BLS and TLS signing capabilities via Web3Signer integration.
//! Includes dedicated module signing key for signing WASM modules.

#![no_std]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::vec;
use alloc::format;
use core::slice;
use serde::{Deserialize, Serialize};

// ============================================================================
// Global Allocator for no_std WASM
// ============================================================================

use core::alloc::{GlobalAlloc, Layout};

struct WasmAllocator;

unsafe impl GlobalAlloc for WasmAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        let align = layout.align();
        // Simple bump allocator - in production would be more sophisticated
        let mut buf: Vec<u8> = Vec::with_capacity(size + align);
        let ptr = buf.as_mut_ptr();
        let aligned_ptr = ((ptr as usize + align - 1) & !(align - 1)) as *mut u8;
        core::mem::forget(buf);
        aligned_ptr
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Simple allocator doesn't track deallocations
        // In production, would implement proper memory management
    }
}

#[global_allocator]
static ALLOCATOR: WasmAllocator = WasmAllocator;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// ============================================================================
// WASM Memory Management
// ============================================================================

static mut OUTPUT_BUFFER: Vec<u8> = Vec::new();

#[no_mangle]
pub extern "C" fn alloc(size: i32) -> i32 {
    let mut buf: Vec<u8> = Vec::with_capacity(size as usize);
    buf.resize(size as usize, 0);
    let ptr = buf.as_mut_ptr() as usize;
    core::mem::forget(buf);
    ptr as i32
}

#[no_mangle]
pub extern "C" fn dealloc(ptr: i32, size: i32) {
    unsafe {
        let _ = Vec::from_raw_parts(ptr as *mut u8, size as usize, size as usize);
    }
}

#[no_mangle]
pub extern "C" fn get_output_ptr() -> i32 {
    unsafe { OUTPUT_BUFFER.as_ptr() as i32 }
}

#[no_mangle]
pub extern "C" fn get_output_len() -> i32 {
    unsafe { OUTPUT_BUFFER.len() as i32 }
}

fn set_output(data: &[u8]) {
    unsafe {
        OUTPUT_BUFFER = data.to_vec();
    }
}

fn read_input(ptr: i32, len: i32) -> Vec<u8> {
    unsafe {
        slice::from_raw_parts(ptr as *const u8, len as usize).to_vec()
    }
}

// ============================================================================
// Data Structures
// ============================================================================

#[derive(Serialize, Deserialize)]
struct ModuleInfo {
    module: &'static str,
    version: &'static str,
    status: &'static str,
    capabilities: Vec<&'static str>,
}

#[derive(Deserialize)]
struct HandleRequest {
    operation: String,
    params: Option<serde_json::Value>,
}

// BLS Types
#[derive(Deserialize)]
struct BlsRegisterRequest {
    mode: Option<String>,          // "persistent", "ephemeral", "import", "verify"
    #[serde(rename = "publicKey")]
    public_key: Option<String>,    // For verify mode
}

#[derive(Serialize)]
struct BlsRegisterResponse {
    success: bool,
    key_handle: Option<String>,
    public_key: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct BlsSignRequest {
    key_handle: Option<String>,
    message: String,               // Hex-encoded message
}

#[derive(Serialize)]
struct BlsSignResponse {
    success: bool,
    signature: Option<String>,
    error: Option<String>,
}

// TLS Types
#[derive(Deserialize)]
struct TlsRegisterRequest {
    mode: Option<String>,
    #[serde(rename = "publicKey")]
    public_key: Option<String>,
}

#[derive(Serialize)]
struct TlsRegisterResponse {
    success: bool,
    key_handle: Option<String>,
    cert_chain: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct TlsSignRequest {
    key_handle: Option<String>,
    message: String,
}

#[derive(Serialize)]
struct TlsSignResponse {
    success: bool,
    signature: Option<String>,
    error: Option<String>,
}

// Module Signing Types
#[derive(Deserialize)]
struct ModuleSigningKeyRequest {
    action: String,                // "generate", "import", "export_pubkey", "list", "delete"
    key_id: Option<String>,        // Key identifier
    private_key: Option<String>,   // For import (hex or PEM)
    key_type: Option<String>,      // "ed25519" (default), "secp256k1"
}

#[derive(Serialize)]
struct ModuleSigningKeyResponse {
    success: bool,
    key_id: Option<String>,
    public_key: Option<String>,    // Hex-encoded public key
    key_type: Option<String>,
    keys: Option<Vec<ModuleSigningKeyInfo>>,
    error: Option<String>,
}

#[derive(Serialize)]
struct ModuleSigningKeyInfo {
    key_id: String,
    key_type: String,
    public_key: String,
    created_at: Option<String>,
}

#[derive(Deserialize)]
struct SignModuleRequest {
    key_id: Option<String>,        // Which key to sign with (default: "default")
    wasm_hash: String,             // SHA256 hash of WASM binary (hex)
    module_id: String,             // Module identifier
    version: String,               // Module version
    publisher_id: String,          // Publisher identifier
    metadata: Option<serde_json::Value>, // Additional metadata to include in signature
}

#[derive(Serialize)]
struct SignModuleResponse {
    success: bool,
    signature: Option<String>,     // Ed25519/secp256k1 signature (hex)
    public_key: Option<String>,    // Public key used for signing
    signed_payload: Option<String>, // The canonical payload that was signed
    error: Option<String>,
}

#[derive(Deserialize)]
struct VerifyModuleRequest {
    signature: String,             // Hex-encoded signature
    wasm_hash: String,             // SHA256 hash of WASM binary
    module_id: String,
    version: String,
    publisher_id: String,
    public_key: String,            // Publisher's public key
    metadata: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct VerifyModuleResponse {
    success: bool,
    valid: bool,
    error: Option<String>,
}

#[derive(Deserialize)]
struct HashModuleRequest {
    wasm_path: Option<String>,     // Path to WASM file (for backend to hash)
    wasm_data: Option<String>,     // Base64-encoded WASM data (for direct hashing)
}

#[derive(Serialize)]
struct HashModuleResponse {
    success: bool,
    hash: Option<String>,          // SHA256 hash (hex)
    size: Option<u64>,             // File size in bytes
    error: Option<String>,
}

// Host API call structure
#[derive(Serialize)]
struct HostApiCall {
    call_type: String,
    params: serde_json::Value,
}

// ============================================================================
// Module Entry Points
// ============================================================================

/// Get module info
#[no_mangle]
pub extern "C" fn get_info(_input_ptr: i32, _input_len: i32) -> i32 {
    let info = ModuleInfo {
        module: "bls_tls_signer_v1",
        version: "1.1.0",
        status: "operational",
        capabilities: vec![
            "bls_register",
            "bls_sign",
            "bls_verify",
            "tls_register",
            "tls_sign",
            "tls_verify",
            "module_signing_key",
            "sign_module",
            "verify_module",
            "hash_module",
        ],
    };
    
    let json = serde_json::to_string(&info).unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string());
    set_output(json.as_bytes());
    0
}

/// Main request handler
#[no_mangle]
pub extern "C" fn handle_request(input_ptr: i32, input_len: i32) -> i32 {
    let input = read_input(input_ptr, input_len);
    
    let request: HandleRequest = match serde_json::from_slice(&input) {
        Ok(r) => r,
        Err(e) => {
            let error = format!(r#"{{"success":false,"error":"Invalid request: {}"}}"#, e);
            set_output(error.as_bytes());
            return 1;
        }
    };
    
    let params = request.params.unwrap_or(serde_json::json!({}));
    
    let result = match request.operation.as_str() {
        "bls_register" => handle_bls_register(&params),
        "bls_sign" => handle_bls_sign(&params),
        "tls_register" => handle_tls_register(&params),
        "tls_sign" => handle_tls_sign(&params),
        "module_signing_key" => handle_module_signing_key(&params),
        "sign_module" => handle_sign_module(&params),
        "verify_module" => handle_verify_module(&params),
        "hash_module" => handle_hash_module(&params),
        _ => {
            format!(r#"{{"success":false,"error":"Unknown operation: {}"}}"#, request.operation)
        }
    };
    
    set_output(result.as_bytes());
    0
}

// ============================================================================
// BLS Handlers
// ============================================================================

fn handle_bls_register(params: &serde_json::Value) -> String {
    let req: BlsRegisterRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => {
            return serde_json::to_string(&BlsRegisterResponse {
                success: false,
                key_handle: None,
                public_key: None,
                error: Some(format!("Invalid params: {}", e)),
            }).unwrap_or_default();
        }
    };
    
    let mode = req.mode.unwrap_or_else(|| "persistent".to_string());
    
    // Build host API call for Web3Signer
    let api_call = HostApiCall {
        call_type: "web3signer_bls".to_string(),
        params: serde_json::json!({
            "action": "register",
            "mode": mode,
            "public_key": req.public_key,
        }),
    };
    
    // Return the API call for the host to execute
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true,
        "message": "BLS registration request prepared for Web3Signer"
    })).unwrap_or_default()
}

fn handle_bls_sign(params: &serde_json::Value) -> String {
    let req: BlsSignRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => {
            return serde_json::to_string(&BlsSignResponse {
                success: false,
                signature: None,
                error: Some(format!("Invalid params: {}", e)),
            }).unwrap_or_default();
        }
    };
    
    let api_call = HostApiCall {
        call_type: "web3signer_bls".to_string(),
        params: serde_json::json!({
            "action": "sign",
            "key_handle": req.key_handle,
            "message": req.message,
        }),
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true,
        "message": "BLS signing request prepared"
    })).unwrap_or_default()
}

// ============================================================================
// TLS Handlers
// ============================================================================

fn handle_tls_register(params: &serde_json::Value) -> String {
    let req: TlsRegisterRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => {
            return serde_json::to_string(&TlsRegisterResponse {
                success: false,
                key_handle: None,
                cert_chain: None,
                error: Some(format!("Invalid params: {}", e)),
            }).unwrap_or_default();
        }
    };
    
    let mode = req.mode.unwrap_or_else(|| "persistent".to_string());
    
    let api_call = HostApiCall {
        call_type: "web3signer_tls".to_string(),
        params: serde_json::json!({
            "action": "register",
            "mode": mode,
            "public_key": req.public_key,
        }),
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true,
        "message": "TLS registration request prepared for Web3Signer"
    })).unwrap_or_default()
}

fn handle_tls_sign(params: &serde_json::Value) -> String {
    let req: TlsSignRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => {
            return serde_json::to_string(&TlsSignResponse {
                success: false,
                signature: None,
                error: Some(format!("Invalid params: {}", e)),
            }).unwrap_or_default();
        }
    };
    
    let api_call = HostApiCall {
        call_type: "web3signer_tls".to_string(),
        params: serde_json::json!({
            "action": "sign",
            "key_handle": req.key_handle,
            "message": req.message,
        }),
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true,
        "message": "TLS signing request prepared"
    })).unwrap_or_default()
}

// ============================================================================
// Module Signing Handlers
// ============================================================================

fn handle_module_signing_key(params: &serde_json::Value) -> String {
    let req: ModuleSigningKeyRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => {
            return serde_json::to_string(&ModuleSigningKeyResponse {
                success: false,
                key_id: None,
                public_key: None,
                key_type: None,
                keys: None,
                error: Some(format!("Invalid params: {}", e)),
            }).unwrap_or_default();
        }
    };
    
    let key_type = req.key_type.unwrap_or_else(|| "ed25519".to_string());
    
    // Build host API call for key management
    // The host runtime will handle actual key generation/storage
    let api_call = HostApiCall {
        call_type: "module_signing_key".to_string(),
        params: serde_json::json!({
            "action": req.action,
            "key_id": req.key_id.unwrap_or_else(|| "default".to_string()),
            "key_type": key_type,
            "private_key": req.private_key,
        }),
    };
    
    let action_msg = match req.action.as_str() {
        "generate" => "Key generation request prepared. Host will generate Ed25519/secp256k1 key pair.",
        "import" => "Key import request prepared. Host will validate and store the key.",
        "export_pubkey" => "Public key export request prepared.",
        "list" => "Key listing request prepared.",
        "delete" => "Key deletion request prepared.",
        _ => "Unknown action",
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true,
        "message": action_msg
    })).unwrap_or_default()
}

fn handle_sign_module(params: &serde_json::Value) -> String {
    let req: SignModuleRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => {
            return serde_json::to_string(&SignModuleResponse {
                success: false,
                signature: None,
                public_key: None,
                signed_payload: None,
                error: Some(format!("Invalid params: {}", e)),
            }).unwrap_or_default();
        }
    };
    
    // Validate wasm_hash format (should be hex SHA256)
    if !req.wasm_hash.chars().all(|c| c.is_ascii_hexdigit()) || req.wasm_hash.len() != 64 {
        return serde_json::to_string(&SignModuleResponse {
            success: false,
            signature: None,
            public_key: None,
            signed_payload: None,
            error: Some("wasm_hash must be 64-character hex SHA256".to_string()),
        }).unwrap_or_default();
    }
    
    // Build canonical payload for signing
    // This ensures signature covers all relevant module metadata
    let canonical_payload = serde_json::json!({
        "module_id": req.module_id,
        "version": req.version,
        "publisher_id": req.publisher_id,
        "wasm_hash": req.wasm_hash.to_lowercase(),
        "metadata": req.metadata,
    });
    
    let api_call = HostApiCall {
        call_type: "sign_module".to_string(),
        params: serde_json::json!({
            "key_id": req.key_id.unwrap_or_else(|| "default".to_string()),
            "payload": canonical_payload,
        }),
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true,
        "canonical_payload": canonical_payload,
        "message": "Module signing request prepared. Host will sign with module signing key."
    })).unwrap_or_default()
}

fn handle_verify_module(params: &serde_json::Value) -> String {
    let req: VerifyModuleRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => {
            return serde_json::to_string(&VerifyModuleResponse {
                success: false,
                valid: false,
                error: Some(format!("Invalid params: {}", e)),
            }).unwrap_or_default();
        }
    };
    
    // Rebuild canonical payload
    let canonical_payload = serde_json::json!({
        "module_id": req.module_id,
        "version": req.version,
        "publisher_id": req.publisher_id,
        "wasm_hash": req.wasm_hash.to_lowercase(),
        "metadata": req.metadata,
    });
    
    let api_call = HostApiCall {
        call_type: "verify_module".to_string(),
        params: serde_json::json!({
            "signature": req.signature,
            "public_key": req.public_key,
            "payload": canonical_payload,
        }),
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true,
        "message": "Module verification request prepared."
    })).unwrap_or_default()
}

fn handle_hash_module(params: &serde_json::Value) -> String {
    let req: HashModuleRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => {
            return serde_json::to_string(&HashModuleResponse {
                success: false,
                hash: None,
                size: None,
                error: Some(format!("Invalid params: {}", e)),
            }).unwrap_or_default();
        }
    };
    
    if req.wasm_path.is_none() && req.wasm_data.is_none() {
        return serde_json::to_string(&HashModuleResponse {
            success: false,
            hash: None,
            size: None,
            error: Some("Either wasm_path or wasm_data is required".to_string()),
        }).unwrap_or_default();
    }
    
    let api_call = HostApiCall {
        call_type: "hash_module".to_string(),
        params: serde_json::json!({
            "wasm_path": req.wasm_path,
            "wasm_data": req.wasm_data,
        }),
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true,
        "message": "Hash computation request prepared."
    })).unwrap_or_default()
}

// ============================================================================
// Legacy Direct Export Functions (for backwards compatibility)
// ============================================================================

#[no_mangle]
pub extern "C" fn bls_register(input_ptr: i32, input_len: i32) -> i32 {
    let input = read_input(input_ptr, input_len);
    let params: serde_json::Value = serde_json::from_slice(&input).unwrap_or(serde_json::json!({}));
    let result = handle_bls_register(&params);
    set_output(result.as_bytes());
    0
}

#[no_mangle]
pub extern "C" fn bls_sign(input_ptr: i32, input_len: i32) -> i32 {
    let input = read_input(input_ptr, input_len);
    let params: serde_json::Value = serde_json::from_slice(&input).unwrap_or(serde_json::json!({}));
    let result = handle_bls_sign(&params);
    set_output(result.as_bytes());
    0
}

#[no_mangle]
pub extern "C" fn tls_register(input_ptr: i32, input_len: i32) -> i32 {
    let input = read_input(input_ptr, input_len);
    let params: serde_json::Value = serde_json::from_slice(&input).unwrap_or(serde_json::json!({}));
    let result = handle_tls_register(&params);
    set_output(result.as_bytes());
    0
}

#[no_mangle]
pub extern "C" fn tls_sign(input_ptr: i32, input_len: i32) -> i32 {
    let input = read_input(input_ptr, input_len);
    let params: serde_json::Value = serde_json::from_slice(&input).unwrap_or(serde_json::json!({}));
    let result = handle_tls_sign(&params);
    set_output(result.as_bytes());
    0
}

#[no_mangle]
pub extern "C" fn module_signing_key(input_ptr: i32, input_len: i32) -> i32 {
    let input = read_input(input_ptr, input_len);
    let params: serde_json::Value = serde_json::from_slice(&input).unwrap_or(serde_json::json!({}));
    let result = handle_module_signing_key(&params);
    set_output(result.as_bytes());
    0
}

#[no_mangle]
pub extern "C" fn sign_module(input_ptr: i32, input_len: i32) -> i32 {
    let input = read_input(input_ptr, input_len);
    let params: serde_json::Value = serde_json::from_slice(&input).unwrap_or(serde_json::json!({}));
    let result = handle_sign_module(&params);
    set_output(result.as_bytes());
    0
}

#[no_mangle]
pub extern "C" fn verify_module(input_ptr: i32, input_len: i32) -> i32 {
    let input = read_input(input_ptr, input_len);
    let params: serde_json::Value = serde_json::from_slice(&input).unwrap_or(serde_json::json!({}));
    let result = handle_verify_module(&params);
    set_output(result.as_bytes());
    0
}

#[no_mangle]
pub extern "C" fn hash_module(input_ptr: i32, input_len: i32) -> i32 {
    let input = read_input(input_ptr, input_len);
    let params: serde_json::Value = serde_json::from_slice(&input).unwrap_or(serde_json::json!({}));
    let result = handle_hash_module(&params);
    set_output(result.as_bytes());
    0
}
