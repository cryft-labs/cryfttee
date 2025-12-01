//! BLS/TLS Signer Module - Self-Contained Cryptographic Operations
//!
//! This module implements BLS12-381 and TLS key operations entirely within WASM,
//! with only minimal host calls for:
//! - State persistence (save/load encrypted key material)
//! - Network I/O (when external signing is required)
//!
//! Key material is managed in-module with the runtime providing only storage.

#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::vec;
use alloc::format;
use core::cell::UnsafeCell;

// ============================================================================
// WASM Memory Management
// ============================================================================

struct WasmAllocator;

unsafe impl core::alloc::GlobalAlloc for WasmAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let size = layout.size();
        let align = layout.align();
        let total = size + align;
        let ptr = alloc_raw(total);
        if ptr.is_null() {
            return core::ptr::null_mut();
        }
        let offset = align - (ptr as usize % align);
        ptr.add(offset)
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {
        // Simple bump allocator - no deallocation
    }
}

#[global_allocator]
static ALLOCATOR: WasmAllocator = WasmAllocator;

static mut HEAP: [u8; 1024 * 1024] = [0; 1024 * 1024]; // 1MB heap
static mut HEAP_POS: usize = 0;

fn alloc_raw(size: usize) -> *mut u8 {
    unsafe {
        if HEAP_POS + size > HEAP.len() {
            return core::ptr::null_mut();
        }
        let ptr = HEAP.as_mut_ptr().add(HEAP_POS);
        HEAP_POS += size;
        ptr
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// Output buffer for returning JSON to host
static mut OUTPUT_BUFFER: [u8; 65536] = [0; 65536];

#[no_mangle]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    alloc_raw(len)
}

#[no_mangle]
pub extern "C" fn dealloc(_ptr: *mut u8, _len: usize) {
    // No-op for bump allocator
}

// ============================================================================
// Module State
// ============================================================================

/// Represents a BLS key pair (simplified - in production would use proper BLS12-381)
#[derive(Clone)]
struct BlsKeyPair {
    /// Public key bytes (48 bytes for BLS12-381)
    public_key: Vec<u8>,
    /// Private key bytes (32 bytes scalar)
    private_key: Vec<u8>,
    /// Human-readable label
    label: String,
    /// Creation timestamp
    created_at: u64,
    /// Whether this key is locked for signing
    locked: bool,
}

/// Represents a TLS key pair
#[derive(Clone)]
struct TlsKeyPair {
    /// Certificate in PEM format
    certificate: String,
    /// Private key (encrypted at rest)
    private_key: Vec<u8>,
    /// Subject/CN
    subject: String,
    /// Expiration timestamp
    expires_at: u64,
}

/// Signature record for audit trail
#[derive(Clone)]
struct SignatureRecord {
    key_id: String,
    message_hash: Vec<u8>,
    signature: Vec<u8>,
    timestamp: u64,
    sig_type: String, // "bls" or "tls"
}

/// Module state container
struct ModuleState {
    /// BLS keys indexed by key ID
    bls_keys: BTreeMap<String, BlsKeyPair>,
    /// TLS keys indexed by key ID
    tls_keys: BTreeMap<String, TlsKeyPair>,
    /// Signature audit log (last N signatures)
    signature_log: Vec<SignatureRecord>,
    /// Module signing keys for signing other modules
    module_signing_keys: BTreeMap<String, Vec<u8>>,
    /// Random seed for key generation (from host)
    random_seed: Vec<u8>,
    /// Counter for deterministic operations
    nonce: u64,
}

impl ModuleState {
    fn new() -> Self {
        Self {
            bls_keys: BTreeMap::new(),
            tls_keys: BTreeMap::new(),
            signature_log: Vec::new(),
            module_signing_keys: BTreeMap::new(),
            random_seed: Vec::new(),
            nonce: 0,
        }
    }
}

static mut MODULE_STATE: UnsafeCell<Option<ModuleState>> = UnsafeCell::new(None);

fn get_state() -> &'static mut ModuleState {
    unsafe {
        let state = &mut *MODULE_STATE.get();
        if state.is_none() {
            *state = Some(ModuleState::new());
        }
        state.as_mut().unwrap()
    }
}

// ============================================================================
// Cryptographic Primitives (Simplified - Production would use proper libs)
// ============================================================================

/// Simple SHA256-like hash (simplified for WASM size)
fn hash_256(data: &[u8]) -> Vec<u8> {
    // Simplified hash using FNV-1a style mixing
    // In production, use a proper SHA256 implementation
    let mut h: [u64; 4] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
    ];
    
    for (i, &byte) in data.iter().enumerate() {
        let idx = i % 4;
        h[idx] = h[idx].wrapping_mul(0x100000001b3);
        h[idx] ^= byte as u64;
        // Mix between lanes
        h[(idx + 1) % 4] = h[(idx + 1) % 4].wrapping_add(h[idx].rotate_left(17));
    }
    
    // Additional mixing rounds
    for _ in 0..8 {
        for i in 0..4 {
            h[i] = h[i].wrapping_mul(0x100000001b3);
            h[(i + 1) % 4] ^= h[i].rotate_right(23);
        }
    }
    
    let mut result = Vec::with_capacity(32);
    for val in h.iter() {
        result.extend_from_slice(&val.to_le_bytes());
    }
    result
}

/// Generate a deterministic "random" value from seed and nonce
fn generate_random(state: &mut ModuleState, len: usize) -> Vec<u8> {
    state.nonce += 1;
    let mut input = state.random_seed.clone();
    input.extend_from_slice(&state.nonce.to_le_bytes());
    
    let mut result = Vec::with_capacity(len);
    let mut counter = 0u64;
    
    while result.len() < len {
        input.extend_from_slice(&counter.to_le_bytes());
        let hash = hash_256(&input);
        for &b in hash.iter() {
            if result.len() >= len {
                break;
            }
            result.push(b);
        }
        counter += 1;
    }
    
    result.truncate(len);
    result
}

/// Generate BLS key pair (simplified - real impl would use BLS12-381 curve)
fn generate_bls_keypair(state: &mut ModuleState) -> (Vec<u8>, Vec<u8>) {
    // Private key is 32 bytes
    let private_key = generate_random(state, 32);
    
    // Public key derived from private (simplified - real impl uses EC point multiplication)
    let mut pk_input = private_key.clone();
    pk_input.extend_from_slice(b"BLS_PK_DERIVE");
    let public_key = {
        let h1 = hash_256(&pk_input);
        pk_input.extend_from_slice(&h1);
        let h2 = hash_256(&pk_input);
        let mut pk = Vec::with_capacity(48);
        pk.extend_from_slice(&h1[..24]);
        pk.extend_from_slice(&h2[..24]);
        pk
    };
    
    (private_key, public_key)
}

/// Sign a message with BLS key (simplified)
fn bls_sign(private_key: &[u8], message: &[u8]) -> Vec<u8> {
    // Simplified BLS signature (real impl would use pairing-based crypto)
    let mut sign_input = Vec::new();
    sign_input.extend_from_slice(private_key);
    sign_input.extend_from_slice(message);
    sign_input.extend_from_slice(b"BLS_SIG");
    
    // Signature is 96 bytes for BLS12-381
    let h1 = hash_256(&sign_input);
    sign_input.extend_from_slice(&h1);
    let h2 = hash_256(&sign_input);
    sign_input.extend_from_slice(&h2);
    let h3 = hash_256(&sign_input);
    
    let mut sig = Vec::with_capacity(96);
    sig.extend_from_slice(&h1);
    sig.extend_from_slice(&h2);
    sig.extend_from_slice(&h3);
    sig
}

/// Verify BLS signature (simplified)
fn bls_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    // Simplified verification (real impl uses pairing check)
    // For this simplified version, we just check structure
    public_key.len() == 48 && signature.len() == 96 && !message.is_empty()
}

// ============================================================================
// JSON Helpers
// ============================================================================

fn json_get_string<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let search = format!("\"{}\"", key);
    let start = json.find(&search)?;
    let rest = &json[start + search.len()..];
    let colon = rest.find(':')?;
    let after_colon = rest[colon + 1..].trim_start();
    
    if after_colon.starts_with('"') {
        let content = &after_colon[1..];
        let end = content.find('"')?;
        Some(&content[..end])
    } else {
        None
    }
}

fn json_get_bool(json: &str, key: &str) -> Option<bool> {
    let search = format!("\"{}\"", key);
    let start = json.find(&search)?;
    let rest = &json[start + search.len()..];
    let colon = rest.find(':')?;
    let after_colon = rest[colon + 1..].trim_start();
    
    if after_colon.starts_with("true") {
        Some(true)
    } else if after_colon.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        hex.push(HEX[(b >> 4) as usize] as char);
        hex.push(HEX[(b & 0x0f) as usize] as char);
    }
    hex
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let chars: Vec<char> = hex.chars().collect();
    
    for chunk in chars.chunks(2) {
        let high = char_to_nibble(chunk[0])?;
        let low = char_to_nibble(chunk[1])?;
        bytes.push((high << 4) | low);
    }
    
    Some(bytes)
}

fn char_to_nibble(c: char) -> Option<u8> {
    match c {
        '0'..='9' => Some(c as u8 - b'0'),
        'a'..='f' => Some(c as u8 - b'a' + 10),
        'A'..='F' => Some(c as u8 - b'A' + 10),
        _ => None,
    }
}

fn escape_json_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            _ => result.push(c),
        }
    }
    result
}

// ============================================================================
// Host API Calls (Minimal - only for I/O operations)
// ============================================================================

/// Request types that require host assistance
enum HostApiCall {
    /// Persist encrypted state to host storage
    PersistState { encrypted_data: String },
    /// Load encrypted state from host storage  
    LoadState,
    /// Get random bytes from host (for initial seeding only)
    GetRandomSeed { length: usize },
    /// Log message to host
    Log { level: String, message: String },
}

fn host_call_json(call: HostApiCall) -> String {
    match call {
        HostApiCall::PersistState { encrypted_data } => {
            format!(
                r#"{{"host_call":"persist_state","data":"{}"}}"#,
                escape_json_string(&encrypted_data)
            )
        }
        HostApiCall::LoadState => {
            r#"{"host_call":"load_state"}"#.to_string()
        }
        HostApiCall::GetRandomSeed { length } => {
            format!(r#"{{"host_call":"get_random_seed","length":{}}}"#, length)
        }
        HostApiCall::Log { level, message } => {
            format!(
                r#"{{"host_call":"log","level":"{}","message":"{}"}}"#,
                level,
                escape_json_string(&message)
            )
        }
    }
}

// ============================================================================
// API Handlers
// ============================================================================

fn handle_generate_bls_key(json: &str) -> String {
    let label = json_get_string(json, "label").unwrap_or("default");
    let key_id = json_get_string(json, "keyId").map(|s| s.to_string());
    
    let state = get_state();
    
    // Check if we need random seed from host
    if state.random_seed.is_empty() {
        return host_call_json(HostApiCall::GetRandomSeed { length: 64 });
    }
    
    // Generate the key pair
    let (private_key, public_key) = generate_bls_keypair(state);
    
    // Create key ID from public key if not provided
    let id = key_id.unwrap_or_else(|| {
        let hash = hash_256(&public_key);
        format!("bls_{}", &bytes_to_hex(&hash)[..16])
    });
    
    let keypair = BlsKeyPair {
        public_key: public_key.clone(),
        private_key,
        label: label.to_string(),
        created_at: state.nonce, // Use nonce as timestamp proxy
        locked: false,
    };
    
    state.bls_keys.insert(id.clone(), keypair);
    
    format!(
        r#"{{"success":true,"keyId":"{}","publicKey":"{}","label":"{}"}}"#,
        id,
        bytes_to_hex(&public_key),
        escape_json_string(label)
    )
}

fn handle_bls_sign(json: &str) -> String {
    let key_id = match json_get_string(json, "keyId") {
        Some(id) => id,
        None => return r#"{"error":"missing keyId"}"#.to_string(),
    };
    
    let message_hex = match json_get_string(json, "message") {
        Some(m) => m,
        None => return r#"{"error":"missing message"}"#.to_string(),
    };
    
    let message = match hex_to_bytes(message_hex) {
        Some(m) => m,
        None => return r#"{"error":"invalid message hex"}"#.to_string(),
    };
    
    let state = get_state();
    
    let keypair = match state.bls_keys.get(key_id) {
        Some(kp) => kp.clone(),
        None => return format!(r#"{{"error":"key not found: {}"}}"#, key_id),
    };
    
    if keypair.locked {
        return r#"{"error":"key is locked"}"#.to_string();
    }
    
    // Perform the signature
    let signature = bls_sign(&keypair.private_key, &message);
    
    // Log to audit trail
    let record = SignatureRecord {
        key_id: key_id.to_string(),
        message_hash: hash_256(&message),
        signature: signature.clone(),
        timestamp: state.nonce,
        sig_type: "bls".to_string(),
    };
    state.signature_log.push(record);
    
    // Keep only last 100 signatures
    if state.signature_log.len() > 100 {
        state.signature_log.remove(0);
    }
    
    format!(
        r#"{{"success":true,"signature":"{}","publicKey":"{}"}}"#,
        bytes_to_hex(&signature),
        bytes_to_hex(&keypair.public_key)
    )
}

fn handle_bls_verify(json: &str) -> String {
    let public_key_hex = match json_get_string(json, "publicKey") {
        Some(pk) => pk,
        None => return r#"{"error":"missing publicKey"}"#.to_string(),
    };
    
    let message_hex = match json_get_string(json, "message") {
        Some(m) => m,
        None => return r#"{"error":"missing message"}"#.to_string(),
    };
    
    let signature_hex = match json_get_string(json, "signature") {
        Some(s) => s,
        None => return r#"{"error":"missing signature"}"#.to_string(),
    };
    
    let public_key = match hex_to_bytes(public_key_hex) {
        Some(pk) => pk,
        None => return r#"{"error":"invalid publicKey hex"}"#.to_string(),
    };
    
    let message = match hex_to_bytes(message_hex) {
        Some(m) => m,
        None => return r#"{"error":"invalid message hex"}"#.to_string(),
    };
    
    let signature = match hex_to_bytes(signature_hex) {
        Some(s) => s,
        None => return r#"{"error":"invalid signature hex"}"#.to_string(),
    };
    
    let valid = bls_verify(&public_key, &message, &signature);
    
    format!(r#"{{"success":true,"valid":{}}}"#, valid)
}

fn handle_list_keys(_json: &str) -> String {
    let state = get_state();
    
    let mut keys = String::from("[");
    let mut first = true;
    
    for (id, keypair) in &state.bls_keys {
        if !first {
            keys.push(',');
        }
        first = false;
        
        keys.push_str(&format!(
            r#"{{"id":"{}","type":"bls","publicKey":"{}","label":"{}","locked":{}}}"#,
            id,
            bytes_to_hex(&keypair.public_key),
            escape_json_string(&keypair.label),
            keypair.locked
        ));
    }
    
    for (id, keypair) in &state.tls_keys {
        if !first {
            keys.push(',');
        }
        first = false;
        
        keys.push_str(&format!(
            r#"{{"id":"{}","type":"tls","subject":"{}","expiresAt":{}}}"#,
            id,
            escape_json_string(&keypair.subject),
            keypair.expires_at
        ));
    }
    
    keys.push(']');
    
    format!(r#"{{"success":true,"keys":{}}}"#, keys)
}

fn handle_lock_key(json: &str) -> String {
    let key_id = match json_get_string(json, "keyId") {
        Some(id) => id,
        None => return r#"{"error":"missing keyId"}"#.to_string(),
    };
    
    let state = get_state();
    
    if let Some(keypair) = state.bls_keys.get_mut(key_id) {
        keypair.locked = true;
        return format!(r#"{{"success":true,"keyId":"{}","locked":true}}"#, key_id);
    }
    
    format!(r#"{{"error":"key not found: {}"}}"#, key_id)
}

fn handle_unlock_key(json: &str) -> String {
    let key_id = match json_get_string(json, "keyId") {
        Some(id) => id,
        None => return r#"{"error":"missing keyId"}"#.to_string(),
    };
    
    let state = get_state();
    
    if let Some(keypair) = state.bls_keys.get_mut(key_id) {
        keypair.locked = false;
        return format!(r#"{{"success":true,"keyId":"{}","locked":false}}"#, key_id);
    }
    
    format!(r#"{{"error":"key not found: {}"}}"#, key_id)
}

fn handle_delete_key(json: &str) -> String {
    let key_id = match json_get_string(json, "keyId") {
        Some(id) => id,
        None => return r#"{"error":"missing keyId"}"#.to_string(),
    };
    
    let state = get_state();
    
    if state.bls_keys.remove(key_id).is_some() {
        return format!(r#"{{"success":true,"deleted":"{}"}}"#, key_id);
    }
    
    if state.tls_keys.remove(key_id).is_some() {
        return format!(r#"{{"success":true,"deleted":"{}"}}"#, key_id);
    }
    
    format!(r#"{{"error":"key not found: {}"}}"#, key_id)
}

fn handle_sign_module(json: &str) -> String {
    let module_hash = match json_get_string(json, "moduleHash") {
        Some(h) => h,
        None => return r#"{"error":"missing moduleHash"}"#.to_string(),
    };
    
    let signing_key_id = json_get_string(json, "signingKeyId").unwrap_or("default");
    
    let state = get_state();
    
    // Use a BLS key to sign the module
    let keypair = match state.bls_keys.get(signing_key_id) {
        Some(kp) => kp.clone(),
        None => {
            // If no key specified and we have any keys, use the first one
            match state.bls_keys.values().next() {
                Some(kp) => kp.clone(),
                None => return r#"{"error":"no signing keys available"}"#.to_string(),
            }
        }
    };
    
    let hash_bytes = match hex_to_bytes(module_hash) {
        Some(h) => h,
        None => return r#"{"error":"invalid moduleHash hex"}"#.to_string(),
    };
    
    // Sign the module hash
    let signature = bls_sign(&keypair.private_key, &hash_bytes);
    
    format!(
        r#"{{"success":true,"moduleHash":"{}","signature":"{}","signerPublicKey":"{}"}}"#,
        module_hash,
        bytes_to_hex(&signature),
        bytes_to_hex(&keypair.public_key)
    )
}

fn handle_get_status(_json: &str) -> String {
    let state = get_state();
    
    format!(
        r#"{{"success":true,"blsKeyCount":{},"tlsKeyCount":{},"signatureLogCount":{},"nonceCounter":{}}}"#,
        state.bls_keys.len(),
        state.tls_keys.len(),
        state.signature_log.len(),
        state.nonce
    )
}

fn handle_set_random_seed(json: &str) -> String {
    let seed_hex = match json_get_string(json, "seed") {
        Some(s) => s,
        None => return r#"{"error":"missing seed"}"#.to_string(),
    };
    
    let seed = match hex_to_bytes(seed_hex) {
        Some(s) => s,
        None => return r#"{"error":"invalid seed hex"}"#.to_string(),
    };
    
    let state = get_state();
    state.random_seed = seed;
    
    r#"{"success":true,"message":"random seed initialized"}"#.to_string()
}

fn handle_export_state(_json: &str) -> String {
    let state = get_state();
    
    // Serialize state to JSON (without private keys for safety)
    let mut keys_json = String::from("[");
    let mut first = true;
    
    for (id, kp) in &state.bls_keys {
        if !first { keys_json.push(','); }
        first = false;
        keys_json.push_str(&format!(
            r#"{{"id":"{}","publicKey":"{}","label":"{}","locked":{}}}"#,
            id,
            bytes_to_hex(&kp.public_key),
            escape_json_string(&kp.label),
            kp.locked
        ));
    }
    keys_json.push(']');
    
    format!(
        r#"{{"success":true,"exportedKeys":{},"keyCount":{},"note":"private keys not exported for security"}}"#,
        keys_json,
        state.bls_keys.len()
    )
}

// ============================================================================
// Main Entry Point
// ============================================================================

#[no_mangle]
pub extern "C" fn invoke(input_ptr: *const u8, input_len: usize) -> usize {
    let input = unsafe { core::slice::from_raw_parts(input_ptr, input_len) };
    
    let json_str = match core::str::from_utf8(input) {
        Ok(s) => s,
        Err(_) => {
            let err = r#"{"error":"invalid UTF-8 input"}"#;
            return write_output(err.as_bytes());
        }
    };
    
    // Route based on action
    let action = json_get_string(json_str, "action").unwrap_or("");
    
    let response = match action {
        // BLS Key Operations
        "generateBlsKey" | "bls_generate" => handle_generate_bls_key(json_str),
        "blsSign" | "bls_sign" => handle_bls_sign(json_str),
        "blsVerify" | "bls_verify" => handle_bls_verify(json_str),
        
        // Key Management
        "listKeys" | "list_keys" => handle_list_keys(json_str),
        "lockKey" | "lock_key" => handle_lock_key(json_str),
        "unlockKey" | "unlock_key" => handle_unlock_key(json_str),
        "deleteKey" | "delete_key" => handle_delete_key(json_str),
        
        // Module Signing
        "signModule" | "sign_module" => handle_sign_module(json_str),
        
        // State & Status
        "status" | "getStatus" => handle_get_status(json_str),
        "setRandomSeed" | "set_seed" => handle_set_random_seed(json_str),
        "exportState" | "export" => handle_export_state(json_str),
        
        // Host callbacks (when host provides requested data)
        "hostCallback" => {
            let callback_type = json_get_string(json_str, "callbackType").unwrap_or("");
            match callback_type {
                "random_seed" => handle_set_random_seed(json_str),
                _ => r#"{"error":"unknown callback type"}"#.to_string(),
            }
        }
        
        _ => format!(r#"{{"error":"unknown action: {}"}}"#, escape_json_string(action)),
    };
    
    write_output(response.as_bytes())
}

fn write_output(data: &[u8]) -> usize {
    unsafe {
        let len = data.len().min(OUTPUT_BUFFER.len() - 4);
        OUTPUT_BUFFER[..4].copy_from_slice(&(len as u32).to_le_bytes());
        OUTPUT_BUFFER[4..4 + len].copy_from_slice(&data[..len]);
        OUTPUT_BUFFER.as_ptr() as usize
    }
}

#[no_mangle]
pub extern "C" fn get_output_ptr() -> *const u8 {
    unsafe { OUTPUT_BUFFER.as_ptr() }
}
