//! Redeemable Codes Module - Self-Contained Gift Code System
//!
//! Implementation aligned with US Patent Application 20250139608:
//! "Card System Utilizing On-Chain Managed Redeemable Gift Code"
//!
//! This module is SELF-CONTAINED - all code storage, hashing, validation,
//! and state management happens in-module. Host calls are used ONLY for:
//! - Random number generation (initial seeding)
//! - Blockchain writes (actual on-chain transactions)
//! - State persistence (save/load encrypted state)
//!
//! In-module storage simulates the dual-contract architecture:
//! - Public registry: status, content assignments, metadata
//! - Private registry: code hashes, salts, redemption tracking

#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::vec;
use alloc::format;
use core::cell::UnsafeCell;

// ============================================================================
// MODULE LIMITS (Power of Ten Rule 2: Fixed Bounds)
// ============================================================================
// All limits are self-declared within this module for standalone operation.

/// Maximum code length (alphanumeric gift code)
const MAX_CODE_LEN: usize = 64;

/// Maximum number of codes per batch
const MAX_CODES_PER_BATCH: usize = 10000;

/// Maximum total codes in registry
const MAX_TOTAL_CODES: usize = 1_000_000;

/// Maximum content ID length for redemption mapping
const MAX_CONTENT_ID_LEN: usize = 256;

/// Maximum metadata size per code
const MAX_CODE_METADATA_SIZE: usize = 4096;

/// Maximum salt length for hash computation
const MAX_SALT_LEN: usize = 64;

/// Maximum hash output size
const MAX_HASH_SIZE: usize = 64;

/// Maximum JSON input size
const MAX_JSON_INPUT_SIZE: usize = 64 * 1024;

/// Maximum JSON output size
const MAX_JSON_OUTPUT_SIZE: usize = 64 * 1024;

/// Maximum redemption records to retain
const MAX_REDEMPTION_LOG: usize = 100000;

/// Maximum pending blockchain transactions
const MAX_PENDING_TXS: usize = 100;

/// Code expiration maximum (10 years in seconds)
const MAX_EXPIRATION_SECS: u64 = 10 * 365 * 24 * 60 * 60;

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

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {}
}

#[global_allocator]
static ALLOCATOR: WasmAllocator = WasmAllocator;

static mut HEAP: [u8; 2 * 1024 * 1024] = [0; 2 * 1024 * 1024]; // 2MB heap
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

static mut OUTPUT_BUFFER: [u8; 65536] = [0; 65536];

#[no_mangle]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    alloc_raw(len)
}

#[no_mangle]
pub extern "C" fn dealloc(_ptr: *mut u8, _len: usize) {}

// ============================================================================
// Data Types (Patent-Compliant)
// ============================================================================

#[derive(Clone, Copy, PartialEq)]
enum CodeStatus {
    Frozen,
    Active,
    Redeemed,
    Revoked,
}

impl CodeStatus {
    fn as_str(&self) -> &'static str {
        match self {
            CodeStatus::Frozen => "frozen",
            CodeStatus::Active => "active",
            CodeStatus::Redeemed => "redeemed",
            CodeStatus::Revoked => "revoked",
        }
    }
    
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "frozen" => Some(CodeStatus::Frozen),
            "active" => Some(CodeStatus::Active),
            "redeemed" => Some(CodeStatus::Redeemed),
            "revoked" => Some(CodeStatus::Revoked),
            _ => None,
        }
    }
}

#[derive(Clone)]
enum RedeemableContent {
    WalletAccess { wallet_address: String },
    Token { token_type: String, contract_address: String, amount: String },
    ValidatorRegistration { node_id: Option<String>, stake_amount: String },
    Experience { api_endpoint: String, experience_type: String },
    Custom { content_type: String, payload: String },
}

/// Public registry entry (simulates public smart contract)
#[derive(Clone)]
struct PublicEntry {
    uid: String,
    status: CodeStatus,
    content: Option<RedeemableContent>,
    manager_address: String,
    created_at: u64,
    updated_at: u64,
    metadata: BTreeMap<String, String>,
}

/// Private registry entry (simulates private/TEE storage)
#[derive(Clone)]
struct PrivateEntry {
    storage_index: String,
    code_hash: Vec<u8>,
    salt: Vec<u8>,
    uid: String,
    redemption_count: u32,
    max_redemptions: u32,
    redeemer: Option<String>,
    redeemed_at: Option<u64>,
}

/// Module state container
struct ModuleState {
    /// Public registry (simulates public smart contract)
    public_registry: BTreeMap<String, PublicEntry>,
    /// Private registry indexed by storage_index
    private_registry: BTreeMap<String, PrivateEntry>,
    /// UID counter per manager
    uid_counters: BTreeMap<String, u64>,
    /// Random seed from host
    random_seed: Vec<u8>,
    /// Nonce for deterministic operations
    nonce: u64,
    /// Tick counter
    tick: u64,
    /// Statistics
    stats: CodeStats,
}

#[derive(Clone, Default)]
struct CodeStats {
    total_generated: u64,
    total_redeemed: u64,
    total_frozen: u64,
    total_active: u64,
    total_revoked: u64,
}

impl ModuleState {
    fn new() -> Self {
        Self {
            public_registry: BTreeMap::new(),
            private_registry: BTreeMap::new(),
            uid_counters: BTreeMap::new(),
            random_seed: Vec::new(),
            nonce: 0,
            tick: 0,
            stats: CodeStats::default(),
        }
    }
    
    fn next_uid(&mut self, manager: &str) -> String {
        let counter = self.uid_counters.entry(manager.to_string()).or_insert(0);
        *counter += 1;
        format!("{}-{}", manager, counter)
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
// Cryptographic Primitives
// ============================================================================

/// SHA256-like hash
fn hash_256(data: &[u8]) -> Vec<u8> {
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
        h[(idx + 1) % 4] = h[(idx + 1) % 4].wrapping_add(h[idx].rotate_left(17));
    }
    
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

/// Hash with salt
fn hash_with_salt(data: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(data.len() + salt.len());
    input.extend_from_slice(salt);
    input.extend_from_slice(data);
    hash_256(&input)
}

/// Generate deterministic random bytes
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
        let mut end = 0;
        let chars: Vec<char> = content.chars().collect();
        while end < chars.len() {
            if chars[end] == '"' && (end == 0 || chars[end - 1] != '\\') {
                break;
            }
            end += 1;
        }
        Some(&content[..end])
    } else {
        None
    }
}

fn json_get_int(json: &str, key: &str) -> Option<i64> {
    let search = format!("\"{}\"", key);
    let start = json.find(&search)?;
    let rest = &json[start + search.len()..];
    let colon = rest.find(':')?;
    let after_colon = rest[colon + 1..].trim_start();
    
    let mut num_str = String::new();
    for c in after_colon.chars() {
        if c.is_ascii_digit() || c == '-' {
            num_str.push(c);
        } else if !num_str.is_empty() {
            break;
        }
    }
    
    num_str.parse().ok()
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

/// Convert bytes to base32 for readable codes
fn bytes_to_base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // No I, O, 0, 1
    let mut result = String::new();
    let mut bits = 0u64;
    let mut num_bits = 0;
    
    for &byte in bytes {
        bits = (bits << 8) | byte as u64;
        num_bits += 8;
        
        while num_bits >= 5 {
            num_bits -= 5;
            let idx = ((bits >> num_bits) & 0x1F) as usize;
            result.push(ALPHABET[idx] as char);
        }
    }
    
    if num_bits > 0 {
        let idx = ((bits << (5 - num_bits)) & 0x1F) as usize;
        result.push(ALPHABET[idx] as char);
    }
    
    result
}

/// Format code with dashes (XXXX-XXXX-XXXX-XXXX)
fn format_code(code: &str) -> String {
    let chars: Vec<char> = code.chars().collect();
    let mut result = String::new();
    for (i, c) in chars.iter().enumerate() {
        if i > 0 && i % 4 == 0 {
            result.push('-');
        }
        result.push(*c);
    }
    result
}

/// Parse code removing dashes
fn parse_code(formatted: &str) -> String {
    formatted.chars().filter(|c| c.is_alphanumeric()).collect()
}

// ============================================================================
// API Handlers
// ============================================================================

fn handle_generate_code(json: &str) -> String {
    let manager = match json_get_string(json, "managerAddress") {
        Some(m) if !m.is_empty() => m,
        _ => return r#"{"error":"managerAddress is required"}"#.to_string(),
    };
    
    let state = get_state();
    
    // Check if we need random seed
    if state.random_seed.is_empty() {
        return r#"{"host_call":"get_random_seed","length":64}"#.to_string();
    }
    
    state.tick += 1;
    
    // Generate code components
    let index_bytes = generate_random(state, 4);
    let code_bytes = generate_random(state, 12);
    let salt = generate_random(state, 16);
    
    // Convert to readable format
    let storage_index = bytes_to_base32(&index_bytes);
    let code_portion = bytes_to_base32(&code_bytes);
    let full_code = format!("{}{}", storage_index, code_portion);
    
    // Hash the code portion with salt
    let code_hash = hash_with_salt(code_portion.as_bytes(), &salt);
    
    // Generate UID
    let uid = state.next_uid(manager);
    
    // Create public entry
    let public_entry = PublicEntry {
        uid: uid.clone(),
        status: CodeStatus::Frozen, // Default frozen per patent
        content: None,
        manager_address: manager.to_string(),
        created_at: state.tick,
        updated_at: state.tick,
        metadata: BTreeMap::new(),
    };
    
    // Create private entry
    let private_entry = PrivateEntry {
        storage_index: storage_index.clone(),
        code_hash,
        salt,
        uid: uid.clone(),
        redemption_count: 0,
        max_redemptions: 1,
        redeemer: None,
        redeemed_at: None,
    };
    
    // Store entries
    state.public_registry.insert(uid.clone(), public_entry);
    state.private_registry.insert(storage_index.clone(), private_entry);
    state.stats.total_generated += 1;
    state.stats.total_frozen += 1;
    
    let formatted = format_code(&full_code);
    
    format!(
        r#"{{
            "success": true,
            "uid": "{}",
            "code": "{}",
            "formattedCode": "{}",
            "storageIndex": "{}",
            "status": "frozen",
            "message": "Code generated. Activate before distribution."
        }}"#,
        escape_json_string(&uid),
        full_code,
        formatted,
        storage_index
    )
}

fn handle_redeem_code(json: &str) -> String {
    let code_input = match json_get_string(json, "code") {
        Some(c) => parse_code(c),
        None => return r#"{"error":"code is required"}"#.to_string(),
    };
    
    let redeemer = match json_get_string(json, "redeemerAddress") {
        Some(r) if !r.is_empty() => r,
        _ => return r#"{"error":"redeemerAddress is required"}"#.to_string(),
    };
    
    if code_input.len() < 8 {
        return r#"{"error":"code too short"}"#.to_string();
    }
    
    // Split into index and code portion
    let storage_index = &code_input[..7]; // First 7 chars
    let code_portion = &code_input[7..];  // Rest
    
    let state = get_state();
    state.tick += 1;
    
    // Look up private entry
    let private_entry = match state.private_registry.get(storage_index) {
        Some(e) => e.clone(),
        None => return r#"{"error":"invalid code"}"#.to_string(),
    };
    
    // Verify hash
    let computed_hash = hash_with_salt(code_portion.as_bytes(), &private_entry.salt);
    if computed_hash != private_entry.code_hash {
        return r#"{"error":"invalid code"}"#.to_string();
    }
    
    // Check public status
    let public_entry = match state.public_registry.get(&private_entry.uid) {
        Some(e) => e.clone(),
        None => return r#"{"error":"code entry not found"}"#.to_string(),
    };
    
    match public_entry.status {
        CodeStatus::Frozen => return r#"{"error":"code is frozen - not yet activated"}"#.to_string(),
        CodeStatus::Redeemed => return r#"{"error":"code already redeemed"}"#.to_string(),
        CodeStatus::Revoked => return r#"{"error":"code has been revoked"}"#.to_string(),
        CodeStatus::Active => {}
    }
    
    // Check redemption count
    if private_entry.redemption_count >= private_entry.max_redemptions {
        return r#"{"error":"max redemptions reached"}"#.to_string();
    }
    
    // Update private entry
    if let Some(pe) = state.private_registry.get_mut(storage_index) {
        pe.redemption_count += 1;
        pe.redeemer = Some(redeemer.to_string());
        pe.redeemed_at = Some(state.tick);
    }
    
    // Update public entry
    if let Some(pub_e) = state.public_registry.get_mut(&private_entry.uid) {
        pub_e.status = CodeStatus::Redeemed;
        pub_e.updated_at = state.tick;
    }
    
    state.stats.total_redeemed += 1;
    state.stats.total_active -= 1;
    
    // Format content for response
    let content_json = match &public_entry.content {
        Some(RedeemableContent::ValidatorRegistration { node_id, stake_amount }) => {
            format!(
                r#"{{"type":"validator_registration","nodeId":{},"stakeAmount":"{}"}}"#,
                node_id.as_ref().map(|n| format!("\"{}\"", n)).unwrap_or("null".to_string()),
                stake_amount
            )
        }
        Some(RedeemableContent::Token { token_type, contract_address, amount }) => {
            format!(
                r#"{{"type":"token","tokenType":"{}","contractAddress":"{}","amount":"{}"}}"#,
                token_type, contract_address, amount
            )
        }
        Some(RedeemableContent::WalletAccess { wallet_address }) => {
            format!(r#"{{"type":"wallet_access","walletAddress":"{}"}}"#, wallet_address)
        }
        Some(RedeemableContent::Experience { api_endpoint, experience_type }) => {
            format!(
                r#"{{"type":"experience","apiEndpoint":"{}","experienceType":"{}"}}"#,
                escape_json_string(api_endpoint),
                escape_json_string(experience_type)
            )
        }
        Some(RedeemableContent::Custom { content_type, payload }) => {
            format!(
                r#"{{"type":"custom","contentType":"{}","payload":"{}"}}"#,
                escape_json_string(content_type),
                escape_json_string(payload)
            )
        }
        None => "null".to_string(),
    };
    
    // If there's content that requires blockchain transaction, request host call
    let needs_blockchain = matches!(
        &public_entry.content,
        Some(RedeemableContent::ValidatorRegistration { .. }) |
        Some(RedeemableContent::Token { .. })
    );
    
    if needs_blockchain {
        format!(
            r#"{{
                "success": true,
                "uid": "{}",
                "redeemer": "{}",
                "content": {},
                "host_call": "submit_redemption_tx",
                "message": "Redemption validated. Submitting blockchain transaction..."
            }}"#,
            escape_json_string(&private_entry.uid),
            escape_json_string(redeemer),
            content_json
        )
    } else {
        format!(
            r#"{{
                "success": true,
                "uid": "{}",
                "redeemer": "{}",
                "content": {},
                "message": "Code redeemed successfully"
            }}"#,
            escape_json_string(&private_entry.uid),
            escape_json_string(redeemer),
            content_json
        )
    }
}

fn handle_validate_code(json: &str) -> String {
    let code_input = match json_get_string(json, "code") {
        Some(c) => parse_code(c),
        None => return r#"{"error":"code is required"}"#.to_string(),
    };
    
    if code_input.len() < 8 {
        return r#"{"valid":false,"error":"code too short"}"#.to_string();
    }
    
    let storage_index = &code_input[..7];
    let code_portion = &code_input[7..];
    
    let state = get_state();
    
    let private_entry = match state.private_registry.get(storage_index) {
        Some(e) => e,
        None => return r#"{"valid":false,"error":"code not found"}"#.to_string(),
    };
    
    let computed_hash = hash_with_salt(code_portion.as_bytes(), &private_entry.salt);
    let valid = computed_hash == private_entry.code_hash;
    
    if !valid {
        return r#"{"valid":false,"error":"invalid code"}"#.to_string();
    }
    
    let public_entry = state.public_registry.get(&private_entry.uid);
    let status = public_entry.map(|e| e.status.as_str()).unwrap_or("unknown");
    
    format!(
        r#"{{"valid":true,"uid":"{}","status":"{}","canRedeem":{}}}"#,
        escape_json_string(&private_entry.uid),
        status,
        status == "active" && private_entry.redemption_count < private_entry.max_redemptions
    )
}

fn handle_freeze_code(json: &str) -> String {
    let uid = match json_get_string(json, "uid") {
        Some(u) => u,
        None => return r#"{"error":"uid is required"}"#.to_string(),
    };
    
    let state = get_state();
    state.tick += 1;
    
    if let Some(entry) = state.public_registry.get_mut(uid) {
        if entry.status == CodeStatus::Active {
            state.stats.total_active -= 1;
            state.stats.total_frozen += 1;
        }
        entry.status = CodeStatus::Frozen;
        entry.updated_at = state.tick;
        
        format!(
            r#"{{"success":true,"uid":"{}","status":"frozen","message":"Code frozen"}}"#,
            escape_json_string(uid)
        )
    } else {
        format!(r#"{{"error":"code not found: {}"}}"#, escape_json_string(uid))
    }
}

fn handle_activate_code(json: &str) -> String {
    let uid = match json_get_string(json, "uid") {
        Some(u) => u,
        None => return r#"{"error":"uid is required"}"#.to_string(),
    };
    
    let state = get_state();
    state.tick += 1;
    
    if let Some(entry) = state.public_registry.get_mut(uid) {
        if entry.status == CodeStatus::Redeemed {
            return r#"{"error":"cannot activate redeemed code"}"#.to_string();
        }
        if entry.status == CodeStatus::Revoked {
            return r#"{"error":"cannot activate revoked code"}"#.to_string();
        }
        
        if entry.status == CodeStatus::Frozen {
            state.stats.total_frozen -= 1;
            state.stats.total_active += 1;
        }
        entry.status = CodeStatus::Active;
        entry.updated_at = state.tick;
        
        format!(
            r#"{{"success":true,"uid":"{}","status":"active","message":"Code activated"}}"#,
            escape_json_string(uid)
        )
    } else {
        format!(r#"{{"error":"code not found: {}"}}"#, escape_json_string(uid))
    }
}

fn handle_revoke_code(json: &str) -> String {
    let uid = match json_get_string(json, "uid") {
        Some(u) => u,
        None => return r#"{"error":"uid is required"}"#.to_string(),
    };
    
    let state = get_state();
    state.tick += 1;
    
    if let Some(entry) = state.public_registry.get_mut(uid) {
        match entry.status {
            CodeStatus::Frozen => state.stats.total_frozen -= 1,
            CodeStatus::Active => state.stats.total_active -= 1,
            _ => {}
        }
        entry.status = CodeStatus::Revoked;
        entry.updated_at = state.tick;
        state.stats.total_revoked += 1;
        
        format!(
            r#"{{"success":true,"uid":"{}","status":"revoked","message":"Code permanently revoked"}}"#,
            escape_json_string(uid)
        )
    } else {
        format!(r#"{{"error":"code not found: {}"}}"#, escape_json_string(uid))
    }
}

fn handle_get_status(json: &str) -> String {
    let uid = match json_get_string(json, "uid") {
        Some(u) => u,
        None => return r#"{"error":"uid is required"}"#.to_string(),
    };
    
    let state = get_state();
    
    if let Some(entry) = state.public_registry.get(uid) {
        let has_content = entry.content.is_some();
        
        format!(
            r#"{{
                "success": true,
                "uid": "{}",
                "status": "{}",
                "manager": "{}",
                "hasContent": {},
                "createdAt": {},
                "updatedAt": {}
            }}"#,
            escape_json_string(uid),
            entry.status.as_str(),
            escape_json_string(&entry.manager_address),
            has_content,
            entry.created_at,
            entry.updated_at
        )
    } else {
        format!(r#"{{"error":"code not found: {}"}}"#, escape_json_string(uid))
    }
}

fn handle_assign_content(json: &str) -> String {
    let uid = match json_get_string(json, "uid") {
        Some(u) => u,
        None => return r#"{"error":"uid is required"}"#.to_string(),
    };
    
    let content_type = json_get_string(json, "contentType").unwrap_or("");
    
    let state = get_state();
    state.tick += 1;
    
    let content = match content_type {
        "validator_registration" => {
            let stake = json_get_string(json, "stakeAmount").unwrap_or("0").to_string();
            let node_id = json_get_string(json, "nodeId").map(|s| s.to_string());
            RedeemableContent::ValidatorRegistration {
                node_id,
                stake_amount: stake,
            }
        }
        "token" => {
            RedeemableContent::Token {
                token_type: json_get_string(json, "tokenType").unwrap_or("native").to_string(),
                contract_address: json_get_string(json, "contractAddress").unwrap_or("").to_string(),
                amount: json_get_string(json, "amount").unwrap_or("0").to_string(),
            }
        }
        "wallet_access" => {
            RedeemableContent::WalletAccess {
                wallet_address: json_get_string(json, "walletAddress").unwrap_or("").to_string(),
            }
        }
        "experience" => {
            RedeemableContent::Experience {
                api_endpoint: json_get_string(json, "apiEndpoint").unwrap_or("").to_string(),
                experience_type: json_get_string(json, "experienceType").unwrap_or("").to_string(),
            }
        }
        _ => {
            RedeemableContent::Custom {
                content_type: content_type.to_string(),
                payload: json_get_string(json, "payload").unwrap_or("").to_string(),
            }
        }
    };
    
    if let Some(entry) = state.public_registry.get_mut(uid) {
        entry.content = Some(content);
        entry.updated_at = state.tick;
        
        format!(
            r#"{{"success":true,"uid":"{}","contentAssigned":true,"message":"Content assigned to code"}}"#,
            escape_json_string(uid)
        )
    } else {
        format!(r#"{{"error":"code not found: {}"}}"#, escape_json_string(uid))
    }
}

fn handle_list_codes(json: &str) -> String {
    let manager_filter = json_get_string(json, "managerAddress");
    let status_filter = json_get_string(json, "status").and_then(CodeStatus::from_str);
    let limit = json_get_int(json, "limit").unwrap_or(50) as usize;
    let offset = json_get_int(json, "offset").unwrap_or(0) as usize;
    
    let state = get_state();
    
    let mut codes_json = String::from("[");
    let mut count = 0;
    let mut skipped = 0;
    
    for (uid, entry) in &state.public_registry {
        // Apply filters
        if let Some(m) = manager_filter {
            if entry.manager_address != m {
                continue;
            }
        }
        if let Some(s) = status_filter {
            if entry.status != s {
                continue;
            }
        }
        
        if skipped < offset {
            skipped += 1;
            continue;
        }
        
        if count >= limit {
            break;
        }
        
        if count > 0 {
            codes_json.push(',');
        }
        
        codes_json.push_str(&format!(
            r#"{{"uid":"{}","status":"{}","manager":"{}","hasContent":{}}}"#,
            escape_json_string(uid),
            entry.status.as_str(),
            escape_json_string(&entry.manager_address),
            entry.content.is_some()
        ));
        
        count += 1;
    }
    
    codes_json.push(']');
    
    format!(
        r#"{{"success":true,"codes":{},"count":{},"total":{}}}"#,
        codes_json,
        count,
        state.public_registry.len()
    )
}

fn handle_get_stats(_json: &str) -> String {
    let state = get_state();
    
    format!(
        r#"{{
            "success": true,
            "totalGenerated": {},
            "totalRedeemed": {},
            "totalFrozen": {},
            "totalActive": {},
            "totalRevoked": {},
            "totalManagers": {}
        }}"#,
        state.stats.total_generated,
        state.stats.total_redeemed,
        state.stats.total_frozen,
        state.stats.total_active,
        state.stats.total_revoked,
        state.uid_counters.len()
    )
}

fn handle_set_random_seed(json: &str) -> String {
    let seed_hex = match json_get_string(json, "seed") {
        Some(s) => s,
        None => return r#"{"error":"seed is required"}"#.to_string(),
    };
    
    let seed = match hex_to_bytes(seed_hex) {
        Some(s) => s,
        None => return r#"{"error":"invalid seed hex"}"#.to_string(),
    };
    
    let state = get_state();
    state.random_seed = seed;
    
    r#"{"success":true,"message":"random seed initialized"}"#.to_string()
}

fn handle_module_info(_json: &str) -> String {
    let state = get_state();
    let heap_used = unsafe { HEAP_POS };
    
    format!(
        r#"{{
            "success": true,
            "module": "redeemable_codes_v1",
            "version": "2.0.0",
            "patent": "US 20250139608",
            "description": "Self-contained gift code system with in-module storage",
            "totalCodes": {},
            "heapUsed": {},
            "capabilities": [
                "generate_code",
                "redeem_code",
                "validate_code",
                "freeze_code",
                "activate_code",
                "revoke_code",
                "assign_content",
                "list_codes",
                "get_stats"
            ]
        }}"#,
        state.public_registry.len(),
        heap_used
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
    
    let action = json_get_string(json_str, "action")
        .or_else(|| json_get_string(json_str, "operation"))
        .unwrap_or("");
    
    let response = match action {
        // Code lifecycle
        "generate" | "generate_code" => handle_generate_code(json_str),
        "redeem" | "redeem_code" => handle_redeem_code(json_str),
        "validate" | "validate_code" => handle_validate_code(json_str),
        
        // Status management
        "freeze" | "freeze_code" => handle_freeze_code(json_str),
        "activate" | "unfreeze" | "activate_code" => handle_activate_code(json_str),
        "revoke" | "revoke_code" => handle_revoke_code(json_str),
        "status" | "get_status" => handle_get_status(json_str),
        
        // Content
        "assign" | "assign_content" => handle_assign_content(json_str),
        
        // Queries
        "list" | "list_codes" => handle_list_codes(json_str),
        "stats" | "get_stats" => handle_get_stats(json_str),
        
        // Module
        "info" | "module_info" => handle_module_info(json_str),
        "set_seed" | "setRandomSeed" => handle_set_random_seed(json_str),
        
        // Host callback
        "hostCallback" => {
            let callback_type = json_get_string(json_str, "callbackType").unwrap_or("");
            match callback_type {
                "random_seed" => handle_set_random_seed(json_str),
                _ => r#"{"error":"unknown callback"}"#.to_string(),
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
