//! CryftIPFS Module - Self-Contained IPFS Implementation
//!
//! A fully self-contained IPFS-like content-addressable storage module.
//! No external IPFS daemon required - all storage and retrieval happens
//! within this WASM module.
//!
//! Architecture:
//! - In-module content-addressable storage (CAS)
//! - Blake3-style hashing for CID generation
//! - Persistent storage via host calls to runtime's storage layer
//! - Optional peer sync via gossip protocol
//!
//! The CryftTEE runtime is just scaffolding - this module is fully independent.

#![no_std]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::vec;
use alloc::format;
use alloc::collections::BTreeMap;
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
        let total = size + align;
        let mut buf: Vec<u8> = Vec::with_capacity(total);
        let ptr = buf.as_mut_ptr();
        let aligned = ((ptr as usize + align - 1) & !(align - 1)) as *mut u8;
        core::mem::forget(buf);
        aligned
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Memory freed when module unloads
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
// In-Module Storage (Self-Contained CAS)
// ============================================================================

/// Content block stored in the module
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ContentBlock {
    /// Raw content bytes (base64 encoded for JSON)
    data: String,
    /// Size in bytes
    size: usize,
    /// Links to other CIDs (for DAG structure)
    links: Vec<String>,
    /// Optional filename
    filename: Option<String>,
    /// Content type hint
    content_type: Option<String>,
    /// Creation timestamp
    created_at: u64,
}

/// Pin entry with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PinEntry {
    cid: String,
    name: Option<String>,
    recursive: bool,
    incentivized: bool,
    tier: Option<String>,
    pinned_at: u64,
}

/// Incentivized pin registration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IncentivizedPin {
    cid: String,
    sponsor: String,
    min_replicas: u32,
    reward_per_epoch: u64,
    reward_pool: u64,
    tier: String,
    expires_at: u64,
    current_replicas: u32,
    pinners: Vec<String>,
    created_at: u64,
}

/// Validator stats for rewards
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ValidatorStats {
    validator_id: String,
    pending_rewards: u64,
    claimed_rewards: u64,
    proofs_submitted: u32,
    incentivized_pins: u32,
    storage_used: u64,
    last_proof_at: u64,
}

/// Storage proof for challenges
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StorageProof {
    challenge_id: String,
    cid: String,
    validator_id: String,
    chunk_hash: String,
    proven_at: u64,
    signature: String,
}

/// Module's internal state - fully self-contained
static mut MODULE_STATE: Option<ModuleState> = None;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ModuleState {
    /// Content-addressable storage: CID -> ContentBlock
    blocks: BTreeMap<String, ContentBlock>,
    /// Pin set: CID -> PinEntry
    pins: BTreeMap<String, PinEntry>,
    /// Incentivized pins registry
    incentivized: BTreeMap<String, IncentivizedPin>,
    /// Validator statistics
    validator_stats: ValidatorStats,
    /// Pending storage proofs
    pending_proofs: Vec<StorageProof>,
    /// Node configuration
    config: NodeConfig,
    /// Node ID (generated on first start)
    node_id: String,
    /// Is node running
    running: bool,
    /// Total storage used (bytes)
    storage_used: u64,
    /// Max storage allowed (bytes)
    max_storage: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeConfig {
    validator_id: Option<String>,
    max_storage_gb: u64,
    public_gateway: String,
    auto_pin_incentivized: bool,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            validator_id: None,
            max_storage_gb: 100,
            public_gateway: "https://ipfs.cryft.network".to_string(),
            auto_pin_incentivized: true,
        }
    }
}

fn get_state() -> &'static mut ModuleState {
    unsafe {
        if MODULE_STATE.is_none() {
            MODULE_STATE = Some(ModuleState::default());
        }
        MODULE_STATE.as_mut().unwrap()
    }
}

// ============================================================================
// Blake3-like Hashing (Simplified for WASM)
// ============================================================================

/// Simple hash function for CID generation
/// Uses a basic but deterministic algorithm suitable for content addressing
fn hash_content(data: &[u8]) -> String {
    // Simple hash implementation (in production, use proper Blake3)
    let mut hash: [u8; 32] = [0; 32];
    let mut state: u64 = 0x6a09e667f3bcc908;
    
    for (i, &byte) in data.iter().enumerate() {
        state = state.wrapping_mul(0x5851f42d4c957f2d);
        state = state.wrapping_add(byte as u64);
        state ^= state >> 33;
        hash[i % 32] ^= (state & 0xff) as u8;
        hash[(i + 7) % 32] ^= ((state >> 8) & 0xff) as u8;
        hash[(i + 13) % 32] ^= ((state >> 16) & 0xff) as u8;
        hash[(i + 19) % 32] ^= ((state >> 24) & 0xff) as u8;
    }
    
    // Add length mixing
    let len = data.len() as u64;
    for i in 0..8 {
        hash[24 + i] ^= ((len >> (i * 8)) & 0xff) as u8;
    }
    
    // Convert to base32-like string (similar to CIDv1)
    let alphabet = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut result = String::from("bafk"); // CIDv1 prefix
    
    // Encode 32 bytes to ~52 base32 characters
    let mut bits: u64 = 0;
    let mut num_bits = 0;
    
    for &byte in &hash {
        bits = (bits << 8) | (byte as u64);
        num_bits += 8;
        
        while num_bits >= 5 {
            num_bits -= 5;
            let idx = ((bits >> num_bits) & 0x1f) as usize;
            result.push(alphabet[idx] as char);
        }
    }
    
    if num_bits > 0 {
        let idx = ((bits << (5 - num_bits)) & 0x1f) as usize;
        result.push(alphabet[idx] as char);
    }
    
    result
}

/// Base64 encode
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).map(|&b| b as u32).unwrap_or(0);
        let b2 = chunk.get(2).map(|&b| b as u32).unwrap_or(0);
        
        let n = (b0 << 16) | (b1 << 8) | b2;
        
        result.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        result.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        
        if chunk.len() > 1 {
            result.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        } else {
            result.push('=');
        }
        
        if chunk.len() > 2 {
            result.push(ALPHABET[(n & 0x3f) as usize] as char);
        } else {
            result.push('=');
        }
    }
    
    result
}

/// Base64 decode
fn base64_decode(data: &str) -> Option<Vec<u8>> {
    const DECODE: [i8; 128] = [
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    ];
    
    let mut result = Vec::new();
    let bytes: Vec<u8> = data.bytes().filter(|&b| b != b'=').collect();
    
    for chunk in bytes.chunks(4) {
        if chunk.len() < 2 { break; }
        
        let b0 = DECODE.get(chunk[0] as usize).copied().unwrap_or(-1);
        let b1 = DECODE.get(chunk[1] as usize).copied().unwrap_or(-1);
        let b2 = chunk.get(2).and_then(|&b| DECODE.get(b as usize).copied()).unwrap_or(0);
        let b3 = chunk.get(3).and_then(|&b| DECODE.get(b as usize).copied()).unwrap_or(0);
        
        if b0 < 0 || b1 < 0 { return None; }
        
        let n = ((b0 as u32) << 18) | ((b1 as u32) << 12) | ((b2 as u32) << 6) | (b3 as u32);
        
        result.push(((n >> 16) & 0xff) as u8);
        if chunk.len() > 2 && b2 >= 0 {
            result.push(((n >> 8) & 0xff) as u8);
        }
        if chunk.len() > 3 && b3 >= 0 {
            result.push((n & 0xff) as u8);
        }
    }
    
    Some(result)
}

/// Generate a simple node ID
fn generate_node_id() -> String {
    // In production, this would use proper key generation
    let state = get_state();
    let seed = state.blocks.len() as u64 * 0x5851f42d4c957f2d;
    format!("12D3KooW{:016x}{:016x}", seed, seed.wrapping_mul(0x6a09e667f3bcc908))
}

// ============================================================================
// Host Call Types (Minimal - only for persistence)
// ============================================================================

/// Host call for runtime to execute
/// These are minimal - just for persisting state to disk
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum HostCall {
    /// Persist module state to storage
    PersistState { 
        key: String,
        value: String,
    },
    /// Load module state from storage
    LoadState {
        key: String,
    },
    /// Notify peers of new content (optional gossip)
    AnnounceContent {
        cid: String,
    },
    /// Request content from peers (optional)
    RequestContent {
        cid: String,
    },
}

// ============================================================================
// Request Types
// ============================================================================

#[derive(Deserialize)]
struct HandleRequest {
    operation: String,
    params: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddRequest {
    content: String,
    #[serde(default)]
    base64: bool,
    filename: Option<String>,
    content_type: Option<String>,
    #[serde(default = "default_true")]
    pin: bool,
    #[serde(default)]
    incentivize: bool,
    #[serde(default)]
    tier: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetRequest {
    cid: String,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    length: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PinRequest {
    cid: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default = "default_true")]
    recursive: bool,
    #[serde(default)]
    incentivize: bool,
    #[serde(default)]
    tier: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IncentivizeRequest {
    cid: String,
    #[serde(default = "default_min_replicas")]
    min_replicas: u32,
    reward_per_epoch: u64,
    reward_pool: u64,
    #[serde(default)]
    tier: Option<String>,
    #[serde(default)]
    expires_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeRequest {
    cid: String,
    offset: u64,
    length: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StartNodeRequest {
    validator_id: Option<String>,
    #[serde(default = "default_max_storage")]
    max_storage_gb: u64,
    #[serde(default)]
    auto_pin_incentivized: bool,
}

fn default_true() -> bool { true }
fn default_min_replicas() -> u32 { 3 }
fn default_max_storage() -> u64 { 100 }

// ============================================================================
// Module Entry Points
// ============================================================================

#[derive(Serialize)]
struct ModuleInfo {
    module: &'static str,
    version: &'static str,
    status: &'static str,
    description: &'static str,
    capabilities: Vec<&'static str>,
    self_contained: bool,
}

#[no_mangle]
pub extern "C" fn get_info(_input_ptr: i32, _input_len: i32) -> i32 {
    let info = ModuleInfo {
        module: "cryft_ipfs",
        version: "3.0.0",
        status: "operational",
        description: "Self-contained IPFS module with in-memory CAS. No external daemon required.",
        self_contained: true,
        capabilities: vec![
            // Node lifecycle
            "start_node",
            "stop_node",
            "status",
            // Content operations (self-contained)
            "add",
            "cat",
            "get",
            "stat",
            "ls",
            // Pin management (in-module)
            "pin",
            "unpin",
            "pin_ls",
            // Repo info
            "repo_stat",
            "repo_gc",
            // Validator rewards
            "validator_stats",
            "list_incentivized",
            "incentivize",
            "challenge",
            "submit_proof",
            "claim_rewards",
        ],
    };
    
    let json = serde_json::to_string(&info).unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string());
    set_output(json.as_bytes());
    0
}

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
        // Node lifecycle
        "start_node" | "start" => handle_start_node(&params),
        "stop_node" | "stop" => handle_stop_node(),
        "status" | "node_status" => handle_status(),
        
        // Content operations (self-contained!)
        "add" | "ipfs_add" => handle_add(&params),
        "cat" | "get" | "ipfs_cat" | "ipfs_get" => handle_get(&params),
        "stat" | "ipfs_stat" => handle_stat(&params),
        "ls" | "ipfs_ls" => handle_ls(&params),
        
        // Pin management (in-module)
        "pin" | "ipfs_pin" => handle_pin(&params),
        "unpin" | "ipfs_unpin" => handle_unpin(&params),
        "pin_ls" | "list_pins" => handle_pin_ls(&params),
        
        // Repo info
        "repo_stat" => handle_repo_stat(),
        "repo_gc" | "gc" => handle_repo_gc(),
        
        // Validator rewards
        "validator_stats" | "stats" => handle_validator_stats(),
        "list_incentivized" | "incentivized_list" => handle_list_incentivized(),
        "incentivize" | "incentivize_pin" => handle_incentivize(&params),
        "challenge" | "storage_challenge" => handle_challenge(&params),
        "submit_proof" | "prove" => handle_submit_proof(&params),
        "claim_rewards" | "claim" => handle_claim_rewards(),
        
        _ => format!(r#"{{"success":false,"error":"Unknown operation: {}"}}"#, request.operation),
    };
    
    set_output(result.as_bytes());
    0
}

// ============================================================================
// Node Lifecycle Handlers
// ============================================================================

fn handle_start_node(params: &serde_json::Value) -> String {
    let req: StartNodeRequest = serde_json::from_value(params.clone()).unwrap_or(StartNodeRequest {
        validator_id: None,
        max_storage_gb: 100,
        auto_pin_incentivized: true,
    });
    
    let state = get_state();
    
    // Generate node ID if not set
    if state.node_id.is_empty() {
        state.node_id = generate_node_id();
    }
    
    // Update config
    state.config.validator_id = req.validator_id.clone();
    state.config.max_storage_gb = req.max_storage_gb;
    state.config.auto_pin_incentivized = req.auto_pin_incentivized;
    state.max_storage = req.max_storage_gb * 1024 * 1024 * 1024;
    
    // Update validator stats
    if let Some(ref vid) = req.validator_id {
        state.validator_stats.validator_id = vid.clone();
    }
    
    state.running = true;
    
    serde_json::to_string(&serde_json::json!({
        "success": true,
        "node_id": state.node_id,
        "validator_id": state.config.validator_id,
        "max_storage_gb": state.config.max_storage_gb,
        "storage_used": state.storage_used,
        "blocks_stored": state.blocks.len(),
        "pins_count": state.pins.len(),
        "message": "CryftIPFS node started (self-contained mode)"
    })).unwrap_or_default()
}

fn handle_stop_node() -> String {
    let state = get_state();
    state.running = false;
    
    // Request persistence before stopping
    let persist_call = HostCall::PersistState {
        key: "ipfs_state".to_string(),
        value: serde_json::to_string(state).unwrap_or_default(),
    };
    
    serde_json::to_string(&serde_json::json!({
        "success": true,
        "host_call": persist_call,
        "message": "CryftIPFS node stopped"
    })).unwrap_or_default()
}

fn handle_status() -> String {
    let state = get_state();
    
    serde_json::to_string(&serde_json::json!({
        "success": true,
        "online": state.running,
        "node_id": state.node_id,
        "version": "3.0.0",
        "mode": "self-contained",
        "blocks_stored": state.blocks.len(),
        "pins_count": state.pins.len(),
        "incentivized_pins": state.incentivized.len(),
        "storage_used": state.storage_used,
        "storage_used_mb": state.storage_used / (1024 * 1024),
        "max_storage_gb": state.config.max_storage_gb,
        "validator_id": state.config.validator_id,
        "pending_rewards": state.validator_stats.pending_rewards,
    })).unwrap_or_default()
}

// ============================================================================
// Content Handlers (Self-Contained!)
// ============================================================================

fn handle_add(params: &serde_json::Value) -> String {
    let req: AddRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid request: {}"}}"#, e),
    };
    
    let state = get_state();
    
    if !state.running {
        return r#"{"success":false,"error":"Node not running. Call start_node first."}"#.to_string();
    }
    
    // Decode content
    let raw_data = if req.base64 {
        match base64_decode(&req.content) {
            Some(d) => d,
            None => return r#"{"success":false,"error":"Invalid base64 content"}"#.to_string(),
        }
    } else {
        req.content.as_bytes().to_vec()
    };
    
    let size = raw_data.len();
    
    // Check storage limit
    if state.storage_used + size as u64 > state.max_storage {
        return r#"{"success":false,"error":"Storage limit exceeded"}"#.to_string();
    }
    
    // Generate CID from content hash
    let cid = hash_content(&raw_data);
    
    // Store the block
    let block = ContentBlock {
        data: base64_encode(&raw_data),
        size,
        links: Vec::new(),
        filename: req.filename.clone(),
        content_type: req.content_type,
        created_at: 0, // Would be set by host
    };
    
    state.blocks.insert(cid.clone(), block);
    state.storage_used += size as u64;
    
    // Auto-pin if requested
    if req.pin {
        let pin_entry = PinEntry {
            cid: cid.clone(),
            name: req.filename.clone(),
            recursive: true,
            incentivized: req.incentivize,
            tier: req.tier.clone(),
            pinned_at: 0,
        };
        state.pins.insert(cid.clone(), pin_entry);
        
        if req.incentivize {
            state.validator_stats.incentivized_pins += 1;
        }
    }
    
    // Announce to peers (optional)
    let announce_call = HostCall::AnnounceContent { cid: cid.clone() };
    
    serde_json::to_string(&serde_json::json!({
        "success": true,
        "cid": cid,
        "size": size,
        "pinned": req.pin,
        "incentivized": req.incentivize,
        "filename": req.filename,
        "host_call": announce_call,
        "gateway_url": format!("{}/ipfs/{}", state.config.public_gateway, cid)
    })).unwrap_or_default()
}

fn handle_get(params: &serde_json::Value) -> String {
    let req: GetRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid request: {}"}}"#, e),
    };
    
    let state = get_state();
    
    // Look up block locally
    if let Some(block) = state.blocks.get(&req.cid) {
        let full_data = match base64_decode(&block.data) {
            Some(d) => d,
            None => return r#"{"success":false,"error":"Corrupted block data"}"#.to_string(),
        };
        
        // Apply offset/length if specified
        let data = match (req.offset, req.length) {
            (Some(off), Some(len)) => {
                let end = core::cmp::min(off + len, full_data.len());
                if off >= full_data.len() {
                    Vec::new()
                } else {
                    full_data[off..end].to_vec()
                }
            }
            (Some(off), None) => {
                if off >= full_data.len() {
                    Vec::new()
                } else {
                    full_data[off..].to_vec()
                }
            }
            (None, Some(len)) => {
                full_data[..core::cmp::min(len, full_data.len())].to_vec()
            }
            (None, None) => full_data,
        };
        
        serde_json::to_string(&serde_json::json!({
            "success": true,
            "cid": req.cid,
            "data": base64_encode(&data),
            "size": data.len(),
            "total_size": block.size,
            "filename": block.filename,
            "content_type": block.content_type
        })).unwrap_or_default()
    } else {
        // Content not found locally - could request from peers
        let request_call = HostCall::RequestContent { cid: req.cid.clone() };
        
        serde_json::to_string(&serde_json::json!({
            "success": false,
            "error": "Content not found locally",
            "cid": req.cid,
            "host_call": request_call,
            "hint": "Content may be available from network peers"
        })).unwrap_or_default()
    }
}

fn handle_stat(params: &serde_json::Value) -> String {
    let cid = params.get("cid").and_then(|v| v.as_str()).unwrap_or("");
    
    if cid.is_empty() {
        return r#"{"success":false,"error":"CID is required"}"#.to_string();
    }
    
    let state = get_state();
    
    if let Some(block) = state.blocks.get(cid) {
        let is_pinned = state.pins.contains_key(cid);
        let pin_info = state.pins.get(cid);
        
        serde_json::to_string(&serde_json::json!({
            "success": true,
            "cid": cid,
            "size": block.size,
            "links": block.links.len(),
            "filename": block.filename,
            "content_type": block.content_type,
            "created_at": block.created_at,
            "pinned": is_pinned,
            "incentivized": pin_info.map(|p| p.incentivized).unwrap_or(false),
            "tier": pin_info.and_then(|p| p.tier.clone())
        })).unwrap_or_default()
    } else {
        serde_json::to_string(&serde_json::json!({
            "success": false,
            "error": "Content not found",
            "cid": cid
        })).unwrap_or_default()
    }
}

fn handle_ls(params: &serde_json::Value) -> String {
    let cid = params.get("cid").and_then(|v| v.as_str()).unwrap_or("");
    
    let state = get_state();
    
    if cid.is_empty() {
        // List all stored CIDs
        let entries: Vec<_> = state.blocks.iter().map(|(cid, block)| {
            serde_json::json!({
                "cid": cid,
                "size": block.size,
                "filename": block.filename
            })
        }).collect();
        
        serde_json::to_string(&serde_json::json!({
            "success": true,
            "entries": entries,
            "count": entries.len()
        })).unwrap_or_default()
    } else if let Some(block) = state.blocks.get(cid) {
        // List links of a specific CID
        serde_json::to_string(&serde_json::json!({
            "success": true,
            "cid": cid,
            "links": block.links,
            "size": block.size
        })).unwrap_or_default()
    } else {
        serde_json::to_string(&serde_json::json!({
            "success": false,
            "error": "Content not found",
            "cid": cid
        })).unwrap_or_default()
    }
}

// ============================================================================
// Pin Management Handlers
// ============================================================================

fn handle_pin(params: &serde_json::Value) -> String {
    let req: PinRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid request: {}"}}"#, e),
    };
    
    let state = get_state();
    
    // Check if content exists
    if !state.blocks.contains_key(&req.cid) {
        return serde_json::to_string(&serde_json::json!({
            "success": false,
            "error": "Content not found. Add content first before pinning.",
            "cid": req.cid
        })).unwrap_or_default();
    }
    
    let pin_entry = PinEntry {
        cid: req.cid.clone(),
        name: req.name.clone(),
        recursive: req.recursive,
        incentivized: req.incentivize,
        tier: req.tier.clone(),
        pinned_at: 0,
    };
    
    let was_pinned = state.pins.contains_key(&req.cid);
    state.pins.insert(req.cid.clone(), pin_entry);
    
    if req.incentivize && !was_pinned {
        state.validator_stats.incentivized_pins += 1;
    }
    
    serde_json::to_string(&serde_json::json!({
        "success": true,
        "cid": req.cid,
        "pinned": true,
        "incentivized": req.incentivize,
        "tier": req.tier,
        "name": req.name
    })).unwrap_or_default()
}

fn handle_unpin(params: &serde_json::Value) -> String {
    let cid = params.get("cid").and_then(|v| v.as_str()).unwrap_or("");
    
    if cid.is_empty() {
        return r#"{"success":false,"error":"CID is required"}"#.to_string();
    }
    
    let state = get_state();
    
    if let Some(pin) = state.pins.remove(cid) {
        if pin.incentivized && state.validator_stats.incentivized_pins > 0 {
            state.validator_stats.incentivized_pins -= 1;
        }
        
        serde_json::to_string(&serde_json::json!({
            "success": true,
            "cid": cid,
            "unpinned": true
        })).unwrap_or_default()
    } else {
        serde_json::to_string(&serde_json::json!({
            "success": false,
            "error": "CID not pinned",
            "cid": cid
        })).unwrap_or_default()
    }
}

fn handle_pin_ls(params: &serde_json::Value) -> String {
    let pin_type = params.get("type").and_then(|v| v.as_str()).unwrap_or("all");
    let incentivized_only = params.get("incentivizedOnly").and_then(|v| v.as_bool()).unwrap_or(false);
    
    let state = get_state();
    
    let pins: Vec<_> = state.pins.iter()
        .filter(|(_, pin)| {
            if incentivized_only && !pin.incentivized {
                return false;
            }
            match pin_type {
                "recursive" => pin.recursive,
                "direct" => !pin.recursive,
                _ => true,
            }
        })
        .map(|(cid, pin)| {
            serde_json::json!({
                "cid": cid,
                "type": if pin.recursive { "recursive" } else { "direct" },
                "name": pin.name,
                "incentivized": pin.incentivized,
                "tier": pin.tier
            })
        })
        .collect();
    
    serde_json::to_string(&serde_json::json!({
        "success": true,
        "pins": pins,
        "count": pins.len()
    })).unwrap_or_default()
}

// ============================================================================
// Repo Handlers
// ============================================================================

fn handle_repo_stat() -> String {
    let state = get_state();
    
    serde_json::to_string(&serde_json::json!({
        "success": true,
        "num_objects": state.blocks.len(),
        "repo_size": state.storage_used,
        "repo_size_mb": state.storage_used / (1024 * 1024),
        "max_storage_gb": state.config.max_storage_gb,
        "storage_percent": if state.max_storage > 0 {
            (state.storage_used as f64 / state.max_storage as f64 * 100.0) as u32
        } else { 0 },
        "pins_count": state.pins.len()
    })).unwrap_or_default()
}

fn handle_repo_gc() -> String {
    let state = get_state();
    
    // Find unpinned blocks
    let pinned_cids: Vec<_> = state.pins.keys().cloned().collect();
    let all_cids: Vec<_> = state.blocks.keys().cloned().collect();
    
    let mut removed = 0;
    let mut freed = 0u64;
    
    for cid in all_cids {
        if !pinned_cids.contains(&cid) {
            if let Some(block) = state.blocks.remove(&cid) {
                freed += block.size as u64;
                removed += 1;
            }
        }
    }
    
    state.storage_used = state.storage_used.saturating_sub(freed);
    
    serde_json::to_string(&serde_json::json!({
        "success": true,
        "removed": removed,
        "freed_bytes": freed,
        "freed_mb": freed / (1024 * 1024),
        "remaining_objects": state.blocks.len()
    })).unwrap_or_default()
}

// ============================================================================
// Validator Reward Handlers
// ============================================================================

fn handle_validator_stats() -> String {
    let state = get_state();
    
    serde_json::to_string(&serde_json::json!({
        "success": true,
        "validator_id": state.validator_stats.validator_id,
        "pending_rewards": state.validator_stats.pending_rewards,
        "claimed_rewards": state.validator_stats.claimed_rewards,
        "proofs_submitted": state.validator_stats.proofs_submitted,
        "incentivized_pins": state.validator_stats.incentivized_pins,
        "storage_used": state.storage_used,
        "last_proof_at": state.validator_stats.last_proof_at
    })).unwrap_or_default()
}

fn handle_list_incentivized() -> String {
    let state = get_state();
    
    let list: Vec<_> = state.incentivized.values().map(|inc| {
        serde_json::json!({
            "cid": inc.cid,
            "sponsor": inc.sponsor,
            "tier": inc.tier,
            "reward_per_epoch": inc.reward_per_epoch,
            "reward_pool": inc.reward_pool,
            "min_replicas": inc.min_replicas,
            "current_replicas": inc.current_replicas,
            "expires_at": inc.expires_at
        })
    }).collect();
    
    serde_json::to_string(&serde_json::json!({
        "success": true,
        "incentivized": list,
        "count": list.len()
    })).unwrap_or_default()
}

fn handle_incentivize(params: &serde_json::Value) -> String {
    let req: IncentivizeRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid request: {}"}}"#, e),
    };
    
    if req.reward_pool == 0 {
        return r#"{"success":false,"error":"Reward pool must be greater than 0"}"#.to_string();
    }
    
    let state = get_state();
    
    let inc_pin = IncentivizedPin {
        cid: req.cid.clone(),
        sponsor: state.config.validator_id.clone().unwrap_or_default(),
        min_replicas: req.min_replicas,
        reward_per_epoch: req.reward_per_epoch,
        reward_pool: req.reward_pool,
        tier: req.tier.clone().unwrap_or_else(|| "standard".to_string()),
        expires_at: req.expires_at,
        current_replicas: 0,
        pinners: Vec::new(),
        created_at: 0,
    };
    
    state.incentivized.insert(req.cid.clone(), inc_pin);
    
    serde_json::to_string(&serde_json::json!({
        "success": true,
        "cid": req.cid,
        "tier": req.tier.unwrap_or_else(|| "standard".to_string()),
        "reward_pool": req.reward_pool,
        "min_replicas": req.min_replicas,
        "message": "Incentivized pin registered"
    })).unwrap_or_default()
}

fn handle_challenge(params: &serde_json::Value) -> String {
    let req: ChallengeRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid request: {}"}}"#, e),
    };
    
    let state = get_state();
    
    // Check if we have the content
    if let Some(block) = state.blocks.get(&req.cid) {
        let data = match base64_decode(&block.data) {
            Some(d) => d,
            None => return r#"{"success":false,"error":"Corrupted block data"}"#.to_string(),
        };
        
        // Extract the challenged chunk
        let offset = req.offset as usize;
        let length = req.length as usize;
        
        if offset >= data.len() {
            return r#"{"success":false,"error":"Offset exceeds content size"}"#.to_string();
        }
        
        let end = core::cmp::min(offset + length, data.len());
        let chunk = &data[offset..end];
        
        // Hash the chunk as proof
        let chunk_hash = hash_content(chunk);
        
        // Create proof
        let challenge_id = format!("challenge-{}-{}", req.cid, offset);
        let proof = StorageProof {
            challenge_id: challenge_id.clone(),
            cid: req.cid.clone(),
            validator_id: state.validator_stats.validator_id.clone(),
            chunk_hash,
            proven_at: 0,
            signature: String::new(), // Would be signed by validator key
        };
        
        serde_json::to_string(&serde_json::json!({
            "success": true,
            "challenge_id": challenge_id,
            "proof": proof,
            "message": "Challenge completed - proof generated"
        })).unwrap_or_default()
    } else {
        serde_json::to_string(&serde_json::json!({
            "success": false,
            "error": "Content not found - cannot prove storage",
            "cid": req.cid
        })).unwrap_or_default()
    }
}

fn handle_submit_proof(params: &serde_json::Value) -> String {
    let proof: StorageProof = match serde_json::from_value(params.clone()) {
        Ok(p) => p,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid proof: {}"}}"#, e),
    };
    
    let state = get_state();
    
    state.pending_proofs.push(proof.clone());
    state.validator_stats.proofs_submitted += 1;
    
    // Award pending rewards (simplified - would verify proof in production)
    if let Some(inc) = state.incentivized.get(&proof.cid) {
        state.validator_stats.pending_rewards += inc.reward_per_epoch;
    }
    
    serde_json::to_string(&serde_json::json!({
        "success": true,
        "challenge_id": proof.challenge_id,
        "proofs_submitted": state.validator_stats.proofs_submitted,
        "pending_rewards": state.validator_stats.pending_rewards,
        "message": "Proof submitted and rewards credited"
    })).unwrap_or_default()
}

fn handle_claim_rewards() -> String {
    let state = get_state();
    
    let pending = state.validator_stats.pending_rewards;
    
    if pending == 0 {
        return r#"{"success":false,"error":"No pending rewards to claim"}"#.to_string();
    }
    
    state.validator_stats.claimed_rewards += pending;
    state.validator_stats.pending_rewards = 0;
    state.pending_proofs.clear();
    
    serde_json::to_string(&serde_json::json!({
        "success": true,
        "claimed": pending,
        "total_claimed": state.validator_stats.claimed_rewards,
        "message": format!("Claimed {} nCRYFT", pending)
    })).unwrap_or_default()
}
