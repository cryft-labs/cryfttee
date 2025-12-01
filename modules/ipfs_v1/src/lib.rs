//! CryftIPFS Module - Unified IPFS with Validator Pin Rewards
//!
//! A decentralized storage network where validators earn rewards for pinning
//! content that is registered on the Cryft blockchain.
//!
//! Architecture:
//! - This WASM module handles request validation and state management
//! - The `native/cryft-ipfs` binary provides the actual IPFS node + reward tracking
//! - Validators pin incentivized content → pass storage challenges → earn CRYFT
//!
//! Key Features:
//! - Standard IPFS operations (add, cat, pin, etc.)
//! - Incentivized pin registry (blockchain-backed)
//! - Proof-of-storage challenges
//! - Reward claims for validators

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
// Configuration
// ============================================================================

/// Module configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleConfig {
    /// API URL (default: http://127.0.0.1:5001)
    #[serde(default = "default_api_url")]
    pub api_url: String,
    
    /// Gateway URL (default: http://127.0.0.1:8080)
    #[serde(default = "default_gateway_url")]
    pub gateway_url: String,
    
    /// Public gateway for shareable URLs
    #[serde(default = "default_public_gateway")]
    pub public_gateway: String,
    
    /// Validator node ID (for reward tracking)
    pub validator_id: Option<String>,
    
    /// Blockchain RPC URL
    #[serde(default = "default_rpc_url")]
    pub rpc_url: String,
    
    /// Max storage in GB
    #[serde(default = "default_max_storage")]
    pub max_storage_gb: u64,
}

fn default_api_url() -> String { "http://127.0.0.1:5001".to_string() }
fn default_gateway_url() -> String { "http://127.0.0.1:8080".to_string() }
fn default_public_gateway() -> String { "https://ipfs.cryft.network".to_string() }
fn default_rpc_url() -> String { "http://127.0.0.1:9650".to_string() }
fn default_max_storage() -> u64 { 100 }

impl Default for ModuleConfig {
    fn default() -> Self {
        Self {
            api_url: default_api_url(),
            gateway_url: default_gateway_url(),
            public_gateway: default_public_gateway(),
            validator_id: None,
            rpc_url: default_rpc_url(),
            max_storage_gb: default_max_storage(),
        }
    }
}

// ============================================================================
// Host Call Types
// ============================================================================

/// Host call for runtime to execute
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum HostCall {
    /// Start the IPFS node
    StartNode { config: ModuleConfig },
    /// Stop the IPFS node
    StopNode,
    /// HTTP request to IPFS API
    HttpRequest { 
        method: String,
        path: String,
        query: BTreeMap<String, String>,
        body: Option<String>,
    },
}

// ============================================================================
// Reward System Types
// ============================================================================

/// Reward tier for incentivized pins
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RewardTier {
    Basic,
    Standard,
    Priority,
    Critical,
}

/// Request to register an incentivized pin
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IncentivizeRequest {
    /// Content CID to incentivize
    pub cid: String,
    /// Minimum replicas required
    #[serde(default = "default_min_replicas")]
    pub min_replicas: u32,
    /// Reward per epoch in nCRYFT
    pub reward_per_epoch: u64,
    /// Reward tier
    #[serde(default)]
    pub tier: Option<String>,
    /// Expiration timestamp (0 = never)
    #[serde(default)]
    pub expires_at: u64,
    /// Total reward pool
    pub reward_pool: u64,
}

fn default_min_replicas() -> u32 { 3 }

/// Storage challenge request
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeRequest {
    /// CID to challenge
    pub cid: String,
    /// Byte offset for proof
    pub offset: u64,
    /// Number of bytes to prove
    pub length: u32,
}

/// Storage proof response
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageProof {
    pub challenge_id: String,
    pub cid: String,
    pub validator_id: String,
    pub chunk_hash: String,
    pub proven_at: u64,
    pub signature: String,
}

// ============================================================================
// Standard IPFS Request Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PinRequest {
    pub cid: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default = "default_true")]
    pub recursive: bool,
    /// Mark as incentivized pin
    #[serde(default)]
    pub incentivize: bool,
    /// Reward tier
    #[serde(default)]
    pub tier: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnpinRequest {
    pub cid: String,
    #[serde(default = "default_true")]
    pub recursive: bool,
}

fn default_true() -> bool { true }

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddRequest {
    pub content: String,
    #[serde(default)]
    pub base64: bool,
    pub filename: Option<String>,
    #[serde(default = "default_true")]
    pub pin: bool,
    #[serde(default)]
    pub incentivize: bool,
    #[serde(default)]
    pub tier: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRequest {
    pub cid: String,
    #[serde(default)]
    pub offset: Option<u64>,
    #[serde(default)]
    pub length: Option<u64>,
}

// ============================================================================
// Request Handler
// ============================================================================

#[derive(Deserialize)]
struct HandleRequest {
    operation: String,
    params: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct ModuleInfo {
    module: &'static str,
    version: &'static str,
    status: &'static str,
    description: &'static str,
    capabilities: Vec<&'static str>,
    native_binary: &'static str,
}

// ============================================================================
// Module Entry Points
// ============================================================================

#[no_mangle]
pub extern "C" fn get_info(_input_ptr: i32, _input_len: i32) -> i32 {
    let info = ModuleInfo {
        module: "cryft_ipfs",
        version: "2.0.0",
        status: "operational",
        description: "CryftIPFS - Unified IPFS with Validator Pin Rewards. Validators earn CRYFT for pinning incentivized content.",
        native_binary: "native/cryft-ipfs",
        capabilities: vec![
            // Node lifecycle
            "node_start",
            "node_stop",
            "node_status",
            // Standard IPFS
            "ipfs_add",
            "ipfs_cat",
            "ipfs_get",
            "ipfs_pin",
            "ipfs_unpin",
            "ipfs_pin_ls",
            "ipfs_stat",
            // Swarm
            "swarm_peers",
            "swarm_connect",
            // Repo
            "repo_stat",
            "repo_gc",
            // === VALIDATOR REWARDS ===
            "validator_stats",
            "incentivized_list",
            "incentivize_pin",
            "storage_challenge",
            "submit_proof",
            "claim_rewards",
            "list_proofs",
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
        "node_start" | "start_node" => handle_start_node(&params),
        "node_stop" | "stop_node" => handle_stop_node(),
        "node_status" | "status" => handle_status(),
        
        // Standard IPFS operations
        "ipfs_add" | "add" => handle_add(&params),
        "ipfs_cat" | "cat" | "ipfs_get" | "get" => handle_get(&params),
        "ipfs_pin" | "pin" => handle_pin(&params),
        "ipfs_unpin" | "unpin" => handle_unpin(&params),
        "ipfs_pin_ls" | "pin_ls" | "list_pins" => handle_pin_ls(&params),
        "ipfs_stat" | "stat" => handle_stat(&params),
        
        // Swarm
        "swarm_peers" | "peers" => handle_swarm_peers(),
        "swarm_connect" | "connect" => handle_swarm_connect(&params),
        
        // Repo
        "repo_stat" => handle_repo_stat(),
        "repo_gc" | "gc" => handle_repo_gc(),
        
        // === VALIDATOR REWARD OPERATIONS ===
        "validator_stats" | "stats" => handle_validator_stats(),
        "incentivized_list" | "list_incentivized" => handle_list_incentivized(),
        "incentivize_pin" | "incentivize" => handle_incentivize(&params),
        "storage_challenge" | "challenge" => handle_challenge(&params),
        "submit_proof" | "prove" => handle_submit_proof(&params),
        "claim_rewards" | "claim" => handle_claim_rewards(),
        "list_proofs" | "proofs" => handle_list_proofs(),
        
        _ => format!(r#"{{"success":false,"error":"Unknown operation: {}"}}"#, request.operation),
    };
    
    set_output(result.as_bytes());
    0
}

// ============================================================================
// Node Lifecycle Handlers
// ============================================================================

fn handle_start_node(params: &serde_json::Value) -> String {
    let config: ModuleConfig = serde_json::from_value(params.clone()).unwrap_or_default();
    
    let host_call = HostCall::StartNode { config };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true,
        "message": "Starting CryftIPFS node..."
    })).unwrap_or_default()
}

fn handle_stop_node() -> String {
    let host_call = HostCall::StopNode;
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true,
        "message": "Stopping CryftIPFS node..."
    })).unwrap_or_default()
}

fn handle_status() -> String {
    let host_call = HostCall::HttpRequest {
        method: "GET".to_string(),
        path: "/api/v0/id".to_string(),
        query: BTreeMap::new(),
        body: None,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true
    })).unwrap_or_default()
}

// ============================================================================
// Standard IPFS Handlers
// ============================================================================

fn handle_add(params: &serde_json::Value) -> String {
    let req: AddRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid request: {}"}}"#, e),
    };
    
    let mut query = BTreeMap::new();
    query.insert("pin".to_string(), req.pin.to_string());
    if req.incentivize {
        query.insert("incentivize".to_string(), "true".to_string());
    }
    if let Some(tier) = &req.tier {
        query.insert("tier".to_string(), tier.clone());
    }
    
    let host_call = HostCall::HttpRequest {
        method: "POST".to_string(),
        path: "/api/v0/add".to_string(),
        query,
        body: Some(req.content),
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true,
        "message": "Adding content..."
    })).unwrap_or_default()
}

fn handle_get(params: &serde_json::Value) -> String {
    let req: GetRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid request: {}"}}"#, e),
    };
    
    if !is_valid_cid(&req.cid) {
        return r#"{"success":false,"error":"Invalid CID format"}"#.to_string();
    }
    
    let mut query = BTreeMap::new();
    query.insert("arg".to_string(), req.cid.clone());
    if let Some(offset) = req.offset {
        query.insert("offset".to_string(), offset.to_string());
    }
    if let Some(length) = req.length {
        query.insert("length".to_string(), length.to_string());
    }
    
    let host_call = HostCall::HttpRequest {
        method: "POST".to_string(),
        path: "/api/v0/cat".to_string(),
        query,
        body: None,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true,
        "cid": req.cid
    })).unwrap_or_default()
}

fn handle_pin(params: &serde_json::Value) -> String {
    let req: PinRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid request: {}"}}"#, e),
    };
    
    if !is_valid_cid(&req.cid) {
        return r#"{"success":false,"error":"Invalid CID format"}"#.to_string();
    }
    
    let mut query = BTreeMap::new();
    query.insert("arg".to_string(), req.cid.clone());
    query.insert("recursive".to_string(), req.recursive.to_string());
    if req.incentivize {
        query.insert("incentivize".to_string(), "true".to_string());
    }
    if let Some(tier) = &req.tier {
        query.insert("tier".to_string(), tier.clone());
    }
    
    let host_call = HostCall::HttpRequest {
        method: "POST".to_string(),
        path: "/api/v0/pin/add".to_string(),
        query,
        body: None,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true,
        "cid": req.cid,
        "incentivized": req.incentivize
    })).unwrap_or_default()
}

fn handle_unpin(params: &serde_json::Value) -> String {
    let req: UnpinRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid request: {}"}}"#, e),
    };
    
    if !is_valid_cid(&req.cid) {
        return r#"{"success":false,"error":"Invalid CID format"}"#.to_string();
    }
    
    let mut query = BTreeMap::new();
    query.insert("arg".to_string(), req.cid.clone());
    query.insert("recursive".to_string(), req.recursive.to_string());
    
    let host_call = HostCall::HttpRequest {
        method: "POST".to_string(),
        path: "/api/v0/pin/rm".to_string(),
        query,
        body: None,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true,
        "cid": req.cid
    })).unwrap_or_default()
}

fn handle_pin_ls(params: &serde_json::Value) -> String {
    let pin_type = params.get("type").and_then(|v| v.as_str()).unwrap_or("all");
    let incentivized_only = params.get("incentivizedOnly").and_then(|v| v.as_bool()).unwrap_or(false);
    
    let mut query = BTreeMap::new();
    query.insert("type".to_string(), pin_type.to_string());
    if incentivized_only {
        query.insert("incentivized_only".to_string(), "true".to_string());
    }
    
    let host_call = HostCall::HttpRequest {
        method: "POST".to_string(),
        path: "/api/v0/pin/ls".to_string(),
        query,
        body: None,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true
    })).unwrap_or_default()
}

fn handle_stat(params: &serde_json::Value) -> String {
    let cid = params.get("cid").and_then(|v| v.as_str()).unwrap_or("");
    
    if !is_valid_cid(cid) {
        return r#"{"success":false,"error":"Invalid CID format"}"#.to_string();
    }
    
    let mut query = BTreeMap::new();
    query.insert("arg".to_string(), cid.to_string());
    
    let host_call = HostCall::HttpRequest {
        method: "POST".to_string(),
        path: "/api/v0/object/stat".to_string(),
        query,
        body: None,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true
    })).unwrap_or_default()
}

fn handle_swarm_peers() -> String {
    let host_call = HostCall::HttpRequest {
        method: "POST".to_string(),
        path: "/api/v0/swarm/peers".to_string(),
        query: BTreeMap::new(),
        body: None,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true
    })).unwrap_or_default()
}

fn handle_swarm_connect(params: &serde_json::Value) -> String {
    let peer_addr = params.get("peerAddr").and_then(|v| v.as_str()).unwrap_or("");
    
    if peer_addr.is_empty() {
        return r#"{"success":false,"error":"Missing peerAddr"}"#.to_string();
    }
    
    let mut query = BTreeMap::new();
    query.insert("arg".to_string(), peer_addr.to_string());
    
    let host_call = HostCall::HttpRequest {
        method: "POST".to_string(),
        path: "/api/v0/swarm/connect".to_string(),
        query,
        body: None,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true
    })).unwrap_or_default()
}

fn handle_repo_stat() -> String {
    let host_call = HostCall::HttpRequest {
        method: "POST".to_string(),
        path: "/api/v0/repo/stat".to_string(),
        query: BTreeMap::new(),
        body: None,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true
    })).unwrap_or_default()
}

fn handle_repo_gc() -> String {
    let host_call = HostCall::HttpRequest {
        method: "POST".to_string(),
        path: "/api/v0/repo/gc".to_string(),
        query: BTreeMap::new(),
        body: None,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true
    })).unwrap_or_default()
}

// ============================================================================
// Validator Reward Handlers
// ============================================================================

/// Get validator node statistics
fn handle_validator_stats() -> String {
    let host_call = HostCall::HttpRequest {
        method: "GET".to_string(),
        path: "/api/v0/cryft/stats".to_string(),
        query: BTreeMap::new(),
        body: None,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true
    })).unwrap_or_default()
}

/// List all network-wide incentivized pins
fn handle_list_incentivized() -> String {
    let host_call = HostCall::HttpRequest {
        method: "GET".to_string(),
        path: "/api/v0/cryft/incentivized".to_string(),
        query: BTreeMap::new(),
        body: None,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true
    })).unwrap_or_default()
}

/// Register a new incentivized pin
fn handle_incentivize(params: &serde_json::Value) -> String {
    let req: IncentivizeRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid request: {}"}}"#, e),
    };
    
    if !is_valid_cid(&req.cid) {
        return r#"{"success":false,"error":"Invalid CID format"}"#.to_string();
    }
    
    if req.reward_pool == 0 {
        return r#"{"success":false,"error":"Reward pool must be greater than 0"}"#.to_string();
    }
    
    let body = serde_json::to_string(&serde_json::json!({
        "cid": req.cid,
        "min_replicas": req.min_replicas,
        "reward_per_epoch": req.reward_per_epoch,
        "tier": req.tier.unwrap_or_else(|| "standard".to_string()),
        "expires_at": req.expires_at,
        "reward_pool": req.reward_pool,
        "sponsor": "", // Would be set from wallet
        "current_replicas": 0,
        "pinners": []
    })).unwrap_or_default();
    
    let host_call = HostCall::HttpRequest {
        method: "POST".to_string(),
        path: "/api/v0/cryft/incentivize".to_string(),
        query: BTreeMap::new(),
        body: Some(body),
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true,
        "message": "Registering incentivized pin..."
    })).unwrap_or_default()
}

/// Respond to a storage challenge (proof of storage)
fn handle_challenge(params: &serde_json::Value) -> String {
    let req: ChallengeRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid request: {}"}}"#, e),
    };
    
    if !is_valid_cid(&req.cid) {
        return r#"{"success":false,"error":"Invalid CID format"}"#.to_string();
    }
    
    let mut query = BTreeMap::new();
    query.insert("cid".to_string(), req.cid.clone());
    query.insert("offset".to_string(), req.offset.to_string());
    query.insert("length".to_string(), req.length.to_string());
    
    let host_call = HostCall::HttpRequest {
        method: "POST".to_string(),
        path: "/api/v0/cryft/challenge".to_string(),
        query,
        body: None,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true,
        "cid": req.cid,
        "message": "Processing storage challenge..."
    })).unwrap_or_default()
}

/// Submit a storage proof
fn handle_submit_proof(params: &serde_json::Value) -> String {
    let proof: StorageProof = match serde_json::from_value(params.clone()) {
        Ok(p) => p,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid proof: {}"}}"#, e),
    };
    
    let body = serde_json::to_string(&proof).unwrap_or_default();
    
    let host_call = HostCall::HttpRequest {
        method: "POST".to_string(),
        path: "/api/v0/cryft/prove".to_string(),
        query: BTreeMap::new(),
        body: Some(body),
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true,
        "message": "Submitting storage proof..."
    })).unwrap_or_default()
}

/// Claim rewards for completed proofs
fn handle_claim_rewards() -> String {
    let host_call = HostCall::HttpRequest {
        method: "POST".to_string(),
        path: "/api/v0/cryft/claim".to_string(),
        query: BTreeMap::new(),
        body: None,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true,
        "message": "Claiming rewards..."
    })).unwrap_or_default()
}

/// List pending proofs
fn handle_list_proofs() -> String {
    let host_call = HostCall::HttpRequest {
        method: "GET".to_string(),
        path: "/api/v0/cryft/proofs".to_string(),
        query: BTreeMap::new(),
        body: None,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true
    })).unwrap_or_default()
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Validate CID format
fn is_valid_cid(cid: &str) -> bool {
    let cid = cid.trim_start_matches("/ipfs/");
    
    // CIDv0: Qm... (46 chars, base58btc)
    if cid.starts_with("Qm") && cid.len() == 46 {
        return cid.chars().all(|c| c.is_alphanumeric());
    }
    
    // CIDv1: bafy... bafk... (base32)
    if (cid.starts_with("bafy") || cid.starts_with("bafk") || cid.starts_with("bafz")) 
        && cid.len() >= 50 {
        return cid.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    }
    
    // Iroh blake3 hash format
    if cid.len() == 52 && cid.chars().all(|c| c.is_ascii_alphanumeric()) {
        return true;
    }
    
    false
}
