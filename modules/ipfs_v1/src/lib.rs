//! IPFS Module for CryftTEE
//!
//! Self-contained IPFS module with embedded Iroh node (default) or external kubo support.
//!
//! Architecture:
//! - This WASM module handles request validation and state management
//! - The `native/ipfs-node` binary runs as a subprocess providing the actual IPFS node
//! - Communication uses kubo-compatible HTTP API on localhost
//!
//! Node Options:
//! - **Iroh (default)**: Embedded `ipfs-node` binary, no external dependencies
//! - **Kubo (optional)**: Use existing kubo daemon if user prefers
//!
//! The module auto-detects: if kubo is already running on 5001, use it.
//! Otherwise, start the embedded Iroh-based node.

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

/// Backend type selection
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BackendType {
    /// Embedded Iroh node (default, ships with module)
    #[default]
    Iroh,
    /// External kubo daemon (user-provided)
    Kubo,
    /// Auto-detect: use kubo if running, else start iroh
    Auto,
}

/// Module configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleConfig {
    /// Backend: iroh (default), kubo, or auto
    #[serde(default)]
    pub backend: BackendType,
    
    /// API URL (default: http://127.0.0.1:5001)
    #[serde(default = "default_api_url")]
    pub api_url: String,
    
    /// Gateway URL (default: http://127.0.0.1:8080)
    #[serde(default = "default_gateway_url")]
    pub gateway_url: String,
    
    /// Public gateway for shareable URLs
    #[serde(default = "default_public_gateway")]
    pub public_gateway: String,
    
    /// Data directory for Iroh storage
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    
    /// Request timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_api_url() -> String { "http://127.0.0.1:5001".to_string() }
fn default_gateway_url() -> String { "http://127.0.0.1:8080".to_string() }
fn default_public_gateway() -> String { "https://gateway.cryft.network".to_string() }
fn default_data_dir() -> String { "~/.cryfttee/ipfs".to_string() }
fn default_timeout() -> u64 { 60 }

impl Default for ModuleConfig {
    fn default() -> Self {
        Self {
            backend: BackendType::Auto,
            api_url: default_api_url(),
            gateway_url: default_gateway_url(),
            public_gateway: default_public_gateway(),
            data_dir: default_data_dir(),
            timeout_secs: 60,
        }
    }
}

// ============================================================================
// Request/Response Types
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
    backend: &'static str,
    description: &'static str,
    capabilities: Vec<&'static str>,
    native_binary: &'static str,
}

/// Host call for runtime to execute
/// The runtime will forward these to the appropriate IPFS backend
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum HostCall {
    /// Start the IPFS node (spawns native binary or verifies kubo)
    StartNode { config: ModuleConfig },
    /// Stop the IPFS node
    StopNode,
    /// Check node status
    CheckStatus,
    /// HTTP request to IPFS API
    HttpRequest { 
        method: String,
        path: String,
        query: BTreeMap<String, String>,
        body: Option<String>,
    },
}

// ============================================================================
// Pin Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PinRequest {
    pub cid: String,
    pub name: Option<String>,
    #[serde(default = "default_true")]
    pub recursive: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnpinRequest {
    pub cid: String,
    #[serde(default = "default_true")]
    pub recursive: bool,
}

fn default_true() -> bool { true }

// ============================================================================
// Content Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddRequest {
    pub content: String,
    #[serde(default)]
    pub base64: bool,
    pub filename: Option<String>,
    #[serde(default = "default_true")]
    pub pin: bool,
    #[serde(default = "default_cid_version")]
    pub cid_version: u8,
    pub name: Option<String>,
}

fn default_cid_version() -> u8 { 1 }

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRequest {
    pub cid: String,
    #[serde(default)]
    pub base64_output: bool,
    pub max_size: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatRequest {
    pub cid: String,
}

// ============================================================================
// IPNS Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpnsPublishRequest {
    pub cid: String,
    #[serde(default = "default_key")]
    pub key: String,
    #[serde(default = "default_ttl")]
    pub ttl_secs: u64,
}

fn default_key() -> String { "self".to_string() }
fn default_ttl() -> u64 { 3600 }

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpnsResolveRequest {
    pub name: String,
    #[serde(default = "default_resolve_timeout")]
    pub timeout_secs: u64,
}

fn default_resolve_timeout() -> u64 { 60 }

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyGenRequest {
    pub name: String,
    #[serde(default = "default_key_type")]
    pub key_type: String,
}

fn default_key_type() -> String { "ed25519".to_string() }

// ============================================================================
// Swarm Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectPeerRequest {
    pub peer_addr: String,
}

// ============================================================================
// Module Entry Points
// ============================================================================

#[no_mangle]
pub extern "C" fn get_info(_input_ptr: i32, _input_len: i32) -> i32 {
    let info = ModuleInfo {
        module: "ipfs_v1",
        version: "2.0.0",
        status: "operational",
        backend: "auto",
        description: "Self-contained IPFS module - Embedded Iroh node (default) or external kubo",
        native_binary: "native/ipfs-node",
        capabilities: vec![
            // Node lifecycle
            "node_start",
            "node_stop",
            "node_status",
            "node_config",
            // Pin operations
            "ipfs_pin",
            "ipfs_unpin",
            "ipfs_pin_ls",
            // Content
            "ipfs_add",
            "ipfs_get",
            "ipfs_cat",
            "ipfs_stat",
            // IPNS
            "ipns_publish",
            "ipns_resolve",
            "ipns_key_gen",
            "ipns_key_list",
            // Swarm
            "swarm_connect",
            "swarm_peers",
            "swarm_addrs",
            // Repo
            "repo_stat",
            "repo_gc",
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
        "node_status" | "get_status" | "status" => handle_status(),
        "node_config" | "get_config" => handle_get_config(),
        "set_config" => handle_set_config(&params),
        
        // Pin operations
        "ipfs_pin" | "pin" => handle_pin(&params),
        "ipfs_unpin" | "unpin" => handle_unpin(&params),
        "ipfs_pin_ls" | "pin_ls" | "list_pins" => handle_pin_ls(&params),
        
        // Content operations
        "ipfs_add" | "add" => handle_add(&params),
        "ipfs_get" | "get" | "ipfs_cat" | "cat" => handle_get(&params),
        "ipfs_stat" | "stat" => handle_stat(&params),
        
        // IPNS
        "ipns_publish" => handle_ipns_publish(&params),
        "ipns_resolve" => handle_ipns_resolve(&params),
        "ipns_key_gen" | "key_gen" => handle_key_gen(&params),
        "ipns_key_list" | "key_list" => handle_key_list(),
        
        // Swarm
        "swarm_connect" | "connect" => handle_swarm_connect(&params),
        "swarm_peers" | "peers" => handle_swarm_peers(),
        "swarm_addrs" | "addrs" => handle_swarm_addrs(),
        
        // Repo
        "repo_stat" => handle_repo_stat(),
        "repo_gc" | "gc" => handle_repo_gc(),
        
        _ => format!(r#"{{"success":false,"error":"Unknown operation: {}"}}"#, request.operation),
    };
    
    set_output(result.as_bytes());
    0
}

// ============================================================================
// Handler Functions
// ============================================================================

fn handle_start_node(params: &serde_json::Value) -> String {
    let config: ModuleConfig = serde_json::from_value(params.clone()).unwrap_or_default();
    
    let host_call = HostCall::StartNode { config };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true,
        "message": "Starting IPFS node..."
    })).unwrap_or_default()
}

fn handle_stop_node() -> String {
    let host_call = HostCall::StopNode;
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true,
        "message": "Stopping IPFS node..."
    })).unwrap_or_default()
}

fn handle_status() -> String {
    let host_call = HostCall::HttpRequest {
        method: "POST".to_string(),
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

fn handle_get_config() -> String {
    // Return current default config
    let config = ModuleConfig::default();
    serde_json::to_string(&serde_json::json!({
        "success": true,
        "config": config
    })).unwrap_or_default()
}

fn handle_set_config(params: &serde_json::Value) -> String {
    let config: ModuleConfig = match serde_json::from_value(params.clone()) {
        Ok(c) => c,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid config: {}"}}"#, e),
    };
    
    serde_json::to_string(&serde_json::json!({
        "success": true,
        "config": config,
        "message": "Configuration updated (restart node to apply)"
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
        "cid": req.cid
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
    
    let mut query = BTreeMap::new();
    query.insert("type".to_string(), pin_type.to_string());
    
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

fn handle_add(params: &serde_json::Value) -> String {
    let req: AddRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid request: {}"}}"#, e),
    };
    
    let mut query = BTreeMap::new();
    query.insert("pin".to_string(), req.pin.to_string());
    query.insert("cid-version".to_string(), req.cid_version.to_string());
    
    // For add, we need to send content as multipart
    // The host will handle the actual multipart encoding
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

fn handle_stat(params: &serde_json::Value) -> String {
    let req: StatRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid request: {}"}}"#, e),
    };
    
    if !is_valid_cid(&req.cid) {
        return r#"{"success":false,"error":"Invalid CID format"}"#.to_string();
    }
    
    let mut query = BTreeMap::new();
    query.insert("arg".to_string(), req.cid.clone());
    
    let host_call = HostCall::HttpRequest {
        method: "POST".to_string(),
        path: "/api/v0/object/stat".to_string(),
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

fn handle_ipns_publish(params: &serde_json::Value) -> String {
    let req: IpnsPublishRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid request: {}"}}"#, e),
    };
    
    if !is_valid_cid(&req.cid) {
        return r#"{"success":false,"error":"Invalid CID format"}"#.to_string();
    }
    
    let mut query = BTreeMap::new();
    query.insert("arg".to_string(), format!("/ipfs/{}", req.cid));
    query.insert("key".to_string(), req.key);
    query.insert("ttl".to_string(), format!("{}s", req.ttl_secs));
    
    let host_call = HostCall::HttpRequest {
        method: "POST".to_string(),
        path: "/api/v0/name/publish".to_string(),
        query,
        body: None,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true
    })).unwrap_or_default()
}

fn handle_ipns_resolve(params: &serde_json::Value) -> String {
    let req: IpnsResolveRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid request: {}"}}"#, e),
    };
    
    let mut query = BTreeMap::new();
    query.insert("arg".to_string(), req.name);
    query.insert("timeout".to_string(), format!("{}s", req.timeout_secs));
    
    let host_call = HostCall::HttpRequest {
        method: "POST".to_string(),
        path: "/api/v0/name/resolve".to_string(),
        query,
        body: None,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true
    })).unwrap_or_default()
}

fn handle_key_gen(params: &serde_json::Value) -> String {
    let req: KeyGenRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid request: {}"}}"#, e),
    };
    
    let mut query = BTreeMap::new();
    query.insert("arg".to_string(), req.name);
    query.insert("type".to_string(), req.key_type);
    
    let host_call = HostCall::HttpRequest {
        method: "POST".to_string(),
        path: "/api/v0/key/gen".to_string(),
        query,
        body: None,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true
    })).unwrap_or_default()
}

fn handle_key_list() -> String {
    let host_call = HostCall::HttpRequest {
        method: "POST".to_string(),
        path: "/api/v0/key/list".to_string(),
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
    let req: ConnectPeerRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid request: {}"}}"#, e),
    };
    
    let mut query = BTreeMap::new();
    query.insert("arg".to_string(), req.peer_addr);
    
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

fn handle_swarm_addrs() -> String {
    let host_call = HostCall::HttpRequest {
        method: "POST".to_string(),
        path: "/api/v0/swarm/addrs".to_string(),
        query: BTreeMap::new(),
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
        "pending": true,
        "message": "Starting garbage collection..."
    })).unwrap_or_default()
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Validate CID format (CIDv0 or CIDv1)
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
    
    // Iroh blake3 hash format (base32)
    if cid.len() == 52 && cid.chars().all(|c| c.is_ascii_alphanumeric()) {
        return true;
    }
    
    false
}
