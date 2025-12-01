//! IPFS Standalone Module for CryftTEE
//!
//! Fully self-contained IPFS implementation with embedded node functionality.
//! No external IPFS daemon required - this module IS the IPFS node.
//!
//! Node Types:
//! - Full Node (default): Complete IPFS node with DHT, content routing, and pinning
//! - Light Node: Lightweight client that delegates to gateway/bootstrap nodes
//!
//! Features:
//! - Embedded IPFS node (no kubo required)
//! - Pin/unpin files locally
//! - Content routing via DHT or delegated routing
//! - IPNS publishing and resolution
//! - Gateway access for content retrieval
//! - Configurable bootstrap peers

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
        let mut buf: Vec<u8> = Vec::with_capacity(size + align);
        let ptr = buf.as_mut_ptr();
        let aligned_ptr = ((ptr as usize + align - 1) & !(align - 1)) as *mut u8;
        core::mem::forget(buf);
        aligned_ptr
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Simple allocator - memory freed when module unloads
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

/// Node type configuration
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeType {
    /// Full IPFS node with DHT participation, content routing, and local storage
    Full,
    /// Light client - delegates to gateways and bootstrap nodes
    Light,
}

impl Default for NodeType {
    fn default() -> Self {
        NodeType::Full // Full node is the default
    }
}

/// Module configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeConfig {
    /// Node type: full (default) or light
    #[serde(default)]
    pub node_type: NodeType,
    
    /// Data directory for node storage
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    
    /// API listen address (for full node)
    #[serde(default = "default_api_addr")]
    pub api_addr: String,
    
    /// Gateway listen address (for full node)
    #[serde(default = "default_gateway_addr")]
    pub gateway_addr: String,
    
    /// Swarm listen addresses (for full node)
    #[serde(default = "default_swarm_addrs")]
    pub swarm_addrs: Vec<String>,
    
    /// Bootstrap peers
    #[serde(default = "default_bootstrap_peers")]
    pub bootstrap_peers: Vec<String>,
    
    /// Enable DHT (full node only)
    #[serde(default = "default_true")]
    pub enable_dht: bool,
    
    /// Enable content routing
    #[serde(default = "default_true")]
    pub enable_routing: bool,
    
    /// Enable relay (NAT traversal)
    #[serde(default = "default_true")]
    pub enable_relay: bool,
    
    /// Delegated routing URL (for light nodes)
    #[serde(default = "default_delegated_routing")]
    pub delegated_routing_url: String,
    
    /// Public gateway URL for content access
    #[serde(default = "default_public_gateway")]
    pub public_gateway: String,
    
    /// Max storage size in bytes (0 = unlimited)
    #[serde(default)]
    pub max_storage: u64,
    
    /// Enable garbage collection
    #[serde(default = "default_true")]
    pub enable_gc: bool,
    
    /// GC watermark (percentage of max_storage)
    #[serde(default = "default_gc_watermark")]
    pub gc_watermark: u8,
}

fn default_data_dir() -> String { "~/.cryfttee/ipfs".to_string() }
fn default_api_addr() -> String { "/ip4/127.0.0.1/tcp/5001".to_string() }
fn default_gateway_addr() -> String { "/ip4/127.0.0.1/tcp/8080".to_string() }
fn default_swarm_addrs() -> Vec<String> {
    vec![
        "/ip4/0.0.0.0/tcp/4001".to_string(),
        "/ip4/0.0.0.0/udp/4001/quic-v1".to_string(),
        "/ip6/::/tcp/4001".to_string(),
        "/ip6/::/udp/4001/quic-v1".to_string(),
    ]
}
fn default_bootstrap_peers() -> Vec<String> {
    vec![
        // IPFS default bootstrap nodes
        "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN".to_string(),
        "/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa".to_string(),
        "/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb".to_string(),
        "/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt".to_string(),
        // Cryft bootstrap nodes
        "/dnsaddr/bootstrap.cryft.network/p2p/12D3KooWCryftBootstrap1".to_string(),
    ]
}
fn default_delegated_routing() -> String { "https://delegated-ipfs.dev".to_string() }
fn default_public_gateway() -> String { "https://gateway.cryft.network".to_string() }
fn default_gc_watermark() -> u8 { 90 }
fn default_true() -> bool { true }

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node_type: NodeType::Full,
            data_dir: default_data_dir(),
            api_addr: default_api_addr(),
            gateway_addr: default_gateway_addr(),
            swarm_addrs: default_swarm_addrs(),
            bootstrap_peers: default_bootstrap_peers(),
            enable_dht: true,
            enable_routing: true,
            enable_relay: true,
            delegated_routing_url: default_delegated_routing(),
            public_gateway: default_public_gateway(),
            max_storage: 0, // Unlimited
            enable_gc: true,
            gc_watermark: 90,
        }
    }
}

/// Node status information
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeStatus {
    pub running: bool,
    pub node_type: NodeType,
    pub peer_id: Option<String>,
    pub addresses: Vec<String>,
    pub peers_connected: u32,
    pub repo_size: u64,
    pub num_pins: u32,
    pub uptime_secs: u64,
    pub version: String,
}

/// Module info response
#[derive(Serialize)]
struct ModuleInfo {
    module: &'static str,
    version: &'static str,
    status: &'static str,
    node_type: &'static str,
    capabilities: Vec<&'static str>,
    description: &'static str,
}

/// Request handler structure
#[derive(Deserialize)]
struct HandleRequest {
    operation: String,
    params: Option<serde_json::Value>,
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
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PinResponse {
    pub success: bool,
    pub cid: String,
    pub name: Option<String>,
    pub size: Option<u64>,
    pub gateway_url: String,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnpinRequest {
    pub cid: String,
    #[serde(default = "default_true")]
    pub recursive: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListPinsRequest {
    #[serde(default = "default_pin_type")]
    pub pin_type: String,
    pub name_filter: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
}

fn default_pin_type() -> String { "recursive".to_string() }
fn default_limit() -> usize { 100 }

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PinInfo {
    pub cid: String,
    pub name: Option<String>,
    pub pin_type: String,
    pub size: Option<u64>,
    pub pinned_at: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

// ============================================================================
// Content Operations
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
    #[serde(default)]
    pub wrap_directory: bool,
    #[serde(default = "default_cid_version")]
    pub cid_version: u8,
    pub name: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

fn default_cid_version() -> u8 { 1 }

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddResponse {
    pub success: bool,
    pub cid: Option<String>,
    pub size: Option<u64>,
    pub pinned: bool,
    pub gateway_url: Option<String>,
    pub error: Option<String>,
}

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
pub struct GetResponse {
    pub success: bool,
    pub cid: String,
    pub content: Option<String>,
    pub size: Option<u64>,
    pub content_type: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatRequest {
    pub cid: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatResponse {
    pub success: bool,
    pub cid: String,
    pub size: Option<u64>,
    pub cumulative_size: Option<u64>,
    pub blocks: Option<u32>,
    pub links: Option<u32>,
    pub data_type: Option<String>,
    pub error: Option<String>,
}

// ============================================================================
// IPNS Operations
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpnsPublishRequest {
    pub cid: String,
    #[serde(default = "default_key")]
    pub key: String,
    #[serde(default = "default_ttl")]
    pub ttl_secs: u64,
    #[serde(default = "default_lifetime")]
    pub lifetime_secs: u64,
}

fn default_key() -> String { "self".to_string() }
fn default_ttl() -> u64 { 3600 }
fn default_lifetime() -> u64 { 86400 }

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpnsPublishResponse {
    pub success: bool,
    pub name: Option<String>,
    pub value: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpnsResolveRequest {
    pub name: String,
    #[serde(default)]
    pub nocache: bool,
    #[serde(default = "default_resolve_timeout")]
    pub timeout_secs: u64,
}

fn default_resolve_timeout() -> u64 { 60 }

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpnsResolveResponse {
    pub success: bool,
    pub path: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyGenRequest {
    pub name: String,
    #[serde(default = "default_key_type")]
    pub key_type: String,
    #[serde(default = "default_key_size")]
    pub size: u32,
}

fn default_key_type() -> String { "ed25519".to_string() }
fn default_key_size() -> u32 { 256 }

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyInfo {
    pub name: String,
    pub id: String,
}

// ============================================================================
// Node Control
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartNodeRequest {
    #[serde(default)]
    pub config: Option<NodeConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectPeerRequest {
    pub peer_addr: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerInfo {
    pub peer_id: String,
    pub addrs: Vec<String>,
    pub latency: Option<String>,
    pub direction: String,
}

// ============================================================================
// Host API Calls
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "call_type", rename_all = "snake_case")]
pub enum HostApiCall {
    // Node lifecycle
    StartNode { config: NodeConfig },
    StopNode,
    GetNodeStatus,
    
    // Pin operations (embedded node)
    Pin { cid: String, recursive: bool, name: Option<String>, metadata: BTreeMap<String, String> },
    Unpin { cid: String, recursive: bool },
    ListPins { pin_type: String, name_filter: Option<String>, limit: usize, offset: usize },
    
    // Content operations
    AddContent { content: String, base64: bool, filename: Option<String>, pin: bool, cid_version: u8, name: Option<String>, metadata: BTreeMap<String, String> },
    GetContent { cid: String, base64_output: bool, max_size: u64 },
    StatContent { cid: String },
    
    // IPNS
    IpnsPublish { cid: String, key: String, ttl_secs: u64, lifetime_secs: u64 },
    IpnsResolve { name: String, nocache: bool, timeout_secs: u64 },
    KeyGen { name: String, key_type: String, size: u32 },
    KeyList,
    KeyRm { name: String },
    
    // Swarm/Network
    SwarmConnect { peer_addr: String },
    SwarmDisconnect { peer_id: String },
    SwarmPeers,
    SwarmAddrs,
    
    // DHT (full node only)
    DhtFindProvs { cid: String, num_providers: u32 },
    DhtProvide { cid: String },
    DhtFindPeer { peer_id: String },
    
    // Config
    GetConfig,
    SetConfig { config: NodeConfig },
    
    // Repo management
    RepoStat,
    RepoGc,
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
        node_type: "full", // Default
        description: "Standalone IPFS node module - Full node (default) or Light client",
        capabilities: vec![
            // Node control
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
            "ipns_key_rm",
            // Swarm/Network
            "swarm_connect",
            "swarm_disconnect",
            "swarm_peers",
            "swarm_addrs",
            // DHT (full node)
            "dht_findprovs",
            "dht_provide",
            "dht_findpeer",
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
        "node_stop" | "stop_node" => handle_stop_node(&params),
        "node_status" | "get_status" => handle_node_status(&params),
        "node_config" | "get_config" => handle_get_config(&params),
        "set_config" => handle_set_config(&params),
        
        // Pin operations
        "ipfs_pin" | "pin" => handle_pin(&params),
        "ipfs_unpin" | "unpin" => handle_unpin(&params),
        "ipfs_pin_ls" | "pin_ls" | "list_pins" => handle_list_pins(&params),
        
        // Content operations
        "ipfs_add" | "add" => handle_add(&params),
        "ipfs_get" | "get" => handle_get(&params),
        "ipfs_cat" | "cat" => handle_cat(&params),
        "ipfs_stat" | "stat" => handle_stat(&params),
        
        // IPNS
        "ipns_publish" => handle_ipns_publish(&params),
        "ipns_resolve" => handle_ipns_resolve(&params),
        "ipns_key_gen" | "key_gen" => handle_key_gen(&params),
        "ipns_key_list" | "key_list" => handle_key_list(&params),
        "ipns_key_rm" | "key_rm" => handle_key_rm(&params),
        
        // Swarm
        "swarm_connect" | "connect" => handle_swarm_connect(&params),
        "swarm_disconnect" | "disconnect" => handle_swarm_disconnect(&params),
        "swarm_peers" | "peers" => handle_swarm_peers(&params),
        "swarm_addrs" | "addrs" => handle_swarm_addrs(&params),
        
        // DHT
        "dht_findprovs" | "findprovs" => handle_dht_findprovs(&params),
        "dht_provide" | "provide" => handle_dht_provide(&params),
        "dht_findpeer" | "findpeer" => handle_dht_findpeer(&params),
        
        // Repo
        "repo_stat" => handle_repo_stat(&params),
        "repo_gc" | "gc" => handle_repo_gc(&params),
        
        _ => format!(r#"{{"success":false,"error":"Unknown operation: {}"}}"#, request.operation),
    };
    
    set_output(result.as_bytes());
    0
}

// ============================================================================
// Handler Functions
// ============================================================================

fn handle_start_node(params: &serde_json::Value) -> String {
    let req: StartNodeRequest = serde_json::from_value(params.clone()).unwrap_or(StartNodeRequest { config: None });
    let config = req.config.unwrap_or_default();
    
    let node_type_str = match config.node_type {
        NodeType::Full => "full",
        NodeType::Light => "light",
    };
    
    let api_call = HostApiCall::StartNode { config };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true,
        "message": format!("Starting {} IPFS node...", node_type_str)
    })).unwrap_or_default()
}

fn handle_stop_node(_params: &serde_json::Value) -> String {
    let api_call = HostApiCall::StopNode;
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true,
        "message": "Stopping IPFS node..."
    })).unwrap_or_default()
}

fn handle_node_status(_params: &serde_json::Value) -> String {
    let api_call = HostApiCall::GetNodeStatus;
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true
    })).unwrap_or_default()
}

fn handle_get_config(_params: &serde_json::Value) -> String {
    let api_call = HostApiCall::GetConfig;
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true
    })).unwrap_or_default()
}

fn handle_set_config(params: &serde_json::Value) -> String {
    let config: NodeConfig = match serde_json::from_value(params.clone()) {
        Ok(c) => c,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid config: {}"}}"#, e),
    };
    
    let api_call = HostApiCall::SetConfig { config };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true
    })).unwrap_or_default()
}

fn handle_pin(params: &serde_json::Value) -> String {
    let req: PinRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid pin request: {}"}}"#, e),
    };
    
    if !is_valid_cid(&req.cid) {
        return r#"{"success":false,"error":"Invalid CID format"}"#.to_string();
    }
    
    let api_call = HostApiCall::Pin {
        cid: req.cid.clone(),
        recursive: req.recursive,
        name: req.name.clone(),
        metadata: req.metadata,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true,
        "cid": req.cid,
        "name": req.name
    })).unwrap_or_default()
}

fn handle_unpin(params: &serde_json::Value) -> String {
    let req: UnpinRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid unpin request: {}"}}"#, e),
    };
    
    if !is_valid_cid(&req.cid) {
        return r#"{"success":false,"error":"Invalid CID format"}"#.to_string();
    }
    
    let api_call = HostApiCall::Unpin {
        cid: req.cid.clone(),
        recursive: req.recursive,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true,
        "cid": req.cid
    })).unwrap_or_default()
}

fn handle_list_pins(params: &serde_json::Value) -> String {
    let req: ListPinsRequest = serde_json::from_value(params.clone()).unwrap_or(ListPinsRequest {
        pin_type: default_pin_type(),
        name_filter: None,
        limit: default_limit(),
        offset: 0,
    });
    
    let api_call = HostApiCall::ListPins {
        pin_type: req.pin_type,
        name_filter: req.name_filter,
        limit: req.limit,
        offset: req.offset,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true
    })).unwrap_or_default()
}

fn handle_add(params: &serde_json::Value) -> String {
    let req: AddRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid add request: {}"}}"#, e),
    };
    
    let api_call = HostApiCall::AddContent {
        content: req.content,
        base64: req.base64,
        filename: req.filename,
        pin: req.pin,
        cid_version: req.cid_version,
        name: req.name,
        metadata: req.metadata,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true,
        "message": "Adding content to IPFS..."
    })).unwrap_or_default()
}

fn handle_get(params: &serde_json::Value) -> String {
    let req: GetRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid get request: {}"}}"#, e),
    };
    
    if !is_valid_cid(&req.cid) {
        return r#"{"success":false,"error":"Invalid CID format"}"#.to_string();
    }
    
    let api_call = HostApiCall::GetContent {
        cid: req.cid.clone(),
        base64_output: req.base64_output,
        max_size: req.max_size.unwrap_or(50 * 1024 * 1024), // 50MB default
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true,
        "cid": req.cid
    })).unwrap_or_default()
}

fn handle_cat(params: &serde_json::Value) -> String {
    // Cat is an alias for get
    handle_get(params)
}

fn handle_stat(params: &serde_json::Value) -> String {
    let req: StatRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid stat request: {}"}}"#, e),
    };
    
    if !is_valid_cid(&req.cid) {
        return r#"{"success":false,"error":"Invalid CID format"}"#.to_string();
    }
    
    let api_call = HostApiCall::StatContent { cid: req.cid.clone() };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true,
        "cid": req.cid
    })).unwrap_or_default()
}

fn handle_ipns_publish(params: &serde_json::Value) -> String {
    let req: IpnsPublishRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid publish request: {}"}}"#, e),
    };
    
    if !is_valid_cid(&req.cid) {
        return r#"{"success":false,"error":"Invalid CID format"}"#.to_string();
    }
    
    let api_call = HostApiCall::IpnsPublish {
        cid: req.cid.clone(),
        key: req.key,
        ttl_secs: req.ttl_secs,
        lifetime_secs: req.lifetime_secs,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true,
        "cid": req.cid
    })).unwrap_or_default()
}

fn handle_ipns_resolve(params: &serde_json::Value) -> String {
    let req: IpnsResolveRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid resolve request: {}"}}"#, e),
    };
    
    let api_call = HostApiCall::IpnsResolve {
        name: req.name.clone(),
        nocache: req.nocache,
        timeout_secs: req.timeout_secs,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true,
        "name": req.name
    })).unwrap_or_default()
}

fn handle_key_gen(params: &serde_json::Value) -> String {
    let req: KeyGenRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid keygen request: {}"}}"#, e),
    };
    
    let api_call = HostApiCall::KeyGen {
        name: req.name.clone(),
        key_type: req.key_type,
        size: req.size,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true,
        "key_name": req.name
    })).unwrap_or_default()
}

fn handle_key_list(_params: &serde_json::Value) -> String {
    let api_call = HostApiCall::KeyList;
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true
    })).unwrap_or_default()
}

fn handle_key_rm(params: &serde_json::Value) -> String {
    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
    
    if name.is_empty() {
        return r#"{"success":false,"error":"Key name required"}"#.to_string();
    }
    
    let api_call = HostApiCall::KeyRm { name: name.to_string() };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true,
        "key_name": name
    })).unwrap_or_default()
}

fn handle_swarm_connect(params: &serde_json::Value) -> String {
    let req: ConnectPeerRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid connect request: {}"}}"#, e),
    };
    
    let api_call = HostApiCall::SwarmConnect { peer_addr: req.peer_addr.clone() };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true,
        "peer_addr": req.peer_addr
    })).unwrap_or_default()
}

fn handle_swarm_disconnect(params: &serde_json::Value) -> String {
    let peer_id = params.get("peer_id").and_then(|v| v.as_str()).unwrap_or("");
    
    if peer_id.is_empty() {
        return r#"{"success":false,"error":"Peer ID required"}"#.to_string();
    }
    
    let api_call = HostApiCall::SwarmDisconnect { peer_id: peer_id.to_string() };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true,
        "peer_id": peer_id
    })).unwrap_or_default()
}

fn handle_swarm_peers(_params: &serde_json::Value) -> String {
    let api_call = HostApiCall::SwarmPeers;
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true
    })).unwrap_or_default()
}

fn handle_swarm_addrs(_params: &serde_json::Value) -> String {
    let api_call = HostApiCall::SwarmAddrs;
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true
    })).unwrap_or_default()
}

fn handle_dht_findprovs(params: &serde_json::Value) -> String {
    let cid = params.get("cid").and_then(|v| v.as_str()).unwrap_or("");
    let num = params.get("num_providers").and_then(|v| v.as_u64()).unwrap_or(20) as u32;
    
    if cid.is_empty() || !is_valid_cid(cid) {
        return r#"{"success":false,"error":"Valid CID required"}"#.to_string();
    }
    
    let api_call = HostApiCall::DhtFindProvs {
        cid: cid.to_string(),
        num_providers: num,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true,
        "cid": cid
    })).unwrap_or_default()
}

fn handle_dht_provide(params: &serde_json::Value) -> String {
    let cid = params.get("cid").and_then(|v| v.as_str()).unwrap_or("");
    
    if cid.is_empty() || !is_valid_cid(cid) {
        return r#"{"success":false,"error":"Valid CID required"}"#.to_string();
    }
    
    let api_call = HostApiCall::DhtProvide { cid: cid.to_string() };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true,
        "cid": cid
    })).unwrap_or_default()
}

fn handle_dht_findpeer(params: &serde_json::Value) -> String {
    let peer_id = params.get("peer_id").and_then(|v| v.as_str()).unwrap_or("");
    
    if peer_id.is_empty() {
        return r#"{"success":false,"error":"Peer ID required"}"#.to_string();
    }
    
    let api_call = HostApiCall::DhtFindPeer { peer_id: peer_id.to_string() };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true,
        "peer_id": peer_id
    })).unwrap_or_default()
}

fn handle_repo_stat(_params: &serde_json::Value) -> String {
    let api_call = HostApiCall::RepoStat;
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true
    })).unwrap_or_default()
}

fn handle_repo_gc(_params: &serde_json::Value) -> String {
    let api_call = HostApiCall::RepoGc;
    
    serde_json::to_string(&serde_json::json!({
        "host_call": api_call,
        "success": true,
        "pending": true,
        "message": "Starting garbage collection..."
    })).unwrap_or_default()
}

// ============================================================================
// Utility Functions
// ============================================================================

fn is_valid_cid(cid: &str) -> bool {
    let cid = cid.trim_start_matches("/ipfs/");
    
    // CIDv0: Qm... (46 chars, base58btc)
    if cid.starts_with("Qm") && cid.len() == 46 {
        return cid.chars().all(|c| c.is_alphanumeric());
    }
    // CIDv1: bafy... bafk... bafz... (base32)
    if (cid.starts_with("bafy") || cid.starts_with("bafk") || cid.starts_with("bafz")) 
        && cid.len() >= 50 {
        return cid.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    }
    false
}
