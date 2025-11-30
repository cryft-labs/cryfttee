//! IPFS Distribution Module for CryftTEE
//!
//! Fully self-contained IPFS module with LOCAL pinning only.
//! Connects to a local IPFS daemon (kubo) for all operations.
//!
//! Features:
//! - Pin/unpin files locally to your IPFS node
//! - Search and list pinned content
//! - IPNS publishing and resolution
//! - Gateway access via gateway.cryft.network (read-only)
//!
//! NO external pinning services - all pins are local to your node.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// WASM ABI - Entry points called by CryftTEE runtime
// ============================================================================

/// Module initialization
#[no_mangle]
pub extern "C" fn init() -> i32 {
    0 // Success
}

/// Get module info
#[no_mangle]
pub extern "C" fn get_info() -> i32 {
    let info = ModuleInfo {
        id: "ipfs_v1".to_string(),
        name: "IPFS Local Node Module".to_string(),
        version: "1.0.0".to_string(),
        description: "Local IPFS pinning and distribution - no external services".to_string(),
        capabilities: vec![
            "ipfs_pin".to_string(),
            "ipfs_unpin".to_string(),
            "ipfs_search".to_string(),
            "ipfs_get".to_string(),
            "ipfs_add".to_string(),
            "ipfs_ls".to_string(),
            "ipfs_cat".to_string(),
            "ipfs_stat".to_string(),
            "ipns_publish".to_string(),
            "ipns_resolve".to_string(),
            "node_status".to_string(),
            "node_id".to_string(),
            // Kubo daemon management
            "kubo_install".to_string(),
            "kubo_init".to_string(),
            "kubo_start".to_string(),
            "kubo_stop".to_string(),
            "kubo_status".to_string(),
            "kubo_config".to_string(),
        ],
    };
    
    let json = serde_json::to_string(&info).unwrap_or_default();
    set_output(&json);
    0
}

/// Handle IPFS operations
#[no_mangle]
pub extern "C" fn handle_request(op_ptr: i32, op_len: i32, data_ptr: i32, data_len: i32) -> i32 {
    let operation = unsafe { read_string(op_ptr, op_len) };
    let data = unsafe { read_string(data_ptr, data_len) };
    
    let result = match operation.as_str() {
        // Pin management (LOCAL only)
        "ipfs_pin" => handle_pin(&data),
        "ipfs_unpin" => handle_unpin(&data),
        "ipfs_ls" => handle_ls(&data),
        "ipfs_search" => handle_search(&data),
        
        // Content operations
        "ipfs_add" => handle_add(&data),
        "ipfs_get" => handle_get(&data),
        "ipfs_cat" => handle_cat(&data),
        "ipfs_stat" => handle_stat(&data),
        
        // IPNS operations
        "ipns_publish" => handle_ipns_publish(&data),
        "ipns_resolve" => handle_ipns_resolve(&data),
        "ipns_keys" => handle_ipns_keys(&data),
        
        // Node status
        "node_status" => handle_node_status(&data),
        "node_id" => handle_node_id(&data),
        
        // Kubo daemon management
        "kubo_install" => handle_kubo_install(&data),
        "kubo_init" => handle_kubo_init(&data),
        "kubo_start" => handle_kubo_start(&data),
        "kubo_stop" => handle_kubo_stop(&data),
        "kubo_status" => handle_kubo_status(&data),
        "kubo_config" => handle_kubo_config(&data),
        
        // Configuration
        "get_config" => handle_get_config(),
        "set_config" => handle_set_config(&data),
        
        _ => Err(format!("Unknown operation: {}", operation)),
    };
    
    match result {
        Ok(response) => {
            set_output(&response);
            0
        }
        Err(e) => {
            set_output(&format!(r#"{{"error":"{}"}}"#, e));
            1
        }
    }
}

// ============================================================================
// Data Structures
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
struct ModuleInfo {
    id: String,
    name: String,
    version: String,
    description: String,
    capabilities: Vec<String>,
}

/// IPFS Configuration - connects to LOCAL node only
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpfsConfig {
    /// Local IPFS API endpoint (default: http://127.0.0.1:5001)
    pub api_url: String,
    /// Read gateway for content retrieval
    pub gateway_url: String,
    /// Cryft gateway for public access URLs
    pub public_gateway: String,
    /// Request timeout in seconds
    pub timeout_secs: u32,
    /// Maximum file size for add operations (bytes)
    pub max_add_size: u64,
    /// Enable verbose logging
    pub verbose: bool,
}

impl Default for IpfsConfig {
    fn default() -> Self {
        Self {
            api_url: "http://127.0.0.1:5001".to_string(),
            gateway_url: "http://127.0.0.1:8080".to_string(),
            public_gateway: "https://gateway.cryft.network".to_string(),
            timeout_secs: 60,
            max_add_size: 100 * 1024 * 1024, // 100MB
            verbose: false,
        }
    }
}

// ============================================================================
// Pin Operations (LOCAL ONLY)
// ============================================================================

/// Pin request - pins to LOCAL node only
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PinRequest {
    /// CID to pin
    pub cid: String,
    /// Optional name/label (stored in local metadata DB)
    pub name: Option<String>,
    /// Recursive pin (default: true)
    #[serde(default = "default_true")]
    pub recursive: bool,
    /// Optional metadata tags
    #[serde(default)]
    pub tags: HashMap<String, String>,
}

/// Pin response
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PinResponse {
    pub cid: String,
    pub name: Option<String>,
    pub pinned: bool,
    pub recursive: bool,
    pub size: Option<u64>,
    pub local_gateway_url: String,
    pub public_gateway_url: String,
}

fn handle_pin(data: &str) -> Result<String, String> {
    let request: PinRequest = serde_json::from_str(data)
        .map_err(|e| format!("Invalid pin request: {}", e))?;
    
    if !is_valid_cid(&request.cid) {
        return Err("Invalid CID format".to_string());
    }
    
    let config = IpfsConfig::default();
    
    // Build IPFS API call: POST /api/v0/pin/add?arg=<cid>&recursive=<bool>
    let action = IpfsApiCall::PinAdd {
        cid: request.cid.clone(),
        recursive: request.recursive,
        name: request.name.clone(),
        tags: request.tags,
    };
    
    // Return response with gateway URLs
    let response = PinResponse {
        cid: request.cid.clone(),
        name: request.name,
        pinned: true, // Will be confirmed by runtime
        recursive: request.recursive,
        size: None, // Filled by runtime after stat
        local_gateway_url: format!("{}/ipfs/{}", config.gateway_url, request.cid),
        public_gateway_url: format!("{}/ipfs/{}", config.public_gateway, request.cid),
    };
    
    serde_json::to_string(&RuntimeAction {
        api_call: action,
        pending_response: serde_json::to_value(&response).ok(),
    }).map_err(|e| e.to_string())
}

/// Unpin request
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnpinRequest {
    /// CID to unpin
    pub cid: String,
    /// Recursive unpin (default: true)
    #[serde(default = "default_true")]
    pub recursive: bool,
}

fn handle_unpin(data: &str) -> Result<String, String> {
    let request: UnpinRequest = serde_json::from_str(data)
        .map_err(|e| format!("Invalid unpin request: {}", e))?;
    
    if !is_valid_cid(&request.cid) {
        return Err("Invalid CID format".to_string());
    }
    
    let action = IpfsApiCall::PinRm {
        cid: request.cid.clone(),
        recursive: request.recursive,
    };
    
    serde_json::to_string(&RuntimeAction {
        api_call: action,
        pending_response: Some(serde_json::json!({
            "cid": request.cid,
            "unpinned": true
        })),
    }).map_err(|e| e.to_string())
}

/// List pins request
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LsRequest {
    /// Filter by pin type: "all", "direct", "indirect", "recursive"
    #[serde(default = "default_pin_type")]
    pub pin_type: String,
    /// Filter by CID prefix
    pub cid_prefix: Option<String>,
    /// Include size info (slower)
    #[serde(default)]
    pub include_size: bool,
}

fn default_pin_type() -> String { "recursive".to_string() }

fn handle_ls(data: &str) -> Result<String, String> {
    let request: LsRequest = serde_json::from_str(data).unwrap_or(LsRequest {
        pin_type: "recursive".to_string(),
        cid_prefix: None,
        include_size: false,
    });
    
    let action = IpfsApiCall::PinLs {
        pin_type: request.pin_type,
        cid_prefix: request.cid_prefix,
        include_size: request.include_size,
    };
    
    serde_json::to_string(&RuntimeAction {
        api_call: action,
        pending_response: None,
    }).map_err(|e| e.to_string())
}

/// Search request - searches local pin metadata
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchRequest {
    /// Search query (matches name, CID prefix, or tags)
    pub query: String,
    /// Filter by tags
    #[serde(default)]
    pub tags: HashMap<String, String>,
    /// Max results
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize { 100 }

fn handle_search(data: &str) -> Result<String, String> {
    let request: SearchRequest = serde_json::from_str(data)
        .map_err(|e| format!("Invalid search request: {}", e))?;
    
    let action = IpfsApiCall::SearchPins {
        query: request.query,
        tags: request.tags,
        limit: request.limit,
    };
    
    serde_json::to_string(&RuntimeAction {
        api_call: action,
        pending_response: None,
    }).map_err(|e| e.to_string())
}

// ============================================================================
// Content Operations
// ============================================================================

/// Add content request
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddRequest {
    /// Content to add (UTF-8 string or base64 encoded)
    pub content: String,
    /// Whether content is base64 encoded
    #[serde(default)]
    pub base64: bool,
    /// Optional filename
    pub filename: Option<String>,
    /// Pin after adding (default: true)
    #[serde(default = "default_true")]
    pub pin: bool,
    /// Wrap in directory
    #[serde(default)]
    pub wrap_directory: bool,
    /// CID version (0 or 1, default: 1)
    #[serde(default = "default_cid_version")]
    pub cid_version: u8,
    /// Optional name for pin metadata
    pub name: Option<String>,
    /// Optional tags for pin metadata
    #[serde(default)]
    pub tags: HashMap<String, String>,
}

fn default_cid_version() -> u8 { 1 }

/// Add response
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddResponse {
    pub cid: String,
    pub size: u64,
    pub pinned: bool,
    pub name: Option<String>,
    pub local_gateway_url: String,
    pub public_gateway_url: String,
}

fn handle_add(data: &str) -> Result<String, String> {
    let request: AddRequest = serde_json::from_str(data)
        .map_err(|e| format!("Invalid add request: {}", e))?;
    
    let config = IpfsConfig::default();
    
    // Check size limit
    let content_size = if request.base64 {
        (request.content.len() * 3) / 4 // Approximate decoded size
    } else {
        request.content.len()
    };
    
    if content_size as u64 > config.max_add_size {
        return Err(format!(
            "Content too large: {} bytes (max: {} bytes)",
            content_size, config.max_add_size
        ));
    }
    
    let action = IpfsApiCall::Add {
        content: request.content,
        base64: request.base64,
        filename: request.filename,
        pin: request.pin,
        wrap_directory: request.wrap_directory,
        cid_version: request.cid_version,
        name: request.name,
        tags: request.tags,
    };
    
    serde_json::to_string(&RuntimeAction {
        api_call: action,
        pending_response: None, // CID unknown until added
    }).map_err(|e| e.to_string())
}

/// Get/Cat request - retrieve content
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRequest {
    /// CID or path to retrieve
    pub path: String,
    /// Max size to retrieve (bytes)
    pub max_size: Option<u64>,
    /// Return as base64
    #[serde(default)]
    pub base64: bool,
    /// Try local node first, then gateway
    #[serde(default = "default_true")]
    pub prefer_local: bool,
}

fn handle_get(data: &str) -> Result<String, String> {
    let request: GetRequest = serde_json::from_str(data)
        .map_err(|e| format!("Invalid get request: {}", e))?;
    
    let action = IpfsApiCall::Cat {
        path: request.path,
        max_size: request.max_size.unwrap_or(10 * 1024 * 1024), // 10MB default
        base64: request.base64,
        prefer_local: request.prefer_local,
    };
    
    serde_json::to_string(&RuntimeAction {
        api_call: action,
        pending_response: None,
    }).map_err(|e| e.to_string())
}

fn handle_cat(data: &str) -> Result<String, String> {
    // Alias for get
    handle_get(data)
}

/// Stat request - get object stats
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatRequest {
    /// CID or path
    pub path: String,
}

fn handle_stat(data: &str) -> Result<String, String> {
    let request: StatRequest = serde_json::from_str(data)
        .map_err(|e| format!("Invalid stat request: {}", e))?;
    
    let action = IpfsApiCall::Stat {
        path: request.path,
    };
    
    serde_json::to_string(&RuntimeAction {
        api_call: action,
        pending_response: None,
    }).map_err(|e| e.to_string())
}

// ============================================================================
// IPNS Operations
// ============================================================================

/// IPNS publish request
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpnsPublishRequest {
    /// CID to publish
    pub cid: String,
    /// Key name (default: "self")
    pub key: Option<String>,
    /// TTL in seconds (default: 3600)
    pub ttl: Option<u64>,
    /// Lifetime in seconds (default: 86400)
    pub lifetime: Option<u64>,
    /// Resolve before publishing to verify
    #[serde(default = "default_true")]
    pub resolve: bool,
}

fn handle_ipns_publish(data: &str) -> Result<String, String> {
    let request: IpnsPublishRequest = serde_json::from_str(data)
        .map_err(|e| format!("Invalid IPNS publish request: {}", e))?;
    
    if !is_valid_cid(&request.cid) {
        return Err("Invalid CID format".to_string());
    }
    
    let action = IpfsApiCall::NamePublish {
        cid: request.cid,
        key: request.key.unwrap_or_else(|| "self".to_string()),
        ttl: request.ttl.unwrap_or(3600),
        lifetime: request.lifetime.unwrap_or(86400),
        resolve: request.resolve,
    };
    
    serde_json::to_string(&RuntimeAction {
        api_call: action,
        pending_response: None,
    }).map_err(|e| e.to_string())
}

/// IPNS resolve request
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpnsResolveRequest {
    /// IPNS name to resolve (peer ID or domain)
    pub name: String,
    /// Use DHT (slower but more reliable)
    #[serde(default)]
    pub dht: bool,
    /// Timeout in seconds
    pub timeout: Option<u64>,
}

fn handle_ipns_resolve(data: &str) -> Result<String, String> {
    let request: IpnsResolveRequest = serde_json::from_str(data)
        .map_err(|e| format!("Invalid IPNS resolve request: {}", e))?;
    
    let action = IpfsApiCall::NameResolve {
        name: request.name,
        dht: request.dht,
        timeout: request.timeout.unwrap_or(60),
    };
    
    serde_json::to_string(&RuntimeAction {
        api_call: action,
        pending_response: None,
    }).map_err(|e| e.to_string())
}

/// List IPNS keys
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeysRequest {
    /// Generate new key with this name (optional)
    pub generate: Option<String>,
    /// Key type for generation (default: ed25519)
    pub key_type: Option<String>,
}

fn handle_ipns_keys(data: &str) -> Result<String, String> {
    let request: KeysRequest = serde_json::from_str(data).unwrap_or(KeysRequest {
        generate: None,
        key_type: None,
    });
    
    let action = if let Some(name) = request.generate {
        IpfsApiCall::KeyGen {
            name,
            key_type: request.key_type.unwrap_or_else(|| "ed25519".to_string()),
        }
    } else {
        IpfsApiCall::KeyList
    };
    
    serde_json::to_string(&RuntimeAction {
        api_call: action,
        pending_response: None,
    }).map_err(|e| e.to_string())
}

// ============================================================================
// Node Status
// ============================================================================

fn handle_node_status(_data: &str) -> Result<String, String> {
    let action = IpfsApiCall::NodeStatus;
    
    serde_json::to_string(&RuntimeAction {
        api_call: action,
        pending_response: None,
    }).map_err(|e| e.to_string())
}

fn handle_node_id(_data: &str) -> Result<String, String> {
    let action = IpfsApiCall::NodeId;
    
    serde_json::to_string(&RuntimeAction {
        api_call: action,
        pending_response: None,
    }).map_err(|e| e.to_string())
}

// ============================================================================
// Configuration
// ============================================================================

fn handle_get_config() -> Result<String, String> {
    let config = IpfsConfig::default();
    serde_json::to_string(&config).map_err(|e| e.to_string())
}

fn handle_set_config(data: &str) -> Result<String, String> {
    let new_config: IpfsConfig = serde_json::from_str(data)
        .map_err(|e| format!("Invalid config: {}", e))?;
    
    // Validate API URL
    if !new_config.api_url.starts_with("http") {
        return Err("API URL must start with http:// or https://".to_string());
    }
    
    let action = IpfsApiCall::SetConfig {
        config: new_config,
    };
    
    serde_json::to_string(&RuntimeAction {
        api_call: action,
        pending_response: Some(serde_json::json!({"success": true})),
    }).map_err(|e| e.to_string())
}

// ============================================================================
// Kubo Daemon Management
// ============================================================================

/// Kubo install request
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KuboInstallRequest {
    /// Kubo version (e.g., "0.27.0")
    #[serde(default = "default_kubo_version")]
    pub version: String,
    /// Target platform (auto-detected if not specified)
    pub platform: Option<String>,
    /// Install directory (default: ~/.cryfttee/bin)
    pub install_dir: Option<String>,
}

fn default_kubo_version() -> String { "0.27.0".to_string() }

fn handle_kubo_install(data: &str) -> Result<String, String> {
    let request: KuboInstallRequest = serde_json::from_str(data).unwrap_or(KuboInstallRequest {
        version: default_kubo_version(),
        platform: None,
        install_dir: None,
    });
    
    let action = IpfsApiCall::KuboInstall {
        version: request.version,
        platform: request.platform.unwrap_or_else(|| detect_platform()),
    };
    
    serde_json::to_string(&RuntimeAction {
        api_call: action,
        pending_response: None,
    }).map_err(|e| e.to_string())
}

/// Kubo init request
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KuboInitRequest {
    /// Profile: "default", "server", "lowpower", "randomports"
    #[serde(default = "default_profile")]
    pub profile: String,
    /// Custom IPFS path (default: ~/.ipfs)
    pub ipfs_path: Option<String>,
}

fn default_profile() -> String { "default".to_string() }

fn handle_kubo_init(data: &str) -> Result<String, String> {
    let request: KuboInitRequest = serde_json::from_str(data).unwrap_or(KuboInitRequest {
        profile: default_profile(),
        ipfs_path: None,
    });
    
    let action = IpfsApiCall::KuboInit {
        profile: request.profile,
    };
    
    serde_json::to_string(&RuntimeAction {
        api_call: action,
        pending_response: None,
    }).map_err(|e| e.to_string())
}

/// Kubo start request
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KuboStartRequest {
    /// Enable PubSub
    #[serde(default)]
    pub enable_pubsub: bool,
    /// Enable Gateway (default: true)
    #[serde(default = "default_true")]
    pub enable_gateway: bool,
    /// Run in background/daemon mode
    #[serde(default = "default_true")]
    pub daemon: bool,
    /// API listen address
    pub api_addr: Option<String>,
    /// Gateway listen address
    pub gateway_addr: Option<String>,
}

fn handle_kubo_start(data: &str) -> Result<String, String> {
    let request: KuboStartRequest = serde_json::from_str(data).unwrap_or(KuboStartRequest {
        enable_pubsub: false,
        enable_gateway: true,
        daemon: true,
        api_addr: None,
        gateway_addr: None,
    });
    
    let action = IpfsApiCall::KuboStart {
        enable_pubsub: request.enable_pubsub,
        enable_gateway: request.enable_gateway,
    };
    
    serde_json::to_string(&RuntimeAction {
        api_call: action,
        pending_response: None,
    }).map_err(|e| e.to_string())
}

fn handle_kubo_stop(_data: &str) -> Result<String, String> {
    let action = IpfsApiCall::KuboStop;
    
    serde_json::to_string(&RuntimeAction {
        api_call: action,
        pending_response: Some(serde_json::json!({"stopped": true})),
    }).map_err(|e| e.to_string())
}

fn handle_kubo_status(_data: &str) -> Result<String, String> {
    let action = IpfsApiCall::KuboStatus;
    
    serde_json::to_string(&RuntimeAction {
        api_call: action,
        pending_response: None,
    }).map_err(|e| e.to_string())
}

/// Kubo config request
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KuboConfigRequest {
    /// Config key (e.g., "Addresses.API", "Swarm.ConnMgr.HighWater")
    pub key: String,
    /// Value to set (if None, returns current value)
    pub value: Option<String>,
    /// Parse value as JSON
    #[serde(default)]
    pub json: bool,
}

fn handle_kubo_config(data: &str) -> Result<String, String> {
    let request: KuboConfigRequest = serde_json::from_str(data)
        .map_err(|e| format!("Invalid config request: {}", e))?;
    
    let action = IpfsApiCall::KuboConfig {
        key: request.key,
        value: request.value,
    };
    
    serde_json::to_string(&RuntimeAction {
        api_call: action,
        pending_response: None,
    }).map_err(|e| e.to_string())
}

fn detect_platform() -> String {
    // Will be properly detected by the runtime
    #[cfg(target_os = "windows")]
    return "windows-amd64".to_string();
    #[cfg(target_os = "macos")]
    return "darwin-amd64".to_string();
    #[cfg(target_os = "linux")]
    return "linux-amd64".to_string();
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    return "linux-amd64".to_string();
}

// ============================================================================
// IPFS API Calls (executed by CryftTEE runtime)
// ============================================================================

/// Actions to be executed by the runtime against the local IPFS node
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpfsApiCall {
    // Pin operations
    PinAdd {
        cid: String,
        recursive: bool,
        name: Option<String>,
        tags: HashMap<String, String>,
    },
    PinRm {
        cid: String,
        recursive: bool,
    },
    PinLs {
        pin_type: String,
        cid_prefix: Option<String>,
        include_size: bool,
    },
    SearchPins {
        query: String,
        tags: HashMap<String, String>,
        limit: usize,
    },
    
    // Content operations
    Add {
        content: String,
        base64: bool,
        filename: Option<String>,
        pin: bool,
        wrap_directory: bool,
        cid_version: u8,
        name: Option<String>,
        tags: HashMap<String, String>,
    },
    Cat {
        path: String,
        max_size: u64,
        base64: bool,
        prefer_local: bool,
    },
    Stat {
        path: String,
    },
    
    // IPNS operations
    NamePublish {
        cid: String,
        key: String,
        ttl: u64,
        lifetime: u64,
        resolve: bool,
    },
    NameResolve {
        name: String,
        dht: bool,
        timeout: u64,
    },
    KeyList,
    KeyGen {
        name: String,
        key_type: String,
    },
    
    // Node operations
    NodeStatus,
    NodeId,
    
    // Kubo daemon management
    KuboInstall {
        version: String,
        platform: String,
    },
    KuboInit {
        profile: String,
    },
    KuboStart {
        enable_pubsub: bool,
        enable_gateway: bool,
    },
    KuboStop,
    KuboStatus,
    KuboConfig {
        key: String,
        value: Option<String>,
    },
    
    // Config
    SetConfig {
        config: IpfsConfig,
    },
}

/// Response wrapper for runtime
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAction {
    pub api_call: IpfsApiCall,
    pub pending_response: Option<serde_json::Value>,
}

// ============================================================================
// Utility Functions
// ============================================================================

fn default_true() -> bool { true }

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
    false
}

// ============================================================================
// WASM Memory Helpers
// ============================================================================

static mut OUTPUT_BUFFER: Vec<u8> = Vec::new();

fn set_output(s: &str) {
    unsafe {
        OUTPUT_BUFFER = s.as_bytes().to_vec();
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

unsafe fn read_string(ptr: i32, len: i32) -> String {
    let slice = std::slice::from_raw_parts(ptr as *const u8, len as usize);
    String::from_utf8_lossy(slice).to_string()
}

#[no_mangle]
pub extern "C" fn alloc(size: i32) -> i32 {
    let mut buf: Vec<u8> = Vec::with_capacity(size as usize);
    let ptr = buf.as_mut_ptr() as usize;
    std::mem::forget(buf);
    ptr as i32
}

#[no_mangle]
pub extern "C" fn dealloc(ptr: i32, size: i32) {
    unsafe {
        let _ = Vec::from_raw_parts(ptr as *mut u8, 0, size as usize);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_cid_v0() {
        assert!(is_valid_cid("QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"));
        assert!(is_valid_cid("/ipfs/QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"));
    }

    #[test]
    fn test_valid_cid_v1() {
        assert!(is_valid_cid("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"));
        assert!(is_valid_cid("bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"));
    }

    #[test]
    fn test_invalid_cid() {
        assert!(!is_valid_cid("not-a-valid-cid"));
        assert!(!is_valid_cid(""));
        assert!(!is_valid_cid("Qm")); // Too short
        assert!(!is_valid_cid("BAFYBEIG")); // CIDv1 must be lowercase
    }

    #[test]
    fn test_ipfs_config_default() {
        let config = IpfsConfig::default();
        assert_eq!(config.api_url, "http://127.0.0.1:5001");
        assert_eq!(config.gateway_url, "http://127.0.0.1:8080");
        assert_eq!(config.public_gateway, "https://gateway.cryft.network");
    }

    #[test]
    fn test_pin_request() {
        let json = r#"{"cid":"QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG","name":"test"}"#;
        let request: PinRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.cid, "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG");
        assert_eq!(request.name, Some("test".to_string()));
        assert!(request.recursive); // default true
    }

    #[test]
    fn test_add_request() {
        let json = r#"{"content":"Hello IPFS!","filename":"hello.txt"}"#;
        let request: AddRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.content, "Hello IPFS!");
        assert!(!request.base64);
        assert!(request.pin); // default true
        assert_eq!(request.cid_version, 1); // default 1
    }
}
