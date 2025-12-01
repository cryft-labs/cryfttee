//! CryftIPFS Node - Unified IPFS with Validator Pin Rewards
//!
//! A decentralized storage network where validators earn rewards for pinning
//! content that is registered on the Cryft blockchain.
//!
//! Key Features:
//! - Embedded Iroh-based IPFS node
//! - Validator pin registry (tracks who's pinning what)
//! - Proof-of-storage challenges (verify validators actually store data)
//! - Reward claims (submit proofs to blockchain for rewards)
//! - Network-wide pin incentives tied to CRYFT tokens

use anyhow::{Context, Result};
use axum::{
    body::Bytes,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use clap::Parser;
use iroh::{protocol::Router as IrohRouter, Endpoint};
use iroh_blobs::{store::mem::MemStore, BlobsProtocol, Hash};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, warn, debug};

// ============================================================================
// CLI Arguments
// ============================================================================

/// CryftIPFS Node - Decentralized storage with validator rewards
#[derive(Parser, Debug)]
#[command(name = "cryft-ipfs")]
#[command(about = "Unified IPFS node with validator pinning rewards")]
struct Args {
    /// API server port
    #[arg(long, env = "IPFS_API_PORT", default_value = "5001")]
    api_port: u16,

    /// Gateway server port
    #[arg(long, env = "IPFS_GATEWAY_PORT", default_value = "8080")]
    gateway_port: u16,

    /// Validator node ID (for reward tracking)
    #[arg(long, env = "VALIDATOR_NODE_ID")]
    validator_id: Option<String>,

    /// Blockchain RPC endpoint for reward submission
    #[arg(long, env = "CRYFT_RPC_URL", default_value = "http://127.0.0.1:9650")]
    rpc_url: String,

    /// Data directory for persistent storage
    #[arg(long, env = "IPFS_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// Maximum storage allocation in GB
    #[arg(long, env = "IPFS_MAX_STORAGE_GB", default_value = "100")]
    max_storage_gb: u64,

    /// Enable verbose logging
    #[arg(long, short, env = "IPFS_VERBOSE")]
    verbose: bool,
}

// ============================================================================
// Application State
// ============================================================================

/// Application state holding the Iroh node and validator tracking
struct AppState {
    /// Blob store
    store: MemStore,
    /// Iroh endpoint for networking
    endpoint: Endpoint,
    /// Iroh router for protocol handling
    router: IrohRouter,
    /// Local pin registry with reward tracking
    pins: RwLock<HashMap<String, PinRecord>>,
    /// Network-wide incentivized pins (from blockchain)
    incentivized_pins: RwLock<HashMap<String, IncentivizedPin>>,
    /// Pending challenges awaiting proof
    pending_challenges: RwLock<HashMap<String, StorageChallenge>>,
    /// Completed proofs ready for reward claim
    completed_proofs: RwLock<Vec<StorageProof>>,
    /// Validator configuration
    validator_config: ValidatorConfig,
    /// Node statistics
    stats: RwLock<NodeStats>,
    /// Start time for uptime tracking
    start_time: Instant,
}

#[derive(Clone, Debug)]
struct ValidatorConfig {
    node_id: Option<String>,
    rpc_url: String,
    max_storage_bytes: u64,
}

// ============================================================================
// Pin Registry Types
// ============================================================================

/// Local pin record with validator tracking
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PinRecord {
    /// Content hash (CID)
    pub hash: String,
    /// Size in bytes
    pub size: u64,
    /// When pinned (Unix timestamp)
    pub pinned_at: u64,
    /// Optional name/label
    pub name: Option<String>,
    /// Is this an incentivized pin?
    pub incentivized: bool,
    /// Reward tier (if incentivized)
    pub reward_tier: Option<RewardTier>,
    /// Last challenge response time
    pub last_challenge: Option<u64>,
    /// Total successful challenges
    pub challenges_passed: u32,
}

/// Network-wide incentivized pin registered on blockchain
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IncentivizedPin {
    /// Content hash (CID)
    pub cid: String,
    /// Required minimum copies across network
    pub min_replicas: u32,
    /// Current replica count
    pub current_replicas: u32,
    /// Reward per epoch (in nCRYFT)
    pub reward_per_epoch: u64,
    /// Reward tier
    pub tier: RewardTier,
    /// Content size in bytes
    pub size: u64,
    /// Expiration timestamp (0 = never)
    pub expires_at: u64,
    /// Who registered this incentive
    pub sponsor: String,
    /// Total pool available for rewards
    pub reward_pool: u64,
    /// List of validators currently pinning
    pub pinners: Vec<String>,
}

/// Reward tiers based on content importance and replication needs
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RewardTier {
    /// Basic storage - low rewards, high replication
    Basic,
    /// Standard storage - moderate rewards
    Standard,
    /// Priority storage - higher rewards, faster retrieval required
    Priority,
    /// Critical storage - highest rewards, strict SLA
    Critical,
}

impl RewardTier {
    pub fn multiplier(&self) -> u64 {
        match self {
            RewardTier::Basic => 1,
            RewardTier::Standard => 2,
            RewardTier::Priority => 5,
            RewardTier::Critical => 10,
        }
    }
}

// ============================================================================
// Proof of Storage Types
// ============================================================================

/// Storage challenge issued to validators
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageChallenge {
    /// Unique challenge ID
    pub challenge_id: String,
    /// CID being challenged
    pub cid: String,
    /// Random byte offset to prove
    pub offset: u64,
    /// Number of bytes to return
    pub length: u32,
    /// Challenge issued timestamp
    pub issued_at: u64,
    /// Challenge expires at
    pub expires_at: u64,
    /// Expected hash of the chunk (for verification)
    pub expected_hash: Option<String>,
}

/// Proof of storage submitted by validator
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageProof {
    /// Challenge this proof responds to
    pub challenge_id: String,
    /// CID being proven
    pub cid: String,
    /// Validator node ID
    pub validator_id: String,
    /// Blake3 hash of the requested chunk
    pub chunk_hash: String,
    /// Timestamp of proof generation
    pub proven_at: u64,
    /// Signature over proof data
    pub signature: String,
}

/// Reward claim for blockchain submission
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RewardClaim {
    /// Validator claiming reward
    pub validator_id: String,
    /// Epoch number
    pub epoch: u64,
    /// List of CIDs pinned during epoch
    pub pinned_cids: Vec<String>,
    /// Total storage provided (bytes)
    pub total_storage: u64,
    /// Challenges passed
    pub challenges_passed: u32,
    /// Calculated reward amount (nCRYFT)
    pub reward_amount: u64,
    /// Merkle root of all proofs
    pub proof_root: String,
    /// Signature
    pub signature: String,
}

// ============================================================================
// Node Statistics
// ============================================================================

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeStats {
    /// Total pins (all types)
    pub total_pins: u64,
    /// Incentivized pins
    pub incentivized_pins: u64,
    /// Total storage used (bytes)
    pub storage_used: u64,
    /// Storage allocated (bytes)
    pub storage_allocated: u64,
    /// Challenges received
    pub challenges_received: u64,
    /// Challenges passed
    pub challenges_passed: u64,
    /// Challenges failed
    pub challenges_failed: u64,
    /// Total rewards earned (nCRYFT)
    pub total_rewards_earned: u64,
    /// Pending rewards
    pub pending_rewards: u64,
    /// Uptime seconds
    pub uptime_secs: u64,
}

// ============================================================================
// API Response Types (kubo-compatible + extensions)
// ============================================================================

#[derive(Serialize)]
struct IdResponse {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "PublicKey")]
    public_key: String,
    #[serde(rename = "Addresses")]
    addresses: Vec<String>,
    #[serde(rename = "AgentVersion")]
    agent_version: String,
    #[serde(rename = "ProtocolVersion")]
    protocol_version: String,
    // Cryft extensions
    #[serde(rename = "ValidatorID")]
    validator_id: Option<String>,
    #[serde(rename = "IncentivizedPins")]
    incentivized_pins: u64,
    #[serde(rename = "PendingRewards")]
    pending_rewards: u64,
}

#[derive(Serialize)]
struct AddResponse {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Hash")]
    hash: String,
    #[serde(rename = "Size")]
    size: String,
}

#[derive(Serialize)]
struct PinResponse {
    #[serde(rename = "Pins")]
    pins: Vec<String>,
}

#[derive(Serialize)]
struct PinLsResponse {
    #[serde(rename = "Keys")]
    keys: HashMap<String, PinTypeInfo>,
}

#[derive(Serialize)]
struct PinTypeInfo {
    #[serde(rename = "Type")]
    pin_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    incentivized: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reward_tier: Option<String>,
}

#[derive(Serialize)]
struct VersionResponse {
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "Commit")]
    commit: String,
    #[serde(rename = "Repo")]
    repo: String,
    #[serde(rename = "System")]
    system: String,
    #[serde(rename = "Golang")]
    golang: String,
}

#[derive(Serialize)]
struct SwarmPeersResponse {
    #[serde(rename = "Peers")]
    peers: Vec<PeerInfo>,
}

#[derive(Serialize)]
struct PeerInfo {
    #[serde(rename = "Addr")]
    addr: String,
    #[serde(rename = "Peer")]
    peer: String,
}

#[derive(Serialize)]
struct RepoStatResponse {
    #[serde(rename = "RepoSize")]
    repo_size: u64,
    #[serde(rename = "StorageMax")]
    storage_max: u64,
    #[serde(rename = "NumObjects")]
    num_objects: u64,
    #[serde(rename = "RepoPath")]
    repo_path: String,
    #[serde(rename = "Version")]
    version: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    #[serde(rename = "Message")]
    message: String,
    #[serde(rename = "Code")]
    code: i32,
    #[serde(rename = "Type")]
    error_type: String,
}

// ============================================================================
// Query Parameters
// ============================================================================

#[derive(Deserialize)]
struct AddQuery {
    #[serde(default)]
    pin: Option<bool>,
    #[serde(default)]
    incentivize: Option<bool>,
    #[serde(default)]
    tier: Option<String>,
}

#[derive(Deserialize)]
struct CatQuery {
    arg: String,
    #[serde(default)]
    offset: Option<u64>,
    #[serde(default)]
    length: Option<u64>,
}

#[derive(Deserialize)]
struct PinQuery {
    arg: String,
    #[serde(default)]
    incentivize: Option<bool>,
    #[serde(default)]
    tier: Option<String>,
}

#[derive(Deserialize)]
struct PinLsQuery {
    #[serde(default)]
    arg: Option<String>,
    #[serde(rename = "type")]
    #[serde(default)]
    pin_type: Option<String>,
    #[serde(default)]
    incentivized_only: Option<bool>,
}

#[derive(Deserialize)]
struct ChallengeQuery {
    cid: String,
    offset: u64,
    length: u32,
}

// ============================================================================
// Main Entry Point
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let filter = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    info!("🚀 Starting CryftIPFS Node...");
    info!("   Validator ID: {}", args.validator_id.as_deref().unwrap_or("(not configured)"));
    info!("   Max Storage: {} GB", args.max_storage_gb);
    info!("   RPC URL: {}", args.rpc_url);

    // Use in-memory storage for now
    let store = MemStore::new();

    // Create Iroh endpoint
    let endpoint = Endpoint::builder()
        .bind()
        .await
        .context("Failed to create Iroh endpoint")?;

    // Wait for endpoint to be online
    let _ = endpoint.online().await;

    let peer_id = endpoint.secret_key().public().to_string();
    info!("📡 Iroh node started with ID: {}", peer_id);

    // Create blobs protocol
    let blobs = BlobsProtocol::new(&store, None);

    // Build router
    let router = IrohRouter::builder(endpoint.clone())
        .accept(iroh_blobs::ALPN, blobs)
        .spawn();

    // Create validator config
    let validator_config = ValidatorConfig {
        node_id: args.validator_id.clone(),
        rpc_url: args.rpc_url,
        max_storage_bytes: args.max_storage_gb * 1024 * 1024 * 1024,
    };

    // Create shared state
    let state = Arc::new(AppState {
        store,
        endpoint,
        router,
        pins: RwLock::new(HashMap::new()),
        incentivized_pins: RwLock::new(HashMap::new()),
        pending_challenges: RwLock::new(HashMap::new()),
        completed_proofs: RwLock::new(Vec::new()),
        validator_config,
        stats: RwLock::new(NodeStats {
            storage_allocated: args.max_storage_gb * 1024 * 1024 * 1024,
            ..Default::default()
        }),
        start_time: Instant::now(),
    });

    // Build HTTP API
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let api_routes = Router::new()
        // Standard kubo-compatible endpoints
        .route("/api/v0/id", post(api_id).get(api_id))
        .route("/api/v0/version", post(api_version).get(api_version))
        .route("/api/v0/add", post(api_add))
        .route("/api/v0/cat", post(api_cat).get(api_cat))
        .route("/api/v0/pin/add", post(api_pin_add).get(api_pin_add))
        .route("/api/v0/pin/rm", post(api_pin_rm).get(api_pin_rm))
        .route("/api/v0/pin/ls", post(api_pin_ls).get(api_pin_ls))
        .route("/api/v0/swarm/peers", post(api_swarm_peers).get(api_swarm_peers))
        .route("/api/v0/repo/stat", post(api_repo_stat).get(api_repo_stat))
        
        // Cryft validator reward extensions
        .route("/api/v0/cryft/stats", get(api_validator_stats))
        .route("/api/v0/cryft/incentivized", get(api_list_incentivized))
        .route("/api/v0/cryft/incentivize", post(api_register_incentive))
        .route("/api/v0/cryft/challenge", post(api_handle_challenge))
        .route("/api/v0/cryft/prove", post(api_submit_proof))
        .route("/api/v0/cryft/claim", post(api_claim_rewards))
        .route("/api/v0/cryft/proofs", get(api_list_proofs))
        
        // Health check
        .route("/health", get(health_check))
        .with_state(state.clone())
        .layer(cors.clone());

    // Gateway routes
    let gateway_routes = Router::new()
        .route("/ipfs/*path", get(gateway_get))
        .with_state(state.clone())
        .layer(cors);

    // Start servers
    let api_addr: SocketAddr = format!("0.0.0.0:{}", args.api_port).parse()?;
    let gateway_addr: SocketAddr = format!("0.0.0.0:{}", args.gateway_port).parse()?;

    info!("🌐 API server listening on http://{}", api_addr);
    info!("🚪 Gateway server listening on http://{}", gateway_addr);

    // Spawn background task for periodic challenge checking and reward calculation
    let state_clone = state.clone();
    tokio::spawn(async move {
        background_tasks(state_clone).await;
    });

    // Run both servers
    let api_server = axum::serve(
        tokio::net::TcpListener::bind(api_addr).await?,
        api_routes,
    );

    let gateway_server = axum::serve(
        tokio::net::TcpListener::bind(gateway_addr).await?,
        gateway_routes,
    );

    tokio::select! {
        result = api_server => {
            if let Err(e) = result {
                warn!("API server error: {}", e);
            }
        }
        result = gateway_server => {
            if let Err(e) = result {
                warn!("Gateway server error: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Shutting down...");
        }
    }

    // Clean shutdown
    state.router.shutdown().await?;
    info!("CryftIPFS Node stopped");
    Ok(())
}

// ============================================================================
// Background Tasks
// ============================================================================

async fn background_tasks(state: Arc<AppState>) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    
    loop {
        interval.tick().await;
        
        // Update uptime
        {
            let mut stats = state.stats.write().await;
            stats.uptime_secs = state.start_time.elapsed().as_secs();
        }
        
        // Clean expired challenges
        {
            let now = current_timestamp();
            let mut challenges = state.pending_challenges.write().await;
            challenges.retain(|_, c| c.expires_at > now);
        }
        
        // Calculate pending rewards from completed proofs
        {
            let proofs = state.completed_proofs.read().await;
            let incentivized = state.incentivized_pins.read().await;
            
            let mut pending: u64 = 0;
            for proof in proofs.iter() {
                if let Some(pin) = incentivized.get(&proof.cid) {
                    pending += pin.reward_per_epoch;
                }
            }
            
            let mut stats = state.stats.write().await;
            stats.pending_rewards = pending;
        }
        
        debug!("Background tasks completed");
    }
}

// ============================================================================
// Standard IPFS API Handlers
// ============================================================================

async fn api_id(State(state): State<Arc<AppState>>) -> Json<IdResponse> {
    let public_key = state.endpoint.secret_key().public();
    let addr = state.endpoint.addr();
    let addresses: Vec<String> = addr.addrs.iter().map(|a| format!("{:?}", a)).collect();
    
    let stats = state.stats.read().await;

    Json(IdResponse {
        id: public_key.to_string(),
        public_key: public_key.to_string(),
        addresses,
        agent_version: format!("cryft-ipfs/{}", env!("CARGO_PKG_VERSION")),
        protocol_version: "iroh/1".to_string(),
        validator_id: state.validator_config.node_id.clone(),
        incentivized_pins: stats.incentivized_pins,
        pending_rewards: stats.pending_rewards,
    })
}

async fn api_version() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: "".to_string(),
        repo: "cryft-1".to_string(),
        system: format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
        golang: "rust/iroh".to_string(),
    })
}

async fn api_add(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AddQuery>,
    body: Bytes,
) -> Result<Json<AddResponse>, (StatusCode, Json<ErrorResponse>)> {
    if body.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                message: "No data provided".to_string(),
                code: 400,
                error_type: "error".to_string(),
            }),
        ));
    }

    let size = body.len() as u64;

    // Add to store
    let tag = state.store.add_slice(&body).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                message: format!("Failed to add content: {}", e),
                code: 500,
                error_type: "error".to_string(),
            }),
        )
    })?;

    let hash = tag.hash.to_string();

    // Determine reward tier
    let tier = params.tier.as_deref().and_then(|t| match t {
        "basic" => Some(RewardTier::Basic),
        "standard" => Some(RewardTier::Standard),
        "priority" => Some(RewardTier::Priority),
        "critical" => Some(RewardTier::Critical),
        _ => None,
    });

    // Pin if requested
    if params.pin.unwrap_or(true) {
        let incentivized = params.incentivize.unwrap_or(false);
        
        let record = PinRecord {
            hash: hash.clone(),
            size,
            pinned_at: current_timestamp(),
            name: None,
            incentivized,
            reward_tier: tier,
            last_challenge: None,
            challenges_passed: 0,
        };

        let mut pins = state.pins.write().await;
        pins.insert(hash.clone(), record);

        // Update stats
        let mut stats = state.stats.write().await;
        stats.total_pins += 1;
        stats.storage_used += size;
        if incentivized {
            stats.incentivized_pins += 1;
        }
    }

    info!("📦 Added content: {} ({} bytes)", hash, size);

    Ok(Json(AddResponse {
        name: hash.clone(),
        hash,
        size: size.to_string(),
    }))
}

async fn api_cat(
    State(state): State<Arc<AppState>>,
    Query(params): Query<CatQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let hash_str = params.arg.trim_start_matches("/ipfs/");

    let hash: Hash = hash_str.parse().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                message: format!("Invalid hash: {}", hash_str),
                code: 400,
                error_type: "error".to_string(),
            }),
        )
    })?;

    let data = state.store.get_bytes(hash).await.map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                message: format!("Content not found: {}", e),
                code: 404,
                error_type: "error".to_string(),
            }),
        )
    })?;

    // Apply offset/length if specified
    let data = match (params.offset, params.length) {
        (Some(offset), Some(length)) => {
            let start = offset as usize;
            let end = (offset + length) as usize;
            data.slice(start.min(data.len())..end.min(data.len()))
        }
        (Some(offset), None) => data.slice((offset as usize).min(data.len())..),
        (None, Some(length)) => data.slice(..(length as usize).min(data.len())),
        (None, None) => data,
    };

    Ok(data)
}

async fn api_pin_add(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PinQuery>,
) -> Result<Json<PinResponse>, (StatusCode, Json<ErrorResponse>)> {
    let hash = params.arg.trim_start_matches("/ipfs/").to_string();
    let incentivized = params.incentivize.unwrap_or(false);

    let tier = params.tier.as_deref().and_then(|t| match t {
        "basic" => Some(RewardTier::Basic),
        "standard" => Some(RewardTier::Standard),
        "priority" => Some(RewardTier::Priority),
        "critical" => Some(RewardTier::Critical),
        _ => None,
    });

    let record = PinRecord {
        hash: hash.clone(),
        size: 0, // Size unknown when pinning by hash
        pinned_at: current_timestamp(),
        name: None,
        incentivized,
        reward_tier: tier,
        last_challenge: None,
        challenges_passed: 0,
    };

    let mut pins = state.pins.write().await;
    let is_new = !pins.contains_key(&hash);
    pins.insert(hash.clone(), record);

    if is_new {
        let mut stats = state.stats.write().await;
        stats.total_pins += 1;
        if incentivized {
            stats.incentivized_pins += 1;
        }
    }

    info!("📌 Pinned: {} (incentivized: {})", hash, incentivized);

    Ok(Json(PinResponse { pins: vec![hash] }))
}

async fn api_pin_rm(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PinQuery>,
) -> Result<Json<PinResponse>, (StatusCode, Json<ErrorResponse>)> {
    let hash = params.arg.trim_start_matches("/ipfs/").to_string();

    let mut pins = state.pins.write().await;
    if let Some(record) = pins.remove(&hash) {
        let mut stats = state.stats.write().await;
        stats.total_pins = stats.total_pins.saturating_sub(1);
        stats.storage_used = stats.storage_used.saturating_sub(record.size);
        if record.incentivized {
            stats.incentivized_pins = stats.incentivized_pins.saturating_sub(1);
        }

        info!("📌 Unpinned: {}", hash);
        Ok(Json(PinResponse { pins: vec![hash] }))
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                message: format!("Pin not found: {}", hash),
                code: 404,
                error_type: "error".to_string(),
            }),
        ))
    }
}

async fn api_pin_ls(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PinLsQuery>,
) -> Json<PinLsResponse> {
    let pins = state.pins.read().await;
    let incentivized_only = params.incentivized_only.unwrap_or(false);

    let keys: HashMap<String, PinTypeInfo> = if let Some(arg) = params.arg {
        let hash = arg.trim_start_matches("/ipfs/");
        if let Some(record) = pins.get(hash) {
            let mut map = HashMap::new();
            map.insert(
                hash.to_string(),
                PinTypeInfo {
                    pin_type: "recursive".to_string(),
                    incentivized: Some(record.incentivized),
                    reward_tier: record.reward_tier.map(|t| format!("{:?}", t).to_lowercase()),
                },
            );
            map
        } else {
            HashMap::new()
        }
    } else {
        pins.iter()
            .filter(|(_, r)| !incentivized_only || r.incentivized)
            .map(|(k, r)| {
                (
                    k.clone(),
                    PinTypeInfo {
                        pin_type: "recursive".to_string(),
                        incentivized: Some(r.incentivized),
                        reward_tier: r.reward_tier.map(|t| format!("{:?}", t).to_lowercase()),
                    },
                )
            })
            .collect()
    };

    Json(PinLsResponse { keys })
}

async fn api_swarm_peers(State(_state): State<Arc<AppState>>) -> Json<SwarmPeersResponse> {
    Json(SwarmPeersResponse { peers: vec![] })
}

async fn api_repo_stat(State(state): State<Arc<AppState>>) -> Json<RepoStatResponse> {
    let stats = state.stats.read().await;

    Json(RepoStatResponse {
        repo_size: stats.storage_used,
        storage_max: stats.storage_allocated,
        num_objects: stats.total_pins,
        repo_path: "cryft-iroh".to_string(),
        version: "cryft-ipfs-1".to_string(),
    })
}

async fn health_check() -> &'static str {
    "OK"
}

// ============================================================================
// Cryft Validator Reward API Handlers
// ============================================================================

/// Get validator statistics
async fn api_validator_stats(State(state): State<Arc<AppState>>) -> Json<NodeStats> {
    let stats = state.stats.read().await;
    Json(stats.clone())
}

/// List all network-wide incentivized pins
async fn api_list_incentivized(State(state): State<Arc<AppState>>) -> Json<Vec<IncentivizedPin>> {
    let incentivized = state.incentivized_pins.read().await;
    Json(incentivized.values().cloned().collect())
}

/// Register a new incentivized pin (requires blockchain tx in production)
async fn api_register_incentive(
    State(state): State<Arc<AppState>>,
    Json(pin): Json<IncentivizedPin>,
) -> Result<Json<IncentivizedPin>, (StatusCode, Json<ErrorResponse>)> {
    // In production, this would verify a blockchain transaction
    // For now, accept the registration directly
    
    let mut incentivized = state.incentivized_pins.write().await;
    incentivized.insert(pin.cid.clone(), pin.clone());

    info!("💰 Registered incentivized pin: {} (reward: {} nCRYFT/epoch)", 
          pin.cid, pin.reward_per_epoch);

    Ok(Json(pin))
}

/// Handle a storage challenge (proof of storage request)
async fn api_handle_challenge(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ChallengeQuery>,
) -> Result<Json<StorageProof>, (StatusCode, Json<ErrorResponse>)> {
    let hash_str = params.cid.trim_start_matches("/ipfs/");
    
    // Parse hash
    let hash: Hash = hash_str.parse().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                message: format!("Invalid hash: {}", hash_str),
                code: 400,
                error_type: "error".to_string(),
            }),
        )
    })?;

    // Fetch the data
    let data = state.store.get_bytes(hash).await.map_err(|e| {
        // Challenge failed - we don't have the data
        // Note: stats update happens after we return
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                message: format!("Challenge failed - content not found: {}", e),
                code: 404,
                error_type: "error".to_string(),
            }),
        )
    })?;

    // Extract the requested chunk
    let start = params.offset as usize;
    let end = (params.offset as usize + params.length as usize).min(data.len());
    
    if start >= data.len() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                message: "Offset beyond content length".to_string(),
                code: 400,
                error_type: "error".to_string(),
            }),
        ));
    }

    let chunk = &data[start..end];
    
    // Compute Blake3 hash of chunk as proof
    let chunk_hash = blake3_hash(chunk);
    
    // Generate challenge ID
    let challenge_id = format!("{}-{}-{}", hash_str, params.offset, current_timestamp());
    
    // Create proof
    let proof = StorageProof {
        challenge_id: challenge_id.clone(),
        cid: hash_str.to_string(),
        validator_id: state.validator_config.node_id.clone().unwrap_or_default(),
        chunk_hash,
        proven_at: current_timestamp(),
        signature: "".to_string(), // Would be signed in production
    };

    // Update stats
    {
        let mut stats = state.stats.write().await;
        stats.challenges_received += 1;
        stats.challenges_passed += 1;
    }

    // Update pin record
    {
        let mut pins = state.pins.write().await;
        if let Some(record) = pins.get_mut(hash_str) {
            record.last_challenge = Some(current_timestamp());
            record.challenges_passed += 1;
        }
    }

    // Store completed proof
    {
        let mut proofs = state.completed_proofs.write().await;
        proofs.push(proof.clone());
    }

    info!("✅ Challenge passed for CID: {}", hash_str);

    Ok(Json(proof))
}

/// Submit a storage proof (for async challenge response)
async fn api_submit_proof(
    State(state): State<Arc<AppState>>,
    Json(proof): Json<StorageProof>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    // Verify the proof would be validated here in production
    
    let mut proofs = state.completed_proofs.write().await;
    proofs.push(proof.clone());

    Ok(Json(serde_json::json!({
        "success": true,
        "proof_id": proof.challenge_id,
        "message": "Proof submitted successfully"
    })))
}

/// Claim rewards for completed proofs
async fn api_claim_rewards(
    State(state): State<Arc<AppState>>,
) -> Result<Json<RewardClaim>, (StatusCode, Json<ErrorResponse>)> {
    let validator_id = state.validator_config.node_id.clone().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                message: "Validator ID not configured".to_string(),
                code: 400,
                error_type: "error".to_string(),
            }),
        )
    })?;

    let proofs = state.completed_proofs.read().await;
    let pins = state.pins.read().await;
    let incentivized = state.incentivized_pins.read().await;

    if proofs.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                message: "No proofs available for claim".to_string(),
                code: 400,
                error_type: "error".to_string(),
            }),
        ));
    }

    // Calculate reward
    let mut total_reward: u64 = 0;
    let mut total_storage: u64 = 0;
    let mut pinned_cids: Vec<String> = Vec::new();

    for proof in proofs.iter() {
        if let Some(inc_pin) = incentivized.get(&proof.cid) {
            total_reward += inc_pin.reward_per_epoch * inc_pin.tier.multiplier();
        }
        if let Some(pin) = pins.get(&proof.cid) {
            total_storage += pin.size;
        }
        if !pinned_cids.contains(&proof.cid) {
            pinned_cids.push(proof.cid.clone());
        }
    }

    let claim = RewardClaim {
        validator_id,
        epoch: current_timestamp() / 3600, // Hourly epochs
        pinned_cids,
        total_storage,
        challenges_passed: proofs.len() as u32,
        reward_amount: total_reward,
        proof_root: "".to_string(), // Would be merkle root in production
        signature: "".to_string(),
    };

    // In production, this would submit to blockchain
    info!("💸 Reward claim: {} nCRYFT for {} challenges", total_reward, claim.challenges_passed);

    // Clear completed proofs after claim
    drop(proofs);
    {
        let mut proofs = state.completed_proofs.write().await;
        proofs.clear();
    }

    // Update stats
    {
        let mut stats = state.stats.write().await;
        stats.total_rewards_earned += total_reward;
        stats.pending_rewards = 0;
    }

    Ok(Json(claim))
}

/// List pending proofs
async fn api_list_proofs(State(state): State<Arc<AppState>>) -> Json<Vec<StorageProof>> {
    let proofs = state.completed_proofs.read().await;
    Json(proofs.clone())
}

// ============================================================================
// Gateway Handler
// ============================================================================

async fn gateway_get(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(path): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let hash_str = path.split('/').next().unwrap_or(&path);

    let hash: Hash = hash_str
        .parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, format!("Invalid hash: {}", hash_str)))?;

    let data = state
        .store
        .get_bytes(hash)
        .await
        .map_err(|e| (StatusCode::NOT_FOUND, format!("Content not found: {}", e)))?;

    let content_type = infer::get(&data)
        .map(|t| t.mime_type())
        .unwrap_or("application/octet-stream");

    Ok(([(axum::http::header::CONTENT_TYPE, content_type)], data))
}

// ============================================================================
// Utility Functions
// ============================================================================

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn blake3_hash(data: &[u8]) -> String {
    // Simple hash for demo - use proper blake3 crate in production
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}
