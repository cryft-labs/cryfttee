//! IPFS Node - Embedded Iroh-based IPFS daemon for CryftTEE
//!
//! Provides a kubo-compatible HTTP API while using Iroh under the hood.
//! This allows the module to work without requiring an external IPFS daemon.

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
use iroh_blobs::{
    store::mem::MemStore,
    BlobsProtocol, Hash,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::Instant,
};
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, warn};

/// IPFS Node for CryftTEE - Iroh-powered embedded IPFS daemon
#[derive(Parser, Debug)]
#[command(name = "ipfs-node")]
#[command(about = "Embedded IPFS node powered by Iroh")]
struct Args {
    /// API server port
    #[arg(long, env = "IPFS_API_PORT", default_value = "5001")]
    api_port: u16,

    /// Gateway server port
    #[arg(long, env = "IPFS_GATEWAY_PORT", default_value = "8080")]
    gateway_port: u16,

    /// Data directory for persistent storage
    #[arg(long, env = "IPFS_DATA_DIR")]
    #[allow(dead_code)]
    data_dir: Option<PathBuf>,

    /// Use in-memory storage (no persistence)
    #[arg(long, env = "IPFS_MEMORY_ONLY", default_value = "false")]
    #[allow(dead_code)]
    memory_only: bool,

    /// Enable verbose logging
    #[arg(long, short, env = "IPFS_VERBOSE")]
    verbose: bool,
}

/// Application state holding the Iroh node and metadata
struct AppState {
    /// Blob store
    store: MemStore,
    /// Iroh endpoint for networking
    endpoint: Endpoint,
    /// Iroh router for protocol handling
    router: IrohRouter,
    /// Pinned hashes (persisted separately)
    pins: RwLock<HashMap<String, PinInfo>>,
    /// Named keys for IPNS-like functionality
    #[allow(dead_code)]
    keys: RwLock<HashMap<String, String>>,
    /// Start time for uptime tracking
    #[allow(dead_code)]
    start_time: Instant,
}

#[derive(Clone, Serialize, Deserialize)]
struct PinInfo {
    hash: String,
    #[allow(dead_code)]
    name: Option<String>,
    #[allow(dead_code)]
    pinned_at: String,
}

// ============================================================================
// API Response Types (kubo-compatible)
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
    #[serde(rename = "wrap-with-directory")]
    #[serde(default)]
    #[allow(dead_code)]
    wrap: Option<bool>,
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
}

#[derive(Deserialize)]
struct PinLsQuery {
    #[serde(default)]
    arg: Option<String>,
    #[serde(rename = "type")]
    #[serde(default)]
    #[allow(dead_code)]
    pin_type: Option<String>,
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

    info!("Starting IPFS Node (Iroh-powered)...");

    // Use in-memory storage for simplicity
    // TODO: Add persistent storage support with FsStore
    info!("Using in-memory storage");
    let store = MemStore::new();

    // Create Iroh endpoint with default discovery
    let endpoint = Endpoint::builder()
        .bind()
        .await
        .context("Failed to create Iroh endpoint")?;

    // Wait for endpoint to be online
    let _ = endpoint.online().await;

    let peer_id = endpoint.secret_key().public().to_string();
    info!("Iroh node started with ID: {}", peer_id);

    // Create blobs protocol
    let blobs = BlobsProtocol::new(&store, None);

    // Build router
    let router = IrohRouter::builder(endpoint.clone())
        .accept(iroh_blobs::ALPN, blobs)
        .spawn();

    // Create shared state
    let state = Arc::new(AppState {
        store,
        endpoint,
        router,
        pins: RwLock::new(HashMap::new()),
        keys: RwLock::new(HashMap::new()),
        start_time: Instant::now(),
    });

    // Build HTTP API
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let api_routes = Router::new()
        // Node info
        .route("/api/v0/id", post(api_id).get(api_id))
        .route("/api/v0/version", post(api_version).get(api_version))
        // Content operations
        .route("/api/v0/add", post(api_add))
        .route("/api/v0/cat", post(api_cat).get(api_cat))
        // Pin operations
        .route("/api/v0/pin/add", post(api_pin_add).get(api_pin_add))
        .route("/api/v0/pin/rm", post(api_pin_rm).get(api_pin_rm))
        .route("/api/v0/pin/ls", post(api_pin_ls).get(api_pin_ls))
        // Swarm operations
        .route("/api/v0/swarm/peers", post(api_swarm_peers).get(api_swarm_peers))
        // Repo operations
        .route("/api/v0/repo/stat", post(api_repo_stat).get(api_repo_stat))
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

    info!("API server listening on http://{}", api_addr);
    info!("Gateway server listening on http://{}", gateway_addr);

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
    info!("IPFS Node stopped");
    Ok(())
}

// ============================================================================
// API Handlers
// ============================================================================

async fn api_id(
    State(state): State<Arc<AppState>>,
) -> Json<IdResponse> {
    let public_key = state.endpoint.secret_key().public();
    
    // Get endpoint address info
    let addr = state.endpoint.addr();
    let addresses: Vec<String> = addr.addrs.iter()
        .map(|a| format!("{:?}", a))
        .collect();

    Json(IdResponse {
        id: public_key.to_string(),
        public_key: public_key.to_string(),
        addresses,
        agent_version: format!("cryfttee-ipfs/{}", env!("CARGO_PKG_VERSION")),
        protocol_version: "iroh/1".to_string(),
    })
}

async fn api_version() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: "".to_string(),
        repo: "12".to_string(),
        system: format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
        golang: "rust".to_string(),
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

    let size = body.len();

    // Add to store
    let tag = state.store
        .add_slice(&body)
        .await
        .map_err(|e| {
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

    // Pin if requested (default: true for kubo compatibility)
    if params.pin.unwrap_or(true) {
        let mut pins = state.pins.write().await;
        pins.insert(
            hash.clone(),
            PinInfo {
                hash: hash.clone(),
                name: None,
                pinned_at: chrono::Utc::now().to_rfc3339(),
            },
        );
    }

    info!("Added content: {} ({} bytes)", hash, size);

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

    // Read from store
    let data = state.store
        .get_bytes(hash)
        .await
        .map_err(|e| {
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
        (Some(offset), None) => {
            let start = offset as usize;
            data.slice(start.min(data.len())..)
        }
        (None, Some(length)) => {
            let end = length as usize;
            data.slice(..end.min(data.len()))
        }
        (None, None) => data,
    };

    Ok(data)
}

async fn api_pin_add(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PinQuery>,
) -> Result<Json<PinResponse>, (StatusCode, Json<ErrorResponse>)> {
    let hash = params.arg.trim_start_matches("/ipfs/").to_string();

    let mut pins = state.pins.write().await;
    pins.insert(
        hash.clone(),
        PinInfo {
            hash: hash.clone(),
            name: None,
            pinned_at: chrono::Utc::now().to_rfc3339(),
        },
    );

    info!("Pinned: {}", hash);

    Ok(Json(PinResponse { pins: vec![hash] }))
}

async fn api_pin_rm(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PinQuery>,
) -> Result<Json<PinResponse>, (StatusCode, Json<ErrorResponse>)> {
    let hash = params.arg.trim_start_matches("/ipfs/").to_string();

    let mut pins = state.pins.write().await;
    if pins.remove(&hash).is_some() {
        info!("Unpinned: {}", hash);
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

    let keys: HashMap<String, PinTypeInfo> = if let Some(arg) = params.arg {
        let hash = arg.trim_start_matches("/ipfs/");
        if pins.contains_key(hash) {
            let mut map = HashMap::new();
            map.insert(hash.to_string(), PinTypeInfo { pin_type: "recursive".to_string() });
            map
        } else {
            HashMap::new()
        }
    } else {
        pins.keys()
            .map(|k| (k.clone(), PinTypeInfo { pin_type: "recursive".to_string() }))
            .collect()
    };

    Json(PinLsResponse { keys })
}

async fn api_swarm_peers(
    State(_state): State<Arc<AppState>>,
) -> Json<SwarmPeersResponse> {
    // For now return empty peers - the new API doesn't have a direct equivalent
    // The connection management is handled differently in the new iroh
    Json(SwarmPeersResponse { peers: vec![] })
}

async fn api_repo_stat(
    State(state): State<Arc<AppState>>,
) -> Json<RepoStatResponse> {
    let pins = state.pins.read().await;

    Json(RepoStatResponse {
        repo_size: 0, // Would need store-specific implementation
        storage_max: 10 * 1024 * 1024 * 1024, // 10GB default
        num_objects: pins.len() as u64,
        repo_path: "iroh".to_string(),
        version: "iroh-blobs-1".to_string(),
    })
}

async fn health_check() -> &'static str {
    "OK"
}

// ============================================================================
// Gateway Handler
// ============================================================================

async fn gateway_get(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(path): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let hash_str = path.split('/').next().unwrap_or(&path);

    let hash: Hash = hash_str.parse().map_err(|_| {
        (StatusCode::BAD_REQUEST, format!("Invalid hash: {}", hash_str))
    })?;

    let data = state.store
        .get_bytes(hash)
        .await
        .map_err(|e| {
            (StatusCode::NOT_FOUND, format!("Content not found: {}", e))
        })?;

    // Detect content type
    let content_type = infer::get(&data)
        .map(|t| t.mime_type())
        .unwrap_or("application/octet-stream");

    Ok((
        [(axum::http::header::CONTENT_TYPE, content_type)],
        data,
    ))
}
