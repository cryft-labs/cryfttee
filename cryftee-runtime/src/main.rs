//! Cryftee Runtime - TEE-style sidecar for WASM modules
//!
//! This is the main entry point for the cryftee binary. It:
//! - Parses configuration from environment and CLI
//! - Initializes the module registry and loads WASM modules
//! - Starts API listeners (UDS and/or HTTPS)
//! - Serves the kiosk UI on port 323

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tokio::sync::RwLock;
use tracing::{info, error, warn};

use cryftee_runtime::{Args, CryfteeConfig, ModuleRegistry, RuntimeState, CRYFTEE_VERSION};
use cryftee_runtime::http;

#[cfg(unix)]
use cryftee_runtime::uds;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse CLI arguments
    let args = Args::parse();

    // Initialize logging
    init_logging(args.verbose);

    info!("Starting cryftee v{}", CRYFTEE_VERSION);

    // Load configuration
    let config = CryfteeConfig::load(&args)?;
    info!("Configuration loaded successfully");

    // Initialize runtime state
    let runtime_state = Arc::new(RwLock::new(RuntimeState::new()));

    // Initialize module registry
    let registry = Arc::new(RwLock::new(ModuleRegistry::new(config.clone())));

    // Load modules from manifest
    {
        let mut reg = registry.write().await;
        match reg.load_all_modules().await {
            Ok(count) => info!("Loaded {} modules from manifest", count),
            Err(e) => {
                error!("Failed to load modules: {}. Continuing with empty registry.", e);
            }
        }
    }

    // Compute initial runtime attestation
    {
        let mut state = runtime_state.write().await;
        let reg = registry.read().await;
        state.compute_attestation(&config, &reg)?;
        info!("Runtime attestation computed");
    }

    // Build the shared application state
    let app_state = http::AppState {
        config: config.clone(),
        registry: registry.clone(),
        runtime_state: runtime_state.clone(),
    };

    // Start servers based on transport configuration
    let ui_addr: SocketAddr = config.ui_addr.parse()?;
    let api_addr: SocketAddr = config.http_addr.parse()?;

    // Always start HTTP server for kiosk UI
    let ui_server = tokio::spawn({
        let state = app_state.clone();
        async move {
            info!("Starting kiosk UI server on {}", ui_addr);
            if let Err(e) = http::serve_http(state, ui_addr).await {
                error!("HTTP server error: {}", e);
            }
        }
    });

    // Start API transport (UDS or HTTPS)
    let api_server = match config.api_transport.as_str() {
        "uds" => {
            #[cfg(unix)]
            {
                let state = app_state.clone();
                let uds_path = config.uds_path.clone();
                Some(tokio::spawn(async move {
                    info!("Starting UDS API server on {}", uds_path);
                    if let Err(e) = uds::serve_uds(state, &uds_path).await {
                        error!("UDS server error: {}", e);
                    }
                }))
            }
            #[cfg(not(unix))]
            {
                warn!("UDS transport not supported on this platform, falling back to HTTP");
                None
            }
        }
        "https" => {
            let state = app_state.clone();
            let tls_cert = config.tls_cert.clone();
            let tls_key = config.tls_key.clone();
            
            if tls_cert.is_some() && tls_key.is_some() {
                Some(tokio::spawn(async move {
                    info!("Starting HTTPS API server on {}", api_addr);
                    if let Err(e) = http::serve_https(state, api_addr, tls_cert.unwrap(), tls_key.unwrap()).await {
                        error!("HTTPS server error: {}", e);
                    }
                }))
            } else {
                error!("HTTPS transport requires TLS certificate and key");
                None
            }
        }
        _ => {
            warn!("Unknown transport '{}', defaulting to HTTP only", config.api_transport);
            None
        }
    };

    info!("Cryftee is ready");

    // Wait for servers
    ui_server.await?;
    if let Some(api) = api_server {
        api.await?;
    }

    Ok(())
}

fn init_logging(verbose: bool) {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    let filter = if verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}
