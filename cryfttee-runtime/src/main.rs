//! CryftTEE Runtime - TEE-style sidecar for WASM modules
//!
//! This is the main entry point for the cryfttee binary. It:
//! - Parses configuration from environment (set by cryftgo) and CLI
//! - Initializes the module registry and loads WASM modules
//! - Starts API listeners (UDS and/or HTTPS)
//! - Serves the kiosk UI on port 3232
//!
//! ## Configuration Priority
//! 1. CLI flags (--flag=value)
//! 2. Environment variables (CRYFTTEE_*) - set by cryftgo
//! 3. Config file (if --config-file specified)
//! 4. Default values

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tokio::sync::RwLock;
use tracing::{info, error, warn};

use cryfttee_runtime::{Args, CryftteeConfig, ModuleRegistry, RuntimeState, ModuleInitConfig, CRYFTTEE_VERSION};
use cryfttee_runtime::http;

#[cfg(unix)]
use cryfttee_runtime::uds;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse CLI arguments (also reads env vars via clap)
    let args = Args::parse();

    // Initialize logging based on config
    let log_level = args.log_level.clone().unwrap_or_else(|| {
        if args.verbose { "debug".to_string() } else { "info".to_string() }
    });
    init_logging(&log_level, args.log_json);

    info!("Starting cryfttee v{}", CRYFTTEE_VERSION);

    // Load configuration with priority: CLI > env > config file > defaults
    let config = CryftteeConfig::load(&args)?;

    // Build module init config from merged config
    let init_config = ModuleInitConfig {
        module_filter: config.enabled_modules.clone(),
        web3signer_url: Some(config.web3signer_url.clone()),
        vault_url: config.vault_url.clone(),
        vault_token: config.vault_token.clone(),
        key_seed: config.key_seed.clone(),
        node_id: config.node_id.clone(),
    };

    // Initialize runtime state
    let runtime_state = Arc::new(RwLock::new(RuntimeState::new()));

    // Initialize module registry with init config
    let registry = Arc::new(RwLock::new(ModuleRegistry::new_with_init_config(config.clone(), init_config)));

    // Load modules from manifest (respecting filter)
    {
        let mut reg = registry.write().await;
        match reg.load_modules_filtered().await {
            Ok(count) => info!("Loaded {} modules", count),
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

    // Initial Web3Signer health check
    {
        let mut state = runtime_state.write().await;
        state.check_web3signer_health(&config.web3signer_url).await;
        if state.web3signer_reachable {
            info!("Web3Signer connected at {}", config.web3signer_url);
        } else {
            warn!("Web3Signer not reachable at {} - signing operations will fail", config.web3signer_url);
        }
    }

    // Start background Web3Signer health checker
    let health_check_state = runtime_state.clone();
    let health_check_url = config.web3signer_url.clone();
    let health_check_interval = config.web3signer_health_check_interval;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(health_check_interval));
        loop {
            interval.tick().await;
            let mut state = health_check_state.write().await;
            state.check_web3signer_health(&health_check_url).await;
        }
    });

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

    info!("CryftTEE is ready");

    // Wait for servers
    ui_server.await?;
    if let Some(api) = api_server {
        api.await?;
    }

    Ok(())
}

fn init_logging(level: &str, json: bool) {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    if json {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }
}
