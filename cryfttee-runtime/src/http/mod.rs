//! HTTP module - axum-based HTTP/HTTPS server

mod api;
mod kiosk;

pub use api::*;
pub use kiosk::*;

use std::net::SocketAddr;
use std::sync::Arc;
use std::path::PathBuf;

use axum::{
    Router,
    routing::{get, post},
};
use tower_http::cors::{CorsLayer, Any};
use tower_http::trace::TraceLayer;
use tower_http::services::ServeDir;
use tokio::sync::RwLock;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use anyhow::{Result, Context};
use tracing::info;

use crate::config::CryftteeConfig;
use crate::runtime::{ModuleRegistry, RuntimeState};

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub config: CryftteeConfig,
    pub registry: Arc<RwLock<ModuleRegistry>>,
    pub runtime_state: Arc<RwLock<RuntimeState>>,
}

/// Build the main router
pub fn build_router(state: AppState) -> Router {
    // API routes under /v1
    let api_routes = Router::new()
        // BLS endpoints
        .route("/staking/bls/register", post(api::bls_register))
        .route("/staking/bls/sign", post(api::bls_sign))
        // TLS endpoints
        .route("/staking/tls/register", post(api::tls_register))
        .route("/staking/tls/sign", post(api::tls_sign))
        // Status and attestation
        .route("/staking/status", get(api::get_status))
        .route("/runtime/attestation", get(api::get_attestation))
        // Schema
        .route("/schema/modules", get(api::get_schema))
        // Admin
        .route("/admin/reload-modules", post(api::reload_modules));

    // Kiosk UI routes
    let ui_dir = state.config.ui_dir.clone();
    let kiosk_routes = Router::new()
        .route("/api/modules", get(kiosk::get_modules))
        .route("/api/attestation", get(kiosk::get_attestation))
        .route("/api/schema", get(kiosk::get_schema))
        .route("/api/manifest", get(kiosk::get_manifest))
        .route("/api/reload", post(kiosk::reload_modules))
        .route("/api/context", get(kiosk::get_context))
        // Module enable/disable
        .route("/api/modules/:module_id/enable", post(kiosk::enable_module))
        .route("/api/modules/:module_id/disable", post(kiosk::disable_module))
        // Module GUI serving - both base path and wildcard for static assets
        .route("/api/modules/:module_id/gui", get(kiosk::serve_module_gui_index))
        .route("/api/modules/:module_id/gui/*path", get(kiosk::serve_module_gui))
        // Module signing endpoints
        .route("/api/signing/modules", get(kiosk::get_signable_modules))
        .route("/api/signing/prepare", post(kiosk::prepare_module_signing))
        .route("/api/signing/sign", post(kiosk::sign_module))
        .route("/api/signing/trust", get(kiosk::get_trust_config))
        .route("/api/signing/chain", get(kiosk::get_chain_info))
        .route("/api/signing/publisher/:publisher_id", get(kiosk::get_publisher_status))
        .route("/api/signing/apply", post(kiosk::apply_signed_module))
        .fallback_service(ServeDir::new(ui_dir));

    // Combine routes
    Router::new()
        .nest("/v1", api_routes)
        .merge(kiosk_routes)
        .layer(CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Serve HTTP (kiosk UI and optionally API)
pub async fn serve_http(state: AppState, addr: SocketAddr) -> Result<()> {
    let router = build_router(state);
    
    info!("HTTP server listening on {}", addr);
    
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    
    Ok(())
}

/// Serve HTTPS (API with TLS)
pub async fn serve_https(
    state: AppState,
    addr: SocketAddr,
    cert_path: PathBuf,
    key_path: PathBuf,
) -> Result<()> {
    use std::io::BufReader;
    use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};

    // Load certificate (rustls 0.21 expects Certificate wrapper)
    let cert_file = std::fs::File::open(&cert_path)
        .with_context(|| format!("Failed to open cert file: {:?}", cert_path))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<Certificate> = rustls_pemfile::certs(&mut cert_reader)
        .filter_map(|r| r.ok())
        .map(|der| Certificate(der.to_vec()))
        .collect();

    if certs.is_empty() {
        anyhow::bail!("No certificates found in {:?}", cert_path);
    }

    // Load private key (rustls 0.21 expects PrivateKey wrapper)
    let key_file = std::fs::File::open(&key_path)
        .with_context(|| format!("Failed to open key file: {:?}", key_path))?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .with_context(|| "Failed to read private key")?
        .ok_or_else(|| anyhow::anyhow!("No private key found in {:?}", key_path))?;
    let key = PrivateKey(key.secret_der().to_vec());

    // Build TLS config (rustls 0.21 API)
    let tls_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .with_context(|| "Invalid TLS configuration")?;

    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let router = build_router(state);
    
    info!("HTTPS server listening on {}", addr);
    
    let listener = TcpListener::bind(addr).await?;
    
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = tls_acceptor.clone();
        let router = router.clone();
        
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let io = hyper_util::rt::TokioIo::new(tls_stream);
                    let service = hyper::service::service_fn(move |req| {
                        let router = router.clone();
                        async move {
                            tower::ServiceExt::oneshot(router, req).await
                        }
                    });
                    
                    if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new()
                    )
                    .serve_connection(io, service)
                    .await
                    {
                        tracing::error!("Error serving connection from {}: {}", peer_addr, e);
                    }
                }
                Err(e) => {
                    tracing::error!("TLS handshake failed from {}: {}", peer_addr, e);
                }
            }
        });
    }
}
