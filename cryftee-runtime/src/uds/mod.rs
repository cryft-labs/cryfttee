//! Unix Domain Socket module - UDS listener for API

mod service;

pub use service::*;

use anyhow::Result;

#[cfg(unix)]
use std::path::Path;

#[cfg(unix)]
use tokio::net::UnixListener;

#[cfg(unix)]
use hyper_util::rt::TokioIo;

use crate::http::AppState;

/// Serve API over Unix Domain Socket
#[cfg(unix)]
pub async fn serve_uds(state: AppState, socket_path: &str) -> Result<()> {
    use tracing::info;

    let path = Path::new(socket_path);
    
    // Remove existing socket if present
    if path.exists() {
        std::fs::remove_file(path)?;
    }

    // Create parent directory if needed
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(path)?;
    info!("UDS server listening on {}", socket_path);

    let router = build_router(state);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        
        let router = router.clone();
        
        tokio::spawn(async move {
            let service = tower::ServiceExt::into_make_service(router);
            if let Err(err) = hyper_util::server::conn::auto::Builder::new(
                hyper_util::rt::TokioExecutor::new()
            )
            .serve_connection(io, service)
            .await
            {
                tracing::error!("Error serving UDS connection: {}", err);
            }
        });
    }
}

/// Stub for non-Unix platforms
#[cfg(not(unix))]
pub async fn serve_uds(_state: AppState, _socket_path: &str) -> Result<()> {
    anyhow::bail!("UDS is not supported on this platform")
}
