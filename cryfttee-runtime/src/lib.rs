//! CryftTEE Runtime Library
//!
//! Core exports for the cryfttee TEE-style sidecar runtime.

use clap::Parser;

pub mod config;
pub mod http;
pub mod runtime;
pub mod signing;
pub mod storage;
pub mod uds;
pub mod wasm_api;

/// CryftTEE semantic version constant
pub const CRYFTTEE_VERSION: &str = "0.4.0";

/// CLI arguments for cryfttee runtime
#[derive(Parser, Debug, Clone)]
#[command(name = "cryfttee")]
#[command(about = "TEE-style sidecar runtime for WASM modules")]
#[command(version = CRYFTTEE_VERSION)]
pub struct Args {
    /// Path to configuration file
    #[arg(short, long, env = "CRYFTTEE_CONFIG")]
    pub config: Option<String>,

    /// Module directory path
    #[arg(long, env = "CRYFTTEE_MODULE_DIR")]
    pub module_dir: Option<String>,

    /// Manifest file path
    #[arg(long, env = "CRYFTTEE_MANIFEST_PATH")]
    pub manifest_path: Option<String>,

    /// UI assets directory
    #[arg(long, env = "CRYFTTEE_UI_DIR")]
    pub ui_dir: Option<String>,

    /// Trust configuration path
    #[arg(long, env = "CRYFTTEE_TRUST_CONFIG")]
    pub trust_config: Option<String>,

    /// API transport: "uds" or "https"
    #[arg(long, env = "CRYFTTEE_API_TRANSPORT", default_value = "uds")]
    pub api_transport: String,

    /// UDS socket path
    #[arg(long, env = "CRYFTTEE_UDS_PATH", default_value = "/tmp/cryfttee.sock")]
    pub uds_path: String,

    /// HTTP bind address for API and kiosk UI
    #[arg(long, env = "CRYFTTEE_HTTP_ADDR", default_value = "0.0.0.0:3232")]
    pub http_addr: String,

    /// TLS certificate path (for HTTPS mode)
    #[arg(long, env = "CRYFTTEE_TLS_CERT")]
    pub tls_cert: Option<String>,

    /// TLS private key path (for HTTPS mode)
    #[arg(long, env = "CRYFTTEE_TLS_KEY")]
    pub tls_key: Option<String>,

    /// Enable verbose logging
    #[arg(short, long, env = "CRYFTTEE_VERBOSE")]
    pub verbose: bool,
}

pub use config::{CryftteeConfig, TrustConfigFile, TrustPolicy, TrustedPublisher};
pub use runtime::{ModuleRegistry, RuntimeState, ModuleInfo, ModuleStatus};
pub use storage::{ManifestEntry, Manifest};
pub use wasm_api::{WasmModule, SigningCapability};
