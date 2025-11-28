//! Cryftee Runtime Library
//!
//! Core exports for the cryftee TEE-style sidecar runtime.

use clap::Parser;

pub mod config;
pub mod http;
pub mod runtime;
pub mod signing;
pub mod storage;
pub mod uds;
pub mod wasm_api;

/// Cryftee semantic version constant
pub const CRYFTEE_VERSION: &str = "0.4.0";

/// CLI arguments for cryftee runtime
#[derive(Parser, Debug, Clone)]
#[command(name = "cryftee")]
#[command(about = "TEE-style sidecar runtime for WASM modules")]
#[command(version = CRYFTEE_VERSION)]
pub struct Args {
    /// Path to configuration file
    #[arg(short, long, env = "CRYFTEE_CONFIG")]
    pub config: Option<String>,

    /// Module directory path
    #[arg(long, env = "CRYFTEE_MODULE_DIR")]
    pub module_dir: Option<String>,

    /// Manifest file path
    #[arg(long, env = "CRYFTEE_MANIFEST_PATH")]
    pub manifest_path: Option<String>,

    /// UI assets directory
    #[arg(long, env = "CRYFTEE_UI_DIR")]
    pub ui_dir: Option<String>,

    /// Trust configuration path
    #[arg(long, env = "CRYFTEE_TRUST_CONFIG")]
    pub trust_config: Option<String>,

    /// API transport: "uds" or "https"
    #[arg(long, env = "CRYFTEE_API_TRANSPORT", default_value = "uds")]
    pub api_transport: String,

    /// UDS socket path
    #[arg(long, env = "CRYFTEE_UDS_PATH", default_value = "/var/run/cryftee.sock")]
    pub uds_path: String,

    /// HTTP bind address for API and kiosk UI
    #[arg(long, env = "CRYFTEE_HTTP_ADDR", default_value = "0.0.0.0:323")]
    pub http_addr: String,

    /// TLS certificate path (for HTTPS mode)
    #[arg(long, env = "CRYFTEE_TLS_CERT")]
    pub tls_cert: Option<String>,

    /// TLS private key path (for HTTPS mode)
    #[arg(long, env = "CRYFTEE_TLS_KEY")]
    pub tls_key: Option<String>,

    /// Enable verbose logging
    #[arg(short, long, env = "CRYFTEE_VERBOSE")]
    pub verbose: bool,
}

pub use config::{CryfteeConfig, TrustConfigFile, TrustPolicy, TrustedPublisher};
pub use runtime::{ModuleRegistry, RuntimeState, ModuleInfo, ModuleStatus};
pub use storage::{ManifestEntry, Manifest};
pub use wasm_api::{WasmModule, SigningCapability};
