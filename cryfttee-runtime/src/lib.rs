//! CryftTEE Runtime Library
//!
//! Core exports for the cryfttee TEE-style sidecar runtime.
//!
//! ## Configuration Priority (highest to lowest)
//! 1. CLI flags (--flag=value)
//! 2. Environment variables (CRYFTTEE_*)  ← cryftgo sets these
//! 3. Config file (if --config-file specified)
//! 4. Default values
//!
//! By default, cryftgo controls cryfttee via environment variables.
//! Config files are only used when explicitly specified.

use clap::Parser;

pub mod config;
pub mod http;
pub mod limits;
pub mod runtime;
pub mod signing;
pub mod storage;
pub mod uds;
pub mod wasm_api;

/// CryftTEE semantic version constant
pub const CRYFTTEE_VERSION: &str = "0.4.0";

/// CLI arguments for cryfttee runtime
/// 
/// Configuration is loaded in this priority order:
/// 1. CLI flags (highest priority)
/// 2. Environment variables (CRYFTTEE_*) - set by cryftgo
/// 3. Config file (if --config-file or --config-content specified)
/// 4. Defaults (lowest priority)
#[derive(Parser, Debug, Clone)]
#[command(name = "cryfttee")]
#[command(about = "TEE-style sidecar runtime for WASM modules")]
#[command(version = CRYFTTEE_VERSION)]
pub struct Args {
    // =========================================================================
    // Config File Options (optional - env vars are preferred)
    // =========================================================================

    /// Path to configuration file (JSON, YAML, or TOML)
    /// Only used if explicitly specified - env vars take precedence
    #[arg(long, env = "CRYFTTEE_CONFIG_FILE")]
    pub config_file: Option<String>,

    /// Base64-encoded configuration content (for Kubernetes secrets)
    /// Alternative to --config-file for containerized deployments
    #[arg(long, env = "CRYFTTEE_CONFIG_CONTENT")]
    pub config_content: Option<String>,

    /// Config content type when using --config-content
    /// Auto-detected from file extension when using --config-file
    #[arg(long, env = "CRYFTTEE_CONFIG_CONTENT_TYPE", default_value = "json")]
    pub config_content_type: String,

    // =========================================================================
    // Core Settings (typically set by cryftgo via env vars)
    // =========================================================================

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

    // =========================================================================
    // API Settings
    // =========================================================================

    /// API transport: "uds" or "https"
    #[arg(long, env = "CRYFTTEE_API_TRANSPORT")]
    pub api_transport: Option<String>,

    /// UDS socket path
    #[arg(long, env = "CRYFTTEE_UDS_PATH")]
    pub uds_path: Option<String>,

    /// HTTP bind address for API and kiosk UI
    #[arg(long, env = "CRYFTTEE_HTTP_ADDR")]
    pub http_addr: Option<String>,

    /// TLS certificate path (for HTTPS mode)
    #[arg(long, env = "CRYFTTEE_TLS_CERT")]
    pub tls_cert: Option<String>,

    /// TLS private key path (for HTTPS mode)
    #[arg(long, env = "CRYFTTEE_TLS_KEY")]
    pub tls_key: Option<String>,

    // =========================================================================
    // Module Selection
    // =========================================================================

    /// Comma-separated list of module IDs to load on startup
    /// If not specified, loads all modules from manifest
    #[arg(long, env = "CRYFTTEE_MODULES", value_delimiter = ',')]
    pub modules: Option<Vec<String>>,

    // =========================================================================
    // Web3Signer Integration
    // =========================================================================

    /// Web3Signer URL
    #[arg(long, env = "CRYFTTEE_WEB3SIGNER_URL")]
    pub web3signer_url: Option<String>,

    /// Web3Signer request timeout in seconds
    #[arg(long, env = "CRYFTTEE_WEB3SIGNER_TIMEOUT")]
    pub web3signer_timeout: Option<u64>,

    // =========================================================================
    // Vault Integration
    // =========================================================================

    /// HashiCorp Vault URL
    #[arg(long, env = "CRYFTTEE_VAULT_URL")]
    pub vault_url: Option<String>,

    /// Vault token for authentication
    #[arg(long, env = "CRYFTTEE_VAULT_TOKEN")]
    pub vault_token: Option<String>,

    // =========================================================================
    // Key Derivation (passed to modules)
    // =========================================================================

    /// Hex-encoded seed for deterministic key derivation
    #[arg(long, env = "CRYFTTEE_KEY_SEED")]
    pub key_seed: Option<String>,

    /// Node ID for key derivation paths (typically cryftgo node ID)
    #[arg(long, env = "CRYFTTEE_NODE_ID")]
    pub node_id: Option<String>,

    /// Expected BLS public key (set by CryftGo on restart to verify availability)
    /// Format: hex with 0x prefix
    #[arg(long, env = "CRYFTTEE_EXPECTED_BLS_PUBKEY")]
    pub expected_bls_pubkey: Option<String>,

    /// Expected TLS/ECDSA public key (set by CryftGo on restart to verify availability)
    /// Format: hex with 0x prefix
    #[arg(long, env = "CRYFTTEE_EXPECTED_TLS_PUBKEY")]
    pub expected_tls_pubkey: Option<String>,

    // =========================================================================
    // Logging
    // =========================================================================

    /// Log level: error, warn, info, debug, trace
    #[arg(long, env = "CRYFTTEE_LOG_LEVEL")]
    pub log_level: Option<String>,

    /// Enable JSON structured logging
    #[arg(long, env = "CRYFTTEE_LOG_JSON")]
    pub log_json: bool,

    /// Enable verbose logging (shorthand for --log-level=debug)
    #[arg(short, long, env = "CRYFTTEE_VERBOSE")]
    pub verbose: bool,

    // =========================================================================
    // Security / Attestation
    // =========================================================================

    /// Verified binary hash (set by cryftgo after verification)
    /// Format: sha256:<hex>
    #[arg(long, env = "CRYFTTEE_VERIFIED_BINARY_HASH")]
    pub verified_binary_hash: Option<String>,

    /// Require attestation for all module operations
    #[arg(long, env = "CRYFTTEE_REQUIRE_ATTESTATION")]
    pub require_attestation: bool,
}

/// Module initialization configuration (derived from Args + config file)
/// Passed to modules during initialization
#[derive(Debug, Clone, Default)]
pub struct ModuleInitConfig {
    /// List of specific module IDs to load (None = load all)
    pub module_filter: Option<Vec<String>>,
    
    /// Web3Signer URL
    pub web3signer_url: Option<String>,
    
    /// Vault URL (if enabled)
    pub vault_url: Option<String>,
    
    /// Vault token
    pub vault_token: Option<String>,
    
    /// Seed for key derivation (hex-encoded)
    pub key_seed: Option<String>,
    
    /// Node ID for derivation path
    pub node_id: Option<String>,
    
    /// Expected BLS public key (for restart verification)
    pub expected_bls_pubkey: Option<String>,
    
    /// Expected TLS public key (for restart verification)
    pub expected_tls_pubkey: Option<String>,
}

impl From<&Args> for ModuleInitConfig {
    fn from(args: &Args) -> Self {
        Self {
            module_filter: args.modules.clone(),
            web3signer_url: args.web3signer_url.clone(),
            vault_url: args.vault_url.clone(),
            vault_token: args.vault_token.clone(),
            key_seed: args.key_seed.clone(),
            node_id: args.node_id.clone(),
            expected_bls_pubkey: args.expected_bls_pubkey.clone(),
            expected_tls_pubkey: args.expected_tls_pubkey.clone(),
        }
    }
}

pub use config::{CryftteeConfig, TrustConfigFile, TrustPolicy, TrustedPublisher, ConfigFile};
pub use runtime::{ModuleRegistry, RuntimeState, ModuleInfo, ModuleStatus};
pub use storage::{ManifestEntry, Manifest};
pub use wasm_api::{WasmModule, SigningCapability};
