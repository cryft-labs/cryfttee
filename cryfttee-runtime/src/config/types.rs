//! Configuration types for cryfttee runtime
//!
//! ## Configuration Priority (highest to lowest)
//! 1. CLI flags (--flag=value)
//! 2. Environment variables (CRYFTTEE_*) - set by cryftgo
//! 3. Config file (if --config-file or --config-content specified)
//! 4. Default values
//!
//! By default, cryftgo controls cryfttee configuration through environment
//! variables. Config files are only loaded when explicitly specified.

use std::collections::HashMap;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

// =============================================================================
// Config File Structure (JSON/YAML/TOML)
// Only used when --config-file or --config-content is specified
// =============================================================================

/// Root config file structure
/// Supports JSON, YAML, or TOML format
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConfigFile {
    /// Optional comment/description
    #[serde(rename = "_comment", default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    /// API configuration
    #[serde(default)]
    pub api: ApiConfigFile,

    /// Module configuration
    #[serde(default)]
    pub modules: ModulesConfigFile,

    /// Web3Signer configuration
    #[serde(default)]
    pub web3signer: Web3SignerConfigFile,

    /// Vault configuration
    #[serde(default)]
    pub vault: VaultConfigFile,

    /// Logging configuration
    #[serde(default)]
    pub logging: LoggingConfigFile,

    /// Security configuration
    #[serde(default)]
    pub security: SecurityConfigFile,
}

/// API section in config file
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ApiConfigFile {
    /// Transport mode: "uds" or "https"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,

    /// UDS socket path
    #[serde(rename = "uds-path", default, skip_serializing_if = "Option::is_none")]
    pub uds_path: Option<String>,

    /// HTTP bind address
    #[serde(rename = "http-addr", default, skip_serializing_if = "Option::is_none")]
    pub http_addr: Option<String>,

    /// TLS certificate path
    #[serde(rename = "tls-cert", default, skip_serializing_if = "Option::is_none")]
    pub tls_cert: Option<String>,

    /// TLS key path
    #[serde(rename = "tls-key", default, skip_serializing_if = "Option::is_none")]
    pub tls_key: Option<String>,
}

/// Modules section in config file
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModulesConfigFile {
    /// List of module IDs to enable
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<Vec<String>>,

    /// Module directory path
    #[serde(rename = "module-dir", default, skip_serializing_if = "Option::is_none")]
    pub module_dir: Option<String>,

    /// Manifest file path
    #[serde(rename = "manifest-path", default, skip_serializing_if = "Option::is_none")]
    pub manifest_path: Option<String>,

    /// Trust config path
    #[serde(rename = "trust-config", default, skip_serializing_if = "Option::is_none")]
    pub trust_config: Option<String>,

    /// Per-module configuration (keyed by module ID)
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub config: HashMap<String, serde_json::Value>,
}

/// Web3Signer section in config file
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Web3SignerConfigFile {
    /// Web3Signer URL
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Request timeout in seconds
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,

    /// Health check interval in seconds
    #[serde(rename = "health-check-interval", default, skip_serializing_if = "Option::is_none")]
    pub health_check_interval: Option<u64>,
}

/// Vault section in config file
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultConfigFile {
    /// Vault URL
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Vault token (prefer env var CRYFTTEE_VAULT_TOKEN for security)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

/// Logging section in config file
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LoggingConfigFile {
    /// Log level: error, warn, info, debug, trace
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,

    /// Enable JSON structured logging
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json: Option<bool>,
}

/// Security section in config file
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityConfigFile {
    /// Require attestation for module operations
    #[serde(rename = "require-attestation", default, skip_serializing_if = "Option::is_none")]
    pub require_attestation: Option<bool>,
}

// =============================================================================
// trust.toml structures (separate file, always TOML)
// =============================================================================

/// Trust policy settings from [trust] section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustPolicy {
    /// Minimum CryftTEE version this trust config was written for
    #[serde(default)]
    pub min_cryfttee_version: String,

    /// If true, reject modules with unknown publisherId
    #[serde(default = "default_true")]
    pub enforce_known_publishers: bool,

    /// If true, verify signatures for all modules before loading
    #[serde(default = "default_true")]
    pub enforce_signatures: bool,

    /// If true, refuse to start if ANY module fails verification
    #[serde(default)]
    pub strict_manifest: bool,
}

impl Default for TrustPolicy {
    fn default() -> Self {
        Self {
            min_cryfttee_version: "0.4.0".to_string(),
            enforce_known_publishers: true,
            enforce_signatures: true,
            strict_manifest: false,
        }
    }
}

/// Publisher entry from [[publishers]] array
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedPublisher {
    /// Publisher identifier (matches publisherId in manifest.json)
    pub id: String,

    /// Signature algorithm (e.g., "ed25519")
    #[serde(default = "default_algo")]
    pub algo: String,

    /// Base64-encoded public key
    #[serde(rename = "publicKey")]
    pub public_key: String,
}

fn default_algo() -> String {
    "ed25519".to_string()
}

/// Attestation settings from [attestation] section
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AttestationConfig {
    /// Whether runtime attestation signing is enabled
    #[serde(default)]
    pub enabled: bool,

    /// Signature algorithm for attestation receipts
    #[serde(default = "default_algo")]
    pub algo: String,

    /// Base64-encoded public key for attestation verification
    #[serde(default, rename = "publicKey")]
    pub public_key: String,
}

/// Full trust.toml file structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrustConfigFile {
    /// Trust policy settings
    #[serde(default)]
    pub trust: TrustPolicy,

    /// List of trusted publishers
    #[serde(default)]
    pub publishers: Vec<TrustedPublisher>,

    /// Attestation configuration
    #[serde(default)]
    pub attestation: AttestationConfig,
}

// =============================================================================
// Runtime Configuration (flattened, merged from all sources)
// =============================================================================

/// Main runtime configuration
/// Built by merging: defaults < config file < env vars < CLI flags
#[derive(Debug, Clone)]
pub struct CryftteeConfig {
    /// Instance name
    pub instance_name: String,

    /// Binary hash verified by cryftgo (set via CRYFTTEE_VERIFIED_BINARY_HASH)
    pub verified_binary_hash: Option<String>,

    /// Root path for modules directory
    pub module_dir: PathBuf,

    /// Path to manifest.json
    pub manifest_path: Option<PathBuf>,

    /// Path to UI static assets
    pub ui_dir: PathBuf,

    /// Path to trust configuration file
    pub trust_config_path: Option<PathBuf>,

    /// API transport mode: "uds" or "https"
    pub api_transport: String,

    /// API base path
    pub api_base_path: String,

    /// UDS socket path
    pub uds_path: String,

    /// HTTP bind address for API
    pub http_addr: String,

    /// UI listen address
    pub ui_addr: String,

    /// TLS certificate path
    pub tls_cert: Option<PathBuf>,

    /// TLS private key path
    pub tls_key: Option<PathBuf>,

    /// Whether schema endpoint is enabled
    pub schema_enabled: bool,

    /// Log level
    pub log_level: String,

    /// JSON logging
    pub log_json: bool,

    /// Loaded trust configuration
    pub trust: TrustConfigFile,

    /// Web3Signer URL
    pub web3signer_url: String,

    /// Web3Signer request timeout (seconds)
    pub web3signer_timeout: u64,

    /// Web3Signer health check interval (seconds)
    pub web3signer_health_check_interval: u64,

    /// Vault URL
    pub vault_url: Option<String>,

    /// Vault token
    pub vault_token: Option<String>,

    /// Key derivation seed
    pub key_seed: Option<String>,

    /// Node ID for key derivation
    pub node_id: Option<String>,

    /// Expected BLS public key (set by CryftGo on restart)
    pub expected_bls_pubkey: Option<String>,

    /// Expected TLS public key (set by CryftGo on restart)
    pub expected_tls_pubkey: Option<String>,

    /// Require attestation
    pub require_attestation: bool,

    /// Module IDs to enable (None = all)
    pub enabled_modules: Option<Vec<String>>,

    /// Per-module configuration from config file
    pub module_config: HashMap<String, serde_json::Value>,
}

// =============================================================================
// Default values
// =============================================================================

fn default_true() -> bool { true }

impl Default for CryftteeConfig {
    fn default() -> Self {
        Self {
            instance_name: "cryfttee-01".to_string(),
            verified_binary_hash: None,
            module_dir: PathBuf::from("modules"),
            manifest_path: None,
            ui_dir: PathBuf::from("ui"),
            trust_config_path: None,
            api_transport: "uds".to_string(),
            api_base_path: "/v1".to_string(),
            uds_path: "/tmp/cryfttee.sock".to_string(),
            http_addr: "0.0.0.0:8443".to_string(),
            ui_addr: "0.0.0.0:3232".to_string(),
            tls_cert: None,
            tls_key: None,
            schema_enabled: true,
            log_level: "info".to_string(),
            log_json: false,
            trust: TrustConfigFile::default(),
            web3signer_url: "http://localhost:9000".to_string(),
            web3signer_timeout: 30,
            web3signer_health_check_interval: 10,
            vault_url: None,
            vault_token: None,
            key_seed: None,
            node_id: None,
            expected_bls_pubkey: None,
            expected_tls_pubkey: None,
            require_attestation: false,
            enabled_modules: None,
            module_config: HashMap::new(),
        }
    }
}

impl CryftteeConfig {
    /// Get the effective manifest path
    pub fn get_manifest_path(&self) -> PathBuf {
        self.manifest_path
            .clone()
            .unwrap_or_else(|| self.module_dir.join("manifest.json"))
    }

    /// Check if a publisher is trusted
    pub fn is_publisher_trusted(&self, publisher_id: &str) -> bool {
        if !self.trust.trust.enforce_known_publishers {
            return true;
        }
        self.trust.publishers.iter().any(|p| p.id == publisher_id)
    }

    /// Get a trusted publisher by ID
    pub fn get_publisher(&self, publisher_id: &str) -> Option<&TrustedPublisher> {
        self.trust.publishers.iter().find(|p| p.id == publisher_id)
    }

    /// Get a trusted publisher's public key
    pub fn get_publisher_key(&self, publisher_id: &str) -> Option<&str> {
        self.get_publisher(publisher_id).map(|p| p.public_key.as_str())
    }

    /// Check if signature enforcement is enabled
    pub fn enforce_signatures(&self) -> bool {
        self.trust.trust.enforce_signatures
    }

    /// Check if strict manifest mode is enabled
    pub fn strict_manifest(&self) -> bool {
        self.trust.trust.strict_manifest
    }

    /// Check if attestation signing is enabled
    pub fn attestation_enabled(&self) -> bool {
        self.trust.attestation.enabled
    }

    /// Get Web3Signer URL
    pub fn get_web3signer_url(&self) -> &str {
        &self.web3signer_url
    }

    /// Get Web3Signer timeout in seconds
    pub fn get_web3signer_timeout(&self) -> u64 {
        self.web3signer_timeout
    }

    /// Get module-specific configuration
    pub fn get_module_config(&self, module_id: &str) -> Option<&serde_json::Value> {
        self.module_config.get(module_id)
    }
}
