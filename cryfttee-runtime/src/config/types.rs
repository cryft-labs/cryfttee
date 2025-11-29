//! Configuration types for cryfttee runtime
//!
//! These types map to:
//! - config/cryfttee.example.toml (main config)
//! - config/trust.toml (publisher trust & attestation)

use std::path::PathBuf;
use serde::{Deserialize, Serialize};

// =============================================================================
// trust.toml structures
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
// cryfttee.toml structures
// =============================================================================

/// [core] section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreConfig {
    /// Human-readable instance name
    #[serde(default = "default_instance_name")]
    pub instance_name: String,

    /// Expected cryfttee version
    #[serde(default = "default_version")]
    pub cryfttee_version: String,

    /// Module directory path
    #[serde(default = "default_module_dir_str")]
    pub module_dir: String,

    /// Manifest file path
    #[serde(default = "default_manifest_path")]
    pub manifest_path: String,

    /// Trust config file path
    #[serde(default = "default_trust_config")]
    pub trust_config: String,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            instance_name: default_instance_name(),
            cryfttee_version: default_version(),
            module_dir: default_module_dir_str(),
            manifest_path: default_manifest_path(),
            trust_config: default_trust_config(),
        }
    }
}

/// [api] section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Transport mode: "uds" or "https"
    #[serde(default = "default_transport")]
    pub transport: String,

    /// UDS socket path
    #[serde(default = "default_uds_path")]
    pub uds_path: String,

    /// HTTP bind address
    #[serde(default = "default_http_addr")]
    pub http_addr: String,

    /// Base path for API (default: "/v1")
    #[serde(default = "default_base_path")]
    pub base_path: String,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            transport: default_transport(),
            uds_path: default_uds_path(),
            http_addr: default_http_addr(),
            base_path: default_base_path(),
        }
    }
}

/// [tls] section
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsConfig {
    /// Path to TLS certificate
    #[serde(default)]
    pub cert_path: String,

    /// Path to TLS private key
    #[serde(default)]
    pub key_path: String,
}

/// [ui] section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    /// UI listen address
    #[serde(default = "default_ui_addr")]
    pub addr: String,

    /// Static assets directory
    #[serde(default = "default_static_dir")]
    pub static_dir: String,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            addr: default_ui_addr(),
            static_dir: default_static_dir(),
        }
    }
}

/// [schema] section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaConfig {
    /// Whether schema endpoint is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for SchemaConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// [logging] section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level: "info", "debug", "trace", "warn", "error"
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Enable JSON structured logging
    #[serde(default)]
    pub json: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            json: false,
        }
    }
}

/// Full cryfttee.toml file structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CryftteeConfigFile {
    #[serde(default)]
    pub core: CoreConfig,

    #[serde(default)]
    pub api: ApiConfig,

    #[serde(default)]
    pub tls: TlsConfig,

    #[serde(default)]
    pub ui: UiConfig,

    #[serde(default)]
    pub schema: SchemaConfig,

    #[serde(default)]
    pub logging: LoggingConfig,
}

// =============================================================================
// Runtime configuration (flattened for use)
// =============================================================================

/// Main configuration for cryfttee runtime (flattened from file + env)
#[derive(Debug, Clone)]
pub struct CryftteeConfig {
    /// Instance name
    pub instance_name: String,

    /// Binary hash verified by cryftgo (set via CRYFTTEE_VERIFIED_BINARY_HASH)
    /// If set, this is trusted as it came from an external verifier
    /// If not set, cryfttee will compute its own hash (less secure)
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
}

// Default value functions
fn default_true() -> bool { true }
fn default_instance_name() -> String { "cryfttee-01".to_string() }
fn default_version() -> String { "0.4.0".to_string() }
fn default_module_dir() -> PathBuf { PathBuf::from("modules") }
fn default_module_dir_str() -> String { "modules".to_string() }
fn default_manifest_path() -> String { "modules/manifest.json".to_string() }
fn default_trust_config() -> String { "config/trust.toml".to_string() }
fn default_transport() -> String { "uds".to_string() }
fn default_uds_path() -> String { "/tmp/cryfttee.sock".to_string() }
fn default_http_addr() -> String { "0.0.0.0:8443".to_string() }
fn default_base_path() -> String { "/v1".to_string() }
fn default_ui_addr() -> String { "0.0.0.0:3232".to_string() }
fn default_static_dir() -> String { "ui".to_string() }
fn default_log_level() -> String { "info".to_string() }

impl Default for CryftteeConfig {
    fn default() -> Self {
        Self {
            instance_name: default_instance_name(),
            verified_binary_hash: None,
            module_dir: default_module_dir(),
            manifest_path: None,
            ui_dir: PathBuf::from("ui"),
            trust_config_path: None,
            api_transport: default_transport(),
            api_base_path: default_base_path(),
            uds_path: default_uds_path(),
            http_addr: default_http_addr(),
            ui_addr: default_ui_addr(),
            tls_cert: None,
            tls_key: None,
            schema_enabled: true,
            log_level: default_log_level(),
            log_json: false,
            trust: TrustConfigFile::default(),
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
        // If enforcement is disabled, trust everyone
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
}
