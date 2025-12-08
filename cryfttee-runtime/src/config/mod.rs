//! Configuration module for cryfttee runtime
//!
//! ## Configuration Priority (highest to lowest)
//! 1. CLI flags (--flag=value)
//! 2. Environment variables (CRYFTTEE_*) - set by cryftgo
//! 3. Config file (if --config-file or --config-content specified)
//! 4. Default values
//!
//! By default, cryftgo controls cryfttee configuration through environment
//! variables. Config files are only loaded when explicitly specified.

mod types;

pub use types::*;

use std::path::PathBuf;
use anyhow::{Result, Context, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use tracing::{info, warn, debug};

/// Supported config file formats
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConfigFormat {
    Json,
    Yaml,
    Toml,
}

impl ConfigFormat {
    /// Detect format from file extension
    fn from_extension(path: &str) -> Option<Self> {
        let path_lower = path.to_lowercase();
        if path_lower.ends_with(".json") {
            Some(Self::Json)
        } else if path_lower.ends_with(".yaml") || path_lower.ends_with(".yml") {
            Some(Self::Yaml)
        } else if path_lower.ends_with(".toml") {
            Some(Self::Toml)
        } else {
            None
        }
    }

    /// Parse format from string (for --config-content-type)
    fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "json" => Some(Self::Json),
            "yaml" | "yml" => Some(Self::Yaml),
            "toml" => Some(Self::Toml),
            _ => None,
        }
    }
}

impl CryftteeConfig {
    /// Load configuration with priority: CLI > env vars > config file > defaults
    ///
    /// By default, cryftgo sets environment variables to control cryfttee.
    /// Config files are only used when explicitly specified via:
    /// - --config-file=/path/to/config.json
    /// - --config-content=<base64> --config-content-type=json
    pub fn load(args: &crate::Args) -> Result<Self> {
        // Start with defaults
        let mut config = Self::default();

        // Step 1: Load config file if explicitly specified (lowest priority after defaults)
        let config_file = Self::load_config_file(args)?;
        if let Some(ref file_config) = config_file {
            config.apply_config_file(file_config);
            info!("Loaded configuration from file");
        }

        // Step 2: Apply environment variables (set by cryftgo)
        // These override config file values
        config.apply_env_vars();

        // Step 3: Apply CLI arguments (highest priority)
        // These override both env vars and config file
        config.apply_cli_args(args);

        // Step 4: Set computed/derived values
        if config.manifest_path.is_none() {
            config.manifest_path = Some(config.module_dir.join("manifest.json"));
        }

        // Step 5: Load trust configuration (separate file, always TOML)
        config.trust = Self::load_trust_config(&config.trust_config_path)?;

        // Log final configuration
        Self::log_config(&config);

        Ok(config)
    }

    /// Load config file if specified via --config-file or --config-content
    fn load_config_file(args: &crate::Args) -> Result<Option<ConfigFile>> {
        // Check for base64-encoded content first (Kubernetes use case)
        if let Some(ref content) = args.config_content {
            let decoded = BASE64.decode(content)
                .with_context(|| "Failed to base64 decode --config-content")?;
            
            let format = ConfigFormat::from_str(&args.config_content_type)
                .ok_or_else(|| anyhow::anyhow!(
                    "Unknown config content type: {}. Use json, yaml, or toml",
                    args.config_content_type
                ))?;
            
            let config_file = Self::parse_config(&decoded, format)?;
            info!("Loaded config from --config-content (format: {:?})", format);
            return Ok(Some(config_file));
        }

        // Check for file path
        if let Some(ref path) = args.config_file {
            let path_buf = PathBuf::from(path);
            if !path_buf.exists() {
                bail!("Config file not found: {}", path);
            }

            let format = ConfigFormat::from_extension(path)
                .ok_or_else(|| anyhow::anyhow!(
                    "Cannot determine config format from extension: {}. Use .json, .yaml, .yml, or .toml",
                    path
                ))?;

            let content = std::fs::read(&path_buf)
                .with_context(|| format!("Failed to read config file: {}", path))?;
            
            let config_file = Self::parse_config(&content, format)?;
            info!("Loaded config from file: {} (format: {:?})", path, format);
            return Ok(Some(config_file));
        }

        // No config file specified - that's fine, use env vars / defaults
        debug!("No config file specified, using environment variables and defaults");
        Ok(None)
    }

    /// Parse config content based on format
    fn parse_config(content: &[u8], format: ConfigFormat) -> Result<ConfigFile> {
        let content_str = std::str::from_utf8(content)
            .with_context(|| "Config content is not valid UTF-8")?;

        match format {
            ConfigFormat::Json => {
                serde_json::from_str(content_str)
                    .with_context(|| "Failed to parse JSON config")
            }
            ConfigFormat::Yaml => {
                serde_yaml::from_str(content_str)
                    .with_context(|| "Failed to parse YAML config")
            }
            ConfigFormat::Toml => {
                toml::from_str(content_str)
                    .with_context(|| "Failed to parse TOML config")
            }
        }
    }

    /// Apply values from config file (lowest priority, easily overridden)
    fn apply_config_file(&mut self, file: &ConfigFile) {
        // API settings
        if let Some(ref v) = file.api.transport {
            self.api_transport = v.clone();
        }
        if let Some(ref v) = file.api.uds_path {
            self.uds_path = v.clone();
        }
        if let Some(ref v) = file.api.http_addr {
            self.http_addr = v.clone();
        }
        if let Some(ref v) = file.api.tls_cert {
            self.tls_cert = Some(PathBuf::from(v));
        }
        if let Some(ref v) = file.api.tls_key {
            self.tls_key = Some(PathBuf::from(v));
        }

        // Module settings
        if let Some(ref v) = file.modules.enabled {
            self.enabled_modules = Some(v.clone());
        }
        if let Some(ref v) = file.modules.module_dir {
            self.module_dir = PathBuf::from(v);
        }
        if let Some(ref v) = file.modules.manifest_path {
            self.manifest_path = Some(PathBuf::from(v));
        }
        if let Some(ref v) = file.modules.trust_config {
            self.trust_config_path = Some(PathBuf::from(v));
        }
        // Copy per-module config
        self.module_config = file.modules.config.clone();

        // Web3Signer settings
        if let Some(ref v) = file.web3signer.url {
            self.web3signer_url = v.clone();
        }
        if let Some(v) = file.web3signer.timeout {
            self.web3signer_timeout = v;
        }
        if let Some(v) = file.web3signer.health_check_interval {
            self.web3signer_health_check_interval = v;
        }

        // Vault settings
        if let Some(ref v) = file.vault.url {
            self.vault_url = Some(v.clone());
        }
        if let Some(ref v) = file.vault.token {
            self.vault_token = Some(v.clone());
        }

        // Logging settings
        if let Some(ref v) = file.logging.level {
            self.log_level = v.clone();
        }
        if let Some(v) = file.logging.json {
            self.log_json = v;
        }

        // Security settings
        if let Some(v) = file.security.require_attestation {
            self.require_attestation = v;
        }
    }

    /// Apply environment variables (set by cryftgo, override config file)
    fn apply_env_vars(&mut self) {
        // Note: Most env vars are handled by clap via #[arg(env = "...")]
        // This handles any that need special processing or aren't in Args

        // Verified binary hash (always from env, set by cryftgo)
        if let Ok(hash) = std::env::var("CRYFTTEE_VERIFIED_BINARY_HASH") {
            if !hash.is_empty() {
                debug!("Using externally-verified binary hash from cryftgo");
                self.verified_binary_hash = Some(hash);
            }
        }

        // Instance name (can be set by cryftgo for multi-instance deployments)
        if let Ok(name) = std::env::var("CRYFTTEE_INSTANCE_NAME") {
            if !name.is_empty() {
                self.instance_name = name;
            }
        }

        // UI directory
        if let Ok(dir) = std::env::var("CRYFTTEE_UI_DIR") {
            if !dir.is_empty() {
                self.ui_dir = PathBuf::from(dir);
            }
        }

        // UI address
        if let Ok(addr) = std::env::var("CRYFTTEE_UI_ADDR") {
            if !addr.is_empty() {
                self.ui_addr = addr;
            }
        }
    }

    /// Apply CLI arguments (highest priority, override everything)
    fn apply_cli_args(&mut self, args: &crate::Args) {
        // Core paths
        if let Some(ref v) = args.module_dir {
            self.module_dir = PathBuf::from(v);
        }
        if let Some(ref v) = args.manifest_path {
            self.manifest_path = Some(PathBuf::from(v));
        }
        if let Some(ref v) = args.ui_dir {
            self.ui_dir = PathBuf::from(v);
        }
        if let Some(ref v) = args.trust_config {
            self.trust_config_path = Some(PathBuf::from(v));
        }

        // API settings
        if let Some(ref v) = args.api_transport {
            self.api_transport = v.clone();
        }
        if let Some(ref v) = args.uds_path {
            self.uds_path = v.clone();
        }
        if let Some(ref v) = args.http_addr {
            self.http_addr = v.clone();
        }
        if let Some(ref v) = args.tls_cert {
            self.tls_cert = Some(PathBuf::from(v));
        }
        if let Some(ref v) = args.tls_key {
            self.tls_key = Some(PathBuf::from(v));
        }

        // Module selection
        if let Some(ref v) = args.modules {
            self.enabled_modules = Some(v.clone());
        }

        // Web3Signer
        if let Some(ref v) = args.web3signer_url {
            self.web3signer_url = v.clone();
        }
        if let Some(v) = args.web3signer_timeout {
            self.web3signer_timeout = v;
        }

        // Vault
        if let Some(ref v) = args.vault_url {
            self.vault_url = Some(v.clone());
        }
        if let Some(ref v) = args.vault_token {
            self.vault_token = Some(v.clone());
        }

        // Key derivation
        if let Some(ref v) = args.key_seed {
            self.key_seed = Some(v.clone());
        }
        if let Some(ref v) = args.node_id {
            self.node_id = Some(v.clone());
        }

        // Expected keys (set by CryftGo on restart)
        if let Some(ref v) = args.expected_bls_pubkey {
            self.expected_bls_pubkey = Some(v.clone());
        }
        if let Some(ref v) = args.expected_tls_pubkey {
            self.expected_tls_pubkey = Some(v.clone());
        }

        // Logging
        if let Some(ref v) = args.log_level {
            self.log_level = v.clone();
        }
        if args.log_json {
            self.log_json = true;
        }
        if args.verbose {
            self.log_level = "debug".to_string();
        }

        // Security
        if let Some(ref v) = args.verified_binary_hash {
            self.verified_binary_hash = Some(v.clone());
        }
        if args.require_attestation {
            self.require_attestation = true;
        }
    }

    /// Load trust configuration from file (always TOML format)
    fn load_trust_config(path: &Option<PathBuf>) -> Result<TrustConfigFile> {
        let Some(trust_path) = path else {
            debug!("No trust config specified, using defaults");
            return Ok(TrustConfigFile::default());
        };

        if !trust_path.exists() {
            warn!("Trust config not found at {:?}, using defaults", trust_path);
            return Ok(TrustConfigFile::default());
        }

        info!("Loading trust config from: {:?}", trust_path);
        let contents = std::fs::read_to_string(trust_path)
            .with_context(|| format!("Failed to read trust config: {:?}", trust_path))?;

        let trust_config: TrustConfigFile = toml::from_str(&contents)
            .with_context(|| "Failed to parse trust config (must be TOML)")?;

        Ok(trust_config)
    }

    /// Log final configuration (redacting sensitive values)
    fn log_config(config: &CryftteeConfig) {
        info!("Configuration loaded:");
        info!("  Instance: {}", config.instance_name);
        info!("  Module directory: {:?}", config.module_dir);
        info!("  Manifest path: {:?}", config.manifest_path);
        info!("  API transport: {}", config.api_transport);
        info!("  UDS path: {}", config.uds_path);
        info!("  HTTP address: {}", config.http_addr);
        info!("  UI address: {}", config.ui_addr);
        info!("  Web3Signer URL: {}", config.web3signer_url);
        info!("  Log level: {}", config.log_level);
        
        if config.verified_binary_hash.is_some() {
            info!("  Binary hash: externally verified ✓");
        } else {
            warn!("  Binary hash: self-reported (not verified by cryftgo)");
        }

        if let Some(ref modules) = config.enabled_modules {
            info!("  Enabled modules: {:?}", modules);
        } else {
            info!("  Enabled modules: all");
        }

        if config.vault_url.is_some() {
            info!("  Vault: enabled");
        }

        // Log expected keys (for CryftGo restart verification)
        if let Some(ref bls) = config.expected_bls_pubkey {
            info!("  Expected BLS key: {}...{}", &bls[..10.min(bls.len())], &bls[bls.len().saturating_sub(6)..]);
        }
        if let Some(ref tls) = config.expected_tls_pubkey {
            info!("  Expected TLS key: {}...{}", &tls[..10.min(tls.len())], &tls[tls.len().saturating_sub(6)..]);
        }

        if config.node_id.is_some() {
            info!("  Node ID: configured");
        }

        debug!("Trust policy: enforce_known_publishers={}, enforce_signatures={}, strict_manifest={}",
            config.trust.trust.enforce_known_publishers,
            config.trust.trust.enforce_signatures,
            config.trust.trust.strict_manifest);
        debug!("Trusted publishers: {}", config.trust.publishers.len());
    }
}
