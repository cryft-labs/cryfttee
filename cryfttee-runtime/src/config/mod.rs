//! Configuration module for cryfttee runtime
//!
//! Loads configuration from:
//! 1. config/cryfttee.toml (or specified path)
//! 2. config/trust.toml (referenced from cryfttee.toml)
//! 3. Environment variable overrides
//! 4. CLI argument overrides

mod types;

pub use types::*;

use std::path::PathBuf;
use anyhow::{Result, Context};
use tracing::{info, warn, debug};

impl CryftteeConfig {
    /// Load configuration from CLI args, environment, and optional config file
    pub fn load(args: &crate::Args) -> Result<Self> {
        // Start with defaults
        let mut config = Self::default();

        // Load from config file if specified
        if let Some(config_path) = &args.config {
            info!("Loading config from: {}", config_path);
            let contents = std::fs::read_to_string(config_path)
                .with_context(|| format!("Failed to read config file: {}", config_path))?;
            
            let file_config: CryftteeConfigFile = toml::from_str(&contents)
                .with_context(|| "Failed to parse config file")?;
            
            // Apply file config to runtime config
            config.instance_name = file_config.core.instance_name;
            config.module_dir = PathBuf::from(&file_config.core.module_dir);
            config.manifest_path = Some(PathBuf::from(&file_config.core.manifest_path));
            config.trust_config_path = Some(PathBuf::from(&file_config.core.trust_config));
            
            config.api_transport = file_config.api.transport;
            config.api_base_path = file_config.api.base_path;
            config.uds_path = file_config.api.uds_path;
            config.http_addr = file_config.api.http_addr;
            
            if !file_config.tls.cert_path.is_empty() {
                config.tls_cert = Some(PathBuf::from(&file_config.tls.cert_path));
            }
            if !file_config.tls.key_path.is_empty() {
                config.tls_key = Some(PathBuf::from(&file_config.tls.key_path));
            }
            
            config.ui_addr = file_config.ui.addr;
            config.ui_dir = PathBuf::from(&file_config.ui.static_dir);
            
            config.schema_enabled = file_config.schema.enabled;
            config.log_level = file_config.logging.level;
            config.log_json = file_config.logging.json;

            // Web3Signer configuration
            config.web3signer_url = file_config.web3signer.url;
            config.web3signer_timeout = file_config.web3signer.timeout;
            config.web3signer_health_check_interval = file_config.web3signer.health_check_interval;
        }

        // Override with CLI/env values (these take precedence)
        if let Some(module_dir) = &args.module_dir {
            config.module_dir = PathBuf::from(module_dir);
        }

        if let Some(manifest_path) = &args.manifest_path {
            config.manifest_path = Some(PathBuf::from(manifest_path));
        }

        if let Some(ui_dir) = &args.ui_dir {
            config.ui_dir = PathBuf::from(ui_dir);
        }

        if let Some(trust_config) = &args.trust_config {
            config.trust_config_path = Some(PathBuf::from(trust_config));
        }

        config.api_transport = args.api_transport.clone();
        config.uds_path = args.uds_path.clone();
        config.http_addr = args.http_addr.clone();

        if let Some(tls_cert) = &args.tls_cert {
            config.tls_cert = Some(PathBuf::from(tls_cert));
        }

        if let Some(tls_key) = &args.tls_key {
            config.tls_key = Some(PathBuf::from(tls_key));
        }

        // Set default manifest path if not specified
        if config.manifest_path.is_none() {
            config.manifest_path = Some(config.module_dir.join("manifest.json"));
        }

        // Load trust configuration
        config.trust = Self::load_trust_config(&config.trust_config_path)?;

        // Check for externally-verified binary hash from cryftgo
        if let Ok(hash) = std::env::var("CRYFTTEE_VERIFIED_BINARY_HASH") {
            if !hash.is_empty() {
                info!("Using externally-verified binary hash from cryftgo");
                config.verified_binary_hash = Some(hash);
            }
        }
        if config.verified_binary_hash.is_none() {
            warn!("No CRYFTTEE_VERIFIED_BINARY_HASH set - attestation will use self-reported hash (less secure)");
        }

        // Web3Signer URL from environment (overrides config file)
        if let Ok(url) = std::env::var("CRYFTTEE_WEB3SIGNER_URL") {
            if !url.is_empty() {
                info!("Using Web3Signer URL from environment: {}", url);
                config.web3signer_url = url;
            }
        }

        // Web3Signer timeout from environment
        if let Ok(timeout) = std::env::var("CRYFTTEE_WEB3SIGNER_TIMEOUT") {
            if let Ok(t) = timeout.parse::<u64>() {
                config.web3signer_timeout = t;
            }
        }

        info!("Instance: {}", config.instance_name);
        info!("Module directory: {:?}", config.module_dir);
        info!("Manifest path: {:?}", config.manifest_path);
        info!("API transport: {}", config.api_transport);
        info!("UI address: {}", config.ui_addr);
        debug!("Trust policy: enforce_known_publishers={}, enforce_signatures={}, strict_manifest={}",
            config.trust.trust.enforce_known_publishers,
            config.trust.trust.enforce_signatures,
            config.trust.trust.strict_manifest);
        debug!("Loaded {} trusted publishers", config.trust.publishers.len());

        Ok(config)
    }

    /// Load trust configuration from file
    fn load_trust_config(path: &Option<PathBuf>) -> Result<TrustConfigFile> {
        let Some(trust_path) = path else {
            warn!("No trust config specified, using defaults");
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
            .with_context(|| "Failed to parse trust config")?;

        Ok(trust_config)
    }
}
