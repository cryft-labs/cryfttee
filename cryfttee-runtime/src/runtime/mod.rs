//! Runtime module - module registry, loader, and dispatch

mod registry;
mod loader;
mod dispatch;

pub use registry::*;
pub use loader::*;
pub use dispatch::*;

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::storage::ManifestEntry;
use crate::config::CryftteeConfig;
use crate::CRYFTTEE_VERSION;
use sha2::{Sha256, Digest};
use anyhow::Result;
use chrono::{DateTime, Utc};

/// Module status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleStatus {
    /// Whether the module is trusted (signature valid, publisher known)
    pub trusted: bool,
    /// Whether the module is compatible (version check passed)
    pub compatible: bool,
    /// Whether the module is currently loaded
    pub loaded: bool,
    /// Reason for any failure (untrusted, incompatible, load error)
    pub reason: Option<String>,
}

impl Default for ModuleStatus {
    fn default() -> Self {
        Self {
            trusted: false,
            compatible: false,
            loaded: false,
            reason: Some("Not yet validated".to_string()),
        }
    }
}

/// Module information combining manifest entry and runtime status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    /// Module ID
    pub id: String,
    /// Module version
    pub version: String,
    /// Minimum cryfttee version required
    pub min_cryfttee_version: String,
    /// Module capabilities
    pub capabilities: Vec<String>,
    /// Default role assignments
    pub default_for: HashMap<String, bool>,
    /// Publisher ID
    pub publisher_id: String,
    /// Module hash
    pub hash: String,
    /// Module description
    pub description: String,
    /// Whether this module provides a GUI
    pub has_gui: bool,
    /// GUI URL to serve (computed at runtime from gui_path)
    pub gui_url: Option<String>,
    /// GUI type: "tab" or "popup" - popup modules render via the pill button
    pub gui_type: Option<String>,
    /// Module type: "standard" or "llm" - LLM modules have special constraints
    pub module_type: Option<String>,
    /// Whether this module is enabled (can be toggled at runtime)
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Runtime status
    #[serde(flatten)]
    pub status: ModuleStatus,
}

fn default_enabled() -> bool { false }

impl ModuleInfo {
    /// Create ModuleInfo from manifest entry
    pub fn from_manifest_entry(entry: &ManifestEntry) -> Self {
        // Compute GUI URL if the module has a GUI
        let gui_url = if entry.has_gui && entry.gui_path.is_some() {
            Some(format!("/api/modules/{}/gui", entry.id))
        } else {
            None
        };

        Self {
            id: entry.id.clone(),
            version: entry.version.clone(),
            min_cryfttee_version: entry.min_cryfttee_version.clone(),
            capabilities: entry.capabilities.clone(),
            default_for: entry.default_for.clone(),
            publisher_id: entry.publisher_id.clone(),
            hash: entry.hash.clone(),
            description: entry.description.clone(),
            has_gui: entry.has_gui,
            gui_url,
            gui_type: entry.gui_type.clone(),
            module_type: entry.module_type.clone(),
            enabled: false, // Modules are disabled by default, must be enabled via UI
            status: ModuleStatus::default(),
        }
    }
}

/// Runtime attestation receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReceipt {
    /// Base64-encoded canonical JSON payload
    pub payload: String,
    /// Base64-encoded signature
    pub signature: String,
    /// Signature algorithm
    pub algorithm: String,
}

/// Runtime attestation data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeAttestation {
    /// CryftTEE version
    pub cryfttee_version: String,
    /// Hash of the core binary
    pub core_binary_hash: String,
    /// Hash of the manifest file
    pub manifest_hash: String,
    /// Module information
    pub modules: Vec<ModuleInfo>,
    /// Signed receipt (optional)
    pub receipt: Option<AttestationReceipt>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Overall runtime state
#[derive(Debug)]
pub struct RuntimeState {
    /// Current attestation
    pub attestation: Option<RuntimeAttestation>,
    /// Web3Signer connection status
    pub web3signer_reachable: bool,
    /// Last Web3Signer error
    pub web3signer_last_error: Option<String>,
    /// WASM runtime health
    pub wasm_runtime_healthy: bool,
    /// Last WASM runtime error
    pub wasm_runtime_last_error: Option<String>,
}

impl RuntimeState {
    pub fn new() -> Self {
        Self {
            attestation: None,
            web3signer_reachable: false,
            web3signer_last_error: None,
            wasm_runtime_healthy: true,
            wasm_runtime_last_error: None,
        }
    }

    /// Compute runtime attestation from current state
    pub fn compute_attestation(
        &mut self,
        config: &CryftteeConfig,
        registry: &ModuleRegistry,
    ) -> Result<()> {
        // Use externally-verified hash from cryftgo if available
        // Otherwise fall back to self-hashing (less secure but useful for dev)
        let core_binary_hash = if let Some(ref verified_hash) = config.verified_binary_hash {
            // Trusted: hash was computed and verified by cryftgo before launching us
            verified_hash.clone()
        } else {
            // Self-reported: compute our own hash (a malicious binary could lie)
            match Self::compute_self_hash() {
                Ok(hash) => {
                    tracing::warn!("Using self-reported binary hash (not externally verified)");
                    hash
                }
                Err(e) => {
                    tracing::error!("Failed to compute self hash: {}", e);
                    format!("sha256:error:{}", e)
                }
            }
        };

        // Compute manifest hash
        let manifest_path = config.get_manifest_path();
        let manifest_hash = if manifest_path.exists() {
            let contents = std::fs::read(&manifest_path)?;
            format!("sha256:{}", hex::encode(Sha256::digest(&contents)))
        } else {
            "sha256:none".to_string()
        };

        // Collect module information
        let modules: Vec<ModuleInfo> = registry.get_all_modules();

        self.attestation = Some(RuntimeAttestation {
            cryfttee_version: CRYFTTEE_VERSION.to_string(),
            core_binary_hash,
            manifest_hash,
            modules,
            receipt: None, // TODO: Sign receipt with attestation key
            timestamp: Utc::now(),
        });

        Ok(())
    }
}

impl RuntimeState {
    /// Compute SHA256 hash of the running binary
    /// This is a fallback when no external verifier (cryftgo) provides the hash
    fn compute_self_hash() -> Result<String> {
        let exe_path = std::env::current_exe()?;
        let binary = std::fs::read(&exe_path)?;
        Ok(format!("sha256:{}", hex::encode(Sha256::digest(&binary))))
    }

    /// Check Web3Signer health and update state
    pub async fn check_web3signer_health(&mut self, url: &str) {
        let upcheck_url = format!("{}/upcheck", url.trim_end_matches('/'));
        
        match reqwest::Client::new()
            .get(&upcheck_url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    self.web3signer_reachable = true;
                    self.web3signer_last_error = None;
                    tracing::debug!("Web3Signer health check passed");
                } else {
                    self.web3signer_reachable = false;
                    self.web3signer_last_error = Some(format!("HTTP {}", response.status()));
                    tracing::warn!("Web3Signer returned error: {}", response.status());
                }
            }
            Err(e) => {
                self.web3signer_reachable = false;
                self.web3signer_last_error = Some(e.to_string());
                tracing::debug!("Web3Signer health check failed: {}", e);
            }
        }
    }

    /// Fetch list of BLS public keys from Web3Signer
    /// Web3Signer returns list at GET /api/v1/eth2/publicKeys
    pub async fn fetch_bls_pubkeys(&self, url: &str) -> Result<Vec<String>> {
        let pubkeys_url = format!("{}/api/v1/eth2/publicKeys", url.trim_end_matches('/'));
        
        let response = reqwest::Client::new()
            .get(&pubkeys_url)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await?;

        if !response.status().is_success() {
            anyhow::bail!("Web3Signer returned HTTP {}", response.status());
        }

        let pubkeys: Vec<String> = response.json().await?;
        Ok(pubkeys)
    }

    /// Verify a BLS public key exists in Web3Signer
    /// Returns Ok(()) if key exists, Err if not found or unreachable
    pub async fn verify_bls_pubkey_exists(&self, url: &str, pubkey: &str) -> Result<()> {
        let pubkeys = self.fetch_bls_pubkeys(url).await?;
        
        // Normalize the pubkey for comparison (lowercase, ensure 0x prefix)
        let normalized = normalize_pubkey(pubkey);
        
        for pk in &pubkeys {
            if normalize_pubkey(pk) == normalized {
                return Ok(());
            }
        }
        
        anyhow::bail!(
            "BLS public key {} not found in Web3Signer. Available keys: {}. \
             The key in CryftGo's local store does not exist in Web3Signer - \
             this may indicate key loss or misconfiguration.",
            pubkey,
            if pubkeys.is_empty() { 
                "none".to_string() 
            } else { 
                pubkeys.iter().map(|k| truncate_key(k)).collect::<Vec<_>>().join(", ")
            }
        )
    }

    /// Fetch list of TLS/SECP256K1 public keys from Web3Signer
    /// Note: Web3Signer's exact endpoint for non-BLS keys may vary
    pub async fn fetch_tls_pubkeys(&self, url: &str) -> Result<Vec<String>> {
        // Web3Signer SECP256K1 keys endpoint
        let pubkeys_url = format!("{}/api/v1/eth1/publicKeys", url.trim_end_matches('/'));
        
        let response = reqwest::Client::new()
            .get(&pubkeys_url)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                let pubkeys: Vec<String> = resp.json().await?;
                Ok(pubkeys)
            }
            Ok(resp) => {
                // Some Web3Signer versions don't support eth1 keys - return empty
                tracing::debug!("Web3Signer TLS keys endpoint returned {}", resp.status());
                Ok(vec![])
            }
            Err(e) => {
                tracing::debug!("Failed to fetch TLS keys from Web3Signer: {}", e);
                Ok(vec![])
            }
        }
    }

    /// Verify a TLS public key exists in Web3Signer
    pub async fn verify_tls_pubkey_exists(&self, url: &str, pubkey: &str) -> Result<()> {
        let pubkeys = self.fetch_tls_pubkeys(url).await?;
        
        let normalized = normalize_pubkey(pubkey);
        
        for pk in &pubkeys {
            if normalize_pubkey(pk) == normalized {
                return Ok(());
            }
        }
        
        anyhow::bail!(
            "TLS public key {} not found in Web3Signer. Available keys: {}. \
             The key in CryftGo's local store does not exist in Web3Signer - \
             this may indicate key loss or misconfiguration.",
            pubkey,
            if pubkeys.is_empty() { 
                "none".to_string() 
            } else { 
                pubkeys.iter().map(|k| truncate_key(k)).collect::<Vec<_>>().join(", ")
            }
        )
    }
}

/// Normalize a public key for comparison (lowercase, ensure 0x prefix)
fn normalize_pubkey(key: &str) -> String {
    let key = key.trim().to_lowercase();
    if key.starts_with("0x") {
        key
    } else {
        format!("0x{}", key)
    }
}

/// Truncate a key for display (first 10 chars...last 6 chars)
fn truncate_key(key: &str) -> String {
    if key.len() > 20 {
        format!("{}...{}", &key[..10], &key[key.len()-6..])
    } else {
        key.to_string()
    }
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self::new()
    }
}
