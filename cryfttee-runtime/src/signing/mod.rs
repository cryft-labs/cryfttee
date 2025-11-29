//! Module signing utilities - hash computation and signature helpers
//!
//! The actual signing is done via the bls_tls_signer module through Web3Signer.
//! This module provides utilities for:
//! - Computing file/content hashes
//! - Building signature manifests
//! - Verifying signatures against trusted publishers
//! - Checking publisher verification status via blockchain state

pub mod blockchain_state;

pub use blockchain_state::{
    BlockchainState, OnChainPublisher, PublisherStatus, ChainInfo,
    get_blockchain_state,
};

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use sha2::{Sha256, Digest};
use anyhow::{Result, Context};
use std::path::Path;
use std::collections::HashMap;

/// Signature manifest - the metadata that gets signed for a module
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureManifest {
    /// Schema version for this signature manifest format
    pub schema_version: String,
    /// Module identifier
    pub module_id: String,
    /// Module version
    pub module_version: String,
    /// SHA256 hash of the WASM binary
    pub wasm_hash: String,
    /// SHA256 hash of module.json
    pub module_json_hash: String,
    /// Publisher identifier (must match trust.toml)
    pub publisher_id: String,
    /// Minimum CryftTEE version required
    pub min_cryfttee_version: String,
    /// Module capabilities
    pub capabilities: Vec<String>,
    /// Default role assignments
    pub default_for: HashMap<String, bool>,
    /// Optional: hash of GUI assets (if module has GUI)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gui_hash: Option<String>,
    /// Timestamp when signature was created
    pub signed_at: DateTime<Utc>,
    /// Additional metadata (extensible)
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
}

/// Signed module entry - combines manifest with signature
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedModule {
    /// The signature manifest (what was signed)
    pub manifest: SignatureManifest,
    /// Base64-encoded signature over canonical JSON of manifest
    pub signature: String,
    /// Signature algorithm used
    pub algorithm: String,
    /// Public key identifier (key handle or fingerprint)
    pub key_id: String,
}

/// Compute SHA256 hash of a file
pub fn compute_file_hash(path: &Path) -> Result<String> {
    let contents = std::fs::read(path)
        .with_context(|| format!("Failed to read file: {:?}", path))?;
    let hash = Sha256::digest(&contents);
    Ok(format!("sha256:{}", hex::encode(hash)))
}

/// Compute SHA256 hash of bytes
pub fn compute_bytes_hash(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    format!("sha256:{}", hex::encode(hash))
}

/// Compute SHA256 hash of a directory's contents (for GUI assets)
pub fn compute_dir_hash(path: &Path) -> Result<String> {
    use std::fs;
    
    let mut hasher = Sha256::new();
    let mut entries: Vec<_> = fs::read_dir(path)
        .with_context(|| format!("Failed to read directory: {:?}", path))?
        .filter_map(|e| e.ok())
        .collect();
    
    // Sort for deterministic ordering
    entries.sort_by_key(|e| e.path());
    
    for entry in entries {
        let entry_path = entry.path();
        if entry_path.is_file() {
            let contents = fs::read(&entry_path)?;
            hasher.update(&contents);
        } else if entry_path.is_dir() {
            // Recursively hash subdirectories
            let sub_hash = compute_dir_hash(&entry_path)?;
            hasher.update(sub_hash.as_bytes());
        }
    }
    
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

/// Canonicalize JSON for signing (deterministic serialization)
pub fn canonicalize_json<T: Serialize>(value: &T) -> Result<String> {
    // Serialize to Value first, then to string with sorted keys
    let json_value = serde_json::to_value(value)?;
    let canonical = canonical_json_string(&json_value);
    Ok(canonical)
}

/// Recursively build canonical JSON string with sorted keys
fn canonical_json_string(value: &serde_json::Value) -> String {
    use serde_json::Value;
    
    match value {
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by_key(|(k, _)| *k);
            let inner: Vec<String> = entries
                .iter()
                .map(|(k, v)| format!("\"{}\":{}", k, canonical_json_string(v)))
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        Value::Array(arr) => {
            let inner: Vec<String> = arr.iter().map(canonical_json_string).collect();
            format!("[{}]", inner.join(","))
        }
        _ => serde_json::to_string(value).unwrap_or_default(),
    }
}

impl SignatureManifest {
    /// Create a new signature manifest for a module
    pub fn new(
        module_id: String,
        module_version: String,
        wasm_hash: String,
        module_json_hash: String,
        publisher_id: String,
        min_cryfttee_version: String,
        capabilities: Vec<String>,
        default_for: HashMap<String, bool>,
    ) -> Self {
        Self {
            schema_version: "1.0.0".to_string(),
            module_id,
            module_version,
            wasm_hash,
            module_json_hash,
            publisher_id,
            min_cryfttee_version,
            capabilities,
            default_for,
            gui_hash: None,
            signed_at: Utc::now(),
            metadata: HashMap::new(),
        }
    }
    
    /// Add GUI hash to the manifest
    pub fn with_gui_hash(mut self, hash: String) -> Self {
        self.gui_hash = Some(hash);
        self
    }
    
    /// Add custom metadata
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
    
    /// Get the canonical JSON representation for signing
    pub fn canonical_json(&self) -> Result<String> {
        canonicalize_json(self)
    }
    
    /// Compute the hash of the canonical JSON (what gets signed)
    pub fn signing_hash(&self) -> Result<String> {
        let canonical = self.canonical_json()?;
        Ok(compute_bytes_hash(canonical.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_bytes_hash() {
        let hash = compute_bytes_hash(b"test data");
        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash.len(), 7 + 64); // "sha256:" + 64 hex chars
    }

    #[test]
    fn test_canonical_json_sorted_keys() {
        let mut map = serde_json::Map::new();
        map.insert("z".to_string(), serde_json::json!("last"));
        map.insert("a".to_string(), serde_json::json!("first"));
        map.insert("m".to_string(), serde_json::json!("middle"));
        
        let value = serde_json::Value::Object(map);
        let canonical = canonical_json_string(&value);
        
        // Keys should be sorted: a, m, z
        assert!(canonical.starts_with("{\"a\":"));
        assert!(canonical.contains("\"m\":"));
        assert!(canonical.ends_with("\"z\":\"last\"}"));
    }

    #[test]
    fn test_signature_manifest_canonical() {
        let manifest = SignatureManifest::new(
            "test_module".to_string(),
            "1.0.0".to_string(),
            "sha256:abc123".to_string(),
            "sha256:def456".to_string(),
            "cryft-labs".to_string(),
            "0.4.0".to_string(),
            vec!["cap1".to_string()],
            HashMap::new(),
        );
        
        let json1 = manifest.canonical_json().unwrap();
        let json2 = manifest.canonical_json().unwrap();
        
        // Same manifest should produce identical canonical JSON
        assert_eq!(json1, json2);
    }
}
