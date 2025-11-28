//! Storage module - manifest and module metadata handling

mod index;

pub use index::*;

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Global manifest file structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Manifest schema version
    pub version: u32,
    /// List of module entries
    pub modules: Vec<ManifestEntry>,
}

/// Single module entry in the manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// Unique module identifier
    pub id: String,
    /// Subdirectory under modules/
    pub dir: String,
    /// WASM filename within the directory
    pub file: String,
    /// Module version (semver)
    pub version: String,
    /// Minimum cryftee version required
    #[serde(rename = "minCryfteeVersion")]
    pub min_cryftee_version: String,
    /// Human-readable description
    pub description: String,
    /// List of capabilities the module provides
    pub capabilities: Vec<String>,
    /// Default role assignments
    #[serde(rename = "defaultFor")]
    pub default_for: HashMap<String, bool>,
    /// Publisher identifier (maps to trust config)
    #[serde(rename = "publisherId")]
    pub publisher_id: String,
    /// Module hash (sha256:...)
    pub hash: String,
    /// Base64-encoded signature over module hash and metadata
    pub signature: String,
    /// Whether this module provides a GUI (optional)
    #[serde(rename = "hasGui", default)]
    pub has_gui: bool,
    /// GUI serve path relative to module directory (optional, e.g., "gui/index.html")
    #[serde(rename = "guiPath", default)]
    pub gui_path: Option<String>,
    /// GUI type: "tab" (default) or "popup" - popup modules render via the pill button
    #[serde(rename = "guiType", default)]
    pub gui_type: Option<String>,
    /// Module type: "standard" (default) or "llm" - LLM modules use the pill popup
    #[serde(rename = "moduleType", default)]
    pub module_type: Option<String>,
}

impl Manifest {
    /// Create an empty manifest
    pub fn new() -> Self {
        Self {
            version: 1,
            modules: Vec::new(),
        }
    }

    /// Find a module by ID
    pub fn find_module(&self, id: &str) -> Option<&ManifestEntry> {
        self.modules.iter().find(|m| m.id == id)
    }

    /// Get all modules with a specific capability
    pub fn modules_with_capability(&self, capability: &str) -> Vec<&ManifestEntry> {
        self.modules
            .iter()
            .filter(|m| m.capabilities.contains(&capability.to_string()))
            .collect()
    }

    /// Get the default module for BLS operations
    pub fn default_bls_module(&self) -> Option<&ManifestEntry> {
        self.modules
            .iter()
            .find(|m| m.default_for.get("bls").copied().unwrap_or(false))
    }

    /// Get the default module for TLS operations
    pub fn default_tls_module(&self) -> Option<&ManifestEntry> {
        self.modules
            .iter()
            .find(|m| m.default_for.get("tls").copied().unwrap_or(false))
    }
}

impl Default for Manifest {
    fn default() -> Self {
        Self::new()
    }
}
