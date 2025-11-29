//! Module registry - tracks loaded modules, defaults, and compatibility

use std::collections::HashMap;
use std::sync::Arc;
use anyhow::{Result, anyhow};
use tracing::{info, warn, error};
use semver::Version;

use crate::config::CryftteeConfig;
use crate::storage::{Manifest, ManifestEntry};
use crate::wasm_api::WasmModule;
use crate::CRYFTTEE_VERSION;

use super::{ModuleInfo, ModuleStatus, ModuleLoader};

/// Module registry - manages all loaded modules and their state
pub struct ModuleRegistry {
    /// Configuration
    config: CryftteeConfig,
    /// Loaded modules indexed by ID
    modules: HashMap<String, ModuleInfo>,
    /// WASM instances for loaded modules
    wasm_instances: HashMap<String, Arc<WasmModule>>,
    /// Default module for BLS operations
    default_bls_module: Option<String>,
    /// Default module for TLS operations
    default_tls_module: Option<String>,
    /// Module loader
    loader: ModuleLoader,
}

impl ModuleRegistry {
    /// Create a new module registry
    pub fn new(config: CryftteeConfig) -> Self {
        Self {
            loader: ModuleLoader::new(config.clone()),
            config,
            modules: HashMap::new(),
            wasm_instances: HashMap::new(),
            default_bls_module: None,
            default_tls_module: None,
        }
    }

    /// Load all modules from the manifest
    pub async fn load_all_modules(&mut self) -> Result<usize> {
        let manifest_path = self.config.get_manifest_path();
        
        if !manifest_path.exists() {
            warn!("Manifest file not found: {:?}", manifest_path);
            return Ok(0);
        }

        let contents = std::fs::read_to_string(&manifest_path)?;
        let manifest: Manifest = serde_json::from_str(&contents)?;

        info!("Loading {} modules from manifest v{}", manifest.modules.len(), manifest.version);

        let mut loaded_count = 0;

        for entry in &manifest.modules {
            // Register the module (but don't load it - modules are disabled by default)
            match self.register_module(entry).await {
                Ok(loaded) => {
                    if loaded {
                        loaded_count += 1;
                        info!("Registered and loaded module: {} v{}", entry.id, entry.version);
                    } else {
                        info!("Registered module (disabled): {} v{}", entry.id, entry.version);
                    }
                }
                Err(e) => {
                    error!("Failed to register module {}: {}", entry.id, e);
                    // Record the failed module with error reason
                    let mut info = ModuleInfo::from_manifest_entry(entry);
                    info.status = ModuleStatus {
                        trusted: false,
                        compatible: false,
                        loaded: false,
                        reason: Some(e.to_string()),
                    };
                    self.modules.insert(entry.id.clone(), info);
                }
            }
        }

        Ok(loaded_count)
    }

    /// Register a module from its manifest entry (validates but doesn't load unless enabled)
    /// Returns true if module was loaded, false if just registered
    pub async fn register_module(&mut self, entry: &ManifestEntry) -> Result<bool> {
        // Check version compatibility
        if !self.check_version_compatibility(&entry.min_cryfttee_version)? {
            let reason = format!(
                "minCryftteeVersion {} > core version {}",
                entry.min_cryfttee_version, CRYFTTEE_VERSION
            );
            // Still register the module but mark as incompatible
            let mut info = ModuleInfo::from_manifest_entry(entry);
            info.status = ModuleStatus {
                trusted: true,
                compatible: false,
                loaded: false,
                reason: Some(reason.clone()),
            };
            self.modules.insert(entry.id.clone(), info);
            return Ok(false);
        }

        // Verify signature and trust
        let trusted = self.verify_module_trust(entry)?;

        // Record module info - modules start disabled by default
        let mut info = ModuleInfo::from_manifest_entry(entry);
        info.status = ModuleStatus {
            trusted,
            compatible: true,
            loaded: false,
            reason: if !trusted { Some("Publisher not trusted or signature invalid".to_string()) } else { None },
        };

        self.modules.insert(entry.id.clone(), info);
        
        // Don't load the module - it's disabled by default
        // User must enable it via the UI
        Ok(false)
    }

    /// Load a single module from its manifest entry (for when module is enabled)
    pub async fn load_module(&mut self, entry: &ManifestEntry) -> Result<()> {
        // Check version compatibility
        if !self.check_version_compatibility(&entry.min_cryfttee_version)? {
            let reason = format!(
                "minCryftteeVersion {} > core version {}",
                entry.min_cryfttee_version, CRYFTTEE_VERSION
            );
            return Err(anyhow!(reason));
        }

        // Verify signature and trust
        if !self.verify_module_trust(entry)? {
            return Err(anyhow!("Module signature verification failed or publisher not trusted"));
        }

        // Verify hash
        if !self.verify_module_hash(entry)? {
            return Err(anyhow!("Module hash verification failed"));
        }

        // Load the WASM module
        let wasm_module = self.loader.load_wasm(entry).await?;

        // Record module info
        let mut info = ModuleInfo::from_manifest_entry(entry);
        info.status = ModuleStatus {
            trusted: true,
            compatible: true,
            loaded: true,
            reason: None,
        };

        self.modules.insert(entry.id.clone(), info);
        self.wasm_instances.insert(entry.id.clone(), Arc::new(wasm_module));

        // Update defaults
        if entry.default_for.get("bls").copied().unwrap_or(false) {
            self.default_bls_module = Some(entry.id.clone());
            info!("Set default BLS module: {}", entry.id);
        }
        if entry.default_for.get("tls").copied().unwrap_or(false) {
            self.default_tls_module = Some(entry.id.clone());
            info!("Set default TLS module: {}", entry.id);
        }

        Ok(())
    }

    /// Check if a module version is compatible with current runtime
    fn check_version_compatibility(&self, min_version: &str) -> Result<bool> {
        let min_ver = Version::parse(min_version)?;
        let current_ver = Version::parse(CRYFTTEE_VERSION)?;
        Ok(current_ver >= min_ver)
    }

    /// Verify module trust (signature and publisher)
    fn verify_module_trust(&self, entry: &ManifestEntry) -> Result<bool> {
        // Check if publisher enforcement is enabled
        if self.config.trust.trust.enforce_known_publishers {
            if !self.config.is_publisher_trusted(&entry.publisher_id) {
                warn!("Publisher not trusted: {} (enforce_known_publishers=true)", entry.publisher_id);
                return Ok(false);
            }
        }

        // Check if signature enforcement is enabled
        if self.config.enforce_signatures() {
            // Get publisher's public key
            let publisher = match self.config.get_publisher(&entry.publisher_id) {
                Some(p) => p,
                None => {
                    warn!("No public key found for publisher: {}", entry.publisher_id);
                    return Ok(false);
                }
            };

            // Verify signature
            let is_valid = crate::storage::verify_signature(
                entry,
                &publisher.public_key,
            )?;

            if !is_valid {
                warn!("Signature verification failed for module: {}", entry.id);
                return Ok(false);
            }
        } else {
            warn!("Signature enforcement disabled, skipping verification for: {}", entry.id);
        }

        Ok(true)
    }

    /// Verify module hash matches manifest
    fn verify_module_hash(&self, entry: &ManifestEntry) -> Result<bool> {
        let module_path = self.config.module_dir
            .join(&entry.dir)
            .join(&entry.file);

        if !module_path.exists() {
            return Err(anyhow!("Module file not found: {:?}", module_path));
        }

        // Verify hash if enforcement is enabled
        if self.config.enforce_signatures() {
            let is_valid = crate::storage::verify_module_hash(
                &self.config.module_dir,
                entry,
            )?;

            if !is_valid {
                warn!("Hash verification failed for module: {}", entry.id);
                return Ok(false);
            }
        } else {
            warn!("Signature enforcement disabled, skipping hash verification for: {}", entry.id);
        }

        Ok(true)
    }

    /// Get all module information
    pub fn get_all_modules(&self) -> Vec<ModuleInfo> {
        self.modules.values().cloned().collect()
    }

    /// Get a specific module by ID
    pub fn get_module(&self, id: &str) -> Option<&ModuleInfo> {
        self.modules.get(id)
    }

    /// Get WASM instance for a module
    pub fn get_wasm_instance(&self, id: &str) -> Option<Arc<WasmModule>> {
        self.wasm_instances.get(id).cloned()
    }

    /// Get the default BLS module ID
    pub fn get_default_bls_module(&self) -> Option<&str> {
        self.default_bls_module.as_deref()
    }

    /// Get the default TLS module ID
    pub fn get_default_tls_module(&self) -> Option<&str> {
        self.default_tls_module.as_deref()
    }

    /// Reload all modules (atomic operation)
    pub async fn reload_modules(&mut self) -> Result<usize> {
        // Store old state for rollback
        let old_modules = self.modules.clone();
        let old_instances = self.wasm_instances.clone();
        let old_default_bls = self.default_bls_module.clone();
        let old_default_tls = self.default_tls_module.clone();

        // Clear current state
        self.modules.clear();
        self.wasm_instances.clear();
        self.default_bls_module = None;
        self.default_tls_module = None;

        // Try to reload
        match self.load_all_modules().await {
            Ok(count) => {
                info!("Successfully reloaded {} modules", count);
                Ok(count)
            }
            Err(e) => {
                // Rollback on failure
                error!("Module reload failed, rolling back: {}", e);
                self.modules = old_modules;
                self.wasm_instances = old_instances;
                self.default_bls_module = old_default_bls;
                self.default_tls_module = old_default_tls;
                Err(e)
            }
        }
    }

    /// Get module for a specific capability
    pub fn get_module_for_capability(&self, capability: &str) -> Option<&ModuleInfo> {
        self.modules.values().find(|m| {
            m.enabled && m.status.loaded && m.capabilities.contains(&capability.to_string())
        })
    }

    /// Enable a module by ID
    pub async fn enable_module(&mut self, id: &str) -> Result<()> {
        // Get the module info
        let module = self.modules.get_mut(id)
            .ok_or_else(|| anyhow!("Module not found: {}", id))?;
        
        if module.enabled {
            return Ok(()); // Already enabled
        }

        module.enabled = true;
        info!("Enabled module: {}", id);

        // Try to load the module if it's compatible but not loaded
        if module.status.compatible && !module.status.loaded {
            // Re-load from manifest
            let manifest_path = self.config.get_manifest_path();
            if manifest_path.exists() {
                let contents = std::fs::read_to_string(&manifest_path)?;
                let manifest: crate::storage::Manifest = serde_json::from_str(&contents)?;
                
                if let Some(entry) = manifest.find_module(id) {
                    match self.loader.load_wasm(entry).await {
                        Ok(wasm_module) => {
                            self.wasm_instances.insert(id.to_string(), Arc::new(wasm_module));
                            if let Some(m) = self.modules.get_mut(id) {
                                m.status.loaded = true;
                                m.status.reason = None;
                            }
                            info!("Loaded module: {} v{}", entry.id, entry.version);
                            
                            // Update defaults if needed
                            if entry.default_for.get("bls").copied().unwrap_or(false) {
                                self.default_bls_module = Some(id.to_string());
                            }
                            if entry.default_for.get("tls").copied().unwrap_or(false) {
                                self.default_tls_module = Some(id.to_string());
                            }
                        }
                        Err(e) => {
                            warn!("Failed to load module {}: {}", id, e);
                            if let Some(m) = self.modules.get_mut(id) {
                                m.status.reason = Some(e.to_string());
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Disable a module by ID
    pub fn disable_module(&mut self, id: &str) -> Result<()> {
        let module = self.modules.get_mut(id)
            .ok_or_else(|| anyhow!("Module not found: {}", id))?;
        
        if !module.enabled {
            return Ok(()); // Already disabled
        }

        module.enabled = false;
        module.status.loaded = false;
        
        // Remove the WASM instance
        self.wasm_instances.remove(id);
        
        // Update defaults if this was a default module
        if self.default_bls_module.as_deref() == Some(id) {
            self.default_bls_module = None;
            info!("Cleared default BLS module (was {})", id);
        }
        if self.default_tls_module.as_deref() == Some(id) {
            self.default_tls_module = None;
            info!("Cleared default TLS module (was {})", id);
        }

        info!("Disabled module: {}", id);
        Ok(())
    }
}
