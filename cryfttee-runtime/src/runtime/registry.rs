//! Module registry - tracks loaded modules, defaults, and compatibility

use std::collections::HashMap;
use std::sync::Arc;
use anyhow::{Result, anyhow};
use tracing::{info, warn, error, debug};
use semver::Version;

use crate::config::CryftteeConfig;
use crate::storage::{Manifest, ManifestEntry};
use crate::wasm_api::WasmModule;
use crate::{ModuleInitConfig, CRYFTTEE_VERSION};

use super::{ModuleInfo, ModuleStatus, ModuleLoader};

/// Module registry - manages all loaded modules and their state
pub struct ModuleRegistry {
    /// Configuration
    config: CryftteeConfig,
    /// Module initialization config (from CLI args)
    init_config: ModuleInitConfig,
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
            init_config: ModuleInitConfig::default(),
            modules: HashMap::new(),
            wasm_instances: HashMap::new(),
            default_bls_module: None,
            default_tls_module: None,
        }
    }

    /// Create a new module registry with initialization config
    pub fn new_with_init_config(config: CryftteeConfig, init_config: ModuleInitConfig) -> Self {
        Self {
            loader: ModuleLoader::new(config.clone()),
            config,
            init_config,
            modules: HashMap::new(),
            wasm_instances: HashMap::new(),
            default_bls_module: None,
            default_tls_module: None,
        }
    }

    /// Get the module init config
    pub fn init_config(&self) -> &ModuleInitConfig {
        &self.init_config
    }

    /// Load modules from manifest, respecting the filter if set
    /// Note: Modules are registered but only loaded if trusted and compatible
    pub async fn load_modules_filtered(&mut self) -> Result<usize> {
        let manifest_path = self.config.get_manifest_path();
        
        if !manifest_path.exists() {
            warn!("Manifest file not found: {:?}", manifest_path);
            return Ok(0);
        }

        let contents = std::fs::read_to_string(&manifest_path)?;
        let manifest: Manifest = serde_json::from_str(&contents)?;

        info!("Loading modules from manifest v{}", manifest.version);

        let mut loaded_count = 0;

        for entry in &manifest.modules {
            // Check if this module should be enabled based on filter
            let should_enable = match &self.init_config.module_filter {
                Some(filter) => {
                    let included = filter.iter().any(|id| id == &entry.id);
                    if !included {
                        debug!("Module {} not in filter, registering as disabled", entry.id);
                    }
                    included
                }
                None => true, // No filter = enable all
            };

            // Register the module (creates ModuleInfo)
            match self.register_module(entry, should_enable).await {
                Ok(loaded) => {
                    if loaded {
                        loaded_count += 1;
                    }
                }
                Err(e) => {
                    error!("Failed to register module {}: {}", entry.id, e);
                }
            }
        }

        Ok(loaded_count)
    }

    /// Register a module from manifest entry
    /// Returns true if the module was loaded (enabled + trusted + compatible)
    async fn register_module(&mut self, entry: &ManifestEntry, enable: bool) -> Result<bool> {
        // Check version compatibility first
        let compatible = self.check_version_compatibility(&entry.min_cryfttee_version)?;
        
        // Log once if signature enforcement is disabled
        if !self.config.enforce_signatures() {
            debug!("Signature enforcement disabled, skipping verification for: {}", entry.id);
        }

        // Check trust (publisher + signature)
        let trusted = if compatible {
            self.verify_module_trust(entry)?
        } else {
            false // Don't bother checking trust if incompatible
        };

        // Verify hash if trusted and compatible
        let hash_valid = if trusted && compatible {
            self.verify_module_hash(entry).unwrap_or(false)
        } else {
            false
        };

        // Determine status and reason
        let (loaded, reason) = if !compatible {
            (false, Some(format!(
                "Incompatible: requires cryfttee >= {}, current is {}",
                entry.min_cryfttee_version, CRYFTTEE_VERSION
            )))
        } else if !trusted {
            (false, Some("Publisher not trusted or signature invalid".to_string()))
        } else if !hash_valid {
            (false, Some("Hash verification failed".to_string()))
        } else if !enable {
            (false, Some("Module disabled by filter".to_string()))
        } else {
            // All checks passed and enabled - try to load
            match self.loader.load_wasm(entry).await {
                Ok(wasm_module) => {
                    self.wasm_instances.insert(entry.id.clone(), Arc::new(wasm_module));
                    info!("Loaded module: {} v{}", entry.id, entry.version);
                    (true, None)
                }
                Err(e) => {
                    error!("Failed to load WASM for {}: {}", entry.id, e);
                    (false, Some(format!("WASM load failed: {}", e)))
                }
            }
        };

        // Create module info from manifest entry
        let mut info = ModuleInfo::from_manifest_entry(entry);
        info.enabled = enable && loaded; // Only enabled if we actually loaded it
        info.status = ModuleStatus {
            trusted,
            compatible,
            loaded,
            reason,
        };

        // Log appropriate message
        if loaded {
            // Set defaults if applicable
            if entry.default_for.get("bls").copied().unwrap_or(false) {
                self.default_bls_module = Some(entry.id.clone());
                info!("Set default BLS module: {}", entry.id);
            }
            if entry.default_for.get("tls").copied().unwrap_or(false) {
                self.default_tls_module = Some(entry.id.clone());
                info!("Set default TLS module: {}", entry.id);
            }
        } else {
            info!("Registered module (not loaded): {} v{}", entry.id, entry.version);
        }

        self.modules.insert(entry.id.clone(), info);
        Ok(loaded)
    }

    /// Register and immediately load a module (for CLI-specified modules)
    /// This is a convenience wrapper that enables the module
    pub async fn register_and_load_module(&mut self, entry: &ManifestEntry) -> Result<bool> {
        self.register_module(entry, true).await
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

        // Try to reload (respecting the filter)
        match self.load_modules_filtered().await {
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
    /// If the module is trusted and compatible but not loaded, it will be loaded
    pub async fn enable_module(&mut self, id: &str) -> Result<()> {
        // Check if module exists
        if !self.modules.contains_key(id) {
            return Err(anyhow!("Module not found: {}", id));
        }

        // Get current state
        let module = self.modules.get(id).unwrap();
        
        if module.enabled && module.status.loaded {
            debug!("Module {} is already enabled and loaded", id);
            return Ok(());
        }

        // Check if module can be enabled (must be trusted and compatible)
        if !module.status.compatible {
            return Err(anyhow!(
                "Cannot enable module {}: incompatible ({})",
                id,
                module.status.reason.as_deref().unwrap_or("unknown")
            ));
        }

        if !module.status.trusted {
            return Err(anyhow!(
                "Cannot enable module {}: not trusted ({})",
                id,
                module.status.reason.as_deref().unwrap_or("publisher/signature issue")
            ));
        }

        info!("Enabled module: {}", id);

        // If already loaded, just mark as enabled
        if module.status.loaded {
            if let Some(m) = self.modules.get_mut(id) {
                m.enabled = true;
            }
            return Ok(());
        }

        // Need to load the module - get manifest entry
        let manifest_path = self.config.get_manifest_path();
        if !manifest_path.exists() {
            return Err(anyhow!("Manifest file not found"));
        }

        let contents = std::fs::read_to_string(&manifest_path)?;
        let manifest: crate::storage::Manifest = serde_json::from_str(&contents)?;
        
        let entry = manifest.find_module(id)
            .ok_or_else(|| anyhow!("Module {} not found in manifest", id))?;

        // Load the WASM module
        let wasm_module = self.loader.load_wasm(entry).await?;
        self.wasm_instances.insert(id.to_string(), Arc::new(wasm_module));
        
        // Update module info
        if let Some(m) = self.modules.get_mut(id) {
            m.enabled = true;
            m.status.loaded = true;
            m.status.reason = None;
        }
        
        info!("Loaded module: {} v{}", entry.id, entry.version);
        
        // Update defaults if needed
        if entry.default_for.get("bls").copied().unwrap_or(false) 
           && self.default_bls_module.is_none() 
        {
            self.default_bls_module = Some(id.to_string());
            info!("Set default BLS module: {}", id);
        }
        if entry.default_for.get("tls").copied().unwrap_or(false)
           && self.default_tls_module.is_none()
        {
            self.default_tls_module = Some(id.to_string());
            info!("Set default TLS module: {}", id);
        }

        Ok(())
    }

    /// Disable a module by ID
    /// This unloads the module and frees its resources
    pub fn disable_module(&mut self, id: &str) -> Result<()> {
        let module = self.modules.get_mut(id)
            .ok_or_else(|| anyhow!("Module not found: {}", id))?;
        
        if !module.enabled && !module.status.loaded {
            debug!("Module {} is already disabled", id);
            return Ok(());
        }

        // Mark as disabled
        module.enabled = false;
        module.status.loaded = false;
        module.status.reason = Some("Disabled by user".to_string());
        
        // Remove the WASM instance to free memory
        self.wasm_instances.remove(id);
        
        // Update defaults if this was a default module
        if self.default_bls_module.as_deref() == Some(id) {
            info!("Cleared default BLS module (was {})", id);
            self.default_bls_module = None;
        }
        if self.default_tls_module.as_deref() == Some(id) {
            info!("Cleared default TLS module (was {})", id);
            self.default_tls_module = None;
        }

        info!("Disabled module: {}", id);
        Ok(())
    }
}
