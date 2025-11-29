//! Module loader - loads WASM modules from disk or IPFS

use anyhow::{Result, anyhow};
use tracing::{info, debug};
use wasmtime::{Engine, Module, Store, Linker};

use crate::config::CryftteeConfig;
use crate::storage::ManifestEntry;
use crate::wasm_api::WasmModule;

/// Module loader - handles WASM loading and instantiation
pub struct ModuleLoader {
    config: CryftteeConfig,
    engine: Engine,
}

impl ModuleLoader {
    /// Create a new module loader
    pub fn new(config: CryftteeConfig) -> Self {
        let engine = Engine::default();
        Self { config, engine }
    }

    /// Load a WASM module from its manifest entry
    pub async fn load_wasm(&self, entry: &ManifestEntry) -> Result<WasmModule> {
        let module_path = self.config.module_dir
            .join(&entry.dir)
            .join(&entry.file);

        info!("Loading WASM module from {:?}", module_path);

        if !module_path.exists() {
            return Err(anyhow!("Module file not found: {:?}", module_path));
        }

        // Read the WASM bytes
        let wasm_bytes = tokio::fs::read(&module_path).await?;
        debug!("Read {} bytes from module file", wasm_bytes.len());

        // Compile the module
        let module = Module::new(&self.engine, &wasm_bytes)?;
        debug!("Compiled WASM module: {}", entry.id);

        // Create store with empty state for now
        let store = Store::new(&self.engine, ());

        // Create linker and set up host functions
        let linker = Linker::new(&self.engine);
        
        // TODO: Link host functions for the module
        // - Memory access
        // - Logging
        // - Web3Signer calls

        Ok(WasmModule::new(
            entry.id.clone(),
            entry.version.clone(),
            entry.capabilities.clone(),
            module,
            store,
            linker,
        ))
    }

    /// Validate that a module exports the required functions for its capabilities
    pub fn validate_exports(&self, module: &Module, capabilities: &[String]) -> Result<()> {
        let exports: Vec<_> = module.exports().collect();
        let export_names: Vec<&str> = exports.iter().map(|e| e.name()).collect();

        for capability in capabilities {
            let required_exports = get_required_exports(capability);
            for required in required_exports {
                if !export_names.contains(&required) {
                    return Err(anyhow!(
                        "Module missing required export '{}' for capability '{}'",
                        required, capability
                    ));
                }
            }
        }

        Ok(())
    }
}

/// Get required WASM exports for a capability
fn get_required_exports(capability: &str) -> Vec<&'static str> {
    match capability {
        "bls_register" => vec!["bls_register"],
        "bls_sign" => vec!["bls_sign"],
        "tls_register" => vec!["tls_register"],
        "tls_sign" => vec!["tls_sign"],
        _ => vec![],
    }
}
