//! Dispatch - routes operations to the appropriate module

use std::sync::Arc;
use anyhow::{Result, anyhow};
use tracing::{debug, info};

use crate::wasm_api::WasmModule;
use super::ModuleRegistry;

/// Dispatch context for routing operations to modules
pub struct Dispatcher<'a> {
    registry: &'a ModuleRegistry,
}

impl<'a> Dispatcher<'a> {
    /// Create a new dispatcher
    pub fn new(registry: &'a ModuleRegistry) -> Self {
        Self { registry }
    }

    /// Dispatch a BLS register operation
    pub async fn dispatch_bls_register(
        &self,
        mode: u32,
        key_material: Option<&[u8]>,
        module_id: Option<&str>,
    ) -> Result<BlsRegisterResult> {
        let module = self.get_bls_module(module_id)?;
        
        info!("Dispatching bls_register to module: {}", module.id);
        
        // TODO: Call into WASM module
        // For now, return placeholder
        Ok(BlsRegisterResult {
            key_handle: "placeholder-handle".to_string(),
            public_key: vec![0u8; 48], // BLS public key is 48 bytes
            module_id: module.id.clone(),
            module_version: module.version.clone(),
        })
    }

    /// Dispatch a BLS sign operation
    pub async fn dispatch_bls_sign(
        &self,
        key_handle: &str,
        message: &[u8],
        module_id: Option<&str>,
    ) -> Result<BlsSignResult> {
        let module = self.get_bls_module(module_id)?;
        
        debug!("Dispatching bls_sign to module: {}", module.id);
        
        // TODO: Call into WASM module
        // For now, return placeholder
        Ok(BlsSignResult {
            signature: vec![0u8; 96], // BLS signature is 96 bytes
            module_id: module.id.clone(),
            module_version: module.version.clone(),
        })
    }

    /// Dispatch a TLS register operation
    pub async fn dispatch_tls_register(
        &self,
        mode: u32,
        key_material: Option<&[u8]>,
        csr_pem: Option<&str>,
        module_id: Option<&str>,
    ) -> Result<TlsRegisterResult> {
        let module = self.get_tls_module(module_id)?;
        
        info!("Dispatching tls_register to module: {}", module.id);
        
        // TODO: Call into WASM module
        // For now, return placeholder
        Ok(TlsRegisterResult {
            key_handle: "placeholder-tls-handle".to_string(),
            cert_chain_pem: "-----BEGIN CERTIFICATE-----\nplaceholder\n-----END CERTIFICATE-----".to_string(),
            module_id: module.id.clone(),
            module_version: module.version.clone(),
        })
    }

    /// Dispatch a TLS sign operation
    pub async fn dispatch_tls_sign(
        &self,
        key_handle: &str,
        digest: &[u8],
        algorithm: &str,
        module_id: Option<&str>,
    ) -> Result<TlsSignResult> {
        let module = self.get_tls_module(module_id)?;
        
        debug!("Dispatching tls_sign to module: {}", module.id);
        
        // TODO: Call into WASM module
        // For now, return placeholder
        Ok(TlsSignResult {
            signature: vec![0u8; 64], // ECDSA signature
            module_id: module.id.clone(),
            module_version: module.version.clone(),
        })
    }

    /// Get the appropriate BLS module
    fn get_bls_module(&self, module_id: Option<&str>) -> Result<Arc<WasmModule>> {
        let id = match module_id {
            Some(id) => id.to_string(),
            None => self.registry
                .get_default_bls_module()
                .ok_or_else(|| anyhow!("No default BLS module configured"))?
                .to_string(),
        };

        self.registry
            .get_wasm_instance(&id)
            .ok_or_else(|| anyhow!("BLS module not found: {}", id))
    }

    /// Get the appropriate TLS module
    fn get_tls_module(&self, module_id: Option<&str>) -> Result<Arc<WasmModule>> {
        let id = match module_id {
            Some(id) => id.to_string(),
            None => self.registry
                .get_default_tls_module()
                .ok_or_else(|| anyhow!("No default TLS module configured"))?
                .to_string(),
        };

        self.registry
            .get_wasm_instance(&id)
            .ok_or_else(|| anyhow!("TLS module not found: {}", id))
    }
}

/// Result of BLS register operation
#[derive(Debug)]
pub struct BlsRegisterResult {
    pub key_handle: String,
    pub public_key: Vec<u8>,
    pub module_id: String,
    pub module_version: String,
}

/// Result of BLS sign operation
#[derive(Debug)]
pub struct BlsSignResult {
    pub signature: Vec<u8>,
    pub module_id: String,
    pub module_version: String,
}

/// Result of TLS register operation
#[derive(Debug)]
pub struct TlsRegisterResult {
    pub key_handle: String,
    pub cert_chain_pem: String,
    pub module_id: String,
    pub module_version: String,
}

/// Result of TLS sign operation
#[derive(Debug)]
pub struct TlsSignResult {
    pub signature: Vec<u8>,
    pub module_id: String,
    pub module_version: String,
}
