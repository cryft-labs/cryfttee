//! WASM API module - traits and ABIs for WASM modules

pub mod staking;

pub use staking::*;

use wasmtime::{Module, Store, Linker};

/// Represents a loaded WASM module instance
pub struct WasmModule {
    /// Module identifier
    pub id: String,
    /// Module version
    pub version: String,
    /// Module capabilities
    pub capabilities: Vec<String>,
    /// Compiled WASM module
    module: Module,
    /// WASM store (holds instance state)
    store: Store<()>,
    /// Linker for host function binding
    linker: Linker<()>,
}

impl WasmModule {
    /// Create a new WASM module wrapper
    pub fn new(
        id: String,
        version: String,
        capabilities: Vec<String>,
        module: Module,
        store: Store<()>,
        linker: Linker<()>,
    ) -> Self {
        Self {
            id,
            version,
            capabilities,
            module,
            store,
            linker,
        }
    }

    /// Check if module has a specific capability
    pub fn has_capability(&self, capability: &str) -> bool {
        self.capabilities.contains(&capability.to_string())
    }

    /// Get the underlying WASM module
    pub fn module(&self) -> &Module {
        &self.module
    }
}

/// Signing capability marker trait
pub trait SigningCapability {
    /// Get the supported signing algorithms
    fn supported_algorithms(&self) -> Vec<String>;
}

/// BLS signing capability
pub trait BlsCapability: SigningCapability {
    /// Register a BLS key
    fn bls_register(
        &mut self,
        mode: u32,
        key_material: Option<&[u8]>,
    ) -> Result<(String, Vec<u8>), WasmError>;

    /// Sign with a BLS key
    fn bls_sign(
        &mut self,
        handle: &str,
        message: &[u8],
    ) -> Result<Vec<u8>, WasmError>;
}

/// TLS signing capability
pub trait TlsCapability: SigningCapability {
    /// Register a TLS key
    fn tls_register(
        &mut self,
        mode: u32,
        key_material: Option<&[u8]>,
        csr_pem: Option<&str>,
    ) -> Result<(String, String), WasmError>;

    /// Sign with a TLS key
    fn tls_sign(
        &mut self,
        handle: &str,
        digest: &[u8],
        algorithm: &str,
    ) -> Result<Vec<u8>, WasmError>;
}

/// Error type for WASM operations
#[derive(Debug, thiserror::Error)]
pub enum WasmError {
    #[error("WASM execution error: {0}")]
    Execution(String),

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Capability not supported: {0}")]
    UnsupportedCapability(String),

    #[error("Memory error: {0}")]
    Memory(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<wasmtime::Error> for WasmError {
    fn from(e: wasmtime::Error) -> Self {
        WasmError::Execution(e.to_string())
    }
}

/// Key registration modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum KeyMode {
    /// Create a persistent key (stored in Web3Signer)
    Persistent = 0,
    /// Create an ephemeral key (in-memory only)
    Ephemeral = 1,
    /// Import an existing key
    Import = 2,
}

impl TryFrom<u32> for KeyMode {
    type Error = WasmError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(KeyMode::Persistent),
            1 => Ok(KeyMode::Ephemeral),
            2 => Ok(KeyMode::Import),
            _ => Err(WasmError::InvalidParameter(format!("Invalid key mode: {}", value))),
        }
    }
}
