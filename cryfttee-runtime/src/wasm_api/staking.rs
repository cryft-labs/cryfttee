//! Staking module - BLS/TLS interface traits and types

use serde::{Deserialize, Serialize};

/// BLS register request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlsRegisterRequest {
    /// Key mode: "verify", "generate", "ephemeral", "persistent", or "import"
    /// - "verify": Verify that public_key exists in Web3Signer (CryftGo has existing key)
    /// - "generate": Generate new key (only allowed if CryftGo indicates no keys exist)
    /// - "persistent": Alias for generate
    /// - "ephemeral": Ephemeral key for testing
    /// - "import": Import provided secret key
    pub mode: String,
    /// Public key to verify exists in Web3Signer (hex-encoded, 0x-prefixed)
    /// Required for "verify" mode - this is the key CryftGo has in its local store
    #[serde(rename = "publicKey")]
    pub public_key: Option<String>,
    /// Base64-encoded ephemeral BLS secret key (for ephemeral/import mode)
    #[serde(rename = "ephemeralKeyB64")]
    pub ephemeral_key_b64: Option<String>,
    /// Network ID
    #[serde(rename = "networkID")]
    pub network_id: Option<u64>,
    /// Optional node label
    #[serde(rename = "nodeLabel")]
    pub node_label: Option<String>,
    /// Optional module ID to use
    #[serde(rename = "moduleId")]
    pub module_id: Option<String>,
}

/// BLS register response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlsRegisterResponse {
    /// Opaque key handle
    #[serde(rename = "keyHandle")]
    pub key_handle: String,
    /// Base64-encoded BLS public key
    #[serde(rename = "blsPubKeyB64")]
    pub bls_pub_key_b64: String,
    /// Module ID used
    #[serde(rename = "moduleId")]
    pub module_id: String,
    /// Module version
    #[serde(rename = "moduleVersion")]
    pub module_version: String,
}

/// BLS sign request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlsSignRequest {
    /// Key handle from registration
    #[serde(rename = "keyHandle")]
    pub key_handle: String,
    /// Base64-encoded message to sign
    pub message: String,
    /// Optional module ID
    #[serde(rename = "moduleId")]
    pub module_id: Option<String>,
}

/// BLS sign response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlsSignResponse {
    /// Base64-encoded BLS signature
    #[serde(rename = "signatureB64")]
    pub signature_b64: String,
    /// Module ID used
    #[serde(rename = "moduleId")]
    pub module_id: String,
    /// Module version
    #[serde(rename = "moduleVersion")]
    pub module_version: String,
}

/// TLS register request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsRegisterRequest {
    /// Key mode: "verify", "generate", "ephemeral", "persistent", or "import"
    /// - "verify": Verify that public_key exists in Web3Signer (CryftGo has existing key)
    /// - "generate": Generate new key (only allowed if CryftGo indicates no keys exist)
    /// - "persistent": Alias for generate
    /// - "ephemeral": Ephemeral key for testing
    /// - "import": Import provided secret key
    pub mode: String,
    /// Public key to verify exists in Web3Signer (hex-encoded, 0x-prefixed)
    /// Required for "verify" mode - this is the key CryftGo has in its local store
    #[serde(rename = "publicKey")]
    pub public_key: Option<String>,
    /// Base64-encoded ephemeral TLS key PEM (for testing)
    #[serde(rename = "ephemeralKeyPEM")]
    pub ephemeral_key_pem: Option<String>,
    /// Optional CSR PEM
    #[serde(rename = "csrPEM")]
    pub csr_pem: Option<String>,
    /// Network ID
    #[serde(rename = "networkID")]
    pub network_id: Option<u64>,
    /// Optional node label
    #[serde(rename = "nodeLabel")]
    pub node_label: Option<String>,
    /// Optional module ID
    #[serde(rename = "moduleId")]
    pub module_id: Option<String>,
}

/// TLS register response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsRegisterResponse {
    /// Opaque key handle
    #[serde(rename = "keyHandle")]
    pub key_handle: String,
    /// Base64-encoded PEM certificate chain
    #[serde(rename = "certChainPEM")]
    pub cert_chain_pem: String,
    /// Module ID used
    #[serde(rename = "moduleId")]
    pub module_id: String,
    /// Module version
    #[serde(rename = "moduleVersion")]
    pub module_version: String,
}

/// TLS sign request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsSignRequest {
    /// Key handle from registration
    #[serde(rename = "keyHandle")]
    pub key_handle: String,
    /// Base64-encoded digest to sign
    pub digest: String,
    /// Signature algorithm (e.g., "ECDSA_P256_SHA256")
    pub algorithm: String,
    /// Optional module ID
    #[serde(rename = "moduleId")]
    pub module_id: Option<String>,
}

/// TLS sign response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsSignResponse {
    /// Base64-encoded signature
    #[serde(rename = "signatureB64")]
    pub signature_b64: String,
    /// Module ID used
    #[serde(rename = "moduleId")]
    pub module_id: String,
    /// Module version
    #[serde(rename = "moduleVersion")]
    pub module_version: String,
}

/// Status response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    /// CryftTEE version
    #[serde(rename = "cryftteeVersion")]
    pub cryfttee_version: String,
    /// Module statuses
    pub modules: Vec<ModuleStatusEntry>,
    /// Web3Signer status
    #[serde(rename = "web3Signer")]
    pub web3_signer: Web3SignerStatus,
    /// WASM runtime status
    #[serde(rename = "wasmRuntime")]
    pub wasm_runtime: WasmRuntimeStatus,
}

/// Module status entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleStatusEntry {
    /// Module identifier
    pub id: String,
    /// Module version
    pub version: String,
    /// Minimum compatible cryfttee runtime version
    #[serde(rename = "minCryftteeVersion")]
    pub min_cryfttee_version: String,
    /// List of module capabilities (e.g., "bls_signing", "tls_signing")
    pub capabilities: Vec<String>,
    /// Default module for each capability type
    #[serde(rename = "defaultFor")]
    pub default_for: std::collections::HashMap<String, bool>,
    /// Whether the module is trusted (signature verified)
    pub trusted: bool,
    /// Whether the module is currently loaded
    pub loaded: bool,
    /// Whether the module is compatible with this runtime version
    pub compatible: bool,
    /// Reason for incompatibility or load failure (if any)
    pub reason: Option<String>,
}

/// Web3Signer status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Web3SignerStatus {
    /// Whether Web3Signer is reachable
    pub reachable: bool,
    /// Last error message from Web3Signer (if any)
    #[serde(rename = "lastError")]
    pub last_error: Option<String>,
}

/// WASM runtime status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmRuntimeStatus {
    /// Whether the WASM runtime is healthy
    pub healthy: bool,
    /// Last WASM runtime error (if any)
    #[serde(rename = "lastError")]
    pub last_error: Option<String>,
}

/// Key mode: Persistent key stored in Web3Signer
pub const KEY_MODE_PERSISTENT: u32 = 0;
/// Key mode: Ephemeral key for testing (not persisted)
pub const KEY_MODE_EPHEMERAL: u32 = 1;
/// Key mode: Import existing key material
pub const KEY_MODE_IMPORT: u32 = 2;
/// Key mode: Verify existing key exists in Web3Signer
pub const KEY_MODE_VERIFY: u32 = 3;
/// Key mode: Generate new key in Web3Signer
pub const KEY_MODE_GENERATE: u32 = 4;

/// Parse key mode string to u32
pub fn parse_key_mode(mode: &str) -> Result<u32, String> {
    match mode.to_lowercase().as_str() {
        "persistent" => Ok(KEY_MODE_PERSISTENT),
        "ephemeral" => Ok(KEY_MODE_EPHEMERAL),
        "import" => Ok(KEY_MODE_IMPORT),
        "verify" => Ok(KEY_MODE_VERIFY),
        "generate" => Ok(KEY_MODE_GENERATE),
        _ => Err(format!("Invalid key mode: {}. Valid modes: verify, generate, ephemeral, persistent, import", mode)),
    }
}

/// Check if mode requires a public key
pub fn mode_requires_public_key(mode: u32) -> bool {
    mode == KEY_MODE_VERIFY
}

/// Check if mode is for key generation
pub fn mode_is_generation(mode: u32) -> bool {
    mode == KEY_MODE_GENERATE || mode == KEY_MODE_PERSISTENT
}
