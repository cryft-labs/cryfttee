//! Staking module - BLS/TLS interface traits and types

use serde::{Deserialize, Serialize};

/// BLS register request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlsRegisterRequest {
    /// Key mode: "ephemeral", "persistent", or "import"
    pub mode: String,
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
    /// Key mode: "ephemeral", "persistent", or "import"
    pub mode: String,
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
    /// Cryftee version
    #[serde(rename = "cryfteeVersion")]
    pub cryftee_version: String,
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
    pub id: String,
    pub version: String,
    #[serde(rename = "minCryfteeVersion")]
    pub min_cryftee_version: String,
    pub capabilities: Vec<String>,
    #[serde(rename = "defaultFor")]
    pub default_for: std::collections::HashMap<String, bool>,
    pub trusted: bool,
    pub loaded: bool,
    pub compatible: bool,
    pub reason: Option<String>,
}

/// Web3Signer status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Web3SignerStatus {
    pub reachable: bool,
    #[serde(rename = "lastError")]
    pub last_error: Option<String>,
}

/// WASM runtime status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmRuntimeStatus {
    pub healthy: bool,
    #[serde(rename = "lastError")]
    pub last_error: Option<String>,
}

/// Parse key mode string to u32
pub fn parse_key_mode(mode: &str) -> Result<u32, String> {
    match mode.to_lowercase().as_str() {
        "persistent" => Ok(0),
        "ephemeral" => Ok(1),
        "import" => Ok(2),
        _ => Err(format!("Invalid key mode: {}", mode)),
    }
}
