//! Dispatch - routes operations to the appropriate module and Web3Signer

use std::sync::Arc;
use anyhow::{Result, anyhow};
use tracing::{debug, info};
use serde::Deserialize;

use crate::wasm_api::WasmModule;
use super::ModuleRegistry;

/// Web3Signer client for BLS/TLS operations
pub struct Web3SignerClient {
    base_url: String,
    client: reqwest::Client,
    timeout: std::time::Duration,
}

impl Web3SignerClient {
    /// Create a new Web3Signer client
    pub fn new(base_url: &str, timeout_secs: u64) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
            timeout: std::time::Duration::from_secs(timeout_secs),
        }
    }

    /// Generate a new BLS key in Web3Signer
    /// POST /eth/v1/keystores with a new keystore
    pub async fn generate_bls_key(&self) -> Result<BlsKeyResult> {
        info!("Generating new BLS key via Web3Signer");
        
        // Web3Signer doesn't directly generate keys - you need to import them
        // For a real implementation, we'd generate locally and import, or use Vault
        // For now, return error indicating this needs external key generation
        Err(anyhow!(
            "BLS key generation requires importing a keystore. \
             Use the import-key.sh script to generate and import keys: \
             sudo /opt/cryfttee-keyvault/scripts/import-key.sh generate-bls"
        ))
    }

    /// List all BLS public keys
    /// GET /api/v1/eth2/publicKeys
    pub async fn list_bls_keys(&self) -> Result<Vec<String>> {
        let url = format!("{}/api/v1/eth2/publicKeys", self.base_url);
        
        let response = self.client
            .get(&url)
            .timeout(self.timeout)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!("Web3Signer returned HTTP {}", response.status()));
        }

        let keys: Vec<String> = response.json().await?;
        Ok(keys)
    }

    /// Sign a message with a BLS key
    /// POST /api/v1/eth2/sign/{pubkey}
    pub async fn bls_sign(&self, pubkey: &str, message: &[u8]) -> Result<Vec<u8>> {
        let normalized_pubkey = normalize_pubkey(pubkey);
        let url = format!("{}/api/v1/eth2/sign/{}", self.base_url, normalized_pubkey);
        
        // Web3Signer expects a specific signing request format
        // For generic signing, we use the BLOCK type with the message as signing_root
        let signing_root = hex::encode(message);
        
        let request_body = serde_json::json!({
            "type": "BLOCK",
            "fork_info": {
                "fork": {
                    "previous_version": "0x00000000",
                    "current_version": "0x00000000", 
                    "epoch": "0"
                },
                "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            },
            "block": {
                "slot": "0",
                "proposer_index": "0",
                "parent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "state_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "body_root": format!("0x{}", signing_root)
            }
        });

        debug!("BLS signing request to {}", url);

        let response = self.client
            .post(&url)
            .json(&request_body)
            .timeout(self.timeout)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("BLS signing failed: HTTP {} - {}", status, body));
        }

        #[derive(Deserialize)]
        struct SignResponse {
            signature: String,
        }

        let sign_response: SignResponse = response.json().await?;
        
        // Signature is hex-encoded with 0x prefix
        let sig_hex = sign_response.signature.trim_start_matches("0x");
        let signature = hex::decode(sig_hex)?;
        
        info!("BLS signature generated successfully ({} bytes)", signature.len());
        Ok(signature)
    }

    /// List SECP256K1/TLS public keys (if supported)
    /// GET /api/v1/eth1/publicKeys
    pub async fn list_tls_keys(&self) -> Result<Vec<String>> {
        let url = format!("{}/api/v1/eth1/publicKeys", self.base_url);
        
        let response = self.client
            .get(&url)
            .timeout(self.timeout)
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                let keys: Vec<String> = resp.json().await?;
                Ok(keys)
            }
            Ok(resp) => {
                debug!("TLS keys endpoint returned {}", resp.status());
                Ok(vec![])
            }
            Err(e) => {
                debug!("TLS keys endpoint error: {}", e);
                Ok(vec![])
            }
        }
    }

    /// Sign with a SECP256K1/TLS key
    /// POST /api/v1/eth1/sign/{pubkey}
    pub async fn tls_sign(&self, pubkey: &str, digest: &[u8], _algorithm: &str) -> Result<Vec<u8>> {
        let normalized_pubkey = normalize_pubkey(pubkey);
        let url = format!("{}/api/v1/eth1/sign/{}", self.base_url, normalized_pubkey);
        
        let request_body = serde_json::json!({
            "data": format!("0x{}", hex::encode(digest))
        });

        debug!("TLS signing request to {}", url);

        let response = self.client
            .post(&url)
            .json(&request_body)
            .timeout(self.timeout)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("TLS signing failed: HTTP {} - {}", status, body));
        }

        #[derive(Deserialize)]
        struct SignResponse {
            signature: String,
        }

        let sign_response: SignResponse = response.json().await?;
        let sig_hex = sign_response.signature.trim_start_matches("0x");
        let signature = hex::decode(sig_hex)?;
        
        info!("TLS signature generated successfully ({} bytes)", signature.len());
        Ok(signature)
    }
}

/// Normalize a public key (lowercase, ensure 0x prefix)
fn normalize_pubkey(key: &str) -> String {
    let key = key.trim().to_lowercase();
    if key.starts_with("0x") {
        key
    } else {
        format!("0x{}", key)
    }
}

/// Result of BLS key lookup/generation
#[derive(Debug)]
pub struct BlsKeyResult {
    /// BLS public key (hex-encoded with 0x prefix)
    pub pubkey: String,
    /// Key handle for subsequent operations
    pub key_handle: String,
}

/// Dispatch context for routing operations to modules
pub struct Dispatcher<'a> {
    registry: &'a ModuleRegistry,
    web3signer_url: String,
    web3signer_timeout: u64,
}

impl<'a> Dispatcher<'a> {
    /// Create a new dispatcher
    pub fn new(registry: &'a ModuleRegistry) -> Self {
        Self { 
            registry,
            web3signer_url: "http://localhost:9000".to_string(),
            web3signer_timeout: 30,
        }
    }

    /// Create a dispatcher with custom Web3Signer config
    pub fn with_web3signer(registry: &'a ModuleRegistry, url: &str, timeout: u64) -> Self {
        Self {
            registry,
            web3signer_url: url.to_string(),
            web3signer_timeout: timeout,
        }
    }

    /// Get Web3Signer client
    fn get_web3signer_client(&self) -> Web3SignerClient {
        Web3SignerClient::new(&self.web3signer_url, self.web3signer_timeout)
    }

    /// Dispatch a BLS register operation
    /// 
    /// For mode=verify: Verifies key exists in Web3Signer
    /// For mode=generate: Returns error (keys must be imported externally)
    /// For mode=ephemeral: Not supported via Web3Signer
    pub async fn dispatch_bls_register(
        &self,
        mode: u32,
        key_material: Option<&[u8]>,
        module_id: Option<&str>,
    ) -> Result<BlsRegisterResult> {
        let module = self.get_bls_module(module_id)?;
        
        info!("Dispatching bls_register to module: {} (mode={})", module.id, mode);
        
        let client = self.get_web3signer_client();
        
        match mode {
            // Persistent or Generate - list available keys
            0 | 4 => {
                // For key generation, we need keys to already exist in Web3Signer
                // Return the first available key, or error if none
                let pubkeys = client.list_bls_keys().await?;
                
                if pubkeys.is_empty() {
                    return Err(anyhow!(
                        "No BLS keys available in Web3Signer. \
                         Import keys using: sudo /opt/cryfttee-keyvault/scripts/import-key.sh bls <keystore.json> <password>"
                    ));
                }
                
                let pubkey = &pubkeys[0];
                info!("Using BLS key from Web3Signer: {}...", &pubkey[..20.min(pubkey.len())]);
                
                // Decode pubkey to bytes for response
                let pubkey_bytes = hex::decode(pubkey.trim_start_matches("0x"))?;
                
                Ok(BlsRegisterResult {
                    key_handle: pubkey.clone(),
                    public_key: pubkey_bytes,
                    module_id: module.id.clone(),
                    module_version: module.version.clone(),
                })
            }
            // Ephemeral - not supported with Web3Signer
            1 => {
                Err(anyhow!("Ephemeral BLS keys are not supported with Web3Signer"))
            }
            // Import - would require importing to Web3Signer
            2 => {
                if key_material.is_none() {
                    return Err(anyhow!("Import mode requires key material"));
                }
                Err(anyhow!(
                    "Key import must be done directly via Web3Signer keystore import. \
                     Use: sudo /opt/cryfttee-keyvault/scripts/import-key.sh bls <keystore.json> <password>"
                ))
            }
            // Verify - check key exists (handled in api.rs before dispatch)
            3 => {
                Err(anyhow!("Verify mode should be handled before dispatch"))
            }
            _ => {
                Err(anyhow!("Invalid BLS register mode: {}", mode))
            }
        }
    }

    /// Dispatch a BLS sign operation
    pub async fn dispatch_bls_sign(
        &self,
        key_handle: &str,
        message: &[u8],
        module_id: Option<&str>,
    ) -> Result<BlsSignResult> {
        let module = self.get_bls_module(module_id)?;
        
        info!("Dispatching bls_sign to module: {} (key={}...)", 
              module.id, &key_handle[..20.min(key_handle.len())]);
        
        let client = self.get_web3signer_client();
        
        // Sign via Web3Signer
        let signature = client.bls_sign(key_handle, message).await?;
        
        Ok(BlsSignResult {
            signature,
            module_id: module.id.clone(),
            module_version: module.version.clone(),
        })
    }

    /// Dispatch a TLS register operation
    pub async fn dispatch_tls_register(
        &self,
        mode: u32,
        _key_material: Option<&[u8]>,
        _csr_pem: Option<&str>,
        module_id: Option<&str>,
    ) -> Result<TlsRegisterResult> {
        let module = self.get_tls_module(module_id)?;
        
        info!("Dispatching tls_register to module: {} (mode={})", module.id, mode);
        
        let client = self.get_web3signer_client();
        
        match mode {
            // Persistent or Generate
            0 | 4 => {
                let pubkeys = client.list_tls_keys().await?;
                
                if pubkeys.is_empty() {
                    return Err(anyhow!(
                        "No TLS/SECP256K1 keys available in Web3Signer. \
                         TLS key support may require additional Web3Signer configuration."
                    ));
                }
                
                let pubkey = &pubkeys[0];
                info!("Using TLS key from Web3Signer: {}...", &pubkey[..20.min(pubkey.len())]);
                
                // For TLS, we'd typically generate a self-signed cert
                // For now, return a placeholder cert indicating the key is available
                let cert_pem = format!(
                    "-----BEGIN CERTIFICATE-----\n\
                     Key available in Web3Signer: {}\n\
                     -----END CERTIFICATE-----",
                    pubkey
                );
                
                Ok(TlsRegisterResult {
                    key_handle: pubkey.clone(),
                    cert_chain_pem: cert_pem,
                    module_id: module.id.clone(),
                    module_version: module.version.clone(),
                })
            }
            1 => {
                Err(anyhow!("Ephemeral TLS keys are not supported with Web3Signer"))
            }
            2 => {
                Err(anyhow!("TLS key import must be done directly via Web3Signer"))
            }
            3 => {
                Err(anyhow!("Verify mode should be handled before dispatch"))
            }
            _ => {
                Err(anyhow!("Invalid TLS register mode: {}", mode))
            }
        }
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
        
        info!("Dispatching tls_sign to module: {} (key={}..., algo={})", 
              module.id, &key_handle[..20.min(key_handle.len())], algorithm);
        
        let client = self.get_web3signer_client();
        
        // Sign via Web3Signer
        let signature = client.tls_sign(key_handle, digest, algorithm).await?;
        
        Ok(TlsSignResult {
            signature,
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
    /// Key handle for subsequent signing operations
    pub key_handle: String,
    /// BLS public key bytes
    pub public_key: Vec<u8>,
    /// Module that handled the registration
    pub module_id: String,
    /// Version of the handling module
    pub module_version: String,
}

/// Result of BLS sign operation
#[derive(Debug)]
pub struct BlsSignResult {
    /// BLS signature bytes
    pub signature: Vec<u8>,
    /// Module that performed the signing
    pub module_id: String,
    /// Version of the signing module
    pub module_version: String,
}

/// Result of TLS register operation
#[derive(Debug)]
pub struct TlsRegisterResult {
    /// Key handle for subsequent signing operations
    pub key_handle: String,
    /// PEM-encoded certificate chain
    pub cert_chain_pem: String,
    /// Module that handled the registration
    pub module_id: String,
    /// Version of the handling module
    pub module_version: String,
}

/// Result of TLS sign operation
#[derive(Debug)]
pub struct TlsSignResult {
    /// TLS signature bytes
    pub signature: Vec<u8>,
    /// Module that performed the signing
    pub module_id: String,
    /// Version of the signing module
    pub module_version: String,
}
