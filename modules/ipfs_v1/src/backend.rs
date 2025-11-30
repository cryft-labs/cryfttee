//! IPFS Backend - Local Node Integration
//!
//! Executes IPFS API calls against a local kubo (go-ipfs) daemon.
//! All operations are LOCAL - no external pinning services.
//!
//! Requires a running IPFS daemon:
//!   - Linux/macOS: `ipfs daemon`
//!   - Docker: `docker run -d --name ipfs -p 5001:5001 -p 8080:8080 ipfs/kubo`
//!
//! Default endpoints:
//!   - API: http://127.0.0.1:5001
//!   - Gateway: http://127.0.0.1:8080

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use anyhow::{Result, anyhow, Context};
use tracing::{info, warn, debug, error};
use chrono::{DateTime, Utc};

/// IPFS Backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpfsBackendConfig {
    /// Local IPFS API URL
    pub api_url: String,
    /// Local gateway URL
    pub gateway_url: String,
    /// Public gateway for shareable URLs
    pub public_gateway: String,
    /// Request timeout
    pub timeout_secs: u64,
    /// Max content size
    pub max_size: u64,
}

impl Default for IpfsBackendConfig {
    fn default() -> Self {
        Self {
            api_url: "http://127.0.0.1:5001".to_string(),
            gateway_url: "http://127.0.0.1:8080".to_string(),
            public_gateway: "https://gateway.cryft.network".to_string(),
            timeout_secs: 60,
            max_size: 100 * 1024 * 1024, // 100MB
        }
    }
}

/// Pin metadata stored locally (not in IPFS itself)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinMetadata {
    pub cid: String,
    pub name: Option<String>,
    pub tags: HashMap<String, String>,
    pub pinned_at: DateTime<Utc>,
    pub size: Option<u64>,
    pub pin_type: String,
}

/// IPFS Backend - manages local IPFS node interactions
pub struct IpfsBackend {
    config: IpfsBackendConfig,
    client: reqwest::Client,
    /// Local metadata database (CID -> metadata)
    metadata: Arc<RwLock<HashMap<String, PinMetadata>>>,
}

impl IpfsBackend {
    /// Create new IPFS backend with default config
    pub fn new() -> Self {
        Self::with_config(IpfsBackendConfig::default())
    }
    
    /// Create new IPFS backend with custom config
    pub fn with_config(config: IpfsBackendConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .expect("Failed to create HTTP client");
        
        Self {
            config,
            client,
            metadata: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Update configuration
    pub fn set_config(&mut self, config: IpfsBackendConfig) {
        self.config = config;
    }
    
    /// Check if local IPFS node is running
    pub async fn check_node(&self) -> Result<NodeStatus> {
        let url = format!("{}/api/v0/id", self.config.api_url);
        
        match self.client.post(&url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    let data: Value = response.json().await?;
                    Ok(NodeStatus {
                        online: true,
                        peer_id: data["ID"].as_str().map(String::from),
                        agent_version: data["AgentVersion"].as_str().map(String::from),
                        protocol_version: data["ProtocolVersion"].as_str().map(String::from),
                        addresses: data["Addresses"].as_array()
                            .map(|arr| arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect())
                            .unwrap_or_default(),
                        error: None,
                    })
                } else {
                    Ok(NodeStatus {
                        online: false,
                        error: Some(format!("HTTP {}", response.status())),
                        ..Default::default()
                    })
                }
            }
            Err(e) => {
                Ok(NodeStatus {
                    online: false,
                    error: Some(format!("Connection failed: {}", e)),
                    ..Default::default()
                })
            }
        }
    }
    
    /// Get node ID and info
    pub async fn node_id(&self) -> Result<Value> {
        let url = format!("{}/api/v0/id", self.config.api_url);
        let response = self.client.post(&url).send().await?;
        
        if !response.status().is_success() {
            return Err(anyhow!("IPFS node error: {}", response.status()));
        }
        
        Ok(response.json().await?)
    }
    
    // =========================================================================
    // Pin Operations
    // =========================================================================
    
    /// Pin a CID locally
    pub async fn pin_add(
        &self,
        cid: &str,
        recursive: bool,
        name: Option<String>,
        tags: HashMap<String, String>,
    ) -> Result<PinResult> {
        info!("Pinning CID locally: {}", cid);
        
        let url = format!(
            "{}/api/v0/pin/add?arg={}&recursive={}",
            self.config.api_url, cid, recursive
        );
        
        let response = self.client.post(&url).send().await
            .context("Failed to connect to IPFS node")?;
        
        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow!("Pin failed: {}", error_text));
        }
        
        let data: Value = response.json().await?;
        let pinned_cids: Vec<String> = data["Pins"].as_array()
            .map(|arr| arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect())
            .unwrap_or_default();
        
        // Get size info
        let size = self.get_object_size(cid).await.ok();
        
        // Store metadata locally
        let metadata = PinMetadata {
            cid: cid.to_string(),
            name: name.clone(),
            tags: tags.clone(),
            pinned_at: Utc::now(),
            size,
            pin_type: if recursive { "recursive".to_string() } else { "direct".to_string() },
        };
        
        {
            let mut meta_db = self.metadata.write().await;
            meta_db.insert(cid.to_string(), metadata);
        }
        
        Ok(PinResult {
            cid: cid.to_string(),
            pinned: true,
            name,
            size,
            local_url: format!("{}/ipfs/{}", self.config.gateway_url, cid),
            public_url: format!("{}/ipfs/{}", self.config.public_gateway, cid),
        })
    }
    
    /// Unpin a CID locally
    pub async fn pin_rm(&self, cid: &str, recursive: bool) -> Result<Value> {
        info!("Unpinning CID: {}", cid);
        
        let url = format!(
            "{}/api/v0/pin/rm?arg={}&recursive={}",
            self.config.api_url, cid, recursive
        );
        
        let response = self.client.post(&url).send().await?;
        
        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow!("Unpin failed: {}", error_text));
        }
        
        // Remove from metadata
        {
            let mut meta_db = self.metadata.write().await;
            meta_db.remove(cid);
        }
        
        Ok(json!({
            "cid": cid,
            "unpinned": true
        }))
    }
    
    /// List local pins
    pub async fn pin_ls(
        &self,
        pin_type: &str,
        cid_prefix: Option<&str>,
        include_size: bool,
    ) -> Result<Vec<PinInfo>> {
        let url = format!(
            "{}/api/v0/pin/ls?type={}",
            self.config.api_url, pin_type
        );
        
        let response = self.client.post(&url).send().await?;
        
        if !response.status().is_success() {
            return Err(anyhow!("Pin list failed: {}", response.status()));
        }
        
        let data: Value = response.json().await?;
        let keys = data["Keys"].as_object();
        
        let mut pins = Vec::new();
        let metadata = self.metadata.read().await;
        
        if let Some(keys) = keys {
            for (cid, info) in keys {
                // Filter by prefix if specified
                if let Some(prefix) = cid_prefix {
                    if !cid.starts_with(prefix) {
                        continue;
                    }
                }
                
                let pin_type = info["Type"].as_str().unwrap_or("unknown").to_string();
                
                // Get metadata if available
                let meta = metadata.get(cid);
                
                let size = if include_size {
                    self.get_object_size(cid).await.ok()
                } else {
                    meta.and_then(|m| m.size)
                };
                
                pins.push(PinInfo {
                    cid: cid.clone(),
                    pin_type,
                    name: meta.and_then(|m| m.name.clone()),
                    tags: meta.map(|m| m.tags.clone()).unwrap_or_default(),
                    size,
                    pinned_at: meta.map(|m| m.pinned_at),
                });
            }
        }
        
        Ok(pins)
    }
    
    /// Search pins by name, CID prefix, or tags
    pub async fn search_pins(
        &self,
        query: &str,
        tags: HashMap<String, String>,
        limit: usize,
    ) -> Result<Vec<PinInfo>> {
        let all_pins = self.pin_ls("all", None, false).await?;
        let query_lower = query.to_lowercase();
        
        let filtered: Vec<PinInfo> = all_pins.into_iter()
            .filter(|pin| {
                // Match CID prefix
                if pin.cid.to_lowercase().starts_with(&query_lower) {
                    return true;
                }
                // Match name
                if let Some(ref name) = pin.name {
                    if name.to_lowercase().contains(&query_lower) {
                        return true;
                    }
                }
                // Match tags
                for (key, value) in &pin.tags {
                    if key.to_lowercase().contains(&query_lower) 
                        || value.to_lowercase().contains(&query_lower) {
                        return true;
                    }
                }
                false
            })
            .filter(|pin| {
                // Filter by required tags
                if tags.is_empty() {
                    return true;
                }
                tags.iter().all(|(k, v)| pin.tags.get(k) == Some(v))
            })
            .take(limit)
            .collect();
        
        Ok(filtered)
    }
    
    // =========================================================================
    // Content Operations
    // =========================================================================
    
    /// Add content to IPFS
    pub async fn add(
        &self,
        content: &[u8],
        filename: Option<&str>,
        pin: bool,
        cid_version: u8,
        name: Option<String>,
        tags: HashMap<String, String>,
    ) -> Result<AddResult> {
        info!("Adding content to IPFS ({} bytes)", content.len());
        
        // Build multipart form
        let file_name = filename.unwrap_or("file");
        let part = reqwest::multipart::Part::bytes(content.to_vec())
            .file_name(file_name.to_string());
        
        let form = reqwest::multipart::Form::new()
            .part("file", part);
        
        let url = format!(
            "{}/api/v0/add?pin={}&cid-version={}",
            self.config.api_url, pin, cid_version
        );
        
        let response = self.client.post(&url)
            .multipart(form)
            .send()
            .await?;
        
        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow!("Add failed: {}", error_text));
        }
        
        let data: Value = response.json().await?;
        let cid = data["Hash"].as_str()
            .ok_or_else(|| anyhow!("No CID in response"))?
            .to_string();
        let size = data["Size"].as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(content.len() as u64);
        
        // Store metadata if pinned
        if pin {
            let metadata = PinMetadata {
                cid: cid.clone(),
                name: name.clone(),
                tags: tags.clone(),
                pinned_at: Utc::now(),
                size: Some(size),
                pin_type: "recursive".to_string(),
            };
            
            let mut meta_db = self.metadata.write().await;
            meta_db.insert(cid.clone(), metadata);
        }
        
        Ok(AddResult {
            cid: cid.clone(),
            size,
            pinned: pin,
            name,
            local_url: format!("{}/ipfs/{}", self.config.gateway_url, cid),
            public_url: format!("{}/ipfs/{}", self.config.public_gateway, cid),
        })
    }
    
    /// Get content from IPFS (cat)
    pub async fn cat(&self, path: &str, max_size: u64, prefer_local: bool) -> Result<CatResult> {
        debug!("Fetching from IPFS: {}", path);
        
        // Clean path
        let clean_path = path.trim_start_matches("/ipfs/");
        
        // Try local node first if preferred
        if prefer_local {
            if let Ok(result) = self.cat_from_api(clean_path, max_size).await {
                return Ok(result);
            }
        }
        
        // Fallback to gateway
        self.cat_from_gateway(clean_path, max_size).await
    }
    
    async fn cat_from_api(&self, path: &str, max_size: u64) -> Result<CatResult> {
        let url = format!("{}/api/v0/cat?arg={}", self.config.api_url, path);
        
        let response = self.client.post(&url).send().await?;
        
        if !response.status().is_success() {
            return Err(anyhow!("Cat failed: {}", response.status()));
        }
        
        let content_type = response.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();
        
        let bytes = response.bytes().await?;
        
        if bytes.len() as u64 > max_size {
            return Err(anyhow!("Content too large: {} bytes (max: {})", bytes.len(), max_size));
        }
        
        Ok(CatResult {
            cid: path.to_string(),
            content: bytes.to_vec(),
            content_type,
            size: bytes.len() as u64,
            source: "local".to_string(),
        })
    }
    
    async fn cat_from_gateway(&self, path: &str, max_size: u64) -> Result<CatResult> {
        let url = format!("{}/ipfs/{}", self.config.gateway_url, path);
        
        let response = self.client.get(&url).send().await?;
        
        if !response.status().is_success() {
            return Err(anyhow!("Gateway fetch failed: {}", response.status()));
        }
        
        let content_type = response.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();
        
        let bytes = response.bytes().await?;
        
        if bytes.len() as u64 > max_size {
            return Err(anyhow!("Content too large"));
        }
        
        Ok(CatResult {
            cid: path.to_string(),
            content: bytes.to_vec(),
            content_type,
            size: bytes.len() as u64,
            source: "gateway".to_string(),
        })
    }
    
    /// Get object stats
    pub async fn stat(&self, path: &str) -> Result<Value> {
        let url = format!("{}/api/v0/object/stat?arg={}", self.config.api_url, path);
        
        let response = self.client.post(&url).send().await?;
        
        if !response.status().is_success() {
            return Err(anyhow!("Stat failed: {}", response.status()));
        }
        
        Ok(response.json().await?)
    }
    
    /// Get cumulative size of an object
    async fn get_object_size(&self, cid: &str) -> Result<u64> {
        let stat = self.stat(cid).await?;
        stat["CumulativeSize"].as_u64()
            .ok_or_else(|| anyhow!("No size in stat"))
    }
    
    // =========================================================================
    // IPNS Operations
    // =========================================================================
    
    /// Publish CID to IPNS
    pub async fn name_publish(
        &self,
        cid: &str,
        key: &str,
        ttl: u64,
        lifetime: u64,
    ) -> Result<IpnsPublishResult> {
        info!("Publishing to IPNS: {} -> {} (key: {})", key, cid, key);
        
        let url = format!(
            "{}/api/v0/name/publish?arg=/ipfs/{}&key={}&ttl={}s&lifetime={}s",
            self.config.api_url, cid, key, ttl, lifetime
        );
        
        let response = self.client.post(&url).send().await?;
        
        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow!("IPNS publish failed: {}", error_text));
        }
        
        let data: Value = response.json().await?;
        let name = data["Name"].as_str().unwrap_or("").to_string();
        let value = data["Value"].as_str().unwrap_or("").to_string();
        
        Ok(IpnsPublishResult {
            name: name.clone(),
            value,
            ipns_url: format!("{}/ipns/{}", self.config.public_gateway, name),
            published_at: Utc::now(),
        })
    }
    
    /// Resolve IPNS name
    pub async fn name_resolve(&self, name: &str, timeout: u64) -> Result<IpnsResolveResult> {
        debug!("Resolving IPNS: {}", name);
        
        let url = format!(
            "{}/api/v0/name/resolve?arg={}&timeout={}s",
            self.config.api_url, name, timeout
        );
        
        let response = self.client.post(&url).send().await?;
        
        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow!("IPNS resolve failed: {}", error_text));
        }
        
        let data: Value = response.json().await?;
        let path = data["Path"].as_str().unwrap_or("").to_string();
        let cid = path.trim_start_matches("/ipfs/").to_string();
        
        Ok(IpnsResolveResult {
            name: name.to_string(),
            cid: cid.clone(),
            path,
            gateway_url: format!("{}/ipfs/{}", self.config.public_gateway, cid),
            resolved_at: Utc::now(),
        })
    }
    
    /// List IPNS keys
    pub async fn key_list(&self) -> Result<Vec<KeyInfo>> {
        let url = format!("{}/api/v0/key/list", self.config.api_url);
        
        let response = self.client.post(&url).send().await?;
        
        if !response.status().is_success() {
            return Err(anyhow!("Key list failed: {}", response.status()));
        }
        
        let data: Value = response.json().await?;
        let keys = data["Keys"].as_array()
            .map(|arr| arr.iter()
                .filter_map(|k| {
                    Some(KeyInfo {
                        name: k["Name"].as_str()?.to_string(),
                        id: k["Id"].as_str()?.to_string(),
                    })
                })
                .collect())
            .unwrap_or_default();
        
        Ok(keys)
    }
    
    /// Generate new IPNS key
    pub async fn key_gen(&self, name: &str, key_type: &str) -> Result<KeyInfo> {
        let url = format!(
            "{}/api/v0/key/gen?arg={}&type={}",
            self.config.api_url, name, key_type
        );
        
        let response = self.client.post(&url).send().await?;
        
        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow!("Key generation failed: {}", error_text));
        }
        
        let data: Value = response.json().await?;
        
        Ok(KeyInfo {
            name: data["Name"].as_str().unwrap_or(name).to_string(),
            id: data["Id"].as_str().unwrap_or("").to_string(),
        })
    }
}

// ============================================================================
// Result Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct NodeStatus {
    pub online: bool,
    pub peer_id: Option<String>,
    pub agent_version: Option<String>,
    pub protocol_version: Option<String>,
    pub addresses: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PinResult {
    pub cid: String,
    pub pinned: bool,
    pub name: Option<String>,
    pub size: Option<u64>,
    pub local_url: String,
    pub public_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PinInfo {
    pub cid: String,
    pub pin_type: String,
    pub name: Option<String>,
    pub tags: HashMap<String, String>,
    pub size: Option<u64>,
    pub pinned_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddResult {
    pub cid: String,
    pub size: u64,
    pub pinned: bool,
    pub name: Option<String>,
    pub local_url: String,
    pub public_url: String,
}

#[derive(Debug, Clone)]
pub struct CatResult {
    pub cid: String,
    pub content: Vec<u8>,
    pub content_type: String,
    pub size: u64,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpnsPublishResult {
    pub name: String,
    pub value: String,
    pub ipns_url: String,
    pub published_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpnsResolveResult {
    pub name: String,
    pub cid: String,
    pub path: String,
    pub gateway_url: String,
    pub resolved_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyInfo {
    pub name: String,
    pub id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = IpfsBackendConfig::default();
        assert_eq!(config.api_url, "http://127.0.0.1:5001");
        assert_eq!(config.gateway_url, "http://127.0.0.1:8080");
    }

    #[test]
    fn test_pin_metadata() {
        let meta = PinMetadata {
            cid: "QmTest".to_string(),
            name: Some("test".to_string()),
            tags: HashMap::new(),
            pinned_at: Utc::now(),
            size: Some(1234),
            pin_type: "recursive".to_string(),
        };
        
        assert_eq!(meta.cid, "QmTest");
        assert_eq!(meta.name, Some("test".to_string()));
    }
}
