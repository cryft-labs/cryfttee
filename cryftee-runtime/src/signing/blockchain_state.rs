//! Blockchain State for Verified Publishers
//!
//! This module provides a blockchain-based verification system for module publishers.
//! Publishers are registered on-chain and their verification status is checked
//! before allowing module signatures to be trusted.
//!
//! Currently uses a dummy/mock implementation that can be replaced with actual
//! blockchain integration (e.g., reading from an Avalanche P-Chain contract).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use chrono::{DateTime, Utc};
use anyhow::{Result, anyhow};

/// Publisher verification status on-chain
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PublisherStatus {
    /// Publisher is verified and in good standing
    Verified,
    /// Publisher registration is pending
    Pending,
    /// Publisher has been suspended (e.g., malicious activity)
    Suspended,
    /// Publisher has been revoked permanently
    Revoked,
    /// Publisher is not registered on-chain
    Unknown,
}

/// On-chain publisher record
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OnChainPublisher {
    /// Publisher identifier (matches module manifest publisherId)
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Publisher's public key (base64 encoded)
    pub public_key: String,
    /// Signature algorithm
    pub algorithm: String,
    /// Current verification status
    pub status: PublisherStatus,
    /// When the publisher was registered
    pub registered_at: DateTime<Utc>,
    /// When the status was last updated
    pub last_updated: DateTime<Utc>,
    /// Optional: stake amount (for proof-of-stake based trust)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stake_amount: Option<u64>,
    /// Optional: reputation score (0-100)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reputation_score: Option<u32>,
    /// Block number where this record was last updated
    pub block_number: u64,
    /// Transaction hash of last update
    pub tx_hash: String,
}

/// Blockchain state cache for publisher verification
#[derive(Debug)]
pub struct BlockchainState {
    /// Cached publisher records
    publishers: Arc<RwLock<HashMap<String, OnChainPublisher>>>,
    /// Last sync block number
    last_sync_block: Arc<RwLock<u64>>,
    /// RPC endpoint for blockchain queries (for future use)
    rpc_endpoint: Option<String>,
    /// Chain ID we're tracking
    chain_id: String,
}

impl BlockchainState {
    /// Create a new blockchain state with dummy/mock data
    pub fn new_with_dummy_data() -> Self {
        let mut publishers = HashMap::new();
        let now = Utc::now();
        
        // Add dummy verified publishers
        publishers.insert(
            "cryft-labs".to_string(),
            OnChainPublisher {
                id: "cryft-labs".to_string(),
                name: "Cryft Labs Official".to_string(),
                public_key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...".to_string(),
                algorithm: "ed25519".to_string(),
                status: PublisherStatus::Verified,
                registered_at: now - chrono::Duration::days(365),
                last_updated: now - chrono::Duration::hours(1),
                stake_amount: Some(100_000_000_000), // 100 AVAX in nAVAX
                reputation_score: Some(100),
                block_number: 12345678,
                tx_hash: "0xabc123def456789012345678901234567890123456789012345678901234abcd".to_string(),
            },
        );
        
        publishers.insert(
            "cryft-labs-experimental".to_string(),
            OnChainPublisher {
                id: "cryft-labs-experimental".to_string(),
                name: "Cryft Labs Experimental".to_string(),
                public_key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAF...".to_string(),
                algorithm: "ed25519".to_string(),
                status: PublisherStatus::Verified,
                registered_at: now - chrono::Duration::days(180),
                last_updated: now - chrono::Duration::hours(2),
                stake_amount: Some(50_000_000_000), // 50 AVAX
                reputation_score: Some(85),
                block_number: 12345600,
                tx_hash: "0xdef456abc789012345678901234567890123456789012345678901234567efgh".to_string(),
            },
        );
        
        publishers.insert(
            "community-signer".to_string(),
            OnChainPublisher {
                id: "community-signer".to_string(),
                name: "Community Module Signer".to_string(),
                public_key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAG...".to_string(),
                algorithm: "ed25519".to_string(),
                status: PublisherStatus::Pending,
                registered_at: now - chrono::Duration::days(7),
                last_updated: now - chrono::Duration::hours(6),
                stake_amount: Some(10_000_000_000), // 10 AVAX
                reputation_score: None,
                block_number: 12340000,
                tx_hash: "0x123456789abcdef012345678901234567890123456789012345678901234ijkl".to_string(),
            },
        );
        
        publishers.insert(
            "malicious-actor".to_string(),
            OnChainPublisher {
                id: "malicious-actor".to_string(),
                name: "Revoked Publisher".to_string(),
                public_key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAH...".to_string(),
                algorithm: "ed25519".to_string(),
                status: PublisherStatus::Revoked,
                registered_at: now - chrono::Duration::days(30),
                last_updated: now - chrono::Duration::days(5),
                stake_amount: Some(0), // Stake slashed
                reputation_score: Some(0),
                block_number: 12300000,
                tx_hash: "0x789abcdef0123456789012345678901234567890123456789012345678mnop".to_string(),
            },
        );

        Self {
            publishers: Arc::new(RwLock::new(publishers)),
            last_sync_block: Arc::new(RwLock::new(12345678)),
            rpc_endpoint: None,
            chain_id: "cryft-mainnet".to_string(),
        }
    }
    
    /// Create blockchain state with custom RPC endpoint (for future real implementation)
    pub fn new_with_rpc(rpc_endpoint: String, chain_id: String) -> Self {
        Self {
            publishers: Arc::new(RwLock::new(HashMap::new())),
            last_sync_block: Arc::new(RwLock::new(0)),
            rpc_endpoint: Some(rpc_endpoint),
            chain_id,
        }
    }
    
    /// Check if a publisher is verified on-chain
    pub fn is_publisher_verified(&self, publisher_id: &str) -> bool {
        let publishers = self.publishers.read().unwrap();
        publishers
            .get(publisher_id)
            .map(|p| p.status == PublisherStatus::Verified)
            .unwrap_or(false)
    }
    
    /// Get the full status of a publisher
    pub fn get_publisher_status(&self, publisher_id: &str) -> PublisherStatus {
        let publishers = self.publishers.read().unwrap();
        publishers
            .get(publisher_id)
            .map(|p| p.status.clone())
            .unwrap_or(PublisherStatus::Unknown)
    }
    
    /// Get full publisher record
    pub fn get_publisher(&self, publisher_id: &str) -> Option<OnChainPublisher> {
        let publishers = self.publishers.read().unwrap();
        publishers.get(publisher_id).cloned()
    }
    
    /// Get all verified publishers
    pub fn get_verified_publishers(&self) -> Vec<OnChainPublisher> {
        let publishers = self.publishers.read().unwrap();
        publishers
            .values()
            .filter(|p| p.status == PublisherStatus::Verified)
            .cloned()
            .collect()
    }
    
    /// Get all publishers (regardless of status)
    pub fn get_all_publishers(&self) -> Vec<OnChainPublisher> {
        let publishers = self.publishers.read().unwrap();
        publishers.values().cloned().collect()
    }
    
    /// Get the last synced block number
    pub fn get_last_sync_block(&self) -> u64 {
        *self.last_sync_block.read().unwrap()
    }
    
    /// Get chain information
    pub fn get_chain_info(&self) -> ChainInfo {
        ChainInfo {
            chain_id: self.chain_id.clone(),
            last_sync_block: self.get_last_sync_block(),
            rpc_connected: self.rpc_endpoint.is_some(),
            publisher_count: self.publishers.read().unwrap().len(),
            verified_count: self.get_verified_publishers().len(),
        }
    }
    
    /// Verify a publisher can sign modules (must be Verified status)
    pub fn verify_publisher_can_sign(&self, publisher_id: &str) -> Result<OnChainPublisher> {
        let status = self.get_publisher_status(publisher_id);
        
        match status {
            PublisherStatus::Verified => {
                self.get_publisher(publisher_id)
                    .ok_or_else(|| anyhow!("Publisher not found: {}", publisher_id))
            }
            PublisherStatus::Pending => {
                Err(anyhow!("Publisher '{}' is pending verification", publisher_id))
            }
            PublisherStatus::Suspended => {
                Err(anyhow!("Publisher '{}' has been suspended", publisher_id))
            }
            PublisherStatus::Revoked => {
                Err(anyhow!("Publisher '{}' has been revoked", publisher_id))
            }
            PublisherStatus::Unknown => {
                Err(anyhow!("Publisher '{}' is not registered on-chain", publisher_id))
            }
        }
    }
    
    /// Simulate syncing from blockchain (for future real implementation)
    pub async fn sync_from_chain(&self) -> Result<u64> {
        // In a real implementation, this would:
        // 1. Query the blockchain for publisher registry events
        // 2. Update local cache with any new/changed publishers
        // 3. Return the new block number
        
        // For now, just return current block (dummy)
        Ok(self.get_last_sync_block())
    }
    
    /// Add or update a publisher (for testing/admin)
    pub fn upsert_publisher(&self, publisher: OnChainPublisher) {
        let mut publishers = self.publishers.write().unwrap();
        publishers.insert(publisher.id.clone(), publisher);
    }
    
    /// Update publisher status (simulates on-chain governance action)
    pub fn update_publisher_status(&self, publisher_id: &str, new_status: PublisherStatus) -> Result<()> {
        let mut publishers = self.publishers.write().unwrap();
        if let Some(publisher) = publishers.get_mut(publisher_id) {
            publisher.status = new_status;
            publisher.last_updated = Utc::now();
            Ok(())
        } else {
            Err(anyhow!("Publisher not found: {}", publisher_id))
        }
    }
}

/// Chain synchronization info
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainInfo {
    pub chain_id: String,
    pub last_sync_block: u64,
    pub rpc_connected: bool,
    pub publisher_count: usize,
    pub verified_count: usize,
}

/// Global blockchain state singleton
static BLOCKCHAIN_STATE: once_cell::sync::Lazy<BlockchainState> = 
    once_cell::sync::Lazy::new(|| BlockchainState::new_with_dummy_data());

/// Get the global blockchain state instance
pub fn get_blockchain_state() -> &'static BlockchainState {
    &BLOCKCHAIN_STATE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dummy_publishers_loaded() {
        let state = BlockchainState::new_with_dummy_data();
        assert!(state.is_publisher_verified("cryft-labs"));
        assert!(state.is_publisher_verified("cryft-labs-experimental"));
        assert!(!state.is_publisher_verified("unknown-publisher"));
    }

    #[test]
    fn test_publisher_status_check() {
        let state = BlockchainState::new_with_dummy_data();
        
        assert_eq!(state.get_publisher_status("cryft-labs"), PublisherStatus::Verified);
        assert_eq!(state.get_publisher_status("community-signer"), PublisherStatus::Pending);
        assert_eq!(state.get_publisher_status("malicious-actor"), PublisherStatus::Revoked);
        assert_eq!(state.get_publisher_status("nonexistent"), PublisherStatus::Unknown);
    }

    #[test]
    fn test_verify_publisher_can_sign() {
        let state = BlockchainState::new_with_dummy_data();
        
        // Verified publisher should succeed
        assert!(state.verify_publisher_can_sign("cryft-labs").is_ok());
        
        // Pending should fail
        assert!(state.verify_publisher_can_sign("community-signer").is_err());
        
        // Revoked should fail
        assert!(state.verify_publisher_can_sign("malicious-actor").is_err());
        
        // Unknown should fail
        assert!(state.verify_publisher_can_sign("unknown").is_err());
    }

    #[test]
    fn test_get_verified_publishers() {
        let state = BlockchainState::new_with_dummy_data();
        let verified = state.get_verified_publishers();
        
        assert_eq!(verified.len(), 2);
        assert!(verified.iter().all(|p| p.status == PublisherStatus::Verified));
    }
}
