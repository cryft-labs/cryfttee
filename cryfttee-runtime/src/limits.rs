//! Runtime limits and constants for Power of Ten compliance
//!
//! All bounds must be defined as constants for static verifiability.
//! These limits ensure predictable resource usage and prevent unbounded operations.

/// Maximum BLS message size in bytes (32 KB)
pub const MAX_BLS_MESSAGE_SIZE: usize = 32 * 1024;

/// Maximum TLS digest size in bytes (SHA-512 = 64 bytes)
pub const MAX_TLS_DIGEST_SIZE: usize = 64;

/// Maximum key handle length in characters
pub const MAX_KEY_HANDLE_LEN: usize = 256;

/// Maximum public key hex string length (BLS = 96 hex chars + 0x prefix)
pub const MAX_PUBKEY_HEX_LEN: usize = 200;

/// Maximum module WASM file size in bytes (10 MB)
pub const MAX_WASM_SIZE: usize = 10 * 1024 * 1024;

/// Maximum number of modules in manifest
pub const MAX_MODULES: usize = 100;

/// Maximum concurrent module loads
pub const MAX_CONCURRENT_LOADS: usize = 4;

/// Maximum retry attempts for Web3Signer operations
pub const MAX_WEB3SIGNER_RETRIES: usize = 3;

/// Web3Signer request timeout in seconds
pub const WEB3SIGNER_TIMEOUT_SECS: u64 = 30;

/// Health check interval in seconds
pub const HEALTH_CHECK_INTERVAL_SECS: u64 = 30;

/// Maximum directory depth for recursive operations (prevents stack overflow)
pub const MAX_DIRECTORY_DEPTH: usize = 10;

/// Maximum path length for module files
pub const MAX_PATH_LEN: usize = 4096;

/// Maximum config file size in bytes (1 MB)
pub const MAX_CONFIG_SIZE: usize = 1024 * 1024;

/// Maximum manifest file size in bytes (1 MB)
pub const MAX_MANIFEST_SIZE: usize = 1024 * 1024;

/// Maximum number of keys returned from Web3Signer
pub const MAX_KEYS_RETURNED: usize = 1000;

/// Maximum signature size in bytes (BLS = 96 bytes)
pub const MAX_SIGNATURE_SIZE: usize = 192;

/// Maximum certificate chain PEM size in bytes (64 KB)
pub const MAX_CERT_CHAIN_SIZE: usize = 64 * 1024;

/// Request body size limit in bytes (1 MB)
pub const MAX_REQUEST_BODY_SIZE: usize = 1024 * 1024;

/// Maximum node label length
pub const MAX_NODE_LABEL_LEN: usize = 128;

/// Maximum module ID length
pub const MAX_MODULE_ID_LEN: usize = 64;

/// Validate BLS message size
#[inline]
pub fn validate_bls_message_size(size: usize) -> Result<(), &'static str> {
    if size > MAX_BLS_MESSAGE_SIZE {
        Err("BLS message exceeds maximum size")
    } else {
        Ok(())
    }
}

/// Validate TLS digest size
#[inline]
pub fn validate_tls_digest_size(size: usize) -> Result<(), &'static str> {
    if size > MAX_TLS_DIGEST_SIZE {
        Err("TLS digest exceeds maximum size")
    } else if size == 0 {
        Err("TLS digest cannot be empty")
    } else {
        Ok(())
    }
}

/// Validate key handle format
#[inline]
pub fn validate_key_handle(handle: &str) -> Result<(), &'static str> {
    if handle.is_empty() {
        Err("Key handle cannot be empty")
    } else if handle.len() > MAX_KEY_HANDLE_LEN {
        Err("Key handle exceeds maximum length")
    } else {
        Ok(())
    }
}

/// Validate public key hex format
#[inline]
pub fn validate_pubkey_hex(pubkey: &str) -> Result<(), &'static str> {
    if pubkey.is_empty() {
        Err("Public key cannot be empty")
    } else if pubkey.len() > MAX_PUBKEY_HEX_LEN {
        Err("Public key exceeds maximum length")
    } else if !pubkey.starts_with("0x") && !pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
        Err("Public key must be hex-encoded")
    } else {
        Ok(())
    }
}

/// Validate module ID format
#[inline]
pub fn validate_module_id(id: &str) -> Result<(), &'static str> {
    if id.is_empty() {
        Err("Module ID cannot be empty")
    } else if id.len() > MAX_MODULE_ID_LEN {
        Err("Module ID exceeds maximum length")
    } else if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        Err("Module ID contains invalid characters")
    } else {
        Ok(())
    }
}

/// Validate WASM file size
#[inline]
pub fn validate_wasm_size(size: usize) -> Result<(), &'static str> {
    if size > MAX_WASM_SIZE {
        Err("WASM file exceeds maximum size")
    } else if size == 0 {
        Err("WASM file cannot be empty")
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bls_message_validation() {
        assert!(validate_bls_message_size(0).is_ok());
        assert!(validate_bls_message_size(1024).is_ok());
        assert!(validate_bls_message_size(MAX_BLS_MESSAGE_SIZE).is_ok());
        assert!(validate_bls_message_size(MAX_BLS_MESSAGE_SIZE + 1).is_err());
    }

    #[test]
    fn test_tls_digest_validation() {
        assert!(validate_tls_digest_size(0).is_err());
        assert!(validate_tls_digest_size(32).is_ok());
        assert!(validate_tls_digest_size(64).is_ok());
        assert!(validate_tls_digest_size(65).is_err());
    }

    #[test]
    fn test_key_handle_validation() {
        assert!(validate_key_handle("").is_err());
        assert!(validate_key_handle("0x123").is_ok());
        assert!(validate_key_handle(&"x".repeat(MAX_KEY_HANDLE_LEN)).is_ok());
        assert!(validate_key_handle(&"x".repeat(MAX_KEY_HANDLE_LEN + 1)).is_err());
    }

    #[test]
    fn test_module_id_validation() {
        assert!(validate_module_id("").is_err());
        assert!(validate_module_id("bls_tls_signer_v1").is_ok());
        assert!(validate_module_id("module-name").is_ok());
        assert!(validate_module_id("module name").is_err()); // spaces not allowed
        assert!(validate_module_id("module/path").is_err()); // slashes not allowed
    }
}
