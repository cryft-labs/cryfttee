//! CryftTEE Runtime Limits and Constants
//!
//! Power of Ten Compliance - All bounds are statically defined for verifiability.
//!
//! ## Self-Contained Architecture
//!
//! CryftTEE follows a self-contained architecture where:
//! - **This module** defines limits for the core runtime API only
//! - **Each WASM module** declares its own domain-specific limits internally
//! - The runtime does NOT enforce module-specific limits (e.g., BLS message sizes)
//!
//! The runtime's responsibility is:
//! - HTTP request/response size limits
//! - Module loading and management bounds
//! - Configuration file limits
//! - Backend connection parameters
//!
//! Module-specific validation (BLS signatures, TLS digests, etc.) is the
//! responsibility of each module.

// ============================================================================
// HTTP API LIMITS
// ============================================================================

/// Maximum HTTP request body size (1 MB)
pub const MAX_REQUEST_BODY_SIZE: usize = 1024 * 1024;

/// Maximum HTTP response body size (1 MB)
pub const MAX_RESPONSE_BODY_SIZE: usize = 1024 * 1024;

/// Maximum URL path length
pub const MAX_URL_PATH_LEN: usize = 2048;

/// Maximum query string length
pub const MAX_QUERY_STRING_LEN: usize = 4096;

/// Maximum number of HTTP headers
pub const MAX_HTTP_HEADERS: usize = 100;

/// Maximum header value length
pub const MAX_HEADER_VALUE_LEN: usize = 8192;

// ============================================================================
// MODULE MANAGEMENT LIMITS
// ============================================================================

/// Maximum WASM module file size (10 MB)
pub const MAX_WASM_SIZE: usize = 10 * 1024 * 1024;

/// Maximum number of modules in manifest
pub const MAX_MODULES: usize = 100;

/// Maximum concurrent module loads
pub const MAX_CONCURRENT_LOADS: usize = 4;

/// Maximum module ID length
pub const MAX_MODULE_ID_LEN: usize = 64;

/// Maximum module version string length
pub const MAX_MODULE_VERSION_LEN: usize = 32;

/// Maximum module description length
pub const MAX_MODULE_DESCRIPTION_LEN: usize = 1024;

/// Maximum capabilities per module
pub const MAX_CAPABILITIES_PER_MODULE: usize = 20;

// ============================================================================
// CONFIGURATION LIMITS
// ============================================================================

/// Maximum config file size (1 MB)
pub const MAX_CONFIG_SIZE: usize = 1024 * 1024;

/// Maximum manifest file size (1 MB)
pub const MAX_MANIFEST_SIZE: usize = 1024 * 1024;

/// Maximum file path length
pub const MAX_PATH_LEN: usize = 4096;

/// Maximum environment variable value length
pub const MAX_ENV_VALUE_LEN: usize = 32768;

/// Maximum node ID length
pub const MAX_NODE_ID_LEN: usize = 128;

/// Maximum instance name length
pub const MAX_INSTANCE_NAME_LEN: usize = 128;

// ============================================================================
// BACKEND CONNECTION LIMITS
// ============================================================================

/// Web3Signer request timeout (seconds)
pub const WEB3SIGNER_TIMEOUT_SECS: u64 = 30;

/// Web3Signer health check interval (seconds)
pub const HEALTH_CHECK_INTERVAL_SECS: u64 = 30;

/// Maximum retry attempts for backend operations
pub const MAX_BACKEND_RETRIES: usize = 3;

/// Maximum backend URL length
pub const MAX_BACKEND_URL_LEN: usize = 2048;

// ============================================================================
// SECURITY LIMITS
// ============================================================================

/// Maximum hash string length (sha256:64hex = 71 chars)
pub const MAX_HASH_LEN: usize = 128;

/// Maximum signature string length (base64)
pub const MAX_SIGNATURE_B64_LEN: usize = 512;

/// Maximum public key hex length
pub const MAX_PUBKEY_HEX_LEN: usize = 256;

/// Maximum token/secret length
pub const MAX_TOKEN_LEN: usize = 4096;

// ============================================================================
// VALIDATION FUNCTIONS (Core API only)
// ============================================================================

/// Validate HTTP request body size
#[inline]
pub fn validate_request_body_size(size: usize) -> Result<(), &'static str> {
    if size > MAX_REQUEST_BODY_SIZE {
        Err("Request body exceeds maximum size")
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

/// Validate file path
#[inline]
pub fn validate_path(path: &str) -> Result<(), &'static str> {
    if path.is_empty() {
        Err("Path cannot be empty")
    } else if path.len() > MAX_PATH_LEN {
        Err("Path exceeds maximum length")
    } else if path.contains('\0') {
        Err("Path contains null bytes")
    } else {
        Ok(())
    }
}

/// Validate backend URL
#[inline]
pub fn validate_backend_url(url: &str) -> Result<(), &'static str> {
    if url.is_empty() {
        Err("URL cannot be empty")
    } else if url.len() > MAX_BACKEND_URL_LEN {
        Err("URL exceeds maximum length")
    } else if !url.starts_with("http://") && !url.starts_with("https://") {
        Err("URL must use http:// or https://")
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_body_validation() {
        assert!(validate_request_body_size(0).is_ok());
        assert!(validate_request_body_size(1024).is_ok());
        assert!(validate_request_body_size(MAX_REQUEST_BODY_SIZE).is_ok());
        assert!(validate_request_body_size(MAX_REQUEST_BODY_SIZE + 1).is_err());
    }

    #[test]
    fn test_module_id_validation() {
        assert!(validate_module_id("").is_err());
        assert!(validate_module_id("bls_tls_signer_v1").is_ok());
        assert!(validate_module_id("module-name").is_ok());
        assert!(validate_module_id("module name").is_err()); // spaces not allowed
        assert!(validate_module_id("module/path").is_err()); // slashes not allowed
    }

    #[test]
    fn test_wasm_size_validation() {
        assert!(validate_wasm_size(0).is_err());
        assert!(validate_wasm_size(1024).is_ok());
        assert!(validate_wasm_size(MAX_WASM_SIZE).is_ok());
        assert!(validate_wasm_size(MAX_WASM_SIZE + 1).is_err());
    }

    #[test]
    fn test_path_validation() {
        assert!(validate_path("").is_err());
        assert!(validate_path("/valid/path").is_ok());
        assert!(validate_path("relative/path").is_ok());
        assert!(validate_path(&"x".repeat(MAX_PATH_LEN + 1)).is_err());
    }

    #[test]
    fn test_backend_url_validation() {
        assert!(validate_backend_url("").is_err());
        assert!(validate_backend_url("http://localhost:9000").is_ok());
        assert!(validate_backend_url("https://example.com").is_ok());
        assert!(validate_backend_url("ftp://invalid").is_err());
        assert!(validate_backend_url("not-a-url").is_err());
    }
}
