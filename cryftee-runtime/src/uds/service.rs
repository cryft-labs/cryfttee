//! UDS service utilities

use std::time::Duration;

/// Default timeout for UDS connections
pub const UDS_TIMEOUT: Duration = Duration::from_secs(30);

/// UDS connection configuration
#[derive(Debug, Clone)]
pub struct UdsConfig {
    /// Socket path
    pub socket_path: String,
    /// Connection timeout
    pub timeout: Duration,
    /// Maximum concurrent connections
    pub max_connections: usize,
}

impl Default for UdsConfig {
    fn default() -> Self {
        Self {
            socket_path: "/var/run/cryftee.sock".to_string(),
            timeout: UDS_TIMEOUT,
            max_connections: 100,
        }
    }
}

impl UdsConfig {
    /// Create a new UDS config with custom socket path
    pub fn with_path(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
            ..Default::default()
        }
    }
}
