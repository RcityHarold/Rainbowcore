//! L0 Protocol Version Configuration
//!
//! Provides version constants and configuration for protocol versioning.
//! These versions are used in batch snapshots, epoch snapshots, and receipts.

use std::sync::OnceLock;

/// Protocol version configuration
#[derive(Debug, Clone)]
pub struct ProtocolVersions {
    /// Canonicalization algorithm version
    pub canonicalization: &'static str,
    /// Fee schedule version
    pub fee_schedule: &'static str,
    /// Anchor policy version
    pub anchor_policy: &'static str,
    /// Signer set version
    pub signer_set: &'static str,
    /// Threshold rule (e.g., "5/9")
    pub threshold_rule: &'static str,
}

impl Default for ProtocolVersions {
    fn default() -> Self {
        Self {
            canonicalization: "v1",
            fee_schedule: "v1",
            anchor_policy: "v1",
            signer_set: "v1",
            threshold_rule: "5/9",
        }
    }
}

/// Global protocol versions instance
static PROTOCOL_VERSIONS: OnceLock<ProtocolVersions> = OnceLock::new();

/// Get the current protocol versions
pub fn protocol_versions() -> &'static ProtocolVersions {
    PROTOCOL_VERSIONS.get_or_init(ProtocolVersions::default)
}

/// Initialize protocol versions with custom configuration
/// Must be called before any access to protocol_versions()
pub fn init_protocol_versions(versions: ProtocolVersions) -> Result<(), &'static str> {
    PROTOCOL_VERSIONS.set(versions).map_err(|_| "Protocol versions already initialized")
}

/// Version string constants for direct use
pub mod versions {
    /// Current canonicalization version
    pub const CANONICALIZATION_VERSION: &str = "v1";
    /// Current fee schedule version
    pub const FEE_SCHEDULE_VERSION: &str = "v1";
    /// Current anchor policy version
    pub const ANCHOR_POLICY_VERSION: &str = "v1";
    /// Current signer set version
    pub const SIGNER_SET_VERSION: &str = "v1";
    /// Default threshold rule
    pub const THRESHOLD_RULE: &str = "5/9";
}

/// Network and protocol configuration constants
pub mod config {
    /// Total number of signers in the signer set
    pub const SIGNER_SET_SIZE: usize = 9;

    /// Threshold for signature aggregation (minimum signers needed)
    pub const SIGNATURE_THRESHOLD: usize = 5;

    /// Default signing session timeout in seconds
    pub const SIGNING_SESSION_TIMEOUT_SECS: u64 = 300;

    /// Maximum number of peers a node can connect to
    pub const MAX_PEERS: usize = 100;

    /// Default batch window size in seconds
    pub const DEFAULT_BATCH_WINDOW_SECS: u64 = 60;

    /// Maximum retry attempts for failed operations
    pub const MAX_RETRY_ATTEMPTS: u32 = 3;

    /// Timeout for network operations in milliseconds
    pub const NETWORK_TIMEOUT_MS: u64 = 30000;

    /// Maximum gap size before forcing backfill (sequence numbers)
    pub const MAX_SEQUENCE_GAP: u64 = 1000;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_versions() {
        let versions = ProtocolVersions::default();
        assert_eq!(versions.canonicalization, "v1");
        assert_eq!(versions.fee_schedule, "v1");
        assert_eq!(versions.anchor_policy, "v1");
        assert_eq!(versions.signer_set, "v1");
        assert_eq!(versions.threshold_rule, "5/9");
    }

    #[test]
    fn test_protocol_versions() {
        let versions = protocol_versions();
        assert_eq!(versions.canonicalization, "v1");
    }
}
