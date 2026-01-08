//! Common types used across L0
//!
//! L0 uses fixed 32-byte digests (SHA3-256 or BLAKE3).
//! We provide conversion to/from soulbase_crypto::Digest.

use serde::{Deserialize, Serialize};
use soulbase_crypto::Digester;
use std::fmt;
use thiserror::Error;

/// Error type for digest operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum DigestError {
    /// Digest has wrong length
    #[error("Invalid digest length: expected {expected} bytes, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    /// Invalid hex string
    #[error("Invalid hex string: {0}")]
    InvalidHex(String),

    /// Digest computation failed
    #[error("Digest computation failed: {0}")]
    ComputationFailed(String),
}

impl From<hex::FromHexError> for DigestError {
    fn from(err: hex::FromHexError) -> Self {
        DigestError::InvalidHex(err.to_string())
    }
}

/// 32-byte fixed-size digest for L0 protocol
///
/// L0 requires fixed-size digests for Merkle trees and commitment chains.
/// This type wraps a 32-byte array and provides conversions to soulbase_crypto::Digest.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct L0Digest(pub [u8; 32]);

impl L0Digest {
    /// Create a new digest from bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create a digest from hex string
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Get the underlying bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Create a zero digest (null marker)
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Check if this is a zero digest
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// Try to convert from soulbase_crypto::Digest
    ///
    /// Returns an error if the source digest is not 32 bytes.
    pub fn try_from_soulbase(digest: &soulbase_crypto::Digest) -> Result<Self, DigestError> {
        let bytes = digest.as_bytes();
        if bytes.len() != 32 {
            return Err(DigestError::InvalidLength {
                expected: 32,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Convert from soulbase_crypto::Digest
    ///
    /// # Panics
    /// Panics if the source digest is not 32 bytes.
    /// Prefer `try_from_soulbase` for fallible conversion.
    #[deprecated(since = "0.2.0", note = "Use try_from_soulbase for fallible conversion")]
    pub fn from_soulbase(digest: &soulbase_crypto::Digest) -> Self {
        Self::try_from_soulbase(digest).expect("L0 requires 32-byte digests")
    }

    /// Convert to soulbase_crypto::Digest (as BLAKE3)
    pub fn to_soulbase(&self) -> soulbase_crypto::Digest {
        soulbase_crypto::Digest {
            algo: "blake3".to_string(),
            size: 32,
            bytes: self.0.to_vec(),
            b64: soulbase_crypto::base64url::encode(&self.0),
        }
    }

    /// Compute BLAKE3 digest using soulbase_crypto
    pub fn blake3(data: &[u8]) -> Self {
        let digester = soulbase_crypto::DefaultDigester;
        let digest = digester.blake3(data).expect("blake3 should not fail");
        // BLAKE3 always produces 32 bytes, so this is safe
        Self::try_from_soulbase(&digest).expect("BLAKE3 produces 32-byte digests")
    }

    /// Compute SHA256 digest using soulbase_crypto
    pub fn sha256(data: &[u8]) -> Self {
        let digester = soulbase_crypto::DefaultDigester;
        let digest = digester.sha256(data).expect("sha256 should not fail");
        // SHA256 always produces 32 bytes, so this is safe
        Self::try_from_soulbase(&digest).expect("SHA256 produces 32-byte digests")
    }

    /// Combine two digests (for Merkle tree internal nodes)
    pub fn combine(left: &Self, right: &Self) -> Self {
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(&left.0);
        combined.extend_from_slice(&right.0);
        Self::blake3(&combined)
    }
}

impl fmt::Debug for L0Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "L0Digest({}...)", &self.to_hex()[..16])
    }
}

impl fmt::Display for L0Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Default for L0Digest {
    fn default() -> Self {
        Self::zero()
    }
}

/// Type alias for backward compatibility
pub type Digest = L0Digest;

/// Evidence level - only A/B allowed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceLevel {
    /// Receipt-backed - can be used for strong verdicts/clawbacks
    A,
    /// Local-only - temporary, needs backfill to upgrade
    B,
}

impl Default for EvidenceLevel {
    fn default() -> Self {
        Self::B
    }
}

/// Batch window for time-based grouping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchWindow {
    pub time_window_start: chrono::DateTime<chrono::Utc>,
    pub time_window_end: chrono::DateTime<chrono::Utc>,
    pub batch_sequence_no: u64,
    pub parent_batch_root: Option<L0Digest>,
}

/// Epoch window for chain anchoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochWindow {
    pub epoch_window_start: chrono::DateTime<chrono::Utc>,
    pub epoch_window_end: chrono::DateTime<chrono::Utc>,
    pub epoch_sequence_no: u64,
    pub parent_epoch_root: Option<L0Digest>,
}

/// Anchoring state for knowledge objects
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchoringState {
    LocalUnconfirmed,
    Anchored,
}

impl Default for AnchoringState {
    fn default() -> Self {
        Self::LocalUnconfirmed
    }
}

/// Protocol version information (per DSN Doc Chapter 5)
///
/// All core objects must carry version information for compatibility
/// checking and upgrade coordination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersionInfo {
    /// Canonicalization version - how objects are serialized
    pub canonicalization_version: String,
    /// Signer set version - which keys are valid
    pub signer_set_version: String,
    /// Anchor policy version - anchoring rules
    pub anchor_policy_version: String,
    /// Fee schedule version - pricing rules
    pub fee_schedule_version: String,
}

impl Default for ProtocolVersionInfo {
    fn default() -> Self {
        Self {
            canonicalization_version: "v1".to_string(),
            signer_set_version: "v1".to_string(),
            anchor_policy_version: "v1".to_string(),
            fee_schedule_version: "v1".to_string(),
        }
    }
}

impl ProtocolVersionInfo {
    /// Create a new version info with all versions set to v1
    pub fn v1() -> Self {
        Self::default()
    }

    /// Create a version info with custom versions
    pub fn new(
        canonicalization: &str,
        signer_set: &str,
        anchor_policy: &str,
        fee_schedule: &str,
    ) -> Self {
        Self {
            canonicalization_version: canonicalization.to_string(),
            signer_set_version: signer_set.to_string(),
            anchor_policy_version: anchor_policy.to_string(),
            fee_schedule_version: fee_schedule.to_string(),
        }
    }

    /// Check if all versions are compatible with another version info
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        // For now, require exact match on canonicalization
        // Other versions can drift within a major version
        self.canonicalization_version == other.canonicalization_version
            && self.major_version(&self.signer_set_version)
                == self.major_version(&other.signer_set_version)
    }

    /// Extract major version number from version string
    fn major_version(&self, version: &str) -> Option<u32> {
        version
            .trim_start_matches('v')
            .split('.')
            .next()
            .and_then(|s| s.parse().ok())
    }

    /// Check if any version field is unknown/unsupported
    pub fn has_unknown_version(&self) -> bool {
        self.canonicalization_version.starts_with("unknown")
            || self.signer_set_version.starts_with("unknown")
            || self.anchor_policy_version.starts_with("unknown")
            || self.fee_schedule_version.starts_with("unknown")
    }

    /// Get combined version digest for quick comparison
    pub fn version_digest(&self) -> Digest {
        let combined = format!(
            "{}:{}:{}:{}",
            self.canonicalization_version,
            self.signer_set_version,
            self.anchor_policy_version,
            self.fee_schedule_version
        );
        Digest::blake3(combined.as_bytes())
    }
}

/// Version drift information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionDrift {
    /// Field with drift
    pub field: VersionField,
    /// Expected version
    pub expected: String,
    /// Actual version
    pub actual: String,
    /// Whether drift is acceptable
    pub acceptable: bool,
}

/// Version fields
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VersionField {
    Canonicalization,
    SignerSet,
    AnchorPolicy,
    FeeSchedule,
}

/// Result of version compatibility check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionCompatibility {
    /// Overall compatibility
    pub compatible: bool,
    /// Detected drifts
    pub drifts: Vec<VersionDrift>,
    /// Recommended action
    pub action: VersionAction,
}

/// Recommended action for version incompatibility
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VersionAction {
    /// Continue normally
    Proceed,
    /// Warn but proceed
    WarnAndProceed,
    /// Upgrade required
    UpgradeRequired,
    /// Reject operation
    Reject,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digest_hex_roundtrip() {
        let original = L0Digest::new([0x42u8; 32]);
        let hex = original.to_hex();
        let parsed = L0Digest::from_hex(&hex).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_digest_zero() {
        let zero = L0Digest::zero();
        assert!(zero.is_zero());

        let non_zero = L0Digest::new([1u8; 32]);
        assert!(!non_zero.is_zero());
    }

    #[test]
    fn test_digest_compute() {
        let data = b"hello world";
        let digest = L0Digest::blake3(data);
        assert!(!digest.is_zero());
        assert_eq!(digest.as_bytes().len(), 32);
    }

    #[test]
    fn test_soulbase_roundtrip() {
        let original = L0Digest::blake3(b"test data");
        let soulbase = original.to_soulbase();
        let back = L0Digest::from_soulbase(&soulbase);
        assert_eq!(original, back);
    }
}
