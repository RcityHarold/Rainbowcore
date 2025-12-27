//! Common types used across L0
//!
//! L0 uses fixed 32-byte digests (SHA3-256 or BLAKE3).
//! We provide conversion to/from soulbase_crypto::Digest.

use serde::{Deserialize, Serialize};
use soulbase_crypto::Digester;
use std::fmt;

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

    /// Convert from soulbase_crypto::Digest
    ///
    /// Panics if the source digest is not 32 bytes.
    pub fn from_soulbase(digest: &soulbase_crypto::Digest) -> Self {
        let bytes = digest.as_bytes();
        assert_eq!(bytes.len(), 32, "L0 requires 32-byte digests");
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Self(arr)
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
        Self::from_soulbase(&digest)
    }

    /// Compute SHA256 digest using soulbase_crypto
    pub fn sha256(data: &[u8]) -> Self {
        let digester = soulbase_crypto::DefaultDigester;
        let digest = digester.sha256(data).expect("sha256 should not fail");
        Self::from_soulbase(&digest)
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
