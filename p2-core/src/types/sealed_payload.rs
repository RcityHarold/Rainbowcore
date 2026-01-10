//! Sealed Payload Types
//!
//! P2's fundamental storage unit - encrypted payload references.
//! These are the basic building blocks of the encrypted permanence domain.
//!
//! # Version Requirements (DSN Documentation Chapter 3)
//!
//! Per DSN documentation, sealed_payload_ref requires FOUR elements:
//! - `ref_id`: Reference identifier
//! - `checksum`: Payload checksum
//! - `access_policy_version`: Access policy version
//! - `payload_format_version`: Payload format/encoding version (REQUIRED)
//!
//! **HARD RULE**: UnknownVersion must refuse strong verification.
//! This prevents incorrect interpretation of payload format during decryption.

use chrono::{DateTime, Utc};
use l0_core::types::Digest;
use serde::{Deserialize, Serialize};

/// Payload format version information
///
/// Per DSN documentation, sealed payloads MUST include format version
/// to ensure correct interpretation during decryption and verification.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PayloadFormatVersion {
    /// Payload encoding version (how payload is structured)
    pub encoding_version: String,

    /// Encryption envelope version (how encryption is applied)
    pub envelope_version: String,

    /// Checksum algorithm version
    pub checksum_version: String,
}

impl PayloadFormatVersion {
    /// Current format version
    pub fn current() -> Self {
        Self {
            encoding_version: "1.0.0".to_string(),
            envelope_version: "1.0.0".to_string(),
            checksum_version: "blake3-1.0".to_string(),
        }
    }

    /// Check if format version is known/supported
    ///
    /// **HARD RULE**: UnknownVersion must refuse strong verification.
    pub fn is_known(&self) -> bool {
        self.encoding_version == "1.0.0"
            && self.envelope_version == "1.0.0"
            && self.checksum_version == "blake3-1.0"
    }

    /// Get description of unknown versions (if any)
    pub fn unknown_versions(&self) -> Vec<(&'static str, &str)> {
        let mut unknown = Vec::new();
        if self.encoding_version != "1.0.0" {
            unknown.push(("encoding_version", self.encoding_version.as_str()));
        }
        if self.envelope_version != "1.0.0" {
            unknown.push(("envelope_version", self.envelope_version.as_str()));
        }
        if self.checksum_version != "blake3-1.0" {
            unknown.push(("checksum_version", self.checksum_version.as_str()));
        }
        unknown
    }
}

/// P2 Sealed Payload Reference - P2's basic storage unit
///
/// A sealed payload reference points to an encrypted blob stored in P2.
/// It contains metadata for integrity verification and access control,
/// but never contains the actual encrypted content.
///
/// # Four Required Elements (DSN Documentation)
///
/// 1. `ref_id` - Reference identifier
/// 2. `checksum` - Payload checksum for integrity
/// 3. `access_policy_version` - Access policy version
/// 4. `format_version` - Payload format version (REQUIRED for correct decryption)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedPayloadRef {
    /// Reference identifier (CID/URI/BlobRef - backend agnostic)
    pub ref_id: String,

    /// Payload checksum for integrity verification
    pub checksum: Digest,

    /// Encryption metadata digest (algorithm, key version, etc.)
    pub encryption_meta_digest: Digest,

    /// Access policy version
    pub access_policy_version: String,

    /// Payload format version (REQUIRED per DSN documentation)
    /// Contains: encoding_version, envelope_version, checksum_version
    #[serde(default)]
    pub format_version: PayloadFormatVersion,

    /// Payload size in bytes
    pub size_bytes: u64,

    /// Payload status
    pub status: SealedPayloadStatus,

    /// Storage temperature tier
    pub temperature: StorageTemperature,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Last access timestamp
    pub last_accessed_at: Option<DateTime<Utc>>,

    /// Content type hint (optional)
    pub content_type: Option<String>,

    /// Retention policy reference
    pub retention_policy_ref: Option<String>,
}

impl SealedPayloadRef {
    /// Create a new sealed payload reference
    pub fn new(
        ref_id: String,
        checksum: Digest,
        encryption_meta_digest: Digest,
        size_bytes: u64,
    ) -> Self {
        Self {
            ref_id,
            checksum,
            encryption_meta_digest,
            access_policy_version: "v1".to_string(),
            format_version: PayloadFormatVersion::current(),
            size_bytes,
            status: SealedPayloadStatus::Active,
            temperature: StorageTemperature::Hot,
            created_at: Utc::now(),
            last_accessed_at: None,
            content_type: None,
            retention_policy_ref: None,
        }
    }

    /// Create with specific format version
    pub fn new_with_format(
        ref_id: String,
        checksum: Digest,
        encryption_meta_digest: Digest,
        size_bytes: u64,
        format_version: PayloadFormatVersion,
    ) -> Self {
        let mut payload = Self::new(ref_id, checksum, encryption_meta_digest, size_bytes);
        payload.format_version = format_version;
        payload
    }

    /// Check if the payload is accessible
    pub fn is_accessible(&self) -> bool {
        matches!(self.status, SealedPayloadStatus::Active)
    }

    /// Check if the payload is tombstoned
    pub fn is_tombstoned(&self) -> bool {
        matches!(self.status, SealedPayloadStatus::Tombstoned)
    }

    /// Check if format version is known/supported
    ///
    /// **HARD RULE**: UnknownVersion must refuse strong verification.
    pub fn has_known_format(&self) -> bool {
        self.format_version.is_known()
    }

    /// Get unknown format versions (if any)
    pub fn unknown_format_versions(&self) -> Vec<(&'static str, &str)> {
        self.format_version.unknown_versions()
    }

    /// Check if payload can be verified with strong guarantees
    ///
    /// Strong verification requires:
    /// 1. Known format version
    /// 2. Payload is accessible
    pub fn can_strong_verify(&self) -> bool {
        self.has_known_format() && self.is_accessible()
    }

    /// Update last accessed timestamp
    pub fn touch(&mut self) {
        self.last_accessed_at = Some(Utc::now());
    }

    /// Mark as tombstoned (right to be forgotten)
    pub fn tombstone(&mut self) {
        self.status = SealedPayloadStatus::Tombstoned;
    }

    /// Set temperature tier
    pub fn set_temperature(&mut self, temp: StorageTemperature) {
        self.temperature = temp;
    }
}

/// Sealed Payload Status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealedPayloadStatus {
    /// Active and accessible
    Active,
    /// Tombstoned (right to be forgotten - existence proof retained)
    Tombstoned,
    /// Temporarily unavailable (storage failure/migration)
    Unavailable,
    /// Archived (cold storage)
    Archived,
}

impl Default for SealedPayloadStatus {
    fn default() -> Self {
        Self::Active
    }
}

/// Storage Temperature Tier
///
/// Determines storage characteristics and access latency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageTemperature {
    /// Hot storage: low latency, high cost, for active data
    Hot,
    /// Warm storage: medium latency/cost, for recent data
    Warm,
    /// Cold storage: high latency, low cost, for archived data
    Cold,
}

impl Default for StorageTemperature {
    fn default() -> Self {
        Self::Hot
    }
}

impl StorageTemperature {
    /// Get expected access latency description
    pub fn latency_description(&self) -> &'static str {
        match self {
            Self::Hot => "< 100ms",
            Self::Warm => "< 1s",
            Self::Cold => "> 1s (may require preheat)",
        }
    }
}

/// Encryption metadata for sealed payloads
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionMetadata {
    /// Encryption algorithm identifier
    pub algorithm: String,

    /// Key version used for encryption
    pub key_version: String,

    /// Key derivation parameters (if applicable)
    pub kdf_params: Option<String>,

    /// Threshold encryption info (if applicable)
    pub threshold_info: Option<ThresholdEncryptionInfo>,

    /// Initialization vector or nonce (hex encoded)
    pub iv_or_nonce: String,
}

/// Threshold encryption information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdEncryptionInfo {
    /// Minimum shares required to decrypt
    pub threshold: u32,

    /// Total number of shares
    pub total_shares: u32,

    /// Share holder identifiers
    pub share_holders: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sealed_payload_ref_creation() {
        let ref_id = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi".to_string();
        let checksum = Digest::zero();
        let enc_meta = Digest::zero();

        let payload_ref = SealedPayloadRef::new(ref_id.clone(), checksum, enc_meta, 1024);

        assert_eq!(payload_ref.ref_id, ref_id);
        assert_eq!(payload_ref.size_bytes, 1024);
        assert!(payload_ref.is_accessible());
        assert!(!payload_ref.is_tombstoned());
    }

    #[test]
    fn test_tombstone() {
        let mut payload_ref = SealedPayloadRef::new(
            "test".to_string(),
            Digest::zero(),
            Digest::zero(),
            100,
        );

        assert!(payload_ref.is_accessible());
        payload_ref.tombstone();
        assert!(!payload_ref.is_accessible());
        assert!(payload_ref.is_tombstoned());
    }

    #[test]
    fn test_temperature_tiers() {
        assert_eq!(StorageTemperature::Hot.latency_description(), "< 100ms");
        assert_eq!(StorageTemperature::Cold.latency_description(), "> 1s (may require preheat)");
    }
}
