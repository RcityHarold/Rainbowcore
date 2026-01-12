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

// ============================================================================
// Tombstone & Deletion Audit (ISSUE-011)
// ============================================================================

/// Tombstone Marker - Detailed record of payload deletion
///
/// Per DSN documentation Chapter 4, deletion MUST preserve:
/// 1. Existence proof (that the payload existed)
/// 2. Audit trail (who deleted, when, why)
/// 3. Integrity verification (checksum retained)
///
/// The actual encrypted content is erased, but metadata is retained
/// for audit and compliance purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TombstoneMarker {
    /// Original payload reference ID
    pub ref_id: String,

    /// Original checksum (retained for existence proof)
    pub original_checksum: Digest,

    /// Original size (retained for audit)
    pub original_size_bytes: u64,

    /// Tombstone creation timestamp
    pub tombstoned_at: DateTime<Utc>,

    /// Actor who initiated the deletion
    pub deleted_by: String,

    /// Deletion reason
    pub deletion_reason: DeletionReason,

    /// Legal basis for deletion (if applicable)
    pub legal_basis: Option<LegalBasis>,

    /// Crypto-erase status
    pub crypto_erase_status: CryptoEraseStatus,

    /// Associated audit log reference
    pub audit_log_ref: String,

    /// Retention policy that triggered deletion (if applicable)
    pub retention_policy_ref: Option<String>,

    /// Original creation timestamp (retained for audit)
    pub original_created_at: DateTime<Utc>,

    /// Tombstone digest (proves tombstone integrity)
    pub tombstone_digest: Digest,
}

impl TombstoneMarker {
    /// Create a new tombstone marker
    pub fn new(
        ref_id: String,
        original_checksum: Digest,
        original_size_bytes: u64,
        original_created_at: DateTime<Utc>,
        deleted_by: String,
        deletion_reason: DeletionReason,
        audit_log_ref: String,
    ) -> Self {
        let now = Utc::now();
        let tombstone_digest = Self::compute_digest(
            &ref_id,
            &original_checksum,
            &now,
            &deleted_by,
        );

        Self {
            ref_id,
            original_checksum,
            original_size_bytes,
            tombstoned_at: now,
            deleted_by,
            deletion_reason,
            legal_basis: None,
            crypto_erase_status: CryptoEraseStatus::Pending,
            audit_log_ref,
            retention_policy_ref: None,
            original_created_at,
            tombstone_digest,
        }
    }

    /// Compute tombstone digest
    fn compute_digest(
        ref_id: &str,
        original_checksum: &Digest,
        tombstoned_at: &DateTime<Utc>,
        deleted_by: &str,
    ) -> Digest {
        let mut data = Vec::new();
        data.extend_from_slice(b"TOMBSTONE:");
        data.extend_from_slice(ref_id.as_bytes());
        data.extend_from_slice(original_checksum.as_bytes());
        data.extend_from_slice(tombstoned_at.to_rfc3339().as_bytes());
        data.extend_from_slice(deleted_by.as_bytes());
        Digest::blake3(&data)
    }

    /// Verify tombstone integrity
    pub fn verify_integrity(&self) -> bool {
        let computed = Self::compute_digest(
            &self.ref_id,
            &self.original_checksum,
            &self.tombstoned_at,
            &self.deleted_by,
        );
        computed == self.tombstone_digest
    }

    /// Set legal basis for deletion
    pub fn with_legal_basis(mut self, basis: LegalBasis) -> Self {
        self.legal_basis = Some(basis);
        self
    }

    /// Set retention policy reference
    pub fn with_retention_policy(mut self, policy_ref: String) -> Self {
        self.retention_policy_ref = Some(policy_ref);
        self
    }

    /// Mark crypto-erase as complete
    pub fn mark_crypto_erased(&mut self) {
        self.crypto_erase_status = CryptoEraseStatus::Complete;
    }

    /// Mark crypto-erase as failed
    pub fn mark_crypto_erase_failed(&mut self, error: String) {
        self.crypto_erase_status = CryptoEraseStatus::Failed { error };
    }

    /// Check if existence proof is intact
    pub fn has_existence_proof(&self) -> bool {
        !self.original_checksum.is_zero() && self.verify_integrity()
    }
}

/// Deletion reason
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionReason {
    /// User-initiated deletion (right to be forgotten)
    UserRequest,
    /// Retention policy expiration
    RetentionExpired,
    /// Legal compliance requirement
    LegalCompliance,
    /// Admin action
    AdminAction,
    /// Data corruption detected
    DataCorruption,
    /// Storage migration cleanup
    MigrationCleanup,
    /// Other reason with description
    Other(String),
}

/// Legal basis for deletion (GDPR, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegalBasis {
    /// GDPR Article 17 - Right to erasure
    GdprArticle17,
    /// CCPA deletion request
    CcpaRequest,
    /// Court order
    CourtOrder,
    /// Contractual obligation
    ContractualObligation,
    /// Consent withdrawal
    ConsentWithdrawal,
    /// Other legal basis
    Other(String),
}

/// Crypto-erase status
///
/// Per DSN documentation, crypto-erase involves:
/// 1. Destroying all encryption keys for the payload
/// 2. Overwriting encrypted content (if possible)
/// 3. Verifying erasure across all replicas
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CryptoEraseStatus {
    /// Crypto-erase pending
    Pending,
    /// Crypto-erase in progress
    InProgress,
    /// Crypto-erase complete
    Complete,
    /// Crypto-erase failed
    Failed { error: String },
    /// Crypto-erase not applicable (no key to destroy)
    NotApplicable,
}

impl Default for CryptoEraseStatus {
    fn default() -> Self {
        Self::Pending
    }
}

/// Deletion Audit Entry - Part of the deletion audit chain
///
/// Every deletion operation MUST produce an audit entry that is
/// appended to an immutable audit chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletionAuditEntry {
    /// Audit entry ID
    pub entry_id: String,

    /// Previous entry reference (forms chain)
    pub prev_entry_ref: Option<String>,

    /// Target payload reference
    pub payload_ref: String,

    /// Actor who performed deletion
    pub actor: String,

    /// Deletion timestamp
    pub deleted_at: DateTime<Utc>,

    /// Deletion reason
    pub reason: DeletionReason,

    /// Pre-deletion state digest (proves what existed)
    pub pre_state_digest: Digest,

    /// Post-deletion state digest (proves tombstone created)
    pub post_state_digest: Digest,

    /// Associated tombstone marker reference
    pub tombstone_ref: String,

    /// Verification status
    pub verification: DeletionVerification,

    /// Entry digest (integrity proof)
    pub entry_digest: Digest,
}

impl DeletionAuditEntry {
    /// Create a new deletion audit entry
    pub fn new(
        entry_id: String,
        prev_entry_ref: Option<String>,
        payload_ref: String,
        actor: String,
        reason: DeletionReason,
        pre_state_digest: Digest,
        post_state_digest: Digest,
        tombstone_ref: String,
    ) -> Self {
        let now = Utc::now();
        let entry_digest = Self::compute_digest(
            &entry_id,
            prev_entry_ref.as_deref(),
            &payload_ref,
            &actor,
            &now,
            &pre_state_digest,
            &post_state_digest,
        );

        Self {
            entry_id,
            prev_entry_ref,
            payload_ref,
            actor,
            deleted_at: now,
            reason,
            pre_state_digest,
            post_state_digest,
            tombstone_ref,
            verification: DeletionVerification::Pending,
            entry_digest,
        }
    }

    /// Compute entry digest
    fn compute_digest(
        entry_id: &str,
        prev_entry_ref: Option<&str>,
        payload_ref: &str,
        actor: &str,
        deleted_at: &DateTime<Utc>,
        pre_state_digest: &Digest,
        post_state_digest: &Digest,
    ) -> Digest {
        let mut data = Vec::new();
        data.extend_from_slice(b"DEL_AUDIT:");
        data.extend_from_slice(entry_id.as_bytes());
        if let Some(prev) = prev_entry_ref {
            data.extend_from_slice(prev.as_bytes());
        }
        data.extend_from_slice(payload_ref.as_bytes());
        data.extend_from_slice(actor.as_bytes());
        data.extend_from_slice(deleted_at.to_rfc3339().as_bytes());
        data.extend_from_slice(pre_state_digest.as_bytes());
        data.extend_from_slice(post_state_digest.as_bytes());
        Digest::blake3(&data)
    }

    /// Verify entry integrity
    pub fn verify_integrity(&self) -> bool {
        let computed = Self::compute_digest(
            &self.entry_id,
            self.prev_entry_ref.as_deref(),
            &self.payload_ref,
            &self.actor,
            &self.deleted_at,
            &self.pre_state_digest,
            &self.post_state_digest,
        );
        computed == self.entry_digest
    }

    /// Verify chain linkage (checks prev_entry_ref matches)
    pub fn verify_chain(&self, prev_entry: Option<&DeletionAuditEntry>) -> bool {
        match (&self.prev_entry_ref, prev_entry) {
            (None, None) => true, // First entry, no previous
            (Some(ref prev_ref), Some(prev)) => prev_ref == &prev.entry_id,
            _ => false,
        }
    }

    /// Mark verification complete
    pub fn mark_verified(&mut self) {
        self.verification = DeletionVerification::Verified;
    }

    /// Mark verification failed
    pub fn mark_verification_failed(&mut self, reason: String) {
        self.verification = DeletionVerification::Failed { reason };
    }
}

/// Deletion verification status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionVerification {
    /// Verification pending
    Pending,
    /// Verification in progress
    InProgress,
    /// Verified successfully
    Verified,
    /// Verification failed
    Failed { reason: String },
}

impl Default for DeletionVerification {
    fn default() -> Self {
        Self::Pending
    }
}

/// Deletion Audit Chain - Immutable chain of deletion records
///
/// This provides a tamper-evident audit trail for all deletions.
#[derive(Debug, Clone, Default)]
pub struct DeletionAuditChain {
    /// Chain entries
    entries: Vec<DeletionAuditEntry>,
    /// Chain head digest
    head_digest: Option<Digest>,
}

impl DeletionAuditChain {
    /// Create a new empty chain
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an entry to the chain
    pub fn append(&mut self, mut entry: DeletionAuditEntry) -> Result<(), String> {
        // Verify chain linkage
        let prev_entry = self.entries.last();
        if !entry.verify_chain(prev_entry) {
            return Err("Chain linkage verification failed".to_string());
        }

        // Verify entry integrity
        if !entry.verify_integrity() {
            return Err("Entry integrity verification failed".to_string());
        }

        // Update head digest
        self.head_digest = Some(entry.entry_digest.clone());
        self.entries.push(entry);
        Ok(())
    }

    /// Get chain length
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if chain is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get chain head digest
    pub fn head_digest(&self) -> Option<&Digest> {
        self.head_digest.as_ref()
    }

    /// Verify entire chain integrity
    pub fn verify_chain_integrity(&self) -> bool {
        let mut prev_entry: Option<&DeletionAuditEntry> = None;
        for entry in &self.entries {
            if !entry.verify_integrity() {
                return false;
            }
            if !entry.verify_chain(prev_entry) {
                return false;
            }
            prev_entry = Some(entry);
        }
        true
    }

    /// Get entries for a specific payload
    pub fn get_entries_for_payload(&self, payload_ref: &str) -> Vec<&DeletionAuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.payload_ref == payload_ref)
            .collect()
    }
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

    // ========== Tombstone & Deletion Audit Tests (ISSUE-011) ==========

    #[test]
    fn test_tombstone_marker_creation() {
        let marker = TombstoneMarker::new(
            "ref:001".to_string(),
            Digest::blake3(b"original content"),
            1024,
            Utc::now() - chrono::Duration::days(30),
            "admin@example.com".to_string(),
            DeletionReason::UserRequest,
            "audit:001".to_string(),
        );

        assert_eq!(marker.ref_id, "ref:001");
        assert_eq!(marker.original_size_bytes, 1024);
        assert!(marker.verify_integrity());
        assert!(marker.has_existence_proof());
        assert!(matches!(marker.crypto_erase_status, CryptoEraseStatus::Pending));
    }

    #[test]
    fn test_tombstone_marker_with_legal_basis() {
        let marker = TombstoneMarker::new(
            "ref:002".to_string(),
            Digest::blake3(b"content"),
            512,
            Utc::now(),
            "admin".to_string(),
            DeletionReason::LegalCompliance,
            "audit:002".to_string(),
        )
        .with_legal_basis(LegalBasis::GdprArticle17)
        .with_retention_policy("policy:001".to_string());

        assert!(marker.legal_basis.is_some());
        assert!(matches!(marker.legal_basis, Some(LegalBasis::GdprArticle17)));
        assert!(marker.retention_policy_ref.is_some());
    }

    #[test]
    fn test_tombstone_marker_crypto_erase() {
        let mut marker = TombstoneMarker::new(
            "ref:003".to_string(),
            Digest::blake3(b"content"),
            256,
            Utc::now(),
            "admin".to_string(),
            DeletionReason::RetentionExpired,
            "audit:003".to_string(),
        );

        assert!(matches!(marker.crypto_erase_status, CryptoEraseStatus::Pending));

        marker.mark_crypto_erased();
        assert!(matches!(marker.crypto_erase_status, CryptoEraseStatus::Complete));
    }

    #[test]
    fn test_deletion_reason_serialization() {
        let reasons = vec![
            DeletionReason::UserRequest,
            DeletionReason::RetentionExpired,
            DeletionReason::LegalCompliance,
            DeletionReason::AdminAction,
            DeletionReason::Other("custom reason".to_string()),
        ];

        for reason in reasons {
            let json = serde_json::to_string(&reason).unwrap();
            let _: DeletionReason = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_deletion_audit_entry_creation() {
        let entry = DeletionAuditEntry::new(
            "entry:001".to_string(),
            None,
            "ref:001".to_string(),
            "admin".to_string(),
            DeletionReason::UserRequest,
            Digest::blake3(b"pre-state"),
            Digest::blake3(b"post-state"),
            "tombstone:001".to_string(),
        );

        assert_eq!(entry.entry_id, "entry:001");
        assert!(entry.prev_entry_ref.is_none());
        assert!(entry.verify_integrity());
        assert!(matches!(entry.verification, DeletionVerification::Pending));
    }

    #[test]
    fn test_deletion_audit_entry_chain_verification() {
        let entry1 = DeletionAuditEntry::new(
            "entry:001".to_string(),
            None,
            "ref:001".to_string(),
            "admin".to_string(),
            DeletionReason::UserRequest,
            Digest::blake3(b"pre1"),
            Digest::blake3(b"post1"),
            "tombstone:001".to_string(),
        );

        // Entry 2 links to Entry 1
        let entry2 = DeletionAuditEntry::new(
            "entry:002".to_string(),
            Some("entry:001".to_string()),
            "ref:002".to_string(),
            "admin".to_string(),
            DeletionReason::RetentionExpired,
            Digest::blake3(b"pre2"),
            Digest::blake3(b"post2"),
            "tombstone:002".to_string(),
        );

        assert!(entry1.verify_chain(None));
        assert!(entry2.verify_chain(Some(&entry1)));

        // Wrong chain should fail
        let entry_wrong = DeletionAuditEntry::new(
            "entry:003".to_string(),
            Some("entry:999".to_string()), // Wrong prev ref
            "ref:003".to_string(),
            "admin".to_string(),
            DeletionReason::AdminAction,
            Digest::blake3(b"pre3"),
            Digest::blake3(b"post3"),
            "tombstone:003".to_string(),
        );
        assert!(!entry_wrong.verify_chain(Some(&entry1)));
    }

    #[test]
    fn test_deletion_audit_chain() {
        let mut chain = DeletionAuditChain::new();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);

        // Add first entry
        let entry1 = DeletionAuditEntry::new(
            "entry:001".to_string(),
            None,
            "ref:001".to_string(),
            "admin".to_string(),
            DeletionReason::UserRequest,
            Digest::blake3(b"pre1"),
            Digest::blake3(b"post1"),
            "tombstone:001".to_string(),
        );
        assert!(chain.append(entry1).is_ok());
        assert_eq!(chain.len(), 1);

        // Add second entry with correct chain
        let entry2 = DeletionAuditEntry::new(
            "entry:002".to_string(),
            Some("entry:001".to_string()),
            "ref:002".to_string(),
            "admin".to_string(),
            DeletionReason::RetentionExpired,
            Digest::blake3(b"pre2"),
            Digest::blake3(b"post2"),
            "tombstone:002".to_string(),
        );
        assert!(chain.append(entry2).is_ok());
        assert_eq!(chain.len(), 2);

        // Verify chain integrity
        assert!(chain.verify_chain_integrity());

        // Get entries for specific payload
        let entries = chain.get_entries_for_payload("ref:001");
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_deletion_audit_chain_rejects_broken_chain() {
        let mut chain = DeletionAuditChain::new();

        // Add first entry
        let entry1 = DeletionAuditEntry::new(
            "entry:001".to_string(),
            None,
            "ref:001".to_string(),
            "admin".to_string(),
            DeletionReason::UserRequest,
            Digest::blake3(b"pre1"),
            Digest::blake3(b"post1"),
            "tombstone:001".to_string(),
        );
        assert!(chain.append(entry1).is_ok());

        // Try to add entry with wrong prev_entry_ref
        let entry_wrong = DeletionAuditEntry::new(
            "entry:002".to_string(),
            Some("entry:999".to_string()), // Wrong!
            "ref:002".to_string(),
            "admin".to_string(),
            DeletionReason::RetentionExpired,
            Digest::blake3(b"pre2"),
            Digest::blake3(b"post2"),
            "tombstone:002".to_string(),
        );
        assert!(chain.append(entry_wrong).is_err());
        assert_eq!(chain.len(), 1); // Still only 1 entry
    }

    #[test]
    fn test_crypto_erase_status_serialization() {
        let statuses = vec![
            CryptoEraseStatus::Pending,
            CryptoEraseStatus::InProgress,
            CryptoEraseStatus::Complete,
            CryptoEraseStatus::Failed { error: "disk error".to_string() },
            CryptoEraseStatus::NotApplicable,
        ];

        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let _: CryptoEraseStatus = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_legal_basis_variants() {
        let bases = vec![
            LegalBasis::GdprArticle17,
            LegalBasis::CcpaRequest,
            LegalBasis::CourtOrder,
            LegalBasis::ContractualObligation,
            LegalBasis::ConsentWithdrawal,
            LegalBasis::Other("custom basis".to_string()),
        ];

        for basis in bases {
            let json = serde_json::to_string(&basis).unwrap();
            let _: LegalBasis = serde_json::from_str(&json).unwrap();
        }
    }
}
