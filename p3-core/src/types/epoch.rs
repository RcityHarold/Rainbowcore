//! EconomyEpoch - Settlement Atom
//!
//! Chapter 2: EconomyEpoch is the sole settlement atom and sealing point
//!
//! Hard constraints:
//! - Sole settlement atom: any economic consequence must reference epoch_id
//! - cutoff_ref must be reconcilable to P1 sequence
//! - Version references cannot be rolled back

use super::common::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Economy Epoch (Sealing Point)
///
/// Hard constraints:
/// - Sole settlement atom: any economic consequence must reference epoch_id
/// - cutoff_ref must be reconcilable to P1 sequence
/// - Version references cannot be rolled back
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EconomyEpoch {
    /// Epoch ID (unique identifier)
    pub epoch_id: EpochId,

    /// Epoch window (half-open interval [start, end))
    pub epoch_window: EpochWindow,

    /// Cutoff reference (must be reconcilable to P1 sequence)
    pub cutoff_ref: CutoffRef,

    /// Input commitment (four sets digest)
    pub manifest_digest: ManifestDigest,

    /// Weights version reference
    pub weights_version: WeightsVersionRef,

    /// Policy references set digest
    pub policy_refs_digest: RefDigest,

    /// Canonicalization version
    pub canon_version: CanonVersion,

    /// Creation time
    pub created_at: DateTime<Utc>,
}

impl EconomyEpoch {
    /// Compute the canonical epoch_id from epoch components
    /// epoch_id = "epoch:" + hex(H(canonical(epoch_window + cutoff_ref + weights_version + policy_refs_digest)))[0:16]
    pub fn compute_epoch_id(&self) -> EpochId {
        let canonical_data = self.canonical_epoch_data();
        let digest = P3Digest::blake3(&canonical_data);
        // Use first 16 hex chars (8 bytes) as epoch identifier
        let hex_prefix = &digest.to_hex()[..16];
        EpochId::new(format!("epoch:{}", hex_prefix))
    }

    /// Get canonical byte representation for epoch_id computation
    fn canonical_epoch_data(&self) -> Vec<u8> {
        // Use domain-separated, deterministic serialization
        let mut data = Vec::new();

        // Domain tag
        data.extend_from_slice(b"p3:epoch_id:v1\x00");

        // Epoch window (fixed format: start_timestamp:end_timestamp)
        data.extend_from_slice(&self.epoch_window.start.timestamp().to_be_bytes());
        data.extend_from_slice(&self.epoch_window.end.timestamp().to_be_bytes());

        // Cutoff ref (epoch_root_ref digest or zeros, then batch_sequence_no)
        if let Some(ref root) = self.cutoff_ref.epoch_root_ref {
            data.extend_from_slice(&root.0);
        } else {
            data.extend_from_slice(&[0u8; 32]);
        }
        data.extend_from_slice(&self.cutoff_ref.batch_sequence_no_ref.unwrap_or(0).to_be_bytes());

        // Weights version (version_id + digest)
        let version_bytes = self.weights_version.version_id.as_bytes();
        data.extend_from_slice(&(version_bytes.len() as u32).to_be_bytes());
        data.extend_from_slice(version_bytes);
        data.extend_from_slice(&self.weights_version.weights_digest.0);

        // Policy refs digest
        data.extend_from_slice(&self.policy_refs_digest.0.0);

        // Canon version
        let canon_bytes = self.canon_version.0.as_bytes();
        data.extend_from_slice(&(canon_bytes.len() as u32).to_be_bytes());
        data.extend_from_slice(canon_bytes);

        data
    }

    /// Verify epoch_id consistency (hash-based scheme)
    /// Returns true if the stored epoch_id matches the computed value
    pub fn verify_epoch_id(&self) -> bool {
        let computed = self.compute_epoch_id();
        self.epoch_id == computed
    }

    /// Create a new EconomyEpoch with auto-computed epoch_id
    pub fn new(
        epoch_window: EpochWindow,
        cutoff_ref: CutoffRef,
        manifest_digest: ManifestDigest,
        weights_version: WeightsVersionRef,
        policy_refs_digest: RefDigest,
        canon_version: CanonVersion,
    ) -> Self {
        let mut epoch = Self {
            epoch_id: EpochId::new(""), // Temporary placeholder
            epoch_window,
            cutoff_ref,
            manifest_digest,
            weights_version,
            policy_refs_digest,
            canon_version,
            created_at: chrono::Utc::now(),
        };
        // Compute and set the correct epoch_id
        epoch.epoch_id = epoch.compute_epoch_id();
        epoch
    }
}

/// Epoch window (half-open interval)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochWindow {
    /// Start time (inclusive)
    pub start: DateTime<Utc>,
    /// End time (exclusive)
    pub end: DateTime<Utc>,
}

impl EpochWindow {
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        Self { start, end }
    }

    /// Check if the window is valid (start < end)
    pub fn is_valid(&self) -> bool {
        self.start < self.end
    }

    /// Check if a timestamp is within the window
    pub fn contains(&self, ts: &DateTime<Utc>) -> bool {
        &self.start <= ts && ts < &self.end
    }
}

/// Cutoff reference (P1 sequence anchor)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CutoffRef {
    /// Epoch root reference (recommended)
    pub epoch_root_ref: Option<P3Digest>,
    /// Batch sequence number reference
    pub batch_sequence_no_ref: Option<u64>,
}

impl CutoffRef {
    pub fn new(epoch_root_ref: Option<P3Digest>, batch_sequence_no_ref: Option<u64>) -> Self {
        Self {
            epoch_root_ref,
            batch_sequence_no_ref,
        }
    }

    /// Check if reference is valid (at least one must be set)
    pub fn is_valid(&self) -> bool {
        self.epoch_root_ref.is_some() || self.batch_sequence_no_ref.is_some()
    }
}

/// Manifest digest (four sets)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManifestDigest {
    /// Knowledge events set digest
    pub knowledge_events_set_digest: SetDigest,
    /// Court events set digest
    pub court_events_set_digest: SetDigest,
    /// Policy state set digest
    pub policy_state_set_digest: SetDigest,
    /// Sampling audit set digest
    pub sampling_audit_set_digest: SetDigest,
}

impl ManifestDigest {
    /// Create empty manifest digest
    pub fn empty() -> Self {
        Self {
            knowledge_events_set_digest: SetDigest::empty(),
            court_events_set_digest: SetDigest::empty(),
            policy_state_set_digest: SetDigest::empty(),
            sampling_audit_set_digest: SetDigest::empty(),
        }
    }

    /// Compute combined digest
    pub fn combined_digest(&self) -> P3Digest {
        let mut data = Vec::new();
        data.extend_from_slice(&self.knowledge_events_set_digest.0.0);
        data.extend_from_slice(&self.court_events_set_digest.0.0);
        data.extend_from_slice(&self.policy_state_set_digest.0.0);
        data.extend_from_slice(&self.sampling_audit_set_digest.0.0);
        P3Digest::blake3(&data)
    }

    /// Check if all sets are empty
    pub fn is_empty(&self) -> bool {
        self.knowledge_events_set_digest.is_empty()
            && self.court_events_set_digest.is_empty()
            && self.policy_state_set_digest.is_empty()
            && self.sampling_audit_set_digest.is_empty()
    }
}

/// Weights version reference
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WeightsVersionRef {
    pub version_id: String,
    pub weights_digest: P3Digest,
}

impl WeightsVersionRef {
    pub fn new(version_id: impl Into<String>, weights_digest: P3Digest) -> Self {
        Self {
            version_id: version_id.into(),
            weights_digest,
        }
    }
}

/// Economy Epoch Bundle (zero-plaintext recalculation export)
///
/// Chapter 2: Material package for independent third-party verification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EconomyEpochBundle {
    /// Epoch header
    pub epoch_header: EpochHeader,

    /// Four sets (with reference digests)
    pub manifest_sets: ManifestFourSets,

    /// Key receipt references digest
    pub receipt_refs_digest: RefDigest,

    /// Result root digest
    pub result_root_digest: P3Digest,

    /// Chain anchor link (optional, only enhances non-repudiability)
    pub chain_anchor_link: Option<ChainAnchorLink>,
}

/// Epoch header
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochHeader {
    pub epoch_id: EpochId,
    pub epoch_window: EpochWindow,
    pub cutoff_ref: CutoffRef,
    pub manifest_digest: ManifestDigest,
    pub weights_version: WeightsVersionRef,
    pub policy_refs_digest: RefDigest,
    pub canon_version: CanonVersion,
}

impl From<&EconomyEpoch> for EpochHeader {
    fn from(epoch: &EconomyEpoch) -> Self {
        Self {
            epoch_id: epoch.epoch_id.clone(),
            epoch_window: epoch.epoch_window.clone(),
            cutoff_ref: epoch.cutoff_ref.clone(),
            manifest_digest: epoch.manifest_digest.clone(),
            weights_version: epoch.weights_version.clone(),
            policy_refs_digest: epoch.policy_refs_digest.clone(),
            canon_version: epoch.canon_version.clone(),
        }
    }
}

/// Four sets complete structure
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManifestFourSets {
    /// Knowledge events set
    pub knowledge_events: EventSet,
    /// Court events set
    pub court_events: EventSet,
    /// Policy state set
    pub policy_state: EventSet,
    /// Sampling audit set
    pub sampling_audit: EventSet,
}

impl ManifestFourSets {
    /// Compute manifest digest from four sets
    pub fn compute_manifest_digest(&self) -> ManifestDigest {
        ManifestDigest {
            knowledge_events_set_digest: self.knowledge_events.set_digest.clone(),
            court_events_set_digest: self.court_events.set_digest.clone(),
            policy_state_set_digest: self.policy_state.set_digest.clone(),
            sampling_audit_set_digest: self.sampling_audit.set_digest.clone(),
        }
    }
}

/// Event set
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventSet {
    /// Set digest
    pub set_digest: SetDigest,
    /// References digest
    pub refs_digest: RefDigest,
    /// Object IDs digest
    pub object_ids_digest: RefDigest,
    /// Receipt references digest
    pub receipt_refs_digest: RefDigest,
}

impl EventSet {
    /// Create empty event set
    pub fn empty() -> Self {
        Self {
            set_digest: SetDigest::empty(),
            refs_digest: RefDigest::empty(),
            object_ids_digest: RefDigest::empty(),
            receipt_refs_digest: RefDigest::empty(),
        }
    }
}

/// Chain anchor link
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainAnchorLink {
    pub tx_id: String,
    pub block_number: u64,
    pub chain_type: String,
}

impl ChainAnchorLink {
    pub fn new(tx_id: impl Into<String>, block_number: u64, chain_type: impl Into<String>) -> Self {
        Self {
            tx_id: tx_id.into(),
            block_number,
            chain_type: chain_type.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_window_validation() {
        let now = Utc::now();
        let later = now + chrono::Duration::hours(1);

        let valid_window = EpochWindow::new(now, later);
        assert!(valid_window.is_valid());

        let invalid_window = EpochWindow::new(later, now);
        assert!(!invalid_window.is_valid());
    }

    #[test]
    fn test_manifest_digest_empty() {
        let manifest = ManifestDigest::empty();
        assert!(manifest.is_empty());
    }

    #[test]
    fn test_cutoff_ref_validation() {
        let empty_ref = CutoffRef::new(None, None);
        assert!(!empty_ref.is_valid());

        let valid_ref = CutoffRef::new(Some(P3Digest::zero()), None);
        assert!(valid_ref.is_valid());

        let valid_ref2 = CutoffRef::new(None, Some(100));
        assert!(valid_ref2.is_valid());
    }

    #[test]
    fn test_economy_epoch_new_computes_epoch_id() {
        let now = Utc::now();
        let later = now + chrono::Duration::hours(1);

        let epoch = EconomyEpoch::new(
            EpochWindow::new(now, later),
            CutoffRef::new(Some(P3Digest::zero()), Some(100)),
            ManifestDigest::empty(),
            WeightsVersionRef::new("weights:v1", P3Digest::zero()),
            RefDigest::empty(),
            CanonVersion::v1(),
        );

        // Verify the epoch_id starts with "epoch:"
        assert!(epoch.epoch_id.as_str().starts_with("epoch:"));
        // Verify the epoch_id has the correct format (epoch: + 16 hex chars)
        assert_eq!(epoch.epoch_id.as_str().len(), 6 + 16); // "epoch:" = 6 chars
    }

    #[test]
    fn test_verify_epoch_id_valid() {
        let now = Utc::now();
        let later = now + chrono::Duration::hours(1);

        let epoch = EconomyEpoch::new(
            EpochWindow::new(now, later),
            CutoffRef::new(Some(P3Digest::zero()), Some(100)),
            ManifestDigest::empty(),
            WeightsVersionRef::new("weights:v1", P3Digest::zero()),
            RefDigest::empty(),
            CanonVersion::v1(),
        );

        // A correctly created epoch should verify
        assert!(epoch.verify_epoch_id());
    }

    #[test]
    fn test_verify_epoch_id_invalid_tampered() {
        let now = Utc::now();
        let later = now + chrono::Duration::hours(1);

        let mut epoch = EconomyEpoch::new(
            EpochWindow::new(now, later),
            CutoffRef::new(Some(P3Digest::zero()), Some(100)),
            ManifestDigest::empty(),
            WeightsVersionRef::new("weights:v1", P3Digest::zero()),
            RefDigest::empty(),
            CanonVersion::v1(),
        );

        // Tamper with the epoch_id
        epoch.epoch_id = EpochId::new("epoch:tampered1234567");

        // Should fail verification
        assert!(!epoch.verify_epoch_id());
    }

    #[test]
    fn test_verify_epoch_id_deterministic() {
        let now = chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let later = now + chrono::Duration::hours(1);

        let epoch1 = EconomyEpoch::new(
            EpochWindow::new(now, later),
            CutoffRef::new(Some(P3Digest::zero()), Some(100)),
            ManifestDigest::empty(),
            WeightsVersionRef::new("weights:v1", P3Digest::zero()),
            RefDigest::empty(),
            CanonVersion::v1(),
        );

        let epoch2 = EconomyEpoch::new(
            EpochWindow::new(now, later),
            CutoffRef::new(Some(P3Digest::zero()), Some(100)),
            ManifestDigest::empty(),
            WeightsVersionRef::new("weights:v1", P3Digest::zero()),
            RefDigest::empty(),
            CanonVersion::v1(),
        );

        // Same inputs should produce same epoch_id
        assert_eq!(epoch1.epoch_id, epoch2.epoch_id);
    }

    #[test]
    fn test_verify_epoch_id_different_inputs() {
        let now = chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let later = now + chrono::Duration::hours(1);

        let epoch1 = EconomyEpoch::new(
            EpochWindow::new(now, later),
            CutoffRef::new(Some(P3Digest::zero()), Some(100)),
            ManifestDigest::empty(),
            WeightsVersionRef::new("weights:v1", P3Digest::zero()),
            RefDigest::empty(),
            CanonVersion::v1(),
        );

        let epoch2 = EconomyEpoch::new(
            EpochWindow::new(now, later),
            CutoffRef::new(Some(P3Digest::zero()), Some(200)), // Different batch_sequence
            ManifestDigest::empty(),
            WeightsVersionRef::new("weights:v1", P3Digest::zero()),
            RefDigest::empty(),
            CanonVersion::v1(),
        );

        // Different inputs should produce different epoch_id
        assert_ne!(epoch1.epoch_id, epoch2.epoch_id);
    }
}
