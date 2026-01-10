//! Payload Map Commit - P1-P2 Mapping Commitment (Bridge Layer)
//!
//! The payload_map_commit is the critical bridge between P1 (L0 consensus layer)
//! and P2 (DSN encrypted storage layer). It provides reconciliation between
//! plaintext commitments in P1 and encrypted payloads in P2.
//!
//! # Module Relationship
//!
//! This module provides **simplified bridge-layer types** for the three-phase sync process.
//! For the **canonical full-featured types**, see `p2_core::types::payload_map`:
//!
//! | Bridge Layer (this module) | P2-Core (canonical) |
//! |---------------------------|---------------------|
//! | `PayloadMapCommit`        | `MapCommit` enum    |
//! | `BatchMapCommit`          | `BatchMapCommit`    |
//! | `SnapshotMapCommit`       | `SnapshotMapCommit` |
//! | (N/A)                     | `ACMapCommit`       |
//! | (N/A)                     | `PayloadMap`        |
//!
//! **When to use which:**
//! - Use bridge types for three-phase sync operations
//! - Use p2-core types for full payload map management and verification
//!
//! # Hard Rule
//!
//! **Missing payload_map_commit MUST result in B-level evidence.**
//! This is a non-negotiable protocol requirement.
//!
//! # Version Fields (Required by DSN Documentation)
//!
//! Per DSN Chapter 3, every payload_map_commit MUST carry version fields:
//! - `canonicalization_version`: Version of the canonicalization algorithm
//! - `signer_set_version`: Version of the signer set used for signatures
//! - `anchor_policy_version`: Version of the anchoring policy
//! - `fee_schedule_version`: Version of the fee schedule
//!
//! **HARD RULE**: UnknownVersion must be rejected for strong verification.
//! Cross-implementation consistency depends on version matching.

use chrono::{DateTime, Utc};
use l0_core::types::Digest;
use p2_core::types::SealedPayloadRef;
use serde::{Deserialize, Serialize};

// Re-export canonical types from p2-core for convenience
pub use p2_core::types::payload_map::{
    ACMapCommit as CanonicalACMapCommit,
    BatchMapCommit as CanonicalBatchMapCommit,
    MapCommit as CanonicalMapCommit,
    MapCommitStatus,
    MapCommitVerifyResult,
    MapCommitVersionInfo,
    PayloadMap,
    PayloadMapEntry,
    PayloadMapEntryStatus,
    SnapshotMapCommit as CanonicalSnapshotMapCommit,
    SnapshotType as CanonicalSnapshotType,
};

/// Protocol version information for cross-implementation consistency
///
/// Per DSN documentation, these versions MUST be included in every commit
/// to ensure consistent verification across different implementations.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProtocolVersions {
    /// Canonicalization algorithm version
    /// Determines how payloads are normalized before hashing
    pub canonicalization_version: String,

    /// Signer set version
    /// Determines which signer set is used for threshold signatures
    pub signer_set_version: String,

    /// Anchor policy version
    /// Determines anchoring rules (to Bitcoin, etc.)
    pub anchor_policy_version: String,

    /// Fee schedule version
    /// Determines fee calculation rules
    pub fee_schedule_version: String,
}

impl ProtocolVersions {
    /// Current protocol versions (v1.0.0)
    pub fn current() -> Self {
        Self {
            canonicalization_version: "1.0.0".to_string(),
            signer_set_version: "1.0.0".to_string(),
            anchor_policy_version: "1.0.0".to_string(),
            fee_schedule_version: "1.0.0".to_string(),
        }
    }

    /// Check if versions are known/supported
    ///
    /// **HARD RULE**: UnknownVersion must be rejected for strong verification.
    pub fn is_known(&self) -> bool {
        // Currently only v1.0.0 is supported
        self.canonicalization_version == "1.0.0"
            && self.signer_set_version == "1.0.0"
            && self.anchor_policy_version == "1.0.0"
            && self.fee_schedule_version == "1.0.0"
    }

    /// Check if canonicalization version is supported
    pub fn canonicalization_supported(&self) -> bool {
        self.canonicalization_version == "1.0.0"
    }

    /// Check if signer set version is supported
    pub fn signer_set_supported(&self) -> bool {
        self.signer_set_version == "1.0.0"
    }

    /// Get unknown version fields
    pub fn unknown_versions(&self) -> Vec<(&'static str, &str)> {
        let mut unknown = Vec::new();
        if self.canonicalization_version != "1.0.0" {
            unknown.push(("canonicalization_version", self.canonicalization_version.as_str()));
        }
        if self.signer_set_version != "1.0.0" {
            unknown.push(("signer_set_version", self.signer_set_version.as_str()));
        }
        if self.anchor_policy_version != "1.0.0" {
            unknown.push(("anchor_policy_version", self.anchor_policy_version.as_str()));
        }
        if self.fee_schedule_version != "1.0.0" {
            unknown.push(("fee_schedule_version", self.fee_schedule_version.as_str()));
        }
        unknown
    }
}

/// Payload Map Commit - P1-P2 mapping commitment
///
/// This is written to P1 (L0 consensus layer) and contains a commitment
/// to the set of sealed payload references stored in P2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadMapCommit {
    /// Commit ID (unique identifier)
    pub commit_id: String,

    /// Commit version (legacy field, use protocol_versions instead)
    pub version: String,

    /// Protocol versions (REQUIRED per DSN documentation)
    /// Contains: canonicalization_version, signer_set_version,
    /// anchor_policy_version, fee_schedule_version
    #[serde(default)]
    pub protocol_versions: ProtocolVersions,

    /// Payload refs set digest (Merkle root of all payload checksums)
    pub refs_set_digest: Digest,

    /// Number of payloads in this commit
    pub payload_count: u64,

    /// Total size of all payloads (bytes)
    pub total_size_bytes: u64,

    /// Commit timestamp
    pub committed_at: DateTime<Utc>,

    /// Committer identifier
    pub committer: String,

    /// Associated batch sequence (for batch-level commits)
    pub batch_sequence: Option<u64>,

    /// Commit type
    pub commit_type: CommitType,

    /// Previous commit reference (for chaining)
    pub prev_commit_ref: Option<String>,

    /// Commit scope
    pub scope: CommitScope,
}

impl PayloadMapCommit {
    /// Create a new payload map commit from sealed payload references
    pub fn from_refs(
        refs: &[SealedPayloadRef],
        committer: &str,
        commit_type: CommitType,
    ) -> Self {
        let refs_digest = Self::compute_refs_digest(refs);
        let total_size: u64 = refs.iter().map(|r| r.size_bytes).sum();
        let commit_id = format!("pmc:{}:{}", Utc::now().timestamp_micros(), uuid::Uuid::new_v4());

        Self {
            commit_id,
            version: "v1".to_string(),
            protocol_versions: ProtocolVersions::current(),
            refs_set_digest: refs_digest,
            payload_count: refs.len() as u64,
            total_size_bytes: total_size,
            committed_at: Utc::now(),
            committer: committer.to_string(),
            batch_sequence: None,
            commit_type,
            prev_commit_ref: None,
            scope: CommitScope::default(),
        }
    }

    /// Create a new payload map commit with specific protocol versions
    pub fn from_refs_with_versions(
        refs: &[SealedPayloadRef],
        committer: &str,
        commit_type: CommitType,
        protocol_versions: ProtocolVersions,
    ) -> Self {
        let mut commit = Self::from_refs(refs, committer, commit_type);
        commit.protocol_versions = protocol_versions;
        commit
    }

    /// Check if the protocol versions are known/supported
    ///
    /// **HARD RULE**: UnknownVersion must be rejected for strong verification.
    pub fn has_known_versions(&self) -> bool {
        self.protocol_versions.is_known()
    }

    /// Get unknown protocol versions (if any)
    pub fn unknown_versions(&self) -> Vec<(&'static str, &str)> {
        self.protocol_versions.unknown_versions()
    }

    /// Compute the refs set digest (Merkle root of payload checksums)
    pub fn compute_refs_digest(refs: &[SealedPayloadRef]) -> Digest {
        if refs.is_empty() {
            return Digest::zero();
        }

        // Sort by ref_id for deterministic ordering
        let mut sorted_refs: Vec<_> = refs.iter().collect();
        sorted_refs.sort_by(|a, b| a.ref_id.cmp(&b.ref_id));

        // Compute Merkle root
        let mut leaves: Vec<Digest> = sorted_refs
            .iter()
            .map(|r| r.checksum.clone())
            .collect();

        // Build Merkle tree by combining pairs of digests
        while leaves.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in leaves.chunks(2) {
                let combined = match chunk {
                    [left, right] => Digest::combine(left, right),
                    [single] => single.clone(),
                    // chunks(2) can only produce slices of length 1 or 2
                    [] => unreachable!("chunks(2) never produces empty slices"),
                    _ => unreachable!("chunks(2) never produces slices longer than 2"),
                };
                next_level.push(combined);
            }
            leaves = next_level;
        }

        leaves.into_iter().next().unwrap_or_else(Digest::zero)
    }

    /// Verify P2 payloads against this commit
    pub fn verify_against_p2(&self, p2_refs: &[SealedPayloadRef]) -> VerifyResult {
        // Check count
        if self.payload_count != p2_refs.len() as u64 {
            return VerifyResult::CountMismatch {
                expected: self.payload_count,
                actual: p2_refs.len() as u64,
            };
        }

        // Check digest
        let actual_digest = Self::compute_refs_digest(p2_refs);
        if self.refs_set_digest != actual_digest {
            return VerifyResult::DigestMismatch {
                expected: self.refs_set_digest.clone(),
                actual: actual_digest,
            };
        }

        // Check for missing payloads (status checks)
        let missing: Vec<String> = p2_refs
            .iter()
            .filter(|r| !r.is_accessible())
            .map(|r| r.ref_id.clone())
            .collect();

        if !missing.is_empty() {
            return VerifyResult::PayloadsMissing { missing_refs: missing };
        }

        VerifyResult::Valid
    }

    /// Set batch sequence
    pub fn with_batch_sequence(mut self, seq: u64) -> Self {
        self.batch_sequence = Some(seq);
        self
    }

    /// Set previous commit reference
    pub fn with_prev_commit(mut self, prev_ref: &str) -> Self {
        self.prev_commit_ref = Some(prev_ref.to_string());
        self
    }

    /// Set scope
    pub fn with_scope(mut self, scope: CommitScope) -> Self {
        self.scope = scope;
        self
    }

    /// Get commit digest (for signing/verification)
    pub fn commit_digest(&self) -> Digest {
        let mut data = Vec::new();
        data.extend_from_slice(self.commit_id.as_bytes());
        data.extend_from_slice(self.refs_set_digest.as_bytes());
        data.extend_from_slice(&self.payload_count.to_le_bytes());
        data.extend_from_slice(self.committed_at.to_rfc3339().as_bytes());
        Digest::blake3(&data)
    }
}

/// Commit type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitType {
    /// Batch-level commit (regular batch processing)
    Batch,
    /// Snapshot-level commit (R0/R1 snapshots)
    Snapshot,
    /// Evidence-level commit (evidence bundles)
    Evidence,
    /// AC-level commit (Actor-Chain specific)
    ActorChain,
    /// Incremental commit (delta from previous)
    Incremental,
}

impl Default for CommitType {
    fn default() -> Self {
        Self::Batch
    }
}

/// Commit scope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitScope {
    /// Scope type
    pub scope_type: ScopeType,
    /// Scope identifier (actor ID, space ID, etc.)
    pub scope_id: Option<String>,
    /// Time window start
    pub window_start: Option<DateTime<Utc>>,
    /// Time window end
    pub window_end: Option<DateTime<Utc>>,
}

impl Default for CommitScope {
    fn default() -> Self {
        Self {
            scope_type: ScopeType::Global,
            scope_id: None,
            window_start: None,
            window_end: None,
        }
    }
}

impl CommitScope {
    /// Create actor-scoped commit
    pub fn actor(actor_id: &str) -> Self {
        Self {
            scope_type: ScopeType::Actor,
            scope_id: Some(actor_id.to_string()),
            ..Default::default()
        }
    }

    /// Create space-scoped commit
    pub fn space(space_id: &str) -> Self {
        Self {
            scope_type: ScopeType::Space,
            scope_id: Some(space_id.to_string()),
            ..Default::default()
        }
    }

    /// Set time window
    pub fn with_window(mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        self.window_start = Some(start);
        self.window_end = Some(end);
        self
    }
}

/// Scope type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeType {
    /// Global scope
    Global,
    /// Actor-specific scope
    Actor,
    /// Space-specific scope
    Space,
    /// Case-specific scope
    Case,
}

/// Verification result
#[derive(Debug, Clone)]
pub enum VerifyResult {
    /// Verification passed
    Valid,
    /// Digest mismatch
    DigestMismatch { expected: Digest, actual: Digest },
    /// Count mismatch
    CountMismatch { expected: u64, actual: u64 },
    /// Some payloads missing or inaccessible
    PayloadsMissing { missing_refs: Vec<String> },
}

impl VerifyResult {
    /// Check if verification passed
    pub fn is_valid(&self) -> bool {
        matches!(self, VerifyResult::Valid)
    }

    /// Convert to evidence level
    ///
    /// Hard rule: Any verification failure results in B-level evidence
    pub fn to_evidence_level(&self) -> l0_core::types::EvidenceLevel {
        match self {
            VerifyResult::Valid => l0_core::types::EvidenceLevel::A,
            _ => l0_core::types::EvidenceLevel::B,
        }
    }
}

/// Batch Map Commit - for regular batch processing
///
/// # Sequence Number Requirements (DSN Documentation)
///
/// Batch sequence numbers MUST be:
/// 1. Strictly increasing (no duplicates, no reversals)
/// 2. Continuous (no gaps - gaps indicate missing batches)
/// 3. Linked via parent_batch_ref to form a chain
///
/// **HARD RULE**: Sequence gaps MUST be detected and flagged.
/// A gap indicates potential data loss or out-of-order processing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchMapCommit {
    /// Base commit
    pub commit: PayloadMapCommit,
    /// Batch sequence number (MUST be strictly increasing)
    pub batch_seq: u64,
    /// Batch window start
    pub window_start: DateTime<Utc>,
    /// Batch window end
    pub window_end: DateTime<Utc>,
    /// Parent batch reference (MUST match previous batch's commit_id)
    pub parent_batch_ref: Option<String>,
    /// Parent batch sequence (for validation)
    pub parent_batch_seq: Option<u64>,
}

impl BatchMapCommit {
    /// Create a new batch map commit
    pub fn new(
        refs: &[SealedPayloadRef],
        committer: &str,
        batch_seq: u64,
        window_start: DateTime<Utc>,
        window_end: DateTime<Utc>,
    ) -> Self {
        let commit = PayloadMapCommit::from_refs(refs, committer, CommitType::Batch)
            .with_batch_sequence(batch_seq)
            .with_scope(CommitScope::default().with_window(window_start, window_end));

        Self {
            commit,
            batch_seq,
            window_start,
            window_end,
            parent_batch_ref: None,
            parent_batch_seq: None,
        }
    }

    /// Set parent batch reference with sequence validation
    pub fn with_parent(mut self, parent_ref: &str, parent_seq: u64) -> Self {
        self.parent_batch_ref = Some(parent_ref.to_string());
        self.parent_batch_seq = Some(parent_seq);
        self.commit = self.commit.with_prev_commit(parent_ref);
        self
    }

    /// Validate sequence against parent
    ///
    /// **HARD RULE**: Sequence must be exactly parent_seq + 1
    pub fn validate_sequence(&self) -> BatchSequenceValidation {
        match self.parent_batch_seq {
            None => {
                // First batch - must be sequence 0 or 1
                if self.batch_seq > 1 {
                    BatchSequenceValidation::GapDetected {
                        expected: 0,
                        actual: self.batch_seq,
                        gap_size: self.batch_seq,
                    }
                } else {
                    BatchSequenceValidation::Valid
                }
            }
            Some(parent_seq) => {
                let expected = parent_seq + 1;
                if self.batch_seq == expected {
                    BatchSequenceValidation::Valid
                } else if self.batch_seq <= parent_seq {
                    BatchSequenceValidation::SequenceReversal {
                        parent_seq,
                        current_seq: self.batch_seq,
                    }
                } else {
                    BatchSequenceValidation::GapDetected {
                        expected,
                        actual: self.batch_seq,
                        gap_size: self.batch_seq - expected,
                    }
                }
            }
        }
    }

    /// Check if this batch follows correctly from a previous batch
    pub fn follows_from(&self, previous: &BatchMapCommit) -> bool {
        // Sequence must be exactly +1
        if self.batch_seq != previous.batch_seq + 1 {
            return false;
        }

        // Parent ref must match previous commit_id
        match &self.parent_batch_ref {
            Some(ref parent_ref) => parent_ref == &previous.commit.commit_id,
            None => false,
        }
    }
}

/// Batch sequence validation result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchSequenceValidation {
    /// Sequence is valid
    Valid,
    /// Gap detected (missing batches)
    GapDetected {
        expected: u64,
        actual: u64,
        gap_size: u64,
    },
    /// Sequence reversal (duplicate or out-of-order)
    SequenceReversal {
        parent_seq: u64,
        current_seq: u64,
    },
    /// Chain broken (parent ref doesn't match)
    ChainBroken {
        expected_parent: String,
        actual_parent: Option<String>,
    },
}

impl BatchSequenceValidation {
    /// Check if validation passed
    pub fn is_valid(&self) -> bool {
        matches!(self, BatchSequenceValidation::Valid)
    }

    /// Get human-readable error message
    pub fn error_message(&self) -> Option<String> {
        match self {
            BatchSequenceValidation::Valid => None,
            BatchSequenceValidation::GapDetected { expected, actual, gap_size } => {
                Some(format!(
                    "Sequence gap detected: expected {}, got {} (gap of {} batches)",
                    expected, actual, gap_size
                ))
            }
            BatchSequenceValidation::SequenceReversal { parent_seq, current_seq } => {
                Some(format!(
                    "Sequence reversal: parent seq {}, but current seq {} (must be greater)",
                    parent_seq, current_seq
                ))
            }
            BatchSequenceValidation::ChainBroken { expected_parent, actual_parent } => {
                Some(format!(
                    "Chain broken: expected parent '{}', got {:?}",
                    expected_parent, actual_parent
                ))
            }
        }
    }
}

/// Batch sequence tracker for validating batch chains
///
/// Tracks all received batches and detects:
/// - Sequence gaps
/// - Duplicate sequences
/// - Out-of-order batches
#[derive(Debug, Default)]
pub struct BatchSequenceTracker {
    /// Last confirmed sequence number
    last_seq: Option<u64>,
    /// Last confirmed batch commit_id
    last_commit_id: Option<String>,
    /// Detected gaps (start_seq, end_seq)
    gaps: Vec<(u64, u64)>,
    /// Out-of-order batches received
    out_of_order: Vec<u64>,
}

impl BatchSequenceTracker {
    /// Create a new tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Create tracker starting from a known sequence
    pub fn from_sequence(last_seq: u64, last_commit_id: String) -> Self {
        Self {
            last_seq: Some(last_seq),
            last_commit_id: Some(last_commit_id),
            gaps: Vec::new(),
            out_of_order: Vec::new(),
        }
    }

    /// Track a new batch and validate its sequence
    pub fn track(&mut self, batch: &BatchMapCommit) -> BatchSequenceValidation {
        let current_seq = batch.batch_seq;

        match self.last_seq {
            None => {
                // First batch
                if current_seq > 1 {
                    // Gap from 0 to current_seq - 1
                    self.gaps.push((0, current_seq - 1));
                }
                self.last_seq = Some(current_seq);
                self.last_commit_id = Some(batch.commit.commit_id.clone());

                if current_seq > 1 {
                    BatchSequenceValidation::GapDetected {
                        expected: 0,
                        actual: current_seq,
                        gap_size: current_seq,
                    }
                } else {
                    BatchSequenceValidation::Valid
                }
            }
            Some(last) => {
                let expected = last + 1;

                if current_seq == expected {
                    // Perfect - sequence is correct
                    // Verify parent chain
                    let chain_valid = match (&batch.parent_batch_ref, &self.last_commit_id) {
                        (Some(parent), Some(last_id)) => parent == last_id,
                        (None, None) => true, // Both none is OK for seq 0->1
                        _ => false,
                    };

                    self.last_seq = Some(current_seq);
                    self.last_commit_id = Some(batch.commit.commit_id.clone());

                    if chain_valid {
                        BatchSequenceValidation::Valid
                    } else {
                        BatchSequenceValidation::ChainBroken {
                            expected_parent: self.last_commit_id.clone().unwrap_or_default(),
                            actual_parent: batch.parent_batch_ref.clone(),
                        }
                    }
                } else if current_seq <= last {
                    // Duplicate or out-of-order
                    self.out_of_order.push(current_seq);
                    BatchSequenceValidation::SequenceReversal {
                        parent_seq: last,
                        current_seq,
                    }
                } else {
                    // Gap detected
                    self.gaps.push((expected, current_seq - 1));
                    self.last_seq = Some(current_seq);
                    self.last_commit_id = Some(batch.commit.commit_id.clone());

                    BatchSequenceValidation::GapDetected {
                        expected,
                        actual: current_seq,
                        gap_size: current_seq - expected,
                    }
                }
            }
        }
    }

    /// Get all detected gaps
    pub fn get_gaps(&self) -> &[(u64, u64)] {
        &self.gaps
    }

    /// Check if there are any gaps
    pub fn has_gaps(&self) -> bool {
        !self.gaps.is_empty()
    }

    /// Get total number of missing batches
    pub fn missing_batch_count(&self) -> u64 {
        self.gaps.iter().map(|(start, end)| end - start + 1).sum()
    }

    /// Get last confirmed sequence
    pub fn last_sequence(&self) -> Option<u64> {
        self.last_seq
    }

    /// Fill a gap (when missing batch is recovered)
    pub fn fill_gap(&mut self, recovered_seq: u64) {
        self.gaps.retain(|(start, end)| {
            !(recovered_seq >= *start && recovered_seq <= *end)
        });
    }
}

/// Snapshot Map Commit - for R0/R1 snapshots
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMapCommit {
    /// Base commit
    pub commit: PayloadMapCommit,
    /// Snapshot ID
    pub snapshot_id: String,
    /// Snapshot type (R0 or R1)
    pub snapshot_type: SnapshotType,
    /// Actor ID
    pub actor_id: String,
}

impl SnapshotMapCommit {
    /// Create a new snapshot map commit
    pub fn new(
        refs: &[SealedPayloadRef],
        committer: &str,
        snapshot_id: &str,
        snapshot_type: SnapshotType,
        actor_id: &str,
    ) -> Self {
        let commit = PayloadMapCommit::from_refs(refs, committer, CommitType::Snapshot)
            .with_scope(CommitScope::actor(actor_id));

        Self {
            commit,
            snapshot_id: snapshot_id.to_string(),
            snapshot_type,
            actor_id: actor_id.to_string(),
        }
    }
}

/// Snapshot type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotType {
    /// R0 skeleton snapshot
    R0Skeleton,
    /// R1 full resurrection snapshot
    R1Full,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_refs(count: usize) -> Vec<SealedPayloadRef> {
        (0..count)
            .map(|i| {
                let checksum = Digest::blake3(format!("payload_{}", i).as_bytes());
                SealedPayloadRef::new(
                    format!("ref:{}", i),
                    checksum,
                    Digest::zero(),
                    100 + i as u64,
                )
            })
            .collect()
    }

    #[test]
    fn test_payload_map_commit_creation() {
        let refs = create_test_refs(5);
        let commit = PayloadMapCommit::from_refs(&refs, "test-committer", CommitType::Batch);

        assert_eq!(commit.payload_count, 5);
        assert!(commit.total_size_bytes > 0);
        assert!(!commit.refs_set_digest.is_zero());
    }

    #[test]
    fn test_verification_valid() {
        let refs = create_test_refs(3);
        let commit = PayloadMapCommit::from_refs(&refs, "test", CommitType::Batch);

        let result = commit.verify_against_p2(&refs);
        assert!(result.is_valid());
        assert_eq!(result.to_evidence_level(), l0_core::types::EvidenceLevel::A);
    }

    #[test]
    fn test_verification_count_mismatch() {
        let refs = create_test_refs(5);
        let commit = PayloadMapCommit::from_refs(&refs, "test", CommitType::Batch);

        let fewer_refs = create_test_refs(3);
        let result = commit.verify_against_p2(&fewer_refs);

        assert!(!result.is_valid());
        assert!(matches!(result, VerifyResult::CountMismatch { .. }));
        assert_eq!(result.to_evidence_level(), l0_core::types::EvidenceLevel::B);
    }

    #[test]
    fn test_verification_digest_mismatch() {
        let refs = create_test_refs(3);
        let commit = PayloadMapCommit::from_refs(&refs, "test", CommitType::Batch);

        // Create different refs with same count
        let different_refs: Vec<SealedPayloadRef> = (0..3)
            .map(|i| {
                let checksum = Digest::blake3(format!("different_{}", i).as_bytes());
                SealedPayloadRef::new(format!("ref:{}", i), checksum, Digest::zero(), 100)
            })
            .collect();

        let result = commit.verify_against_p2(&different_refs);
        assert!(!result.is_valid());
        assert!(matches!(result, VerifyResult::DigestMismatch { .. }));
    }

    #[test]
    fn test_batch_map_commit() {
        let refs = create_test_refs(10);
        let now = Utc::now();
        let batch_commit = BatchMapCommit::new(
            &refs,
            "test",
            1,
            now - chrono::Duration::hours(1),
            now,
        );

        assert_eq!(batch_commit.batch_seq, 1);
        assert_eq!(batch_commit.commit.payload_count, 10);
    }

    #[test]
    fn test_snapshot_map_commit() {
        let refs = create_test_refs(5);
        let snapshot_commit = SnapshotMapCommit::new(
            &refs,
            "test",
            "snapshot:001",
            SnapshotType::R0Skeleton,
            "actor:001",
        );

        assert_eq!(snapshot_commit.snapshot_id, "snapshot:001");
        assert_eq!(snapshot_commit.snapshot_type, SnapshotType::R0Skeleton);
        assert_eq!(snapshot_commit.actor_id, "actor:001");
    }

    #[test]
    fn test_refs_digest_deterministic() {
        let refs = create_test_refs(5);

        let digest1 = PayloadMapCommit::compute_refs_digest(&refs);
        let digest2 = PayloadMapCommit::compute_refs_digest(&refs);

        assert_eq!(digest1, digest2);
    }

    #[test]
    fn test_refs_digest_order_independent() {
        let refs = create_test_refs(5);
        let mut reversed_refs = refs.clone();
        reversed_refs.reverse();

        let digest1 = PayloadMapCommit::compute_refs_digest(&refs);
        let digest2 = PayloadMapCommit::compute_refs_digest(&reversed_refs);

        // Should be equal because we sort by ref_id
        assert_eq!(digest1, digest2);
    }

    #[test]
    fn test_batch_sequence_validation_valid() {
        let refs = create_test_refs(5);
        let now = Utc::now();

        // First batch (seq 0)
        let batch0 = BatchMapCommit::new(&refs, "test", 0, now, now);
        assert!(batch0.validate_sequence().is_valid());

        // Second batch (seq 1) with proper parent
        let batch1 = BatchMapCommit::new(&refs, "test", 1, now, now)
            .with_parent(&batch0.commit.commit_id, 0);
        assert!(batch1.validate_sequence().is_valid());
    }

    #[test]
    fn test_batch_sequence_validation_gap() {
        let refs = create_test_refs(5);
        let now = Utc::now();

        // First batch (seq 0)
        let batch0 = BatchMapCommit::new(&refs, "test", 0, now, now);

        // Third batch (seq 2) - gap of 1
        let batch2 = BatchMapCommit::new(&refs, "test", 2, now, now)
            .with_parent(&batch0.commit.commit_id, 0);

        let validation = batch2.validate_sequence();
        assert!(!validation.is_valid());
        assert!(matches!(validation, BatchSequenceValidation::GapDetected { gap_size: 1, .. }));
    }

    #[test]
    fn test_batch_sequence_validation_reversal() {
        let refs = create_test_refs(5);
        let now = Utc::now();

        // Batch with seq 5 claiming parent seq 10 (reversal)
        let batch = BatchMapCommit::new(&refs, "test", 5, now, now)
            .with_parent("parent", 10);

        let validation = batch.validate_sequence();
        assert!(!validation.is_valid());
        assert!(matches!(validation, BatchSequenceValidation::SequenceReversal { .. }));
    }

    #[test]
    fn test_batch_follows_from() {
        let refs = create_test_refs(5);
        let now = Utc::now();

        let batch0 = BatchMapCommit::new(&refs, "test", 0, now, now);
        let batch1 = BatchMapCommit::new(&refs, "test", 1, now, now)
            .with_parent(&batch0.commit.commit_id, 0);

        assert!(batch1.follows_from(&batch0));

        // Wrong sequence
        let batch_wrong = BatchMapCommit::new(&refs, "test", 3, now, now)
            .with_parent(&batch0.commit.commit_id, 0);
        assert!(!batch_wrong.follows_from(&batch0));
    }

    #[test]
    fn test_batch_sequence_tracker() {
        let refs = create_test_refs(5);
        let now = Utc::now();
        let mut tracker = BatchSequenceTracker::new();

        // Track batch 0
        let batch0 = BatchMapCommit::new(&refs, "test", 0, now, now);
        let result0 = tracker.track(&batch0);
        assert!(result0.is_valid());
        assert!(!tracker.has_gaps());

        // Track batch 1
        let batch1 = BatchMapCommit::new(&refs, "test", 1, now, now)
            .with_parent(&batch0.commit.commit_id, 0);
        let result1 = tracker.track(&batch1);
        assert!(result1.is_valid());
        assert!(!tracker.has_gaps());

        // Track batch 3 (gap!)
        let batch3 = BatchMapCommit::new(&refs, "test", 3, now, now)
            .with_parent(&batch1.commit.commit_id, 1);
        let result3 = tracker.track(&batch3);
        assert!(!result3.is_valid());
        assert!(tracker.has_gaps());
        assert_eq!(tracker.missing_batch_count(), 1);
    }

    #[test]
    fn test_batch_sequence_tracker_out_of_order() {
        let refs = create_test_refs(5);
        let now = Utc::now();
        let mut tracker = BatchSequenceTracker::new();

        // Track batch 0, 1, 2
        let batch0 = BatchMapCommit::new(&refs, "test", 0, now, now);
        tracker.track(&batch0);
        let batch1 = BatchMapCommit::new(&refs, "test", 1, now, now)
            .with_parent(&batch0.commit.commit_id, 0);
        tracker.track(&batch1);
        let batch2 = BatchMapCommit::new(&refs, "test", 2, now, now)
            .with_parent(&batch1.commit.commit_id, 1);
        tracker.track(&batch2);

        // Try to track batch 1 again (out of order/duplicate)
        let duplicate = BatchMapCommit::new(&refs, "test", 1, now, now);
        let result = tracker.track(&duplicate);
        assert!(!result.is_valid());
        assert!(matches!(result, BatchSequenceValidation::SequenceReversal { .. }));
    }
}
