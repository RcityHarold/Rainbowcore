//! Payload Map Commit - P1-P2 Mapping Commitment
//!
//! The payload_map_commit is the critical bridge between P1 (L0 consensus layer)
//! and P2 (DSN encrypted storage layer). It provides reconciliation between
//! plaintext commitments in P1 and encrypted payloads in P2.
//!
//! # Hard Rule
//!
//! **Missing payload_map_commit MUST result in B-level evidence.**
//! This is a non-negotiable protocol requirement.

use chrono::{DateTime, Utc};
use l0_core::types::Digest;
use p2_core::types::SealedPayloadRef;
use serde::{Deserialize, Serialize};

/// Payload Map Commit - P1-P2 mapping commitment
///
/// This is written to P1 (L0 consensus layer) and contains a commitment
/// to the set of sealed payload references stored in P2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadMapCommit {
    /// Commit ID (unique identifier)
    pub commit_id: String,

    /// Commit version
    pub version: String,

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
    pub fn to_evidence_level(&self) -> p2_core::types::EvidenceLevel {
        match self {
            VerifyResult::Valid => p2_core::types::EvidenceLevel::A,
            _ => p2_core::types::EvidenceLevel::B,
        }
    }
}

/// Batch Map Commit - for regular batch processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchMapCommit {
    /// Base commit
    pub commit: PayloadMapCommit,
    /// Batch sequence number
    pub batch_seq: u64,
    /// Batch window start
    pub window_start: DateTime<Utc>,
    /// Batch window end
    pub window_end: DateTime<Utc>,
    /// Parent batch reference
    pub parent_batch_ref: Option<String>,
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
        }
    }

    /// Set parent batch reference
    pub fn with_parent(mut self, parent_ref: &str) -> Self {
        self.parent_batch_ref = Some(parent_ref.to_string());
        self.commit = self.commit.with_prev_commit(parent_ref);
        self
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
        assert_eq!(result.to_evidence_level(), p2_core::types::EvidenceLevel::A);
    }

    #[test]
    fn test_verification_count_mismatch() {
        let refs = create_test_refs(5);
        let commit = PayloadMapCommit::from_refs(&refs, "test", CommitType::Batch);

        let fewer_refs = create_test_refs(3);
        let result = commit.verify_against_p2(&fewer_refs);

        assert!(!result.is_valid());
        assert!(matches!(result, VerifyResult::CountMismatch { .. }));
        assert_eq!(result.to_evidence_level(), p2_core::types::EvidenceLevel::B);
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
}
