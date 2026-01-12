//! Payload Map Commit Types (Canonical Implementation)
//!
//! This module implements the complete payload_map_commit system as defined
//! in DSN documentation Chapter 3 - 映射承诺体系.
//!
//! # The Three Types of MapCommit
//!
//! Per DSN documentation, there are three distinct commit types:
//! - **BatchMapCommit**: Main path for batch synchronization (主路)
//! - **SnapshotMapCommit**: Minimum guarantee for snapshots (最低保)
//! - **ACMapCommit**: Special case for AC sequence (特例)
//!
//! Use the unified `MapCommit` enum for storage and polymorphic operations.
//!
//! # Module Relationship
//!
//! This is the **canonical implementation** with full features:
//! - `PayloadMap`: Full payload mapping structure
//! - `MapCommit`: Unified enum for all commit types
//! - Verification, integrity checking, etc.
//!
//! The `bridge` crate has simplified types for three-phase sync operations.
//! When in doubt, use this module's types.
//!
//! # HARD INVARIANT
//!
//! **Missing payload_map_commit MUST result in B-level evidence.**
//! This is a non-negotiable protocol requirement.

use chrono::{DateTime, Utc};
use l0_core::types::{ActorId, Digest, ReceiptId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::sealed_payload::SealedPayloadRef;

// ============================================================================
// PayloadMap - The Core Mapping Structure
// ============================================================================

/// PayloadMap - Maps object references to sealed payload references
///
/// This is the fundamental data structure that bridges P1 (causality) and P2 (storage).
/// Each entry maps a logical object reference to its encrypted payload(s) in P2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadMap {
    /// Map ID
    pub map_id: String,
    /// Map version
    pub version: u64,
    /// Object reference to sealed payload mapping
    pub entries: HashMap<String, PayloadMapEntry>,
    /// Total entry count
    pub entry_count: u64,
    /// Map digest (covers all entries)
    pub map_digest: Digest,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Last modified timestamp
    pub modified_at: DateTime<Utc>,
}

/// Single entry in the payload map
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadMapEntry {
    /// Object reference (P1 side)
    pub object_ref: String,
    /// Sealed payload references (P2 side) - can be multiple for sharded objects
    pub sealed_payload_refs: Vec<String>,
    /// Combined checksum of all payloads
    pub combined_checksum: Digest,
    /// Total size across all payloads
    pub total_size_bytes: u64,
    /// Entry status
    pub status: PayloadMapEntryStatus,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Encryption metadata version
    pub encryption_version: String,
}

/// Payload map entry status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadMapEntryStatus {
    /// Active and valid
    Active,
    /// Tombstoned (right to be forgotten)
    Tombstoned,
    /// Pending verification
    Pending,
    /// Migration in progress
    Migrating,
}

impl Default for PayloadMapEntryStatus {
    fn default() -> Self {
        Self::Active
    }
}

impl PayloadMap {
    /// Create a new empty payload map
    pub fn new(map_id: String) -> Self {
        let now = Utc::now();
        Self {
            map_id,
            version: 1,
            entries: HashMap::new(),
            entry_count: 0,
            map_digest: Digest::zero(),
            created_at: now,
            modified_at: now,
        }
    }

    /// Add an entry to the map
    pub fn add_entry(&mut self, entry: PayloadMapEntry) {
        self.entries.insert(entry.object_ref.clone(), entry);
        self.entry_count = self.entries.len() as u64;
        self.modified_at = Utc::now();
        self.version += 1;
        self.recompute_digest();
    }

    /// Get entry by object reference
    pub fn get_entry(&self, object_ref: &str) -> Option<&PayloadMapEntry> {
        self.entries.get(object_ref)
    }

    /// Remove entry (tombstone)
    pub fn tombstone_entry(&mut self, object_ref: &str) -> Option<PayloadMapEntry> {
        if let Some(entry) = self.entries.get_mut(object_ref) {
            entry.status = PayloadMapEntryStatus::Tombstoned;
            let cloned_entry = entry.clone();
            // Drop the mutable borrow before calling recompute_digest
            drop(entry);
            self.modified_at = Utc::now();
            self.version += 1;
            self.recompute_digest();
            Some(cloned_entry)
        } else {
            None
        }
    }

    /// Recompute the map digest
    fn recompute_digest(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.map_id.as_bytes());
        data.extend_from_slice(&self.version.to_le_bytes());

        // Sort keys for deterministic ordering
        let mut keys: Vec<_> = self.entries.keys().collect();
        keys.sort();

        for key in keys {
            if let Some(entry) = self.entries.get(key) {
                data.extend_from_slice(key.as_bytes());
                data.extend_from_slice(entry.combined_checksum.as_bytes());
            }
        }

        self.map_digest = Digest::blake3(&data);
    }

    /// Verify map integrity
    pub fn verify_integrity(&self) -> bool {
        let mut map_copy = self.clone();
        map_copy.recompute_digest();
        map_copy.map_digest == self.map_digest
    }
}

impl PayloadMapEntry {
    /// Create a new entry
    pub fn new(object_ref: String, sealed_payload_refs: Vec<String>, combined_checksum: Digest, total_size_bytes: u64) -> Self {
        Self {
            object_ref,
            sealed_payload_refs,
            combined_checksum,
            total_size_bytes,
            status: PayloadMapEntryStatus::Active,
            created_at: Utc::now(),
            encryption_version: "v1".to_string(),
        }
    }

    /// Create from sealed payload references
    pub fn from_sealed_refs(object_ref: String, refs: &[SealedPayloadRef]) -> Self {
        let sealed_payload_refs: Vec<String> = refs.iter().map(|r| r.ref_id.clone()).collect();
        let total_size: u64 = refs.iter().map(|r| r.size_bytes).sum();

        // Compute combined checksum
        let mut data = Vec::new();
        for r in refs {
            data.extend_from_slice(r.checksum.as_bytes());
        }
        let combined_checksum = Digest::blake3(&data);

        Self::new(object_ref, sealed_payload_refs, combined_checksum, total_size)
    }
}

// ============================================================================
// BatchMapCommit - Main Path (主路)
// ============================================================================

/// BatchMapCommit - Main path for batch synchronization
///
/// This is the primary mechanism for committing payload mappings during
/// regular batch operations. It's used in the three-phase sync process.
///
/// # ISSUE-006: Idempotency and Cutoff Time
///
/// Per DSN documentation:
/// - `idempotency_key`: Prevents duplicate processing of the same commit
/// - `commit_cutoff_time`: Determines if commit is "normal" or "backfill"
///   - If submitted before cutoff: normal commit
///   - If submitted after cutoff: backfill commit (subject to backfill rules)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchMapCommit {
    /// Commit ID
    pub commit_id: String,
    /// Batch reference (links to L0 batch)
    pub batch_ref: String,
    /// Actor ID
    pub actor_id: ActorId,
    /// Payload map snapshot
    pub payload_map: PayloadMap,
    /// Entries added in this batch
    pub added_entries: Vec<String>,
    /// Entries modified in this batch
    pub modified_entries: Vec<String>,
    /// Commit digest
    pub commit_digest: Digest,
    /// Time window start
    pub time_window_start: DateTime<Utc>,
    /// Time window end
    pub time_window_end: DateTime<Utc>,
    /// Committed timestamp
    pub committed_at: DateTime<Utc>,
    /// Associated receipt
    pub receipt_id: Option<ReceiptId>,
    /// Commit status
    pub status: MapCommitStatus,
    /// Version info
    pub version_info: MapCommitVersionInfo,
    /// Idempotency key for duplicate detection (ISSUE-006)
    ///
    /// This key is used to detect and reject duplicate commits.
    /// Format: "{actor_id}:{batch_ref}:{payload_map_digest}"
    #[serde(default)]
    pub idempotency_key: Option<String>,
    /// Commit cutoff time (ISSUE-006)
    ///
    /// The deadline by which this commit should have been submitted.
    /// If submitted after this time, the commit is considered a "backfill"
    /// and subject to additional verification rules.
    #[serde(default)]
    pub commit_cutoff_time: Option<DateTime<Utc>>,
    /// Whether this is a backfill commit
    #[serde(default)]
    pub is_backfill: bool,
}

/// Default cutoff grace period (how long after time_window_end before it's considered backfill)
const DEFAULT_CUTOFF_GRACE_MINUTES: i64 = 30;

impl BatchMapCommit {
    /// Create a new batch map commit
    pub fn new(
        commit_id: String,
        batch_ref: String,
        actor_id: ActorId,
        payload_map: PayloadMap,
        time_window_start: DateTime<Utc>,
        time_window_end: DateTime<Utc>,
    ) -> Self {
        let now = Utc::now();

        // Compute commit digest
        let commit_data = format!(
            "{}:{}:{}:{}:{}",
            commit_id,
            batch_ref,
            actor_id.0,
            payload_map.map_digest.to_hex(),
            now.to_rfc3339()
        );
        let commit_digest = Digest::blake3(commit_data.as_bytes());

        // Generate idempotency key (ISSUE-006)
        let idempotency_key = format!(
            "{}:{}:{}",
            actor_id.0,
            batch_ref,
            payload_map.map_digest.to_hex()
        );

        // Compute cutoff time (ISSUE-006)
        // Default: 30 minutes after time_window_end
        let commit_cutoff_time = time_window_end + chrono::Duration::minutes(DEFAULT_CUTOFF_GRACE_MINUTES);

        // Determine if this is a backfill commit
        let is_backfill = now > commit_cutoff_time;

        Self {
            commit_id,
            batch_ref,
            actor_id,
            payload_map,
            added_entries: Vec::new(),
            modified_entries: Vec::new(),
            commit_digest,
            time_window_start,
            time_window_end,
            committed_at: now,
            receipt_id: None,
            status: MapCommitStatus::Pending,
            version_info: MapCommitVersionInfo::default(),
            idempotency_key: Some(idempotency_key),
            commit_cutoff_time: Some(commit_cutoff_time),
            is_backfill,
        }
    }

    /// Create with custom cutoff time
    pub fn with_cutoff_time(mut self, cutoff_time: DateTime<Utc>) -> Self {
        self.commit_cutoff_time = Some(cutoff_time);
        self.is_backfill = self.committed_at > cutoff_time;
        self
    }

    /// Check if this commit is a duplicate based on idempotency key
    pub fn is_duplicate_of(&self, other: &BatchMapCommit) -> bool {
        match (&self.idempotency_key, &other.idempotency_key) {
            (Some(k1), Some(k2)) => k1 == k2,
            _ => false,
        }
    }

    /// Get the idempotency key or generate one
    pub fn get_or_generate_idempotency_key(&self) -> String {
        self.idempotency_key.clone().unwrap_or_else(|| {
            format!(
                "{}:{}:{}",
                self.actor_id.0,
                self.batch_ref,
                self.payload_map.map_digest.to_hex()
            )
        })
    }

    /// Check if commit was submitted within cutoff time
    pub fn is_within_cutoff(&self) -> bool {
        !self.is_backfill
    }

    /// Get time past cutoff (for backfill commits)
    pub fn time_past_cutoff(&self) -> Option<chrono::Duration> {
        if self.is_backfill {
            self.commit_cutoff_time.map(|cutoff| {
                self.committed_at.signed_duration_since(cutoff)
            })
        } else {
            None
        }
    }

    /// Verify commit integrity
    pub fn verify(&self) -> MapCommitVerifyResult {
        // Check payload map integrity
        if !self.payload_map.verify_integrity() {
            return MapCommitVerifyResult::fail("Payload map integrity check failed");
        }

        // Check commit digest
        let commit_data = format!(
            "{}:{}:{}:{}:{}",
            self.commit_id,
            self.batch_ref,
            self.actor_id.0,
            self.payload_map.map_digest.to_hex(),
            self.committed_at.to_rfc3339()
        );
        let expected_digest = Digest::blake3(commit_data.as_bytes());

        if expected_digest != self.commit_digest {
            return MapCommitVerifyResult::fail("Commit digest mismatch");
        }

        MapCommitVerifyResult::pass()
    }

    /// Check if this commit has a receipt (A-level evidence)
    pub fn has_receipt(&self) -> bool {
        self.receipt_id.is_some()
    }
}

// ============================================================================
// SnapshotMapCommit - Minimum Guarantee (最低保)
// ============================================================================

/// SnapshotMapCommit - Minimum guarantee for R0/R1 snapshots
///
/// This is the fallback mechanism that ensures every snapshot has at least
/// a basic payload mapping commit, even if batch commits are missed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMapCommit {
    /// Commit ID
    pub commit_id: String,
    /// Snapshot reference (R0 or R1)
    pub snapshot_ref: String,
    /// Snapshot type
    pub snapshot_type: SnapshotType,
    /// Actor ID
    pub actor_id: ActorId,
    /// Payload refs digest (not full map, just digest)
    pub payload_refs_digest: Digest,
    /// Entry count in snapshot
    pub entry_count: u64,
    /// Total size of all payloads
    pub total_size_bytes: u64,
    /// Commit digest
    pub commit_digest: Digest,
    /// Committed timestamp
    pub committed_at: DateTime<Utc>,
    /// Associated receipt
    pub receipt_id: Option<ReceiptId>,
    /// Status
    pub status: MapCommitStatus,
    /// Version info
    pub version_info: MapCommitVersionInfo,
}

/// Snapshot type for SnapshotMapCommit
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotType {
    /// R0 Skeleton snapshot
    R0Skeleton,
    /// R1 Full resurrection snapshot
    R1Full,
}

impl SnapshotMapCommit {
    /// Create a new snapshot map commit
    pub fn new(
        commit_id: String,
        snapshot_ref: String,
        snapshot_type: SnapshotType,
        actor_id: ActorId,
        payload_refs_digest: Digest,
        entry_count: u64,
        total_size_bytes: u64,
    ) -> Self {
        let now = Utc::now();

        let commit_data = format!(
            "{}:{}:{:?}:{}:{}",
            commit_id,
            snapshot_ref,
            snapshot_type,
            payload_refs_digest.to_hex(),
            now.to_rfc3339()
        );
        let commit_digest = Digest::blake3(commit_data.as_bytes());

        Self {
            commit_id,
            snapshot_ref,
            snapshot_type,
            actor_id,
            payload_refs_digest,
            entry_count,
            total_size_bytes,
            commit_digest,
            committed_at: now,
            receipt_id: None,
            status: MapCommitStatus::Pending,
            version_info: MapCommitVersionInfo::default(),
        }
    }

    /// Verify commit integrity
    pub fn verify(&self) -> MapCommitVerifyResult {
        let commit_data = format!(
            "{}:{}:{:?}:{}:{}",
            self.commit_id,
            self.snapshot_ref,
            self.snapshot_type,
            self.payload_refs_digest.to_hex(),
            self.committed_at.to_rfc3339()
        );
        let expected_digest = Digest::blake3(commit_data.as_bytes());

        if expected_digest != self.commit_digest {
            return MapCommitVerifyResult::fail("Commit digest mismatch");
        }

        MapCommitVerifyResult::pass()
    }
}

// ============================================================================
// ACMapCommit - Special Case for AC Sequence (特例)
// ============================================================================

/// ACMapCommit - Special case for AC (Append Chain) sequence
///
/// Used for fine-grained mapping in the append chain, where individual
/// operations need their payload mappings tracked separately.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ACMapCommit {
    /// Commit ID
    pub commit_id: String,
    /// AC sequence number
    pub ac_sequence_no: u64,
    /// AC entry reference
    pub ac_entry_ref: String,
    /// Actor ID
    pub actor_id: ActorId,
    /// Single object reference
    pub object_ref: String,
    /// Sealed payload references
    pub sealed_payload_refs: Vec<String>,
    /// Payload checksum
    pub payload_checksum: Digest,
    /// Commit digest
    pub commit_digest: Digest,
    /// Committed timestamp
    pub committed_at: DateTime<Utc>,
    /// Associated receipt
    pub receipt_id: Option<ReceiptId>,
    /// Status
    pub status: MapCommitStatus,
    /// Parent commit reference (for chaining)
    pub parent_commit_ref: Option<String>,
}

impl ACMapCommit {
    /// Create a new AC map commit
    pub fn new(
        commit_id: String,
        ac_sequence_no: u64,
        ac_entry_ref: String,
        actor_id: ActorId,
        object_ref: String,
        sealed_payload_refs: Vec<String>,
        payload_checksum: Digest,
    ) -> Self {
        let now = Utc::now();

        let commit_data = format!(
            "{}:{}:{}:{}:{}",
            commit_id,
            ac_sequence_no,
            object_ref,
            payload_checksum.to_hex(),
            now.to_rfc3339()
        );
        let commit_digest = Digest::blake3(commit_data.as_bytes());

        Self {
            commit_id,
            ac_sequence_no,
            ac_entry_ref,
            actor_id,
            object_ref,
            sealed_payload_refs,
            payload_checksum,
            commit_digest,
            committed_at: now,
            receipt_id: None,
            status: MapCommitStatus::Pending,
            parent_commit_ref: None,
        }
    }

    /// Verify commit integrity
    pub fn verify(&self) -> MapCommitVerifyResult {
        let commit_data = format!(
            "{}:{}:{}:{}:{}",
            self.commit_id,
            self.ac_sequence_no,
            self.object_ref,
            self.payload_checksum.to_hex(),
            self.committed_at.to_rfc3339()
        );
        let expected_digest = Digest::blake3(commit_data.as_bytes());

        if expected_digest != self.commit_digest {
            return MapCommitVerifyResult::fail("Commit digest mismatch");
        }

        MapCommitVerifyResult::pass()
    }
}

// ============================================================================
// Common Types
// ============================================================================

/// Map commit status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MapCommitStatus {
    /// Pending commit
    Pending,
    /// Committed to P1
    Committed,
    /// Receipt obtained (A-level)
    Receipted,
    /// Failed
    Failed,
    /// Superseded by newer commit
    Superseded,
}

impl Default for MapCommitStatus {
    fn default() -> Self {
        Self::Pending
    }
}

/// Version information for map commits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapCommitVersionInfo {
    /// Canonicalization version
    pub canonicalization_version: String,
    /// Encryption version
    pub encryption_version: String,
    /// Protocol version
    pub protocol_version: String,
}

impl Default for MapCommitVersionInfo {
    fn default() -> Self {
        Self {
            canonicalization_version: "v1".to_string(),
            encryption_version: "v1".to_string(),
            protocol_version: "v1".to_string(),
        }
    }
}

/// Map commit verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapCommitVerifyResult {
    /// Verification passed
    pub valid: bool,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Verified at timestamp
    pub verified_at: DateTime<Utc>,
}

impl MapCommitVerifyResult {
    /// Create passing result
    pub fn pass() -> Self {
        Self {
            valid: true,
            error: None,
            verified_at: Utc::now(),
        }
    }

    /// Create failing result
    pub fn fail(error: &str) -> Self {
        Self {
            valid: false,
            error: Some(error.to_string()),
            verified_at: Utc::now(),
        }
    }
}

/// Unified map commit type (for storage and querying)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "commit_type", rename_all = "snake_case")]
pub enum MapCommit {
    /// Batch map commit
    Batch(BatchMapCommit),
    /// Snapshot map commit
    Snapshot(SnapshotMapCommit),
    /// AC map commit
    Ac(ACMapCommit),
}

impl MapCommit {
    /// Get commit ID
    pub fn commit_id(&self) -> &str {
        match self {
            Self::Batch(c) => &c.commit_id,
            Self::Snapshot(c) => &c.commit_id,
            Self::Ac(c) => &c.commit_id,
        }
    }

    /// Get commit digest
    pub fn commit_digest(&self) -> &Digest {
        match self {
            Self::Batch(c) => &c.commit_digest,
            Self::Snapshot(c) => &c.commit_digest,
            Self::Ac(c) => &c.commit_digest,
        }
    }

    /// Get receipt ID
    pub fn receipt_id(&self) -> Option<&ReceiptId> {
        match self {
            Self::Batch(c) => c.receipt_id.as_ref(),
            Self::Snapshot(c) => c.receipt_id.as_ref(),
            Self::Ac(c) => c.receipt_id.as_ref(),
        }
    }

    /// Get status
    pub fn status(&self) -> MapCommitStatus {
        match self {
            Self::Batch(c) => c.status,
            Self::Snapshot(c) => c.status,
            Self::Ac(c) => c.status,
        }
    }

    /// Check if has receipt (A-level evidence requirement)
    pub fn has_receipt(&self) -> bool {
        self.receipt_id().is_some()
    }

    /// Verify the commit
    pub fn verify(&self) -> MapCommitVerifyResult {
        match self {
            Self::Batch(c) => c.verify(),
            Self::Snapshot(c) => c.verify(),
            Self::Ac(c) => c.verify(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_map_entry() {
        let entry = PayloadMapEntry::new(
            "obj:001".to_string(),
            vec!["sealed:001".to_string(), "sealed:002".to_string()],
            Digest::blake3(b"test"),
            1024,
        );

        assert_eq!(entry.object_ref, "obj:001");
        assert_eq!(entry.sealed_payload_refs.len(), 2);
        assert_eq!(entry.status, PayloadMapEntryStatus::Active);
    }

    #[test]
    fn test_payload_map() {
        let mut map = PayloadMap::new("map:001".to_string());

        let entry = PayloadMapEntry::new(
            "obj:001".to_string(),
            vec!["sealed:001".to_string()],
            Digest::blake3(b"test"),
            512,
        );
        map.add_entry(entry);

        assert_eq!(map.entry_count, 1);
        assert!(map.get_entry("obj:001").is_some());
        assert!(map.verify_integrity());
    }

    #[test]
    fn test_batch_map_commit() {
        let map = PayloadMap::new("map:001".to_string());
        let commit = BatchMapCommit::new(
            "commit:001".to_string(),
            "batch:001".to_string(),
            ActorId::new("actor:001"),
            map,
            Utc::now() - chrono::Duration::hours(1),
            Utc::now(),
        );

        assert_eq!(commit.status, MapCommitStatus::Pending);
        assert!(!commit.has_receipt());

        let result = commit.verify();
        assert!(result.valid);
    }

    #[test]
    fn test_snapshot_map_commit() {
        let commit = SnapshotMapCommit::new(
            "commit:002".to_string(),
            "snapshot:r0:001".to_string(),
            SnapshotType::R0Skeleton,
            ActorId::new("actor:001"),
            Digest::blake3(b"payload refs"),
            10,
            10240,
        );

        assert_eq!(commit.snapshot_type, SnapshotType::R0Skeleton);
        let result = commit.verify();
        assert!(result.valid);
    }

    #[test]
    fn test_ac_map_commit() {
        let commit = ACMapCommit::new(
            "commit:003".to_string(),
            100,
            "ac:100".to_string(),
            ActorId::new("actor:001"),
            "obj:001".to_string(),
            vec!["sealed:001".to_string()],
            Digest::blake3(b"payload"),
        );

        assert_eq!(commit.ac_sequence_no, 100);
        let result = commit.verify();
        assert!(result.valid);
    }

    #[test]
    fn test_map_commit_enum() {
        let map = PayloadMap::new("map:001".to_string());
        let batch = BatchMapCommit::new(
            "commit:001".to_string(),
            "batch:001".to_string(),
            ActorId::new("actor:001"),
            map,
            Utc::now(),
            Utc::now(),
        );

        let commit = MapCommit::Batch(batch);
        assert_eq!(commit.commit_id(), "commit:001");
        assert!(!commit.has_receipt());
        assert!(commit.verify().valid);
    }
}
