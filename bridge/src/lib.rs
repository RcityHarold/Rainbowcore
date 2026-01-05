//! P1-P2 Bridge Layer
//!
//! The bridge layer provides critical coordination between P1 (L0 consensus layer)
//! and P2 (DSN encrypted storage layer). This is where payload_map_commit
//! reconciliation happens.
//!
//! # Hard Rule
//!
//! **Missing payload_map_commit MUST result in B-level evidence.**
//!
//! This is a non-negotiable protocol requirement that ensures proper chain-of-custody
//! for all evidence materials.
//!
//! # Three-Phase Sync Protocol
//!
//! The bridge implements a three-phase synchronization protocol:
//!
//! 1. **Plain (Local)** - Data generated locally, digest computed
//! 2. **Encrypted (DSN)** - Data encrypted and uploaded to P2
//! 3. **Committed (L0)** - Mapping committed to P1 via payload_map_commit
//!
//! Each phase must complete successfully before the next begins. Failed syncs
//! can be resumed from their last successful phase.
//!
//! # Usage
//!
//! ```ignore
//! use bridge::{ThreePhaseSyncer, SyncMetadata, PayloadMapCommit};
//! use p2_storage::LocalStorageBackend;
//!
//! async fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     let storage = LocalStorageBackend::new("/path/to/storage").await?;
//!     let l0_client = MyL0Client::new();
//!
//!     let syncer = ThreePhaseSyncer::new(storage, l0_client);
//!
//!     let data = b"sensitive payload data";
//!     let metadata = SyncMetadata::default();
//!
//!     let sync_state = syncer.sync(data, metadata).await?;
//!     println!("Sync completed: {}", sync_state.sync_id);
//!
//!     Ok(())
//! }
//! ```

pub mod backfill;
pub mod error;
pub mod evidence_level;
pub mod l0_client;
pub mod payload_map_commit;
pub mod three_phase_sync;

pub use backfill::{
    BackfillBatchResult, BackfillEntry, BackfillExecutor, BackfillLedger, BackfillResult,
    BackfillStats, BackfillStatus, EvidenceUpdater, InMemoryBackfillLedger,
};
pub use error::{BridgeError, BridgeResult};
pub use evidence_level::{
    check_evidence_level, DiscrepancyType, DowngradeReason, EvidenceCheck, EvidenceLevelDeterminer,
    EvidenceLevelResult, ReconciliationChecker, ReconciliationDiscrepancy, ReconciliationResult,
    ReconciliationStatus as EvidenceReconciliationStatus,
};
pub use l0_client::{
    HttpL0Client, L0ClientResult, L0CommitClient, L0HealthStatus, MockL0Client, RetryConfig,
    SubmitCommitRequest, SubmitCommitResponse,
};
pub use payload_map_commit::{
    BatchMapCommit, CommitScope, CommitType, PayloadMapCommit, ScopeType, SnapshotMapCommit,
    SnapshotType, VerifyResult,
};
pub use three_phase_sync::{
    BatchStatus, CommittedPhaseInfo, EncryptedPhaseInfo, PlainPhaseInfo, SyncBatch, SyncMetadata,
    SyncPhase, ThreePhaseSyncState, ThreePhaseSyncer,
};

/// Bridge version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Check if a sync result would produce A-level evidence
pub fn is_a_level_evidence(sync_state: &ThreePhaseSyncState) -> bool {
    sync_state.is_complete()
        && sync_state.committed.is_some()
        && sync_state
            .committed
            .as_ref()
            .map(|c| !c.receipt_id.is_empty())
            .unwrap_or(false)
}

/// Reconciliation status between P1 and P2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconciliationStatus {
    /// Fully reconciled - P1 commit matches P2 payloads
    Reconciled,
    /// Pending - commit exists but not yet verified against P2
    Pending,
    /// Mismatch - P1 commit doesn't match P2 payloads
    Mismatch,
    /// Missing - no P1 commit for P2 payloads
    Missing,
}

impl ReconciliationStatus {
    /// Get evidence level for this reconciliation status
    pub fn evidence_level(&self) -> p2_core::types::EvidenceLevel {
        match self {
            ReconciliationStatus::Reconciled => p2_core::types::EvidenceLevel::A,
            _ => p2_core::types::EvidenceLevel::B,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reconciliation_evidence_levels() {
        assert_eq!(
            ReconciliationStatus::Reconciled.evidence_level(),
            p2_core::types::EvidenceLevel::A
        );
        assert_eq!(
            ReconciliationStatus::Pending.evidence_level(),
            p2_core::types::EvidenceLevel::B
        );
        assert_eq!(
            ReconciliationStatus::Mismatch.evidence_level(),
            p2_core::types::EvidenceLevel::B
        );
        assert_eq!(
            ReconciliationStatus::Missing.evidence_level(),
            p2_core::types::EvidenceLevel::B
        );
    }
}
