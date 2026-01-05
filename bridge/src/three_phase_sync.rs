//! Three-Phase Synchronization
//!
//! Implements the three-phase sync protocol:
//! 1. Plain (Local) - Data generated locally
//! 2. Encrypted (DSN) - Data uploaded to P2
//! 3. Committed (L0) - Mapping committed to P1
//!
//! This ensures proper coordination between local state, encrypted storage,
//! and consensus layer commitments.

use chrono::{DateTime, Utc};
use l0_core::types::Digest;
use p2_core::types::SealedPayloadRef;
use p2_storage::{P2StorageBackend, WriteMetadata};
use serde::{Deserialize, Serialize};

use super::l0_client::L0CommitClient;
use super::payload_map_commit::PayloadMapCommit;
use crate::error::{BridgeError, BridgeResult};

/// Three-phase sync state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreePhaseSyncState {
    /// Sync ID
    pub sync_id: String,

    /// Current phase
    pub phase: SyncPhase,

    /// Phase 1: Plain (local) info
    pub plain: Option<PlainPhaseInfo>,

    /// Phase 2: Encrypted (DSN) info
    pub encrypted: Option<EncryptedPhaseInfo>,

    /// Phase 3: Committed (L0) info
    pub committed: Option<CommittedPhaseInfo>,

    /// Start timestamp
    pub started_at: DateTime<Utc>,

    /// Completion timestamp
    pub completed_at: Option<DateTime<Utc>>,

    /// Error message (if failed)
    pub error: Option<String>,

    /// Retry count
    pub retry_count: u32,
}

impl ThreePhaseSyncState {
    /// Create a new sync state
    pub fn new() -> Self {
        Self {
            sync_id: format!("sync:{}", uuid::Uuid::new_v4()),
            phase: SyncPhase::Plain,
            plain: None,
            encrypted: None,
            committed: None,
            started_at: Utc::now(),
            completed_at: None,
            error: None,
            retry_count: 0,
        }
    }

    /// Check if sync is complete
    pub fn is_complete(&self) -> bool {
        matches!(self.phase, SyncPhase::Completed)
    }

    /// Check if sync failed
    pub fn is_failed(&self) -> bool {
        matches!(self.phase, SyncPhase::Failed)
    }

    /// Get duration in milliseconds
    pub fn duration_ms(&self) -> Option<i64> {
        self.completed_at.map(|end| (end - self.started_at).num_milliseconds())
    }
}

impl Default for ThreePhaseSyncState {
    fn default() -> Self {
        Self::new()
    }
}

/// Sync phase
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncPhase {
    /// Phase 1: Plain (local generation)
    Plain,
    /// Phase 2: Encrypted (upload to DSN)
    Encrypted,
    /// Phase 3: Committed (L0 commitment)
    Committed,
    /// Completed successfully
    Completed,
    /// Failed
    Failed,
}

/// Phase 1: Plain (local) information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlainPhaseInfo {
    /// Local data digest
    pub local_digest: Digest,
    /// Local path or identifier
    pub local_path: String,
    /// Size in bytes
    pub size_bytes: u64,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
}

/// Phase 2: Encrypted (DSN) information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPhaseInfo {
    /// Sealed payload reference
    pub sealed_ref: SealedPayloadRef,
    /// Upload timestamp
    pub uploaded_at: DateTime<Utc>,
    /// Backend type used
    pub backend_type: String,
}

/// Phase 3: Committed (L0) information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommittedPhaseInfo {
    /// Payload map commit
    pub map_commit: PayloadMapCommit,
    /// Receipt ID from L0
    pub receipt_id: String,
    /// Commit timestamp
    pub committed_at: DateTime<Utc>,
}

/// Sync metadata
#[derive(Debug, Clone)]
pub struct SyncMetadata {
    /// Local path or identifier
    pub local_path: String,
    /// Committer identifier
    pub committer: String,
    /// Write metadata for storage
    pub write_meta: WriteMetadata,
    /// Content type
    pub content_type: String,
}

impl Default for SyncMetadata {
    fn default() -> Self {
        Self {
            local_path: "".to_string(),
            committer: "default".to_string(),
            write_meta: WriteMetadata::default(),
            content_type: "application/octet-stream".to_string(),
        }
    }
}

/// Three-phase syncer
pub struct ThreePhaseSyncer<S, L> {
    /// Storage backend
    storage: S,
    /// L0 commit client
    l0_client: L,
    /// Syncer ID
    syncer_id: String,
}

impl<S, L> ThreePhaseSyncer<S, L>
where
    S: P2StorageBackend,
    L: L0CommitClient,
{
    /// Create a new three-phase syncer
    pub fn new(storage: S, l0_client: L) -> Self {
        Self {
            storage,
            l0_client,
            syncer_id: format!("syncer:{}", uuid::Uuid::new_v4()),
        }
    }

    /// Execute full three-phase sync
    pub async fn sync(
        &self,
        data: &[u8],
        metadata: SyncMetadata,
    ) -> BridgeResult<ThreePhaseSyncState> {
        let mut state = ThreePhaseSyncState::new();

        // Phase 1: Plain (local)
        state = self.phase_plain(state, data, &metadata).await?;

        // Phase 2: Encrypted (DSN upload)
        state = self.phase_encrypted(state, data, &metadata).await?;

        // Phase 3: Committed (L0)
        state = self.phase_committed(state, &metadata).await?;

        // Mark complete
        state.phase = SyncPhase::Completed;
        state.completed_at = Some(Utc::now());

        Ok(state)
    }

    /// Phase 1: Plain (local generation)
    async fn phase_plain(
        &self,
        mut state: ThreePhaseSyncState,
        data: &[u8],
        metadata: &SyncMetadata,
    ) -> BridgeResult<ThreePhaseSyncState> {
        let local_digest = Digest::blake3(data);

        state.plain = Some(PlainPhaseInfo {
            local_digest,
            local_path: metadata.local_path.clone(),
            size_bytes: data.len() as u64,
            created_at: Utc::now(),
        });

        state.phase = SyncPhase::Encrypted;
        Ok(state)
    }

    /// Phase 2: Encrypted (DSN upload)
    async fn phase_encrypted(
        &self,
        mut state: ThreePhaseSyncState,
        data: &[u8],
        metadata: &SyncMetadata,
    ) -> BridgeResult<ThreePhaseSyncState> {
        let sealed_ref = self
            .storage
            .write(data, metadata.write_meta.clone())
            .await
            .map_err(|e| BridgeError::UploadFailed(e.to_string()))?;

        state.encrypted = Some(EncryptedPhaseInfo {
            sealed_ref,
            uploaded_at: Utc::now(),
            backend_type: self.storage.backend_type().to_string(),
        });

        state.phase = SyncPhase::Committed;
        Ok(state)
    }

    /// Phase 3: Committed (L0)
    async fn phase_committed(
        &self,
        mut state: ThreePhaseSyncState,
        metadata: &SyncMetadata,
    ) -> BridgeResult<ThreePhaseSyncState> {
        let encrypted = state.encrypted.as_ref().ok_or_else(|| {
            BridgeError::InvalidState("Missing encrypted phase info".to_string())
        })?;

        let map_commit = PayloadMapCommit::from_refs(
            &[encrypted.sealed_ref.clone()],
            &metadata.committer,
            super::payload_map_commit::CommitType::Batch,
        );

        let receipt_id = self
            .l0_client
            .submit_commit(&map_commit)
            .await?;

        state.committed = Some(CommittedPhaseInfo {
            map_commit,
            receipt_id: receipt_id.0,
            committed_at: Utc::now(),
        });

        Ok(state)
    }

    /// Resume a failed or incomplete sync
    pub async fn resume(
        &self,
        mut state: ThreePhaseSyncState,
        data: &[u8],
        metadata: &SyncMetadata,
    ) -> BridgeResult<ThreePhaseSyncState> {
        state.retry_count += 1;
        state.error = None;

        match state.phase {
            SyncPhase::Plain => {
                state = self.phase_plain(state, data, metadata).await?;
                state = self.phase_encrypted(state, data, metadata).await?;
                state = self.phase_committed(state, metadata).await?;
            }
            SyncPhase::Encrypted => {
                state = self.phase_encrypted(state, data, metadata).await?;
                state = self.phase_committed(state, metadata).await?;
            }
            SyncPhase::Committed => {
                state = self.phase_committed(state, metadata).await?;
            }
            SyncPhase::Completed => {
                // Already complete
                return Ok(state);
            }
            SyncPhase::Failed => {
                // Retry from beginning - handle inline to avoid recursion
                state.phase = SyncPhase::Plain;
                state = self.phase_plain(state, data, metadata).await?;
                state = self.phase_encrypted(state, data, metadata).await?;
                state = self.phase_committed(state, metadata).await?;
            }
        }

        state.phase = SyncPhase::Completed;
        state.completed_at = Some(Utc::now());
        Ok(state)
    }
}

/// Sync batch - for syncing multiple payloads atomically
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncBatch {
    /// Batch ID
    pub batch_id: String,
    /// Individual sync states
    pub syncs: Vec<ThreePhaseSyncState>,
    /// Overall batch status
    pub status: BatchStatus,
    /// Batch map commit (after all syncs complete)
    pub batch_commit: Option<PayloadMapCommit>,
    /// Start timestamp
    pub started_at: DateTime<Utc>,
    /// Completion timestamp
    pub completed_at: Option<DateTime<Utc>>,
}

/// Batch status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    /// In progress
    InProgress,
    /// Completed successfully
    Completed,
    /// Partially completed (some syncs failed)
    PartiallyCompleted,
    /// Failed
    Failed,
}

impl SyncBatch {
    /// Create a new sync batch
    pub fn new() -> Self {
        Self {
            batch_id: format!("batch:{}", uuid::Uuid::new_v4()),
            syncs: Vec::new(),
            status: BatchStatus::InProgress,
            batch_commit: None,
            started_at: Utc::now(),
            completed_at: None,
        }
    }

    /// Add a sync to the batch
    pub fn add_sync(&mut self, sync: ThreePhaseSyncState) {
        self.syncs.push(sync);
    }

    /// Get count of completed syncs
    pub fn completed_count(&self) -> usize {
        self.syncs.iter().filter(|s| s.is_complete()).count()
    }

    /// Get count of failed syncs
    pub fn failed_count(&self) -> usize {
        self.syncs.iter().filter(|s| s.is_failed()).count()
    }

    /// Finalize the batch
    pub fn finalize(&mut self, committer: &str) {
        let completed = self.completed_count();
        let failed = self.failed_count();
        let total = self.syncs.len();

        if failed == 0 && completed == total {
            self.status = BatchStatus::Completed;
        } else if completed > 0 {
            self.status = BatchStatus::PartiallyCompleted;
        } else {
            self.status = BatchStatus::Failed;
        }

        // Create batch commit from all successful syncs
        let refs: Vec<SealedPayloadRef> = self
            .syncs
            .iter()
            .filter_map(|s| s.encrypted.as_ref().map(|e| e.sealed_ref.clone()))
            .collect();

        if !refs.is_empty() {
            self.batch_commit = Some(PayloadMapCommit::from_refs(
                &refs,
                committer,
                super::payload_map_commit::CommitType::Batch,
            ));
        }

        self.completed_at = Some(Utc::now());
    }
}

impl Default for SyncBatch {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_state_creation() {
        let state = ThreePhaseSyncState::new();
        assert_eq!(state.phase, SyncPhase::Plain);
        assert!(!state.is_complete());
        assert!(!state.is_failed());
    }

    #[test]
    fn test_sync_batch() {
        let mut batch = SyncBatch::new();
        assert_eq!(batch.status, BatchStatus::InProgress);

        let mut sync1 = ThreePhaseSyncState::new();
        sync1.phase = SyncPhase::Completed;
        batch.add_sync(sync1);

        let mut sync2 = ThreePhaseSyncState::new();
        sync2.phase = SyncPhase::Completed;
        batch.add_sync(sync2);

        batch.finalize("test");
        assert_eq!(batch.status, BatchStatus::Completed);
        assert_eq!(batch.completed_count(), 2);
    }

    #[test]
    fn test_sync_phase_serialization() {
        let phase = SyncPhase::Encrypted;
        let json = serde_json::to_string(&phase).unwrap();
        assert_eq!(json, "\"encrypted\"");
    }
}
