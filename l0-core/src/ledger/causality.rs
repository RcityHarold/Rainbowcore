//! Causality Ledger - Commitment ordering and parent chains
//!
//! The Causality Ledger tracks:
//! - Commitment ordering (happened-before relationships)
//! - Parent chain references
//! - Batch roots and epoch roots
//! - Cross-reference integrity

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use crate::types::{
    Digest, ReceiptId, ActorId, L0Receipt, ScopeType,
    SignedBatchSnapshot, EpochSnapshot,
};
use super::{Ledger, LedgerResult, QueryOptions};

/// Commitment record in the causality chain
#[derive(Debug, Clone)]
pub struct CommitmentRecord {
    pub commitment_id: String,
    pub actor_id: ActorId,
    pub scope_type: ScopeType,
    pub commitment_digest: Digest,
    pub parent_commitment_ref: Option<String>,
    pub sequence_no: u64,
    pub created_at: DateTime<Utc>,
    pub receipt_id: Option<ReceiptId>,
}

/// Causality Ledger trait
#[async_trait]
pub trait CausalityLedger: Ledger {
    /// Submit a new commitment
    async fn submit_commitment(
        &self,
        actor_id: &ActorId,
        scope_type: ScopeType,
        commitment_digest: Digest,
        parent_ref: Option<String>,
    ) -> LedgerResult<CommitmentRecord>;

    /// Get commitment by ID
    async fn get_commitment(&self, commitment_id: &str) -> LedgerResult<Option<CommitmentRecord>>;

    /// Get commitment chain for an actor
    async fn get_commitment_chain(
        &self,
        actor_id: &ActorId,
        scope_type: Option<ScopeType>,
        options: QueryOptions,
    ) -> LedgerResult<Vec<CommitmentRecord>>;

    /// Verify parent chain integrity
    async fn verify_chain(
        &self,
        commitment_id: &str,
        depth: Option<u32>,
    ) -> LedgerResult<bool>;

    /// Submit a batch root (from threshold signing)
    async fn submit_batch_root(
        &self,
        snapshot: SignedBatchSnapshot,
    ) -> LedgerResult<L0Receipt>;

    /// Get batch snapshot by sequence
    async fn get_batch_snapshot(
        &self,
        sequence_no: u64,
    ) -> LedgerResult<Option<SignedBatchSnapshot>>;

    /// Submit an epoch root (for chain anchoring)
    async fn submit_epoch_root(
        &self,
        snapshot: EpochSnapshot,
    ) -> LedgerResult<L0Receipt>;

    /// Get epoch snapshot by sequence
    async fn get_epoch_snapshot(
        &self,
        sequence_no: u64,
    ) -> LedgerResult<Option<EpochSnapshot>>;

    /// Get commitments in a time window
    async fn get_commitments_in_window(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        scope_type: Option<ScopeType>,
    ) -> LedgerResult<Vec<CommitmentRecord>>;

    /// Calculate batch root for given commitments
    async fn calculate_batch_root(
        &self,
        commitment_ids: &[String],
    ) -> LedgerResult<Digest>;
}
