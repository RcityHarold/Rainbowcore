//! Dispute-Resolution Ledger - Verdicts, repairs, and clawbacks
//!
//! The Dispute-Resolution Ledger handles:
//! - Dispute filing and tracking
//! - Verdict issuance
//! - Repair checkpoints
//! - Clawback execution
//! - Appeal processing

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use crate::types::{
    Digest, ReceiptId, ActorId,
    DisputeRecord, DisputeStatus, DisputePriority,
    VerdictRecord, VerdictType,
    RepairCheckpoint, ClawbackRecord, ClawbackType, ClawbackStatus,
    AppealRecord,
};
use super::{Ledger, LedgerResult, QueryOptions};

/// Dispute-Resolution Ledger trait
#[async_trait]
pub trait DisputeLedger: Ledger {
    /// File a new dispute
    async fn file_dispute(
        &self,
        filed_by: &ActorId,
        filed_against: Vec<ActorId>,
        priority: DisputePriority,
        subject_commitment_ref: String,
        evidence_digest: Digest,
    ) -> LedgerResult<DisputeRecord>;

    /// Get dispute by ID
    async fn get_dispute(&self, dispute_id: &str) -> LedgerResult<Option<DisputeRecord>>;

    /// Update dispute status
    async fn update_dispute_status(
        &self,
        dispute_id: &str,
        new_status: DisputeStatus,
    ) -> LedgerResult<ReceiptId>;

    /// List disputes by status
    async fn list_disputes(
        &self,
        status: Option<DisputeStatus>,
        priority: Option<DisputePriority>,
        options: QueryOptions,
    ) -> LedgerResult<Vec<DisputeRecord>>;

    /// List disputes involving an actor
    async fn list_disputes_for_actor(
        &self,
        actor_id: &ActorId,
        as_filer: bool,
        options: QueryOptions,
    ) -> LedgerResult<Vec<DisputeRecord>>;

    /// Issue verdict
    async fn issue_verdict(
        &self,
        dispute_id: &str,
        verdict_type: VerdictType,
        verdict_digest: Digest,
        rationale_digest: Digest,
        remedies_digest: Option<Digest>,
        issued_by: String,
        appeal_deadline: Option<DateTime<Utc>>,
    ) -> LedgerResult<VerdictRecord>;

    /// Get verdict by ID
    async fn get_verdict(&self, verdict_id: &str) -> LedgerResult<Option<VerdictRecord>>;

    /// Get verdict for dispute
    async fn get_verdict_for_dispute(
        &self,
        dispute_id: &str,
    ) -> LedgerResult<Option<VerdictRecord>>;

    /// Create repair checkpoint
    async fn create_repair_checkpoint(
        &self,
        dispute_id: &str,
        verdict_id: &str,
        affected_actors: Vec<ActorId>,
        repair_plan_digest: Digest,
    ) -> LedgerResult<RepairCheckpoint>;

    /// Update repair progress
    async fn update_repair_progress(
        &self,
        checkpoint_id: &str,
        progress_percent: u8,
        checkpoint_digest: Digest,
    ) -> LedgerResult<ReceiptId>;

    /// Complete repair
    async fn complete_repair(
        &self,
        checkpoint_id: &str,
        final_digest: Digest,
    ) -> LedgerResult<ReceiptId>;

    /// Get repair checkpoint
    async fn get_repair_checkpoint(
        &self,
        checkpoint_id: &str,
    ) -> LedgerResult<Option<RepairCheckpoint>>;

    /// Initiate clawback
    async fn initiate_clawback(
        &self,
        verdict_id: &str,
        clawback_type: ClawbackType,
        target_commitment_refs: Vec<String>,
        affected_actors: Vec<ActorId>,
        compensation_digest: Option<Digest>,
    ) -> LedgerResult<ClawbackRecord>;

    /// Execute clawback
    async fn execute_clawback(
        &self,
        clawback_id: &str,
        execution_digest: Digest,
    ) -> LedgerResult<ReceiptId>;

    /// Update clawback status
    async fn update_clawback_status(
        &self,
        clawback_id: &str,
        new_status: ClawbackStatus,
    ) -> LedgerResult<ReceiptId>;

    /// Get clawback by ID
    async fn get_clawback(&self, clawback_id: &str) -> LedgerResult<Option<ClawbackRecord>>;

    /// List clawbacks by status
    async fn list_clawbacks(
        &self,
        status: Option<ClawbackStatus>,
        options: QueryOptions,
    ) -> LedgerResult<Vec<ClawbackRecord>>;

    /// File appeal
    async fn file_appeal(
        &self,
        verdict_id: &str,
        filed_by: &ActorId,
        grounds_digest: Digest,
        new_evidence_digest: Option<Digest>,
    ) -> LedgerResult<AppealRecord>;

    /// Get appeal for verdict
    async fn get_appeal_for_verdict(
        &self,
        verdict_id: &str,
    ) -> LedgerResult<Option<AppealRecord>>;
}
