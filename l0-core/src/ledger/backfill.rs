//! Backfill Ledger Interface
//!
//! Manages the upgrade path from B-level (local) to A-level (receipt-backed)
//! evidence through backfill operations.

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::{Ledger, LedgerResult};
use crate::types::{
    ActorId, BackfillPlan, BackfillReceipt, BackfillRequest, BackfillScope, BackfillStatus,
    ContinuityCheckResult, Digest, GapRecord, GapType,
};

/// Backfill request creation parameters
#[derive(Debug, Clone)]
pub struct CreateBackfillRequest {
    pub actor_id: ActorId,
    pub start_digest: Digest,
    pub start_sequence_no: u64,
    pub end_digest: Digest,
    pub end_sequence_no: u64,
    pub tip_witness_ref: String,
    pub scope_filter: Option<BackfillScope>,
}

/// Backfill Ledger interface
///
/// Handles the upgrade of local (B-level) evidence to receipt-backed (A-level)
/// evidence through backfill operations.
#[async_trait]
pub trait BackfillLedger: Ledger {
    /// Create a new backfill request
    ///
    /// Initiates the process of upgrading historical objects to A-level evidence.
    async fn create_request(&self, request: CreateBackfillRequest) -> LedgerResult<BackfillRequest>;

    /// Get a backfill request by ID
    async fn get_request(&self, request_id: &str) -> LedgerResult<Option<BackfillRequest>>;

    /// List backfill requests for an actor
    async fn list_requests(
        &self,
        actor_id: &ActorId,
        status: Option<BackfillStatus>,
    ) -> LedgerResult<Vec<BackfillRequest>>;

    /// Update backfill request status
    async fn update_request_status(
        &self,
        request_id: &str,
        status: BackfillStatus,
    ) -> LedgerResult<()>;

    /// Generate a backfill plan for a request
    ///
    /// Analyzes the objects to be backfilled and creates an execution plan.
    async fn generate_plan(&self, request_id: &str) -> LedgerResult<BackfillPlan>;

    /// Get a backfill plan by ID
    async fn get_plan(&self, plan_id: &str) -> LedgerResult<Option<BackfillPlan>>;

    /// Execute a backfill plan
    ///
    /// Performs the actual anchoring of objects and generates receipts.
    async fn execute_plan(&self, plan_id: &str) -> LedgerResult<BackfillReceipt>;

    /// Get a backfill receipt by ID
    async fn get_receipt(&self, receipt_id: &str) -> LedgerResult<Option<BackfillReceipt>>;

    /// Cancel a backfill request
    async fn cancel_request(&self, request_id: &str, reason: String) -> LedgerResult<()>;

    /// Detect gaps in the actor's history
    ///
    /// Analyzes the sequence from start to end and identifies gaps.
    async fn detect_gaps(
        &self,
        actor_id: &ActorId,
        start_sequence: u64,
        end_sequence: u64,
    ) -> LedgerResult<Vec<GapRecord>>;

    /// Verify continuity of an actor's chain
    ///
    /// Checks if the chain from start to end has acceptable continuity.
    async fn verify_continuity(
        &self,
        actor_id: &ActorId,
        start_sequence: u64,
        end_sequence: u64,
    ) -> LedgerResult<ContinuityCheckResult>;

    /// Get backfill history for an actor
    async fn get_backfill_history(
        &self,
        actor_id: &ActorId,
        limit: u32,
    ) -> LedgerResult<Vec<BackfillReceipt>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_backfill_request() {
        let actor_id = ActorId::new("actor:test");
        let request = CreateBackfillRequest {
            actor_id: actor_id.clone(),
            start_digest: Digest::zero(),
            start_sequence_no: 1,
            end_digest: Digest::zero(),
            end_sequence_no: 100,
            tip_witness_ref: "tip:test:100".to_string(),
            scope_filter: None,
        };

        assert_eq!(request.actor_id.0, "actor:test");
        assert_eq!(request.start_sequence_no, 1);
        assert_eq!(request.end_sequence_no, 100);
    }
}
