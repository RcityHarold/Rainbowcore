//! Receipt Ledger - L0 Receipt and Fee tracking
//!
//! The Receipt Ledger manages:
//! - L0 Receipts for batch confirmations
//! - Fee receipts for billing and tracking
//! - Receipt verification and status updates

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use crate::types::{
    Digest, ActorId,
    L0Receipt, FeeReceipt, FeeReceiptStatus, FeeUnits, ScopeType, RootKind,
    ReceiptVerifyResult,
};
use super::{Ledger, LedgerResult, QueryOptions};

/// Receipt creation request
#[derive(Debug, Clone)]
pub struct CreateReceiptRequest {
    pub scope_type: ScopeType,
    pub root_kind: RootKind,
    pub root: Digest,
    pub time_window_start: DateTime<Utc>,
    pub time_window_end: DateTime<Utc>,
    pub batch_sequence_no: Option<u64>,
    pub signer_set_version: String,
    pub canonicalization_version: String,
    pub anchor_policy_version: String,
    pub fee_schedule_version: String,
    pub signed_snapshot_ref: String,
}

/// Fee charge request
#[derive(Debug, Clone)]
pub struct ChargeFeeRequest {
    pub payer_actor_id: ActorId,
    pub anchor_type: String,
    pub units: FeeUnits,
    pub units_count: u32,
    pub fee_schedule_version: String,
    pub linked_anchor_id: String,
    pub risk_multiplier: Option<String>,
    pub deposit_amount: Option<String>,
    pub discount_digest: Option<Digest>,
    pub subsidy_digest: Option<Digest>,
}

/// Receipt Ledger trait
#[async_trait]
pub trait ReceiptLedger: Ledger {
    /// Create a new L0 Receipt
    async fn create_receipt(
        &self,
        request: CreateReceiptRequest,
        fee_receipt_id: String,
    ) -> LedgerResult<L0Receipt>;

    /// Get receipt by ID
    async fn get_receipt(&self, receipt_id: &str) -> LedgerResult<Option<L0Receipt>>;

    /// Get receipts by batch sequence
    async fn get_receipts_by_batch(
        &self,
        batch_sequence: u64,
    ) -> LedgerResult<Vec<L0Receipt>>;

    /// Verify receipt
    async fn verify_receipt(&self, receipt_id: &str) -> LedgerResult<ReceiptVerifyResult>;

    /// Mark receipt as rejected
    async fn reject_receipt(
        &self,
        receipt_id: &str,
        reason_code: String,
        observer_reports_digest: Option<Digest>,
    ) -> LedgerResult<()>;

    /// List recent receipts
    async fn list_receipts(
        &self,
        scope_type: Option<ScopeType>,
        options: QueryOptions,
    ) -> LedgerResult<Vec<L0Receipt>>;

    // Fee Receipt operations

    /// Charge a fee (create pending fee receipt)
    async fn charge_fee(&self, request: ChargeFeeRequest) -> LedgerResult<FeeReceipt>;

    /// Get fee receipt by ID
    async fn get_fee_receipt(&self, fee_receipt_id: &str) -> LedgerResult<Option<FeeReceipt>>;

    /// Link fee receipt to L0 receipt (after receipt created)
    async fn link_fee_to_receipt(
        &self,
        fee_receipt_id: &str,
        receipt_id: &str,
    ) -> LedgerResult<()>;

    /// Update fee receipt status
    async fn update_fee_status(
        &self,
        fee_receipt_id: &str,
        new_status: FeeReceiptStatus,
    ) -> LedgerResult<()>;

    /// Get pending fees for a payer
    async fn get_pending_fees(
        &self,
        payer: &ActorId,
    ) -> LedgerResult<Vec<FeeReceipt>>;

    /// Get fee history for a payer
    async fn get_fee_history(
        &self,
        payer: &ActorId,
        options: QueryOptions,
    ) -> LedgerResult<Vec<FeeReceipt>>;

    /// Calculate total pending fees for a payer
    async fn calculate_pending_total(
        &self,
        payer: &ActorId,
    ) -> LedgerResult<String>;

    /// Refund a fee
    async fn refund_fee(
        &self,
        fee_receipt_id: &str,
        refund_reason: Option<String>,
    ) -> LedgerResult<()>;

    /// Forfeit a fee (when receipt rejected)
    async fn forfeit_fee(
        &self,
        fee_receipt_id: &str,
    ) -> LedgerResult<()>;
}
