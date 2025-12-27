//! Receipt repository - L0 Receipt storage

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

use crate::error::L0DbResult;

/// L0 Receipt entity for SurrealDB storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptEntity {
    pub id: String,
    pub receipt_id: String,
    pub scope_type: String,
    pub root_kind: String,
    pub root: String,
    pub time_window_start: DateTime<Utc>,
    pub time_window_end: DateTime<Utc>,
    pub batch_sequence_no: Option<u64>,
    pub signer_set_version: String,
    pub canonicalization_version: String,
    pub anchor_policy_version: String,
    pub fee_schedule_version: String,
    pub fee_receipt_id: String,
    pub signed_snapshot_ref: String,
    pub created_at: DateTime<Utc>,
    pub rejected: Option<bool>,
    pub reject_reason_code: Option<String>,
}

/// Receipt repository trait
#[async_trait]
pub trait ReceiptRepository: Send + Sync {
    async fn create(&self, entity: ReceiptEntity) -> L0DbResult<ReceiptEntity>;
    async fn get_by_id(&self, receipt_id: &str) -> L0DbResult<Option<ReceiptEntity>>;
    async fn get_by_batch(&self, batch_seq: u64) -> L0DbResult<Vec<ReceiptEntity>>;
    async fn verify(&self, receipt_id: &str) -> L0DbResult<bool>;
}
