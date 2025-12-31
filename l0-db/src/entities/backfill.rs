//! Backfill entity definitions

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use soulbase_storage::model::Entity;
use soulbase_types::prelude::TenantId;

/// Backfill request entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackfillRequestEntity {
    pub id: String,
    pub tenant_id: TenantId,
    pub request_id: String,
    pub actor_id: String,
    pub status: String,
    pub start_digest: String,
    pub start_sequence_no: u64,
    pub end_digest: String,
    pub end_sequence_no: u64,
    pub tip_witness_ref: String,
    pub requested_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub receipt_id: Option<String>,
    pub plan_id: Option<String>,
}

impl Entity for BackfillRequestEntity {
    const TABLE: &'static str = "l0_backfill_request";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}

/// Backfill plan entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackfillPlanEntity {
    pub id: String,
    pub tenant_id: TenantId,
    pub plan_id: String,
    pub request_id: String,
    pub actor_id: String,
    pub estimated_fee: String,
    pub continuity_result: String,
    pub gap_count: u32,
    pub item_count: u32,
    pub plan_digest: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl Entity for BackfillPlanEntity {
    const TABLE: &'static str = "l0_backfill_plan";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}

/// Backfill receipt entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackfillReceiptEntity {
    pub id: String,
    pub tenant_id: TenantId,
    pub backfill_receipt_id: String,
    pub request_id: String,
    pub plan_id: String,
    pub actor_id: String,
    pub objects_anchored: u64,
    pub anchored_digest: String,
    pub gaps_acknowledged_digest: Option<String>,
    pub total_fee: String,
    pub continuity_result: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub receipt_id: String,
}

impl Entity for BackfillReceiptEntity {
    const TABLE: &'static str = "l0_backfill_receipt";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}
