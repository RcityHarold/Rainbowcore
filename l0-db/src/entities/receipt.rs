//! Receipt entity for L0 receipts

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use soulbase_storage::model::Entity;
use soulbase_types::prelude::TenantId;

/// L0 Receipt entity stored in SurrealDB
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptEntity {
    /// SurrealDB record ID
    pub id: String,
    /// Tenant ID
    pub tenant_id: TenantId,
    /// Receipt ID (unique within L0)
    pub receipt_id: String,
    /// Scope type (one of 11 batch types)
    pub scope_type: String,
    /// Root kind: commitment, batch, epoch
    pub root_kind: String,
    /// Root digest
    pub root: String,
    /// Batch time window start
    pub time_window_start: DateTime<Utc>,
    /// Batch time window end
    pub time_window_end: DateTime<Utc>,
    /// Batch sequence number
    pub batch_sequence_no: Option<u64>,
    /// Version fields (must enter signature domain)
    pub signer_set_version: String,
    pub canonicalization_version: String,
    pub anchor_policy_version: String,
    pub fee_schedule_version: String,
    /// Associated fee receipt
    pub fee_receipt_id: String,
    /// Reference to signed snapshot
    pub signed_snapshot_ref: String,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Rejection status
    pub rejected: bool,
    pub reject_reason_code: Option<String>,
}

impl Entity for ReceiptEntity {
    const TABLE: &'static str = "l0_receipt";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}

impl ReceiptEntity {
    /// Check if receipt is valid (not rejected)
    pub fn is_valid(&self) -> bool {
        !self.rejected
    }
}

/// Fee receipt entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeReceiptEntity {
    pub id: String,
    pub tenant_id: TenantId,
    pub fee_receipt_id: String,
    pub payer_actor_id: String,
    pub fee_units: u64,
    pub fee_schedule_version: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub settled_at: Option<DateTime<Utc>>,
}

impl Entity for FeeReceiptEntity {
    const TABLE: &'static str = "l0_fee_receipt";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}

/// TipWitness entity (anti-history-rewrite, mandatory, free)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TipWitnessEntity {
    pub id: String,
    pub tenant_id: TenantId,
    pub tip_witness_id: String,
    pub actor_id: String,
    pub local_tip_digest: String,
    pub local_sequence_no: u64,
    pub last_known_receipt_ref: Option<String>,
    pub witnessed_at: DateTime<Utc>,
    pub receipt_id: Option<String>,
}

impl Entity for TipWitnessEntity {
    const TABLE: &'static str = "l0_tip_witness";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}
