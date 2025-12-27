//! Dispute entity for Dispute-Resolution Ledger

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use soulbase_storage::model::Entity;
use soulbase_types::prelude::TenantId;

/// Dispute entity stored in SurrealDB
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeEntity {
    pub id: String,
    pub tenant_id: TenantId,
    pub dispute_id: String,
    pub filed_by: String,
    pub filed_against: Vec<String>,
    pub priority: String,
    pub status: String,
    pub subject_commitment_ref: String,
    pub evidence_digest: String,
    pub filed_at: DateTime<Utc>,
    pub last_updated: DateTime<Utc>,
    pub receipt_id: Option<String>,
}

impl Entity for DisputeEntity {
    const TABLE: &'static str = "l0_dispute";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}

/// Verdict entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictEntity {
    pub id: String,
    pub tenant_id: TenantId,
    pub verdict_id: String,
    pub dispute_id: String,
    pub verdict_type: String,
    pub verdict_digest: String,
    pub rationale_digest: String,
    pub remedies_digest: Option<String>,
    pub issued_by: String,
    pub issued_at: DateTime<Utc>,
    pub effective_at: DateTime<Utc>,
    pub appeal_deadline: Option<DateTime<Utc>>,
    pub receipt_id: Option<String>,
}

impl Entity for VerdictEntity {
    const TABLE: &'static str = "l0_verdict";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}

/// Clawback entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClawbackEntity {
    pub id: String,
    pub tenant_id: TenantId,
    pub clawback_id: String,
    pub verdict_id: String,
    pub clawback_type: String,
    pub status: String,
    pub clawback_digest: String,
    pub target_commitment_refs: Vec<String>,
    pub affected_actors: Vec<String>,
    pub compensation_digest: Option<String>,
    pub initiated_at: DateTime<Utc>,
    pub executed_at: Option<DateTime<Utc>>,
    pub receipt_id: Option<String>,
}

impl Entity for ClawbackEntity {
    const TABLE: &'static str = "l0_clawback";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}

/// Repair checkpoint entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairCheckpointEntity {
    pub id: String,
    pub tenant_id: TenantId,
    pub checkpoint_id: String,
    pub dispute_id: String,
    pub verdict_id: String,
    pub checkpoint_digest: String,
    pub affected_actors: Vec<String>,
    pub repair_plan_digest: String,
    pub progress_percent: u8,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub receipt_id: Option<String>,
}

impl Entity for RepairCheckpointEntity {
    const TABLE: &'static str = "l0_repair_checkpoint";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}
