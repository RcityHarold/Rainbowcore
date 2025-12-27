//! Commitment entity for Causality Ledger

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use soulbase_storage::model::Entity;
use soulbase_types::prelude::TenantId;

/// Commitment entity stored in SurrealDB
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentEntity {
    /// SurrealDB record ID
    pub id: String,
    /// Tenant ID
    pub tenant_id: TenantId,
    /// Commitment ID (unique within L0)
    pub commitment_id: String,
    /// Actor who submitted this commitment
    pub actor_id: String,
    /// Scope type (one of 11 batch types)
    pub scope_type: String,
    /// Commitment digest (BLAKE3 hash)
    pub commitment_digest: String,
    /// Parent commitment reference (for chain)
    pub parent_commitment_ref: Option<String>,
    /// Sequence number within actor's chain
    pub sequence_no: u64,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// L0 receipt ID
    pub receipt_id: Option<String>,
    /// Batch sequence this commitment was included in
    pub batch_sequence_no: Option<u64>,
}

impl Entity for CommitmentEntity {
    const TABLE: &'static str = "l0_commitment";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}

impl CommitmentEntity {
    /// Create a new commitment entity
    pub fn new(
        tenant_id: TenantId,
        commitment_id: String,
        actor_id: String,
        scope_type: String,
        commitment_digest: String,
        parent_commitment_ref: Option<String>,
        sequence_no: u64,
    ) -> Self {
        let id = format!("{}:{}:{}", Self::TABLE, tenant_id.0, commitment_id);
        Self {
            id,
            tenant_id,
            commitment_id,
            actor_id,
            scope_type,
            commitment_digest,
            parent_commitment_ref,
            sequence_no,
            created_at: Utc::now(),
            receipt_id: None,
            batch_sequence_no: None,
        }
    }
}

/// Batch snapshot entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSnapshotEntity {
    pub id: String,
    pub tenant_id: TenantId,
    pub batch_sequence_no: u64,
    pub batch_root: String,
    pub time_window_start: DateTime<Utc>,
    pub time_window_end: DateTime<Utc>,
    pub parent_batch_root: Option<String>,
    pub commitment_count: u64,
    pub signer_set_version: String,
    pub threshold_rule: String,
    pub signature_bitmap: String,
    pub threshold_proof: String,
    pub created_at: DateTime<Utc>,
}

impl Entity for BatchSnapshotEntity {
    const TABLE: &'static str = "l0_batch_snapshot";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}

/// Epoch snapshot entity (for chain anchoring)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochSnapshotEntity {
    pub id: String,
    pub tenant_id: TenantId,
    pub epoch_sequence_no: u64,
    pub epoch_root: String,
    pub time_window_start: DateTime<Utc>,
    pub time_window_end: DateTime<Utc>,
    pub batch_start: u64,
    pub batch_end: u64,
    pub parent_epoch_root: Option<String>,
    pub chain_anchor_tx: Option<String>,
    pub anchor_status: String,
    pub created_at: DateTime<Utc>,
}

impl Entity for EpochSnapshotEntity {
    const TABLE: &'static str = "l0_epoch_snapshot";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}
