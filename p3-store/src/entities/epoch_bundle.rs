//! Epoch Bundle Entity

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use soulbase_storage::model::Entity;
use soulbase_types::prelude::TenantId;

/// Epoch bundle status
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpochBundleStatus {
    /// Pending - bundle created but not committed
    Pending,
    /// Committed - bundle committed to storage
    Committed,
    /// Finalized - bundle finalized with all proofs
    Finalized,
    /// Anchored - bundle anchored to external chain
    Anchored,
}

impl Default for EpochBundleStatus {
    fn default() -> Self {
        Self::Pending
    }
}

impl std::fmt::Display for EpochBundleStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Committed => write!(f, "committed"),
            Self::Finalized => write!(f, "finalized"),
            Self::Anchored => write!(f, "anchored"),
        }
    }
}

/// Epoch bundle entity for database storage
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochBundleEntity {
    /// Entity ID
    pub id: String,
    /// Tenant ID
    pub tenant_id: TenantId,
    /// Epoch ID
    pub epoch_id: String,
    /// Epoch window start
    pub epoch_window_start: DateTime<Utc>,
    /// Epoch window end
    pub epoch_window_end: DateTime<Utc>,
    /// Cutoff reference digest
    pub cutoff_ref_digest: Option<String>,
    /// Cutoff reference sequence
    pub cutoff_ref_sequence: Option<i64>,
    /// Manifest digest
    pub manifest_digest: String,
    /// Weights version ID
    pub weights_version_id: String,
    /// Weights version digest
    pub weights_version_digest: String,
    /// Policy refs digest
    pub policy_refs_digest: String,
    /// Canon version
    pub canon_version: String,
    /// Receipt refs digest
    pub receipt_refs_digest: String,
    /// Result root digest
    pub result_root_digest: String,
    /// Chain anchor tx ID
    pub chain_anchor_tx_id: Option<String>,
    /// Chain anchor chain type
    pub chain_anchor_chain_type: Option<String>,
    /// Chain anchor block height
    pub chain_anchor_block_height: Option<i64>,
    /// Chain anchor timestamp
    pub chain_anchor_timestamp: Option<DateTime<Utc>>,
    /// Status
    pub status: EpochBundleStatus,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Updated at
    pub updated_at: DateTime<Utc>,
}

impl Entity for EpochBundleEntity {
    const TABLE: &'static str = "p3_epoch_bundle";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}

impl EpochBundleEntity {
    /// Create a new epoch bundle entity
    pub fn new(tenant_id: TenantId, epoch_id: impl Into<String>) -> Self {
        let now = Utc::now();
        let eid = epoch_id.into();
        let id = format!("{}:{}:{}", Self::TABLE, tenant_id.0, eid);
        Self {
            id,
            tenant_id,
            epoch_id: eid,
            epoch_window_start: now,
            epoch_window_end: now,
            cutoff_ref_digest: None,
            cutoff_ref_sequence: None,
            manifest_digest: String::new(),
            weights_version_id: String::new(),
            weights_version_digest: String::new(),
            policy_refs_digest: String::new(),
            canon_version: "v1".to_string(),
            receipt_refs_digest: String::new(),
            result_root_digest: String::new(),
            chain_anchor_tx_id: None,
            chain_anchor_chain_type: None,
            chain_anchor_block_height: None,
            chain_anchor_timestamp: None,
            status: EpochBundleStatus::Pending,
            created_at: now,
            updated_at: now,
        }
    }

    /// Set epoch window
    pub fn with_window(mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        self.epoch_window_start = start;
        self.epoch_window_end = end;
        self
    }

    /// Set manifest digest
    pub fn with_manifest_digest(mut self, digest: impl Into<String>) -> Self {
        self.manifest_digest = digest.into();
        self
    }

    /// Set result root digest
    pub fn with_result_root(mut self, digest: impl Into<String>) -> Self {
        self.result_root_digest = digest.into();
        self
    }

    /// Set status
    pub fn with_status(mut self, status: EpochBundleStatus) -> Self {
        self.status = status;
        self.updated_at = Utc::now();
        self
    }

    /// Check if bundle is finalized
    pub fn is_finalized(&self) -> bool {
        matches!(
            self.status,
            EpochBundleStatus::Finalized | EpochBundleStatus::Anchored
        )
    }

    /// Check if bundle is anchored
    pub fn is_anchored(&self) -> bool {
        matches!(self.status, EpochBundleStatus::Anchored)
    }
}

/// Execution proof entity
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionProofEntity {
    /// Entity ID
    pub id: String,
    /// Tenant ID
    pub tenant_id: TenantId,
    /// Proof ID
    pub proof_id: String,
    /// Epoch ID
    pub epoch_id: String,
    /// Proof type
    pub proof_type: String,
    /// Executor reference
    pub executor_ref: String,
    /// Executed at
    pub executed_at: DateTime<Utc>,
    /// Receipt reference
    pub receipt_ref: Option<String>,
    /// Proof digest
    pub proof_digest: String,
    /// Created at
    pub created_at: DateTime<Utc>,
}

impl Entity for ExecutionProofEntity {
    const TABLE: &'static str = "p3_execution_proof";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}

impl ExecutionProofEntity {
    /// Create a new execution proof entity
    pub fn new(tenant_id: TenantId, proof_id: impl Into<String>, epoch_id: impl Into<String>) -> Self {
        let now = Utc::now();
        let pid = proof_id.into();
        let id = format!("{}:{}:{}", Self::TABLE, tenant_id.0, pid);
        Self {
            id,
            tenant_id,
            proof_id: pid,
            epoch_id: epoch_id.into(),
            proof_type: "on_chain".to_string(),
            executor_ref: String::new(),
            executed_at: now,
            receipt_ref: None,
            proof_digest: String::new(),
            created_at: now,
        }
    }
}

/// Idempotency key entity
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdempotencyKeyEntity {
    /// Entity ID
    pub id: String,
    /// Tenant ID
    pub tenant_id: TenantId,
    /// Key value
    pub key_value: String,
    /// Key digest
    pub key_digest: String,
    /// Epoch ID
    pub epoch_id: String,
    /// Result digest
    pub result_digest: String,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Expires at
    pub expires_at: Option<DateTime<Utc>>,
}

impl Entity for IdempotencyKeyEntity {
    const TABLE: &'static str = "p3_idempotency_key";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}

impl IdempotencyKeyEntity {
    /// Create a new idempotency key entity
    pub fn new(tenant_id: TenantId, key: impl Into<String>, epoch_id: impl Into<String>) -> Self {
        let now = Utc::now();
        let k = key.into();
        let id = format!("{}:{}:{}", Self::TABLE, tenant_id.0, k);
        Self {
            id,
            tenant_id,
            key_value: k,
            key_digest: String::new(),
            epoch_id: epoch_id.into(),
            result_digest: String::new(),
            created_at: now,
            expires_at: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_tenant() -> TenantId {
        TenantId("test".to_string())
    }

    #[test]
    fn test_epoch_bundle_entity_creation() {
        let entity = EpochBundleEntity::new(test_tenant(), "epoch:test:001");
        assert_eq!(entity.epoch_id, "epoch:test:001");
        assert_eq!(entity.status, EpochBundleStatus::Pending);
        assert!(!entity.is_finalized());
    }

    #[test]
    fn test_epoch_bundle_status_transition() {
        let entity = EpochBundleEntity::new(test_tenant(), "epoch:test:001")
            .with_status(EpochBundleStatus::Finalized);
        assert!(entity.is_finalized());
        assert!(!entity.is_anchored());
    }

    #[test]
    fn test_execution_proof_entity() {
        let entity = ExecutionProofEntity::new(test_tenant(), "proof:001", "epoch:test:001");
        assert_eq!(entity.proof_id, "proof:001");
        assert_eq!(entity.epoch_id, "epoch:test:001");
    }
}
