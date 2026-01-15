//! Clearing Entity

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use soulbase_storage::model::Entity;
use soulbase_types::prelude::TenantId;

/// Clearing batch status
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearingBatchStatus {
    /// Pending processing
    Pending,
    /// Currently processing
    Processing,
    /// Successfully settled
    Settled,
    /// Failed
    Failed,
}

impl Default for ClearingBatchStatus {
    fn default() -> Self {
        Self::Pending
    }
}

impl std::fmt::Display for ClearingBatchStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Processing => write!(f, "processing"),
            Self::Settled => write!(f, "settled"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

/// Clearing batch entity
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClearingBatchEntity {
    /// Entity ID
    pub id: String,
    /// Tenant ID
    pub tenant_id: TenantId,
    /// Batch ID
    pub batch_id: String,
    /// Epoch ID
    pub epoch_id: String,
    /// Batch digest
    pub batch_digest: String,
    /// Entry count
    pub entry_count: i32,
    /// Total amount digest (zero-plaintext)
    pub total_amount_digest: String,
    /// Currency
    pub currency: String,
    /// Status
    pub status: ClearingBatchStatus,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Settled at
    pub settled_at: Option<DateTime<Utc>>,
}

impl Entity for ClearingBatchEntity {
    const TABLE: &'static str = "p3_clearing_batch";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}

impl ClearingBatchEntity {
    /// Create a new clearing batch entity
    pub fn new(tenant_id: TenantId, batch_id: impl Into<String>, epoch_id: impl Into<String>) -> Self {
        let now = Utc::now();
        let bid = batch_id.into();
        let id = format!("{}:{}:{}", Self::TABLE, tenant_id.0, bid);
        Self {
            id,
            tenant_id,
            batch_id: bid,
            epoch_id: epoch_id.into(),
            batch_digest: String::new(),
            entry_count: 0,
            total_amount_digest: String::new(),
            currency: "USD".to_string(),
            status: ClearingBatchStatus::Pending,
            created_at: now,
            settled_at: None,
        }
    }

    /// Set status
    pub fn with_status(mut self, status: ClearingBatchStatus) -> Self {
        self.status = status;
        if status == ClearingBatchStatus::Settled {
            self.settled_at = Some(Utc::now());
        }
        self
    }

    /// Mark as settled
    pub fn settle(&mut self) {
        self.status = ClearingBatchStatus::Settled;
        self.settled_at = Some(Utc::now());
    }

    /// Check if settled
    pub fn is_settled(&self) -> bool {
        self.status == ClearingBatchStatus::Settled
    }
}

/// Clearing entry entity
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClearingEntryEntity {
    /// Entity ID
    pub id: String,
    /// Tenant ID
    pub tenant_id: TenantId,
    /// Entry ID
    pub entry_id: String,
    /// Batch ID
    pub batch_id: String,
    /// From actor
    pub from_actor: String,
    /// To actor
    pub to_actor: String,
    /// Amount digest (zero-plaintext)
    pub amount_digest: String,
    /// Currency
    pub currency: String,
    /// Entry type
    pub entry_type: String,
    /// Reference digest
    pub reference_digest: Option<String>,
    /// Created at
    pub created_at: DateTime<Utc>,
}

impl Entity for ClearingEntryEntity {
    const TABLE: &'static str = "p3_clearing_entry";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}

impl ClearingEntryEntity {
    /// Create a new clearing entry entity
    pub fn new(
        tenant_id: TenantId,
        entry_id: impl Into<String>,
        batch_id: impl Into<String>,
        from_actor: impl Into<String>,
        to_actor: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        let eid = entry_id.into();
        let id = format!("{}:{}:{}", Self::TABLE, tenant_id.0, eid);
        Self {
            id,
            tenant_id,
            entry_id: eid,
            batch_id: batch_id.into(),
            from_actor: from_actor.into(),
            to_actor: to_actor.into(),
            amount_digest: String::new(),
            currency: "USD".to_string(),
            entry_type: "transfer".to_string(),
            reference_digest: None,
            created_at: now,
        }
    }

    /// Set amount digest
    pub fn with_amount_digest(mut self, digest: impl Into<String>) -> Self {
        self.amount_digest = digest.into();
        self
    }

    /// Set entry type
    pub fn with_entry_type(mut self, entry_type: impl Into<String>) -> Self {
        self.entry_type = entry_type.into();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_tenant() -> TenantId {
        TenantId("test".to_string())
    }

    #[test]
    fn test_clearing_batch_entity() {
        let entity = ClearingBatchEntity::new(test_tenant(), "batch:001", "epoch:001");
        assert_eq!(entity.batch_id, "batch:001");
        assert_eq!(entity.status, ClearingBatchStatus::Pending);
        assert!(!entity.is_settled());
    }

    #[test]
    fn test_clearing_batch_settle() {
        let mut entity = ClearingBatchEntity::new(test_tenant(), "batch:001", "epoch:001");
        entity.settle();
        assert!(entity.is_settled());
        assert!(entity.settled_at.is_some());
    }

    #[test]
    fn test_clearing_entry_entity() {
        let entity = ClearingEntryEntity::new(
            test_tenant(),
            "entry:001",
            "batch:001",
            "actor:from",
            "actor:to",
        );
        assert_eq!(entity.entry_id, "entry:001");
        assert_eq!(entity.from_actor, "actor:from");
        assert_eq!(entity.to_actor, "actor:to");
    }
}
