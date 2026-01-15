//! Manifest Set Entity

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use soulbase_storage::model::Entity;
use soulbase_types::prelude::TenantId;

/// Manifest set type
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestSetType {
    /// Knowledge events
    KnowledgeEvents,
    /// Court events
    CourtEvents,
    /// Policy state
    PolicyState,
    /// Sampling audit
    SamplingAudit,
}

impl std::fmt::Display for ManifestSetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KnowledgeEvents => write!(f, "knowledge_events"),
            Self::CourtEvents => write!(f, "court_events"),
            Self::PolicyState => write!(f, "policy_state"),
            Self::SamplingAudit => write!(f, "sampling_audit"),
        }
    }
}

/// Manifest set entity
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManifestSetEntity {
    /// Entity ID
    pub id: String,
    /// Tenant ID
    pub tenant_id: TenantId,
    /// Epoch ID
    pub epoch_id: String,
    /// Set type
    pub set_type: ManifestSetType,
    /// Set digest
    pub set_digest: String,
    /// Event count
    pub event_count: i32,
    /// Event refs JSON (serialized)
    pub event_refs_json: Option<String>,
    /// Created at
    pub created_at: DateTime<Utc>,
}

impl Entity for ManifestSetEntity {
    const TABLE: &'static str = "p3_manifest_set";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}

impl ManifestSetEntity {
    /// Create a new manifest set entity
    pub fn new(tenant_id: TenantId, epoch_id: impl Into<String>, set_type: ManifestSetType) -> Self {
        let now = Utc::now();
        let eid = epoch_id.into();
        let id = format!("{}:{}:{}:{}", Self::TABLE, tenant_id.0, eid, set_type);
        Self {
            id,
            tenant_id,
            epoch_id: eid,
            set_type,
            set_digest: String::new(),
            event_count: 0,
            event_refs_json: None,
            created_at: now,
        }
    }

    /// Set digest
    pub fn with_digest(mut self, digest: impl Into<String>) -> Self {
        self.set_digest = digest.into();
        self
    }

    /// Set event count
    pub fn with_event_count(mut self, count: i32) -> Self {
        self.event_count = count;
        self
    }
}

/// Result entry entity (for result root Merkle tree)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResultEntryEntity {
    /// Entity ID
    pub id: String,
    /// Tenant ID
    pub tenant_id: TenantId,
    /// Epoch ID
    pub epoch_id: String,
    /// Entry index in Merkle tree
    pub entry_index: i32,
    /// Entry type
    pub entry_type: String,
    /// Entry digest
    pub entry_digest: String,
    /// Actor ID (if applicable)
    pub actor_id: Option<String>,
    /// Amount digest (if applicable)
    pub amount_digest: Option<String>,
    /// Currency (if applicable)
    pub currency: Option<String>,
    /// Created at
    pub created_at: DateTime<Utc>,
}

impl Entity for ResultEntryEntity {
    const TABLE: &'static str = "p3_result_entry";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}

impl ResultEntryEntity {
    /// Create a new result entry entity
    pub fn new(tenant_id: TenantId, epoch_id: impl Into<String>, index: i32) -> Self {
        let now = Utc::now();
        let eid = epoch_id.into();
        let id = format!("{}:{}:{}:{}", Self::TABLE, tenant_id.0, eid, index);
        Self {
            id,
            tenant_id,
            epoch_id: eid,
            entry_index: index,
            entry_type: String::new(),
            entry_digest: String::new(),
            actor_id: None,
            amount_digest: None,
            currency: None,
            created_at: now,
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
    fn test_manifest_set_entity() {
        let entity = ManifestSetEntity::new(test_tenant(), "epoch:test:001", ManifestSetType::KnowledgeEvents);
        assert_eq!(entity.epoch_id, "epoch:test:001");
        assert_eq!(entity.set_type, ManifestSetType::KnowledgeEvents);
    }

    #[test]
    fn test_result_entry_entity() {
        let entity = ResultEntryEntity::new(test_tenant(), "epoch:test:001", 0);
        assert_eq!(entity.epoch_id, "epoch:test:001");
        assert_eq!(entity.entry_index, 0);
    }
}
