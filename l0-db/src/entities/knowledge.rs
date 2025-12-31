//! Knowledge Index entities for L0

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use soulbase_storage::model::Entity;
use soulbase_types::prelude::TenantId;

/// Knowledge Index Entry entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeIndexEntity {
    pub id: String,
    pub tenant_id: TenantId,
    pub entry_id: String,
    pub entry_type: String,
    pub content_digest: String,
    pub parent_digest: Option<String>,
    pub space_id: Option<String>,
    pub owner_actor_id: String,
    pub created_at: DateTime<Utc>,
    pub evidence_level: String,
    pub anchoring_state: String,
    pub receipt_id: Option<String>,
}

impl Entity for KnowledgeIndexEntity {
    const TABLE: &'static str = "l0_knowledge_index";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}

impl KnowledgeIndexEntity {
    /// Create a new knowledge index entity
    pub fn new(
        tenant_id: TenantId,
        entry_id: String,
        entry_type: String,
        content_digest: String,
        owner_actor_id: String,
    ) -> Self {
        Self {
            id: format!("l0_knowledge_index:{}:{}", tenant_id.0, entry_id),
            tenant_id,
            entry_id,
            entry_type,
            content_digest,
            parent_digest: None,
            space_id: None,
            owner_actor_id,
            created_at: Utc::now(),
            evidence_level: "b_local_only".to_string(),
            anchoring_state: "pending".to_string(),
            receipt_id: None,
        }
    }
}

/// Cross-reference entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossReferenceEntity {
    pub id: String,
    pub tenant_id: TenantId,
    pub ref_id: String,
    pub source_digest: String,
    pub target_digest: String,
    pub ref_type: String,
    pub created_at: DateTime<Utc>,
    pub receipt_id: Option<String>,
}

impl Entity for CrossReferenceEntity {
    const TABLE: &'static str = "l0_cross_reference";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}

impl CrossReferenceEntity {
    /// Create a new cross-reference entity
    pub fn new(
        tenant_id: TenantId,
        ref_id: String,
        source_digest: String,
        target_digest: String,
        ref_type: String,
    ) -> Self {
        Self {
            id: format!("l0_cross_reference:{}:{}", tenant_id.0, ref_id),
            tenant_id,
            ref_id,
            source_digest,
            target_digest,
            ref_type,
            created_at: Utc::now(),
            receipt_id: None,
        }
    }
}
