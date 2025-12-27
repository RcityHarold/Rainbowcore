//! Actor entity for Identity Ledger

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use soulbase_storage::model::Entity;
use soulbase_types::prelude::TenantId;

/// Actor entity stored in SurrealDB
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorEntity {
    /// SurrealDB record ID (format: actor:{tenant}:{actor_id})
    pub id: String,
    /// Tenant ID for multi-tenancy
    pub tenant_id: TenantId,
    /// Actor ID (unique within L0)
    pub actor_id: String,
    /// Actor type: human, ai_agent, node, group
    pub actor_type: String,
    /// Node that registered this actor
    pub node_actor_id: String,
    /// Current public key (Ed25519)
    pub public_key: String,
    /// Optional payment address slot
    pub payment_address_slot: Option<String>,
    /// Actor status: active, suspended, revoked
    pub status: String,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
    /// L0 receipt ID for registration
    pub receipt_id: Option<String>,
    /// Metadata digest (off-chain reference)
    pub metadata_digest: Option<String>,
}

impl Entity for ActorEntity {
    const TABLE: &'static str = "l0_actor";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}

impl ActorEntity {
    /// Create a new actor entity
    pub fn new(
        tenant_id: TenantId,
        actor_id: String,
        actor_type: String,
        node_actor_id: String,
        public_key: String,
    ) -> Self {
        let now = Utc::now();
        let id = format!("{}:{}:{}", Self::TABLE, tenant_id.0, actor_id);
        Self {
            id,
            tenant_id,
            actor_id,
            actor_type,
            node_actor_id,
            public_key,
            payment_address_slot: None,
            status: "active".to_string(),
            created_at: now,
            updated_at: now,
            receipt_id: None,
            metadata_digest: None,
        }
    }

    /// Check if actor is active
    pub fn is_active(&self) -> bool {
        self.status == "active"
    }
}

/// Key rotation record entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationEntity {
    pub id: String,
    pub tenant_id: TenantId,
    pub actor_id: String,
    pub old_public_key: String,
    pub new_public_key: String,
    pub rotated_at: DateTime<Utc>,
    pub reason_digest: Option<String>,
    pub receipt_id: Option<String>,
}

impl Entity for KeyRotationEntity {
    const TABLE: &'static str = "l0_key_rotation";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}
