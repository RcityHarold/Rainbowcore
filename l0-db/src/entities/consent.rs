//! Consent entity for Policy-Consent Ledger

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use soulbase_storage::model::Entity;
use soulbase_types::prelude::TenantId;

/// Consent entity stored in SurrealDB
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentEntity {
    pub id: String,
    pub tenant_id: TenantId,
    pub consent_id: String,
    pub consent_type: String,
    pub grantor: String,
    pub grantee: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub actions: Vec<String>,
    pub constraints_digest: Option<String>,
    pub status: String,
    pub terms_digest: String,
    pub granted_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_reason_digest: Option<String>,
    pub superseded_by: Option<String>,
    pub receipt_id: Option<String>,
}

impl Entity for ConsentEntity {
    const TABLE: &'static str = "l0_consent";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}

/// Access ticket entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTicketEntity {
    pub id: String,
    pub tenant_id: TenantId,
    pub ticket_id: String,
    pub consent_ref: String,
    pub holder: String,
    pub target_resource: String,
    pub permissions: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub one_time: bool,
    pub used_at: Option<DateTime<Utc>>,
    pub ticket_digest: String,
    pub receipt_id: Option<String>,
}

impl Entity for AccessTicketEntity {
    const TABLE: &'static str = "l0_access_ticket";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}

/// Delegation entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationEntity {
    pub id: String,
    pub tenant_id: TenantId,
    pub delegation_id: String,
    pub delegator: String,
    pub delegate: String,
    pub resource_type: String,
    pub actions: Vec<String>,
    pub can_redelegate: bool,
    pub max_depth: u32,
    pub current_depth: u32,
    pub parent_delegation_ref: Option<String>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub receipt_id: Option<String>,
}

impl Entity for DelegationEntity {
    const TABLE: &'static str = "l0_delegation";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}
