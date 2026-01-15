//! Provider Entity

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use soulbase_storage::model::Entity;
use soulbase_types::prelude::TenantId;

/// Conformance level
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConformanceLevelDb {
    /// L1 - Read-only verification
    L1,
    /// L2 - Weak execution
    L2,
    /// L3 - Full verification
    L3,
}

impl std::fmt::Display for ConformanceLevelDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::L1 => write!(f, "L1"),
            Self::L2 => write!(f, "L2"),
            Self::L3 => write!(f, "L3"),
        }
    }
}

/// Provider status
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    /// Active
    Active,
    /// Suspended
    Suspended,
    /// Revoked
    Revoked,
}

impl Default for ProviderStatus {
    fn default() -> Self {
        Self::Active
    }
}

impl std::fmt::Display for ProviderStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Suspended => write!(f, "suspended"),
            Self::Revoked => write!(f, "revoked"),
        }
    }
}

/// Provider registration entity
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderEntity {
    /// Entity ID
    pub id: String,
    /// Tenant ID
    pub tenant_id: TenantId,
    /// Provider ID
    pub provider_id: String,
    /// Actor ID
    pub actor_id: String,
    /// Conformance level
    pub conformance_level: ConformanceLevelDb,
    /// Capabilities digest
    pub capabilities_digest: String,
    /// Endpoint URL
    pub endpoint_url: Option<String>,
    /// Status
    pub status: ProviderStatus,
    /// Registered at
    pub registered_at: DateTime<Utc>,
    /// Last verified at
    pub last_verified_at: Option<DateTime<Utc>>,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Updated at
    pub updated_at: DateTime<Utc>,
}

impl Entity for ProviderEntity {
    const TABLE: &'static str = "p3_provider";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}

impl ProviderEntity {
    /// Create a new provider entity
    pub fn new(
        tenant_id: TenantId,
        provider_id: impl Into<String>,
        actor_id: impl Into<String>,
        level: ConformanceLevelDb,
    ) -> Self {
        let now = Utc::now();
        let pid = provider_id.into();
        let id = format!("{}:{}:{}", Self::TABLE, tenant_id.0, pid);
        Self {
            id,
            tenant_id,
            provider_id: pid,
            actor_id: actor_id.into(),
            conformance_level: level,
            capabilities_digest: String::new(),
            endpoint_url: None,
            status: ProviderStatus::Active,
            registered_at: now,
            last_verified_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Set endpoint URL
    pub fn with_endpoint(mut self, url: impl Into<String>) -> Self {
        self.endpoint_url = Some(url.into());
        self
    }

    /// Mark as verified
    pub fn mark_verified(&mut self) {
        self.last_verified_at = Some(Utc::now());
        self.updated_at = Utc::now();
    }

    /// Suspend provider
    pub fn suspend(&mut self) {
        self.status = ProviderStatus::Suspended;
        self.updated_at = Utc::now();
    }

    /// Revoke provider
    pub fn revoke(&mut self) {
        self.status = ProviderStatus::Revoked;
        self.updated_at = Utc::now();
    }

    /// Check if active
    pub fn is_active(&self) -> bool {
        self.status == ProviderStatus::Active
    }
}

/// Version registry entity
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionRegistryEntity {
    /// Entity ID
    pub id: String,
    /// Tenant ID
    pub tenant_id: TenantId,
    /// Object type
    pub object_type: String,
    /// Version ID
    pub version_id: String,
    /// Version number
    pub version_number: i32,
    /// Object digest
    pub object_digest: String,
    /// Status
    pub status: String,
    /// Effective from
    pub effective_from: Option<DateTime<Utc>>,
    /// Effective until
    pub effective_until: Option<DateTime<Utc>>,
    /// Supersedes
    pub supersedes: Option<String>,
    /// Created at
    pub created_at: DateTime<Utc>,
}

impl Entity for VersionRegistryEntity {
    const TABLE: &'static str = "p3_version_registry";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}

impl VersionRegistryEntity {
    /// Create a new version registry entity
    pub fn new(
        tenant_id: TenantId,
        object_type: impl Into<String>,
        version_id: impl Into<String>,
        version_number: i32,
    ) -> Self {
        let now = Utc::now();
        let vid = version_id.into();
        let id = format!("{}:{}:{}", Self::TABLE, tenant_id.0, vid);
        Self {
            id,
            tenant_id,
            object_type: object_type.into(),
            version_id: vid,
            version_number,
            object_digest: String::new(),
            status: "draft".to_string(),
            effective_from: None,
            effective_until: None,
            supersedes: None,
            created_at: now,
        }
    }

    /// Activate version
    pub fn activate(&mut self) {
        self.status = "active".to_string();
        self.effective_from = Some(Utc::now());
    }

    /// Deprecate version
    pub fn deprecate(&mut self) {
        self.status = "deprecated".to_string();
        self.effective_until = Some(Utc::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_tenant() -> TenantId {
        TenantId("test".to_string())
    }

    #[test]
    fn test_provider_entity() {
        let entity = ProviderEntity::new(test_tenant(), "provider:001", "actor:001", ConformanceLevelDb::L2);
        assert_eq!(entity.provider_id, "provider:001");
        assert_eq!(entity.conformance_level, ConformanceLevelDb::L2);
        assert!(entity.is_active());
    }

    #[test]
    fn test_provider_lifecycle() {
        let mut entity = ProviderEntity::new(test_tenant(), "provider:001", "actor:001", ConformanceLevelDb::L1);

        entity.mark_verified();
        assert!(entity.last_verified_at.is_some());

        entity.suspend();
        assert_eq!(entity.status, ProviderStatus::Suspended);
        assert!(!entity.is_active());
    }

    #[test]
    fn test_version_registry_entity() {
        let mut entity = VersionRegistryEntity::new(test_tenant(), "weights", "weights:v1", 1);
        assert_eq!(entity.status, "draft");

        entity.activate();
        assert_eq!(entity.status, "active");
        assert!(entity.effective_from.is_some());
    }
}
