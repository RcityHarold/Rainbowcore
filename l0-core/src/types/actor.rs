//! Actor types for L0 Identity Ledger

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use super::common::Digest;

/// Actor ID - primary identifier for all subjects
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActorId(pub String);

impl ActorId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ActorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Node Actor ID - identifier for node operators
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeActorId(pub String);

impl NodeActorId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Group Actor ID - identifier for collective subjects
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GroupActorId(pub String);

impl GroupActorId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Space ID - identifier for scene containers (NOT a subject)
/// NEVER use in parties/approvers/payer fields
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpaceId(pub String);

impl SpaceId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Receipt ID - identifier for L0 receipts
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReceiptId(pub String);

impl ReceiptId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Actor type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    HumanActor,
    AiActor,
    NodeActor,
    GroupActor,
}

/// Actor status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorStatus {
    Active,
    Suspended,
    InRepair,
    Terminated,
}

impl Default for ActorStatus {
    fn default() -> Self {
        Self::Active
    }
}

/// Actor registration record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorRecord {
    pub actor_id: ActorId,
    pub actor_type: ActorType,
    pub node_actor_id: NodeActorId,
    pub public_key: String,
    pub payment_address_slot: Option<String>,
    pub status: ActorStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub receipt_id: Option<ReceiptId>,
    pub metadata_digest: Option<Digest>,
}

/// Actor history event type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorEventType {
    Registered,
    KeyRotated,
    StatusChanged,
    PaymentAddressUpdated,
    MetadataUpdated,
}

/// Actor history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorHistoryEntry {
    pub event_type: ActorEventType,
    pub timestamp: DateTime<Utc>,
    pub receipt_id: ReceiptId,
    pub details_digest: Digest,
    pub previous_value_digest: Option<Digest>,
    pub new_value_digest: Option<Digest>,
}

/// Key rotation record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotateRecord {
    pub actor_id: ActorId,
    pub old_public_key: String,
    pub new_public_key: String,
    pub reason_digest: Option<Digest>,
    pub rotated_at: DateTime<Utc>,
    pub receipt_id: Option<ReceiptId>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_actor_id_creation() {
        let id = ActorId::new("ai_actor:test_001");
        assert_eq!(id.as_str(), "ai_actor:test_001");
    }

    #[test]
    fn test_actor_type_serialization() {
        let actor_type = ActorType::AiActor;
        let json = serde_json::to_string(&actor_type).unwrap();
        assert_eq!(json, "\"ai_actor\"");
    }
}
