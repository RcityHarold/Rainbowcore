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
///
/// Format: `receipt:{block_height}:{tx_index}:{hash_prefix}`
/// Example: `receipt:12345:0:a1b2c3d4`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReceiptId(pub String);

impl ReceiptId {
    /// Create a new receipt ID (validated)
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Create a receipt ID from components
    pub fn from_components(block_height: u64, tx_index: u32, hash_prefix: &str) -> Self {
        Self(format!("receipt:{}:{}:{}", block_height, tx_index, hash_prefix))
    }

    /// Parse receipt ID from string with validation
    pub fn parse(s: &str) -> Result<Self, ReceiptIdError> {
        if !s.starts_with("receipt:") {
            return Err(ReceiptIdError::InvalidPrefix);
        }

        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() < 4 {
            return Err(ReceiptIdError::InvalidFormat);
        }

        // Validate block height is numeric
        parts[1].parse::<u64>().map_err(|_| ReceiptIdError::InvalidBlockHeight)?;

        // Validate tx index is numeric
        parts[2].parse::<u32>().map_err(|_| ReceiptIdError::InvalidTxIndex)?;

        // Validate hash prefix is hex
        if !parts[3].chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ReceiptIdError::InvalidHashPrefix);
        }

        Ok(Self(s.to_string()))
    }

    /// Get the string representation
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Extract block height from receipt ID
    pub fn block_height(&self) -> Option<u64> {
        self.0.split(':').nth(1)?.parse().ok()
    }

    /// Extract tx index from receipt ID
    pub fn tx_index(&self) -> Option<u32> {
        self.0.split(':').nth(2)?.parse().ok()
    }

    /// Extract hash prefix from receipt ID
    pub fn hash_prefix(&self) -> Option<&str> {
        self.0.split(':').nth(3)
    }

    /// Check if this is a valid receipt ID format
    pub fn is_valid_format(&self) -> bool {
        Self::parse(&self.0).is_ok()
    }
}

impl std::fmt::Display for ReceiptId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Default for ReceiptId {
    fn default() -> Self {
        Self("receipt:0:0:0000000000000000".to_string())
    }
}

/// Receipt ID parsing error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptIdError {
    /// Missing "receipt:" prefix
    InvalidPrefix,
    /// Invalid format (wrong number of parts)
    InvalidFormat,
    /// Block height is not a valid number
    InvalidBlockHeight,
    /// Tx index is not a valid number
    InvalidTxIndex,
    /// Hash prefix is not valid hex
    InvalidHashPrefix,
}

impl std::fmt::Display for ReceiptIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReceiptIdError::InvalidPrefix => write!(f, "Receipt ID must start with 'receipt:'"),
            ReceiptIdError::InvalidFormat => write!(f, "Invalid receipt ID format"),
            ReceiptIdError::InvalidBlockHeight => write!(f, "Invalid block height in receipt ID"),
            ReceiptIdError::InvalidTxIndex => write!(f, "Invalid tx index in receipt ID"),
            ReceiptIdError::InvalidHashPrefix => write!(f, "Invalid hash prefix in receipt ID"),
        }
    }
}

impl std::error::Error for ReceiptIdError {}

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
