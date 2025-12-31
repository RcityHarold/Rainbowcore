//! L0 Network Message Types
//!
//! Defines the messages exchanged between L0 nodes for threshold signing.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Unique message identifier
pub type MessageId = String;

/// Node identifier
pub type NodeId = String;

/// L0 network message envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L0Message {
    /// Message ID
    #[serde(alias = "id")]
    pub message_id: MessageId,
    /// Sender node ID
    pub from: NodeId,
    /// Target node ID (None = broadcast)
    pub to: Option<NodeId>,
    /// Message timestamp
    pub timestamp: DateTime<Utc>,
    /// Message payload
    pub payload: MessagePayload,
    /// Sender's signature on the message
    pub signature: Option<String>,
    /// Hop count for forwarding
    #[serde(default)]
    pub hop_count: u8,
}

impl L0Message {
    /// Create a new message
    pub fn new(from: NodeId, to: Option<NodeId>, payload: MessagePayload) -> Self {
        Self {
            message_id: generate_message_id(),
            from,
            to,
            timestamp: Utc::now(),
            payload,
            signature: None,
            hop_count: 0,
        }
    }

    /// Create a broadcast message
    pub fn broadcast(from: NodeId, payload: MessagePayload) -> Self {
        Self::new(from, None, payload)
    }

    /// Create a direct message to a specific node
    pub fn direct(from: NodeId, to: NodeId, payload: MessagePayload) -> Self {
        Self::new(from, Some(to), payload)
    }

    /// Check if this is a broadcast message
    pub fn is_broadcast(&self) -> bool {
        self.to.is_none()
    }

    /// Get the signing message (for signature verification)
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.message_id.as_bytes());
        data.extend_from_slice(self.from.as_bytes());
        if let Some(ref to) = self.to {
            data.extend_from_slice(to.as_bytes());
        }
        data.extend_from_slice(self.timestamp.to_rfc3339().as_bytes());
        // Serialize payload
        if let Ok(payload_bytes) = serde_json::to_vec(&self.payload) {
            data.extend_from_slice(&payload_bytes);
        }
        data
    }
}

/// Message payload types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum MessagePayload {
    /// Ping for liveness check
    Ping(PingPayload),
    /// Pong response
    Pong(PongPayload),
    /// Request to start a signing session
    SignRequest(SignRequestPayload),
    /// Response with signature
    SignResponse(SignResponsePayload),
    /// Signature collection status update
    SignStatus(SignStatusPayload),
    /// Node announcement
    NodeAnnounce(NodeAnnouncePayload),
    /// Request node list (alias for NodeListRequest)
    RequestNodes,
    /// Request node list
    NodeListRequest,
    /// Node list response
    NodeList(Vec<NodeInfo>),
    /// Node list response (legacy)
    NodeListResponse(NodeListPayload),
    /// Sync request for missing data
    SyncRequest(SyncRequestPayload),
    /// Sync response with data
    SyncResponse(SyncResponsePayload),
    /// Commitment announcement
    CommitmentAnnounce(CommitmentAnnouncePayload),
}

impl MessagePayload {
    /// Get the message type as a string
    pub fn message_type(&self) -> String {
        match self {
            MessagePayload::Ping(_) => "Ping".to_string(),
            MessagePayload::Pong(_) => "Pong".to_string(),
            MessagePayload::SignRequest(_) => "SignRequest".to_string(),
            MessagePayload::SignResponse(_) => "SignResponse".to_string(),
            MessagePayload::SignStatus(_) => "SignStatus".to_string(),
            MessagePayload::NodeAnnounce(_) => "NodeAnnounce".to_string(),
            MessagePayload::RequestNodes => "RequestNodes".to_string(),
            MessagePayload::NodeListRequest => "NodeListRequest".to_string(),
            MessagePayload::NodeList(_) => "NodeList".to_string(),
            MessagePayload::NodeListResponse(_) => "NodeListResponse".to_string(),
            MessagePayload::SyncRequest(_) => "SyncRequest".to_string(),
            MessagePayload::SyncResponse(_) => "SyncResponse".to_string(),
            MessagePayload::CommitmentAnnounce(_) => "CommitmentAnnounce".to_string(),
        }
    }
}

/// Commitment announcement payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentAnnouncePayload {
    /// Commitment ID
    pub commitment_id: String,
    /// Actor ID
    pub actor_id: String,
    /// Commitment digest (hex)
    pub commitment_digest: String,
    /// Sequence number
    pub sequence_no: u64,
}

/// Ping payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingPayload {
    pub nonce: u64,
}

/// Pong payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PongPayload {
    pub nonce: u64,
    #[serde(default)]
    pub node_role: Option<String>,
    #[serde(default)]
    pub signer_set_version: Option<String>,
}

/// Sign request payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequestPayload {
    /// Signing session ID
    pub session_id: String,
    /// Type of snapshot being signed
    pub snapshot_type: SnapshotType,
    /// The message to sign (hex encoded)
    pub message: String,
    /// Snapshot metadata (batch/epoch info)
    pub metadata: SigningMetadata,
    /// Signer set version required
    pub signer_set_version: String,
    /// Request timeout
    pub timeout_ms: u64,
}

/// Type of snapshot
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SnapshotType {
    Batch,
    Epoch,
}

/// Signing metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningMetadata {
    /// Batch/Epoch sequence number
    pub sequence_no: u64,
    /// Root hash (hex encoded)
    pub root: String,
    /// Time window start
    pub time_start: DateTime<Utc>,
    /// Time window end
    pub time_end: DateTime<Utc>,
}

/// Sign response payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResponsePayload {
    /// Session ID this is responding to
    pub session_id: String,
    /// Signer's public key (hex)
    pub signer_pubkey: String,
    /// Signer's signature (hex)
    pub signature: String,
    /// Success or error
    pub status: SignResponseStatus,
    /// Error message if failed
    pub error: Option<String>,
}

/// Sign response status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignResponseStatus {
    Success,
    InvalidRequest,
    NotInSignerSet,
    SessionExpired,
    InternalError,
}

/// Signing status update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignStatusPayload {
    /// Session ID
    pub session_id: String,
    /// Number of signatures collected
    pub signature_count: u32,
    /// Required threshold
    pub threshold: u32,
    /// Current bitmap
    pub bitmap: String,
    /// Is session complete?
    pub complete: bool,
    /// Final proof if complete (hex)
    pub proof: Option<String>,
}

/// Node announcement payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeAnnouncePayload {
    /// Node ID
    pub node_id: NodeId,
    /// Node role
    pub role: NodeRole,
    /// Public key (hex)
    pub pubkey: String,
    /// Listen address
    pub address: String,
    /// Supported protocol version
    pub protocol_version: String,
    /// Current signer set version (if signer)
    pub signer_set_version: Option<String>,
}

/// Node role
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NodeRole {
    /// Read-only node
    ReadVerify,
    /// Observer signer
    ObserverSigner,
    /// Certified signer
    CertifiedSigner,
}

/// Node list payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeListPayload {
    pub nodes: Vec<NodeInfo>,
}

/// Node info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub node_id: NodeId,
    pub role: NodeRole,
    pub pubkey: String,
    pub address: String,
    pub last_seen: DateTime<Utc>,
    pub is_online: bool,
}

/// Sync request payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequestPayload {
    /// Type of data to sync
    pub sync_type: SyncType,
    /// Start sequence (inclusive)
    pub from_seq: u64,
    /// End sequence (inclusive)
    pub to_seq: u64,
}

/// Sync type
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SyncType {
    BatchSnapshots,
    EpochSnapshots,
    SignerSets,
}

/// Sync response payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponsePayload {
    pub sync_type: SyncType,
    /// JSON-encoded data items
    pub items: Vec<String>,
    /// Has more data?
    pub has_more: bool,
    /// Next sequence if has_more
    pub next_seq: Option<u64>,
}

/// Generate a unique message ID
fn generate_message_id() -> MessageId {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let seq = COUNTER.fetch_add(1, Ordering::SeqCst);
    let timestamp = Utc::now().timestamp_micros();
    format!("msg_{:016x}_{:08x}", timestamp, seq)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_serialization() {
        let msg = L0Message::broadcast(
            "node_1".to_string(),
            MessagePayload::Ping(PingPayload { nonce: 12345 }),
        );

        let json = serde_json::to_string(&msg).unwrap();
        let restored: L0Message = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.from, "node_1");
        assert!(matches!(restored.payload, MessagePayload::Ping(_)));
    }

    #[test]
    fn test_sign_request() {
        let payload = SignRequestPayload {
            session_id: "sess_1".to_string(),
            snapshot_type: SnapshotType::Batch,
            message: "deadbeef".to_string(),
            metadata: SigningMetadata {
                sequence_no: 1,
                root: "abcd1234".to_string(),
                time_start: Utc::now(),
                time_end: Utc::now(),
            },
            signer_set_version: "v1:1".to_string(),
            timeout_ms: 5000,
        };

        let msg = L0Message::broadcast("coordinator".to_string(), MessagePayload::SignRequest(payload));
        assert!(msg.is_broadcast());
    }
}
