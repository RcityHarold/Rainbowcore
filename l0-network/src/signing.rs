//! L0 Distributed Signing Protocol
//!
//! Coordinates threshold signing across network nodes.

use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use l0_core::version::config::SIGNING_SESSION_TIMEOUT_SECS;

use crate::error::{NetworkError, NetworkResult};
use crate::message::{
    L0Message, MessagePayload, NodeId, SignRequestPayload, SignResponsePayload,
    SignResponseStatus, SignStatusPayload, SigningMetadata, SnapshotType,
};
use crate::node::{NodeManager, Transport};

/// Distributed signing session
#[derive(Debug, Clone)]
pub struct DistributedSigningSession {
    /// Session ID
    pub session_id: String,
    /// Snapshot type
    pub snapshot_type: SnapshotType,
    /// Message being signed (hex)
    pub message: String,
    /// Metadata
    pub metadata: SigningMetadata,
    /// Signer set version
    pub signer_set_version: String,
    /// Collected signatures (pubkey -> signature hex)
    pub signatures: HashMap<String, String>,
    /// Required threshold
    pub threshold: u32,
    /// Session start time
    pub started_at: chrono::DateTime<Utc>,
    /// Session timeout
    pub timeout: Duration,
    /// Is complete?
    pub complete: bool,
    /// Final bitmap if complete
    pub bitmap: Option<String>,
    /// Final proof if complete
    pub proof: Option<String>,
}

impl DistributedSigningSession {
    /// Create a new session
    pub fn new(
        session_id: String,
        snapshot_type: SnapshotType,
        message: String,
        metadata: SigningMetadata,
        signer_set_version: String,
        threshold: u32,
        timeout: Duration,
    ) -> Self {
        Self {
            session_id,
            snapshot_type,
            message,
            metadata,
            signer_set_version,
            signatures: HashMap::new(),
            threshold,
            started_at: Utc::now(),
            timeout,
            complete: false,
            bitmap: None,
            proof: None,
        }
    }

    /// Check if session has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.started_at + self.timeout
    }

    /// Check if threshold is met
    pub fn threshold_met(&self) -> bool {
        self.signatures.len() as u32 >= self.threshold
    }

    /// Add a signature
    pub fn add_signature(&mut self, pubkey: String, signature: String) -> bool {
        if self.signatures.contains_key(&pubkey) {
            return false; // Duplicate
        }
        self.signatures.insert(pubkey, signature);
        self.threshold_met()
    }

    /// Get signature count
    pub fn signature_count(&self) -> u32 {
        self.signatures.len() as u32
    }
}

/// Signing coordinator for managing distributed signing sessions
pub struct SigningCoordinator<T: Transport> {
    /// Our node ID
    node_id: NodeId,
    /// Node manager
    node_manager: Arc<NodeManager>,
    /// Transport
    transport: Arc<T>,
    /// Active sessions
    sessions: Arc<RwLock<HashMap<String, DistributedSigningSession>>>,
    /// Default timeout (5 minutes)
    default_timeout: Duration,
}

impl<T: Transport> SigningCoordinator<T> {
    /// Create a new signing coordinator
    pub fn new(
        node_id: NodeId,
        node_manager: Arc<NodeManager>,
        transport: Arc<T>,
    ) -> Self {
        Self {
            node_id,
            node_manager,
            transport,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            default_timeout: Duration::seconds(SIGNING_SESSION_TIMEOUT_SECS as i64),
        }
    }

    /// Start a new signing session and broadcast request
    pub async fn start_session(
        &self,
        snapshot_type: SnapshotType,
        message: String,
        metadata: SigningMetadata,
        signer_set_version: String,
        threshold: u32,
    ) -> NetworkResult<String> {
        // Check if we have enough signers
        if !self.node_manager.has_threshold_signers(threshold as usize).await {
            return Err(NetworkError::InsufficientSigners {
                have: self.node_manager.connected_signer_count().await,
                need: threshold as usize,
            });
        }

        // Generate session ID
        let session_id = generate_session_id();

        // Create session
        let session = DistributedSigningSession::new(
            session_id.clone(),
            snapshot_type,
            message.clone(),
            metadata.clone(),
            signer_set_version.clone(),
            threshold,
            self.default_timeout,
        );

        // Store session
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session_id.clone(), session);
        }

        // Create and broadcast sign request
        let payload = SignRequestPayload {
            session_id: session_id.clone(),
            snapshot_type,
            message,
            metadata,
            signer_set_version,
            timeout_ms: self.default_timeout.num_milliseconds() as u64,
        };

        let msg = L0Message::broadcast(self.node_id.clone(), MessagePayload::SignRequest(payload));
        self.transport.broadcast(&msg).await?;

        Ok(session_id)
    }

    /// Handle incoming sign response
    pub async fn handle_sign_response(
        &self,
        response: SignResponsePayload,
    ) -> NetworkResult<Option<SignStatusPayload>> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(&response.session_id)
            .ok_or_else(|| NetworkError::SessionNotFound(response.session_id.clone()))?;

        if session.is_expired() {
            return Err(NetworkError::SessionExpired(response.session_id.clone()));
        }

        if response.status != SignResponseStatus::Success {
            // Log but don't fail - other signers may succeed
            return Ok(None);
        }

        // Add signature
        let threshold_met = session.add_signature(response.signer_pubkey.clone(), response.signature);

        // Create status update
        let status = SignStatusPayload {
            session_id: session.session_id.clone(),
            signature_count: session.signature_count(),
            threshold: session.threshold,
            bitmap: create_bitmap(&session.signatures),
            complete: threshold_met,
            proof: if threshold_met {
                Some(create_aggregated_proof(&session.signatures))
            } else {
                None
            },
        };

        if threshold_met {
            session.complete = true;
            session.bitmap = Some(status.bitmap.clone());
            session.proof = status.proof.clone();
        }

        Ok(Some(status))
    }

    /// Get session status
    pub async fn get_session(&self, session_id: &str) -> Option<DistributedSigningSession> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).cloned()
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired(&self) {
        let mut sessions = self.sessions.write().await;
        sessions.retain(|_, s| !s.is_expired());
    }
}

/// Signing participant for responding to sign requests
pub struct SigningParticipant<T: Transport> {
    /// Our node ID
    node_id: NodeId,
    /// Our public key
    pubkey: String,
    /// Transport
    transport: Arc<T>,
    /// Signer function (takes message bytes, returns signature bytes)
    signer: Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>,
}

impl<T: Transport> SigningParticipant<T> {
    /// Create a new signing participant
    pub fn new<F>(
        node_id: NodeId,
        pubkey: String,
        transport: Arc<T>,
        signer: F,
    ) -> Self
    where
        F: Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static,
    {
        Self {
            node_id,
            pubkey,
            transport,
            signer: Arc::new(signer),
        }
    }

    /// Handle incoming sign request
    pub async fn handle_sign_request(
        &self,
        from: &NodeId,
        request: SignRequestPayload,
    ) -> NetworkResult<()> {
        // Decode message
        let message_bytes = hex::decode(&request.message)
            .map_err(|e| NetworkError::InvalidMessage(format!("Invalid hex: {}", e)))?;

        // Sign the message
        let signature = (self.signer)(&message_bytes);
        let signature_hex = hex::encode(&signature);

        // Create response
        let response = SignResponsePayload {
            session_id: request.session_id,
            signer_pubkey: self.pubkey.clone(),
            signature: signature_hex,
            status: SignResponseStatus::Success,
            error: None,
        };

        // Send response to coordinator
        let msg = L0Message::new(
            self.node_id.clone(),
            Some(from.clone()),
            MessagePayload::SignResponse(response),
        );
        self.transport.send(from, &msg).await
    }
}

/// Generate a session ID
fn generate_session_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let seq = COUNTER.fetch_add(1, Ordering::SeqCst);
    let timestamp = Utc::now().timestamp_micros();
    format!("dsign_{:016x}_{:08x}", timestamp, seq)
}

/// Signer index mapping for a 9-node signer set
/// This would be loaded from the signer set configuration in production
fn get_signer_index(pubkey: &str, signer_set: &[String]) -> Option<u8> {
    signer_set.iter().position(|pk| pk == pubkey).map(|i| i as u8)
}

/// Create bitmap from signatures
/// The bitmap indicates which signers have signed (bit position = signer index)
/// For a 9-signer set, this is a 9-bit value (stored as u16)
fn create_bitmap(signatures: &HashMap<String, String>) -> String {
    // Sort pubkeys to get consistent ordering
    let mut sorted_pubkeys: Vec<&String> = signatures.keys().collect();
    sorted_pubkeys.sort();

    // Create a simple index-based bitmap
    // In production, this would use the actual signer set to map pubkeys to indices
    let mut bitmap: u16 = 0;
    for (i, _pubkey) in sorted_pubkeys.iter().enumerate() {
        // Set bit at position i
        if i < 9 {
            bitmap |= 1 << i;
        }
    }

    // Format as hex for compact representation
    format!("{:04x}", bitmap)
}

/// Aggregated signature proof structure
/// Contains the bitmap and the concatenated signatures
fn create_aggregated_proof(signatures: &HashMap<String, String>) -> String {
    // Sort pubkeys for deterministic ordering
    let mut sorted_entries: Vec<(&String, &String)> = signatures.iter().collect();
    sorted_entries.sort_by(|a, b| a.0.cmp(b.0));

    // Create structured proof:
    // Format: version:bitmap:count:sig1_len:sig1:sig2_len:sig2:...
    // This allows for proper parsing and verification

    let bitmap = create_bitmap(signatures);
    let count = signatures.len();

    // Build proof components
    let mut proof_parts = Vec::new();
    proof_parts.push("v1".to_string());              // Version
    proof_parts.push(bitmap);                         // Bitmap
    proof_parts.push(count.to_string());              // Signature count

    // Add each signature with its pubkey for verification
    for (pubkey, sig) in &sorted_entries {
        // Format: pubkey_first8chars|signature
        let pk_short = if pubkey.len() > 8 {
            &pubkey[..8]
        } else {
            pubkey.as_str()
        };
        proof_parts.push(format!("{}={}", pk_short, sig));
    }

    proof_parts.join(":")
}

/// Parse an aggregated proof to extract signatures
pub fn parse_aggregated_proof(proof: &str) -> Option<(String, u32, Vec<(String, String)>)> {
    let parts: Vec<&str> = proof.split(':').collect();
    if parts.len() < 3 {
        return None;
    }

    // Check version
    if parts[0] != "v1" {
        return None;
    }

    let bitmap = parts[1].to_string();
    let count: u32 = parts[2].parse().ok()?;

    // Parse signatures
    let mut signatures = Vec::new();
    for part in &parts[3..] {
        let sig_parts: Vec<&str> = part.splitn(2, '=').collect();
        if sig_parts.len() == 2 {
            signatures.push((sig_parts[0].to_string(), sig_parts[1].to_string()));
        }
    }

    Some((bitmap, count, signatures))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_signing_session() {
        let metadata = SigningMetadata {
            sequence_no: 1,
            root: "abc123".to_string(),
            time_start: Utc::now(),
            time_end: Utc::now(),
        };

        let mut session = DistributedSigningSession::new(
            "test_session".to_string(),
            SnapshotType::Batch,
            "deadbeef".to_string(),
            metadata,
            "v1:1".to_string(),
            3,
            Duration::seconds(SIGNING_SESSION_TIMEOUT_SECS as i64),
        );

        assert!(!session.threshold_met());

        session.add_signature("pubkey_0".to_string(), "sig_0".to_string());
        session.add_signature("pubkey_1".to_string(), "sig_1".to_string());
        assert!(!session.threshold_met());

        session.add_signature("pubkey_2".to_string(), "sig_2".to_string());
        assert!(session.threshold_met());
    }
}
