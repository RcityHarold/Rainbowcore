//! Signing Session Management
//!
//! A signing session collects signatures from certified signers
//! until the 5/9 threshold is met.

use chrono::{DateTime, Duration, Utc};
use l0_core::types::{Digest, SignedBatchSnapshot, EpochSnapshot};
use std::collections::HashMap;

use crate::error::{SessionState, SignerError, SignerResult};
use crate::signer_set::SignerSet;

/// Signature from a signer
#[derive(Debug, Clone)]
pub struct SignerSignature {
    /// Signer's public key
    pub signer_pubkey: String,
    /// Signer index in the set
    pub signer_index: usize,
    /// The signature bytes (Ed25519)
    pub signature: Vec<u8>,
    /// When the signature was received
    pub received_at: DateTime<Utc>,
}

/// Type of snapshot being signed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotType {
    Batch,
    Epoch,
}

/// A signing session for a batch or epoch
pub struct SigningSession {
    /// Session ID
    pub session_id: String,
    /// Type of snapshot
    pub snapshot_type: SnapshotType,
    /// The message being signed (snapshot signing message)
    pub message: Vec<u8>,
    /// The digest of the message
    pub message_digest: Digest,
    /// Reference to the signer set
    pub signer_set_version: String,
    /// Collected signatures
    signatures: HashMap<String, SignerSignature>,
    /// Signer indices that have signed
    signed_indices: Vec<usize>,
    /// Current state
    state: SessionState,
    /// When the session was created
    pub created_at: DateTime<Utc>,
    /// When the session expires
    pub expires_at: DateTime<Utc>,
    /// Required threshold
    threshold: u32,
}

impl SigningSession {
    /// Default session timeout (5 minutes)
    pub const DEFAULT_TIMEOUT_SECS: i64 = 300;

    /// Create a new signing session for a batch
    pub fn for_batch(
        session_id: String,
        snapshot: &SignedBatchSnapshot,
        signer_set: &SignerSet,
    ) -> Self {
        let message = snapshot.signing_message();
        let message_digest = Digest::blake3(&message);
        let now = Utc::now();

        Self {
            session_id,
            snapshot_type: SnapshotType::Batch,
            message,
            message_digest,
            signer_set_version: signer_set.version_string(),
            signatures: HashMap::new(),
            signed_indices: Vec::new(),
            state: SessionState::Pending,
            created_at: now,
            expires_at: now + Duration::seconds(Self::DEFAULT_TIMEOUT_SECS),
            threshold: signer_set.threshold(),
        }
    }

    /// Create a new signing session for an epoch
    pub fn for_epoch(
        session_id: String,
        snapshot: &EpochSnapshot,
        signer_set: &SignerSet,
    ) -> Self {
        // Epoch snapshot signing message
        let mut message = Vec::new();
        message.extend_from_slice(b"L0:EpochSnapshotMsg:v1\0");
        message.extend_from_slice(snapshot.epoch_root.as_bytes());
        message.extend_from_slice(snapshot.epoch_window_start.to_rfc3339().as_bytes());
        message.extend_from_slice(b"\0");
        message.extend_from_slice(snapshot.epoch_window_end.to_rfc3339().as_bytes());
        message.extend_from_slice(b"\0");
        message.extend_from_slice(&snapshot.epoch_sequence_no.to_le_bytes());

        let message_digest = Digest::blake3(&message);
        let now = Utc::now();

        Self {
            session_id,
            snapshot_type: SnapshotType::Epoch,
            message,
            message_digest,
            signer_set_version: signer_set.version_string(),
            signatures: HashMap::new(),
            signed_indices: Vec::new(),
            state: SessionState::Pending,
            created_at: now,
            expires_at: now + Duration::seconds(Self::DEFAULT_TIMEOUT_SECS),
            threshold: signer_set.threshold(),
        }
    }

    /// Get the current state
    pub fn state(&self) -> SessionState {
        if self.is_expired() && !self.state.is_terminal() {
            SessionState::Failed
        } else {
            self.state
        }
    }

    /// Check if the session is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if threshold is met
    pub fn threshold_met(&self) -> bool {
        self.signatures.len() as u32 >= self.threshold
    }

    /// Get the number of signatures collected
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    /// Add a signature from a signer
    pub fn add_signature(
        &mut self,
        signer_pubkey: String,
        signer_index: usize,
        signature: Vec<u8>,
    ) -> SignerResult<()> {
        // Check session state
        if !self.state.can_accept_signature() {
            return Err(SignerError::SessionComplete);
        }

        if self.is_expired() {
            self.state = SessionState::Failed;
            return Err(SignerError::SessionExpired);
        }

        // Check for duplicate
        if self.signatures.contains_key(&signer_pubkey) {
            return Err(SignerError::DuplicateSignature(signer_pubkey));
        }

        // Add the signature
        let sig = SignerSignature {
            signer_pubkey: signer_pubkey.clone(),
            signer_index,
            signature,
            received_at: Utc::now(),
        };
        self.signatures.insert(signer_pubkey, sig);
        self.signed_indices.push(signer_index);

        // Update state
        if self.state == SessionState::Pending {
            self.state = SessionState::Collecting;
        }
        if self.threshold_met() {
            self.state = SessionState::ThresholdMet;
        }

        Ok(())
    }

    /// Get all collected signatures
    pub fn signatures(&self) -> Vec<&SignerSignature> {
        self.signatures.values().collect()
    }

    /// Get signed indices (for bitmap)
    pub fn signed_indices(&self) -> &[usize] {
        &self.signed_indices
    }

    /// Finalize the session and produce aggregated proof
    pub fn finalize(&mut self, signer_set: &SignerSet) -> SignerResult<ThresholdProof> {
        if !self.threshold_met() {
            return Err(SignerError::ThresholdNotMet {
                got: self.signature_count() as u32,
                need: self.threshold,
            });
        }

        // Create the bitmap
        let bitmap = signer_set.create_bitmap(&self.signed_indices);

        // Aggregate signatures (in phase 1, we concatenate them)
        // In production, this would use BLS aggregation or multi-sig
        let mut aggregated = Vec::new();
        for sig in self.signatures.values() {
            aggregated.extend(&sig.signature);
        }

        self.state = SessionState::Signed;

        Ok(ThresholdProof {
            session_id: self.session_id.clone(),
            signer_set_version: self.signer_set_version.clone(),
            signature_bitmap: bitmap,
            threshold_proof: hex::encode(&aggregated),
            signature_count: self.signature_count() as u32,
            threshold: self.threshold,
            finalized_at: Utc::now(),
        })
    }
}

/// The aggregated threshold proof
#[derive(Debug, Clone)]
pub struct ThresholdProof {
    /// Session ID
    pub session_id: String,
    /// Signer set version
    pub signer_set_version: String,
    /// Bitmap of which signers signed
    pub signature_bitmap: String,
    /// Aggregated proof (hex encoded)
    pub threshold_proof: String,
    /// Number of signatures
    pub signature_count: u32,
    /// Required threshold
    pub threshold: u32,
    /// When finalized
    pub finalized_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer_set::SignerInfo;

    fn make_test_set() -> SignerSet {
        let signers: Vec<SignerInfo> = (0..9)
            .map(|i| SignerInfo {
                pubkey: format!("pubkey_{}", i),
                node_id: format!("node_{}", i),
                is_observer: false,
                added_at: Utc::now(),
            })
            .collect();
        SignerSet::new("test".to_string(), 1, signers, vec![], Utc::now(), None).unwrap()
    }

    fn make_test_snapshot() -> SignedBatchSnapshot {
        SignedBatchSnapshot {
            snapshot_id: "test_snapshot".to_string(),
            batch_root: Digest::zero(),
            time_window_start: Utc::now(),
            time_window_end: Utc::now(),
            batch_sequence_no: 1,
            parent_batch_root: None,
            signer_set_version: "test:1".to_string(),
            canonicalization_version: "v1".to_string(),
            anchor_policy_version: "v1".to_string(),
            fee_schedule_version: "v1".to_string(),
            threshold_rule: "5/9".to_string(),
            signature_bitmap: String::new(),
            threshold_proof: String::new(),
            observer_reports_digest: None,
        }
    }

    #[test]
    fn test_session_requires_threshold() {
        let set = make_test_set();
        let snapshot = make_test_snapshot();
        let mut session = SigningSession::for_batch("sess_1".to_string(), &snapshot, &set);

        // Add 4 signatures (below threshold)
        for i in 0..4 {
            session
                .add_signature(format!("pubkey_{}", i), i, vec![0u8; 64])
                .unwrap();
        }

        assert!(!session.threshold_met());
        assert!(session.finalize(&set).is_err());

        // Add 5th signature
        session
            .add_signature("pubkey_4".to_string(), 4, vec![0u8; 64])
            .unwrap();

        assert!(session.threshold_met());
        assert!(session.finalize(&set).is_ok());
    }

    #[test]
    fn test_duplicate_signature_rejected() {
        let set = make_test_set();
        let snapshot = make_test_snapshot();
        let mut session = SigningSession::for_batch("sess_1".to_string(), &snapshot, &set);

        session
            .add_signature("pubkey_0".to_string(), 0, vec![0u8; 64])
            .unwrap();

        let result = session.add_signature("pubkey_0".to_string(), 0, vec![0u8; 64]);
        assert!(result.is_err());
    }
}
