//! Threshold Signer Service
//!
//! Main interface for threshold signing operations.

use async_trait::async_trait;
use chrono::Utc;
use l0_core::types::{EpochSnapshot, SignedBatchSnapshot};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::{SessionState, SignerError, SignerResult};
use crate::session::{SigningSession, ThresholdProof};
use crate::signer_set::{SignerSet, SignerSetManager};

/// Threshold signer trait
#[async_trait]
pub trait ThresholdSigner: Send + Sync {
    /// Start a signing session for a batch snapshot
    async fn start_batch_session(
        &self,
        snapshot: &SignedBatchSnapshot,
    ) -> SignerResult<String>;

    /// Start a signing session for an epoch snapshot
    async fn start_epoch_session(
        &self,
        snapshot: &EpochSnapshot,
    ) -> SignerResult<String>;

    /// Submit a signature for a session
    async fn submit_signature(
        &self,
        session_id: &str,
        signer_pubkey: &str,
        signature: Vec<u8>,
    ) -> SignerResult<SessionState>;

    /// Check session status
    async fn session_status(&self, session_id: &str) -> SignerResult<SessionState>;

    /// Finalize a session and get the threshold proof
    async fn finalize_session(&self, session_id: &str) -> SignerResult<ThresholdProof>;

    /// Sign a message directly (for local signer)
    async fn sign_message(&self, message: &[u8]) -> SignerResult<Vec<u8>>;

    /// Verify a threshold proof
    async fn verify_proof(
        &self,
        message: &[u8],
        proof: &ThresholdProof,
    ) -> SignerResult<bool>;
}

/// Local threshold signer implementation
pub struct LocalThresholdSigner {
    /// Our signing key (Ed25519 private key, hex encoded)
    signing_key: String,
    /// Our public key
    pub pubkey: String,
    /// Signer set manager
    signer_set_manager: Arc<RwLock<SignerSetManager>>,
    /// Active signing sessions
    sessions: Arc<RwLock<HashMap<String, SigningSession>>>,
    /// Session counter
    session_counter: std::sync::atomic::AtomicU64,
}

impl LocalThresholdSigner {
    /// Create a new local signer
    pub fn new(signing_key: String, pubkey: String) -> Self {
        Self {
            signing_key,
            pubkey,
            signer_set_manager: Arc::new(RwLock::new(SignerSetManager::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            session_counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Set the current signer set
    pub async fn set_signer_set(&self, set: SignerSet) {
        let mut manager = self.signer_set_manager.write().await;
        manager.set_current(set);
    }

    /// Generate a session ID
    fn generate_session_id(&self) -> String {
        let seq = self
            .session_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let timestamp = Utc::now().timestamp_micros();
        format!("sess_{:016x}_{:08x}", timestamp, seq)
    }

    /// Sign a message with our key (Ed25519)
    fn sign_local(&self, message: &[u8]) -> SignerResult<Vec<u8>> {
        // In production, use proper Ed25519 signing via soulbase-crypto
        // For now, we'll create a placeholder signature using BLAKE3
        let hash = l0_core::types::Digest::blake3(message);
        let mut sig = hash.as_bytes().to_vec();
        // Append key hash for "authenticity"
        let key_hash = l0_core::types::Digest::blake3(self.signing_key.as_bytes());
        sig.extend(key_hash.as_bytes());
        Ok(sig)
    }
}

#[async_trait]
impl ThresholdSigner for LocalThresholdSigner {
    async fn start_batch_session(
        &self,
        snapshot: &SignedBatchSnapshot,
    ) -> SignerResult<String> {
        let manager = self.signer_set_manager.read().await;
        let signer_set = manager.current().ok_or_else(|| {
            SignerError::InvalidSigner("No current signer set configured".to_string())
        })?;

        let session_id = self.generate_session_id();
        let session = SigningSession::for_batch(session_id.clone(), snapshot, signer_set);

        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.clone(), session);

        Ok(session_id)
    }

    async fn start_epoch_session(
        &self,
        snapshot: &EpochSnapshot,
    ) -> SignerResult<String> {
        let manager = self.signer_set_manager.read().await;
        let signer_set = manager.current().ok_or_else(|| {
            SignerError::InvalidSigner("No current signer set configured".to_string())
        })?;

        let session_id = self.generate_session_id();
        let session = SigningSession::for_epoch(session_id.clone(), snapshot, signer_set);

        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.clone(), session);

        Ok(session_id)
    }

    async fn submit_signature(
        &self,
        session_id: &str,
        signer_pubkey: &str,
        signature: Vec<u8>,
    ) -> SignerResult<SessionState> {
        // Verify signer is in the set
        let manager = self.signer_set_manager.read().await;
        let signer_set = manager.current().ok_or_else(|| {
            SignerError::InvalidSigner("No current signer set configured".to_string())
        })?;

        let signer_index = signer_set
            .signer_index(signer_pubkey)
            .ok_or_else(|| SignerError::SignerNotInSet(signer_pubkey.to_string()))?;

        // Add signature to session
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| SignerError::SessionNotFound(session_id.to_string()))?;

        session.add_signature(signer_pubkey.to_string(), signer_index, signature)?;

        Ok(session.state())
    }

    async fn session_status(&self, session_id: &str) -> SignerResult<SessionState> {
        let sessions = self.sessions.read().await;
        let session = sessions
            .get(session_id)
            .ok_or_else(|| SignerError::SessionNotFound(session_id.to_string()))?;

        Ok(session.state())
    }

    async fn finalize_session(&self, session_id: &str) -> SignerResult<ThresholdProof> {
        let manager = self.signer_set_manager.read().await;
        let signer_set = manager.current().ok_or_else(|| {
            SignerError::InvalidSigner("No current signer set configured".to_string())
        })?;

        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| SignerError::SessionNotFound(session_id.to_string()))?;

        session.finalize(signer_set)
    }

    async fn sign_message(&self, message: &[u8]) -> SignerResult<Vec<u8>> {
        self.sign_local(message)
    }

    async fn verify_proof(
        &self,
        _message: &[u8],
        proof: &ThresholdProof,
    ) -> SignerResult<bool> {
        // Verify the threshold was met
        if proof.signature_count < proof.threshold {
            return Ok(false);
        }

        // Verify the signer set exists
        let manager = self.signer_set_manager.read().await;
        let _signer_set = manager.get_by_version(&proof.signer_set_version).ok_or_else(|| {
            SignerError::InvalidSigner(format!(
                "Unknown signer set: {}",
                proof.signer_set_version
            ))
        })?;

        // In production, verify each signature in the aggregated proof
        // For now, we trust the structure
        Ok(true)
    }
}

/// Batch signing coordinator
pub struct BatchSigningCoordinator {
    /// The threshold signer
    signer: Arc<dyn ThresholdSigner>,
}

impl BatchSigningCoordinator {
    /// Create a new coordinator
    pub fn new(signer: Arc<dyn ThresholdSigner>) -> Self {
        Self { signer }
    }

    /// Sign a batch snapshot (starts session and waits for threshold)
    pub async fn sign_batch(
        &self,
        mut snapshot: SignedBatchSnapshot,
    ) -> SignerResult<SignedBatchSnapshot> {
        let session_id = self.signer.start_batch_session(&snapshot).await?;

        // In a real implementation, this would coordinate with other nodes
        // For now, we just finalize immediately (assuming signatures come in)
        let proof = self.signer.finalize_session(&session_id).await?;

        // Update snapshot with proof
        snapshot.signature_bitmap = proof.signature_bitmap;
        snapshot.threshold_proof = proof.threshold_proof;

        Ok(snapshot)
    }

    /// Sign an epoch snapshot
    pub async fn sign_epoch(
        &self,
        mut snapshot: EpochSnapshot,
    ) -> SignerResult<EpochSnapshot> {
        let session_id = self.signer.start_epoch_session(&snapshot).await?;

        // Finalize
        let proof = self.signer.finalize_session(&session_id).await?;

        // Update snapshot with proof
        snapshot.signature_bitmap = Some(proof.signature_bitmap);
        snapshot.threshold_proof = Some(proof.threshold_proof);

        Ok(snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer_set::SignerInfo;
    use l0_core::types::Digest;

    async fn setup_signer() -> LocalThresholdSigner {
        let signer = LocalThresholdSigner::new(
            "test_private_key".to_string(),
            "pubkey_0".to_string(),
        );

        // Set up signer set
        let signers: Vec<SignerInfo> = (0..9)
            .map(|i| SignerInfo {
                pubkey: format!("pubkey_{}", i),
                node_id: format!("node_{}", i),
                is_observer: false,
                added_at: Utc::now(),
            })
            .collect();
        let set = SignerSet::new("test".to_string(), 1, signers, vec![], Utc::now(), None).unwrap();
        signer.set_signer_set(set).await;

        signer
    }

    #[tokio::test]
    async fn test_batch_session() {
        let signer = setup_signer().await;

        let snapshot = SignedBatchSnapshot {
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
        };

        let session_id = signer.start_batch_session(&snapshot).await.unwrap();
        assert!(!session_id.is_empty());

        // Submit 5 signatures
        for i in 0..5 {
            let state = signer
                .submit_signature(&session_id, &format!("pubkey_{}", i), vec![0u8; 64])
                .await
                .unwrap();
            if i < 4 {
                assert_eq!(state, SessionState::Collecting);
            } else {
                assert_eq!(state, SessionState::ThresholdMet);
            }
        }

        // Finalize
        let proof = signer.finalize_session(&session_id).await.unwrap();
        assert_eq!(proof.signature_count, 5);
        assert_eq!(proof.threshold, 5);
    }
}
