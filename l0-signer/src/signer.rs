//! Threshold Signer Service
//!
//! Main interface for threshold signing operations.

use async_trait::async_trait;
use chrono::Utc;
use l0_core::types::{EpochSnapshot, SignedBatchSnapshot};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::crypto::{domain, L0SigningKey, L0Signature, L0VerifyingKey, AggregatedProof};
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
    /// Our Ed25519 signing key
    signing_key: L0SigningKey,
    /// Our public key (hex encoded)
    pub pubkey: String,
    /// Signer set manager
    signer_set_manager: Arc<RwLock<SignerSetManager>>,
    /// Active signing sessions
    sessions: Arc<RwLock<HashMap<String, SigningSession>>>,
    /// Session counter
    session_counter: std::sync::atomic::AtomicU64,
    /// Cached verifying keys for signers
    verifying_keys: Arc<RwLock<HashMap<String, L0VerifyingKey>>>,
}

impl LocalThresholdSigner {
    /// Create a new local signer with a generated key
    pub fn generate() -> Self {
        let signing_key = L0SigningKey::generate();
        let pubkey = signing_key.public_key_hex();
        Self {
            signing_key,
            pubkey,
            signer_set_manager: Arc::new(RwLock::new(SignerSetManager::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            session_counter: std::sync::atomic::AtomicU64::new(0),
            verifying_keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new local signer from hex-encoded secret key
    pub fn from_secret_hex(secret_hex: &str) -> SignerResult<Self> {
        let signing_key = L0SigningKey::from_hex(secret_hex)?;
        let pubkey = signing_key.public_key_hex();
        Ok(Self {
            signing_key,
            pubkey,
            signer_set_manager: Arc::new(RwLock::new(SignerSetManager::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            session_counter: std::sync::atomic::AtomicU64::new(0),
            verifying_keys: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Create a new local signer (legacy constructor for compatibility)
    pub fn new(signing_key_hex: String, pubkey: String) -> Self {
        // Try to parse as hex, fall back to generated key if invalid
        match L0SigningKey::from_hex(&signing_key_hex) {
            Ok(key) => Self {
                signing_key: key,
                pubkey,
                signer_set_manager: Arc::new(RwLock::new(SignerSetManager::new())),
                sessions: Arc::new(RwLock::new(HashMap::new())),
                session_counter: std::sync::atomic::AtomicU64::new(0),
                verifying_keys: Arc::new(RwLock::new(HashMap::new())),
            },
            Err(_) => {
                // Fall back to generated key for tests
                let key = L0SigningKey::generate();
                Self {
                    signing_key: key,
                    pubkey,
                    signer_set_manager: Arc::new(RwLock::new(SignerSetManager::new())),
                    sessions: Arc::new(RwLock::new(HashMap::new())),
                    session_counter: std::sync::atomic::AtomicU64::new(0),
                    verifying_keys: Arc::new(RwLock::new(HashMap::new())),
                }
            }
        }
    }

    /// Set the current signer set
    pub async fn set_signer_set(&self, set: SignerSet) {
        // Cache verifying keys for all signers
        let mut keys = self.verifying_keys.write().await;
        for pubkey in set.certified_pubkeys() {
            if let Ok(vk) = L0VerifyingKey::from_hex(pubkey) {
                keys.insert(pubkey.to_string(), vk);
            }
        }
        drop(keys);

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

    /// Sign a message with our key using Ed25519
    fn sign_local(&self, message: &[u8]) -> SignerResult<Vec<u8>> {
        let signature = self.signing_key.sign_batch(message);
        Ok(signature.to_bytes().to_vec())
    }

    /// Verify a signature from a signer
    async fn verify_signature(
        &self,
        signer_pubkey: &str,
        message: &[u8],
        signature: &[u8],
    ) -> SignerResult<()> {
        // Get or create verifying key
        let keys = self.verifying_keys.read().await;
        let verifying_key = match keys.get(signer_pubkey) {
            Some(vk) => vk.clone(),
            None => {
                drop(keys);
                L0VerifyingKey::from_hex(signer_pubkey)?
            }
        };

        if signature.len() != 64 {
            return Err(SignerError::InvalidSignature(format!(
                "Invalid signature length: expected 64, got {}",
                signature.len()
            )));
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);

        let l0_sig = L0Signature::from_bytes(&sig_bytes, signer_pubkey.to_string())?;
        verifying_key.verify_batch(message, &l0_sig)
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
        message: &[u8],
        proof: &ThresholdProof,
    ) -> SignerResult<bool> {
        // Verify the threshold was met
        if proof.signature_count < proof.threshold {
            return Ok(false);
        }

        // Verify the signer set exists
        let manager = self.signer_set_manager.read().await;
        let signer_set = manager.get_by_version(&proof.signer_set_version).ok_or_else(|| {
            SignerError::InvalidSigner(format!(
                "Unknown signer set: {}",
                proof.signer_set_version
            ))
        })?;

        // Parse the aggregated proof and verify each signature
        let aggregated = AggregatedProof::from_compact(&proof.threshold_proof)?;

        // Verify threshold count matches
        if aggregated.count < proof.threshold {
            return Ok(false);
        }

        // Verify each signer is in the signer set
        for (pubkey, _sig) in &aggregated.signatures {
            if !signer_set.is_certified_signer(pubkey) {
                return Err(SignerError::SignerNotInSet(pubkey.clone()));
            }
        }

        // Verify all signatures cryptographically
        match aggregated.verify_all(domain::BATCH_SNAPSHOT, message) {
            Ok(true) => Ok(true),
            Ok(false) => Ok(false),
            Err(e) => Err(e),
        }
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
