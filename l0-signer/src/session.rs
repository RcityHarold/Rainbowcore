//! Signing Session Management
//!
//! A signing session collects signatures from certified signers
//! until the 5/9 threshold is met. Includes timeout and retry logic.

use chrono::{DateTime, Duration, Utc};
use l0_core::types::{Digest, EpochSnapshot, SignedBatchSnapshot};
use std::collections::HashMap;

use crate::error::{SessionState, SignerError, SignerResult};
use crate::signer_set::SignerSet;

/// Session configuration for timeout and retry behavior
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Session timeout in seconds
    pub timeout_secs: i64,
    /// Maximum retry attempts
    pub max_retries: u32,
    /// Backoff multiplier for retries (timeout = base * multiplier^attempt)
    pub backoff_multiplier: f64,
    /// Minimum signatures to consider partial success
    pub min_signatures_for_partial: u32,
    /// Whether to allow partial finalization (below threshold)
    pub allow_partial: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 300, // 5 minutes
            max_retries: 3,
            backoff_multiplier: 1.5,
            min_signatures_for_partial: 3,
            allow_partial: false,
        }
    }
}

impl SessionConfig {
    /// Create a config with custom timeout
    pub fn with_timeout(timeout_secs: i64) -> Self {
        Self {
            timeout_secs,
            ..Default::default()
        }
    }

    /// Create a fast config for testing
    pub fn fast() -> Self {
        Self {
            timeout_secs: 10,
            max_retries: 2,
            backoff_multiplier: 1.2,
            min_signatures_for_partial: 2,
            allow_partial: false,
        }
    }

    /// Calculate timeout for a retry attempt
    pub fn timeout_for_attempt(&self, attempt: u32) -> i64 {
        let multiplier = self.backoff_multiplier.powi(attempt as i32);
        (self.timeout_secs as f64 * multiplier) as i64
    }
}

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

/// Record of a retry attempt
#[derive(Debug, Clone)]
pub struct RetryAttempt {
    /// Attempt number
    pub attempt: u32,
    /// When the attempt started
    pub started_at: DateTime<Utc>,
    /// When the attempt ended
    pub ended_at: DateTime<Utc>,
    /// Signatures collected during this attempt
    pub signatures_collected: u32,
    /// Reason for retry (if applicable)
    pub failure_reason: Option<String>,
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
    /// Session configuration
    config: SessionConfig,
    /// Current retry attempt (0 = first attempt)
    retry_attempt: u32,
    /// History of retry attempts
    retry_history: Vec<RetryAttempt>,
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
        Self::for_batch_with_config(session_id, snapshot, signer_set, SessionConfig::default())
    }

    /// Create a new signing session for a batch with custom config
    pub fn for_batch_with_config(
        session_id: String,
        snapshot: &SignedBatchSnapshot,
        signer_set: &SignerSet,
        config: SessionConfig,
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
            expires_at: now + Duration::seconds(config.timeout_secs),
            threshold: signer_set.threshold(),
            config,
            retry_attempt: 0,
            retry_history: Vec::new(),
        }
    }

    /// Create a new signing session for an epoch
    pub fn for_epoch(
        session_id: String,
        snapshot: &EpochSnapshot,
        signer_set: &SignerSet,
    ) -> Self {
        Self::for_epoch_with_config(session_id, snapshot, signer_set, SessionConfig::default())
    }

    /// Create a new signing session for an epoch with custom config
    pub fn for_epoch_with_config(
        session_id: String,
        snapshot: &EpochSnapshot,
        signer_set: &SignerSet,
        config: SessionConfig,
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
            expires_at: now + Duration::seconds(config.timeout_secs),
            threshold: signer_set.threshold(),
            config,
            retry_attempt: 0,
            retry_history: Vec::new(),
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

    /// Check if the session can be retried
    pub fn can_retry(&self) -> bool {
        // Cannot retry if already signed or if max retries exceeded
        if self.state == SessionState::Signed {
            return false;
        }
        self.retry_attempt < self.config.max_retries
    }

    /// Get the current retry count
    pub fn retry_count(&self) -> u32 {
        self.retry_attempt
    }

    /// Get time remaining before expiration
    pub fn time_remaining(&self) -> Duration {
        let now = Utc::now();
        if now >= self.expires_at {
            Duration::zero()
        } else {
            self.expires_at - now
        }
    }

    /// Get retry history
    pub fn retry_history(&self) -> &[RetryAttempt] {
        &self.retry_history
    }

    /// Retry the session (reset for another attempt)
    pub fn retry(&mut self) -> SignerResult<()> {
        if !self.can_retry() {
            return Err(SignerError::MaxRetriesExceeded(self.retry_attempt));
        }

        if self.state == SessionState::Signed {
            return Err(SignerError::SessionComplete);
        }

        // Record the current attempt in history
        let attempt = RetryAttempt {
            attempt: self.retry_attempt,
            started_at: self.created_at + Duration::seconds(
                if self.retry_attempt == 0 { 0 } else {
                    self.config.timeout_for_attempt(self.retry_attempt - 1)
                }
            ),
            ended_at: Utc::now(),
            signatures_collected: self.signature_count() as u32,
            failure_reason: Some(format!(
                "Timeout: collected {}/{} signatures",
                self.signature_count(),
                self.threshold
            )),
        };
        self.retry_history.push(attempt);

        // Increment retry counter
        self.retry_attempt += 1;

        // Reset session state
        self.signatures.clear();
        self.signed_indices.clear();
        self.state = SessionState::Pending;

        // Calculate new timeout with exponential backoff
        let new_timeout = self.config.timeout_for_attempt(self.retry_attempt);
        let now = Utc::now();
        self.expires_at = now + Duration::seconds(new_timeout);

        Ok(())
    }

    /// Finalize with partial signatures (if allowed by config)
    pub fn finalize_partial(&mut self, signer_set: &SignerSet) -> SignerResult<ThresholdProof> {
        if !self.config.allow_partial {
            return Err(SignerError::ThresholdNotMet {
                got: self.signature_count() as u32,
                need: self.threshold,
            });
        }

        if (self.signature_count() as u32) < self.config.min_signatures_for_partial {
            return Err(SignerError::ThresholdNotMet {
                got: self.signature_count() as u32,
                need: self.config.min_signatures_for_partial,
            });
        }

        // Create the bitmap
        let bitmap = signer_set.create_bitmap(&self.signed_indices);

        // Aggregate signatures
        let mut aggregated = Vec::new();
        for sig in self.signatures.values() {
            aggregated.extend(&sig.signature);
        }

        // Mark as signed but note it's partial
        self.state = SessionState::Signed;

        Ok(ThresholdProof {
            session_id: self.session_id.clone(),
            signer_set_version: self.signer_set_version.clone(),
            signature_bitmap: bitmap,
            threshold_proof: hex::encode(&aggregated),
            signature_count: self.signature_count() as u32,
            threshold: self.threshold, // Original threshold (not met)
            finalized_at: Utc::now(),
        })
    }

    /// Mark the session as failed
    pub fn fail(&mut self, reason: &str) {
        if !self.state.is_terminal() {
            // Record final attempt
            let attempt = RetryAttempt {
                attempt: self.retry_attempt,
                started_at: if self.retry_attempt == 0 {
                    self.created_at
                } else {
                    self.retry_history.last()
                        .map(|a| a.ended_at)
                        .unwrap_or(self.created_at)
                },
                ended_at: Utc::now(),
                signatures_collected: self.signature_count() as u32,
                failure_reason: Some(reason.to_string()),
            };
            self.retry_history.push(attempt);
            self.state = SessionState::Failed;
        }
    }

    /// Get the session configuration
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// Check if the session has failed after all retries
    pub fn is_permanently_failed(&self) -> bool {
        self.state == SessionState::Failed && !self.can_retry()
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

    #[test]
    fn test_session_config_timeout() {
        let config = SessionConfig::with_timeout(60);
        assert_eq!(config.timeout_secs, 60);
        assert_eq!(config.max_retries, 3);
    }

    #[test]
    fn test_session_config_backoff() {
        let config = SessionConfig::default();
        // timeout_secs = 300, backoff_multiplier = 1.5
        assert_eq!(config.timeout_for_attempt(0), 300);
        assert_eq!(config.timeout_for_attempt(1), 450); // 300 * 1.5
        assert_eq!(config.timeout_for_attempt(2), 675); // 300 * 1.5^2
    }

    #[test]
    fn test_session_retry() {
        let set = make_test_set();
        let snapshot = make_test_snapshot();
        let config = SessionConfig::fast();
        let mut session = SigningSession::for_batch_with_config(
            "sess_1".to_string(),
            &snapshot,
            &set,
            config,
        );

        // Add 2 signatures (below threshold)
        for i in 0..2 {
            session
                .add_signature(format!("pubkey_{}", i), i, vec![0u8; 64])
                .unwrap();
        }

        assert!(!session.threshold_met());
        assert!(session.can_retry());
        assert_eq!(session.retry_count(), 0);

        // Retry the session
        session.retry().unwrap();

        assert_eq!(session.retry_count(), 1);
        assert_eq!(session.signature_count(), 0); // Signatures cleared
        assert_eq!(session.retry_history().len(), 1);
        assert!(session.can_retry()); // Can still retry (max_retries = 2)
    }

    #[test]
    fn test_session_max_retries_exceeded() {
        let set = make_test_set();
        let snapshot = make_test_snapshot();
        let config = SessionConfig {
            max_retries: 1,
            ..SessionConfig::fast()
        };
        let mut session = SigningSession::for_batch_with_config(
            "sess_1".to_string(),
            &snapshot,
            &set,
            config,
        );

        // First retry
        session.retry().unwrap();
        assert_eq!(session.retry_count(), 1);
        assert!(!session.can_retry()); // max_retries = 1

        // Second retry should fail
        let result = session.retry();
        assert!(result.is_err());
    }

    #[test]
    fn test_session_partial_finalization() {
        let set = make_test_set();
        let snapshot = make_test_snapshot();
        let config = SessionConfig {
            allow_partial: true,
            min_signatures_for_partial: 3,
            ..SessionConfig::default()
        };
        let mut session = SigningSession::for_batch_with_config(
            "sess_1".to_string(),
            &snapshot,
            &set,
            config,
        );

        // Add 3 signatures (meets partial but not threshold)
        for i in 0..3 {
            session
                .add_signature(format!("pubkey_{}", i), i, vec![0u8; 64])
                .unwrap();
        }

        assert!(!session.threshold_met());

        // Partial finalization should work
        let result = session.finalize_partial(&set);
        assert!(result.is_ok());

        let proof = result.unwrap();
        assert_eq!(proof.signature_count, 3);
    }

    #[test]
    fn test_session_partial_finalization_not_allowed() {
        let set = make_test_set();
        let snapshot = make_test_snapshot();
        let config = SessionConfig {
            allow_partial: false,
            ..SessionConfig::default()
        };
        let mut session = SigningSession::for_batch_with_config(
            "sess_1".to_string(),
            &snapshot,
            &set,
            config,
        );

        // Add 3 signatures
        for i in 0..3 {
            session
                .add_signature(format!("pubkey_{}", i), i, vec![0u8; 64])
                .unwrap();
        }

        // Partial finalization should fail (not allowed)
        let result = session.finalize_partial(&set);
        assert!(result.is_err());
    }

    #[test]
    fn test_session_fail() {
        let set = make_test_set();
        let snapshot = make_test_snapshot();
        let mut session = SigningSession::for_batch("sess_1".to_string(), &snapshot, &set);

        session
            .add_signature("pubkey_0".to_string(), 0, vec![0u8; 64])
            .unwrap();

        session.fail("Network timeout");

        assert_eq!(session.state(), SessionState::Failed);
        assert_eq!(session.retry_history().len(), 1);
        assert_eq!(
            session.retry_history()[0].failure_reason.as_deref(),
            Some("Network timeout")
        );
    }
}
