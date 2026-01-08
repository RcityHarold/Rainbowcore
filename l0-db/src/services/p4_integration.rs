//! P4 Layer Integration
//!
//! This module provides integration between the AnchorService and the P4 layer
//! for real blockchain anchoring operations.
//!
//! When the `p4` feature is enabled, the AnchorService can use the P4Client
//! to submit real transactions to Bitcoin and Atomicals.

#[cfg(feature = "p4")]
use l0_p4::{P4Client, P4Config, P4Error, P4Result};

use std::sync::Arc;
use tracing::{debug, error, info, warn};

use l0_core::error::LedgerError;
use l0_core::ledger::LedgerResult;
use l0_core::types::{AnchorChainType, AnchorStatus, Digest};

/// P4 Anchor Provider trait
///
/// Abstracts the blockchain anchoring operations, allowing for mock implementations
/// in testing and real P4Client implementations in production.
#[async_trait::async_trait]
pub trait AnchorProvider: Send + Sync {
    /// Submit an anchor transaction to the blockchain
    async fn submit_anchor(
        &self,
        chain_type: AnchorChainType,
        epoch_sequence: u64,
        epoch_root: &Digest,
    ) -> LedgerResult<String>;

    /// Check transaction confirmations
    async fn check_confirmations(&self, chain_type: AnchorChainType, tx_hash: &str) -> LedgerResult<u32>;

    /// Verify an anchor on chain
    async fn verify_anchor(
        &self,
        chain_type: AnchorChainType,
        tx_hash: &str,
        epoch_sequence: u64,
        epoch_root: &Digest,
    ) -> LedgerResult<bool>;

    /// Get required confirmations for a chain
    fn required_confirmations(&self, chain_type: AnchorChainType) -> u32;
}

/// Mock anchor provider for testing
pub struct MockAnchorProvider;

#[async_trait::async_trait]
impl AnchorProvider for MockAnchorProvider {
    async fn submit_anchor(
        &self,
        chain_type: AnchorChainType,
        epoch_sequence: u64,
        epoch_root: &Digest,
    ) -> LedgerResult<String> {
        // Generate deterministic mock tx hash
        let data = format!(
            "mock:{}:{}:{}",
            chain_type_str(chain_type),
            epoch_sequence,
            epoch_root.to_hex()
        );
        let hash = Digest::blake3(data.as_bytes());

        let tx_hash = match chain_type {
            AnchorChainType::Bitcoin | AnchorChainType::Atomicals => hash.to_hex(),
            AnchorChainType::Ethereum | AnchorChainType::Polygon => format!("0x{}", hash.to_hex()),
            AnchorChainType::Internal => format!("internal:{}", hash.to_hex()),
            AnchorChainType::Solana => format!("{}Sol", &hash.to_hex()[..44]),
        };

        info!(
            "Mock anchor submitted for epoch {} on {:?}: {}",
            epoch_sequence, chain_type, tx_hash
        );

        Ok(tx_hash)
    }

    async fn check_confirmations(&self, _chain_type: AnchorChainType, _tx_hash: &str) -> LedgerResult<u32> {
        // Mock: always return 6 confirmations
        Ok(6)
    }

    async fn verify_anchor(
        &self,
        _chain_type: AnchorChainType,
        _tx_hash: &str,
        _epoch_sequence: u64,
        _epoch_root: &Digest,
    ) -> LedgerResult<bool> {
        // Mock: always verify successfully
        Ok(true)
    }

    fn required_confirmations(&self, chain_type: AnchorChainType) -> u32 {
        match chain_type {
            AnchorChainType::Bitcoin | AnchorChainType::Atomicals => 6,
            AnchorChainType::Ethereum => 12,
            AnchorChainType::Polygon => 256,
            AnchorChainType::Solana => 32,
            AnchorChainType::Internal => 0,
        }
    }
}

/// P4 Client anchor provider (when p4 feature is enabled)
#[cfg(feature = "p4")]
pub struct P4AnchorProvider {
    client: Arc<P4Client>,
}

#[cfg(feature = "p4")]
impl P4AnchorProvider {
    /// Create a new P4 anchor provider
    pub async fn new(config: P4Config) -> LedgerResult<Self> {
        let client = P4Client::new(config)
            .await
            .map_err(|e| LedgerError::Storage(format!("P4 client init failed: {}", e)))?;

        Ok(Self {
            client: Arc::new(client),
        })
    }

    /// Create from existing P4 client
    pub fn from_client(client: Arc<P4Client>) -> Self {
        Self { client }
    }

    /// Get the underlying P4 client
    pub fn client(&self) -> &Arc<P4Client> {
        &self.client
    }

    /// Start background services
    pub async fn start_services(&self) {
        self.client.start_background_services().await;
    }

    /// Stop background services
    pub fn stop_services(&self) {
        self.client.stop_background_services();
    }
}

#[cfg(feature = "p4")]
#[async_trait::async_trait]
impl AnchorProvider for P4AnchorProvider {
    async fn submit_anchor(
        &self,
        chain_type: AnchorChainType,
        epoch_sequence: u64,
        epoch_root: &Digest,
    ) -> LedgerResult<String> {
        // Convert Digest to [u8; 32]
        let root_bytes: [u8; 32] = *epoch_root.as_bytes();

        self.client
            .anchor_epoch_to_chain(chain_type, epoch_sequence, &root_bytes)
            .await
            .map_err(|e| LedgerError::Storage(format!("P4 anchor failed: {}", e)))
    }

    async fn check_confirmations(&self, _chain_type: AnchorChainType, tx_hash: &str) -> LedgerResult<u32> {
        self.client
            .get_confirmations(tx_hash)
            .await
            .map_err(|e| LedgerError::Storage(format!("P4 confirmation check failed: {}", e)))
    }

    async fn verify_anchor(
        &self,
        _chain_type: AnchorChainType,
        tx_hash: &str,
        epoch_sequence: u64,
        epoch_root: &Digest,
    ) -> LedgerResult<bool> {
        let root_bytes: [u8; 32] = *epoch_root.as_bytes();

        self.client
            .verify_anchor(tx_hash, epoch_sequence, &root_bytes)
            .await
            .map_err(|e| LedgerError::Storage(format!("P4 verify failed: {}", e)))
    }

    fn required_confirmations(&self, chain_type: AnchorChainType) -> u32 {
        match chain_type {
            AnchorChainType::Bitcoin | AnchorChainType::Atomicals => {
                self.client.config().bitcoin.network.required_confirmations()
            }
            AnchorChainType::Ethereum => 12,
            AnchorChainType::Polygon => 256,
            AnchorChainType::Solana => 32,
            AnchorChainType::Internal => 0,
        }
    }
}

/// Create default anchor provider based on feature flags
#[cfg(feature = "p4")]
pub async fn create_anchor_provider(config: Option<P4Config>) -> LedgerResult<Box<dyn AnchorProvider>> {
    match config {
        Some(cfg) => {
            let provider = P4AnchorProvider::new(cfg).await?;
            Ok(Box::new(provider))
        }
        None => Ok(Box::new(MockAnchorProvider)),
    }
}

#[cfg(not(feature = "p4"))]
pub async fn create_anchor_provider(_config: Option<()>) -> LedgerResult<Box<dyn AnchorProvider>> {
    Ok(Box::new(MockAnchorProvider))
}

/// Helper function to convert chain type to string
fn chain_type_str(chain_type: AnchorChainType) -> &'static str {
    match chain_type {
        AnchorChainType::Bitcoin => "bitcoin",
        AnchorChainType::Atomicals => "atomicals",
        AnchorChainType::Ethereum => "ethereum",
        AnchorChainType::Polygon => "polygon",
        AnchorChainType::Solana => "solana",
        AnchorChainType::Internal => "internal",
    }
}

// ============================================================================
// P4 Anchor Manager - Extended functionality for production use
// ============================================================================

use std::collections::HashMap;
use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};

/// Anchor submission status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorSubmission {
    /// Submission ID
    pub submission_id: String,
    /// Chain type
    pub chain_type: AnchorChainType,
    /// Epoch sequence number
    pub epoch_sequence: u64,
    /// Epoch root digest
    pub epoch_root: Digest,
    /// Transaction hash (once submitted)
    pub tx_hash: Option<String>,
    /// Current status
    pub status: AnchorSubmissionStatus,
    /// Number of confirmations
    pub confirmations: u32,
    /// Submission timestamp
    pub submitted_at: Option<DateTime<Utc>>,
    /// Confirmation timestamp
    pub confirmed_at: Option<DateTime<Utc>>,
    /// Number of retry attempts
    pub retry_count: u32,
    /// Last error message
    pub last_error: Option<String>,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
}

/// Anchor submission status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorSubmissionStatus {
    /// Pending submission
    Pending,
    /// Submitted to chain
    Submitted,
    /// Waiting for confirmations
    Confirming,
    /// Confirmed and finalized
    Confirmed,
    /// Submission failed
    Failed,
    /// Verification failed
    VerificationFailed,
}

/// Anchor manager configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorManagerConfig {
    /// Maximum retry attempts per submission
    pub max_retries: u32,
    /// Retry delay in seconds
    pub retry_delay_secs: u64,
    /// Confirmation check interval in seconds
    pub confirmation_check_interval_secs: u64,
    /// Enable automatic retries
    pub auto_retry: bool,
    /// Enable batch submissions
    pub batch_submissions: bool,
    /// Maximum batch size
    pub max_batch_size: usize,
}

impl Default for AnchorManagerConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            retry_delay_secs: 60,
            confirmation_check_interval_secs: 30,
            auto_retry: true,
            batch_submissions: false,
            max_batch_size: 10,
        }
    }
}

/// P4 Anchor Manager - manages anchor submissions with retry and confirmation tracking
pub struct AnchorManager {
    provider: Box<dyn AnchorProvider>,
    config: AnchorManagerConfig,
    submissions: std::sync::Mutex<HashMap<String, AnchorSubmission>>,
}

impl AnchorManager {
    /// Create a new anchor manager
    pub fn new(provider: Box<dyn AnchorProvider>, config: AnchorManagerConfig) -> Self {
        Self {
            provider,
            config,
            submissions: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Submit an anchor with tracking
    pub async fn submit(
        &self,
        chain_type: AnchorChainType,
        epoch_sequence: u64,
        epoch_root: Digest,
    ) -> LedgerResult<String> {
        let submission_id = format!(
            "anchor:{}:{}:{}",
            chain_type_str(chain_type),
            epoch_sequence,
            Utc::now().timestamp_millis()
        );

        let mut submission = AnchorSubmission {
            submission_id: submission_id.clone(),
            chain_type,
            epoch_sequence,
            epoch_root: epoch_root.clone(),
            tx_hash: None,
            status: AnchorSubmissionStatus::Pending,
            confirmations: 0,
            submitted_at: None,
            confirmed_at: None,
            retry_count: 0,
            last_error: None,
            created_at: Utc::now(),
        };

        // Store submission
        {
            let mut submissions = self.submissions.lock()
                .map_err(|_| LedgerError::Storage("Lock poisoned".to_string()))?;
            submissions.insert(submission_id.clone(), submission.clone());
        }

        // Attempt submission
        match self.provider.submit_anchor(chain_type, epoch_sequence, &epoch_root).await {
            Ok(tx_hash) => {
                submission.tx_hash = Some(tx_hash.clone());
                submission.status = AnchorSubmissionStatus::Submitted;
                submission.submitted_at = Some(Utc::now());

                self.update_submission(&submission)?;

                info!(
                    "Anchor submitted: {} -> {} on {:?}",
                    submission_id, tx_hash, chain_type
                );

                Ok(submission_id)
            }
            Err(e) => {
                submission.status = AnchorSubmissionStatus::Failed;
                submission.last_error = Some(e.to_string());
                submission.retry_count = 1;

                self.update_submission(&submission)?;

                error!("Anchor submission failed: {}", e);
                Err(e)
            }
        }
    }

    /// Check and update confirmation status
    pub async fn check_confirmation(&self, submission_id: &str) -> LedgerResult<AnchorSubmission> {
        let submission = {
            let submissions = self.submissions.lock()
                .map_err(|_| LedgerError::Storage("Lock poisoned".to_string()))?;
            submissions.get(submission_id).cloned()
                .ok_or_else(|| LedgerError::NotFound(format!("Submission not found: {}", submission_id)))?
        };

        let tx_hash = submission.tx_hash.as_ref()
            .ok_or_else(|| LedgerError::InvalidOperation("No tx_hash for submission".to_string()))?;

        let confirmations = self.provider
            .check_confirmations(submission.chain_type, tx_hash)
            .await?;

        let required = self.provider.required_confirmations(submission.chain_type);

        let mut updated = submission.clone();
        updated.confirmations = confirmations;

        if confirmations >= required {
            // Verify the anchor
            let verified = self.provider
                .verify_anchor(
                    submission.chain_type,
                    tx_hash,
                    submission.epoch_sequence,
                    &submission.epoch_root,
                )
                .await?;

            if verified {
                updated.status = AnchorSubmissionStatus::Confirmed;
                updated.confirmed_at = Some(Utc::now());
                info!(
                    "Anchor confirmed: {} with {} confirmations",
                    submission_id, confirmations
                );
            } else {
                updated.status = AnchorSubmissionStatus::VerificationFailed;
                updated.last_error = Some("Anchor verification failed".to_string());
                warn!("Anchor verification failed: {}", submission_id);
            }
        } else {
            updated.status = AnchorSubmissionStatus::Confirming;
            debug!(
                "Anchor {} has {} of {} confirmations",
                submission_id, confirmations, required
            );
        }

        self.update_submission(&updated)?;
        Ok(updated)
    }

    /// Retry a failed submission
    pub async fn retry(&self, submission_id: &str) -> LedgerResult<()> {
        let submission = {
            let submissions = self.submissions.lock()
                .map_err(|_| LedgerError::Storage("Lock poisoned".to_string()))?;
            submissions.get(submission_id).cloned()
                .ok_or_else(|| LedgerError::NotFound(format!("Submission not found: {}", submission_id)))?
        };

        if submission.status != AnchorSubmissionStatus::Failed {
            return Err(LedgerError::InvalidOperation(
                "Can only retry failed submissions".to_string()
            ));
        }

        if submission.retry_count >= self.config.max_retries {
            return Err(LedgerError::InvalidOperation(
                format!("Max retries ({}) exceeded", self.config.max_retries)
            ));
        }

        let mut updated = submission.clone();
        updated.retry_count += 1;

        match self.provider
            .submit_anchor(submission.chain_type, submission.epoch_sequence, &submission.epoch_root)
            .await
        {
            Ok(tx_hash) => {
                updated.tx_hash = Some(tx_hash);
                updated.status = AnchorSubmissionStatus::Submitted;
                updated.submitted_at = Some(Utc::now());
                updated.last_error = None;
            }
            Err(e) => {
                updated.last_error = Some(e.to_string());
            }
        }

        self.update_submission(&updated)
    }

    /// Get submission status
    pub fn get_submission(&self, submission_id: &str) -> LedgerResult<Option<AnchorSubmission>> {
        let submissions = self.submissions.lock()
            .map_err(|_| LedgerError::Storage("Lock poisoned".to_string()))?;
        Ok(submissions.get(submission_id).cloned())
    }

    /// Get all submissions for an epoch
    pub fn get_epoch_submissions(&self, epoch_sequence: u64) -> LedgerResult<Vec<AnchorSubmission>> {
        let submissions = self.submissions.lock()
            .map_err(|_| LedgerError::Storage("Lock poisoned".to_string()))?;
        Ok(submissions.values()
            .filter(|s| s.epoch_sequence == epoch_sequence)
            .cloned()
            .collect())
    }

    /// Get pending submissions
    pub fn get_pending_submissions(&self) -> LedgerResult<Vec<AnchorSubmission>> {
        let submissions = self.submissions.lock()
            .map_err(|_| LedgerError::Storage("Lock poisoned".to_string()))?;
        Ok(submissions.values()
            .filter(|s| matches!(
                s.status,
                AnchorSubmissionStatus::Pending |
                AnchorSubmissionStatus::Submitted |
                AnchorSubmissionStatus::Confirming
            ))
            .cloned()
            .collect())
    }

    /// Update submission in storage
    fn update_submission(&self, submission: &AnchorSubmission) -> LedgerResult<()> {
        let mut submissions = self.submissions.lock()
            .map_err(|_| LedgerError::Storage("Lock poisoned".to_string()))?;
        submissions.insert(submission.submission_id.clone(), submission.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_anchor_provider() {
        let provider = MockAnchorProvider;
        let epoch_root = Digest::blake3(b"test");

        let tx_hash = provider
            .submit_anchor(AnchorChainType::Bitcoin, 1, &epoch_root)
            .await
            .unwrap();

        assert!(!tx_hash.is_empty());
        assert!(!tx_hash.starts_with("0x")); // Bitcoin style

        let confirmations = provider
            .check_confirmations(AnchorChainType::Bitcoin, &tx_hash)
            .await
            .unwrap();

        assert_eq!(confirmations, 6);
    }

    #[tokio::test]
    async fn test_mock_anchor_provider_ethereum() {
        let provider = MockAnchorProvider;
        let epoch_root = Digest::blake3(b"test");

        let tx_hash = provider
            .submit_anchor(AnchorChainType::Ethereum, 1, &epoch_root)
            .await
            .unwrap();

        assert!(tx_hash.starts_with("0x"));
    }

    #[test]
    fn test_required_confirmations() {
        let provider = MockAnchorProvider;

        assert_eq!(provider.required_confirmations(AnchorChainType::Bitcoin), 6);
        assert_eq!(provider.required_confirmations(AnchorChainType::Ethereum), 12);
        assert_eq!(provider.required_confirmations(AnchorChainType::Internal), 0);
    }
}
