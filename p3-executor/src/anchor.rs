//! L0 Anchor Integration Module
//!
//! This module integrates P3 executor with the L0 P4 layer for blockchain anchoring.
//! It bridges P3 epoch proofs with Bitcoin/Atomicals anchoring.
//!
//! # Architecture
//!
//! ```text
//! P3 Executor                    L0 P4 Layer
//! ┌───────────────┐             ┌───────────────┐
//! │ EpochProofBuilder│           │  P4Client     │
//! │       ↓         │           │      ↓        │
//! │ EpochRoot      │──anchor──▶│ OP_RETURN TX  │
//! └───────────────┘             └───────────────┘
//!                                      ↓
//!                               Bitcoin Network
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use p3_executor::anchor::{P3Anchor, P3AnchorConfig};
//!
//! async fn example() {
//!     let config = P3AnchorConfig::development();
//!     let anchor = P3Anchor::new(config).await.unwrap();
//!
//!     // Anchor a P3 epoch
//!     let epoch_root = [0u8; 32];
//!     let result = anchor.anchor_p3_epoch(1, &epoch_root).await.unwrap();
//! }
//! ```

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use l0_core::epoch_proof::{EpochAnchorStatus, EpochProofBuilder};
use l0_core::types::Digest;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::error::{ExecutorError, ExecutorResult};

/// P3 Anchor status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum P3AnchorStatus {
    /// Anchor pending submission
    Pending,
    /// Anchor submitted to blockchain
    Submitted,
    /// Waiting for confirmations
    Confirming,
    /// Anchor finalized with sufficient confirmations
    Finalized,
    /// Anchor failed
    Failed,
}

impl From<EpochAnchorStatus> for P3AnchorStatus {
    fn from(status: EpochAnchorStatus) -> Self {
        match status {
            EpochAnchorStatus::Pending => P3AnchorStatus::Pending,
            EpochAnchorStatus::Submitted => P3AnchorStatus::Submitted,
            EpochAnchorStatus::Confirmed => P3AnchorStatus::Confirming,
            EpochAnchorStatus::Finalized => P3AnchorStatus::Finalized,
            EpochAnchorStatus::Failed => P3AnchorStatus::Failed,
        }
    }
}

/// P3 anchor record
#[derive(Debug, Clone)]
pub struct P3AnchorRecord {
    /// Epoch sequence number
    pub epoch_sequence: u64,
    /// Epoch root hash (P3 digest)
    pub epoch_root: [u8; 32],
    /// Anchor transaction ID
    pub txid: Option<String>,
    /// Current status
    pub status: P3AnchorStatus,
    /// Number of confirmations
    pub confirmations: u32,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Last updated timestamp
    pub updated_at: DateTime<Utc>,
    /// Error message if failed
    pub error: Option<String>,
}

impl P3AnchorRecord {
    /// Create a new pending anchor record
    pub fn new(epoch_sequence: u64, epoch_root: [u8; 32]) -> Self {
        let now = Utc::now();
        Self {
            epoch_sequence,
            epoch_root,
            txid: None,
            status: P3AnchorStatus::Pending,
            confirmations: 0,
            created_at: now,
            updated_at: now,
            error: None,
        }
    }

    /// Update status
    pub fn update_status(&mut self, status: P3AnchorStatus) {
        self.status = status;
        self.updated_at = Utc::now();
    }

    /// Set transaction ID
    pub fn with_txid(mut self, txid: String) -> Self {
        self.txid = Some(txid);
        self.status = P3AnchorStatus::Submitted;
        self.updated_at = Utc::now();
        self
    }

    /// Update confirmations
    pub fn update_confirmations(&mut self, confirmations: u32) {
        self.confirmations = confirmations;
        self.updated_at = Utc::now();
    }

    /// Mark as failed
    pub fn fail(&mut self, error: String) {
        self.status = P3AnchorStatus::Failed;
        self.error = Some(error);
        self.updated_at = Utc::now();
    }

    /// Check if finalized
    pub fn is_finalized(&self) -> bool {
        self.status == P3AnchorStatus::Finalized
    }
}

/// P3 Anchor configuration
#[derive(Debug, Clone)]
pub struct P3AnchorConfig {
    /// Enable Bitcoin anchoring
    pub enable_bitcoin: bool,
    /// Enable Atomicals anchoring
    pub enable_atomicals: bool,
    /// Required confirmations for finalization
    pub required_confirmations: u32,
    /// Confirmation check interval in seconds
    pub check_interval_secs: u64,
    /// Maximum retry attempts
    pub max_retries: u32,
    /// Retry delay in seconds
    pub retry_delay_secs: u64,
}

impl Default for P3AnchorConfig {
    fn default() -> Self {
        Self {
            enable_bitcoin: true,
            enable_atomicals: false,
            required_confirmations: 6,
            check_interval_secs: 60,
            max_retries: 3,
            retry_delay_secs: 300,
        }
    }
}

impl P3AnchorConfig {
    /// Development configuration (regtest)
    pub fn development() -> Self {
        Self {
            enable_bitcoin: true,
            enable_atomicals: false,
            required_confirmations: 1,
            check_interval_secs: 10,
            max_retries: 3,
            retry_delay_secs: 30,
        }
    }

    /// Testnet configuration
    pub fn testnet() -> Self {
        Self {
            enable_bitcoin: true,
            enable_atomicals: false,
            required_confirmations: 3,
            check_interval_secs: 60,
            max_retries: 5,
            retry_delay_secs: 180,
        }
    }

    /// Mainnet configuration
    pub fn mainnet() -> Self {
        Self {
            enable_bitcoin: true,
            enable_atomicals: true,
            required_confirmations: 6,
            check_interval_secs: 120,
            max_retries: 10,
            retry_delay_secs: 600,
        }
    }
}

/// P3 Anchor service trait
#[async_trait]
pub trait P3AnchorService: Send + Sync {
    /// Anchor a P3 epoch to the blockchain
    async fn anchor_epoch(
        &self,
        epoch_sequence: u64,
        epoch_root: &[u8; 32],
    ) -> ExecutorResult<String>;

    /// Get anchor status
    async fn get_anchor_status(&self, epoch_sequence: u64) -> Option<P3AnchorRecord>;

    /// Wait for anchor confirmation
    async fn wait_for_confirmation(&self, epoch_sequence: u64) -> ExecutorResult<P3AnchorRecord>;

    /// Verify an anchor on chain
    async fn verify_anchor(
        &self,
        txid: &str,
        epoch_sequence: u64,
        epoch_root: &[u8; 32],
    ) -> ExecutorResult<bool>;
}

/// Mock P3 Anchor service for testing
#[derive(Debug)]
pub struct MockP3Anchor {
    config: P3AnchorConfig,
    records: RwLock<HashMap<u64, P3AnchorRecord>>,
    next_txid: RwLock<u64>,
}

impl MockP3Anchor {
    /// Create a new mock anchor service
    pub fn new(config: P3AnchorConfig) -> Self {
        Self {
            config,
            records: RwLock::new(HashMap::new()),
            next_txid: RwLock::new(1),
        }
    }

    /// Generate a mock transaction ID
    async fn generate_txid(&self) -> String {
        let mut next = self.next_txid.write().await;
        let txid = format!(
            "{:064x}",
            *next
        );
        *next += 1;
        txid
    }
}

#[async_trait]
impl P3AnchorService for MockP3Anchor {
    async fn anchor_epoch(
        &self,
        epoch_sequence: u64,
        epoch_root: &[u8; 32],
    ) -> ExecutorResult<String> {
        let txid = self.generate_txid().await;

        let record = P3AnchorRecord::new(epoch_sequence, *epoch_root)
            .with_txid(txid.clone());

        let mut records = self.records.write().await;
        records.insert(epoch_sequence, record);

        debug!(
            "Mock anchor: epoch {} anchored with txid {}",
            epoch_sequence, txid
        );

        Ok(txid)
    }

    async fn get_anchor_status(&self, epoch_sequence: u64) -> Option<P3AnchorRecord> {
        let records = self.records.read().await;
        records.get(&epoch_sequence).cloned()
    }

    async fn wait_for_confirmation(&self, epoch_sequence: u64) -> ExecutorResult<P3AnchorRecord> {
        // In mock mode, immediately finalize
        let mut records = self.records.write().await;
        if let Some(record) = records.get_mut(&epoch_sequence) {
            record.update_confirmations(self.config.required_confirmations);
            record.update_status(P3AnchorStatus::Finalized);
            Ok(record.clone())
        } else {
            Err(ExecutorError::not_found("P3AnchorRecord", &epoch_sequence.to_string()))
        }
    }

    async fn verify_anchor(
        &self,
        txid: &str,
        epoch_sequence: u64,
        epoch_root: &[u8; 32],
    ) -> ExecutorResult<bool> {
        let records = self.records.read().await;
        if let Some(record) = records.get(&epoch_sequence) {
            Ok(record.txid.as_deref() == Some(txid) && record.epoch_root == *epoch_root)
        } else {
            Ok(false)
        }
    }
}

/// P3 Anchor manager
///
/// Coordinates P3 epoch anchoring with the L0 P4 layer.
pub struct P3AnchorManager {
    /// Configuration
    config: P3AnchorConfig,
    /// Anchor service
    anchor_service: Arc<dyn P3AnchorService>,
    /// Pending epochs waiting to be anchored
    pending_epochs: RwLock<Vec<PendingEpochAnchor>>,
}

/// Pending epoch anchor
#[derive(Debug, Clone)]
pub struct PendingEpochAnchor {
    /// Epoch sequence
    pub epoch_sequence: u64,
    /// Epoch root
    pub epoch_root: [u8; 32],
    /// Batch count
    pub batch_count: usize,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Retry count
    pub retry_count: u32,
}

impl P3AnchorManager {
    /// Create a new anchor manager with mock service
    pub fn new_mock(config: P3AnchorConfig) -> Self {
        Self {
            config: config.clone(),
            anchor_service: Arc::new(MockP3Anchor::new(config)),
            pending_epochs: RwLock::new(Vec::new()),
        }
    }

    /// Create with custom anchor service
    pub fn with_service(config: P3AnchorConfig, service: Arc<dyn P3AnchorService>) -> Self {
        Self {
            config,
            anchor_service: service,
            pending_epochs: RwLock::new(Vec::new()),
        }
    }

    /// Queue an epoch for anchoring
    pub async fn queue_epoch(
        &self,
        epoch_sequence: u64,
        epoch_root: [u8; 32],
        batch_count: usize,
    ) {
        let pending = PendingEpochAnchor {
            epoch_sequence,
            epoch_root,
            batch_count,
            created_at: Utc::now(),
            retry_count: 0,
        };

        let mut queue = self.pending_epochs.write().await;
        queue.push(pending);

        info!(
            "Epoch {} queued for anchoring ({} batches)",
            epoch_sequence, batch_count
        );
    }

    /// Anchor the next pending epoch
    pub async fn anchor_next(&self) -> ExecutorResult<Option<P3AnchorRecord>> {
        let pending = {
            let mut queue = self.pending_epochs.write().await;
            if queue.is_empty() {
                return Ok(None);
            }
            queue.remove(0)
        };

        info!(
            "Anchoring epoch {} with {} batches",
            pending.epoch_sequence, pending.batch_count
        );

        match self.anchor_service.anchor_epoch(pending.epoch_sequence, &pending.epoch_root).await {
            Ok(txid) => {
                info!(
                    "Epoch {} anchored: txid={}",
                    pending.epoch_sequence, txid
                );
                Ok(self.anchor_service.get_anchor_status(pending.epoch_sequence).await)
            }
            Err(e) => {
                error!(
                    "Failed to anchor epoch {}: {}",
                    pending.epoch_sequence, e
                );

                // Re-queue if retries remaining
                if pending.retry_count < self.config.max_retries {
                    let mut requeue = pending.clone();
                    requeue.retry_count += 1;

                    let mut queue = self.pending_epochs.write().await;
                    queue.push(requeue);

                    warn!(
                        "Epoch {} re-queued for retry (attempt {})",
                        pending.epoch_sequence,
                        pending.retry_count + 1
                    );
                }

                Err(e)
            }
        }
    }

    /// Anchor all pending epochs
    pub async fn anchor_all(&self) -> Vec<ExecutorResult<P3AnchorRecord>> {
        let mut results = Vec::new();

        loop {
            match self.anchor_next().await {
                Ok(Some(record)) => results.push(Ok(record)),
                Ok(None) => break,
                Err(e) => results.push(Err(e)),
            }
        }

        results
    }

    /// Get anchor status for an epoch
    pub async fn get_status(&self, epoch_sequence: u64) -> Option<P3AnchorRecord> {
        self.anchor_service.get_anchor_status(epoch_sequence).await
    }

    /// Wait for epoch confirmation
    pub async fn wait_for_confirmation(&self, epoch_sequence: u64) -> ExecutorResult<P3AnchorRecord> {
        self.anchor_service.wait_for_confirmation(epoch_sequence).await
    }

    /// Get pending epoch count
    pub async fn pending_count(&self) -> usize {
        self.pending_epochs.read().await.len()
    }

    /// Build epoch from proof batch and queue for anchoring
    pub async fn finalize_and_queue_epoch(
        &self,
        epoch_sequence: u64,
        batch_roots: Vec<([u8; 32], String, DateTime<Utc>)>,
    ) -> ExecutorResult<[u8; 32]> {
        if batch_roots.is_empty() {
            return Err(ExecutorError::verification_failed("No batches to finalize"));
        }

        // Build epoch proof using l0-core
        let mut builder = EpochProofBuilder::new(epoch_sequence);

        for (root, batch_id, timestamp) in &batch_roots {
            builder.add_batch(batch_id.clone(), Digest::new(*root), *timestamp);
        }

        let epoch_root = builder.compute_epoch_root()
            .map_err(|e| ExecutorError::ProofGenerationFailed {
                reason: e.to_string(),
            })?;

        let root_bytes = epoch_root.0;

        // Queue for anchoring
        self.queue_epoch(epoch_sequence, root_bytes, batch_roots.len()).await;

        info!(
            "Epoch {} finalized: root={}, batches={}",
            epoch_sequence,
            hex::encode(&root_bytes),
            batch_roots.len()
        );

        Ok(root_bytes)
    }
}

/// Statistics for anchor operations
#[derive(Debug, Clone, Default)]
pub struct AnchorStats {
    /// Total epochs anchored
    pub total_anchored: u64,
    /// Total epochs finalized
    pub total_finalized: u64,
    /// Total epochs failed
    pub total_failed: u64,
    /// Pending epochs
    pub pending: usize,
    /// Average confirmations
    pub avg_confirmations: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_anchor_service() {
        let config = P3AnchorConfig::development();
        let service = MockP3Anchor::new(config);

        let epoch_root = [0x42u8; 32];
        let txid = service.anchor_epoch(1, &epoch_root).await.unwrap();

        assert!(!txid.is_empty());
        assert_eq!(txid.len(), 64);

        let status = service.get_anchor_status(1).await.unwrap();
        assert_eq!(status.epoch_sequence, 1);
        assert_eq!(status.status, P3AnchorStatus::Submitted);
    }

    #[tokio::test]
    async fn test_mock_anchor_confirmation() {
        let config = P3AnchorConfig::development();
        let service = MockP3Anchor::new(config.clone());

        let epoch_root = [0x42u8; 32];
        service.anchor_epoch(1, &epoch_root).await.unwrap();

        let record = service.wait_for_confirmation(1).await.unwrap();
        assert_eq!(record.status, P3AnchorStatus::Finalized);
        assert_eq!(record.confirmations, config.required_confirmations);
    }

    #[tokio::test]
    async fn test_anchor_manager_queue() {
        let config = P3AnchorConfig::development();
        let manager = P3AnchorManager::new_mock(config);

        let epoch_root = [0x42u8; 32];
        manager.queue_epoch(1, epoch_root, 5).await;
        manager.queue_epoch(2, epoch_root, 3).await;

        assert_eq!(manager.pending_count().await, 2);
    }

    #[tokio::test]
    async fn test_anchor_manager_anchor_all() {
        let config = P3AnchorConfig::development();
        let manager = P3AnchorManager::new_mock(config);

        manager.queue_epoch(1, [0x01u8; 32], 2).await;
        manager.queue_epoch(2, [0x02u8; 32], 3).await;
        manager.queue_epoch(3, [0x03u8; 32], 4).await;

        let results = manager.anchor_all().await;
        assert_eq!(results.len(), 3);

        for result in results {
            assert!(result.is_ok());
        }

        assert_eq!(manager.pending_count().await, 0);
    }

    #[tokio::test]
    async fn test_anchor_record_lifecycle() {
        let mut record = P3AnchorRecord::new(1, [0x42u8; 32]);
        assert_eq!(record.status, P3AnchorStatus::Pending);

        record = record.with_txid("abc123".to_string());
        assert_eq!(record.status, P3AnchorStatus::Submitted);
        assert_eq!(record.txid, Some("abc123".to_string()));

        record.update_confirmations(3);
        assert_eq!(record.confirmations, 3);

        record.update_status(P3AnchorStatus::Finalized);
        assert!(record.is_finalized());
    }

    #[tokio::test]
    async fn test_anchor_verify() {
        let config = P3AnchorConfig::development();
        let service = MockP3Anchor::new(config);

        let epoch_root = [0x42u8; 32];
        let txid = service.anchor_epoch(1, &epoch_root).await.unwrap();

        // Correct verification
        assert!(service.verify_anchor(&txid, 1, &epoch_root).await.unwrap());

        // Wrong epoch
        assert!(!service.verify_anchor(&txid, 2, &epoch_root).await.unwrap());

        // Wrong root
        let wrong_root = [0x99u8; 32];
        assert!(!service.verify_anchor(&txid, 1, &wrong_root).await.unwrap());
    }

    #[tokio::test]
    async fn test_finalize_and_queue_epoch() {
        let config = P3AnchorConfig::development();
        let manager = P3AnchorManager::new_mock(config);

        let batch_roots = vec![
            ([0x01u8; 32], "batch:1".to_string(), Utc::now()),
            ([0x02u8; 32], "batch:2".to_string(), Utc::now()),
            ([0x03u8; 32], "batch:3".to_string(), Utc::now()),
        ];

        let epoch_root = manager.finalize_and_queue_epoch(1, batch_roots).await.unwrap();
        assert_ne!(epoch_root, [0u8; 32]);

        assert_eq!(manager.pending_count().await, 1);
    }

    #[test]
    fn test_config_presets() {
        let dev = P3AnchorConfig::development();
        assert_eq!(dev.required_confirmations, 1);

        let testnet = P3AnchorConfig::testnet();
        assert_eq!(testnet.required_confirmations, 3);

        let mainnet = P3AnchorConfig::mainnet();
        assert_eq!(mainnet.required_confirmations, 6);
        assert!(mainnet.enable_atomicals);
    }
}
