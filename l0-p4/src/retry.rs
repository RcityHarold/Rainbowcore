//! Transaction Retry Mechanism
//!
//! Handles automatic retry of failed or stuck transactions.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::bitcoin::BitcoinRpcClient;
use crate::config::P4Config;
use crate::error::{P4Error, P4Result};
use crate::monitor::{ConfirmationMonitor, TxStatus};
use crate::tx_builder::{AnchorData, AnchorTxBuilder, BuiltTransaction};

/// Retry strategy
#[derive(Debug, Clone)]
pub enum RetryStrategy {
    /// No retry
    None,
    /// Fixed delay between retries
    Fixed { delay_secs: u64 },
    /// Exponential backoff
    Exponential {
        initial_delay_secs: u64,
        max_delay_secs: u64,
        multiplier: f64,
    },
}

impl Default for RetryStrategy {
    fn default() -> Self {
        Self::Exponential {
            initial_delay_secs: 60,
            max_delay_secs: 3600,
            multiplier: 2.0,
        }
    }
}

impl RetryStrategy {
    /// Calculate delay for attempt number
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        match self {
            RetryStrategy::None => Duration::ZERO,
            RetryStrategy::Fixed { delay_secs } => Duration::from_secs(*delay_secs),
            RetryStrategy::Exponential {
                initial_delay_secs,
                max_delay_secs,
                multiplier,
            } => {
                let delay = (*initial_delay_secs as f64) * multiplier.powi(attempt as i32 - 1);
                let delay = delay.min(*max_delay_secs as f64);
                Duration::from_secs(delay as u64)
            }
        }
    }
}

/// Pending anchor task
#[derive(Debug, Clone)]
pub struct PendingAnchor {
    /// Epoch sequence
    pub epoch_sequence: u64,
    /// Epoch root
    pub epoch_root: [u8; 32],
    /// Current transaction ID (if any)
    pub current_txid: Option<String>,
    /// Number of attempts
    pub attempts: u32,
    /// Maximum attempts
    pub max_attempts: u32,
    /// Last attempt timestamp
    pub last_attempt: Option<chrono::DateTime<chrono::Utc>>,
    /// Last error message
    pub last_error: Option<String>,
    /// Status
    pub status: AnchorTaskStatus,
    /// Created timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Anchor task status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorTaskStatus {
    /// Pending - not yet attempted
    Pending,
    /// Submitted - waiting for confirmation
    Submitted,
    /// Confirmed - has confirmations
    Confirming,
    /// Finalized - complete
    Finalized,
    /// Failed - exceeded max attempts
    Failed,
    /// Replaced - replaced by another transaction
    Replaced,
}

/// Retry manager for anchor transactions
pub struct RetryManager {
    /// Bitcoin RPC client
    rpc: Arc<BitcoinRpcClient>,
    /// Transaction builder
    tx_builder: Arc<AnchorTxBuilder>,
    /// Confirmation monitor
    monitor: Arc<ConfirmationMonitor>,
    /// Configuration
    config: P4Config,
    /// Retry strategy
    strategy: RetryStrategy,
    /// Pending anchors
    pending: Arc<RwLock<Vec<PendingAnchor>>>,
    /// Is running
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl RetryManager {
    /// Create a new retry manager
    pub fn new(
        rpc: Arc<BitcoinRpcClient>,
        tx_builder: Arc<AnchorTxBuilder>,
        monitor: Arc<ConfirmationMonitor>,
        config: P4Config,
    ) -> Self {
        Self {
            rpc,
            tx_builder,
            monitor,
            config: config.clone(),
            strategy: RetryStrategy::Exponential {
                initial_delay_secs: config.retry_delay_secs,
                max_delay_secs: config.retry_delay_secs * 10,
                multiplier: 2.0,
            },
            pending: Arc::new(RwLock::new(Vec::new())),
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Set retry strategy
    pub fn with_strategy(mut self, strategy: RetryStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Add anchor task
    pub async fn add_anchor(
        &self,
        epoch_sequence: u64,
        epoch_root: [u8; 32],
    ) -> P4Result<()> {
        let task = PendingAnchor {
            epoch_sequence,
            epoch_root,
            current_txid: None,
            attempts: 0,
            max_attempts: self.config.max_retries,
            last_attempt: None,
            last_error: None,
            status: AnchorTaskStatus::Pending,
            created_at: chrono::Utc::now(),
        };

        let mut pending = self.pending.write().await;
        pending.push(task);

        info!("Added anchor task for epoch {}", epoch_sequence);
        Ok(())
    }

    /// Get all pending anchors
    pub async fn get_pending(&self) -> Vec<PendingAnchor> {
        let pending = self.pending.read().await;
        pending.clone()
    }

    /// Get anchor by epoch sequence
    pub async fn get_anchor(&self, epoch_sequence: u64) -> Option<PendingAnchor> {
        let pending = self.pending.read().await;
        pending.iter().find(|a| a.epoch_sequence == epoch_sequence).cloned()
    }

    /// Attempt to anchor an epoch
    pub async fn attempt_anchor(&self, epoch_sequence: u64) -> P4Result<String> {
        let mut pending = self.pending.write().await;
        let task = pending
            .iter_mut()
            .find(|a| a.epoch_sequence == epoch_sequence)
            .ok_or_else(|| P4Error::InvalidEpochRoot(format!("Epoch {} not found", epoch_sequence)))?;

        // Check if already finalized
        if task.status == AnchorTaskStatus::Finalized {
            return Err(P4Error::InvalidEpochRoot("Already finalized".to_string()));
        }

        // Check max attempts
        if task.attempts >= task.max_attempts {
            task.status = AnchorTaskStatus::Failed;
            return Err(P4Error::RetryExhausted {
                attempts: task.attempts,
                last_error: task.last_error.clone().unwrap_or_default(),
            });
        }

        // Increment attempt counter
        task.attempts += 1;
        task.last_attempt = Some(chrono::Utc::now());

        let epoch_root = task.epoch_root;
        drop(pending); // Release lock before making RPC calls

        // Build and broadcast transaction
        let result = self
            .tx_builder
            .anchor_epoch(epoch_sequence, &epoch_root, None)
            .await;

        // Update task based on result
        let (txid_result, attempts) = {
            let mut pending = self.pending.write().await;
            let task = pending
                .iter_mut()
                .find(|a| a.epoch_sequence == epoch_sequence)
                .ok_or_else(|| P4Error::InvalidEpochRoot(format!("Epoch {} not found", epoch_sequence)))?;

            let attempts = task.attempts;

            match &result {
                Ok(txid) => {
                    task.current_txid = Some(txid.clone());
                    task.status = AnchorTaskStatus::Submitted;
                    task.last_error = None;
                }
                Err(e) => {
                    task.last_error = Some(e.to_string());
                }
            }
            (result, attempts)
        };

        match txid_result {
            Ok(txid) => {
                // Add to monitor (lock is released now)
                self.monitor.add_transaction(&txid, epoch_sequence).await?;

                info!(
                    "Anchor transaction submitted for epoch {}: {} (attempt {})",
                    epoch_sequence, txid, attempts
                );

                Ok(txid)
            }
            Err(e) => {
                warn!(
                    "Anchor attempt {} failed for epoch {}: {}",
                    attempts, epoch_sequence, e
                );
                Err(e)
            }
        }
    }

    /// Process a single retry cycle
    pub async fn process_retries(&self) -> P4Result<Vec<String>> {
        let mut processed = Vec::new();
        let now = chrono::Utc::now();

        // Get tasks that need retry
        let tasks_to_retry: Vec<u64> = {
            let pending = self.pending.read().await;
            pending
                .iter()
                .filter(|task| {
                    // Only retry pending or failed tasks
                    if !matches!(
                        task.status,
                        AnchorTaskStatus::Pending | AnchorTaskStatus::Submitted
                    ) {
                        return false;
                    }

                    // Check if enough time has passed
                    if let Some(last_attempt) = task.last_attempt {
                        let delay = self.strategy.delay_for_attempt(task.attempts);
                        let next_attempt = last_attempt + chrono::Duration::from_std(delay).unwrap();
                        if now < next_attempt {
                            return false;
                        }
                    }

                    // Check if max attempts reached
                    task.attempts < task.max_attempts
                })
                .map(|t| t.epoch_sequence)
                .collect()
        };

        // Process each task
        for epoch_seq in tasks_to_retry {
            // First check if existing tx is still pending/confirming
            let current_txid = {
                let pending = self.pending.read().await;
                pending
                    .iter()
                    .find(|t| t.epoch_sequence == epoch_seq)
                    .and_then(|t| t.current_txid.clone())
            };

            if let Some(txid) = current_txid {
                // Check transaction status
                let status = self.monitor.check_transaction(&txid).await;
                match status {
                    Ok(TxStatus::Finalized { .. }) => {
                        // Mark as finalized
                        let mut pending = self.pending.write().await;
                        if let Some(task) = pending
                            .iter_mut()
                            .find(|t| t.epoch_sequence == epoch_seq)
                        {
                            task.status = AnchorTaskStatus::Finalized;
                            info!("Epoch {} anchor finalized: {}", epoch_seq, txid);
                        }
                        continue;
                    }
                    Ok(TxStatus::Confirming { .. }) | Ok(TxStatus::Pending) => {
                        // Still waiting, skip retry
                        debug!("Epoch {} tx {} still pending/confirming", epoch_seq, txid);
                        continue;
                    }
                    Ok(TxStatus::NotFound) => {
                        // Transaction dropped, retry
                        warn!("Epoch {} tx {} not found, will retry", epoch_seq, txid);
                    }
                    Ok(TxStatus::Failed { reason }) => {
                        // Transaction failed, retry
                        warn!("Epoch {} tx {} failed: {}, will retry", epoch_seq, txid, reason);
                    }
                    Err(e) => {
                        debug!("Failed to check tx {}: {}", txid, e);
                    }
                }
            }

            // Attempt retry
            match self.attempt_anchor(epoch_seq).await {
                Ok(txid) => {
                    processed.push(txid);
                }
                Err(P4Error::RetryExhausted { .. }) => {
                    warn!("Epoch {} retry exhausted", epoch_seq);
                }
                Err(e) => {
                    debug!("Epoch {} retry failed: {}", epoch_seq, e);
                }
            }
        }

        Ok(processed)
    }

    /// Update task status from monitor events
    pub async fn update_from_monitor(&self) {
        // Collect updates to make
        let updates: Vec<(u64, AnchorTaskStatus)> = {
            let pending = self.pending.read().await;
            let mut updates = Vec::new();

            for task in pending.iter() {
                if let Some(txid) = &task.current_txid {
                    if let Some(tx) = self.monitor.get_status(txid).await {
                        let new_status = match &tx.status {
                            TxStatus::Pending => AnchorTaskStatus::Submitted,
                            TxStatus::Confirming { .. } => AnchorTaskStatus::Confirming,
                            TxStatus::Finalized { .. } => AnchorTaskStatus::Finalized,
                            TxStatus::NotFound | TxStatus::Failed { .. } => AnchorTaskStatus::Pending,
                        };

                        if new_status != task.status {
                            updates.push((task.epoch_sequence, new_status));
                        }
                    }
                }
            }
            updates
        };

        // Apply updates
        if !updates.is_empty() {
            let mut pending = self.pending.write().await;
            for (epoch_seq, new_status) in updates {
                if let Some(task) = pending.iter_mut().find(|t| t.epoch_sequence == epoch_seq) {
                    task.status = new_status;
                }
            }
        }
    }

    /// Start background retry processing
    pub async fn start(&self) {
        if self
            .running
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            warn!("Retry manager already running");
            return;
        }

        let pending = self.pending.clone();
        let monitor = self.monitor.clone();
        let running = self.running.clone();
        let strategy = self.strategy.clone();
        let rpc = self.rpc.clone();
        let tx_builder = self.tx_builder.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            let interval_secs = config.retry_delay_secs;
            let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));

            info!("Retry manager started (interval: {}s)", interval_secs);

            while running.load(std::sync::atomic::Ordering::SeqCst) {
                interval.tick().await;

                // Create a temporary manager for processing
                let manager = RetryManager {
                    rpc: rpc.clone(),
                    tx_builder: tx_builder.clone(),
                    monitor: monitor.clone(),
                    config: config.clone(),
                    strategy: strategy.clone(),
                    pending: pending.clone(),
                    running: running.clone(),
                };

                // Process retries
                match manager.process_retries().await {
                    Ok(processed) => {
                        if !processed.is_empty() {
                            debug!("Processed {} retries", processed.len());
                        }
                    }
                    Err(e) => {
                        error!("Retry processing error: {}", e);
                    }
                }
            }

            info!("Retry manager stopped");
        });
    }

    /// Stop background retry processing
    pub fn stop(&self) {
        self.running
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// Check if manager is running
    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Remove completed anchors
    pub async fn cleanup_completed(&self) {
        let mut pending = self.pending.write().await;
        pending.retain(|task| {
            !matches!(task.status, AnchorTaskStatus::Finalized | AnchorTaskStatus::Failed)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_strategy_fixed() {
        let strategy = RetryStrategy::Fixed { delay_secs: 60 };
        assert_eq!(strategy.delay_for_attempt(1), Duration::from_secs(60));
        assert_eq!(strategy.delay_for_attempt(5), Duration::from_secs(60));
    }

    #[test]
    fn test_retry_strategy_exponential() {
        let strategy = RetryStrategy::Exponential {
            initial_delay_secs: 60,
            max_delay_secs: 3600,
            multiplier: 2.0,
        };

        assert_eq!(strategy.delay_for_attempt(1), Duration::from_secs(60));
        assert_eq!(strategy.delay_for_attempt(2), Duration::from_secs(120));
        assert_eq!(strategy.delay_for_attempt(3), Duration::from_secs(240));
        assert_eq!(strategy.delay_for_attempt(10), Duration::from_secs(3600)); // Capped at max
    }
}
