//! Confirmation Monitor
//!
//! Monitors Bitcoin transactions for confirmations and handles finalization.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use crate::bitcoin::BitcoinRpcClient;
use crate::config::{BitcoinNetwork, P4Config};
use crate::error::{P4Error, P4Result};

/// Transaction status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxStatus {
    /// Transaction is in mempool
    Pending,
    /// Transaction has confirmations but not finalized
    Confirming { confirmations: u32 },
    /// Transaction is finalized (has required confirmations)
    Finalized { confirmations: u32, block_hash: String },
    /// Transaction was not found (may have been dropped)
    NotFound,
    /// Transaction failed
    Failed { reason: String },
}

/// Monitored transaction info
#[derive(Debug, Clone)]
pub struct MonitoredTx {
    /// Transaction ID
    pub txid: String,
    /// Epoch sequence this anchors
    pub epoch_sequence: u64,
    /// Current status
    pub status: TxStatus,
    /// Block hash if confirmed
    pub block_hash: Option<String>,
    /// Block height if confirmed
    pub block_height: Option<u64>,
    /// Number of confirmations
    pub confirmations: u32,
    /// Required confirmations
    pub required_confirmations: u32,
    /// Last checked timestamp
    pub last_checked: chrono::DateTime<chrono::Utc>,
    /// Number of times checked
    pub check_count: u32,
    /// Callback on finalization
    pub on_finalized: Option<String>,
}

/// Transaction confirmation event
#[derive(Debug, Clone)]
pub struct ConfirmationEvent {
    /// Transaction ID
    pub txid: String,
    /// Epoch sequence
    pub epoch_sequence: u64,
    /// New status
    pub status: TxStatus,
    /// Block hash
    pub block_hash: Option<String>,
    /// Block height
    pub block_height: Option<u64>,
    /// Confirmations
    pub confirmations: u32,
    /// Event timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Confirmation event handler
pub type EventHandler = Box<dyn Fn(ConfirmationEvent) + Send + Sync>;

/// Confirmation monitor
pub struct ConfirmationMonitor {
    /// Bitcoin RPC client
    rpc: Arc<BitcoinRpcClient>,
    /// Configuration
    config: P4Config,
    /// Network type
    network: BitcoinNetwork,
    /// Monitored transactions
    transactions: Arc<RwLock<HashMap<String, MonitoredTx>>>,
    /// Event handlers
    handlers: Arc<RwLock<Vec<EventHandler>>>,
    /// Is running
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl ConfirmationMonitor {
    /// Create a new confirmation monitor
    pub fn new(rpc: Arc<BitcoinRpcClient>, config: P4Config) -> Self {
        let network = config.bitcoin.network;
        Self {
            rpc,
            config,
            network,
            transactions: Arc::new(RwLock::new(HashMap::new())),
            handlers: Arc::new(RwLock::new(Vec::new())),
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Add transaction to monitor
    pub async fn add_transaction(&self, txid: &str, epoch_sequence: u64) -> P4Result<()> {
        let tx = MonitoredTx {
            txid: txid.to_string(),
            epoch_sequence,
            status: TxStatus::Pending,
            block_hash: None,
            block_height: None,
            confirmations: 0,
            required_confirmations: self.network.required_confirmations(),
            last_checked: chrono::Utc::now(),
            check_count: 0,
            on_finalized: None,
        };

        let mut transactions = self.transactions.write().await;
        transactions.insert(txid.to_string(), tx);

        info!("Added transaction {} for epoch {} to monitor", txid, epoch_sequence);
        Ok(())
    }

    /// Remove transaction from monitor
    pub async fn remove_transaction(&self, txid: &str) {
        let mut transactions = self.transactions.write().await;
        transactions.remove(txid);
        debug!("Removed transaction {} from monitor", txid);
    }

    /// Get transaction status
    pub async fn get_status(&self, txid: &str) -> Option<MonitoredTx> {
        let transactions = self.transactions.read().await;
        transactions.get(txid).cloned()
    }

    /// Get all monitored transactions
    pub async fn get_all_transactions(&self) -> Vec<MonitoredTx> {
        let transactions = self.transactions.read().await;
        transactions.values().cloned().collect()
    }

    /// Get finalized transactions
    pub async fn get_finalized(&self) -> Vec<MonitoredTx> {
        let transactions = self.transactions.read().await;
        transactions
            .values()
            .filter(|tx| matches!(tx.status, TxStatus::Finalized { .. }))
            .cloned()
            .collect()
    }

    /// Get pending transactions
    pub async fn get_pending(&self) -> Vec<MonitoredTx> {
        let transactions = self.transactions.read().await;
        transactions
            .values()
            .filter(|tx| !matches!(tx.status, TxStatus::Finalized { .. }))
            .cloned()
            .collect()
    }

    /// Register event handler
    pub async fn on_event(&self, handler: EventHandler) {
        let mut handlers = self.handlers.write().await;
        handlers.push(handler);
    }

    /// Check a single transaction
    pub async fn check_transaction(&self, txid: &str) -> P4Result<TxStatus> {
        let info = match self.rpc.get_transaction_info(txid).await {
            Ok(info) => info,
            Err(P4Error::TransactionNotFound(_)) => {
                // Check if it's in mempool
                if self.rpc.is_in_mempool(txid).await.unwrap_or(false) {
                    return Ok(TxStatus::Pending);
                }
                return Ok(TxStatus::NotFound);
            }
            Err(P4Error::RpcResponse { code: -5, .. }) => {
                // TX not found
                if self.rpc.is_in_mempool(txid).await.unwrap_or(false) {
                    return Ok(TxStatus::Pending);
                }
                return Ok(TxStatus::NotFound);
            }
            Err(e) => return Err(e),
        };

        let confirmations = info.confirmations;
        let required = self.network.required_confirmations();

        let status = if confirmations == 0 {
            TxStatus::Pending
        } else if confirmations >= required {
            TxStatus::Finalized {
                confirmations,
                block_hash: info.blockhash.clone().unwrap_or_default(),
            }
        } else {
            TxStatus::Confirming { confirmations }
        };

        // Update stored transaction
        let mut transactions = self.transactions.write().await;
        if let Some(tx) = transactions.get_mut(txid) {
            let old_status = tx.status.clone();
            tx.status = status.clone();
            tx.confirmations = confirmations;
            tx.block_hash = info.blockhash.clone();
            tx.block_height = info.blockheight;
            tx.last_checked = chrono::Utc::now();
            tx.check_count += 1;

            // Emit event if status changed
            if old_status != status {
                let event = ConfirmationEvent {
                    txid: txid.to_string(),
                    epoch_sequence: tx.epoch_sequence,
                    status: status.clone(),
                    block_hash: tx.block_hash.clone(),
                    block_height: tx.block_height,
                    confirmations,
                    timestamp: chrono::Utc::now(),
                };
                drop(transactions); // Release lock before calling handlers
                self.emit_event(event).await;
            }
        }

        Ok(status)
    }

    /// Emit event to all handlers
    async fn emit_event(&self, event: ConfirmationEvent) {
        let handlers = self.handlers.read().await;
        for handler in handlers.iter() {
            handler(event.clone());
        }
    }

    /// Run a single check cycle on all transactions
    pub async fn check_all(&self) -> P4Result<Vec<ConfirmationEvent>> {
        let txids: Vec<String> = {
            let transactions = self.transactions.read().await;
            transactions.keys().cloned().collect()
        };

        let mut events = Vec::new();

        for txid in txids {
            match self.check_transaction(&txid).await {
                Ok(status) => {
                    let tx = self.get_status(&txid).await;
                    if let Some(tx) = tx {
                        events.push(ConfirmationEvent {
                            txid: txid.clone(),
                            epoch_sequence: tx.epoch_sequence,
                            status,
                            block_hash: tx.block_hash,
                            block_height: tx.block_height,
                            confirmations: tx.confirmations,
                            timestamp: chrono::Utc::now(),
                        });
                    }
                }
                Err(e) => {
                    warn!("Failed to check transaction {}: {}", txid, e);
                }
            }
        }

        Ok(events)
    }

    /// Wait for transaction to be finalized
    pub async fn wait_for_confirmation(
        &self,
        txid: &str,
        timeout: Duration,
    ) -> P4Result<MonitoredTx> {
        let start = std::time::Instant::now();
        let check_interval = Duration::from_secs(self.config.confirmation_interval_secs);

        loop {
            // Check if timeout exceeded
            if start.elapsed() > timeout {
                return Err(P4Error::ConfirmationTimeout {
                    attempts: (timeout.as_secs() / check_interval.as_secs()) as u32,
                });
            }

            // Check transaction
            let status = self.check_transaction(txid).await?;

            match status {
                TxStatus::Finalized { .. } => {
                    let tx = self.get_status(txid).await.ok_or_else(|| {
                        P4Error::TransactionNotFound(txid.to_string())
                    })?;
                    return Ok(tx);
                }
                TxStatus::NotFound => {
                    return Err(P4Error::TransactionNotFound(txid.to_string()));
                }
                TxStatus::Failed { reason } => {
                    return Err(P4Error::TransactionBroadcast(reason));
                }
                _ => {
                    // Wait and check again
                    tokio::time::sleep(check_interval).await;
                }
            }
        }
    }

    /// Start background monitoring
    pub async fn start(&self) {
        if self
            .running
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            warn!("Monitor already running");
            return;
        }

        let rpc = self.rpc.clone();
        let transactions = self.transactions.clone();
        let handlers = self.handlers.clone();
        let running = self.running.clone();
        let interval_secs = self.config.confirmation_interval_secs;
        let network = self.network;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(interval_secs));

            info!("Confirmation monitor started (interval: {}s)", interval_secs);

            while running.load(std::sync::atomic::Ordering::SeqCst) {
                interval.tick().await;

                let txids: Vec<String> = {
                    let txs = transactions.read().await;
                    txs.keys().cloned().collect()
                };

                for txid in txids {
                    let info = match rpc.get_transaction_info(&txid).await {
                        Ok(info) => info,
                        Err(e) => {
                            debug!("Failed to get tx info for {}: {}", txid, e);
                            continue;
                        }
                    };

                    let confirmations = info.confirmations;
                    let required = network.required_confirmations();

                    let status = if confirmations == 0 {
                        TxStatus::Pending
                    } else if confirmations >= required {
                        TxStatus::Finalized {
                            confirmations,
                            block_hash: info.blockhash.clone().unwrap_or_default(),
                        }
                    } else {
                        TxStatus::Confirming { confirmations }
                    };

                    // Update and emit event
                    let mut txs = transactions.write().await;
                    if let Some(tx) = txs.get_mut(&txid) {
                        let old_status = tx.status.clone();
                        tx.status = status.clone();
                        tx.confirmations = confirmations;
                        tx.block_hash = info.blockhash.clone();
                        tx.block_height = info.blockheight;
                        tx.last_checked = chrono::Utc::now();
                        tx.check_count += 1;

                        if old_status != status {
                            let event = ConfirmationEvent {
                                txid: txid.clone(),
                                epoch_sequence: tx.epoch_sequence,
                                status: status.clone(),
                                block_hash: tx.block_hash.clone(),
                                block_height: tx.block_height,
                                confirmations,
                                timestamp: chrono::Utc::now(),
                            };

                            // Emit event
                            let hs = handlers.read().await;
                            for handler in hs.iter() {
                                handler(event.clone());
                            }

                            if matches!(status, TxStatus::Finalized { .. }) {
                                info!(
                                    "Transaction {} finalized at block {:?}",
                                    txid, tx.block_height
                                );
                            }
                        }
                    }
                }
            }

            info!("Confirmation monitor stopped");
        });
    }

    /// Stop background monitoring
    pub fn stop(&self) {
        self.running
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// Check if monitor is running
    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tx_status_equality() {
        let s1 = TxStatus::Pending;
        let s2 = TxStatus::Pending;
        assert_eq!(s1, s2);

        let s3 = TxStatus::Confirming { confirmations: 3 };
        let s4 = TxStatus::Confirming { confirmations: 3 };
        assert_eq!(s3, s4);

        let s5 = TxStatus::Confirming { confirmations: 4 };
        assert_ne!(s3, s5);
    }
}
