//! L0 P4 Layer - Blockchain Anchoring
//!
//! This crate provides the P4 (Public Proof) layer for the L0 consensus system.
//! It handles anchoring L0 epoch roots to external blockchains, primarily
//! Bitcoin and the Atomicals protocol.
//!
//! # Architecture
//!
//! The P4 layer consists of several components:
//!
//! - **Bitcoin RPC Client**: Interfaces with Bitcoin Core for transaction operations
//! - **Transaction Builder**: Constructs OP_RETURN transactions with L0 anchor data
//! - **Atomicals Client**: Creates Atomicals inscriptions for anchor data
//! - **Confirmation Monitor**: Tracks transaction confirmations
//! - **Retry Manager**: Handles failed transaction retries with backoff
//!
//! # Anchor Data Format
//!
//! L0 anchors use a compact 49-byte format in OP_RETURN outputs:
//!
//! ```text
//! | Field        | Size | Description                    |
//! |--------------|------|--------------------------------|
//! | Magic        | 4    | "L0v1" = [0x4C, 0x30, 0x76, 0x31] |
//! | Version      | 1    | Protocol version (currently 1) |
//! | Epoch Seq    | 8    | Epoch sequence number (BE)     |
//! | Epoch Root   | 32   | Epoch Merkle root              |
//! | Checksum     | 4    | SHA256(above)[0:4]             |
//! ```
//!
//! # Usage
//!
//! ```rust,no_run
//! use l0_p4::{P4Client, P4Config};
//!
//! async fn example() {
//!     // Create client with default config
//!     let config = P4Config::development();
//!     let client = P4Client::new(config).await.unwrap();
//!
//!     // Anchor an epoch
//!     let epoch_root = [0u8; 32]; // Your epoch root
//!     let txid = client.anchor_epoch(1, &epoch_root).await.unwrap();
//!
//!     // Wait for confirmation
//!     client.wait_for_confirmation(&txid).await.unwrap();
//! }
//! ```

pub mod atomicals;
pub mod bitcoin;
pub mod config;
pub mod error;
pub mod monitor;
pub mod retry;
pub mod tx_builder;

pub use atomicals::{AtomicalsAnchorPayload, AtomicalsClient, AtomicalsCommitReveal};
pub use bitcoin::{BitcoinRpcClient, TransactionInfo, Utxo};
pub use config::{AtomicalsConfig, BitcoinNetwork, BitcoinRpcConfig, P4Config};
pub use error::{P4Error, P4Result};
pub use monitor::{ConfirmationEvent, ConfirmationMonitor, MonitoredTx, TxStatus};
pub use retry::{AnchorTaskStatus, PendingAnchor, RetryManager, RetryStrategy};
pub use tx_builder::{AnchorData, AnchorTxBuilder, BuiltTransaction, L0_ANCHOR_MAGIC};

use std::sync::Arc;
use std::time::Duration;
use l0_core::types::AnchorChainType;
use tracing::{debug, info, warn};

/// P4 Layer Client
///
/// Main interface for blockchain anchoring operations.
pub struct P4Client {
    /// Configuration
    config: P4Config,
    /// Bitcoin RPC client
    bitcoin_rpc: Arc<BitcoinRpcClient>,
    /// Transaction builder
    tx_builder: Arc<AnchorTxBuilder>,
    /// Atomicals client (optional)
    atomicals: Option<Arc<AtomicalsClient>>,
    /// Confirmation monitor
    monitor: Arc<ConfirmationMonitor>,
    /// Retry manager
    retry_manager: Arc<RetryManager>,
}

impl P4Client {
    /// Create a new P4 client
    pub async fn new(config: P4Config) -> P4Result<Self> {
        info!("Initializing P4 client");

        // Create Bitcoin RPC client
        let bitcoin_rpc = Arc::new(BitcoinRpcClient::new(config.bitcoin.clone())?);

        // Test connection
        bitcoin_rpc.ping().await.map_err(|e| {
            P4Error::RpcConnection(format!("Failed to connect to Bitcoin node: {}", e))
        })?;

        info!(
            "Connected to Bitcoin node at {}",
            config.bitcoin.url
        );

        // Create transaction builder
        let tx_builder = Arc::new(AnchorTxBuilder::new(bitcoin_rpc.clone(), config.clone()));

        // Create Atomicals client if enabled
        let atomicals = if config.enable_atomicals {
            if let Some(atomicals_config) = &config.atomicals {
                Some(Arc::new(AtomicalsClient::new(
                    bitcoin_rpc.clone(),
                    atomicals_config.clone(),
                )?))
            } else {
                warn!("Atomicals enabled but no configuration provided");
                None
            }
        } else {
            None
        };

        // Create confirmation monitor
        let monitor = Arc::new(ConfirmationMonitor::new(bitcoin_rpc.clone(), config.clone()));

        // Create retry manager
        let retry_manager = Arc::new(RetryManager::new(
            bitcoin_rpc.clone(),
            tx_builder.clone(),
            monitor.clone(),
            config.clone(),
        ));

        Ok(Self {
            config,
            bitcoin_rpc,
            tx_builder,
            atomicals,
            monitor,
            retry_manager,
        })
    }

    /// Anchor an epoch root to the blockchain
    ///
    /// This creates a Bitcoin transaction with an OP_RETURN output containing
    /// the L0 anchor data and broadcasts it to the network.
    pub async fn anchor_epoch(
        &self,
        epoch_sequence: u64,
        epoch_root: &[u8; 32],
    ) -> P4Result<String> {
        self.anchor_epoch_to_chain(AnchorChainType::Bitcoin, epoch_sequence, epoch_root)
            .await
    }

    /// Anchor an epoch root to a specific chain
    pub async fn anchor_epoch_to_chain(
        &self,
        chain_type: AnchorChainType,
        epoch_sequence: u64,
        epoch_root: &[u8; 32],
    ) -> P4Result<String> {
        match chain_type {
            AnchorChainType::Bitcoin => {
                if !self.config.enable_bitcoin {
                    return Err(P4Error::ChainNotSupported("Bitcoin not enabled".to_string()));
                }

                let txid = self
                    .tx_builder
                    .anchor_epoch(epoch_sequence, epoch_root, None)
                    .await?;

                // Add to monitor
                self.monitor.add_transaction(&txid, epoch_sequence).await?;

                Ok(txid)
            }
            AnchorChainType::Atomicals => {
                if !self.config.enable_atomicals {
                    return Err(P4Error::ChainNotSupported("Atomicals not enabled".to_string()));
                }

                let atomicals = self.atomicals.as_ref().ok_or_else(|| {
                    P4Error::ChainNotSupported("Atomicals client not initialized".to_string())
                })?;

                let result = atomicals
                    .create_anchor_inscription(epoch_sequence, epoch_root, "v1:1", None)
                    .await?;

                // Add reveal tx to monitor (the one that creates the atomical)
                self.monitor
                    .add_transaction(&result.reveal_txid, epoch_sequence)
                    .await?;

                Ok(result.reveal_txid)
            }
            AnchorChainType::Internal => {
                // Internal anchoring - just log and return a pseudo-txid
                let pseudo_txid = format!(
                    "internal:{:016x}:{}",
                    epoch_sequence,
                    hex::encode(&epoch_root[..8])
                );
                info!("Internal anchor for epoch {}: {}", epoch_sequence, pseudo_txid);
                Ok(pseudo_txid)
            }
            _ => Err(P4Error::ChainNotSupported(format!("{:?}", chain_type))),
        }
    }

    /// Wait for a transaction to be confirmed
    pub async fn wait_for_confirmation(&self, txid: &str) -> P4Result<MonitoredTx> {
        let timeout = Duration::from_secs(
            self.config.confirmation_interval_secs *
            (self.config.bitcoin.network.required_confirmations() as u64 + 10) *
            10 // ~10 minutes per block worst case
        );

        self.monitor.wait_for_confirmation(txid, timeout).await
    }

    /// Get transaction status
    pub async fn get_status(&self, txid: &str) -> Option<MonitoredTx> {
        self.monitor.get_status(txid).await
    }

    /// Check transaction confirmations
    pub async fn get_confirmations(&self, txid: &str) -> P4Result<u32> {
        self.bitcoin_rpc.get_transaction_confirmations(txid).await
    }

    /// Add anchor task to retry manager
    pub async fn queue_anchor(
        &self,
        epoch_sequence: u64,
        epoch_root: [u8; 32],
    ) -> P4Result<()> {
        self.retry_manager.add_anchor(epoch_sequence, epoch_root).await
    }

    /// Get pending anchor tasks
    pub async fn get_pending_anchors(&self) -> Vec<PendingAnchor> {
        self.retry_manager.get_pending().await
    }

    /// Start background services (monitor + retry)
    pub async fn start_background_services(&self) {
        self.monitor.start().await;
        self.retry_manager.start().await;
        info!("P4 background services started");
    }

    /// Stop background services
    pub fn stop_background_services(&self) {
        self.monitor.stop();
        self.retry_manager.stop();
        info!("P4 background services stopped");
    }

    /// Get blockchain info
    pub async fn get_blockchain_info(&self) -> P4Result<bitcoin::BlockchainInfo> {
        self.bitcoin_rpc.get_blockchain_info().await
    }

    /// Get current block height
    pub async fn get_block_height(&self) -> P4Result<u64> {
        self.bitcoin_rpc.get_block_count().await
    }

    /// Estimate fee rate (sat/vB)
    pub async fn estimate_fee_rate(&self, target_blocks: u32) -> P4Result<u64> {
        self.bitcoin_rpc.estimate_smart_fee(target_blocks).await
    }

    /// Verify an anchor on chain
    pub async fn verify_anchor(
        &self,
        txid: &str,
        expected_epoch: u64,
        expected_root: &[u8; 32],
    ) -> P4Result<bool> {
        // Get transaction
        let tx_info = self.bitcoin_rpc.get_transaction_info(txid).await?;

        // Parse anchor data from transaction
        if let Some(anchor_data) = tx_builder::parse_anchor_from_tx(&tx_info.hex)? {
            // Verify epoch and root match
            if anchor_data.epoch_sequence != expected_epoch {
                debug!(
                    "Epoch mismatch: expected {}, got {}",
                    expected_epoch, anchor_data.epoch_sequence
                );
                return Ok(false);
            }

            if anchor_data.epoch_root != *expected_root {
                debug!(
                    "Root mismatch: expected {}, got {}",
                    hex::encode(expected_root),
                    hex::encode(&anchor_data.epoch_root)
                );
                return Ok(false);
            }

            Ok(true)
        } else {
            debug!("No L0 anchor data found in transaction {}", txid);
            Ok(false)
        }
    }

    /// Get configuration
    pub fn config(&self) -> &P4Config {
        &self.config
    }

    /// Get Bitcoin RPC client
    pub fn bitcoin_rpc(&self) -> &Arc<BitcoinRpcClient> {
        &self.bitcoin_rpc
    }

    /// Get Atomicals client (if enabled)
    pub fn atomicals(&self) -> Option<&Arc<AtomicalsClient>> {
        self.atomicals.as_ref()
    }

    /// Get confirmation monitor
    pub fn monitor(&self) -> &Arc<ConfirmationMonitor> {
        &self.monitor
    }

    /// Get retry manager
    pub fn retry_manager(&self) -> &Arc<RetryManager> {
        &self.retry_manager
    }
}

/// Create a P4 client with default development configuration
pub async fn create_development_client() -> P4Result<P4Client> {
    P4Client::new(P4Config::development()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anchor_data_format() {
        let epoch_root = [0x12; 32];
        let anchor = AnchorData::new(42, epoch_root);
        let bytes = anchor.to_bytes();

        // Verify magic
        assert_eq!(&bytes[0..4], &L0_ANCHOR_MAGIC);

        // Verify version
        assert_eq!(bytes[4], 1);

        // Verify epoch sequence
        assert_eq!(&bytes[5..13], &42u64.to_be_bytes());

        // Verify root
        assert_eq!(&bytes[13..45], &epoch_root);

        // Parse back
        let parsed = AnchorData::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.epoch_sequence, 42);
        assert_eq!(parsed.epoch_root, epoch_root);
    }

    #[test]
    fn test_config_creation() {
        let config = P4Config::development();
        assert!(config.enable_bitcoin);
        assert!(!config.enable_atomicals);
        assert_eq!(config.bitcoin.network, BitcoinNetwork::Regtest);
    }
}
