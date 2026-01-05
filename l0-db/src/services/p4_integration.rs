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
