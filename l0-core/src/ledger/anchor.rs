//! Chain Anchor Ledger Interface
//!
//! Manages the anchoring of L0 epoch roots to external blockchains.

use async_trait::async_trait;

use super::{Ledger, LedgerResult};
use crate::types::{
    AnchorChainType, AnchorPolicy, AnchorStatus, AnchorTransaction, AnchorVerification, Digest,
    EpochProof,
};

/// Request to create an anchor transaction
#[derive(Debug, Clone)]
pub struct CreateAnchorRequest {
    /// Target chain
    pub chain_type: AnchorChainType,
    /// Epoch root to anchor
    pub epoch_root: Digest,
    /// Epoch sequence number
    pub epoch_sequence: u64,
    /// Epoch start timestamp
    pub epoch_start: chrono::DateTime<chrono::Utc>,
    /// Epoch end timestamp
    pub epoch_end: chrono::DateTime<chrono::Utc>,
    /// Number of batches in epoch
    pub batch_count: u64,
    /// Optional epoch proof
    pub epoch_proof: Option<EpochProof>,
}

/// Anchor Ledger interface
///
/// Handles the anchoring of L0 epoch roots to external blockchains.
#[async_trait]
pub trait AnchorLedger: Ledger {
    /// Create a new anchor transaction
    async fn create_anchor(&self, request: CreateAnchorRequest) -> LedgerResult<AnchorTransaction>;

    /// Get an anchor transaction by ID
    async fn get_anchor(&self, anchor_id: &str) -> LedgerResult<Option<AnchorTransaction>>;

    /// Get anchor by epoch sequence
    async fn get_anchor_by_epoch(
        &self,
        chain_type: AnchorChainType,
        epoch_sequence: u64,
    ) -> LedgerResult<Option<AnchorTransaction>>;

    /// Update anchor status
    async fn update_anchor_status(
        &self,
        anchor_id: &str,
        status: AnchorStatus,
        tx_hash: Option<String>,
        block_number: Option<u64>,
        confirmations: u32,
    ) -> LedgerResult<()>;

    /// Submit anchor transaction to chain
    async fn submit_anchor(&self, anchor_id: &str) -> LedgerResult<String>;

    /// Check anchor status on chain
    async fn check_anchor_status(&self, anchor_id: &str) -> LedgerResult<AnchorStatus>;

    /// Verify an anchor on chain
    async fn verify_anchor(&self, anchor_id: &str) -> LedgerResult<AnchorVerification>;

    /// Get pending anchors
    async fn get_pending_anchors(
        &self,
        chain_type: Option<AnchorChainType>,
    ) -> LedgerResult<Vec<AnchorTransaction>>;

    /// Get finalized anchors
    async fn get_finalized_anchors(
        &self,
        chain_type: AnchorChainType,
        limit: u32,
    ) -> LedgerResult<Vec<AnchorTransaction>>;

    /// Get anchor history for an epoch range
    async fn get_anchor_history(
        &self,
        chain_type: AnchorChainType,
        from_epoch: u64,
        to_epoch: u64,
    ) -> LedgerResult<Vec<AnchorTransaction>>;

    /// Get current anchor policy
    async fn get_anchor_policy(&self) -> LedgerResult<AnchorPolicy>;

    /// Update anchor policy
    async fn update_anchor_policy(&self, policy: AnchorPolicy) -> LedgerResult<()>;

    /// Retry a failed anchor
    async fn retry_anchor(&self, anchor_id: &str) -> LedgerResult<AnchorTransaction>;

    /// Get latest finalized epoch for a chain
    async fn get_latest_finalized_epoch(
        &self,
        chain_type: AnchorChainType,
    ) -> LedgerResult<Option<u64>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_create_anchor_request() {
        let request = CreateAnchorRequest {
            chain_type: AnchorChainType::Ethereum,
            epoch_root: Digest::zero(),
            epoch_sequence: 1,
            epoch_start: Utc::now(),
            epoch_end: Utc::now(),
            batch_count: 10,
            epoch_proof: None,
        };

        assert_eq!(request.chain_type, AnchorChainType::Ethereum);
        assert_eq!(request.epoch_sequence, 1);
        assert_eq!(request.batch_count, 10);
    }
}
