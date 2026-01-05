//! Chain Anchoring Types
//!
//! Types for anchoring L0 epoch roots to external blockchains.
//! This provides the ultimate level of evidence (A-level) by
//! creating an immutable reference on a public blockchain.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use super::common::Digest;

/// Supported anchor chain types
///
/// According to L0 development documentation (Chapter 7 & 8),
/// the chain anchoring target is locked to **Bitcoin + Atomicals**.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorChainType {
    /// Bitcoin mainnet (primary target per L0 spec)
    Bitcoin,
    /// Atomicals protocol on Bitcoin (primary extension per L0 spec)
    Atomicals,
    /// Internal L0 only (no external anchor, for testing/development)
    Internal,
    /// Ethereum mainnet (legacy/future consideration)
    #[serde(rename = "ethereum")]
    Ethereum,
    /// Polygon (legacy/future consideration)
    #[serde(rename = "polygon")]
    Polygon,
    /// Solana (legacy/future consideration)
    #[serde(rename = "solana")]
    Solana,
}

impl Default for AnchorChainType {
    fn default() -> Self {
        // Bitcoin is the primary anchor target per L0 documentation
        Self::Bitcoin
    }
}

/// Anchor transaction status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorStatus {
    /// Anchor transaction pending
    Pending,
    /// Transaction submitted, awaiting confirmation
    Submitted,
    /// Confirmed on chain
    Confirmed,
    /// Finalized (sufficient confirmations)
    Finalized,
    /// Transaction failed
    Failed,
    /// Transaction expired/dropped
    Expired,
}

/// Anchor transaction format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorTransaction {
    /// Unique anchor ID
    pub anchor_id: String,
    /// Target chain
    pub chain_type: AnchorChainType,
    /// Epoch root being anchored
    pub epoch_root: Digest,
    /// Epoch sequence number
    pub epoch_sequence: u64,
    /// Time range covered by this epoch
    pub epoch_start: DateTime<Utc>,
    pub epoch_end: DateTime<Utc>,
    /// Number of batches in this epoch
    pub batch_count: u64,
    /// Merkle proof of epoch root
    pub epoch_proof: Option<EpochProof>,
    /// Current status
    pub status: AnchorStatus,
    /// Chain-specific transaction hash
    pub tx_hash: Option<String>,
    /// Block number on target chain
    pub block_number: Option<u64>,
    /// Block hash on target chain
    pub block_hash: Option<String>,
    /// Number of confirmations
    pub confirmations: u32,
    /// Minimum confirmations required for finality
    pub required_confirmations: u32,
    /// Gas price used (for EVM chains)
    pub gas_price: Option<String>,
    /// Gas used (for EVM chains)
    pub gas_used: Option<u64>,
    /// Transaction fee paid
    pub fee_paid: Option<String>,
    /// Timestamp of submission
    pub submitted_at: Option<DateTime<Utc>>,
    /// Timestamp of confirmation
    pub confirmed_at: Option<DateTime<Utc>>,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
}

impl AnchorTransaction {
    /// Create a new anchor transaction
    pub fn new(
        anchor_id: String,
        chain_type: AnchorChainType,
        epoch_root: Digest,
        epoch_sequence: u64,
        epoch_start: DateTime<Utc>,
        epoch_end: DateTime<Utc>,
        batch_count: u64,
    ) -> Self {
        Self {
            anchor_id,
            chain_type,
            epoch_root,
            epoch_sequence,
            epoch_start,
            epoch_end,
            batch_count,
            epoch_proof: None,
            status: AnchorStatus::Pending,
            tx_hash: None,
            block_number: None,
            block_hash: None,
            confirmations: 0,
            required_confirmations: match chain_type {
                AnchorChainType::Bitcoin => 6,
                AnchorChainType::Atomicals => 6, // Same as Bitcoin (built on BTC)
                AnchorChainType::Internal => 0,
                AnchorChainType::Ethereum => 12,
                AnchorChainType::Polygon => 256,
                AnchorChainType::Solana => 32,
            },
            gas_price: None,
            gas_used: None,
            fee_paid: None,
            submitted_at: None,
            confirmed_at: None,
            created_at: Utc::now(),
        }
    }

    /// Check if transaction is finalized
    pub fn is_finalized(&self) -> bool {
        self.status == AnchorStatus::Finalized
            || (self.status == AnchorStatus::Confirmed
                && self.confirmations >= self.required_confirmations)
    }

    /// Check if transaction can be retried
    pub fn can_retry(&self) -> bool {
        matches!(self.status, AnchorStatus::Failed | AnchorStatus::Expired)
    }
}

/// Proof of epoch root inclusion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochProof {
    /// Root hash of the epoch
    pub root: Digest,
    /// Merkle path from batch roots to epoch root
    pub merkle_path: Vec<MerklePathNode>,
    /// Signer set that signed this epoch
    pub signer_set_version: String,
    /// Aggregated signature
    pub signature: String,
    /// Bitmap of signers
    pub signer_bitmap: String,
}

/// Node in a Merkle proof path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerklePathNode {
    /// Hash at this node
    pub hash: Digest,
    /// Position (left = 0, right = 1)
    pub position: u8,
}

/// Anchor verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorVerification {
    /// Is the anchor valid?
    pub valid: bool,
    /// Chain type verified against
    pub chain_type: AnchorChainType,
    /// Transaction hash on chain
    pub tx_hash: Option<String>,
    /// Block number
    pub block_number: Option<u64>,
    /// Confirmations at time of verification
    pub confirmations: u32,
    /// Epoch root matches?
    pub epoch_root_matches: bool,
    /// Proof verified?
    pub proof_verified: bool,
    /// Errors encountered
    pub errors: Vec<String>,
    /// Verified at timestamp
    pub verified_at: DateTime<Utc>,
}

impl AnchorVerification {
    /// Create a successful verification
    pub fn success(
        chain_type: AnchorChainType,
        tx_hash: String,
        block_number: u64,
        confirmations: u32,
    ) -> Self {
        Self {
            valid: true,
            chain_type,
            tx_hash: Some(tx_hash),
            block_number: Some(block_number),
            confirmations,
            epoch_root_matches: true,
            proof_verified: true,
            errors: vec![],
            verified_at: Utc::now(),
        }
    }

    /// Create a failed verification
    pub fn failure(chain_type: AnchorChainType, errors: Vec<String>) -> Self {
        Self {
            valid: false,
            chain_type,
            tx_hash: None,
            block_number: None,
            confirmations: 0,
            epoch_root_matches: false,
            proof_verified: false,
            errors,
            verified_at: Utc::now(),
        }
    }
}

/// Anchor policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorPolicy {
    /// Policy version
    pub version: String,
    /// Enabled chains for anchoring
    pub enabled_chains: Vec<AnchorChainType>,
    /// Primary chain (for automatic anchoring)
    pub primary_chain: AnchorChainType,
    /// Epoch interval in batches
    pub epoch_interval: u64,
    /// Maximum wait time before anchoring (seconds)
    pub max_anchor_delay: u64,
    /// Retry count for failed transactions
    pub retry_count: u32,
    /// Gas price strategy
    pub gas_strategy: GasStrategy,
    /// Minimum confirmations for finality
    pub min_confirmations: std::collections::HashMap<String, u32>,
}

impl Default for AnchorPolicy {
    fn default() -> Self {
        let mut min_confirmations = std::collections::HashMap::new();
        // Primary targets per L0 documentation
        min_confirmations.insert("bitcoin".to_string(), 6);
        min_confirmations.insert("atomicals".to_string(), 6);
        // Legacy/future chains
        min_confirmations.insert("ethereum".to_string(), 12);
        min_confirmations.insert("polygon".to_string(), 256);
        min_confirmations.insert("solana".to_string(), 32);

        Self {
            version: "v1.0.0".to_string(),
            // Bitcoin + Atomicals are the primary targets per L0 spec
            enabled_chains: vec![AnchorChainType::Bitcoin, AnchorChainType::Atomicals],
            primary_chain: AnchorChainType::Bitcoin,
            epoch_interval: 100,
            max_anchor_delay: 3600,
            retry_count: 3,
            gas_strategy: GasStrategy::Standard,
            min_confirmations,
        }
    }
}

/// Gas price strategy for EVM chains
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GasStrategy {
    /// Use standard gas price
    Standard,
    /// Use fast gas price (higher priority)
    Fast,
    /// Use slow gas price (lower cost)
    Slow,
    /// Custom gas price
    Custom,
}

/// Anchor priority level (per L0 spec Chapter 8)
///
/// Note: ChainAnchorInput and ChainAnchorLink are defined in snapshot.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorPriority {
    /// Must anchor - VerdictBatch, REVOKED, major RepairCheckpoint
    /// Paid by public budget (Foundation/DAO)
    Must,
    /// Should anchor - high-risk ConsentBatch, critical SelfOnset
    /// Paid by public budget + Actor/Node optional
    Should,
    /// May anchor - normal logs, normal narratives
    /// Paid by Actor/Node self-funding
    May,
}

impl Default for AnchorPriority {
    fn default() -> Self {
        Self::May
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anchor_transaction_creation() {
        let anchor = AnchorTransaction::new(
            "anchor:001".to_string(),
            AnchorChainType::Ethereum,
            Digest::zero(),
            1,
            Utc::now(),
            Utc::now(),
            10,
        );

        assert_eq!(anchor.status, AnchorStatus::Pending);
        assert_eq!(anchor.required_confirmations, 12);
        assert!(!anchor.is_finalized());
    }

    #[test]
    fn test_anchor_finalization() {
        let mut anchor = AnchorTransaction::new(
            "anchor:002".to_string(),
            AnchorChainType::Ethereum,
            Digest::zero(),
            1,
            Utc::now(),
            Utc::now(),
            10,
        );

        anchor.status = AnchorStatus::Confirmed;
        anchor.confirmations = 5;
        assert!(!anchor.is_finalized());

        anchor.confirmations = 12;
        assert!(anchor.is_finalized());
    }

    #[test]
    fn test_anchor_retry() {
        let mut anchor = AnchorTransaction::new(
            "anchor:003".to_string(),
            AnchorChainType::Ethereum,
            Digest::zero(),
            1,
            Utc::now(),
            Utc::now(),
            10,
        );

        assert!(!anchor.can_retry());

        anchor.status = AnchorStatus::Failed;
        assert!(anchor.can_retry());

        anchor.status = AnchorStatus::Expired;
        assert!(anchor.can_retry());
    }

    #[test]
    fn test_anchor_verification() {
        let verification = AnchorVerification::success(
            AnchorChainType::Ethereum,
            "0x123abc".to_string(),
            12345,
            15,
        );

        assert!(verification.valid);
        assert!(verification.epoch_root_matches);
        assert!(verification.proof_verified);
        assert!(verification.errors.is_empty());
    }

    #[test]
    fn test_anchor_policy_default() {
        let policy = AnchorPolicy::default();

        // Bitcoin is the primary chain per L0 documentation
        assert_eq!(policy.primary_chain, AnchorChainType::Bitcoin);
        assert_eq!(policy.epoch_interval, 100);
        assert!(policy.min_confirmations.contains_key("bitcoin"));
        assert!(policy.min_confirmations.contains_key("atomicals"));
        assert_eq!(*policy.min_confirmations.get("bitcoin").unwrap(), 6);
    }

    #[test]
    fn test_anchor_chain_type_default() {
        // Bitcoin is the default per L0 documentation
        assert_eq!(AnchorChainType::default(), AnchorChainType::Bitcoin);
    }

    #[test]
    fn test_anchor_priority_default() {
        // MAY is the default priority
        assert_eq!(AnchorPriority::default(), AnchorPriority::May);
    }

    #[test]
    fn test_atomicals_chain_type() {
        // Atomicals is a valid chain type
        let chain = AnchorChainType::Atomicals;
        assert_ne!(chain, AnchorChainType::Bitcoin);
        assert_ne!(chain, AnchorChainType::Internal);
    }
}
