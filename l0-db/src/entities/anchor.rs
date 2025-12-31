//! Anchor entity definitions
//!
//! Entities for storing anchor transactions that link L0 epochs to external blockchains.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use soulbase_storage::model::Entity;
use soulbase_types::prelude::TenantId;

/// Anchor transaction entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorTransactionEntity {
    pub id: String,
    pub tenant_id: TenantId,
    pub anchor_id: String,
    pub chain_type: String,
    pub epoch_root: String,
    pub epoch_sequence: u64,
    pub epoch_start: DateTime<Utc>,
    pub epoch_end: DateTime<Utc>,
    pub batch_count: u64,
    pub status: String,
    pub tx_hash: Option<String>,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub confirmations: u32,
    pub required_confirmations: u32,
    pub gas_price: Option<String>,
    pub gas_used: Option<u64>,
    pub fee_paid: Option<String>,
    pub submitted_at: Option<DateTime<Utc>>,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub retry_count: u32,
}

impl Entity for AnchorTransactionEntity {
    const TABLE: &'static str = "l0_anchor_transaction";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}

/// Anchor policy entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorPolicyEntity {
    pub id: String,
    pub tenant_id: TenantId,
    pub version: String,
    pub enabled_chains: Vec<String>,
    pub primary_chain: String,
    pub epoch_interval: u64,
    pub max_anchor_delay: u64,
    pub retry_count: u32,
    pub gas_strategy: String,
    pub min_confirmations_ethereum: u32,
    pub min_confirmations_bitcoin: u32,
    pub min_confirmations_polygon: u32,
    pub min_confirmations_solana: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Entity for AnchorPolicyEntity {
    const TABLE: &'static str = "l0_anchor_policy";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}

/// Epoch proof entity for storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochProofEntity {
    pub id: String,
    pub tenant_id: TenantId,
    pub anchor_id: String,
    pub root: String,
    pub merkle_path_json: String,
    pub signer_set_version: String,
    pub signature: String,
    pub signer_bitmap: String,
    pub created_at: DateTime<Utc>,
}

impl Entity for EpochProofEntity {
    const TABLE: &'static str = "l0_epoch_proof";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}
