//! Anchor Service Implementation
//!
//! Implements the AnchorLedger trait for managing chain anchoring operations.
//!
//! ## P4 Integration
//!
//! When compiled with the `p4` feature, this service can use the P4 layer
//! for real blockchain anchoring. Without the feature, it uses a mock provider.
//!
//! ```rust,no_run
//! use l0_db::services::{AnchorService, P4AnchorProvider};
//!
//! // With P4 integration:
//! #[cfg(feature = "p4")]
//! async fn example() {
//!     let provider = P4AnchorProvider::new(p4_config).await.unwrap();
//!     let service = AnchorService::new_with_provider(datastore, tenant_id, Box::new(provider));
//! }
//! ```

use async_trait::async_trait;
use chrono::Utc;
use l0_core::error::LedgerError;
use l0_core::ledger::{AnchorLedger, CreateAnchorRequest, Ledger, LedgerResult};
use l0_core::types::{
    AnchorChainType, AnchorPolicy, AnchorStatus, AnchorTransaction, AnchorVerification, Digest,
    GasStrategy,
};
use serde::Deserialize;
use soulbase_storage::model::Entity;
use soulbase_storage::surreal::SurrealDatastore;
use soulbase_storage::Datastore;
use soulbase_types::prelude::TenantId;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::entities::{AnchorPolicyEntity, AnchorTransactionEntity};
use crate::services::p4_integration::{AnchorProvider, MockAnchorProvider};

/// Anchor Service
///
/// Manages the anchoring of L0 epoch roots to external blockchains.
///
/// Supports optional P4 layer integration for real blockchain anchoring.
/// Without a provider, uses simulated transaction hashes.
pub struct AnchorService {
    datastore: Arc<SurrealDatastore>,
    tenant_id: TenantId,
    sequence: std::sync::atomic::AtomicU64,
    /// Optional P4 anchor provider for real blockchain integration
    anchor_provider: Option<Box<dyn AnchorProvider>>,
}

impl AnchorService {
    /// Create a new Anchor Service (without P4 provider - uses simulated anchoring)
    pub fn new(datastore: Arc<SurrealDatastore>, tenant_id: TenantId) -> Self {
        Self {
            datastore,
            tenant_id,
            sequence: std::sync::atomic::AtomicU64::new(0),
            anchor_provider: None,
        }
    }

    /// Create a new Anchor Service with P4 anchor provider
    ///
    /// This enables real blockchain anchoring through the P4 layer.
    pub fn new_with_provider(
        datastore: Arc<SurrealDatastore>,
        tenant_id: TenantId,
        provider: Box<dyn AnchorProvider>,
    ) -> Self {
        Self {
            datastore,
            tenant_id,
            sequence: std::sync::atomic::AtomicU64::new(0),
            anchor_provider: Some(provider),
        }
    }

    /// Create a new Anchor Service with persistent sequence
    pub async fn new_with_persistence(
        datastore: Arc<SurrealDatastore>,
        tenant_id: TenantId,
    ) -> Result<Self, LedgerError> {
        let service = Self::new(datastore.clone(), tenant_id.clone());
        let max_seq = service.load_max_sequence().await?;
        service
            .sequence
            .store(max_seq + 1, std::sync::atomic::Ordering::SeqCst);
        Ok(service)
    }

    /// Create with persistence and P4 provider
    pub async fn new_with_persistence_and_provider(
        datastore: Arc<SurrealDatastore>,
        tenant_id: TenantId,
        provider: Box<dyn AnchorProvider>,
    ) -> Result<Self, LedgerError> {
        let mut service = Self::new_with_provider(datastore.clone(), tenant_id.clone(), provider);
        let max_seq = service.load_max_sequence().await?;
        service
            .sequence
            .store(max_seq + 1, std::sync::atomic::Ordering::SeqCst);
        Ok(service)
    }

    /// Set the anchor provider (for late binding)
    pub fn set_anchor_provider(&mut self, provider: Box<dyn AnchorProvider>) {
        self.anchor_provider = Some(provider);
    }

    /// Check if P4 provider is configured
    pub fn has_provider(&self) -> bool {
        self.anchor_provider.is_some()
    }

    /// Load the maximum sequence number from existing records
    async fn load_max_sequence(&self) -> Result<u64, LedgerError> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant ORDER BY created_at DESC LIMIT 1",
            AnchorTransactionEntity::TABLE
        );

        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let result: Option<AnchorTransactionEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        if let Some(anchor) = result {
            if let Some(seq) = crate::sequence::extract_sequence_from_id(&anchor.anchor_id) {
                return Ok(seq);
            }
        }

        Ok(0)
    }

    /// Generate a new ID
    fn generate_id(&self, prefix: &str) -> String {
        let seq = self
            .sequence
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let timestamp = Utc::now().timestamp_micros();
        format!("{}_{:016x}_{:08x}", prefix, timestamp, seq)
    }

    /// Convert chain type to string
    fn chain_type_to_str(chain_type: AnchorChainType) -> &'static str {
        match chain_type {
            AnchorChainType::Bitcoin => "bitcoin",
            AnchorChainType::Atomicals => "atomicals",
            AnchorChainType::Internal => "internal",
            AnchorChainType::Ethereum => "ethereum",
            AnchorChainType::Polygon => "polygon",
            AnchorChainType::Solana => "solana",
        }
    }

    /// Convert string to chain type
    fn str_to_chain_type(s: &str) -> AnchorChainType {
        match s {
            "bitcoin" => AnchorChainType::Bitcoin,
            "atomicals" => AnchorChainType::Atomicals,
            "internal" => AnchorChainType::Internal,
            "ethereum" => AnchorChainType::Ethereum,
            "polygon" => AnchorChainType::Polygon,
            "solana" => AnchorChainType::Solana,
            // Default to Bitcoin (primary target per L0 spec)
            _ => AnchorChainType::Bitcoin,
        }
    }

    /// Convert status to string
    fn status_to_str(status: AnchorStatus) -> &'static str {
        match status {
            AnchorStatus::Pending => "pending",
            AnchorStatus::Submitted => "submitted",
            AnchorStatus::Confirmed => "confirmed",
            AnchorStatus::Finalized => "finalized",
            AnchorStatus::Failed => "failed",
            AnchorStatus::Expired => "expired",
        }
    }

    /// Convert string to status
    fn str_to_status(s: &str) -> AnchorStatus {
        match s {
            "pending" => AnchorStatus::Pending,
            "submitted" => AnchorStatus::Submitted,
            "confirmed" => AnchorStatus::Confirmed,
            "finalized" => AnchorStatus::Finalized,
            "failed" => AnchorStatus::Failed,
            "expired" => AnchorStatus::Expired,
            _ => AnchorStatus::Pending,
        }
    }

    /// Convert gas strategy to string
    fn gas_strategy_to_str(strategy: GasStrategy) -> &'static str {
        match strategy {
            GasStrategy::Standard => "standard",
            GasStrategy::Fast => "fast",
            GasStrategy::Slow => "slow",
            GasStrategy::Custom => "custom",
        }
    }

    /// Convert string to gas strategy
    fn str_to_gas_strategy(s: &str) -> GasStrategy {
        match s {
            "standard" => GasStrategy::Standard,
            "fast" => GasStrategy::Fast,
            "slow" => GasStrategy::Slow,
            "custom" => GasStrategy::Custom,
            _ => GasStrategy::Standard,
        }
    }

    /// Get required confirmations for a chain type
    fn required_confirmations(chain_type: AnchorChainType) -> u32 {
        match chain_type {
            AnchorChainType::Bitcoin => 6,
            AnchorChainType::Atomicals => 6, // Same as Bitcoin (built on BTC)
            AnchorChainType::Internal => 0,
            AnchorChainType::Ethereum => 12,
            AnchorChainType::Polygon => 256,
            AnchorChainType::Solana => 32,
        }
    }

    /// Convert entity to AnchorTransaction
    fn entity_to_transaction(entity: &AnchorTransactionEntity) -> AnchorTransaction {
        AnchorTransaction {
            anchor_id: entity.anchor_id.clone(),
            chain_type: Self::str_to_chain_type(&entity.chain_type),
            epoch_root: Digest::from_hex(&entity.epoch_root).unwrap_or_default(),
            epoch_sequence: entity.epoch_sequence,
            epoch_start: entity.epoch_start,
            epoch_end: entity.epoch_end,
            batch_count: entity.batch_count,
            epoch_proof: None, // Would be fetched separately
            status: Self::str_to_status(&entity.status),
            tx_hash: entity.tx_hash.clone(),
            block_number: entity.block_number,
            block_hash: entity.block_hash.clone(),
            confirmations: entity.confirmations,
            required_confirmations: entity.required_confirmations,
            gas_price: entity.gas_price.clone(),
            gas_used: entity.gas_used,
            fee_paid: entity.fee_paid.clone(),
            submitted_at: entity.submitted_at,
            confirmed_at: entity.confirmed_at,
            created_at: entity.created_at,
        }
    }

    /// Convert entity to AnchorPolicy
    fn entity_to_policy(entity: &AnchorPolicyEntity) -> AnchorPolicy {
        let mut min_confirmations = HashMap::new();
        // Primary targets per L0 spec
        min_confirmations.insert("bitcoin".to_string(), entity.min_confirmations_bitcoin);
        min_confirmations.insert("atomicals".to_string(), entity.min_confirmations_bitcoin); // Same as Bitcoin
        // Legacy chains
        min_confirmations.insert("ethereum".to_string(), entity.min_confirmations_ethereum);
        min_confirmations.insert("polygon".to_string(), entity.min_confirmations_polygon);
        min_confirmations.insert("solana".to_string(), entity.min_confirmations_solana);

        AnchorPolicy {
            version: entity.version.clone(),
            enabled_chains: entity
                .enabled_chains
                .iter()
                .map(|s| Self::str_to_chain_type(s))
                .collect(),
            primary_chain: Self::str_to_chain_type(&entity.primary_chain),
            epoch_interval: entity.epoch_interval,
            max_anchor_delay: entity.max_anchor_delay,
            retry_count: entity.retry_count,
            gas_strategy: Self::str_to_gas_strategy(&entity.gas_strategy),
            min_confirmations,
        }
    }

    /// Generate simulated transaction hash (fallback when no P4 provider)
    fn generate_simulated_tx_hash(&self, anchor: &AnchorTransaction) -> String {
        match anchor.chain_type {
            AnchorChainType::Bitcoin | AnchorChainType::Atomicals => {
                // Bitcoin-style tx hash (32 bytes = 64 hex chars)
                let epoch_data = format!(
                    "btc:{}:{}:{}",
                    anchor.epoch_sequence,
                    anchor.epoch_root.to_hex(),
                    anchor.created_at.timestamp()
                );
                let hash = Digest::blake3(epoch_data.as_bytes());
                hash.to_hex()
            }
            AnchorChainType::Ethereum | AnchorChainType::Polygon => {
                // Ethereum-style tx hash (0x prefixed)
                let epoch_data = format!(
                    "eth:{}:{}:{}",
                    anchor.epoch_sequence,
                    anchor.epoch_root.to_hex(),
                    anchor.created_at.timestamp()
                );
                let hash = Digest::blake3(epoch_data.as_bytes());
                format!("0x{}", hash.to_hex())
            }
            AnchorChainType::Solana => {
                // Solana-style signature (base58)
                let epoch_data = format!(
                    "sol:{}:{}:{}",
                    anchor.epoch_sequence,
                    anchor.epoch_root.to_hex(),
                    anchor.created_at.timestamp()
                );
                let hash = Digest::blake3(epoch_data.as_bytes());
                // Simplified base58-like encoding
                format!("{}Sol", hash.to_hex())
            }
            AnchorChainType::Internal => {
                // Internal anchoring (immediate confirmation)
                let epoch_data = format!(
                    "internal:{}:{}",
                    anchor.epoch_sequence,
                    anchor.epoch_root.to_hex()
                );
                Digest::blake3(epoch_data.as_bytes()).to_hex()
            }
        }
    }
}

#[async_trait]
impl Ledger for AnchorService {
    fn name(&self) -> &'static str {
        "anchor"
    }

    async fn current_sequence(&self) -> LedgerResult<u64> {
        Ok(self.sequence.load(std::sync::atomic::Ordering::SeqCst))
    }

    async fn current_root(&self) -> LedgerResult<Digest> {
        // Compute Merkle root from all anchor transactions
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT epoch_root, epoch_sequence FROM {} WHERE tenant_id = $tenant ORDER BY epoch_sequence ASC",
            AnchorTransactionEntity::TABLE
        );

        #[derive(Deserialize)]
        struct AnchorRoot {
            epoch_root: String,
            epoch_sequence: u64,
        }

        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let anchors: Vec<AnchorRoot> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        if anchors.is_empty() {
            return Ok(Digest::zero());
        }

        // Build Merkle tree from anchor roots
        use l0_core::crypto::IncrementalMerkleTree;
        let mut tree = IncrementalMerkleTree::new();
        for anchor in &anchors {
            let digest = Digest::from_hex(&anchor.epoch_root).unwrap_or_default();
            tree.add(digest);
        }

        Ok(tree.root())
    }

    async fn verify_integrity(&self) -> LedgerResult<bool> {
        // Verify integrity by checking:
        // 1. All anchors have valid status values
        // 2. Finalized anchors have tx_hash and block_number
        // 3. Epoch sequences are unique per chain
        // 4. Confirmations don't exceed required_confirmations unreasonably

        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant",
            AnchorTransactionEntity::TABLE
        );

        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let anchors: Vec<AnchorTransactionEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        let valid_statuses = ["pending", "submitted", "confirmed", "finalized", "failed", "expired"];
        let mut chain_epochs: HashMap<(String, u64), String> = HashMap::new();

        for anchor in &anchors {
            // Check valid status
            if !valid_statuses.contains(&anchor.status.as_str()) {
                return Ok(false);
            }

            // Check finalized anchors have required fields
            if anchor.status == "finalized" {
                if anchor.tx_hash.is_none() || anchor.block_number.is_none() {
                    return Ok(false);
                }
            }

            // Check for duplicate epoch sequences per chain
            let key = (anchor.chain_type.clone(), anchor.epoch_sequence);
            if let Some(existing_id) = chain_epochs.get(&key) {
                if existing_id != &anchor.anchor_id {
                    return Ok(false); // Duplicate epoch for same chain
                }
            }
            chain_epochs.insert(key, anchor.anchor_id.clone());

            // Check confirmations are reasonable
            if anchor.confirmations > anchor.required_confirmations * 100 {
                // Unreasonably high confirmations might indicate data corruption
                return Ok(false);
            }
        }

        Ok(true)
    }
}

#[async_trait]
impl AnchorLedger for AnchorService {
    async fn create_anchor(&self, request: CreateAnchorRequest) -> LedgerResult<AnchorTransaction> {
        let anchor_id = self.generate_id("anchor");
        let now = Utc::now();

        let entity = AnchorTransactionEntity {
            id: format!("l0_anchor:{}:{}", self.tenant_id.0, anchor_id),
            tenant_id: self.tenant_id.clone(),
            anchor_id: anchor_id.clone(),
            chain_type: Self::chain_type_to_str(request.chain_type).to_string(),
            epoch_root: request.epoch_root.to_hex(),
            epoch_sequence: request.epoch_sequence,
            epoch_start: request.epoch_start,
            epoch_end: request.epoch_end,
            batch_count: request.batch_count,
            status: "pending".to_string(),
            tx_hash: None,
            block_number: None,
            block_hash: None,
            confirmations: 0,
            required_confirmations: Self::required_confirmations(request.chain_type),
            gas_price: None,
            gas_used: None,
            fee_paid: None,
            submitted_at: None,
            confirmed_at: None,
            created_at: now,
            retry_count: 0,
        };

        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "CREATE {} CONTENT $data RETURN AFTER",
            AnchorTransactionEntity::TABLE
        );

        let mut response = session
            .client()
            .query(&query)
            .bind(("data", entity))
            .await
            .map_err(|e| LedgerError::Storage(format!("Create failed: {}", e)))?;

        let result: Option<AnchorTransactionEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        let created =
            result.ok_or_else(|| LedgerError::Storage("Create returned no result".to_string()))?;
        Ok(Self::entity_to_transaction(&created))
    }

    async fn get_anchor(&self, anchor_id: &str) -> LedgerResult<Option<AnchorTransaction>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND anchor_id = $anchor_id LIMIT 1",
            AnchorTransactionEntity::TABLE
        );

        let anchor_id_owned = anchor_id.to_string();
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("anchor_id", anchor_id_owned))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let result: Option<AnchorTransactionEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        Ok(result.map(|e| Self::entity_to_transaction(&e)))
    }

    async fn get_anchor_by_epoch(
        &self,
        chain_type: AnchorChainType,
        epoch_sequence: u64,
    ) -> LedgerResult<Option<AnchorTransaction>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND chain_type = $chain AND epoch_sequence = $epoch LIMIT 1",
            AnchorTransactionEntity::TABLE
        );

        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("chain", Self::chain_type_to_str(chain_type)))
            .bind(("epoch", epoch_sequence))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let result: Option<AnchorTransactionEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        Ok(result.map(|e| Self::entity_to_transaction(&e)))
    }

    async fn update_anchor_status(
        &self,
        anchor_id: &str,
        status: AnchorStatus,
        tx_hash: Option<String>,
        block_number: Option<u64>,
        confirmations: u32,
    ) -> LedgerResult<()> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let confirmed_at = if matches!(status, AnchorStatus::Confirmed | AnchorStatus::Finalized) {
            Some(Utc::now())
        } else {
            None
        };

        let query = format!(
            "UPDATE {} SET status = $status, tx_hash = $tx_hash, block_number = $block_num, confirmations = $confirmations, confirmed_at = $confirmed WHERE tenant_id = $tenant AND anchor_id = $anchor_id",
            AnchorTransactionEntity::TABLE
        );

        let anchor_id_owned = anchor_id.to_string();
        session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("anchor_id", anchor_id_owned))
            .bind(("status", Self::status_to_str(status)))
            .bind(("tx_hash", tx_hash))
            .bind(("block_num", block_number))
            .bind(("confirmations", confirmations))
            .bind(("confirmed", confirmed_at))
            .await
            .map_err(|e| LedgerError::Storage(format!("Update failed: {}", e)))?;

        Ok(())
    }

    async fn submit_anchor(&self, anchor_id: &str) -> LedgerResult<String> {
        // Get the anchor to submit
        let anchor = self
            .get_anchor(anchor_id)
            .await?
            .ok_or_else(|| LedgerError::NotFound(format!("Anchor {} not found", anchor_id)))?;

        // Validate anchor is in correct state for submission
        if anchor.status != AnchorStatus::Pending {
            return Err(LedgerError::InvalidStateTransition(format!(
                "Anchor {} is not pending (status: {:?})",
                anchor_id, anchor.status
            )));
        }

        // Use P4 provider if available, otherwise fall back to simulated anchoring
        let tx_hash = if let Some(provider) = &self.anchor_provider {
            info!(
                "Submitting anchor {} to {:?} via P4 provider",
                anchor_id, anchor.chain_type
            );
            provider
                .submit_anchor(anchor.chain_type, anchor.epoch_sequence, &anchor.epoch_root)
                .await?
        } else {
            // Fallback: Generate simulated transaction hash based on chain type and epoch data
            debug!(
                "No P4 provider configured, using simulated anchoring for {}",
                anchor_id
            );
            self.generate_simulated_tx_hash(&anchor)
        };

        let submitted_at = Utc::now();

        // Update status to submitted with the tx hash
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "UPDATE {} SET status = 'submitted', tx_hash = $tx_hash, submitted_at = $submitted WHERE tenant_id = $tenant AND anchor_id = $anchor_id",
            AnchorTransactionEntity::TABLE
        );

        let anchor_id_owned = anchor_id.to_string();
        session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("anchor_id", anchor_id_owned))
            .bind(("tx_hash", tx_hash.clone()))
            .bind(("submitted", submitted_at))
            .await
            .map_err(|e| LedgerError::Storage(format!("Update failed: {}", e)))?;

        // For internal chain, immediately finalize
        if anchor.chain_type == AnchorChainType::Internal {
            self.update_anchor_status(
                anchor_id,
                AnchorStatus::Finalized,
                Some(tx_hash.clone()),
                Some(1), // block 1 for internal
                0,
            ).await?;
        }

        info!("Anchor {} submitted with tx_hash: {}", anchor_id, tx_hash);
        Ok(tx_hash)
    }

    async fn check_anchor_status(&self, anchor_id: &str) -> LedgerResult<AnchorStatus> {
        let anchor = self
            .get_anchor(anchor_id)
            .await?
            .ok_or_else(|| LedgerError::NotFound(format!("Anchor {} not found", anchor_id)))?;

        Ok(anchor.status)
    }

    async fn verify_anchor(&self, anchor_id: &str) -> LedgerResult<AnchorVerification> {
        let anchor = self
            .get_anchor(anchor_id)
            .await?
            .ok_or_else(|| LedgerError::NotFound(format!("Anchor {} not found", anchor_id)))?;

        // In a full implementation, this would:
        // 1. Query the target blockchain for the tx
        // 2. Verify the data in the tx matches our epoch root
        // 3. Check confirmation count

        if anchor.is_finalized() {
            Ok(AnchorVerification::success(
                anchor.chain_type,
                anchor.tx_hash.unwrap_or_default(),
                anchor.block_number.unwrap_or(0),
                anchor.confirmations,
            ))
        } else if anchor.status == AnchorStatus::Confirmed {
            Ok(AnchorVerification {
                valid: true,
                chain_type: anchor.chain_type,
                tx_hash: anchor.tx_hash,
                block_number: anchor.block_number,
                confirmations: anchor.confirmations,
                epoch_root_matches: true,
                proof_verified: true,
                errors: vec!["Awaiting finalization".to_string()],
                verified_at: Utc::now(),
            })
        } else {
            Ok(AnchorVerification::failure(
                anchor.chain_type,
                vec![format!("Anchor status is {:?}", anchor.status)],
            ))
        }
    }

    async fn get_pending_anchors(
        &self,
        chain_type: Option<AnchorChainType>,
    ) -> LedgerResult<Vec<AnchorTransaction>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let chain_clause = chain_type
            .map(|ct| format!("AND chain_type = '{}'", Self::chain_type_to_str(ct)))
            .unwrap_or_default();

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND status IN ['pending', 'submitted'] {} ORDER BY created_at DESC LIMIT 100",
            AnchorTransactionEntity::TABLE,
            chain_clause
        );

        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let results: Vec<AnchorTransactionEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        Ok(results.iter().map(Self::entity_to_transaction).collect())
    }

    async fn get_finalized_anchors(
        &self,
        chain_type: AnchorChainType,
        limit: u32,
    ) -> LedgerResult<Vec<AnchorTransaction>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND chain_type = $chain AND status = 'finalized' ORDER BY epoch_sequence DESC LIMIT $limit",
            AnchorTransactionEntity::TABLE
        );

        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("chain", Self::chain_type_to_str(chain_type)))
            .bind(("limit", limit))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let results: Vec<AnchorTransactionEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        Ok(results.iter().map(Self::entity_to_transaction).collect())
    }

    async fn get_anchor_history(
        &self,
        chain_type: AnchorChainType,
        from_epoch: u64,
        to_epoch: u64,
    ) -> LedgerResult<Vec<AnchorTransaction>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND chain_type = $chain AND epoch_sequence >= $from AND epoch_sequence <= $to ORDER BY epoch_sequence ASC",
            AnchorTransactionEntity::TABLE
        );

        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("chain", Self::chain_type_to_str(chain_type)))
            .bind(("from", from_epoch))
            .bind(("to", to_epoch))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let results: Vec<AnchorTransactionEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        Ok(results.iter().map(Self::entity_to_transaction).collect())
    }

    async fn get_anchor_policy(&self) -> LedgerResult<AnchorPolicy> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant ORDER BY created_at DESC LIMIT 1",
            AnchorPolicyEntity::TABLE
        );

        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let result: Option<AnchorPolicyEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        Ok(result
            .map(|e| Self::entity_to_policy(&e))
            .unwrap_or_default())
    }

    async fn update_anchor_policy(&self, policy: AnchorPolicy) -> LedgerResult<()> {
        let now = Utc::now();
        let policy_id = self.generate_id("policy");

        let entity = AnchorPolicyEntity {
            id: format!("l0_anchor_policy:{}:{}", self.tenant_id.0, policy_id),
            tenant_id: self.tenant_id.clone(),
            version: policy.version.clone(),
            enabled_chains: policy
                .enabled_chains
                .iter()
                .map(|c| Self::chain_type_to_str(*c).to_string())
                .collect(),
            primary_chain: Self::chain_type_to_str(policy.primary_chain).to_string(),
            epoch_interval: policy.epoch_interval,
            max_anchor_delay: policy.max_anchor_delay,
            retry_count: policy.retry_count,
            gas_strategy: Self::gas_strategy_to_str(policy.gas_strategy).to_string(),
            min_confirmations_ethereum: *policy.min_confirmations.get("ethereum").unwrap_or(&12),
            min_confirmations_bitcoin: *policy.min_confirmations.get("bitcoin").unwrap_or(&6),
            min_confirmations_polygon: *policy.min_confirmations.get("polygon").unwrap_or(&256),
            min_confirmations_solana: *policy.min_confirmations.get("solana").unwrap_or(&32),
            created_at: now,
            updated_at: now,
        };

        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "CREATE {} CONTENT $data",
            AnchorPolicyEntity::TABLE
        );

        session
            .client()
            .query(&query)
            .bind(("data", entity))
            .await
            .map_err(|e| LedgerError::Storage(format!("Create failed: {}", e)))?;

        Ok(())
    }

    async fn retry_anchor(&self, anchor_id: &str) -> LedgerResult<AnchorTransaction> {
        let anchor = self
            .get_anchor(anchor_id)
            .await?
            .ok_or_else(|| LedgerError::NotFound(format!("Anchor {} not found", anchor_id)))?;

        if !anchor.can_retry() {
            return Err(LedgerError::InvalidStateTransition(format!(
                "Anchor {} cannot be retried (status: {:?})",
                anchor_id, anchor.status
            )));
        }

        // Update status back to pending
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "UPDATE {} SET status = 'pending', retry_count = retry_count + 1 WHERE tenant_id = $tenant AND anchor_id = $anchor_id RETURN AFTER",
            AnchorTransactionEntity::TABLE
        );

        let anchor_id_owned = anchor_id.to_string();
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("anchor_id", anchor_id_owned))
            .await
            .map_err(|e| LedgerError::Storage(format!("Update failed: {}", e)))?;

        let result: Option<AnchorTransactionEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        let updated =
            result.ok_or_else(|| LedgerError::Storage("Update returned no result".to_string()))?;
        Ok(Self::entity_to_transaction(&updated))
    }

    async fn get_latest_finalized_epoch(
        &self,
        chain_type: AnchorChainType,
    ) -> LedgerResult<Option<u64>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT epoch_sequence FROM {} WHERE tenant_id = $tenant AND chain_type = $chain AND status = 'finalized' ORDER BY epoch_sequence DESC LIMIT 1",
            AnchorTransactionEntity::TABLE
        );

        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("chain", Self::chain_type_to_str(chain_type)))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        #[derive(Deserialize)]
        struct EpochResult {
            epoch_sequence: u64,
        }

        let result: Option<EpochResult> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        Ok(result.map(|r| r.epoch_sequence))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_type_conversion() {
        // Primary targets per L0 spec
        assert_eq!(
            AnchorService::chain_type_to_str(AnchorChainType::Bitcoin),
            "bitcoin"
        );
        assert_eq!(
            AnchorService::chain_type_to_str(AnchorChainType::Atomicals),
            "atomicals"
        );
        assert_eq!(
            AnchorService::str_to_chain_type("bitcoin"),
            AnchorChainType::Bitcoin
        );
        assert_eq!(
            AnchorService::str_to_chain_type("atomicals"),
            AnchorChainType::Atomicals
        );
        // Unknown defaults to Bitcoin (primary target)
        assert_eq!(
            AnchorService::str_to_chain_type("unknown"),
            AnchorChainType::Bitcoin
        );
    }

    #[test]
    fn test_status_conversion() {
        assert_eq!(AnchorService::status_to_str(AnchorStatus::Pending), "pending");
        assert_eq!(
            AnchorService::str_to_status("finalized"),
            AnchorStatus::Finalized
        );
        assert_eq!(AnchorService::str_to_status("unknown"), AnchorStatus::Pending);
    }

    #[test]
    fn test_required_confirmations() {
        // Primary targets per L0 spec
        assert_eq!(AnchorService::required_confirmations(AnchorChainType::Bitcoin), 6);
        assert_eq!(AnchorService::required_confirmations(AnchorChainType::Atomicals), 6);
        assert_eq!(AnchorService::required_confirmations(AnchorChainType::Internal), 0);
        // Legacy chains
        assert_eq!(AnchorService::required_confirmations(AnchorChainType::Ethereum), 12);
        assert_eq!(AnchorService::required_confirmations(AnchorChainType::Polygon), 256);
    }
}
