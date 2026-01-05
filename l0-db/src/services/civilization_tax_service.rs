//! Civilization Tax Service
//!
//! Manages the three-pool fee distribution model:
//! - Infra Pool: Infrastructure costs
//! - Civilization Pool: Public goods
//! - Reward-Mining Pool: Node incentives

use async_trait::async_trait;
use chrono::Utc;
use l0_core::error::LedgerError;
use l0_core::ledger::LedgerResult;
use l0_core::types::{
    CivilizationTaxConfig, DistributionRatio, FeeDistributionRecord,
    PoolAccount, PoolDistribution, PoolSummary, PoolType,
};
use soulbase_storage::surreal::SurrealDatastore;
use soulbase_storage::Datastore;
use soulbase_types::prelude::TenantId;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Civilization Tax Ledger trait
#[async_trait]
pub trait CivilizationTaxLedger: Send + Sync {
    /// Distribute a fee across the three pools
    async fn distribute_fee(
        &self,
        fee_receipt_id: &str,
        amount: u64,
        epoch_sequence: Option<u64>,
    ) -> LedgerResult<FeeDistributionRecord>;

    /// Get pool balances
    async fn get_pool_summary(&self) -> LedgerResult<PoolSummary>;

    /// Get balance for a specific pool
    async fn get_pool_balance(&self, pool: PoolType) -> LedgerResult<u64>;

    /// Withdraw from a pool (for disbursements)
    async fn withdraw_from_pool(
        &self,
        pool: PoolType,
        amount: u64,
        reason: &str,
    ) -> LedgerResult<u64>;

    /// Get distribution history
    async fn get_distribution_history(
        &self,
        limit: usize,
    ) -> LedgerResult<Vec<FeeDistributionRecord>>;

    /// Update distribution ratio (governance action)
    async fn update_ratio(&self, new_ratio: DistributionRatio) -> LedgerResult<()>;

    /// Get current configuration
    fn get_config(&self) -> CivilizationTaxConfig;
}

/// Civilization Tax Service implementation
pub struct CivilizationTaxService {
    datastore: Arc<SurrealDatastore>,
    tenant_id: TenantId,
    config: RwLock<CivilizationTaxConfig>,
    /// In-memory pool accounts (would be persisted in production)
    pools: RwLock<HashMap<PoolType, PoolAccount>>,
    /// Distribution records (would be persisted in production)
    records: RwLock<Vec<FeeDistributionRecord>>,
    sequence: std::sync::atomic::AtomicU64,
}

impl CivilizationTaxService {
    /// Create a new Civilization Tax Service
    pub fn new(datastore: Arc<SurrealDatastore>, tenant_id: TenantId) -> Self {
        let mut pools = HashMap::new();
        for pool_type in PoolType::all() {
            pools.insert(pool_type, PoolAccount::new(pool_type));
        }

        Self {
            datastore,
            tenant_id,
            config: RwLock::new(CivilizationTaxConfig::default()),
            pools: RwLock::new(pools),
            records: RwLock::new(Vec::new()),
            sequence: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Create with custom configuration
    pub fn with_config(
        datastore: Arc<SurrealDatastore>,
        tenant_id: TenantId,
        config: CivilizationTaxConfig,
    ) -> Self {
        let mut service = Self::new(datastore, tenant_id);
        *service.config.write().unwrap() = config;
        service
    }

    /// Generate a new record ID
    fn generate_record_id(&self) -> String {
        let seq = self.sequence.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let timestamp = Utc::now().timestamp_micros();
        format!("dist_{:016x}_{:08x}", timestamp, seq)
    }

    /// Load pool state from database
    pub async fn load_from_db(&self) -> LedgerResult<()> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        // Load pool accounts
        for pool_type in PoolType::all() {
            let pool_name = match pool_type {
                PoolType::Infra => "infra",
                PoolType::Civilization => "civilization",
                PoolType::RewardMining => "reward_mining",
            };

            let query = format!(
                "SELECT * FROM pool_accounts WHERE tenant_id = $tenant AND pool_type = '{}'",
                pool_name
            );

            let mut response = session
                .client()
                .query(&query)
                .bind(("tenant", self.tenant_id.clone()))
                .await
                .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

            #[derive(serde::Deserialize)]
            struct PoolRow {
                balance: u64,
                total_deposits: u64,
                total_withdrawals: u64,
            }

            if let Ok(Some(row)) = response.take::<Option<PoolRow>>(0) {
                let mut pools = self.pools.write().unwrap();
                if let Some(account) = pools.get_mut(&pool_type) {
                    account.balance = row.balance;
                    account.total_deposits = row.total_deposits;
                    account.total_withdrawals = row.total_withdrawals;
                }
            }
        }

        Ok(())
    }

    /// Save pool state to database
    async fn save_pool_to_db(&self, pool_type: PoolType) -> LedgerResult<()> {
        let account = {
            let pools = self.pools.read().unwrap();
            pools.get(&pool_type).cloned()
        };

        let Some(account) = account else {
            return Ok(());
        };

        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let pool_name = match pool_type {
            PoolType::Infra => "infra",
            PoolType::Civilization => "civilization",
            PoolType::RewardMining => "reward_mining",
        };

        let id = format!("pool_accounts:{}:{}", self.tenant_id.0, pool_name);

        session
            .client()
            .query("UPSERT $id SET tenant_id = $tenant, pool_type = $pool_type, balance = $balance, total_deposits = $total_deposits, total_withdrawals = $total_withdrawals, updated_at = $updated_at")
            .bind(("id", id))
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("pool_type", pool_name))
            .bind(("balance", account.balance))
            .bind(("total_deposits", account.total_deposits))
            .bind(("total_withdrawals", account.total_withdrawals))
            .bind(("updated_at", account.updated_at))
            .await
            .map_err(|e| LedgerError::Storage(format!("Save failed: {}", e)))?;

        Ok(())
    }

    /// Save distribution record to database
    async fn save_record_to_db(&self, record: &FeeDistributionRecord) -> LedgerResult<()> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let id = format!("fee_distributions:{}:{}", self.tenant_id.0, record.record_id);
        let record_id = record.record_id.clone();
        let fee_receipt_id = record.fee_receipt_id.clone();
        let original_amount = record.original_amount;
        let infra_amount = record.distribution.infra;
        let civilization_amount = record.distribution.civilization;
        let reward_mining_amount = record.distribution.reward_mining;
        let epoch_sequence = record.epoch_sequence;
        let created_at = record.created_at;

        session
            .client()
            .query("CREATE $id SET tenant_id = $tenant, record_id = $record_id, fee_receipt_id = $fee_receipt_id, original_amount = $original_amount, infra_amount = $infra_amount, civilization_amount = $civilization_amount, reward_mining_amount = $reward_mining_amount, epoch_sequence = $epoch_sequence, created_at = $created_at")
            .bind(("id", id))
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("record_id", record_id))
            .bind(("fee_receipt_id", fee_receipt_id))
            .bind(("original_amount", original_amount))
            .bind(("infra_amount", infra_amount))
            .bind(("civilization_amount", civilization_amount))
            .bind(("reward_mining_amount", reward_mining_amount))
            .bind(("epoch_sequence", epoch_sequence))
            .bind(("created_at", created_at))
            .await
            .map_err(|e| LedgerError::Storage(format!("Save record failed: {}", e)))?;

        Ok(())
    }
}

#[async_trait]
impl CivilizationTaxLedger for CivilizationTaxService {
    async fn distribute_fee(
        &self,
        fee_receipt_id: &str,
        amount: u64,
        epoch_sequence: Option<u64>,
    ) -> LedgerResult<FeeDistributionRecord> {
        let config = self.config.read().unwrap().clone();

        // Check minimum threshold
        let distribution = if amount < config.min_distribution_threshold {
            // Below threshold: all goes to Infra pool
            PoolDistribution {
                infra: amount,
                civilization: 0,
                reward_mining: 0,
                total: amount,
            }
        } else {
            config.ratio.distribute(amount)
        };

        // Update pool balances
        {
            let mut pools = self.pools.write().unwrap();
            if let Some(account) = pools.get_mut(&PoolType::Infra) {
                account.deposit(distribution.infra);
            }
            if let Some(account) = pools.get_mut(&PoolType::Civilization) {
                account.deposit(distribution.civilization);
            }
            if let Some(account) = pools.get_mut(&PoolType::RewardMining) {
                account.deposit(distribution.reward_mining);
            }
        }

        // Create record
        let record = FeeDistributionRecord {
            record_id: self.generate_record_id(),
            fee_receipt_id: fee_receipt_id.to_string(),
            original_amount: amount,
            ratio: config.ratio.clone(),
            distribution,
            created_at: Utc::now(),
            epoch_sequence,
        };

        // Save to in-memory records
        {
            let mut records = self.records.write().unwrap();
            records.push(record.clone());
        }

        // Persist to database
        self.save_record_to_db(&record).await?;
        for pool_type in PoolType::all() {
            self.save_pool_to_db(pool_type).await?;
        }

        Ok(record)
    }

    async fn get_pool_summary(&self) -> LedgerResult<PoolSummary> {
        let pools = self.pools.read().unwrap();
        let config = self.config.read().unwrap();

        let accounts: Vec<_> = pools.values().cloned().collect();
        Ok(PoolSummary::from_accounts(&accounts, config.ratio.clone()))
    }

    async fn get_pool_balance(&self, pool: PoolType) -> LedgerResult<u64> {
        let pools = self.pools.read().unwrap();
        Ok(pools.get(&pool).map(|a| a.balance).unwrap_or(0))
    }

    async fn withdraw_from_pool(
        &self,
        pool: PoolType,
        amount: u64,
        _reason: &str,
    ) -> LedgerResult<u64> {
        let withdrawn = {
            let mut pools = self.pools.write().unwrap();
            pools
                .get_mut(&pool)
                .map(|a| a.withdraw(amount))
                .unwrap_or(0)
        };

        // Persist change
        self.save_pool_to_db(pool).await?;

        Ok(withdrawn)
    }

    async fn get_distribution_history(
        &self,
        limit: usize,
    ) -> LedgerResult<Vec<FeeDistributionRecord>> {
        let records = self.records.read().unwrap();
        let start = records.len().saturating_sub(limit);
        Ok(records[start..].to_vec())
    }

    async fn update_ratio(&self, new_ratio: DistributionRatio) -> LedgerResult<()> {
        if !new_ratio.is_valid() {
            return Err(LedgerError::Validation(
                "Distribution ratio must sum to 100% (10000 basis points)".to_string(),
            ));
        }

        let mut config = self.config.write().unwrap();
        config.ratio = new_ratio;
        Ok(())
    }

    fn get_config(&self) -> CivilizationTaxConfig {
        self.config.read().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create test service
    async fn create_test_service() -> CivilizationTaxService {
        // For tests, we'll use a mock approach since we can't easily create SurrealDatastore
        // In production, this would connect to an actual database
        panic!("Use new() with actual datastore for integration tests")
    }

    #[test]
    fn test_distribution_calculation() {
        let ratio = DistributionRatio::default();
        let dist = ratio.distribute(1000);

        assert_eq!(dist.infra, 300);
        assert_eq!(dist.civilization, 200);
        assert_eq!(dist.reward_mining, 500);
        assert!(dist.is_valid());
    }

    #[test]
    fn test_pool_account_operations() {
        let mut account = PoolAccount::new(PoolType::Infra);

        account.deposit(1000);
        assert_eq!(account.balance, 1000);

        let withdrawn = account.withdraw(400);
        assert_eq!(withdrawn, 400);
        assert_eq!(account.balance, 600);
    }

    #[test]
    fn test_ratio_validation() {
        // Valid
        let valid = DistributionRatio::new(4000, 3000, 3000);
        assert!(valid.is_some());
        assert!(valid.unwrap().is_valid());

        // Invalid
        let invalid = DistributionRatio::new(5000, 3000, 3000);
        assert!(invalid.is_none());
    }
}
