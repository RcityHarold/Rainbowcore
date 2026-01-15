//! Treasury Manager
//!
//! Manages the three pools and enforces invariants.

use super::{PoolState, TreasuryContext};
use crate::error::{P3Error, P3Result};
use crate::types::*;
use rust_decimal::Decimal;
use std::collections::HashMap;

/// Treasury manager
pub struct TreasuryManager {
    /// Pool states
    pools: HashMap<TreasuryPool, PoolState>,
    /// Current context
    context: Option<TreasuryContext>,
}

impl TreasuryManager {
    /// Create new manager
    pub fn new() -> Self {
        let mut pools = HashMap::new();
        for pool in TreasuryPool::all() {
            pools.insert(pool.clone(), PoolState::new(pool));
        }

        Self {
            pools,
            context: None,
        }
    }

    /// Set context
    pub fn set_context(&mut self, context: TreasuryContext) {
        self.context = Some(context);
    }

    /// Get context
    pub fn context(&self) -> Option<&TreasuryContext> {
        self.context.as_ref()
    }

    /// Get pool state
    pub fn get_pool(&self, pool: &TreasuryPool) -> Option<&PoolState> {
        self.pools.get(pool)
    }

    /// Get pool state mutably
    pub fn get_pool_mut(&mut self, pool: &TreasuryPool) -> Option<&mut PoolState> {
        self.pools.get_mut(pool)
    }

    /// Capture income and split according to ratios
    pub fn capture_income(&mut self, total_amount: Decimal, epoch_id: &EpochId) -> P3Result<IncomeSplit> {
        let ctx = self.context.as_ref().ok_or_else(|| P3Error::InvalidState {
            reason: "Treasury context not set".to_string(),
        })?;

        // Validate ratios
        if !ctx.ratio_version.ratios.validate() {
            return Err(P3Error::InvalidState {
                reason: "Pool ratios do not sum to 1".to_string(),
            });
        }

        let mut split = IncomeSplit::new(epoch_id.clone(), total_amount);

        // Calculate split
        let infra_amount = total_amount * ctx.ratio_for(&TreasuryPool::InfraPool);
        let civ_amount = total_amount * ctx.ratio_for(&TreasuryPool::CivilizationPool);
        let reward_amount = total_amount - infra_amount - civ_amount; // Remainder to avoid rounding issues

        split.infra_amount = infra_amount;
        split.civilization_amount = civ_amount;
        split.reward_amount = reward_amount;

        // Credit each pool
        self.get_pool_mut(&TreasuryPool::InfraPool)
            .unwrap()
            .credit(infra_amount, epoch_id)?;

        self.get_pool_mut(&TreasuryPool::CivilizationPool)
            .unwrap()
            .credit(civ_amount, epoch_id)?;

        self.get_pool_mut(&TreasuryPool::RewardPool)
            .unwrap()
            .credit(reward_amount, epoch_id)?;

        Ok(split)
    }

    /// Spend from a specific pool
    pub fn spend(
        &mut self,
        pool: TreasuryPool,
        amount: Decimal,
        reason: SpendReasonType,
        epoch_id: &EpochId,
    ) -> P3Result<SpendRecord> {
        let pool_state = self.get_pool_mut(&pool).unwrap();
        pool_state.debit(amount, epoch_id)?;

        Ok(SpendRecord {
            pool,
            amount,
            reason,
            epoch_id: epoch_id.clone(),
        })
    }

    /// Get total balance across all pools
    pub fn total_balance(&self) -> Decimal {
        self.pools.values().map(|p| p.balance).sum()
    }

    /// Get balance for a specific pool
    pub fn pool_balance(&self, pool: &TreasuryPool) -> Decimal {
        self.pools.get(pool).map(|p| p.balance).unwrap_or(Decimal::ZERO)
    }

    /// Reset epoch totals for all pools
    pub fn reset_epoch_totals(&mut self) {
        for pool_state in self.pools.values_mut() {
            pool_state.reset_epoch_totals();
        }
    }

    /// Create snapshots for all pools
    pub fn create_snapshots(&self, epoch_id: &EpochId) -> Vec<PoolBalanceSnapshot> {
        self.pools.values().map(|p| p.snapshot(epoch_id)).collect()
    }

    /// Verify three pool invariant (pools cannot be deleted)
    pub fn verify_invariant(&self) -> bool {
        self.pools.len() == 3
            && self.pools.contains_key(&TreasuryPool::InfraPool)
            && self.pools.contains_key(&TreasuryPool::CivilizationPool)
            && self.pools.contains_key(&TreasuryPool::RewardPool)
    }
}

impl Default for TreasuryManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Income split result
#[derive(Clone, Debug)]
pub struct IncomeSplit {
    /// Epoch ID
    pub epoch_id: EpochId,
    /// Total amount
    pub total_amount: Decimal,
    /// Amount to InfraPool
    pub infra_amount: Decimal,
    /// Amount to CivilizationPool
    pub civilization_amount: Decimal,
    /// Amount to RewardPool
    pub reward_amount: Decimal,
}

impl IncomeSplit {
    /// Create new split
    pub fn new(epoch_id: EpochId, total_amount: Decimal) -> Self {
        Self {
            epoch_id,
            total_amount,
            infra_amount: Decimal::ZERO,
            civilization_amount: Decimal::ZERO,
            reward_amount: Decimal::ZERO,
        }
    }

    /// Verify split sums to total
    pub fn verify_sum(&self) -> bool {
        self.infra_amount + self.civilization_amount + self.reward_amount == self.total_amount
    }
}

/// Spend record
#[derive(Clone, Debug)]
pub struct SpendRecord {
    /// Pool spent from
    pub pool: TreasuryPool,
    /// Amount spent
    pub amount: Decimal,
    /// Reason for spend
    pub reason: SpendReasonType,
    /// Epoch ID
    pub epoch_id: EpochId,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_context() -> TreasuryContext {
        let ratios = PoolRatios::default();
        let ratio_version = PoolRatioVersion {
            ratio_id: "ratio:test".to_string(),
            version: "v1".to_string(),
            valid_from: EpochId::new("epoch:1"),
            supersedes: None,
            issuer_ref: "test".to_string(),
            ratio_digest: ratios.compute_digest(),
            canonicalization_version: CanonVersion::v1(),
            ratios,
        };
        TreasuryContext::new(EpochId::new("epoch:1"), ratio_version)
    }

    #[test]
    fn test_treasury_manager_creation() {
        let manager = TreasuryManager::new();
        assert!(manager.verify_invariant());
        assert_eq!(manager.total_balance(), Decimal::ZERO);
    }

    #[test]
    fn test_capture_income() {
        let mut manager = TreasuryManager::new();
        manager.set_context(create_test_context());

        let epoch = EpochId::new("epoch:1");
        let split = manager.capture_income(Decimal::new(100, 0), &epoch).unwrap();

        assert!(split.verify_sum());
        assert_eq!(split.infra_amount, Decimal::new(40, 0)); // 40%
        assert_eq!(split.civilization_amount, Decimal::new(30, 0)); // 30%
        assert_eq!(split.reward_amount, Decimal::new(30, 0)); // 30%

        // Verify pool balances
        assert_eq!(manager.pool_balance(&TreasuryPool::InfraPool), Decimal::new(40, 0));
        assert_eq!(manager.pool_balance(&TreasuryPool::CivilizationPool), Decimal::new(30, 0));
        assert_eq!(manager.pool_balance(&TreasuryPool::RewardPool), Decimal::new(30, 0));
    }

    #[test]
    fn test_spend() {
        let mut manager = TreasuryManager::new();
        manager.set_context(create_test_context());

        let epoch = EpochId::new("epoch:1");
        manager.capture_income(Decimal::new(100, 0), &epoch).unwrap();

        let record = manager
            .spend(TreasuryPool::RewardPool, Decimal::new(10, 0), SpendReasonType::Anchor, &epoch)
            .unwrap();

        assert_eq!(record.amount, Decimal::new(10, 0));
        assert_eq!(manager.pool_balance(&TreasuryPool::RewardPool), Decimal::new(20, 0));
    }

    #[test]
    fn test_spend_insufficient_balance() {
        let mut manager = TreasuryManager::new();
        manager.set_context(create_test_context());

        let epoch = EpochId::new("epoch:1");
        manager.capture_income(Decimal::new(100, 0), &epoch).unwrap();

        let result = manager.spend(
            TreasuryPool::RewardPool,
            Decimal::new(50, 0), // More than available (30)
            SpendReasonType::Anchor,
            &epoch,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_create_snapshots() {
        let mut manager = TreasuryManager::new();
        manager.set_context(create_test_context());

        let epoch = EpochId::new("epoch:1");
        manager.capture_income(Decimal::new(100, 0), &epoch).unwrap();

        let snapshots = manager.create_snapshots(&epoch);
        assert_eq!(snapshots.len(), 3);
    }

    #[test]
    fn test_reset_epoch_totals() {
        let mut manager = TreasuryManager::new();
        manager.set_context(create_test_context());

        let epoch = EpochId::new("epoch:1");
        manager.capture_income(Decimal::new(100, 0), &epoch).unwrap();

        // Verify totals are set
        let infra = manager.get_pool(&TreasuryPool::InfraPool).unwrap();
        assert_eq!(infra.income_total, Decimal::new(40, 0));

        // Reset
        manager.reset_epoch_totals();

        let infra = manager.get_pool(&TreasuryPool::InfraPool).unwrap();
        assert_eq!(infra.income_total, Decimal::ZERO);
        // Balance should remain
        assert_eq!(infra.balance, Decimal::new(40, 0));
    }
}
