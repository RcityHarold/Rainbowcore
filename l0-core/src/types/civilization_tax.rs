//! Civilization Tax - Three Pool Distribution Model
//!
//! Implements the L0 fee distribution mechanism across three pools:
//! - Infra Pool: Infrastructure and operational costs
//! - Civilization Pool: Public goods and ecosystem development
//! - Reward-Mining Pool: Node operator incentives

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Pool type for fee distribution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolType {
    /// Infrastructure pool - covers operational costs
    Infra,
    /// Civilization pool - funds public goods
    Civilization,
    /// Reward-Mining pool - node operator incentives
    RewardMining,
}

impl PoolType {
    /// Get all pool types
    pub fn all() -> [PoolType; 3] {
        [PoolType::Infra, PoolType::Civilization, PoolType::RewardMining]
    }

    /// Get pool name for display
    pub fn name(&self) -> &'static str {
        match self {
            PoolType::Infra => "Infrastructure Pool",
            PoolType::Civilization => "Civilization Pool",
            PoolType::RewardMining => "Reward-Mining Pool",
        }
    }
}

/// Distribution ratio for the three pools (must sum to 10000 = 100%)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributionRatio {
    /// Infra pool percentage (in basis points, e.g., 3000 = 30%)
    pub infra_bps: u16,
    /// Civilization pool percentage (in basis points)
    pub civilization_bps: u16,
    /// Reward-Mining pool percentage (in basis points)
    pub reward_mining_bps: u16,
}

impl Default for DistributionRatio {
    fn default() -> Self {
        // Default: 30% Infra, 20% Civilization, 50% Reward-Mining
        Self {
            infra_bps: 3000,
            civilization_bps: 2000,
            reward_mining_bps: 5000,
        }
    }
}

impl DistributionRatio {
    /// Create a new distribution ratio
    /// Returns None if percentages don't sum to 10000 (100%)
    pub fn new(infra_bps: u16, civilization_bps: u16, reward_mining_bps: u16) -> Option<Self> {
        if infra_bps as u32 + civilization_bps as u32 + reward_mining_bps as u32 != 10000 {
            return None;
        }
        Some(Self {
            infra_bps,
            civilization_bps,
            reward_mining_bps,
        })
    }

    /// Validate that the ratio sums to 100%
    pub fn is_valid(&self) -> bool {
        self.infra_bps as u32 + self.civilization_bps as u32 + self.reward_mining_bps as u32 == 10000
    }

    /// Get percentage for a specific pool
    pub fn get_bps(&self, pool: PoolType) -> u16 {
        match pool {
            PoolType::Infra => self.infra_bps,
            PoolType::Civilization => self.civilization_bps,
            PoolType::RewardMining => self.reward_mining_bps,
        }
    }

    /// Calculate amount for each pool from a total fee
    pub fn distribute(&self, total_amount: u64) -> PoolDistribution {
        let infra = (total_amount as u128 * self.infra_bps as u128 / 10000) as u64;
        let civilization = (total_amount as u128 * self.civilization_bps as u128 / 10000) as u64;
        // Reward-mining gets the remainder to avoid rounding errors
        let reward_mining = total_amount - infra - civilization;

        PoolDistribution {
            infra,
            civilization,
            reward_mining,
            total: total_amount,
        }
    }
}

/// Result of distributing a fee across pools
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolDistribution {
    /// Amount allocated to Infra pool
    pub infra: u64,
    /// Amount allocated to Civilization pool
    pub civilization: u64,
    /// Amount allocated to Reward-Mining pool
    pub reward_mining: u64,
    /// Total amount distributed
    pub total: u64,
}

impl PoolDistribution {
    /// Get amount for a specific pool
    pub fn get(&self, pool: PoolType) -> u64 {
        match pool {
            PoolType::Infra => self.infra,
            PoolType::Civilization => self.civilization,
            PoolType::RewardMining => self.reward_mining,
        }
    }

    /// Verify the distribution sums correctly
    pub fn is_valid(&self) -> bool {
        self.infra + self.civilization + self.reward_mining == self.total
    }
}

/// Pool account state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolAccount {
    /// Pool type
    pub pool_type: PoolType,
    /// Current balance
    pub balance: u64,
    /// Total deposits (lifetime)
    pub total_deposits: u64,
    /// Total withdrawals (lifetime)
    pub total_withdrawals: u64,
    /// Last updated timestamp
    pub updated_at: DateTime<Utc>,
}

impl PoolAccount {
    /// Create a new empty pool account
    pub fn new(pool_type: PoolType) -> Self {
        Self {
            pool_type,
            balance: 0,
            total_deposits: 0,
            total_withdrawals: 0,
            updated_at: Utc::now(),
        }
    }

    /// Deposit funds into the pool
    pub fn deposit(&mut self, amount: u64) {
        self.balance = self.balance.saturating_add(amount);
        self.total_deposits = self.total_deposits.saturating_add(amount);
        self.updated_at = Utc::now();
    }

    /// Withdraw funds from the pool (returns actual withdrawn amount)
    pub fn withdraw(&mut self, amount: u64) -> u64 {
        let actual = std::cmp::min(amount, self.balance);
        self.balance = self.balance.saturating_sub(actual);
        self.total_withdrawals = self.total_withdrawals.saturating_add(actual);
        self.updated_at = Utc::now();
        actual
    }
}

/// Fee distribution record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeDistributionRecord {
    /// Unique record ID
    pub record_id: String,
    /// Source fee receipt ID
    pub fee_receipt_id: String,
    /// Original fee amount
    pub original_amount: u64,
    /// Distribution ratio used
    pub ratio: DistributionRatio,
    /// Resulting distribution
    pub distribution: PoolDistribution,
    /// Timestamp
    pub created_at: DateTime<Utc>,
    /// Epoch sequence (if applicable)
    pub epoch_sequence: Option<u64>,
}

/// Civilization Tax configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CivilizationTaxConfig {
    /// Distribution ratio
    pub ratio: DistributionRatio,
    /// Minimum fee for distribution (below this, all goes to Infra)
    pub min_distribution_threshold: u64,
    /// Whether to enable subsidy from Civilization pool
    pub enable_subsidies: bool,
    /// Maximum subsidy percentage from Civilization pool (basis points)
    pub max_subsidy_bps: u16,
    /// Operations eligible for subsidy
    pub subsidy_eligible_operations: Vec<String>,
}

impl Default for CivilizationTaxConfig {
    fn default() -> Self {
        Self {
            ratio: DistributionRatio::default(),
            min_distribution_threshold: 10,
            enable_subsidies: true,
            max_subsidy_bps: 5000, // Max 50% subsidy
            subsidy_eligible_operations: vec![
                "identity_registration".to_string(),
                "first_consent".to_string(),
            ],
        }
    }
}

/// Pool summary for reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolSummary {
    /// Pool balances
    pub balances: HashMap<PoolType, u64>,
    /// Total across all pools
    pub total_balance: u64,
    /// Distribution ratio in effect
    pub current_ratio: DistributionRatio,
    /// Timestamp of summary
    pub as_of: DateTime<Utc>,
}

impl PoolSummary {
    /// Create from pool accounts
    pub fn from_accounts(accounts: &[PoolAccount], ratio: DistributionRatio) -> Self {
        let mut balances = HashMap::new();
        let mut total = 0u64;

        for account in accounts {
            balances.insert(account.pool_type, account.balance);
            total = total.saturating_add(account.balance);
        }

        Self {
            balances,
            total_balance: total,
            current_ratio: ratio,
            as_of: Utc::now(),
        }
    }

    /// Get balance for a specific pool
    pub fn get_balance(&self, pool: PoolType) -> u64 {
        self.balances.get(&pool).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_distribution_ratio() {
        let ratio = DistributionRatio::default();
        assert!(ratio.is_valid());
        assert_eq!(ratio.infra_bps, 3000);
        assert_eq!(ratio.civilization_bps, 2000);
        assert_eq!(ratio.reward_mining_bps, 5000);
    }

    #[test]
    fn test_distribution_ratio_validation() {
        // Valid ratio
        let valid = DistributionRatio::new(3000, 2000, 5000);
        assert!(valid.is_some());

        // Invalid ratio (doesn't sum to 100%)
        let invalid = DistributionRatio::new(3000, 2000, 4000);
        assert!(invalid.is_none());
    }

    #[test]
    fn test_distribute_fee() {
        let ratio = DistributionRatio::default();

        // Test with 1000 units
        let dist = ratio.distribute(1000);
        assert_eq!(dist.infra, 300);      // 30%
        assert_eq!(dist.civilization, 200); // 20%
        assert_eq!(dist.reward_mining, 500); // 50%
        assert!(dist.is_valid());

        // Test with odd amount (rounding)
        let dist = ratio.distribute(1001);
        assert_eq!(dist.infra, 300);
        assert_eq!(dist.civilization, 200);
        assert_eq!(dist.reward_mining, 501); // Gets remainder
        assert!(dist.is_valid());
    }

    #[test]
    fn test_pool_account() {
        let mut account = PoolAccount::new(PoolType::Infra);
        assert_eq!(account.balance, 0);

        account.deposit(1000);
        assert_eq!(account.balance, 1000);
        assert_eq!(account.total_deposits, 1000);

        let withdrawn = account.withdraw(300);
        assert_eq!(withdrawn, 300);
        assert_eq!(account.balance, 700);
        assert_eq!(account.total_withdrawals, 300);

        // Try to withdraw more than balance
        let withdrawn = account.withdraw(1000);
        assert_eq!(withdrawn, 700); // Only gets what's available
        assert_eq!(account.balance, 0);
    }

    #[test]
    fn test_pool_summary() {
        let accounts = vec![
            {
                let mut a = PoolAccount::new(PoolType::Infra);
                a.deposit(1000);
                a
            },
            {
                let mut a = PoolAccount::new(PoolType::Civilization);
                a.deposit(500);
                a
            },
            {
                let mut a = PoolAccount::new(PoolType::RewardMining);
                a.deposit(2000);
                a
            },
        ];

        let summary = PoolSummary::from_accounts(&accounts, DistributionRatio::default());
        assert_eq!(summary.total_balance, 3500);
        assert_eq!(summary.get_balance(PoolType::Infra), 1000);
        assert_eq!(summary.get_balance(PoolType::Civilization), 500);
        assert_eq!(summary.get_balance(PoolType::RewardMining), 2000);
    }
}
