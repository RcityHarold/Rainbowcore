//! Three Pool Treasury
//!
//! Chapter 6: Three Pool Treasury and Budget Allocation
//!
//! Core invariants:
//! - Three pools cannot be deleted or merged
//! - Fee split must not mix columns (protocol_tax / dsn_storage / service_fee)
//! - Pool ratio sum must equal 1

mod manager;
mod distribution;

pub use manager::*;
pub use distribution::*;

use crate::error::{P3Error, P3Result};
use crate::types::*;
use rust_decimal::Decimal;

/// Treasury context
#[derive(Clone, Debug)]
pub struct TreasuryContext {
    /// Epoch ID
    pub epoch_id: EpochId,
    /// Pool ratio version
    pub ratio_version: PoolRatioVersion,
}

impl TreasuryContext {
    /// Create new context
    pub fn new(epoch_id: EpochId, ratio_version: PoolRatioVersion) -> Self {
        Self {
            epoch_id,
            ratio_version,
        }
    }

    /// Get ratio for a pool
    pub fn ratio_for(&self, pool: &TreasuryPool) -> Decimal {
        self.ratio_version.ratios.ratio_for(pool)
    }
}

/// Pool state
#[derive(Clone, Debug)]
pub struct PoolState {
    /// Pool type
    pub pool: TreasuryPool,
    /// Current balance
    pub balance: Decimal,
    /// Total income this epoch
    pub income_total: Decimal,
    /// Total spend this epoch
    pub spend_total: Decimal,
    /// Last update epoch
    pub last_updated_epoch: EpochId,
}

impl PoolState {
    /// Create new pool state
    pub fn new(pool: TreasuryPool) -> Self {
        Self {
            pool,
            balance: Decimal::ZERO,
            income_total: Decimal::ZERO,
            spend_total: Decimal::ZERO,
            last_updated_epoch: EpochId::new("epoch:genesis"),
        }
    }

    /// Credit income to pool
    pub fn credit(&mut self, amount: Decimal, epoch_id: &EpochId) -> P3Result<()> {
        if amount < Decimal::ZERO {
            return Err(P3Error::InvalidAmount {
                reason: "Cannot credit negative amount".to_string(),
            });
        }
        self.balance += amount;
        self.income_total += amount;
        self.last_updated_epoch = epoch_id.clone();
        Ok(())
    }

    /// Debit spend from pool
    pub fn debit(&mut self, amount: Decimal, epoch_id: &EpochId) -> P3Result<()> {
        if amount < Decimal::ZERO {
            return Err(P3Error::InvalidAmount {
                reason: "Cannot debit negative amount".to_string(),
            });
        }
        if amount > self.balance {
            return Err(P3Error::InsufficientBalance {
                pool: self.pool.name().to_string(),
                required: amount,
                available: self.balance,
            });
        }
        self.balance -= amount;
        self.spend_total += amount;
        self.last_updated_epoch = epoch_id.clone();
        Ok(())
    }

    /// Reset epoch totals
    pub fn reset_epoch_totals(&mut self) {
        self.income_total = Decimal::ZERO;
        self.spend_total = Decimal::ZERO;
    }

    /// Create snapshot
    pub fn snapshot(&self, epoch_id: &EpochId) -> PoolBalanceSnapshot {
        PoolBalanceSnapshot {
            pool: self.pool.clone(),
            epoch_id: epoch_id.clone(),
            balance_digest: MoneyDigest::new(
                P3Digest::blake3(self.balance.to_string().as_bytes()),
                "POINTS",
            ),
            income_total_digest: MoneyDigest::new(
                P3Digest::blake3(self.income_total.to_string().as_bytes()),
                "POINTS",
            ),
            spend_total_digest: MoneyDigest::new(
                P3Digest::blake3(self.spend_total.to_string().as_bytes()),
                "POINTS",
            ),
            snapshot_at: chrono::Utc::now(),
        }
    }
}

/// Three column bill builder
pub struct ThreeColumnBillBuilder {
    epoch_id: EpochId,
    protocol_tax_amount: Decimal,
    dsn_storage_amount: Decimal,
    service_fee_amount: Decimal,
    fee_schedule_version: String,
}

impl ThreeColumnBillBuilder {
    /// Create new builder
    pub fn new(epoch_id: EpochId) -> Self {
        Self {
            epoch_id,
            protocol_tax_amount: Decimal::ZERO,
            dsn_storage_amount: Decimal::ZERO,
            service_fee_amount: Decimal::ZERO,
            fee_schedule_version: "v1".to_string(),
        }
    }

    /// Set protocol tax
    pub fn protocol_tax(mut self, amount: Decimal) -> Self {
        self.protocol_tax_amount = amount;
        self
    }

    /// Set DSN storage
    pub fn dsn_storage(mut self, amount: Decimal) -> Self {
        self.dsn_storage_amount = amount;
        self
    }

    /// Set service fee
    pub fn service_fee(mut self, amount: Decimal) -> Self {
        self.service_fee_amount = amount;
        self
    }

    /// Set fee schedule version
    pub fn fee_schedule(mut self, version: impl Into<String>) -> Self {
        self.fee_schedule_version = version.into();
        self
    }

    /// Build the bill
    pub fn build(self) -> ThreeColumnBill {
        ThreeColumnBill {
            protocol_tax: ProtocolTaxColumn {
                amount_digest: MoneyDigest::new(
                    P3Digest::blake3(self.protocol_tax_amount.to_string().as_bytes()),
                    "POINTS",
                ),
                fee_receipt_refs_digest: RefDigest::empty(),
                fee_schedule_version_ref: self.fee_schedule_version.clone(),
                bound_epoch_id: self.epoch_id.clone(),
            },
            dsn_storage: DsnStorageColumn {
                amount_digest: MoneyDigest::new(
                    P3Digest::blake3(self.dsn_storage_amount.to_string().as_bytes()),
                    "POINTS",
                ),
                dsn_spend_refs_digest: RefDigest::empty(),
                storage_policy_ref: None,
                bound_epoch_id: self.epoch_id.clone(),
            },
            service_fee: ServiceFeeColumn {
                amount_digest: MoneyDigest::new(
                    P3Digest::blake3(self.service_fee_amount.to_string().as_bytes()),
                    "POINTS",
                ),
                invoice_ref: None,
                contract_ref: None,
                provider_ref: None,
                bound_epoch_id: self.epoch_id,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_state_credit_debit() {
        let mut state = PoolState::new(TreasuryPool::RewardPool);
        let epoch = EpochId::new("epoch:1");

        state.credit(Decimal::new(100, 0), &epoch).unwrap();
        assert_eq!(state.balance, Decimal::new(100, 0));
        assert_eq!(state.income_total, Decimal::new(100, 0));

        state.debit(Decimal::new(30, 0), &epoch).unwrap();
        assert_eq!(state.balance, Decimal::new(70, 0));
        assert_eq!(state.spend_total, Decimal::new(30, 0));
    }

    #[test]
    fn test_pool_state_insufficient_balance() {
        let mut state = PoolState::new(TreasuryPool::RewardPool);
        let epoch = EpochId::new("epoch:1");

        state.credit(Decimal::new(50, 0), &epoch).unwrap();

        let result = state.debit(Decimal::new(100, 0), &epoch);
        assert!(result.is_err());
    }

    #[test]
    fn test_three_column_bill_builder() {
        let bill = ThreeColumnBillBuilder::new(EpochId::new("epoch:1"))
            .protocol_tax(Decimal::new(10, 0))
            .dsn_storage(Decimal::new(5, 0))
            .service_fee(Decimal::new(3, 0))
            .build();

        assert!(bill.verify_no_mixing());
    }

    #[test]
    fn test_treasury_context() {
        let ratios = PoolRatios::default();
        let ratio_version = PoolRatioVersion {
            ratio_id: "ratio:1".to_string(),
            version: "v1".to_string(),
            valid_from: EpochId::new("epoch:1"),
            supersedes: None,
            issuer_ref: "governance".to_string(),
            ratio_digest: ratios.compute_digest(),
            canonicalization_version: CanonVersion::v1(),
            ratios,
        };

        let ctx = TreasuryContext::new(EpochId::new("epoch:1"), ratio_version);

        assert_eq!(ctx.ratio_for(&TreasuryPool::InfraPool), Decimal::new(40, 2));
    }
}
