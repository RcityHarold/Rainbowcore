//! Three Pool Treasury
//!
//! Chapter 6: Three Pool Treasury and Budget Allocation
//!
//! Core invariants:
//! - Three pools cannot be deleted or merged
//! - Fee split must not mix columns (protocol_tax / dsn_storage / service_fee)
//! - Pool ratio sum must equal 1

use super::common::*;
use l0_core::types::ActorId;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

/// Three pool structure (cannot be deleted or merged)
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TreasuryPool {
    /// Infrastructure public base
    InfraPool,
    /// Governance public safety
    CivilizationPool,
    /// Incentive pool
    RewardPool,
}

impl TreasuryPool {
    /// Get all pools
    pub fn all() -> Vec<TreasuryPool> {
        vec![
            TreasuryPool::InfraPool,
            TreasuryPool::CivilizationPool,
            TreasuryPool::RewardPool,
        ]
    }

    /// Get pool name
    pub fn name(&self) -> &'static str {
        match self {
            TreasuryPool::InfraPool => "InfraPool",
            TreasuryPool::CivilizationPool => "CivilizationPool",
            TreasuryPool::RewardPool => "RewardPool",
        }
    }
}

/// Pool ratio version
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoolRatioVersion {
    pub ratio_id: String,
    pub version: String,
    pub valid_from: EpochId,
    pub supersedes: Option<String>,
    pub issuer_ref: String,
    pub ratio_digest: P3Digest,
    pub canonicalization_version: CanonVersion,
    /// Three pool ratios
    pub ratios: PoolRatios,
}

impl PoolRatioVersion {
    /// Verify ratio digest
    pub fn verify_digest(&self) -> bool {
        let computed = self.ratios.compute_digest();
        computed == self.ratio_digest
    }
}

/// Three pool ratios
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoolRatios {
    pub infra_ratio: Decimal,
    pub civilization_ratio: Decimal,
    pub reward_ratio: Decimal,
}

impl PoolRatios {
    /// Verify ratio sum equals 1
    pub fn validate(&self) -> bool {
        self.infra_ratio + self.civilization_ratio + self.reward_ratio == Decimal::ONE
    }

    /// Get ratio for a specific pool
    pub fn ratio_for(&self, pool: &TreasuryPool) -> Decimal {
        match pool {
            TreasuryPool::InfraPool => self.infra_ratio,
            TreasuryPool::CivilizationPool => self.civilization_ratio,
            TreasuryPool::RewardPool => self.reward_ratio,
        }
    }

    /// Compute digest
    pub fn compute_digest(&self) -> P3Digest {
        let data = format!(
            "{}:{}:{}",
            self.infra_ratio, self.civilization_ratio, self.reward_ratio
        );
        P3Digest::blake3(data.as_bytes())
    }

    /// Default ratios (40/30/30)
    pub fn default_ratios() -> Self {
        Self {
            infra_ratio: Decimal::new(40, 2),       // 0.40
            civilization_ratio: Decimal::new(30, 2), // 0.30
            reward_ratio: Decimal::new(30, 2),       // 0.30
        }
    }
}

impl Default for PoolRatios {
    fn default() -> Self {
        Self::default_ratios()
    }
}

/// Income captured entry
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IncomeCapturedEntry {
    pub entry_id: String,
    pub bound_epoch_id: EpochId,
    pub fee_receipt_refs_digest: RefDigest,
    pub amount_digest: MoneyDigest,
    pub anchor_type_breakdown_digest: Option<P3Digest>,
    pub fee_schedule_version_ref: String,
    pub status: IncomeStatus,
    pub idempotency_key: IdempotencyKey,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncomeStatus {
    Captured,
    Pending,
    Reversed,
}

/// Budget spend entry
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BudgetSpendEntry {
    pub entry_id: String,
    pub bound_epoch_id: EpochId,
    pub reason_type: SpendReasonType,
    pub amount_digest: MoneyDigest,
    pub basis_refs_digest: RefDigest,
    pub idempotency_key: IdempotencyKey,
    pub status: ExecutionStatus,
    pub failure_reason_digest: Option<P3Digest>,
    pub policy_refs_digest: Option<RefDigest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpendReasonType {
    Anchor,
    Sampling,
    Ops,
    Governance,
    Distribution,
    DepositForfeiture,
    FineCollection,
    Clawback,
}

/// Subsidy entry
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubsidyEntry {
    pub entry_id: String,
    pub bound_epoch_id: EpochId,
    pub subsidy_policy_ref: String,
    pub reason_type: SubsidyReasonType,
    pub beneficiary_ref: String,
    pub amount_digest: MoneyDigest,
    pub basis_refs_digest: RefDigest,
    pub status: ExecutionStatus,
    pub failure_reason_digest: Option<P3Digest>,
    pub reasons_digest: Option<super::points::ReasonsDigest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubsidyReasonType {
    Sampling,
    Storage,
    Ops,
    Governance,
    Anchor,
}

/// Three column bill split (no mixing tax)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreeColumnBill {
    /// Protocol tax
    pub protocol_tax: ProtocolTaxColumn,
    /// DSN storage
    pub dsn_storage: DsnStorageColumn,
    /// Service fee
    pub service_fee: ServiceFeeColumn,
}

impl ThreeColumnBill {
    /// Verify no mixing (each column has exclusive receipts and consistent epochs)
    ///
    /// This basic verification checks:
    /// 1. All columns reference the same epoch (bound_epoch_id consistency)
    /// 2. Non-zero amounts must have non-zero receipt refs (traceability)
    /// 3. Currency consistency across all columns
    ///
    /// For full receipt-level overlap verification, use `verify_no_mixing_with_receipts`
    pub fn verify_no_mixing(&self) -> bool {
        // Check epoch consistency - all columns must reference the same epoch
        if self.protocol_tax.bound_epoch_id != self.dsn_storage.bound_epoch_id
            || self.dsn_storage.bound_epoch_id != self.service_fee.bound_epoch_id
        {
            return false;
        }

        // Check currency consistency - all columns must use the same currency
        let base_currency = &self.protocol_tax.amount_digest.currency;
        if self.dsn_storage.amount_digest.currency != *base_currency
            || self.service_fee.amount_digest.currency != *base_currency
        {
            return false;
        }

        // Check traceability - non-zero amounts must have non-zero receipt refs
        // Protocol tax: if amount is non-zero, fee_receipt_refs_digest must be non-zero
        if !self.protocol_tax.amount_digest.amount_digest.is_zero()
            && self.protocol_tax.fee_receipt_refs_digest.0.is_zero()
        {
            return false;
        }

        // DSN storage: if amount is non-zero, dsn_spend_refs_digest must be non-zero
        if !self.dsn_storage.amount_digest.amount_digest.is_zero()
            && self.dsn_storage.dsn_spend_refs_digest.0.is_zero()
        {
            return false;
        }

        // Service fee: if amount is non-zero, at least one of invoice_ref/contract_ref/provider_ref must exist
        if !self.service_fee.amount_digest.amount_digest.is_zero() {
            let has_reference = self.service_fee.invoice_ref.is_some()
                || self.service_fee.contract_ref.is_some()
                || self.service_fee.provider_ref.is_some();
            if !has_reference {
                return false;
            }
        }

        true
    }

    /// Verify no mixing with actual receipt sets
    ///
    /// This performs full receipt-level verification to ensure no receipt appears in multiple columns.
    /// Each receipt should belong to exactly one column (protocol_tax, dsn_storage, or service_fee).
    pub fn verify_no_mixing_with_receipts(
        &self,
        protocol_tax_receipts: &[P3Digest],
        dsn_storage_receipts: &[P3Digest],
        service_fee_receipts: &[P3Digest],
    ) -> bool {
        use std::collections::HashSet;

        // Build sets for O(1) lookup
        let protocol_set: HashSet<_> = protocol_tax_receipts.iter().collect();
        let dsn_set: HashSet<_> = dsn_storage_receipts.iter().collect();
        let service_set: HashSet<_> = service_fee_receipts.iter().collect();

        // Check for overlaps between protocol_tax and dsn_storage
        for receipt in &protocol_set {
            if dsn_set.contains(receipt) {
                return false; // Same receipt in both protocol_tax and dsn_storage
            }
        }

        // Check for overlaps between protocol_tax and service_fee
        for receipt in &protocol_set {
            if service_set.contains(receipt) {
                return false; // Same receipt in both protocol_tax and service_fee
            }
        }

        // Check for overlaps between dsn_storage and service_fee
        for receipt in &dsn_set {
            if service_set.contains(receipt) {
                return false; // Same receipt in both dsn_storage and service_fee
            }
        }

        // No overlaps found
        true
    }

    /// Get total amount digest
    pub fn total_digest(&self) -> P3Digest {
        let mut data = Vec::new();
        data.extend_from_slice(&self.protocol_tax.amount_digest.amount_digest.0);
        data.extend_from_slice(&self.dsn_storage.amount_digest.amount_digest.0);
        data.extend_from_slice(&self.service_fee.amount_digest.amount_digest.0);
        P3Digest::blake3(&data)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtocolTaxColumn {
    pub amount_digest: MoneyDigest,
    pub fee_receipt_refs_digest: RefDigest,
    pub fee_schedule_version_ref: String,
    pub bound_epoch_id: EpochId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DsnStorageColumn {
    pub amount_digest: MoneyDigest,
    pub dsn_spend_refs_digest: RefDigest,
    pub storage_policy_ref: Option<String>,
    pub bound_epoch_id: EpochId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceFeeColumn {
    pub amount_digest: MoneyDigest,
    pub invoice_ref: Option<String>,
    pub contract_ref: Option<String>,
    pub provider_ref: Option<String>,
    pub bound_epoch_id: EpochId,
}

/// Pool balance snapshot
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoolBalanceSnapshot {
    pub pool: TreasuryPool,
    pub epoch_id: EpochId,
    pub balance_digest: MoneyDigest,
    pub income_total_digest: MoneyDigest,
    pub spend_total_digest: MoneyDigest,
    pub snapshot_at: chrono::DateTime<chrono::Utc>,
}

/// Distribution entry (reward payout)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DistributionEntry {
    pub distribution_id: DistributionId,
    pub bound_epoch_id: EpochId,
    pub recipient_actor_id: ActorId,
    pub amount_digest: MoneyDigest,
    pub points_ref: P3Digest,
    pub attribution_ref: P3Digest,
    pub status: ExecutionStatus,
    pub payout_method: PayoutMethod,
    pub idempotency_key: IdempotencyKey,
    pub failure_reason_digest: Option<P3Digest>,
}

/// Payout method
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayoutMethod {
    OnChain,
    OffChain,
    Credit,
    Deferred,
}

/// Pool ID
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PoolId(pub String);

impl PoolId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Reward points (wrapper for decimal)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewardPoints(pub Decimal);

impl RewardPoints {
    pub fn new(value: Decimal) -> Self {
        Self(value)
    }

    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

/// Reward distribution entry (for result root)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RewardDistributionEntry {
    /// Entry ID
    pub entry_id: String,
    /// Recipient actor ID
    pub recipient: ActorId,
    /// Pool ID
    pub pool_id: PoolId,
    /// Reward amount in points
    pub amount: RewardPoints,
    /// Attribution reference
    pub attribution_ref: Option<P3Digest>,
    /// Distribution reference
    pub distribution_ref: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_ratios_validation() {
        let valid = PoolRatios {
            infra_ratio: Decimal::new(40, 2),
            civilization_ratio: Decimal::new(30, 2),
            reward_ratio: Decimal::new(30, 2),
        };
        assert!(valid.validate());

        let invalid = PoolRatios {
            infra_ratio: Decimal::new(50, 2),
            civilization_ratio: Decimal::new(30, 2),
            reward_ratio: Decimal::new(30, 2),
        };
        assert!(!invalid.validate());
    }

    #[test]
    fn test_treasury_pool_all() {
        let pools = TreasuryPool::all();
        assert_eq!(pools.len(), 3);
    }

    #[test]
    fn test_pool_ratio_lookup() {
        let ratios = PoolRatios::default_ratios();
        assert_eq!(ratios.ratio_for(&TreasuryPool::InfraPool), Decimal::new(40, 2));
        assert_eq!(ratios.ratio_for(&TreasuryPool::RewardPool), Decimal::new(30, 2));
    }

    fn create_test_bill(epoch_id: EpochId, currency: &str) -> ThreeColumnBill {
        ThreeColumnBill {
            protocol_tax: ProtocolTaxColumn {
                amount_digest: MoneyDigest::new(P3Digest::blake3(b"100"), currency),
                fee_receipt_refs_digest: RefDigest::new(P3Digest::blake3(b"protocol_receipts")),
                fee_schedule_version_ref: "v1".to_string(),
                bound_epoch_id: epoch_id.clone(),
            },
            dsn_storage: DsnStorageColumn {
                amount_digest: MoneyDigest::new(P3Digest::blake3(b"50"), currency),
                dsn_spend_refs_digest: RefDigest::new(P3Digest::blake3(b"dsn_receipts")),
                storage_policy_ref: Some("policy:1".to_string()),
                bound_epoch_id: epoch_id.clone(),
            },
            service_fee: ServiceFeeColumn {
                amount_digest: MoneyDigest::new(P3Digest::blake3(b"25"), currency),
                invoice_ref: Some("invoice:001".to_string()),
                contract_ref: None,
                provider_ref: Some("provider:A".to_string()),
                bound_epoch_id: epoch_id,
            },
        }
    }

    #[test]
    fn test_verify_no_mixing_valid() {
        let bill = create_test_bill(EpochId::new("epoch:1"), "USD");
        assert!(bill.verify_no_mixing());
    }

    #[test]
    fn test_verify_no_mixing_epoch_mismatch() {
        let mut bill = create_test_bill(EpochId::new("epoch:1"), "USD");
        // Make DSN storage reference a different epoch
        bill.dsn_storage.bound_epoch_id = EpochId::new("epoch:2");
        assert!(!bill.verify_no_mixing());
    }

    #[test]
    fn test_verify_no_mixing_currency_mismatch() {
        let mut bill = create_test_bill(EpochId::new("epoch:1"), "USD");
        // Make service fee use a different currency
        bill.service_fee.amount_digest.currency = "EUR".to_string();
        assert!(!bill.verify_no_mixing());
    }

    #[test]
    fn test_verify_no_mixing_missing_receipt_ref() {
        let epoch_id = EpochId::new("epoch:1");
        let bill = ThreeColumnBill {
            protocol_tax: ProtocolTaxColumn {
                amount_digest: MoneyDigest::new(P3Digest::blake3(b"100"), "USD"),
                fee_receipt_refs_digest: RefDigest::empty(), // Zero ref with non-zero amount
                fee_schedule_version_ref: "v1".to_string(),
                bound_epoch_id: epoch_id.clone(),
            },
            dsn_storage: DsnStorageColumn {
                amount_digest: MoneyDigest::new(P3Digest::zero(), "USD"), // Zero amount is OK
                dsn_spend_refs_digest: RefDigest::empty(),
                storage_policy_ref: None,
                bound_epoch_id: epoch_id.clone(),
            },
            service_fee: ServiceFeeColumn {
                amount_digest: MoneyDigest::new(P3Digest::zero(), "USD"),
                invoice_ref: None,
                contract_ref: None,
                provider_ref: None,
                bound_epoch_id: epoch_id,
            },
        };
        // Non-zero amount with zero receipt ref should fail
        assert!(!bill.verify_no_mixing());
    }

    #[test]
    fn test_verify_no_mixing_service_fee_missing_refs() {
        let epoch_id = EpochId::new("epoch:1");
        let bill = ThreeColumnBill {
            protocol_tax: ProtocolTaxColumn {
                amount_digest: MoneyDigest::new(P3Digest::zero(), "USD"),
                fee_receipt_refs_digest: RefDigest::empty(),
                fee_schedule_version_ref: "v1".to_string(),
                bound_epoch_id: epoch_id.clone(),
            },
            dsn_storage: DsnStorageColumn {
                amount_digest: MoneyDigest::new(P3Digest::zero(), "USD"),
                dsn_spend_refs_digest: RefDigest::empty(),
                storage_policy_ref: None,
                bound_epoch_id: epoch_id.clone(),
            },
            service_fee: ServiceFeeColumn {
                amount_digest: MoneyDigest::new(P3Digest::blake3(b"25"), "USD"), // Non-zero amount
                invoice_ref: None, // No refs at all
                contract_ref: None,
                provider_ref: None,
                bound_epoch_id: epoch_id,
            },
        };
        // Non-zero service fee amount with no refs should fail
        assert!(!bill.verify_no_mixing());
    }

    #[test]
    fn test_verify_no_mixing_with_receipts_valid() {
        let bill = create_test_bill(EpochId::new("epoch:1"), "USD");

        let protocol_receipts = vec![
            P3Digest::blake3(b"receipt:protocol:1"),
            P3Digest::blake3(b"receipt:protocol:2"),
        ];
        let dsn_receipts = vec![
            P3Digest::blake3(b"receipt:dsn:1"),
        ];
        let service_receipts = vec![
            P3Digest::blake3(b"receipt:service:1"),
            P3Digest::blake3(b"receipt:service:2"),
        ];

        assert!(bill.verify_no_mixing_with_receipts(
            &protocol_receipts,
            &dsn_receipts,
            &service_receipts,
        ));
    }

    #[test]
    fn test_verify_no_mixing_with_receipts_overlap() {
        let bill = create_test_bill(EpochId::new("epoch:1"), "USD");

        let shared_receipt = P3Digest::blake3(b"receipt:shared"); // Same receipt in multiple columns

        let protocol_receipts = vec![
            P3Digest::blake3(b"receipt:protocol:1"),
            shared_receipt.clone(), // Duplicate!
        ];
        let dsn_receipts = vec![
            shared_receipt, // Duplicate!
        ];
        let service_receipts = vec![];

        // Should detect the overlap
        assert!(!bill.verify_no_mixing_with_receipts(
            &protocol_receipts,
            &dsn_receipts,
            &service_receipts,
        ));
    }
}
