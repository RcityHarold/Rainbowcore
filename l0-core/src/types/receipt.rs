//! Receipt types for L0

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use super::common::Digest;
use super::actor::ReceiptId;

/// Domain batch type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeType {
    AknBatch,
    ConsentBatch,
    VerdictBatch,
    DisputeBatch,
    RepairBatch,
    ClawbackBatch,
    LogBatch,
    TraceBatch,
    BackfillBatch,
    IdentityBatch,
    CovenantStatusBatch,
}

/// Root type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootKind {
    BatchRoot,
    EpochRoot,
}

/// L0 Receipt - the core accountability object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L0Receipt {
    pub receipt_id: ReceiptId,
    pub scope_type: ScopeType,
    pub root_kind: RootKind,
    pub root: Digest,
    pub time_window_start: DateTime<Utc>,
    pub time_window_end: DateTime<Utc>,
    pub batch_sequence_no: Option<u64>,
    pub signer_set_version: String,
    pub canonicalization_version: String,
    pub anchor_policy_version: String,
    pub fee_schedule_version: String,
    pub fee_receipt_id: String,
    pub signed_snapshot_ref: String,
    pub created_at: DateTime<Utc>,
    pub rejected: Option<bool>,
    pub reject_reason_code: Option<String>,
    pub observer_reports_digest: Option<Digest>,
}

/// Fee units type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeUnits {
    BatchRoot,
    EntryCount,
    SizeTier,
}

impl Default for FeeUnits {
    fn default() -> Self {
        Self::BatchRoot
    }
}

/// Fee receipt status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeReceiptStatus {
    ChargedPendingReceipt,
    Charged,
    Refunded,
    Forfeited,
    ChargedNoReceipt,
}

/// Fee receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeReceipt {
    pub fee_receipt_id: String,
    pub fee_schedule_version: String,
    pub payer_actor_id: String,
    pub anchor_type: String,
    pub units: FeeUnits,
    pub units_count: u32,
    pub risk_multiplier: Option<String>,
    pub amount: String,
    pub timestamp: DateTime<Utc>,
    pub linked_anchor_id: String,
    pub linked_receipt_id: Option<String>,
    pub deposit_amount: Option<String>,
    pub discount_digest: Option<Digest>,
    pub subsidy_digest: Option<Digest>,
    pub status: FeeReceiptStatus,
}

/// Fee schedule - defines pricing for L0 operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeSchedule {
    /// Schedule version (e.g., "v1.0.0")
    pub version: String,
    /// Effective from timestamp
    pub effective_from: DateTime<Utc>,
    /// Base fee per batch root (in smallest unit)
    pub batch_root_fee: u64,
    /// Fee per entry in a batch
    pub entry_fee: u64,
    /// Size tier fees (index = tier, value = fee)
    pub size_tier_fees: Vec<u64>,
    /// Risk multiplier ranges (min, max, multiplier)
    pub risk_multipliers: Vec<RiskMultiplierTier>,
    /// Discount eligibility (actor type -> discount percentage)
    pub discounts: std::collections::HashMap<String, u8>,
    /// Operations that are free (e.g., TipWitness)
    pub free_operations: Vec<String>,
}

impl Default for FeeSchedule {
    fn default() -> Self {
        Self {
            version: "v1.0.0".to_string(),
            effective_from: Utc::now(),
            batch_root_fee: 100,
            entry_fee: 1,
            size_tier_fees: vec![10, 50, 100, 500, 1000],
            risk_multipliers: vec![
                RiskMultiplierTier { min_amount: 0, max_amount: 1000, multiplier: 100 },
                RiskMultiplierTier { min_amount: 1001, max_amount: 10000, multiplier: 110 },
                RiskMultiplierTier { min_amount: 10001, max_amount: u64::MAX, multiplier: 125 },
            ],
            discounts: std::collections::HashMap::new(),
            free_operations: vec!["tip_witness".to_string()],
        }
    }
}

impl FeeSchedule {
    /// Calculate fee for a given operation
    pub fn calculate_fee(&self, units: FeeUnits, units_count: u32, risk_amount: Option<u64>) -> FeeCalculation {
        // Check if operation is free
        let base_fee = match units {
            FeeUnits::BatchRoot => self.batch_root_fee * units_count as u64,
            FeeUnits::EntryCount => self.entry_fee * units_count as u64,
            FeeUnits::SizeTier => {
                let tier = std::cmp::min(units_count as usize, self.size_tier_fees.len().saturating_sub(1));
                self.size_tier_fees.get(tier).copied().unwrap_or(0)
            }
        };

        // Apply risk multiplier if applicable
        let risk_multiplier = risk_amount.map(|amount| {
            self.risk_multipliers
                .iter()
                .find(|t| amount >= t.min_amount && amount <= t.max_amount)
                .map(|t| t.multiplier)
                .unwrap_or(100)
        }).unwrap_or(100);

        let adjusted_fee = (base_fee * risk_multiplier as u64) / 100;

        FeeCalculation {
            base_fee,
            risk_multiplier,
            discount_percentage: 0,
            subsidy_amount: 0,
            final_fee: adjusted_fee,
        }
    }

    /// Check if an operation is free
    pub fn is_free_operation(&self, operation: &str) -> bool {
        self.free_operations.contains(&operation.to_string())
    }
}

/// Risk multiplier tier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskMultiplierTier {
    pub min_amount: u64,
    pub max_amount: u64,
    /// Multiplier as percentage (100 = 1x, 150 = 1.5x)
    pub multiplier: u16,
}

/// Result of fee calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeCalculation {
    /// Base fee before adjustments
    pub base_fee: u64,
    /// Risk multiplier applied (as percentage, 100 = 1x)
    pub risk_multiplier: u16,
    /// Discount percentage applied
    pub discount_percentage: u8,
    /// Subsidy amount deducted
    pub subsidy_amount: u64,
    /// Final fee after all adjustments
    pub final_fee: u64,
}

/// Receipt verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptVerifyResult {
    pub valid: bool,
    pub evidence_level: super::common::EvidenceLevel,
    pub chain_anchored: bool,
    pub errors: Vec<String>,
}

impl ReceiptVerifyResult {
    pub fn verified_a() -> Self {
        Self {
            valid: true,
            evidence_level: super::common::EvidenceLevel::A,
            chain_anchored: false,
            errors: vec![],
        }
    }

    pub fn verified_a_with_chain() -> Self {
        Self {
            valid: true,
            evidence_level: super::common::EvidenceLevel::A,
            chain_anchored: true,
            errors: vec![],
        }
    }

    pub fn local_only() -> Self {
        Self {
            valid: true,
            evidence_level: super::common::EvidenceLevel::B,
            chain_anchored: false,
            errors: vec![],
        }
    }

    pub fn failed(errors: Vec<String>) -> Self {
        Self {
            valid: false,
            evidence_level: super::common::EvidenceLevel::B,
            chain_anchored: false,
            errors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_type_serialization() {
        let scope = ScopeType::VerdictBatch;
        let json = serde_json::to_string(&scope).unwrap();
        assert_eq!(json, "\"verdict_batch\"");
    }

    #[test]
    fn test_root_kind_serialization() {
        let kind = RootKind::BatchRoot;
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, "\"batch_root\"");
    }

    #[test]
    fn test_fee_schedule_default() {
        let schedule = FeeSchedule::default();
        assert_eq!(schedule.version, "v1.0.0");
        assert_eq!(schedule.batch_root_fee, 100);
        assert_eq!(schedule.entry_fee, 1);
        assert!(schedule.is_free_operation("tip_witness"));
        assert!(!schedule.is_free_operation("commit"));
    }

    #[test]
    fn test_fee_calculation_batch_root() {
        let schedule = FeeSchedule::default();
        let calc = schedule.calculate_fee(FeeUnits::BatchRoot, 1, None);
        assert_eq!(calc.base_fee, 100);
        assert_eq!(calc.risk_multiplier, 100);
        assert_eq!(calc.final_fee, 100);
    }

    #[test]
    fn test_fee_calculation_entry_count() {
        let schedule = FeeSchedule::default();
        let calc = schedule.calculate_fee(FeeUnits::EntryCount, 50, None);
        assert_eq!(calc.base_fee, 50);
        assert_eq!(calc.final_fee, 50);
    }

    #[test]
    fn test_fee_calculation_with_risk_multiplier() {
        let schedule = FeeSchedule::default();

        // Low risk (amount <= 1000): 1x multiplier
        let calc = schedule.calculate_fee(FeeUnits::BatchRoot, 1, Some(500));
        assert_eq!(calc.risk_multiplier, 100);
        assert_eq!(calc.final_fee, 100);

        // Medium risk (1001-10000): 1.1x multiplier
        let calc = schedule.calculate_fee(FeeUnits::BatchRoot, 1, Some(5000));
        assert_eq!(calc.risk_multiplier, 110);
        assert_eq!(calc.final_fee, 110);

        // High risk (>10000): 1.25x multiplier
        let calc = schedule.calculate_fee(FeeUnits::BatchRoot, 1, Some(50000));
        assert_eq!(calc.risk_multiplier, 125);
        assert_eq!(calc.final_fee, 125);
    }

    #[test]
    fn test_fee_calculation_size_tier() {
        let schedule = FeeSchedule::default();

        // Tier 0
        let calc = schedule.calculate_fee(FeeUnits::SizeTier, 0, None);
        assert_eq!(calc.base_fee, 10);

        // Tier 2
        let calc = schedule.calculate_fee(FeeUnits::SizeTier, 2, None);
        assert_eq!(calc.base_fee, 100);

        // Tier 4 (highest)
        let calc = schedule.calculate_fee(FeeUnits::SizeTier, 4, None);
        assert_eq!(calc.base_fee, 1000);

        // Tier beyond max (should cap at highest tier)
        let calc = schedule.calculate_fee(FeeUnits::SizeTier, 10, None);
        assert_eq!(calc.base_fee, 1000);
    }
}
