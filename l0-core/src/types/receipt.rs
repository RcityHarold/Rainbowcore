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
    /// Minimum fee after all discounts (prevents fee going to zero)
    pub minimum_fee: u64,
    /// Maximum total discount percentage (0-100, prevents stacking to 100%)
    pub max_total_discount_percentage: u8,
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
            minimum_fee: 1,  // Minimum 1 unit fee
            max_total_discount_percentage: 90, // Max 90% discount
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

    /// Calculate fee with discount and subsidy support (ISSUE-020)
    ///
    /// Security: Enforces minimum fee and maximum total discount percentage
    /// to prevent fee manipulation through discount stacking.
    pub fn calculate_fee_with_discount(
        &self,
        units: FeeUnits,
        units_count: u32,
        risk_amount: Option<u64>,
        actor_type: Option<&str>,
        subsidy_pool: Option<&SubsidyPool>,
        discount_code: Option<&DiscountCode>,
    ) -> FeeCalculationResult {
        // Start with base calculation
        let base_calc = self.calculate_fee(units, units_count, risk_amount);
        let mut current_fee = base_calc.final_fee;
        let mut applied_discounts = Vec::new();
        let mut applied_subsidies = Vec::new();
        #[allow(unused_assignments)]
        let mut total_discount_pct: u16 = 0; // Track cumulative discount percentage (used for validation, not returned)

        // Calculate maximum allowed discount
        let max_discount_amount = (base_calc.final_fee * self.max_total_discount_percentage as u64) / 100;
        let min_allowed_fee = std::cmp::max(
            self.minimum_fee,
            base_calc.final_fee.saturating_sub(max_discount_amount)
        );

        // Apply actor type discount
        if let Some(actor) = actor_type {
            if let Some(&discount_pct) = self.discounts.get(actor) {
                // Check if adding this discount would exceed max
                if total_discount_pct + discount_pct as u16 <= self.max_total_discount_percentage as u16 {
                    let discount_amount = (current_fee * discount_pct as u64) / 100;
                    let new_fee = current_fee.saturating_sub(discount_amount);

                    // Ensure minimum fee
                    if new_fee >= min_allowed_fee {
                        current_fee = new_fee;
                        total_discount_pct += discount_pct as u16;
                        applied_discounts.push(AppliedDiscount {
                            discount_type: DiscountType::ActorType,
                            percentage: discount_pct,
                            amount: discount_amount,
                            source: actor.to_string(),
                        });
                    }
                }
            }
        }

        // Apply discount code
        if let Some(code) = discount_code {
            if code.is_valid() {
                // Check if adding this discount would exceed max
                if total_discount_pct + code.percentage as u16 <= self.max_total_discount_percentage as u16 {
                    let discount_amount = code.calculate_discount(current_fee);
                    let new_fee = current_fee.saturating_sub(discount_amount);

                    // Ensure minimum fee
                    if new_fee >= min_allowed_fee {
                        current_fee = new_fee;
                        #[allow(unused_assignments)]
                        {
                            total_discount_pct += code.percentage as u16;
                        }
                        applied_discounts.push(AppliedDiscount {
                            discount_type: DiscountType::PromoCode,
                            percentage: code.percentage,
                            amount: discount_amount,
                            source: code.code.clone(),
                        });
                    }
                }
            }
        }

        // Apply subsidy from pool (subsidies don't count against discount limit)
        if let Some(pool) = subsidy_pool {
            if pool.is_active() && pool.remaining_balance > 0 {
                // Subsidy can bring fee to minimum, but not below
                let max_subsidy = current_fee.saturating_sub(self.minimum_fee);
                let subsidy_amount = std::cmp::min(
                    pool.max_per_operation,
                    std::cmp::min(pool.remaining_balance, max_subsidy)
                );
                if subsidy_amount > 0 {
                    current_fee = current_fee.saturating_sub(subsidy_amount);
                    applied_subsidies.push(AppliedSubsidy {
                        pool_id: pool.pool_id.clone(),
                        amount: subsidy_amount,
                        reason: pool.subsidy_reason.clone(),
                    });
                }
            }
        }

        // Final minimum fee enforcement
        current_fee = std::cmp::max(current_fee, self.minimum_fee);

        // Save base_final_fee before moving base_calc
        let base_final_fee = base_calc.final_fee;

        FeeCalculationResult {
            base_calculation: base_calc,
            applied_discounts,
            applied_subsidies,
            final_fee_after_discounts: current_fee,
            total_discount: base_final_fee.saturating_sub(current_fee),
            calculation_timestamp: chrono::Utc::now(),
        }
    }

    /// Get discount for an actor type
    pub fn get_actor_discount(&self, actor_type: &str) -> Option<u8> {
        self.discounts.get(actor_type).copied()
    }

    /// Add or update an actor type discount
    pub fn set_actor_discount(&mut self, actor_type: &str, percentage: u8) {
        self.discounts.insert(actor_type.to_string(), percentage.min(100));
    }

    /// Check if an operation is free
    pub fn is_free_operation(&self, operation: &str) -> bool {
        self.free_operations.contains(&operation.to_string())
    }
}

// ============================================================================
// FeeSchedule Discount Logic (ISSUE-020)
// ============================================================================

/// Type of discount applied
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscountType {
    /// Discount based on actor type (e.g., node operator)
    ActorType,
    /// Promotional discount code
    PromoCode,
    /// Volume-based discount
    Volume,
    /// Early adopter discount
    EarlyAdopter,
    /// Partnership discount
    Partnership,
    /// Foundation/DAO subsidy
    FoundationSubsidy,
}

/// Discount code for promotional discounts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscountCode {
    /// Unique code string
    pub code: String,
    /// Discount percentage (0-100)
    pub percentage: u8,
    /// Maximum discount amount (None = unlimited)
    pub max_amount: Option<u64>,
    /// Valid from timestamp
    pub valid_from: DateTime<Utc>,
    /// Valid until timestamp
    pub valid_until: DateTime<Utc>,
    /// Maximum uses (None = unlimited)
    pub max_uses: Option<u32>,
    /// Current use count
    pub use_count: u32,
    /// Eligible actor types (empty = all)
    pub eligible_actors: Vec<String>,
    /// Eligible operations (empty = all)
    pub eligible_operations: Vec<String>,
}

impl DiscountCode {
    /// Create a new discount code
    pub fn new(code: String, percentage: u8, duration: chrono::Duration) -> Self {
        let now = Utc::now();
        Self {
            code,
            percentage: percentage.min(100),
            max_amount: None,
            valid_from: now,
            valid_until: now + duration,
            max_uses: None,
            use_count: 0,
            eligible_actors: Vec::new(),
            eligible_operations: Vec::new(),
        }
    }

    /// Check if the code is valid (time and use limits)
    pub fn is_valid(&self) -> bool {
        let now = Utc::now();
        if now < self.valid_from || now > self.valid_until {
            return false;
        }
        if let Some(max) = self.max_uses {
            if self.use_count >= max {
                return false;
            }
        }
        true
    }

    /// Check if code is valid for a specific actor type
    pub fn is_valid_for_actor(&self, actor_type: &str) -> bool {
        self.eligible_actors.is_empty() || self.eligible_actors.contains(&actor_type.to_string())
    }

    /// Check if code is valid for a specific operation
    pub fn is_valid_for_operation(&self, operation: &str) -> bool {
        self.eligible_operations.is_empty() || self.eligible_operations.contains(&operation.to_string())
    }

    /// Calculate the discount amount for a given fee
    pub fn calculate_discount(&self, fee: u64) -> u64 {
        let discount = (fee * self.percentage as u64) / 100;
        match self.max_amount {
            Some(max) => std::cmp::min(discount, max),
            None => discount,
        }
    }

    /// Record a use of this code
    pub fn record_use(&mut self) {
        self.use_count += 1;
    }
}

/// Subsidy pool for foundation/DAO subsidized operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubsidyPool {
    /// Pool ID
    pub pool_id: String,
    /// Total pool balance
    pub total_balance: u64,
    /// Remaining balance
    pub remaining_balance: u64,
    /// Maximum subsidy per operation
    pub max_per_operation: u64,
    /// Eligible operations (empty = all)
    pub eligible_operations: Vec<String>,
    /// Reason for subsidy
    pub subsidy_reason: String,
    /// Pool active status
    pub is_active: bool,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Expires at timestamp
    pub expires_at: Option<DateTime<Utc>>,
}

impl SubsidyPool {
    /// Create a new subsidy pool
    pub fn new(pool_id: String, total_balance: u64, max_per_op: u64, reason: String) -> Self {
        Self {
            pool_id,
            total_balance,
            remaining_balance: total_balance,
            max_per_operation: max_per_op,
            eligible_operations: Vec::new(),
            subsidy_reason: reason,
            is_active: true,
            created_at: Utc::now(),
            expires_at: None,
        }
    }

    /// Check if pool is active and has balance
    pub fn is_active(&self) -> bool {
        if !self.is_active || self.remaining_balance == 0 {
            return false;
        }
        if let Some(expires) = self.expires_at {
            if Utc::now() > expires {
                return false;
            }
        }
        true
    }

    /// Deduct from pool
    pub fn deduct(&mut self, amount: u64) -> bool {
        if amount > self.remaining_balance {
            return false;
        }
        self.remaining_balance -= amount;
        true
    }

    /// Refund to pool
    pub fn refund(&mut self, amount: u64) {
        self.remaining_balance = std::cmp::min(
            self.remaining_balance + amount,
            self.total_balance
        );
    }
}

/// Applied discount record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliedDiscount {
    /// Type of discount
    pub discount_type: DiscountType,
    /// Percentage applied
    pub percentage: u8,
    /// Amount discounted
    pub amount: u64,
    /// Source (code, actor type, etc.)
    pub source: String,
}

/// Applied subsidy record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliedSubsidy {
    /// Pool ID
    pub pool_id: String,
    /// Amount subsidized
    pub amount: u64,
    /// Reason
    pub reason: String,
}

/// Complete fee calculation result with discounts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeCalculationResult {
    /// Base calculation before discounts
    pub base_calculation: FeeCalculation,
    /// All discounts applied
    pub applied_discounts: Vec<AppliedDiscount>,
    /// All subsidies applied
    pub applied_subsidies: Vec<AppliedSubsidy>,
    /// Final fee after all discounts and subsidies
    pub final_fee_after_discounts: u64,
    /// Total discount amount
    pub total_discount: u64,
    /// Calculation timestamp
    pub calculation_timestamp: DateTime<Utc>,
}

impl FeeCalculationResult {
    /// Get total discount percentage
    pub fn total_discount_percentage(&self) -> f64 {
        if self.base_calculation.final_fee == 0 {
            return 0.0;
        }
        (self.total_discount as f64 / self.base_calculation.final_fee as f64) * 100.0
    }

    /// Check if any discount was applied
    pub fn has_discounts(&self) -> bool {
        !self.applied_discounts.is_empty()
    }

    /// Check if any subsidy was applied
    pub fn has_subsidies(&self) -> bool {
        !self.applied_subsidies.is_empty()
    }

    /// Get breakdown by discount type
    pub fn discount_by_type(&self, dtype: DiscountType) -> u64 {
        self.applied_discounts
            .iter()
            .filter(|d| d.discount_type == dtype)
            .map(|d| d.amount)
            .sum()
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
