//! Points and Weights Functions
//!
//! Chapter 4: Points and Weight Functions

use super::common::*;
use super::epoch::WeightsVersionRef;
use super::manifest::EvalBucket;
use l0_core::types::ActorId;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

/// Points output (four components + reason digest)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PointsOutput {
    /// Epoch ID
    pub epoch_id: EpochId,
    /// Actor ID
    pub actor_id: ActorId,
    /// Weights version
    pub weights_version: WeightsVersionRef,

    /// Gross points (without risk deduction)
    pub gross_points: Decimal,
    /// Risk-adjusted points
    pub risk_adjusted_points: Decimal,
    /// Eligible points (for payout)
    pub eligible_points: Decimal,
    /// Withheld points
    pub withheld_points: Decimal,

    /// Reason digest (deduction/freeze reasons)
    pub reasons_digest: ReasonsDigest,

    /// Input references
    pub input_refs: PointsInputRefs,
}

impl PointsOutput {
    /// Verify points invariant: gross >= risk_adjusted >= eligible
    pub fn verify_invariant(&self) -> bool {
        self.gross_points >= self.risk_adjusted_points
            && self.risk_adjusted_points >= self.eligible_points
            && self.eligible_points >= Decimal::ZERO
            && self.withheld_points >= Decimal::ZERO
    }

    /// Total should equal gross
    pub fn verify_total(&self) -> bool {
        self.eligible_points + self.withheld_points == self.risk_adjusted_points
    }
}

/// Reason digest
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReasonsDigest {
    pub reason_codes: Vec<ReasonCode>,
    pub digest: P3Digest,
}

impl ReasonsDigest {
    pub fn empty() -> Self {
        Self {
            reason_codes: Vec::new(),
            digest: P3Digest::zero(),
        }
    }

    pub fn compute_digest(&self) -> P3Digest {
        let data = serde_json::to_vec(&self.reason_codes).unwrap_or_default();
        P3Digest::blake3(&data)
    }
}

/// Reason code
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReasonCode {
    pub code: String,
    pub linked_ref: Option<P3Digest>,
}

impl ReasonCode {
    pub fn new(code: impl Into<String>, linked_ref: Option<P3Digest>) -> Self {
        Self {
            code: code.into(),
            linked_ref,
        }
    }
}

/// Points input references
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PointsInputRefs {
    pub event_refs_digest: RefDigest,
    pub receipt_refs_digest: RefDigest,
    pub object_ids_digest: RefDigest,
    pub policy_refs_digest: RefDigest,
}

/// Weights version object
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WeightsVersion {
    /// Version ID
    pub version_id: String,
    /// Semantic version
    pub semantic_version: SemanticVersion,
    /// Valid from epoch (no rollback)
    pub valid_from: EpochId,
    /// Supersedes (superseded chain)
    pub supersedes: Option<String>,
    /// Issuer reference
    pub issuer_ref: String,
    /// Canonicalization version
    pub canonicalization_version: CanonVersion,
    /// Compatibility declaration
    pub compatibility: CompatibilityVector,
    /// Weights content digest
    pub weights_digest: P3Digest,
    /// Weights content
    pub content: WeightsContent,
}

impl WeightsVersion {
    /// Create a reference to this version
    pub fn to_ref(&self) -> WeightsVersionRef {
        WeightsVersionRef {
            version_id: self.version_id.clone(),
            weights_digest: self.weights_digest.clone(),
        }
    }

    /// Verify version digest
    pub fn verify_digest(&self) -> bool {
        let computed = self.content.compute_digest();
        computed == self.weights_digest
    }
}

/// Semantic version
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SemanticVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl SemanticVersion {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }

    pub fn v1() -> Self {
        Self::new(1, 0, 0)
    }

    /// Check if compatible (same major version)
    pub fn is_compatible_with(&self, other: &SemanticVersion) -> bool {
        self.major == other.major
    }

    /// Check if this version is newer
    pub fn is_newer_than(&self, other: &SemanticVersion) -> bool {
        (self.major, self.minor, self.patch) > (other.major, other.minor, other.patch)
    }
}

impl std::fmt::Display for SemanticVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Compatibility declaration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompatibilityVector {
    pub min_event_schema: Vec<String>,
    pub min_policy_schema: Vec<String>,
}

impl CompatibilityVector {
    pub fn v1() -> Self {
        Self {
            min_event_schema: vec!["v1".to_string()],
            min_policy_schema: vec!["v1".to_string()],
        }
    }
}

/// Weights content
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WeightsContent {
    /// Mint base points function
    pub f_mint_base: MintBaseConfig,
    /// Use base points function
    pub f_use_base: UseBaseConfig,
    /// Quality multiplier table
    pub quality_multiplier_table: MultiplierTable,
    /// Compliance multiplier table
    pub compliance_multiplier_table: MultiplierTable,
    /// Stability multiplier table
    pub stability_multiplier_table: MultiplierTable,
    /// Penalty table
    pub penalty_table: PenaltyTable,
    /// Discount table
    pub discount_table: DiscountTable,
    /// Cap functions
    pub cap_functions: CapFunctions,
    /// Holdback rules
    pub holdback_rules: HoldbackRules,
    /// Rounding mode
    pub rounding_mode: RoundingMode,
    /// Precision
    pub precision: u32,
}

impl WeightsContent {
    /// Compute content digest
    pub fn compute_digest(&self) -> P3Digest {
        let data = serde_json::to_vec(self).unwrap_or_default();
        P3Digest::blake3(&data)
    }
}

/// Mint base configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintBaseConfig {
    pub new_object_points: Decimal,
    pub version_update_points: Decimal,
    pub duplicate_points: Decimal,
}

impl Default for MintBaseConfig {
    fn default() -> Self {
        Self {
            new_object_points: Decimal::new(100, 0),
            version_update_points: Decimal::new(50, 0),
            duplicate_points: Decimal::ZERO,
        }
    }
}

/// Use base configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UseBaseConfig {
    pub final_use_points: Decimal,
    pub non_final_use_points: Decimal,
}

impl Default for UseBaseConfig {
    fn default() -> Self {
        Self {
            final_use_points: Decimal::new(10, 0),
            non_final_use_points: Decimal::new(1, 0),
        }
    }
}

/// Multiplier table
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultiplierTable {
    pub mappings: Vec<BucketMultiplier>,
}

impl MultiplierTable {
    pub fn get_multiplier(&self, bucket: &EvalBucket) -> Option<Decimal> {
        self.mappings
            .iter()
            .find(|m| &m.bucket == bucket)
            .map(|m| m.multiplier)
    }
}

impl Default for MultiplierTable {
    fn default() -> Self {
        Self {
            mappings: vec![
                BucketMultiplier { bucket: EvalBucket::High, multiplier: Decimal::new(15, 1) },
                BucketMultiplier { bucket: EvalBucket::Medium, multiplier: Decimal::ONE },
                BucketMultiplier { bucket: EvalBucket::Low, multiplier: Decimal::new(5, 1) },
                BucketMultiplier { bucket: EvalBucket::Pass, multiplier: Decimal::ONE },
                BucketMultiplier { bucket: EvalBucket::Fail, multiplier: Decimal::ZERO },
                BucketMultiplier { bucket: EvalBucket::Inconclusive, multiplier: Decimal::new(5, 1) },
            ],
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BucketMultiplier {
    pub bucket: EvalBucket,
    pub multiplier: Decimal,
}

/// Penalty table
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PenaltyTable {
    pub entries: Vec<PenaltyEntry>,
}

impl PenaltyTable {
    pub fn get_penalty(&self, signal_type: &str) -> Option<Decimal> {
        self.entries
            .iter()
            .find(|e| e.signal_type == signal_type)
            .map(|e| e.penalty_amount)
    }
}

impl Default for PenaltyTable {
    fn default() -> Self {
        Self { entries: Vec::new() }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PenaltyEntry {
    pub signal_type: String,
    pub penalty_amount: Decimal,
}

/// Discount table
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscountTable {
    pub entries: Vec<DiscountEntry>,
}

impl Default for DiscountTable {
    fn default() -> Self {
        Self { entries: Vec::new() }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscountEntry {
    pub signal_type: String,
    pub discount_multiplier: Decimal,
}

/// Cap functions configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapFunctions {
    pub per_actor_cap: Option<Decimal>,
    pub per_object_cap: Option<Decimal>,
    pub per_consumer_cap: Option<Decimal>,
}

impl Default for CapFunctions {
    fn default() -> Self {
        Self {
            per_actor_cap: None,
            per_object_cap: None,
            per_consumer_cap: None,
        }
    }
}

/// Holdback rules
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HoldbackRules {
    pub degraded_holdback: bool,
    pub pending_evidence_holdback: bool,
    pub unknown_version_holdback: bool,
}

impl Default for HoldbackRules {
    fn default() -> Self {
        Self {
            degraded_holdback: true,
            pending_evidence_holdback: true,
            unknown_version_holdback: true,
        }
    }
}

/// Rounding mode
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoundingMode {
    BankersRounding,
    RoundDown,
    RoundUp,
    RoundHalfUp,
}

impl Default for RoundingMode {
    fn default() -> Self {
        Self::BankersRounding
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_points_output_invariant() {
        let output = PointsOutput {
            epoch_id: EpochId::new("epoch:test"),
            actor_id: ActorId::new("actor:test"),
            weights_version: WeightsVersionRef::new("v1", P3Digest::zero()),
            gross_points: Decimal::new(100, 0),
            risk_adjusted_points: Decimal::new(90, 0),
            eligible_points: Decimal::new(80, 0),
            withheld_points: Decimal::new(10, 0),
            reasons_digest: ReasonsDigest::empty(),
            input_refs: PointsInputRefs {
                event_refs_digest: RefDigest::empty(),
                receipt_refs_digest: RefDigest::empty(),
                object_ids_digest: RefDigest::empty(),
                policy_refs_digest: RefDigest::empty(),
            },
        };
        assert!(output.verify_invariant());
        assert!(output.verify_total());
    }

    #[test]
    fn test_semantic_version_comparison() {
        let v1 = SemanticVersion::new(1, 0, 0);
        let v2 = SemanticVersion::new(1, 1, 0);
        let v3 = SemanticVersion::new(2, 0, 0);

        assert!(v2.is_newer_than(&v1));
        assert!(v3.is_newer_than(&v2));
        assert!(v1.is_compatible_with(&v2));
        assert!(!v1.is_compatible_with(&v3));
    }

    #[test]
    fn test_multiplier_table_lookup() {
        let table = MultiplierTable::default();
        assert_eq!(table.get_multiplier(&EvalBucket::High), Some(Decimal::new(15, 1)));
        assert_eq!(table.get_multiplier(&EvalBucket::Fail), Some(Decimal::ZERO));
    }
}
