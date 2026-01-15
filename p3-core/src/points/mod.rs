//! Points Calculation Engine
//!
//! Chapter 4: Points and Weight Functions
//!
//! Provides points calculation based on:
//! - Event-based scoring (mint, use, eval)
//! - Quality/Compliance/Stability multipliers
//! - Risk adjustment and holdback rules
//! - Penalty and discount application

mod calculator;
mod weights;

pub use calculator::*;
pub use weights::*;

use crate::error::P3Result;
use crate::types::*;
use rust_decimal::Decimal;

/// Points calculation context
#[derive(Clone, Debug)]
pub struct PointsContext {
    /// Epoch ID for this calculation
    pub epoch_id: EpochId,
    /// Weights version to use
    pub weights_version: WeightsVersionRef,
    /// Evidence level
    pub evidence_level: EvidenceLevel,
    /// Degraded flags
    pub degraded_flags: Vec<DegradedFlag>,
    /// Known version set
    pub known_versions: KnownVersionSet,
}

impl PointsContext {
    /// Create new context
    pub fn new(epoch_id: EpochId, weights_version: WeightsVersionRef) -> Self {
        Self {
            epoch_id,
            weights_version,
            evidence_level: EvidenceLevel::B,
            degraded_flags: Vec::new(),
            known_versions: KnownVersionSet::default_v1(),
        }
    }

    /// Set evidence level
    pub fn with_evidence_level(mut self, level: EvidenceLevel) -> Self {
        self.evidence_level = level;
        self
    }

    /// Add degraded flag
    pub fn with_degraded_flag(mut self, flag: DegradedFlag) -> Self {
        self.degraded_flags.push(flag);
        self
    }

    /// Check if should apply holdback
    pub fn should_holdback(&self, rules: &HoldbackRules) -> bool {
        (rules.degraded_holdback && !self.degraded_flags.is_empty())
            || (rules.pending_evidence_holdback && self.evidence_level == EvidenceLevel::Pending)
    }
}

/// Points calculation result
#[derive(Clone, Debug)]
pub struct PointsResult {
    /// Actor ID
    pub actor_id: ActorId,
    /// Epoch ID
    pub epoch_id: EpochId,
    /// Gross points (before adjustments)
    pub gross_points: Decimal,
    /// Risk-adjusted points
    pub risk_adjusted_points: Decimal,
    /// Eligible points (for payout)
    pub eligible_points: Decimal,
    /// Withheld points
    pub withheld_points: Decimal,
    /// Reason codes for adjustments
    pub reason_codes: Vec<ReasonCode>,
    /// Input references
    pub input_refs: PointsInputRefs,
}

impl PointsResult {
    /// Create new result
    pub fn new(actor_id: ActorId, epoch_id: EpochId) -> Self {
        Self {
            actor_id,
            epoch_id,
            gross_points: Decimal::ZERO,
            risk_adjusted_points: Decimal::ZERO,
            eligible_points: Decimal::ZERO,
            withheld_points: Decimal::ZERO,
            reason_codes: Vec::new(),
            input_refs: PointsInputRefs {
                event_refs_digest: RefDigest::empty(),
                receipt_refs_digest: RefDigest::empty(),
                object_ids_digest: RefDigest::empty(),
                policy_refs_digest: RefDigest::empty(),
            },
        }
    }

    /// Verify points invariant
    pub fn verify_invariant(&self) -> bool {
        self.gross_points >= self.risk_adjusted_points
            && self.risk_adjusted_points >= self.eligible_points
            && self.eligible_points >= Decimal::ZERO
            && self.withheld_points >= Decimal::ZERO
    }

    /// Convert to PointsOutput type
    pub fn to_output(&self, weights_version: WeightsVersionRef) -> PointsOutput {
        PointsOutput {
            epoch_id: self.epoch_id.clone(),
            actor_id: self.actor_id.clone(),
            weights_version,
            gross_points: self.gross_points,
            risk_adjusted_points: self.risk_adjusted_points,
            eligible_points: self.eligible_points,
            withheld_points: self.withheld_points,
            reasons_digest: ReasonsDigest {
                reason_codes: self.reason_codes.clone(),
                digest: P3Digest::blake3(
                    &serde_json::to_vec(&self.reason_codes).unwrap_or_default(),
                ),
            },
            input_refs: self.input_refs.clone(),
        }
    }
}

/// Event score input
#[derive(Clone, Debug)]
pub struct EventScore {
    /// Event type
    pub event_type: EventType,
    /// Base points
    pub base_points: Decimal,
    /// Quality bucket (if applicable)
    pub quality_bucket: Option<EvalBucket>,
    /// Compliance bucket (if applicable)
    pub compliance_bucket: Option<EvalBucket>,
    /// Stability bucket (if applicable)
    pub stability_bucket: Option<EvalBucket>,
    /// Penalty signals
    pub penalty_signals: Vec<String>,
    /// Discount signals
    pub discount_signals: Vec<String>,
}

impl EventScore {
    /// Create mint event score
    pub fn mint(kind: &MintKind, config: &MintBaseConfig) -> Self {
        let base_points = match kind {
            MintKind::NewObject => config.new_object_points,
            MintKind::VersionUpdate => config.version_update_points,
            MintKind::Duplicate => config.duplicate_points,
        };
        Self {
            event_type: EventType::Mint,
            base_points,
            quality_bucket: None,
            compliance_bucket: None,
            stability_bucket: None,
            penalty_signals: Vec::new(),
            discount_signals: Vec::new(),
        }
    }

    /// Create use event score
    pub fn use_event(kind: &UseKind, config: &UseBaseConfig) -> Self {
        let base_points = match kind {
            UseKind::FinalUse => config.final_use_points,
            UseKind::NonFinalUse => config.non_final_use_points,
        };
        Self {
            event_type: EventType::FinalUse,
            base_points,
            quality_bucket: None,
            compliance_bucket: None,
            stability_bucket: None,
            penalty_signals: Vec::new(),
            discount_signals: Vec::new(),
        }
    }

    /// Add quality bucket
    pub fn with_quality(mut self, bucket: EvalBucket) -> Self {
        self.quality_bucket = Some(bucket);
        self
    }

    /// Add compliance bucket
    pub fn with_compliance(mut self, bucket: EvalBucket) -> Self {
        self.compliance_bucket = Some(bucket);
        self
    }

    /// Add penalty signal
    pub fn with_penalty(mut self, signal: String) -> Self {
        self.penalty_signals.push(signal);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_points_context_creation() {
        let ctx = PointsContext::new(
            EpochId::new("epoch:1"),
            WeightsVersionRef::new("v1", P3Digest::zero()),
        );
        assert_eq!(ctx.evidence_level, EvidenceLevel::B);
        assert!(ctx.degraded_flags.is_empty());
    }

    #[test]
    fn test_points_context_holdback() {
        let rules = HoldbackRules::default();

        let ctx_normal = PointsContext::new(
            EpochId::new("epoch:1"),
            WeightsVersionRef::new("v1", P3Digest::zero()),
        );
        assert!(!ctx_normal.should_holdback(&rules));

        let ctx_degraded = ctx_normal.clone().with_degraded_flag(DegradedFlag::DsnDown);
        assert!(ctx_degraded.should_holdback(&rules));
    }

    #[test]
    fn test_points_result_invariant() {
        let mut result = PointsResult::new(
            ActorId::new("actor:1"),
            EpochId::new("epoch:1"),
        );
        result.gross_points = Decimal::new(100, 0);
        result.risk_adjusted_points = Decimal::new(90, 0);
        result.eligible_points = Decimal::new(80, 0);
        result.withheld_points = Decimal::new(10, 0);

        assert!(result.verify_invariant());
    }

    #[test]
    fn test_event_score_mint() {
        let config = MintBaseConfig::default();
        let score = EventScore::mint(&MintKind::NewObject, &config);
        assert_eq!(score.base_points, Decimal::new(100, 0));
    }
}
