//! Attribution Engine
//!
//! Chapter 5: Attribution and Association
//!
//! Provides attribution calculation:
//! - Contributor share computation
//! - Lineage tree processing
//! - Decay curve application
//! - Share sum verification

mod engine;
mod lineage;

pub use engine::*;
pub use lineage::*;

use crate::error::P3Result;
use crate::types::*;
use rust_decimal::Decimal;
use std::collections::HashMap;

/// Attribution context
#[derive(Clone, Debug)]
pub struct AttributionContext {
    /// Epoch ID
    pub epoch_id: EpochId,
    /// Weights version
    pub weights_version: WeightsVersionRef,
    /// Lineage policy version
    pub lineage_policy: LineagePolicyVersion,
    /// Target kind
    pub target_kind: TargetKind,
}

impl AttributionContext {
    /// Create new context
    pub fn new(
        epoch_id: EpochId,
        weights_version: WeightsVersionRef,
        lineage_policy: LineagePolicyVersion,
    ) -> Self {
        Self {
            epoch_id,
            weights_version,
            lineage_policy,
            target_kind: TargetKind::Reward,
        }
    }

    /// Set target kind
    pub fn with_target_kind(mut self, kind: TargetKind) -> Self {
        self.target_kind = kind;
        self
    }
}

/// Attribution result
#[derive(Clone, Debug)]
pub struct AttributionResult {
    /// Attribution ID
    pub attribution_id: String,
    /// Epoch ID
    pub epoch_id: EpochId,
    /// Total amount to distribute
    pub total_amount: Decimal,
    /// Contributor shares
    pub shares: Vec<ContributorShare>,
    /// Reasons for any adjustments
    pub reason_codes: Vec<ReasonCode>,
    /// Attribution digest
    pub attribution_digest: P3Digest,
}

impl AttributionResult {
    /// Create new result
    pub fn new(attribution_id: String, epoch_id: EpochId, total_amount: Decimal) -> Self {
        Self {
            attribution_id,
            epoch_id,
            total_amount,
            shares: Vec::new(),
            reason_codes: Vec::new(),
            attribution_digest: P3Digest::zero(),
        }
    }

    /// Verify shares sum to total
    pub fn verify_shares_sum(&self) -> bool {
        let sum: Decimal = self.shares.iter().map(|s| s.share_amount).sum();
        // Allow small rounding error
        (sum - self.total_amount).abs() < Decimal::new(1, 18)
    }

    /// Verify all shares are valid
    pub fn verify_shares_valid(&self) -> bool {
        self.shares.iter().all(|s| s.is_valid())
    }

    /// Get share for a specific contributor
    pub fn get_share(&self, actor_id: &ActorId) -> Option<&ContributorShare> {
        self.shares.iter().find(|s| &s.contributor_id == actor_id)
    }

    /// Compute attribution digest
    pub fn compute_digest(&mut self) {
        let data = serde_json::to_vec(&self.shares).unwrap_or_default();
        self.attribution_digest = P3Digest::blake3(&data);
    }
}

/// Share calculation input
#[derive(Clone, Debug)]
pub struct ShareInput {
    /// Contributor ID
    pub contributor_id: ActorId,
    /// Contributor type
    pub contributor_type: ContributorType,
    /// Weight (before normalization)
    pub weight: Decimal,
    /// Basis reference
    pub basis_ref: P3Digest,
}

impl ShareInput {
    /// Create new input
    pub fn new(contributor_id: ActorId, contributor_type: ContributorType, weight: Decimal) -> Self {
        Self {
            contributor_id,
            contributor_type,
            weight,
            basis_ref: P3Digest::zero(),
        }
    }

    /// Set basis reference
    pub fn with_basis_ref(mut self, basis_ref: P3Digest) -> Self {
        self.basis_ref = basis_ref;
        self
    }
}

/// Share distribution mode
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DistributionMode {
    /// Proportional to weights
    Proportional,
    /// Equal shares
    Equal,
    /// Fixed amounts
    Fixed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attribution_context() {
        let ctx = AttributionContext::new(
            EpochId::new("epoch:1"),
            WeightsVersionRef::new("v1", P3Digest::zero()),
            LineagePolicyVersion::default_policy(EpochId::new("epoch:genesis")),
        );
        assert_eq!(ctx.target_kind, TargetKind::Reward);
    }

    #[test]
    fn test_attribution_result_verify_sum() {
        let mut result = AttributionResult::new(
            "attr:1".to_string(),
            EpochId::new("epoch:1"),
            Decimal::new(100, 0),
        );

        result.shares.push(ContributorShare {
            contributor_id: ActorId::new("actor:1"),
            contributor_type: ContributorType::HumanActor,
            share_weight: Decimal::new(6, 1),
            share_amount: Decimal::new(60, 0),
            basis_ref: P3Digest::zero(),
        });

        result.shares.push(ContributorShare {
            contributor_id: ActorId::new("actor:2"),
            contributor_type: ContributorType::HumanActor,
            share_weight: Decimal::new(4, 1),
            share_amount: Decimal::new(40, 0),
            basis_ref: P3Digest::zero(),
        });

        assert!(result.verify_shares_sum());
        assert!(result.verify_shares_valid());
    }

    #[test]
    fn test_share_input() {
        let input = ShareInput::new(
            ActorId::new("actor:1"),
            ContributorType::HumanActor,
            Decimal::new(50, 0),
        );
        assert_eq!(input.weight, Decimal::new(50, 0));
    }
}
