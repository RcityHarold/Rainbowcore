//! Attribution and Association
//!
//! Chapter 5: Attribution and Association

use super::common::*;
use super::epoch::WeightsVersionRef;
use super::points::ReasonsDigest;
use l0_core::types::ActorId;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

/// Attribution map digest
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttributionMapDigest {
    // === A.1 Identification and Binding ===
    pub attribution_id: String,
    pub bound_epoch_id: EpochId,
    pub bound_weights_version: WeightsVersionRef,
    pub bound_policy_refs_digest: RefDigest,
    pub bound_target_kind: TargetKind,
    pub supersedes_attribution_ref: Option<P3Digest>,

    // === A.2 Input Digest Foreign Keys ===
    pub points_summary_ref_digest: RefDigest,
    pub input_sets_refs_digest: RefDigest,
    pub lineage_inputs_digest: Option<RefDigest>,

    // === A.3 Contributor Set ===
    pub contributors_digest: RefDigest,
    pub contributors_count: u64,

    // === A.4 Share Set ===
    pub shares_digest: RefDigest,
    pub shares_sum_rule_ref: String,
    pub rounding_rule_ref: String,

    // === A.5 Basis References Set ===
    pub basis_refs_digest: RefDigest,
    pub coverage_proof_ref_digest: Option<RefDigest>,

    // === A.6 Policy and Compliance ===
    pub attribution_policy_ref: String,
    pub reasons_digest: Option<ReasonsDigest>,
}

impl AttributionMapDigest {
    /// Compute overall attribution digest
    pub fn compute_digest(&self) -> P3Digest {
        let data = serde_json::to_vec(self).unwrap_or_default();
        P3Digest::blake3(&data)
    }
}

/// Target kind
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    /// Reward
    Reward,
    /// Subsidy
    Subsidy,
    /// Clearing
    Clearing,
    /// Clawback recovery
    ClawbackRecovery,
    /// Local scope
    LocalScope,
}

/// Contributor share
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContributorShare {
    pub contributor_id: ActorId,
    pub contributor_type: ContributorType,
    pub share_weight: Decimal,
    pub share_amount: Decimal,
    pub basis_ref: P3Digest,
}

impl ContributorShare {
    /// Verify share is valid (weight and amount are non-negative)
    pub fn is_valid(&self) -> bool {
        self.share_weight >= Decimal::ZERO && self.share_amount >= Decimal::ZERO
    }
}

/// Contributor type
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContributorType {
    /// Human actor
    HumanActor,
    /// AI actor
    AiActor,
    /// Node actor
    NodeActor,
    /// Group actor
    GroupActor,
    /// Provider
    Provider,
    /// Ancestor knowledge
    AncestorAkn,
}

/// Connected weight
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectedWeight {
    /// Connected level
    pub connected_level: ConnectedLevel,
    /// Multiplier
    pub multiplier: Decimal,
    /// Pool attribution
    pub pool_attribution: PoolAttribution,
}

/// Connected level
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectedLevel {
    Tier0,
    Tier1,
    Tier2,
    LocalOnly,
}

impl ConnectedLevel {
    /// Get default multiplier for this level
    pub fn default_multiplier(&self) -> Decimal {
        match self {
            ConnectedLevel::Tier0 => Decimal::ONE,
            ConnectedLevel::Tier1 => Decimal::new(8, 1), // 0.8
            ConnectedLevel::Tier2 => Decimal::new(5, 1), // 0.5
            ConnectedLevel::LocalOnly => Decimal::ZERO,
        }
    }
}

/// Pool attribution
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolAttribution {
    /// Collective reward pool
    CollectiveReward,
    /// Local scope
    LocalScope,
}

/// Lineage policy version
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LineagePolicyVersion {
    pub version_id: String,
    pub valid_from: EpochId,
    pub supersedes: Option<String>,
    /// Maximum recursion depth
    pub max_depth: u32,
    /// Decay curve
    pub decay_curve: DecayCurve,
    /// Minimum share threshold
    pub min_share_threshold: Decimal,
    /// Cache window
    pub cache_window: Option<u32>,
    /// Merge rule
    pub merge_rule: MergeRule,
}

impl LineagePolicyVersion {
    /// Default lineage policy
    pub fn default_policy(valid_from: EpochId) -> Self {
        Self {
            version_id: "lineage_v1".to_string(),
            valid_from,
            supersedes: None,
            max_depth: 5,
            decay_curve: DecayCurve::Exponential { base: Decimal::new(5, 1) },
            min_share_threshold: Decimal::new(1, 3), // 0.001
            cache_window: Some(10),
            merge_rule: MergeRule::KnowledgeFirst,
        }
    }
}

/// Decay curve
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecayCurve {
    Exponential { base: Decimal },
    Linear { slope: Decimal },
    StepFunction { steps: Vec<(u32, Decimal)> },
}

impl DecayCurve {
    /// Calculate decay factor for a given depth
    pub fn factor_at_depth(&self, depth: u32) -> Decimal {
        match self {
            DecayCurve::Exponential { base } => {
                // Calculate base^depth using repeated multiplication
                let mut result = Decimal::ONE;
                for _ in 0..depth {
                    result *= base;
                }
                result
            }
            DecayCurve::Linear { slope } => {
                let factor = Decimal::ONE - (*slope * Decimal::from(depth));
                if factor < Decimal::ZERO {
                    Decimal::ZERO
                } else {
                    factor
                }
            }
            DecayCurve::StepFunction { steps } => {
                steps
                    .iter()
                    .filter(|(d, _)| *d <= depth)
                    .max_by_key(|(d, _)| d)
                    .map(|(_, f)| *f)
                    .unwrap_or(Decimal::ZERO)
            }
        }
    }
}

/// Merge rule
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeRule {
    KnowledgeFirst,
    SubjectFirst,
    Parallel,
}

/// Lineage node
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LineageNode {
    pub node_id: String,
    pub actor_id: ActorId,
    pub depth: u32,
    pub share_weight: Decimal,
    pub parent_refs: Vec<P3Digest>,
    pub contribution_type: ContributionType,
}

/// Contribution type
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContributionType {
    Direct,
    Derived,
    Cited,
    Referenced,
}

/// Lineage tree
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LineageTree {
    pub root_object_id: String,
    pub nodes: Vec<LineageNode>,
    pub tree_digest: P3Digest,
    pub policy_version: String,
    pub computed_at: chrono::DateTime<chrono::Utc>,
}

impl LineageTree {
    /// Compute tree digest
    pub fn compute_digest(&self) -> P3Digest {
        let data = serde_json::to_vec(&self.nodes).unwrap_or_default();
        P3Digest::blake3(&data)
    }

    /// Get all ancestors at a given depth
    pub fn ancestors_at_depth(&self, depth: u32) -> Vec<&LineageNode> {
        self.nodes.iter().filter(|n| n.depth == depth).collect()
    }

    /// Calculate total share for an actor
    pub fn total_share_for_actor(&self, actor_id: &ActorId) -> Decimal {
        self.nodes
            .iter()
            .filter(|n| &n.actor_id == actor_id)
            .map(|n| n.share_weight)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connected_level_multiplier() {
        assert_eq!(ConnectedLevel::Tier0.default_multiplier(), Decimal::ONE);
        assert_eq!(ConnectedLevel::LocalOnly.default_multiplier(), Decimal::ZERO);
    }

    #[test]
    fn test_decay_curve_exponential() {
        let curve = DecayCurve::Exponential { base: Decimal::new(5, 1) };
        assert_eq!(curve.factor_at_depth(0), Decimal::ONE);
        assert_eq!(curve.factor_at_depth(1), Decimal::new(5, 1));
        assert_eq!(curve.factor_at_depth(2), Decimal::new(25, 2));
    }

    #[test]
    fn test_decay_curve_linear() {
        let curve = DecayCurve::Linear { slope: Decimal::new(2, 1) }; // 0.2
        assert_eq!(curve.factor_at_depth(0), Decimal::ONE);
        assert_eq!(curve.factor_at_depth(1), Decimal::new(8, 1)); // 0.8
        assert_eq!(curve.factor_at_depth(5), Decimal::ZERO); // Would be 0
    }

    #[test]
    fn test_contributor_share_valid() {
        let share = ContributorShare {
            contributor_id: ActorId::new("actor:test"),
            contributor_type: ContributorType::HumanActor,
            share_weight: Decimal::new(5, 1),
            share_amount: Decimal::new(50, 0),
            basis_ref: P3Digest::zero(),
        };
        assert!(share.is_valid());
    }
}
