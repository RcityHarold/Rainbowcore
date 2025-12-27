//! Version object types for L0 policy management

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::BTreeMap;
use super::common::Digest;
use super::actor::ReceiptId;
use super::receipt::FeeUnits;

/// Anchor requirement level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AnchorRequirement {
    Must,
    Should,
    May,
}

/// Anchor policy version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorPolicyVersion {
    pub anchor_policy_version: String,
    pub valid_from: DateTime<Utc>,
    pub supersedes: Option<String>,
    /// Key = AnchorType, Value = MUST/SHOULD/MAY
    pub anchor_requirements: BTreeMap<String, AnchorRequirement>,
    pub risk_multipliers_ref: Option<String>,
    pub degraded_mode_ref: Option<String>,
    pub rules_digest: Digest,
    pub receipt_id: Option<ReceiptId>,
    pub notes_digest: Option<Digest>,
}

impl AnchorPolicyVersion {
    /// Check if an anchor type is MUST
    pub fn is_must(&self, anchor_type: &str) -> bool {
        self.anchor_requirements
            .get(anchor_type)
            .map(|r| *r == AnchorRequirement::Must)
            .unwrap_or(false)
    }

    /// Get the requirement for an anchor type
    pub fn get_requirement(&self, anchor_type: &str) -> Option<AnchorRequirement> {
        self.anchor_requirements.get(anchor_type).copied()
    }
}

/// Pricing rule for fee schedule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingRule {
    pub anchor_type: String,
    pub units: FeeUnits,
    pub base_price: String,
    pub risk_multiplier_table_ref: Option<String>,
}

/// Fee schedule version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeScheduleVersion {
    pub fee_schedule_version: String,
    pub valid_from: DateTime<Utc>,
    pub supersedes: Option<String>,
    pub pricing_rules: Vec<PricingRule>,
    pub pricing_rules_digest: Digest,
    pub deposit_rules_digest: Option<Digest>,
    pub discount_rules_digest: Option<Digest>,
    pub subsidy_rules_digest: Option<Digest>,
    pub receipt_id: Option<ReceiptId>,
}

impl FeeScheduleVersion {
    /// Get the pricing rule for an anchor type
    pub fn get_pricing(&self, anchor_type: &str) -> Option<&PricingRule> {
        self.pricing_rules.iter().find(|r| r.anchor_type == anchor_type)
    }
}

/// Pool ratio version (three pools)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolRatioVersion {
    pub pool_ratio_version: String,
    pub infra_ratio: String,
    pub civilization_ratio: String,
    pub reward_ratio: String,
    pub valid_from: DateTime<Utc>,
    pub supersedes: Option<String>,
    pub governance_ref: String,
    pub receipt_id: Option<ReceiptId>,
}

impl PoolRatioVersion {
    /// Validate that ratios sum to 1.0
    pub fn validate(&self) -> Result<(), String> {
        let infra: f64 = self.infra_ratio.parse().map_err(|_| "Invalid infra_ratio")?;
        let civ: f64 = self.civilization_ratio.parse().map_err(|_| "Invalid civilization_ratio")?;
        let reward: f64 = self.reward_ratio.parse().map_err(|_| "Invalid reward_ratio")?;

        let sum = infra + civ + reward;
        if (sum - 1.0).abs() > 0.0001 {
            return Err(format!("Ratios must sum to 1.0, got {}", sum));
        }

        Ok(())
    }
}

/// Budget policy version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetPolicyVersion {
    pub budget_policy_version: String,
    pub valid_from: DateTime<Utc>,
    pub supersedes: Option<String>,
    pub governance_ops_cap: String,
    pub infra_ops_cap: String,
    pub must_chain_anchor_cap: String,
    pub allowed_spend_categories: Vec<String>,
    pub governance_ref: String,
    pub receipt_id: Option<ReceiptId>,
}

impl BudgetPolicyVersion {
    /// Check if a spend category is allowed
    pub fn is_category_allowed(&self, category: &str) -> bool {
        self.allowed_spend_categories.iter().any(|c| c == category)
    }
}

/// Chain anchor policy version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainAnchorPolicyVersion {
    pub chain_anchor_policy_version: String,
    pub valid_from: DateTime<Utc>,
    pub supersedes: Option<String>,
    pub must_objects: Vec<String>,
    pub should_objects: Vec<String>,
    pub may_objects: Vec<String>,
    pub epoch_frequency: String,
    pub retry_policy: RetryPolicy,
    pub actor_self_anchor_whitelist: Vec<String>,
    pub receipt_id: Option<ReceiptId>,
}

/// Retry policy for chain anchoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub retry_interval_ms: u64,
}

/// Canonicalization version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalizationVersion {
    pub canonicalization_version: String,
    pub valid_from: DateTime<Utc>,
    pub supersedes: Option<String>,
    pub encoding_spec: EncodingSpec,
    pub field_ordering_spec: String,
    pub null_marker: Vec<u8>,
    pub receipt_id: Option<ReceiptId>,
}

/// Encoding specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodingSpec {
    pub string_encoding: String,  // UTF-8
    pub int_encoding: String,     // varint/le/be
    pub list_encoding: String,    // length-prefixed
    pub hash_function: String,    // sha3-256
}

impl Default for EncodingSpec {
    fn default() -> Self {
        Self {
            string_encoding: "UTF-8".to_string(),
            int_encoding: "varint".to_string(),
            list_encoding: "length-prefixed".to_string(),
            hash_function: "sha3-256".to_string(),
        }
    }
}

/// Degraded mode policy version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegradedModePolicyVersion {
    pub degraded_mode_policy_version: String,
    pub valid_from: DateTime<Utc>,
    pub supersedes: Option<String>,
    pub l0_down_high_risk_behavior: String,
    pub dsn_down_ticket_mode: String,
    pub econ_down_settlement_mode: String,
    pub required_markers: Vec<String>,
    pub receipt_id: Option<ReceiptId>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_ratio_validation() {
        let valid = PoolRatioVersion {
            pool_ratio_version: "v1".to_string(),
            infra_ratio: "0.4".to_string(),
            civilization_ratio: "0.4".to_string(),
            reward_ratio: "0.2".to_string(),
            valid_from: Utc::now(),
            supersedes: None,
            governance_ref: "gov:1".to_string(),
            receipt_id: None,
        };
        assert!(valid.validate().is_ok());

        let invalid = PoolRatioVersion {
            pool_ratio_version: "v1".to_string(),
            infra_ratio: "0.5".to_string(),
            civilization_ratio: "0.5".to_string(),
            reward_ratio: "0.5".to_string(),
            valid_from: Utc::now(),
            supersedes: None,
            governance_ref: "gov:1".to_string(),
            receipt_id: None,
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_anchor_requirement_serialization() {
        let req = AnchorRequirement::Must;
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, "\"MUST\"");
    }
}
