//! Attribution Engine
//!
//! Core attribution calculation logic.

use super::{AttributionContext, AttributionResult, DistributionMode, ShareInput};
use crate::error::P3Result;
use crate::types::*;
use rust_decimal::Decimal;

/// Attribution engine
pub struct AttributionEngine {
    /// Rounding precision
    precision: u32,
    /// Minimum share threshold
    min_share_threshold: Decimal,
}

impl AttributionEngine {
    /// Create new engine
    pub fn new() -> Self {
        Self {
            precision: 18,
            min_share_threshold: Decimal::new(1, 6), // 0.000001
        }
    }

    /// Create engine with custom precision
    pub fn with_precision(mut self, precision: u32) -> Self {
        self.precision = precision;
        self
    }

    /// Create engine with custom threshold
    pub fn with_min_threshold(mut self, threshold: Decimal) -> Self {
        self.min_share_threshold = threshold;
        self
    }

    /// Calculate attribution for given inputs
    pub fn calculate(
        &self,
        attribution_id: &str,
        inputs: &[ShareInput],
        total_amount: Decimal,
        mode: DistributionMode,
        ctx: &AttributionContext,
    ) -> P3Result<AttributionResult> {
        let mut result = AttributionResult::new(
            attribution_id.to_string(),
            ctx.epoch_id.clone(),
            total_amount,
        );

        if inputs.is_empty() {
            return Ok(result);
        }

        match mode {
            DistributionMode::Proportional => {
                self.calculate_proportional(&mut result, inputs, total_amount)?;
            }
            DistributionMode::Equal => {
                self.calculate_equal(&mut result, inputs, total_amount)?;
            }
            DistributionMode::Fixed => {
                self.calculate_fixed(&mut result, inputs)?;
            }
        }

        // Filter out shares below threshold
        result.shares.retain(|s| s.share_amount >= self.min_share_threshold);

        // Compute attribution digest
        result.compute_digest();

        Ok(result)
    }

    /// Calculate proportional distribution
    fn calculate_proportional(
        &self,
        result: &mut AttributionResult,
        inputs: &[ShareInput],
        total_amount: Decimal,
    ) -> P3Result<()> {
        // Calculate total weight
        let total_weight: Decimal = inputs.iter().map(|i| i.weight).sum();

        if total_weight.is_zero() {
            return Ok(());
        }

        // Calculate shares
        let mut distributed = Decimal::ZERO;
        for (i, input) in inputs.iter().enumerate() {
            let weight_ratio = input.weight / total_weight;
            let share_amount = if i == inputs.len() - 1 {
                // Last share gets remainder to avoid rounding errors
                total_amount - distributed
            } else {
                self.round(total_amount * weight_ratio)
            };

            distributed += share_amount;

            result.shares.push(ContributorShare {
                contributor_id: input.contributor_id.clone(),
                contributor_type: input.contributor_type.clone(),
                share_weight: weight_ratio,
                share_amount,
                basis_ref: input.basis_ref.clone(),
            });
        }

        Ok(())
    }

    /// Calculate equal distribution
    fn calculate_equal(
        &self,
        result: &mut AttributionResult,
        inputs: &[ShareInput],
        total_amount: Decimal,
    ) -> P3Result<()> {
        let count = Decimal::from(inputs.len() as i64);
        let share_per_person = self.round(total_amount / count);
        let weight_per_person = Decimal::ONE / count;

        let mut distributed = Decimal::ZERO;
        for (i, input) in inputs.iter().enumerate() {
            let share_amount = if i == inputs.len() - 1 {
                total_amount - distributed
            } else {
                share_per_person
            };

            distributed += share_amount;

            result.shares.push(ContributorShare {
                contributor_id: input.contributor_id.clone(),
                contributor_type: input.contributor_type.clone(),
                share_weight: weight_per_person,
                share_amount,
                basis_ref: input.basis_ref.clone(),
            });
        }

        Ok(())
    }

    /// Calculate fixed distribution (use weights as amounts)
    fn calculate_fixed(
        &self,
        result: &mut AttributionResult,
        inputs: &[ShareInput],
    ) -> P3Result<()> {
        let total_weight: Decimal = inputs.iter().map(|i| i.weight).sum();

        for input in inputs {
            let weight_ratio = if total_weight.is_zero() {
                Decimal::ZERO
            } else {
                input.weight / total_weight
            };

            result.shares.push(ContributorShare {
                contributor_id: input.contributor_id.clone(),
                contributor_type: input.contributor_type.clone(),
                share_weight: weight_ratio,
                share_amount: input.weight, // Use weight as fixed amount
                basis_ref: input.basis_ref.clone(),
            });
        }

        // Update total amount to actual sum
        result.total_amount = inputs.iter().map(|i| i.weight).sum();

        Ok(())
    }

    /// Round to precision
    fn round(&self, value: Decimal) -> Decimal {
        value.round_dp(self.precision)
    }

    /// Merge multiple attribution results
    pub fn merge_results(&self, results: &[AttributionResult]) -> P3Result<AttributionResult> {
        if results.is_empty() {
            return Ok(AttributionResult::new(
                "merged".to_string(),
                EpochId::new("unknown"),
                Decimal::ZERO,
            ));
        }

        let mut merged = AttributionResult::new(
            format!("merged:{}", results.len()),
            results[0].epoch_id.clone(),
            Decimal::ZERO,
        );

        // Aggregate shares by contributor
        let mut share_map: std::collections::HashMap<String, ContributorShare> =
            std::collections::HashMap::new();

        for result in results {
            merged.total_amount += result.total_amount;

            for share in &result.shares {
                let key = share.contributor_id.as_str().to_string();
                share_map
                    .entry(key)
                    .and_modify(|existing| {
                        existing.share_amount += share.share_amount;
                        existing.share_weight += share.share_weight;
                    })
                    .or_insert_with(|| share.clone());
            }
        }

        merged.shares = share_map.into_values().collect();

        // Normalize weights
        let total_weight: Decimal = merged.shares.iter().map(|s| s.share_weight).sum();
        if !total_weight.is_zero() {
            for share in &mut merged.shares {
                share.share_weight /= total_weight;
            }
        }

        merged.compute_digest();
        Ok(merged)
    }
}

impl Default for AttributionEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_context() -> AttributionContext {
        AttributionContext::new(
            EpochId::new("epoch:test"),
            WeightsVersionRef::new("v1", P3Digest::zero()),
            LineagePolicyVersion::default_policy(EpochId::new("epoch:genesis")),
        )
    }

    #[test]
    fn test_proportional_distribution() {
        let engine = AttributionEngine::new();
        let ctx = create_test_context();

        let inputs = vec![
            ShareInput::new(ActorId::new("actor:1"), ContributorType::HumanActor, Decimal::new(60, 0)),
            ShareInput::new(ActorId::new("actor:2"), ContributorType::HumanActor, Decimal::new(40, 0)),
        ];

        let result = engine
            .calculate("attr:1", &inputs, Decimal::new(100, 0), DistributionMode::Proportional, &ctx)
            .unwrap();

        assert!(result.verify_shares_sum());
        assert_eq!(result.shares.len(), 2);

        let share1 = result.get_share(&ActorId::new("actor:1")).unwrap();
        assert_eq!(share1.share_amount, Decimal::new(60, 0));
    }

    #[test]
    fn test_equal_distribution() {
        let engine = AttributionEngine::new();
        let ctx = create_test_context();

        let inputs = vec![
            ShareInput::new(ActorId::new("actor:1"), ContributorType::HumanActor, Decimal::new(100, 0)),
            ShareInput::new(ActorId::new("actor:2"), ContributorType::HumanActor, Decimal::new(50, 0)),
            ShareInput::new(ActorId::new("actor:3"), ContributorType::HumanActor, Decimal::new(25, 0)),
        ];

        let result = engine
            .calculate("attr:1", &inputs, Decimal::new(99, 0), DistributionMode::Equal, &ctx)
            .unwrap();

        assert!(result.verify_shares_sum());
        assert_eq!(result.shares.len(), 3);

        // Each should get ~33
        for share in &result.shares {
            assert!(share.share_amount >= Decimal::new(32, 0));
            assert!(share.share_amount <= Decimal::new(34, 0));
        }
    }

    #[test]
    fn test_fixed_distribution() {
        let engine = AttributionEngine::new();
        let ctx = create_test_context();

        let inputs = vec![
            ShareInput::new(ActorId::new("actor:1"), ContributorType::HumanActor, Decimal::new(50, 0)),
            ShareInput::new(ActorId::new("actor:2"), ContributorType::HumanActor, Decimal::new(30, 0)),
        ];

        let result = engine
            .calculate("attr:1", &inputs, Decimal::new(100, 0), DistributionMode::Fixed, &ctx)
            .unwrap();

        // Total should be sum of weights (80), not the input total_amount
        assert_eq!(result.total_amount, Decimal::new(80, 0));
        assert_eq!(result.shares[0].share_amount, Decimal::new(50, 0));
        assert_eq!(result.shares[1].share_amount, Decimal::new(30, 0));
    }

    #[test]
    fn test_empty_inputs() {
        let engine = AttributionEngine::new();
        let ctx = create_test_context();

        let result = engine
            .calculate("attr:1", &[], Decimal::new(100, 0), DistributionMode::Proportional, &ctx)
            .unwrap();

        assert!(result.shares.is_empty());
    }

    #[test]
    fn test_merge_results() {
        let engine = AttributionEngine::new();
        let ctx = create_test_context();

        let inputs1 = vec![
            ShareInput::new(ActorId::new("actor:1"), ContributorType::HumanActor, Decimal::new(50, 0)),
        ];
        let inputs2 = vec![
            ShareInput::new(ActorId::new("actor:1"), ContributorType::HumanActor, Decimal::new(30, 0)),
            ShareInput::new(ActorId::new("actor:2"), ContributorType::HumanActor, Decimal::new(20, 0)),
        ];

        let result1 = engine
            .calculate("attr:1", &inputs1, Decimal::new(50, 0), DistributionMode::Proportional, &ctx)
            .unwrap();
        let result2 = engine
            .calculate("attr:2", &inputs2, Decimal::new(50, 0), DistributionMode::Proportional, &ctx)
            .unwrap();

        let merged = engine.merge_results(&[result1, result2]).unwrap();

        assert_eq!(merged.total_amount, Decimal::new(100, 0));
        assert_eq!(merged.shares.len(), 2);

        // actor:1 should have 50 + 30 = 80
        let actor1_share = merged.get_share(&ActorId::new("actor:1")).unwrap();
        assert_eq!(actor1_share.share_amount, Decimal::new(80, 0));
    }
}
