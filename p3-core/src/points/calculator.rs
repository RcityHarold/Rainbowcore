//! Points Calculator
//!
//! Implements the points calculation pipeline:
//! 1. Base points from events
//! 2. Multiplier application (quality, compliance, stability)
//! 3. Penalty deduction
//! 4. Discount application
//! 5. Cap enforcement
//! 6. Risk adjustment
//! 7. Holdback rules

use super::{EventScore, PointsContext, PointsResult};
use crate::error::P3Result;
use crate::types::*;
use rust_decimal::Decimal;
use std::collections::HashMap;

/// Points calculator
pub struct PointsCalculator {
    /// Weights content
    weights: WeightsContent,
    /// Rounding precision
    precision: u32,
}

impl PointsCalculator {
    /// Create new calculator with weights
    pub fn new(weights: WeightsContent) -> Self {
        let precision = weights.precision;
        Self { weights, precision }
    }

    /// Create calculator with default weights
    pub fn default_v1() -> Self {
        Self::new(WeightsContent::default())
    }

    /// Calculate points for a single actor
    pub fn calculate_for_actor(
        &self,
        actor_id: &ActorId,
        events: &[EventScore],
        ctx: &PointsContext,
    ) -> P3Result<PointsResult> {
        let mut result = PointsResult::new(actor_id.clone(), ctx.epoch_id.clone());

        // Step 1: Calculate gross points
        let mut gross = Decimal::ZERO;
        for event in events {
            let event_points = self.calculate_event_points(event);
            gross += event_points;
        }
        result.gross_points = self.round(gross);

        // Step 2: Apply risk adjustment
        let risk_factor = self.calculate_risk_factor(events);
        result.risk_adjusted_points = self.round(result.gross_points * risk_factor);

        // Step 3: Apply caps
        if let Some(cap) = self.weights.cap_functions.per_actor_cap {
            if result.risk_adjusted_points > cap {
                result.risk_adjusted_points = cap;
                result.reason_codes.push(ReasonCode::new("CAP_ACTOR", None));
            }
        }

        // Step 4: Apply holdback rules
        if ctx.should_holdback(&self.weights.holdback_rules) {
            result.withheld_points = result.risk_adjusted_points;
            result.eligible_points = Decimal::ZERO;

            if !ctx.degraded_flags.is_empty() {
                result.reason_codes.push(ReasonCode::new("HOLDBACK_DEGRADED", None));
            }
            if ctx.evidence_level == EvidenceLevel::Pending {
                result.reason_codes.push(ReasonCode::new("HOLDBACK_EVIDENCE", None));
            }
        } else {
            result.eligible_points = result.risk_adjusted_points;
            result.withheld_points = Decimal::ZERO;
        }

        Ok(result)
    }

    /// Calculate points for multiple actors (batch)
    pub fn calculate_batch(
        &self,
        actor_events: &HashMap<ActorId, Vec<EventScore>>,
        ctx: &PointsContext,
    ) -> P3Result<Vec<PointsResult>> {
        let mut results = Vec::with_capacity(actor_events.len());

        for (actor_id, events) in actor_events {
            let result = self.calculate_for_actor(actor_id, events, ctx)?;
            results.push(result);
        }

        Ok(results)
    }

    /// Calculate points for a single event
    fn calculate_event_points(&self, event: &EventScore) -> Decimal {
        let mut points = event.base_points;

        // Apply quality multiplier
        if let Some(ref bucket) = event.quality_bucket {
            if let Some(mult) = self.weights.quality_multiplier_table.get_multiplier(bucket) {
                points *= mult;
            }
        }

        // Apply compliance multiplier
        if let Some(ref bucket) = event.compliance_bucket {
            if let Some(mult) = self.weights.compliance_multiplier_table.get_multiplier(bucket) {
                points *= mult;
            }
        }

        // Apply stability multiplier
        if let Some(ref bucket) = event.stability_bucket {
            if let Some(mult) = self.weights.stability_multiplier_table.get_multiplier(bucket) {
                points *= mult;
            }
        }

        // Apply penalties
        for signal in &event.penalty_signals {
            if let Some(penalty) = self.weights.penalty_table.get_penalty(signal) {
                points -= penalty;
            }
        }

        // Ensure non-negative
        if points < Decimal::ZERO {
            points = Decimal::ZERO;
        }

        // Apply discounts
        for signal in &event.discount_signals {
            if let Some(entry) = self.weights.discount_table.entries.iter().find(|e| &e.signal_type == signal) {
                points *= entry.discount_multiplier;
            }
        }

        points
    }

    /// Calculate risk factor based on events
    fn calculate_risk_factor(&self, events: &[EventScore]) -> Decimal {
        // Default risk factor is 1.0 (no adjustment)
        // Can be customized based on event patterns
        let mut factor = Decimal::ONE;

        // Count penalty signals
        let penalty_count: usize = events.iter().map(|e| e.penalty_signals.len()).sum();
        if penalty_count > 0 {
            // Reduce by 5% per penalty signal, max 50% reduction
            let reduction = Decimal::new(5, 2) * Decimal::from(penalty_count.min(10) as i64);
            factor -= reduction;
        }

        factor.max(Decimal::new(5, 1)) // Minimum 50%
    }

    /// Round to precision
    fn round(&self, value: Decimal) -> Decimal {
        value.round_dp(self.precision)
    }

    /// Get weights reference
    pub fn weights(&self) -> &WeightsContent {
        &self.weights
    }
}

impl Default for PointsCalculator {
    fn default() -> Self {
        Self::default_v1()
    }
}

/// Default weights content
impl Default for WeightsContent {
    fn default() -> Self {
        Self {
            f_mint_base: MintBaseConfig::default(),
            f_use_base: UseBaseConfig::default(),
            quality_multiplier_table: MultiplierTable::default(),
            compliance_multiplier_table: MultiplierTable::default(),
            stability_multiplier_table: MultiplierTable::default(),
            penalty_table: PenaltyTable::default(),
            discount_table: DiscountTable::default(),
            cap_functions: CapFunctions::default(),
            holdback_rules: HoldbackRules::default(),
            rounding_mode: RoundingMode::BankersRounding,
            precision: 18,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_context() -> PointsContext {
        PointsContext::new(
            EpochId::new("epoch:test"),
            WeightsVersionRef::new("v1", P3Digest::zero()),
        )
    }

    #[test]
    fn test_calculate_single_event() {
        let calc = PointsCalculator::default_v1();
        let ctx = create_test_context();

        let events = vec![EventScore::mint(&MintKind::NewObject, &MintBaseConfig::default())];

        let result = calc
            .calculate_for_actor(&ActorId::new("actor:1"), &events, &ctx)
            .unwrap();

        assert_eq!(result.gross_points, Decimal::new(100, 0));
        assert!(result.verify_invariant());
    }

    #[test]
    fn test_calculate_with_quality_multiplier() {
        let calc = PointsCalculator::default_v1();
        let ctx = create_test_context();

        let events = vec![
            EventScore::mint(&MintKind::NewObject, &MintBaseConfig::default())
                .with_quality(EvalBucket::High),
        ];

        let result = calc
            .calculate_for_actor(&ActorId::new("actor:1"), &events, &ctx)
            .unwrap();

        // High quality = 1.5x multiplier
        assert_eq!(result.gross_points, Decimal::new(150, 0));
    }

    #[test]
    fn test_calculate_with_penalty() {
        let mut weights = WeightsContent::default();
        weights.penalty_table = PenaltyTable {
            entries: vec![PenaltyEntry {
                signal_type: "spam".to_string(),
                penalty_amount: Decimal::new(50, 0),
            }],
        };

        let calc = PointsCalculator::new(weights);
        let ctx = create_test_context();

        let events = vec![
            EventScore::mint(&MintKind::NewObject, &MintBaseConfig::default())
                .with_penalty("spam".to_string()),
        ];

        let result = calc
            .calculate_for_actor(&ActorId::new("actor:1"), &events, &ctx)
            .unwrap();

        // 100 base - 50 penalty = 50
        assert_eq!(result.gross_points, Decimal::new(50, 0));
    }

    #[test]
    fn test_calculate_with_holdback() {
        let calc = PointsCalculator::default_v1();
        let ctx = create_test_context().with_degraded_flag(DegradedFlag::DsnDown);

        let events = vec![EventScore::mint(&MintKind::NewObject, &MintBaseConfig::default())];

        let result = calc
            .calculate_for_actor(&ActorId::new("actor:1"), &events, &ctx)
            .unwrap();

        assert_eq!(result.eligible_points, Decimal::ZERO);
        assert!(result.withheld_points > Decimal::ZERO);
    }

    #[test]
    fn test_calculate_with_cap() {
        let mut weights = WeightsContent::default();
        weights.cap_functions.per_actor_cap = Some(Decimal::new(50, 0));

        let calc = PointsCalculator::new(weights);
        let ctx = create_test_context();

        let events = vec![EventScore::mint(&MintKind::NewObject, &MintBaseConfig::default())];

        let result = calc
            .calculate_for_actor(&ActorId::new("actor:1"), &events, &ctx)
            .unwrap();

        // Capped at 50
        assert_eq!(result.risk_adjusted_points, Decimal::new(50, 0));
    }

    #[test]
    fn test_batch_calculation() {
        let calc = PointsCalculator::default_v1();
        let ctx = create_test_context();

        let mut actor_events = HashMap::new();
        actor_events.insert(
            ActorId::new("actor:1"),
            vec![EventScore::mint(&MintKind::NewObject, &MintBaseConfig::default())],
        );
        actor_events.insert(
            ActorId::new("actor:2"),
            vec![EventScore::mint(&MintKind::VersionUpdate, &MintBaseConfig::default())],
        );

        let results = calc.calculate_batch(&actor_events, &ctx).unwrap();
        assert_eq!(results.len(), 2);
    }
}
