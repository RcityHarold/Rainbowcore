//! Treasury Distribution
//!
//! Handles reward distribution from treasury pools.

use super::TreasuryManager;
use crate::attribution::{AttributionContext, AttributionEngine, AttributionResult, DistributionMode, ShareInput};
use crate::error::{P3Error, P3Result};
use crate::types::*;
use rust_decimal::Decimal;
use std::collections::HashMap;

/// Distribution engine
pub struct DistributionEngine {
    /// Attribution engine
    attribution: AttributionEngine,
    /// Distribution batch size limit
    batch_size_limit: usize,
}

impl DistributionEngine {
    /// Create new distribution engine
    pub fn new() -> Self {
        Self {
            attribution: AttributionEngine::new(),
            batch_size_limit: 1000,
        }
    }

    /// Set batch size limit
    pub fn with_batch_limit(mut self, limit: usize) -> Self {
        self.batch_size_limit = limit;
        self
    }

    /// Execute distribution from reward pool
    pub fn distribute_rewards(
        &self,
        treasury: &mut TreasuryManager,
        inputs: &[ShareInput],
        total_amount: Decimal,
        mode: DistributionMode,
        ctx: &AttributionContext,
    ) -> P3Result<DistributionResult> {
        // Verify sufficient balance
        let available = treasury.pool_balance(&TreasuryPool::RewardPool);
        if total_amount > available {
            return Err(P3Error::InsufficientBalance {
                pool: TreasuryPool::RewardPool.name().to_string(),
                required: total_amount,
                available,
            });
        }

        // Calculate attribution
        let attribution = self.attribution.calculate(
            &format!("dist:{}", ctx.epoch_id.as_str()),
            inputs,
            total_amount,
            mode,
            ctx,
        )?;

        // Debit from reward pool
        treasury.spend(
            TreasuryPool::RewardPool,
            total_amount,
            SpendReasonType::Distribution,
            &ctx.epoch_id,
        )?;

        // Create distribution entries
        let entries: Vec<DistributionEntry> = attribution
            .shares
            .iter()
            .map(|share| DistributionEntry {
                recipient_id: share.contributor_id.clone(),
                amount: share.share_amount,
                share_weight: share.share_weight,
                basis_ref: share.basis_ref.clone(),
            })
            .collect();

        let mut result = DistributionResult {
            distribution_id: format!("dist:{}:{}", ctx.epoch_id.as_str(), chrono::Utc::now().timestamp()),
            epoch_id: ctx.epoch_id.clone(),
            pool: TreasuryPool::RewardPool,
            total_distributed: total_amount,
            entries,
            attribution_digest: attribution.attribution_digest,
            distribution_digest: P3Digest::zero(),
        };

        result.compute_digest();

        Ok(result)
    }

    /// Execute batch distribution
    pub fn distribute_batch(
        &self,
        treasury: &mut TreasuryManager,
        batches: Vec<DistributionBatch>,
        ctx: &AttributionContext,
    ) -> P3Result<Vec<DistributionResult>> {
        let mut results = Vec::new();

        for batch in batches {
            if batch.inputs.len() > self.batch_size_limit {
                return Err(P3Error::InvalidState {
                    reason: format!(
                        "Batch size {} exceeds limit {}",
                        batch.inputs.len(),
                        self.batch_size_limit
                    ),
                });
            }

            let result = self.distribute_rewards(
                treasury,
                &batch.inputs,
                batch.total_amount,
                batch.mode,
                ctx,
            )?;
            results.push(result);
        }

        Ok(results)
    }

    /// Calculate distribution preview (without executing)
    pub fn preview_distribution(
        &self,
        inputs: &[ShareInput],
        total_amount: Decimal,
        mode: DistributionMode,
        ctx: &AttributionContext,
    ) -> P3Result<AttributionResult> {
        self.attribution.calculate(
            &format!("preview:{}", ctx.epoch_id.as_str()),
            inputs,
            total_amount,
            mode,
            ctx,
        )
    }
}

impl Default for DistributionEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Distribution batch
#[derive(Clone, Debug)]
pub struct DistributionBatch {
    /// Batch ID
    pub batch_id: String,
    /// Share inputs
    pub inputs: Vec<ShareInput>,
    /// Total amount to distribute
    pub total_amount: Decimal,
    /// Distribution mode
    pub mode: DistributionMode,
}

impl DistributionBatch {
    /// Create new batch
    pub fn new(batch_id: impl Into<String>, inputs: Vec<ShareInput>, total_amount: Decimal) -> Self {
        Self {
            batch_id: batch_id.into(),
            inputs,
            total_amount,
            mode: DistributionMode::Proportional,
        }
    }

    /// Set distribution mode
    pub fn with_mode(mut self, mode: DistributionMode) -> Self {
        self.mode = mode;
        self
    }
}

/// Distribution result
#[derive(Clone, Debug)]
pub struct DistributionResult {
    /// Distribution ID
    pub distribution_id: String,
    /// Epoch ID
    pub epoch_id: EpochId,
    /// Source pool
    pub pool: TreasuryPool,
    /// Total amount distributed
    pub total_distributed: Decimal,
    /// Distribution entries
    pub entries: Vec<DistributionEntry>,
    /// Attribution digest
    pub attribution_digest: P3Digest,
    /// Distribution digest
    pub distribution_digest: P3Digest,
}

impl DistributionResult {
    /// Compute distribution digest
    pub fn compute_digest(&mut self) {
        let data = format!(
            "{}:{}:{}:{}",
            self.distribution_id,
            self.epoch_id.as_str(),
            self.total_distributed,
            self.entries.len()
        );
        self.distribution_digest = P3Digest::blake3(data.as_bytes());
    }

    /// Verify entries sum to total
    pub fn verify_sum(&self) -> bool {
        let sum: Decimal = self.entries.iter().map(|e| e.amount).sum();
        (sum - self.total_distributed).abs() < Decimal::new(1, 18)
    }

    /// Get entry for recipient
    pub fn get_entry(&self, actor_id: &ActorId) -> Option<&DistributionEntry> {
        self.entries.iter().find(|e| &e.recipient_id == actor_id)
    }
}

/// Distribution entry
#[derive(Clone, Debug)]
pub struct DistributionEntry {
    /// Recipient ID
    pub recipient_id: ActorId,
    /// Amount distributed
    pub amount: Decimal,
    /// Share weight
    pub share_weight: Decimal,
    /// Basis reference
    pub basis_ref: P3Digest,
}

/// Distribution schedule
#[derive(Clone, Debug)]
pub struct DistributionSchedule {
    /// Schedule ID
    pub schedule_id: String,
    /// Target epoch
    pub target_epoch: EpochId,
    /// Planned distributions
    pub planned: Vec<PlannedDistribution>,
    /// Schedule status
    pub status: ScheduleStatus,
}

impl DistributionSchedule {
    /// Create new schedule
    pub fn new(schedule_id: impl Into<String>, target_epoch: EpochId) -> Self {
        Self {
            schedule_id: schedule_id.into(),
            target_epoch,
            planned: Vec::new(),
            status: ScheduleStatus::Pending,
        }
    }

    /// Add planned distribution
    pub fn add_distribution(&mut self, distribution: PlannedDistribution) {
        self.planned.push(distribution);
    }

    /// Get total planned amount
    pub fn total_planned(&self) -> Decimal {
        self.planned.iter().map(|p| p.amount).sum()
    }
}

/// Planned distribution
#[derive(Clone, Debug)]
pub struct PlannedDistribution {
    /// Distribution type
    pub distribution_type: DistributionType,
    /// Amount
    pub amount: Decimal,
    /// Recipient count (estimated)
    pub recipient_count: usize,
}

/// Distribution type
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DistributionType {
    /// Epoch rewards
    EpochReward,
    /// Bonus distribution
    Bonus,
    /// Retroactive distribution
    Retroactive,
    /// Special distribution
    Special,
}

/// Schedule status
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScheduleStatus {
    /// Pending execution
    Pending,
    /// In progress
    InProgress,
    /// Completed
    Completed,
    /// Cancelled
    Cancelled,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribution::AttributionContext;

    fn create_test_treasury() -> TreasuryManager {
        let mut manager = TreasuryManager::new();
        let ratios = PoolRatios::default();
        let ratio_version = PoolRatioVersion {
            ratio_id: "ratio:test".to_string(),
            version: "v1".to_string(),
            valid_from: EpochId::new("epoch:1"),
            supersedes: None,
            issuer_ref: "test".to_string(),
            ratio_digest: ratios.compute_digest(),
            canonicalization_version: CanonVersion::v1(),
            ratios,
        };
        let ctx = super::super::TreasuryContext::new(EpochId::new("epoch:1"), ratio_version);
        manager.set_context(ctx);
        manager
    }

    fn create_test_attribution_context() -> AttributionContext {
        AttributionContext::new(
            EpochId::new("epoch:1"),
            WeightsVersionRef::new("v1", P3Digest::zero()),
            LineagePolicyVersion::default_policy(EpochId::new("epoch:genesis")),
        )
    }

    #[test]
    fn test_distribution_engine_creation() {
        let engine = DistributionEngine::new();
        assert_eq!(engine.batch_size_limit, 1000);
    }

    #[test]
    fn test_distribute_rewards() {
        let engine = DistributionEngine::new();
        let mut treasury = create_test_treasury();
        let ctx = create_test_attribution_context();

        // First add funds to reward pool
        treasury
            .capture_income(Decimal::new(100, 0), &EpochId::new("epoch:1"))
            .unwrap();

        let inputs = vec![
            ShareInput::new(ActorId::new("actor:1"), ContributorType::HumanActor, Decimal::new(60, 0)),
            ShareInput::new(ActorId::new("actor:2"), ContributorType::HumanActor, Decimal::new(40, 0)),
        ];

        let result = engine
            .distribute_rewards(
                &mut treasury,
                &inputs,
                Decimal::new(20, 0), // Distribute 20 from reward pool (has 30)
                DistributionMode::Proportional,
                &ctx,
            )
            .unwrap();

        assert!(result.verify_sum());
        assert_eq!(result.entries.len(), 2);
        assert_eq!(result.total_distributed, Decimal::new(20, 0));

        // Verify pool balance decreased
        assert_eq!(treasury.pool_balance(&TreasuryPool::RewardPool), Decimal::new(10, 0));
    }

    #[test]
    fn test_distribute_insufficient_balance() {
        let engine = DistributionEngine::new();
        let mut treasury = create_test_treasury();
        let ctx = create_test_attribution_context();

        // Add some funds
        treasury
            .capture_income(Decimal::new(100, 0), &EpochId::new("epoch:1"))
            .unwrap();

        let inputs = vec![ShareInput::new(
            ActorId::new("actor:1"),
            ContributorType::HumanActor,
            Decimal::new(100, 0),
        )];

        // Try to distribute more than available in reward pool (30)
        let result = engine.distribute_rewards(
            &mut treasury,
            &inputs,
            Decimal::new(50, 0),
            DistributionMode::Proportional,
            &ctx,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_preview_distribution() {
        let engine = DistributionEngine::new();
        let ctx = create_test_attribution_context();

        let inputs = vec![
            ShareInput::new(ActorId::new("actor:1"), ContributorType::HumanActor, Decimal::new(50, 0)),
            ShareInput::new(ActorId::new("actor:2"), ContributorType::HumanActor, Decimal::new(50, 0)),
        ];

        let preview = engine
            .preview_distribution(&inputs, Decimal::new(100, 0), DistributionMode::Equal, &ctx)
            .unwrap();

        assert!(preview.verify_shares_sum());
        assert_eq!(preview.shares.len(), 2);
    }

    #[test]
    fn test_distribution_batch() {
        let batch = DistributionBatch::new(
            "batch:1",
            vec![ShareInput::new(
                ActorId::new("actor:1"),
                ContributorType::HumanActor,
                Decimal::ONE,
            )],
            Decimal::new(100, 0),
        )
        .with_mode(DistributionMode::Equal);

        assert_eq!(batch.batch_id, "batch:1");
        assert_eq!(batch.mode, DistributionMode::Equal);
    }

    #[test]
    fn test_distribution_schedule() {
        let mut schedule = DistributionSchedule::new("sched:1", EpochId::new("epoch:5"));

        schedule.add_distribution(PlannedDistribution {
            distribution_type: DistributionType::EpochReward,
            amount: Decimal::new(1000, 0),
            recipient_count: 50,
        });

        schedule.add_distribution(PlannedDistribution {
            distribution_type: DistributionType::Bonus,
            amount: Decimal::new(200, 0),
            recipient_count: 10,
        });

        assert_eq!(schedule.total_planned(), Decimal::new(1200, 0));
        assert_eq!(schedule.status, ScheduleStatus::Pending);
    }
}
