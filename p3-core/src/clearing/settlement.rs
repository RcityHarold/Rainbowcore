//! Settlement Processing
//!
//! Handles epoch settlement and finalization.

use super::*;
use crate::attribution::AttributionResult;
use crate::error::{P3Error, P3Result};
use crate::treasury::{IncomeSplit, TreasuryManager};
use crate::types::*;
use rust_decimal::Decimal;
use std::collections::HashMap;

/// Settlement processor
pub struct SettlementProcessor {
    /// Settlement rules
    rules: SettlementRules,
}

impl SettlementProcessor {
    /// Create new processor
    pub fn new() -> Self {
        Self {
            rules: SettlementRules::default(),
        }
    }

    /// Create processor with custom rules
    pub fn with_rules(rules: SettlementRules) -> Self {
        Self { rules }
    }

    /// Process epoch settlement
    pub fn process_settlement(
        &self,
        treasury: &mut TreasuryManager,
        clearing: &mut ClearingEngine,
        epoch_id: &EpochId,
        income: Decimal,
        attributions: &[AttributionResult],
    ) -> P3Result<SettlementReport> {
        let mut report = SettlementReport::new(epoch_id.clone());

        // Step 1: Capture income into treasury pools
        let income_split = treasury.capture_income(income, epoch_id)?;
        report.income_split = Some(income_split);

        // Step 2: Process pending fines
        let fine_summary = self.process_pending_fines(clearing, treasury)?;
        report.fines_collected = fine_summary.0;
        report.fines_collected_amount = fine_summary.1;

        // Step 3: Process pending clawbacks
        let clawback_summary = self.process_pending_clawbacks(clearing, treasury)?;
        report.clawbacks_executed = clawback_summary.0;
        report.clawbacks_executed_amount = clawback_summary.1;

        // Step 4: Process deposit releases (based on rules)
        let deposit_summary = self.process_deposit_releases(clearing, epoch_id)?;
        report.deposits_released = deposit_summary.0;
        report.deposits_released_amount = deposit_summary.1;

        // Step 5: Record attributions
        report.attributions_processed = attributions.len();
        report.total_distributed = attributions.iter().map(|a| a.total_amount).sum();

        // Step 6: Create snapshots
        report.pool_snapshots = treasury.create_snapshots(epoch_id);

        // Step 7: Reset epoch totals for next epoch
        treasury.reset_epoch_totals();

        // Finalize report
        report.status = SettlementStatus::Completed;
        report.compute_digest();

        Ok(report)
    }

    /// Process pending fines
    fn process_pending_fines(
        &self,
        clearing: &mut ClearingEngine,
        treasury: &mut TreasuryManager,
    ) -> P3Result<(usize, Decimal)> {
        let pending_fine_ids: Vec<String> = clearing
            .fines
            .values()
            .filter(|f| f.status == FineStatus::Pending)
            .map(|f| f.fine_id.clone())
            .collect();

        let mut count = 0;
        let mut amount = Decimal::ZERO;

        for fine_id in pending_fine_ids {
            if let Ok(record) = clearing.collect_fine(&fine_id, treasury) {
                count += 1;
                amount += record.amount;
            }
        }

        Ok((count, amount))
    }

    /// Process pending clawbacks
    fn process_pending_clawbacks(
        &self,
        clearing: &mut ClearingEngine,
        treasury: &mut TreasuryManager,
    ) -> P3Result<(usize, Decimal)> {
        let pending_clawback_ids: Vec<String> = clearing
            .clawbacks
            .values()
            .filter(|c| c.status == ClawbackRecordStatus::Pending)
            .map(|c| c.clawback_id.clone())
            .collect();

        let mut count = 0;
        let mut amount = Decimal::ZERO;

        for clawback_id in pending_clawback_ids {
            if let Ok(record) = clearing.execute_clawback(&clawback_id, treasury) {
                count += 1;
                amount += record.amount;
            }
        }

        Ok((count, amount))
    }

    /// Process deposit releases based on rules
    fn process_deposit_releases(
        &self,
        clearing: &mut ClearingEngine,
        epoch_id: &EpochId,
    ) -> P3Result<(usize, Decimal)> {
        // In standard mode, deposits are released based on their type and holding period
        // For now, we don't auto-release - deposits are released explicitly
        Ok((0, Decimal::ZERO))
    }

    /// Validate settlement preconditions
    pub fn validate_preconditions(
        &self,
        treasury: &TreasuryManager,
        clearing: &ClearingEngine,
    ) -> P3Result<()> {
        // Verify treasury invariant
        if !treasury.verify_invariant() {
            return Err(P3Error::InvariantViolation {
                invariant: "Three pool invariant".to_string(),
                details: "Treasury pools are not in valid state".to_string(),
            });
        }

        // Verify escrow accounting
        let summary = clearing.summary();
        if summary.escrow_balance != summary.active_deposit_amount {
            return Err(P3Error::InvariantViolation {
                invariant: "Escrow balance".to_string(),
                details: "Escrow balance does not match active deposits".to_string(),
            });
        }

        Ok(())
    }
}

impl Default for SettlementProcessor {
    fn default() -> Self {
        Self::new()
    }
}

/// Settlement rules
#[derive(Clone, Debug)]
pub struct SettlementRules {
    /// Auto-collect fines
    pub auto_collect_fines: bool,
    /// Auto-execute clawbacks
    pub auto_execute_clawbacks: bool,
    /// Deposit holding periods by type
    pub deposit_holding_periods: HashMap<DepositType, u32>,
    /// Minimum settlement amount
    pub min_settlement_amount: Decimal,
}

impl Default for SettlementRules {
    fn default() -> Self {
        let mut holding_periods = HashMap::new();
        holding_periods.insert(DepositType::Security, 10);
        holding_periods.insert(DepositType::Performance, 5);
        holding_periods.insert(DepositType::Challenge, 3);
        holding_periods.insert(DepositType::Appeal, 7);

        Self {
            auto_collect_fines: true,
            auto_execute_clawbacks: true,
            deposit_holding_periods: holding_periods,
            min_settlement_amount: Decimal::new(1, 2), // 0.01
        }
    }
}

/// Settlement report
#[derive(Clone, Debug)]
pub struct SettlementReport {
    /// Epoch ID
    pub epoch_id: EpochId,
    /// Income split
    pub income_split: Option<IncomeSplit>,
    /// Fines collected count
    pub fines_collected: usize,
    /// Fines collected amount
    pub fines_collected_amount: Decimal,
    /// Clawbacks executed count
    pub clawbacks_executed: usize,
    /// Clawbacks executed amount
    pub clawbacks_executed_amount: Decimal,
    /// Deposits released count
    pub deposits_released: usize,
    /// Deposits released amount
    pub deposits_released_amount: Decimal,
    /// Attributions processed
    pub attributions_processed: usize,
    /// Total distributed
    pub total_distributed: Decimal,
    /// Pool snapshots
    pub pool_snapshots: Vec<PoolBalanceSnapshot>,
    /// Settlement status
    pub status: SettlementStatus,
    /// Report digest
    pub report_digest: P3Digest,
}

impl SettlementReport {
    /// Create new report
    pub fn new(epoch_id: EpochId) -> Self {
        Self {
            epoch_id,
            income_split: None,
            fines_collected: 0,
            fines_collected_amount: Decimal::ZERO,
            clawbacks_executed: 0,
            clawbacks_executed_amount: Decimal::ZERO,
            deposits_released: 0,
            deposits_released_amount: Decimal::ZERO,
            attributions_processed: 0,
            total_distributed: Decimal::ZERO,
            pool_snapshots: Vec::new(),
            status: SettlementStatus::Pending,
            report_digest: P3Digest::zero(),
        }
    }

    /// Compute report digest
    pub fn compute_digest(&mut self) {
        let data = format!(
            "{}:{}:{}:{}:{}:{}",
            self.epoch_id.as_str(),
            self.fines_collected,
            self.clawbacks_executed,
            self.deposits_released,
            self.attributions_processed,
            self.total_distributed,
        );
        self.report_digest = P3Digest::blake3(data.as_bytes());
    }

    /// Get total pool balance from snapshots
    pub fn total_pool_balance(&self) -> Decimal {
        // Snapshots only contain digests, not actual balances
        // This would need to be tracked separately in production
        Decimal::ZERO
    }
}

/// Settlement status
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettlementStatus {
    /// Pending
    Pending,
    /// In progress
    InProgress,
    /// Completed
    Completed,
    /// Failed
    Failed,
    /// Rolled back
    RolledBack,
}

/// Settlement batch
#[derive(Clone, Debug)]
pub struct SettlementBatch {
    /// Batch ID
    pub batch_id: String,
    /// Epochs in batch
    pub epochs: Vec<EpochId>,
    /// Status
    pub status: SettlementStatus,
}

impl SettlementBatch {
    /// Create new batch
    pub fn new(batch_id: impl Into<String>) -> Self {
        Self {
            batch_id: batch_id.into(),
            epochs: Vec::new(),
            status: SettlementStatus::Pending,
        }
    }

    /// Add epoch to batch
    pub fn add_epoch(&mut self, epoch_id: EpochId) {
        self.epochs.push(epoch_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::treasury::TreasuryContext;

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
        let ctx = TreasuryContext::new(EpochId::new("epoch:1"), ratio_version);
        manager.set_context(ctx);
        manager
    }

    fn create_test_clearing_engine() -> ClearingEngine {
        let mut engine = ClearingEngine::new();
        engine.set_context(ClearingContext::new(EpochId::new("epoch:1")));
        engine
    }

    #[test]
    fn test_settlement_processor_creation() {
        let processor = SettlementProcessor::new();
        assert!(processor.rules.auto_collect_fines);
    }

    #[test]
    fn test_process_settlement() {
        let processor = SettlementProcessor::new();
        let mut treasury = create_test_treasury();
        let mut clearing = create_test_clearing_engine();
        let epoch = EpochId::new("epoch:1");

        let report = processor
            .process_settlement(&mut treasury, &mut clearing, &epoch, Decimal::new(100, 0), &[])
            .unwrap();

        assert_eq!(report.status, SettlementStatus::Completed);
        assert!(report.income_split.is_some());
        assert_eq!(report.pool_snapshots.len(), 3);
    }

    #[test]
    fn test_settlement_with_fines() {
        let processor = SettlementProcessor::new();
        let mut treasury = create_test_treasury();
        let mut clearing = create_test_clearing_engine();
        let epoch = EpochId::new("epoch:1");

        // Record a fine
        clearing
            .record_fine(
                ActorId::new("actor:1"),
                Decimal::new(25, 0),
                FineType::Misconduct,
                P3Digest::zero(),
            )
            .unwrap();

        let report = processor
            .process_settlement(&mut treasury, &mut clearing, &epoch, Decimal::new(100, 0), &[])
            .unwrap();

        assert_eq!(report.fines_collected, 1);
        assert_eq!(report.fines_collected_amount, Decimal::new(25, 0));
    }

    #[test]
    fn test_validate_preconditions() {
        let processor = SettlementProcessor::new();
        let treasury = create_test_treasury();
        let clearing = create_test_clearing_engine();

        let result = processor.validate_preconditions(&treasury, &clearing);
        assert!(result.is_ok());
    }

    #[test]
    fn test_settlement_rules_default() {
        let rules = SettlementRules::default();
        assert!(rules.auto_collect_fines);
        assert!(rules.auto_execute_clawbacks);
        assert_eq!(rules.deposit_holding_periods.get(&DepositType::Security), Some(&10));
    }

    #[test]
    fn test_settlement_batch() {
        let mut batch = SettlementBatch::new("batch:1");
        batch.add_epoch(EpochId::new("epoch:1"));
        batch.add_epoch(EpochId::new("epoch:2"));

        assert_eq!(batch.epochs.len(), 2);
        assert_eq!(batch.status, SettlementStatus::Pending);
    }

    #[test]
    fn test_settlement_report() {
        let mut report = SettlementReport::new(EpochId::new("epoch:1"));
        report.fines_collected = 5;
        report.fines_collected_amount = Decimal::new(100, 0);
        report.compute_digest();

        assert_ne!(report.report_digest, P3Digest::zero());
    }
}
