//! Clearing Engine
//!
//! Core clearing and settlement logic.

use super::*;
use crate::error::{P3Error, P3Result};
use crate::treasury::{TreasuryManager, SpendRecord};
use crate::types::*;
use rust_decimal::Decimal;
use std::collections::HashMap;

/// Clearing engine
pub struct ClearingEngine {
    /// Active deposits
    pub deposits: HashMap<String, DepositRecord>,
    /// Pending fines
    pub fines: HashMap<String, FineRecord>,
    /// Pending clawbacks
    pub clawbacks: HashMap<String, ClawbackRecord>,
    /// Escrow balance
    escrow_balance: Decimal,
    /// Context
    context: Option<ClearingContext>,
}

impl ClearingEngine {
    /// Create new clearing engine
    pub fn new() -> Self {
        Self {
            deposits: HashMap::new(),
            fines: HashMap::new(),
            clawbacks: HashMap::new(),
            escrow_balance: Decimal::ZERO,
            context: None,
        }
    }

    /// Set context
    pub fn set_context(&mut self, context: ClearingContext) {
        self.context = Some(context);
    }

    /// Get context
    pub fn context(&self) -> Option<&ClearingContext> {
        self.context.as_ref()
    }

    /// Accept deposit
    pub fn accept_deposit(
        &mut self,
        actor_id: ActorId,
        amount: Decimal,
        deposit_type: DepositType,
        action_ref: Option<P3Digest>,
    ) -> P3Result<DepositRecord> {
        let ctx = self.context.as_ref().ok_or_else(|| P3Error::InvalidState {
            reason: "Clearing context not set".to_string(),
        })?;

        if amount <= Decimal::ZERO {
            return Err(P3Error::InvalidAmount {
                reason: "Deposit amount must be positive".to_string(),
            });
        }

        let deposit_id = format!(
            "dep:{}:{}:{}",
            ctx.epoch_id.as_str(),
            actor_id.as_str(),
            self.deposits.len()
        );

        let mut deposit = DepositRecord::new(
            deposit_id.clone(),
            actor_id,
            amount,
            deposit_type,
            ctx.epoch_id.clone(),
        );

        if let Some(action_ref) = action_ref {
            deposit = deposit.with_action_ref(action_ref);
        }

        // Add to escrow
        self.escrow_balance += amount;
        self.deposits.insert(deposit_id, deposit.clone());

        Ok(deposit)
    }

    /// Release deposit
    pub fn release_deposit(&mut self, deposit_id: &str) -> P3Result<Decimal> {
        let ctx = self.context.as_ref().ok_or_else(|| P3Error::InvalidState {
            reason: "Clearing context not set".to_string(),
        })?;

        let deposit = self.deposits.get_mut(deposit_id).ok_or_else(|| P3Error::NotFound {
            entity: "Deposit".to_string(),
            id: deposit_id.to_string(),
        })?;

        let amount = deposit.amount;
        deposit.release(ctx.epoch_id.clone())?;
        self.escrow_balance -= amount;

        Ok(amount)
    }

    /// Forfeit deposit (to treasury)
    ///
    /// Core anti-black-box clause: Deposit forfeit requires valid VerdictRef if the deposit type requires it.
    /// This prevents unauthorized "dark box" forfeitures without proper legal basis.
    pub fn forfeit_deposit(
        &mut self,
        deposit_id: &str,
        treasury: &mut TreasuryManager,
    ) -> P3Result<SpendRecord> {
        let ctx = self.context.as_ref().ok_or_else(|| P3Error::InvalidState {
            reason: "Clearing context not set".to_string(),
        })?;

        let deposit = self.deposits.get_mut(deposit_id).ok_or_else(|| P3Error::NotFound {
            entity: "Deposit".to_string(),
            id: deposit_id.to_string(),
        })?;

        // Core anti-black-box clause: Check if forfeit is authorized
        // According to Chapter 7: "任何罚没必须绑定 VerdictRef，不得暗箱扣款"
        if !deposit.can_forfeit() {
            return Err(P3Error::VerdictRefRequired);
        }

        let amount = deposit.amount;
        deposit.forfeit(ctx.epoch_id.clone())?;
        self.escrow_balance -= amount;

        // Credit to infra pool (forfeited deposits go to infrastructure)
        treasury
            .get_pool_mut(&TreasuryPool::InfraPool)
            .unwrap()
            .credit(amount, &ctx.epoch_id)?;

        Ok(SpendRecord {
            pool: TreasuryPool::InfraPool,
            amount,
            reason: SpendReasonType::DepositForfeiture,
            epoch_id: ctx.epoch_id.clone(),
        })
    }

    /// Set verdict reference for a deposit (required before forfeit for most deposit types)
    pub fn set_deposit_verdict_ref(
        &mut self,
        deposit_id: &str,
        verdict_ref: P3Digest,
    ) -> P3Result<()> {
        let deposit = self.deposits.get_mut(deposit_id).ok_or_else(|| P3Error::NotFound {
            entity: "Deposit".to_string(),
            id: deposit_id.to_string(),
        })?;

        // VerdictRef must be valid (not zero)
        if verdict_ref.is_zero() {
            return Err(P3Error::VerdictRefRequired);
        }

        deposit.verdict_ref = Some(verdict_ref);
        Ok(())
    }

    /// Record fine
    ///
    /// Core anti-black-box clause: Fine requires valid VerdictRef (not zero).
    /// Any fine without a valid verdict reference is considered "dark box deduction" and will be rejected.
    pub fn record_fine(
        &mut self,
        actor_id: ActorId,
        amount: Decimal,
        fine_type: FineType,
        verdict_ref: P3Digest,
    ) -> P3Result<FineRecord> {
        let ctx = self.context.as_ref().ok_or_else(|| P3Error::InvalidState {
            reason: "Clearing context not set".to_string(),
        })?;

        // Core anti-black-box clause: VerdictRef must be valid (not zero)
        // According to Chapter 7: "任何罚金必须绑定 VerdictRef，不得暗箱扣款"
        if verdict_ref.is_zero() {
            return Err(P3Error::VerdictRefRequired);
        }

        if amount <= Decimal::ZERO {
            return Err(P3Error::InvalidAmount {
                reason: "Fine amount must be positive".to_string(),
            });
        }

        let fine_id = format!(
            "fine:{}:{}:{}",
            ctx.epoch_id.as_str(),
            actor_id.as_str(),
            self.fines.len()
        );

        let fine = FineRecord::new(
            fine_id.clone(),
            actor_id,
            amount,
            fine_type,
            verdict_ref,
            ctx.epoch_id.clone(),
        );

        self.fines.insert(fine_id, fine.clone());

        Ok(fine)
    }

    /// Collect fine (transfer to treasury)
    pub fn collect_fine(
        &mut self,
        fine_id: &str,
        treasury: &mut TreasuryManager,
    ) -> P3Result<SpendRecord> {
        let ctx = self.context.as_ref().ok_or_else(|| P3Error::InvalidState {
            reason: "Clearing context not set".to_string(),
        })?;

        let fine = self.fines.get_mut(fine_id).ok_or_else(|| P3Error::NotFound {
            entity: "Fine".to_string(),
            id: fine_id.to_string(),
        })?;

        let amount = fine.amount;
        fine.collect(ctx.epoch_id.clone())?;

        // Credit to civilization pool (fines support governance)
        treasury
            .get_pool_mut(&TreasuryPool::CivilizationPool)
            .unwrap()
            .credit(amount, &ctx.epoch_id)?;

        Ok(SpendRecord {
            pool: TreasuryPool::CivilizationPool,
            amount,
            reason: SpendReasonType::FineCollection,
            epoch_id: ctx.epoch_id.clone(),
        })
    }

    /// Waive fine
    pub fn waive_fine(&mut self, fine_id: &str) -> P3Result<()> {
        let ctx = self.context.as_ref().ok_or_else(|| P3Error::InvalidState {
            reason: "Clearing context not set".to_string(),
        })?;

        let fine = self.fines.get_mut(fine_id).ok_or_else(|| P3Error::NotFound {
            entity: "Fine".to_string(),
            id: fine_id.to_string(),
        })?;

        fine.waive(ctx.epoch_id.clone())?;
        Ok(())
    }

    /// Record clawback
    pub fn record_clawback(
        &mut self,
        actor_id: ActorId,
        distribution_ref: P3Digest,
        amount: Decimal,
        reason: ClawbackReason,
    ) -> P3Result<ClawbackRecord> {
        let ctx = self.context.as_ref().ok_or_else(|| P3Error::InvalidState {
            reason: "Clearing context not set".to_string(),
        })?;

        if amount <= Decimal::ZERO {
            return Err(P3Error::InvalidAmount {
                reason: "Clawback amount must be positive".to_string(),
            });
        }

        let clawback_id = format!(
            "claw:{}:{}:{}",
            ctx.epoch_id.as_str(),
            actor_id.as_str(),
            self.clawbacks.len()
        );

        let clawback = ClawbackRecord::new(
            clawback_id.clone(),
            actor_id,
            distribution_ref,
            amount,
            reason,
            ctx.epoch_id.clone(),
        );

        self.clawbacks.insert(clawback_id, clawback.clone());

        Ok(clawback)
    }

    /// Execute clawback
    pub fn execute_clawback(
        &mut self,
        clawback_id: &str,
        treasury: &mut TreasuryManager,
    ) -> P3Result<SpendRecord> {
        let ctx = self.context.as_ref().ok_or_else(|| P3Error::InvalidState {
            reason: "Clearing context not set".to_string(),
        })?;

        let clawback = self.clawbacks.get_mut(clawback_id).ok_or_else(|| P3Error::NotFound {
            entity: "Clawback".to_string(),
            id: clawback_id.to_string(),
        })?;

        let amount = clawback.amount;
        clawback.execute(ctx.epoch_id.clone())?;

        // Return to reward pool
        treasury
            .get_pool_mut(&TreasuryPool::RewardPool)
            .unwrap()
            .credit(amount, &ctx.epoch_id)?;

        Ok(SpendRecord {
            pool: TreasuryPool::RewardPool,
            amount,
            reason: SpendReasonType::Clawback,
            epoch_id: ctx.epoch_id.clone(),
        })
    }

    /// Cancel clawback
    pub fn cancel_clawback(&mut self, clawback_id: &str) -> P3Result<()> {
        let clawback = self.clawbacks.get_mut(clawback_id).ok_or_else(|| P3Error::NotFound {
            entity: "Clawback".to_string(),
            id: clawback_id.to_string(),
        })?;

        clawback.cancel()?;
        Ok(())
    }

    /// Get deposit
    pub fn get_deposit(&self, deposit_id: &str) -> Option<&DepositRecord> {
        self.deposits.get(deposit_id)
    }

    /// Get fine
    pub fn get_fine(&self, fine_id: &str) -> Option<&FineRecord> {
        self.fines.get(fine_id)
    }

    /// Get clawback
    pub fn get_clawback(&self, clawback_id: &str) -> Option<&ClawbackRecord> {
        self.clawbacks.get(clawback_id)
    }

    /// Get escrow balance
    pub fn escrow_balance(&self) -> Decimal {
        self.escrow_balance
    }

    /// Get active deposits for actor
    pub fn active_deposits_for(&self, actor_id: &ActorId) -> Vec<&DepositRecord> {
        self.deposits
            .values()
            .filter(|d| &d.actor_id == actor_id && d.is_active())
            .collect()
    }

    /// Get pending fines for actor
    pub fn pending_fines_for(&self, actor_id: &ActorId) -> Vec<&FineRecord> {
        self.fines
            .values()
            .filter(|f| &f.actor_id == actor_id && f.status == FineStatus::Pending)
            .collect()
    }

    /// Get pending clawbacks for actor
    pub fn pending_clawbacks_for(&self, actor_id: &ActorId) -> Vec<&ClawbackRecord> {
        self.clawbacks
            .values()
            .filter(|c| &c.actor_id == actor_id && c.status == ClawbackRecordStatus::Pending)
            .collect()
    }

    /// Calculate total obligations for actor
    pub fn total_obligations_for(&self, actor_id: &ActorId) -> Decimal {
        let pending_fines: Decimal = self
            .pending_fines_for(actor_id)
            .iter()
            .map(|f| f.amount)
            .sum();

        let pending_clawbacks: Decimal = self
            .pending_clawbacks_for(actor_id)
            .iter()
            .map(|c| c.amount)
            .sum();

        pending_fines + pending_clawbacks
    }

    /// Generate clearing summary
    pub fn summary(&self) -> ClearingSummary {
        let active_deposits: Decimal = self
            .deposits
            .values()
            .filter(|d| d.is_active())
            .map(|d| d.amount)
            .sum();

        let pending_fines: Decimal = self
            .fines
            .values()
            .filter(|f| f.status == FineStatus::Pending)
            .map(|f| f.amount)
            .sum();

        let pending_clawbacks: Decimal = self
            .clawbacks
            .values()
            .filter(|c| c.status == ClawbackRecordStatus::Pending)
            .map(|c| c.amount)
            .sum();

        ClearingSummary {
            active_deposit_count: self.deposits.values().filter(|d| d.is_active()).count(),
            active_deposit_amount: active_deposits,
            pending_fine_count: self.fines.values().filter(|f| f.status == FineStatus::Pending).count(),
            pending_fine_amount: pending_fines,
            pending_clawback_count: self.clawbacks.values().filter(|c| c.status == ClawbackRecordStatus::Pending).count(),
            pending_clawback_amount: pending_clawbacks,
            escrow_balance: self.escrow_balance,
        }
    }
}

impl Default for ClearingEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Clearing summary
#[derive(Clone, Debug)]
pub struct ClearingSummary {
    /// Active deposit count
    pub active_deposit_count: usize,
    /// Active deposit amount
    pub active_deposit_amount: Decimal,
    /// Pending fine count
    pub pending_fine_count: usize,
    /// Pending fine amount
    pub pending_fine_amount: Decimal,
    /// Pending clawback count
    pub pending_clawback_count: usize,
    /// Pending clawback amount
    pub pending_clawback_amount: Decimal,
    /// Escrow balance
    pub escrow_balance: Decimal,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::treasury::TreasuryContext;

    fn create_test_clearing_engine() -> ClearingEngine {
        let mut engine = ClearingEngine::new();
        engine.set_context(ClearingContext::new(EpochId::new("epoch:1")));
        engine
    }

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

    #[test]
    fn test_clearing_engine_creation() {
        let engine = create_test_clearing_engine();
        assert_eq!(engine.escrow_balance(), Decimal::ZERO);
    }

    #[test]
    fn test_accept_deposit() {
        let mut engine = create_test_clearing_engine();

        let deposit = engine
            .accept_deposit(
                ActorId::new("actor:1"),
                Decimal::new(100, 0),
                DepositType::Security,
                None,
            )
            .unwrap();

        assert_eq!(deposit.amount, Decimal::new(100, 0));
        assert!(deposit.is_active());
        assert_eq!(engine.escrow_balance(), Decimal::new(100, 0));
    }

    #[test]
    fn test_release_deposit() {
        let mut engine = create_test_clearing_engine();

        let deposit = engine
            .accept_deposit(
                ActorId::new("actor:1"),
                Decimal::new(100, 0),
                DepositType::Security,
                None,
            )
            .unwrap();

        let released = engine.release_deposit(&deposit.deposit_id).unwrap();
        assert_eq!(released, Decimal::new(100, 0));
        assert_eq!(engine.escrow_balance(), Decimal::ZERO);
    }

    #[test]
    fn test_forfeit_deposit_with_verdict() {
        let mut engine = create_test_clearing_engine();
        let mut treasury = create_test_treasury();

        let deposit = engine
            .accept_deposit(
                ActorId::new("actor:1"),
                Decimal::new(100, 0),
                DepositType::Challenge,
                None,
            )
            .unwrap();

        // Set a valid verdict_ref before forfeit (anti-black-box requirement)
        let valid_verdict_ref = P3Digest::blake3(b"verdict:test:001");
        engine.set_deposit_verdict_ref(&deposit.deposit_id, valid_verdict_ref).unwrap();

        let infra_before = treasury.pool_balance(&TreasuryPool::InfraPool);
        engine.forfeit_deposit(&deposit.deposit_id, &mut treasury).unwrap();
        let infra_after = treasury.pool_balance(&TreasuryPool::InfraPool);

        assert_eq!(infra_after - infra_before, Decimal::new(100, 0));
        assert_eq!(engine.escrow_balance(), Decimal::ZERO);
    }

    #[test]
    fn test_forfeit_deposit_without_verdict_fails() {
        let mut engine = create_test_clearing_engine();
        let mut treasury = create_test_treasury();

        let deposit = engine
            .accept_deposit(
                ActorId::new("actor:1"),
                Decimal::new(100, 0),
                DepositType::Challenge, // Challenge requires verdict
                None,
            )
            .unwrap();

        // Attempt to forfeit without setting verdict_ref should fail
        let result = engine.forfeit_deposit(&deposit.deposit_id, &mut treasury);
        assert!(result.is_err());
    }

    #[test]
    fn test_forfeit_deposit_with_performance_type() {
        let mut engine = create_test_clearing_engine();
        let mut treasury = create_test_treasury();

        let deposit = engine
            .accept_deposit(
                ActorId::new("actor:1"),
                Decimal::new(100, 0),
                DepositType::Performance, // Performance does not require verdict
                None,
            )
            .unwrap();

        // Performance deposits don't require verdict, can forfeit directly
        let infra_before = treasury.pool_balance(&TreasuryPool::InfraPool);
        engine.forfeit_deposit(&deposit.deposit_id, &mut treasury).unwrap();
        let infra_after = treasury.pool_balance(&TreasuryPool::InfraPool);

        assert_eq!(infra_after - infra_before, Decimal::new(100, 0));
    }

    #[test]
    fn test_record_and_collect_fine() {
        let mut engine = create_test_clearing_engine();
        let mut treasury = create_test_treasury();

        // Use a valid verdict_ref (not zero) - anti-black-box requirement
        let valid_verdict_ref = P3Digest::blake3(b"verdict:court:2024:001");

        let fine = engine
            .record_fine(
                ActorId::new("actor:1"),
                Decimal::new(50, 0),
                FineType::ProtocolViolation,
                valid_verdict_ref,
            )
            .unwrap();

        let civ_before = treasury.pool_balance(&TreasuryPool::CivilizationPool);
        engine.collect_fine(&fine.fine_id, &mut treasury).unwrap();
        let civ_after = treasury.pool_balance(&TreasuryPool::CivilizationPool);

        assert_eq!(civ_after - civ_before, Decimal::new(50, 0));
    }

    #[test]
    fn test_record_fine_with_zero_verdict_fails() {
        let mut engine = create_test_clearing_engine();

        // Using P3Digest::zero() as verdict_ref should fail (anti-black-box clause)
        let result = engine.record_fine(
            ActorId::new("actor:1"),
            Decimal::new(50, 0),
            FineType::ProtocolViolation,
            P3Digest::zero(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_record_and_execute_clawback() {
        let mut engine = create_test_clearing_engine();
        let mut treasury = create_test_treasury();

        let clawback = engine
            .record_clawback(
                ActorId::new("actor:1"),
                P3Digest::zero(),
                Decimal::new(30, 0),
                ClawbackReason::Fraud,
            )
            .unwrap();

        let reward_before = treasury.pool_balance(&TreasuryPool::RewardPool);
        engine.execute_clawback(&clawback.clawback_id, &mut treasury).unwrap();
        let reward_after = treasury.pool_balance(&TreasuryPool::RewardPool);

        assert_eq!(reward_after - reward_before, Decimal::new(30, 0));
    }

    #[test]
    fn test_total_obligations() {
        let mut engine = create_test_clearing_engine();
        let actor = ActorId::new("actor:1");

        // Use valid verdict_ref
        let valid_verdict_ref = P3Digest::blake3(b"verdict:misconduct:001");

        engine
            .record_fine(
                actor.clone(),
                Decimal::new(50, 0),
                FineType::Misconduct,
                valid_verdict_ref,
            )
            .unwrap();

        engine
            .record_clawback(
                actor.clone(),
                P3Digest::zero(),
                Decimal::new(30, 0),
                ClawbackReason::AttributionError,
            )
            .unwrap();

        let total = engine.total_obligations_for(&actor);
        assert_eq!(total, Decimal::new(80, 0));
    }

    #[test]
    fn test_clearing_summary() {
        let mut engine = create_test_clearing_engine();

        engine
            .accept_deposit(
                ActorId::new("actor:1"),
                Decimal::new(100, 0),
                DepositType::Security,
                None,
            )
            .unwrap();

        // Use valid verdict_ref
        let valid_verdict_ref = P3Digest::blake3(b"verdict:late:002");

        engine
            .record_fine(
                ActorId::new("actor:2"),
                Decimal::new(50, 0),
                FineType::LateSubmission,
                valid_verdict_ref,
            )
            .unwrap();

        let summary = engine.summary();
        assert_eq!(summary.active_deposit_count, 1);
        assert_eq!(summary.active_deposit_amount, Decimal::new(100, 0));
        assert_eq!(summary.pending_fine_count, 1);
        assert_eq!(summary.pending_fine_amount, Decimal::new(50, 0));
    }

    #[test]
    fn test_invalid_deposit_amount() {
        let mut engine = create_test_clearing_engine();

        let result = engine.accept_deposit(
            ActorId::new("actor:1"),
            Decimal::ZERO,
            DepositType::Security,
            None,
        );

        assert!(result.is_err());
    }
}
