//! Clearing Engine
//!
//! Chapter 7: Clearing Engine
//!
//! Handles:
//! - Deposit holding and release
//! - Fine collection and escrow
//! - Clawback execution
//! - Settlement finalization

mod engine;
mod settlement;

pub use engine::*;
pub use settlement::*;

use crate::error::{P3Error, P3Result};
use crate::types::*;
use rust_decimal::Decimal;
use std::collections::HashMap;

/// Clearing context
#[derive(Clone, Debug)]
pub struct ClearingContext {
    /// Epoch ID
    pub epoch_id: EpochId,
    /// Settlement mode
    pub settlement_mode: SettlementMode,
    /// Clearing rules version
    pub rules_version: String,
}

impl ClearingContext {
    /// Create new context
    pub fn new(epoch_id: EpochId) -> Self {
        Self {
            epoch_id,
            settlement_mode: SettlementMode::Standard,
            rules_version: "v1".to_string(),
        }
    }

    /// Set settlement mode
    pub fn with_mode(mut self, mode: SettlementMode) -> Self {
        self.settlement_mode = mode;
        self
    }

    /// Set rules version
    pub fn with_rules_version(mut self, version: impl Into<String>) -> Self {
        self.rules_version = version.into();
        self
    }
}

/// Settlement mode
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettlementMode {
    /// Standard settlement
    Standard,
    /// Immediate settlement
    Immediate,
    /// Deferred settlement
    Deferred,
    /// Emergency settlement
    Emergency,
}

/// Deposit record
#[derive(Clone, Debug)]
pub struct DepositRecord {
    /// Deposit ID
    pub deposit_id: String,
    /// Actor ID
    pub actor_id: ActorId,
    /// Deposit amount
    pub amount: Decimal,
    /// Deposit type
    pub deposit_type: DepositType,
    /// Status
    pub status: DepositStatus,
    /// Created epoch
    pub created_epoch: EpochId,
    /// Release epoch (if applicable)
    pub release_epoch: Option<EpochId>,
    /// Linked action ref
    pub action_ref: Option<P3Digest>,
    /// Whether forfeit requires a verdict reference (core anti-black-box clause)
    pub forfeit_requires_verdict: bool,
    /// Verdict reference for forfeit authorization (required if forfeit_requires_verdict is true)
    pub verdict_ref: Option<P3Digest>,
}

impl DepositRecord {
    /// Create new deposit
    pub fn new(
        deposit_id: impl Into<String>,
        actor_id: ActorId,
        amount: Decimal,
        deposit_type: DepositType,
        epoch_id: EpochId,
    ) -> Self {
        // By default, most deposit types require verdict for forfeit (anti-black-box)
        let forfeit_requires_verdict = matches!(
            deposit_type,
            DepositType::Challenge | DepositType::Appeal | DepositType::Security
        );

        Self {
            deposit_id: deposit_id.into(),
            actor_id,
            amount,
            deposit_type,
            status: DepositStatus::Held,
            created_epoch: epoch_id,
            release_epoch: None,
            action_ref: None,
            forfeit_requires_verdict,
            verdict_ref: None,
        }
    }

    /// Set action reference
    pub fn with_action_ref(mut self, action_ref: P3Digest) -> Self {
        self.action_ref = Some(action_ref);
        self
    }

    /// Set verdict reference (required for forfeit if forfeit_requires_verdict is true)
    pub fn with_verdict_ref(mut self, verdict_ref: P3Digest) -> Self {
        self.verdict_ref = Some(verdict_ref);
        self
    }

    /// Override the forfeit_requires_verdict flag
    pub fn with_forfeit_requires_verdict(mut self, requires: bool) -> Self {
        self.forfeit_requires_verdict = requires;
        self
    }

    /// Check if deposit can be forfeited
    /// Core anti-black-box clause: forfeit requires valid VerdictRef if forfeit_requires_verdict is true
    pub fn can_forfeit(&self) -> bool {
        if !self.forfeit_requires_verdict {
            return true;
        }
        // VerdictRef must exist and not be zero (zero is invalid)
        match &self.verdict_ref {
            Some(ref digest) => !digest.is_zero(),
            None => false,
        }
    }

    /// Release deposit
    pub fn release(&mut self, epoch_id: EpochId) -> P3Result<()> {
        if self.status != DepositStatus::Held {
            return Err(P3Error::InvalidState {
                reason: format!("Cannot release deposit in {:?} status", self.status),
            });
        }
        self.status = DepositStatus::Released;
        self.release_epoch = Some(epoch_id);
        Ok(())
    }

    /// Forfeit deposit
    /// Note: Caller should check can_forfeit() before calling this method
    pub fn forfeit(&mut self, epoch_id: EpochId) -> P3Result<()> {
        if self.status != DepositStatus::Held {
            return Err(P3Error::InvalidState {
                reason: format!("Cannot forfeit deposit in {:?} status", self.status),
            });
        }
        self.status = DepositStatus::Forfeited;
        self.release_epoch = Some(epoch_id);
        Ok(())
    }

    /// Check if deposit is active
    pub fn is_active(&self) -> bool {
        self.status == DepositStatus::Held
    }
}

/// Deposit type
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DepositType {
    /// Security deposit (requires verdict for forfeit)
    Security,
    /// Performance deposit (does NOT require verdict for forfeit - automatic release on failure)
    Performance,
    /// Challenge deposit (requires verdict for forfeit)
    Challenge,
    /// Appeal deposit (requires verdict for forfeit)
    Appeal,
}

/// Deposit status
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DepositStatus {
    /// Currently held
    Held,
    /// Released to depositor
    Released,
    /// Forfeited
    Forfeited,
    /// Partially released
    PartiallyReleased,
}

/// Fine record
#[derive(Clone, Debug)]
pub struct FineRecord {
    /// Fine ID
    pub fine_id: String,
    /// Actor ID
    pub actor_id: ActorId,
    /// Fine amount
    pub amount: Decimal,
    /// Fine type
    pub fine_type: FineType,
    /// Status
    pub status: FineStatus,
    /// Verdict reference
    pub verdict_ref: P3Digest,
    /// Created epoch
    pub created_epoch: EpochId,
    /// Collection epoch (if collected)
    pub collection_epoch: Option<EpochId>,
}

impl FineRecord {
    /// Create new fine
    pub fn new(
        fine_id: impl Into<String>,
        actor_id: ActorId,
        amount: Decimal,
        fine_type: FineType,
        verdict_ref: P3Digest,
        epoch_id: EpochId,
    ) -> Self {
        Self {
            fine_id: fine_id.into(),
            actor_id,
            amount,
            fine_type,
            status: FineStatus::Pending,
            verdict_ref,
            created_epoch: epoch_id,
            collection_epoch: None,
        }
    }

    /// Mark as collected
    pub fn collect(&mut self, epoch_id: EpochId) -> P3Result<()> {
        if self.status != FineStatus::Pending {
            return Err(P3Error::InvalidState {
                reason: format!("Cannot collect fine in {:?} status", self.status),
            });
        }
        self.status = FineStatus::Collected;
        self.collection_epoch = Some(epoch_id);
        Ok(())
    }

    /// Mark as waived
    pub fn waive(&mut self, epoch_id: EpochId) -> P3Result<()> {
        if self.status != FineStatus::Pending {
            return Err(P3Error::InvalidState {
                reason: format!("Cannot waive fine in {:?} status", self.status),
            });
        }
        self.status = FineStatus::Waived;
        self.collection_epoch = Some(epoch_id);
        Ok(())
    }
}

/// Fine type
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FineType {
    /// Protocol violation
    ProtocolViolation,
    /// Late submission
    LateSubmission,
    /// Failed verification
    FailedVerification,
    /// Misconduct
    Misconduct,
}

/// Fine status
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FineStatus {
    /// Pending collection
    Pending,
    /// Collected
    Collected,
    /// Waived
    Waived,
    /// Appealed
    Appealed,
}

/// Clawback record
#[derive(Clone, Debug)]
pub struct ClawbackRecord {
    /// Clawback ID
    pub clawback_id: String,
    /// Actor ID
    pub actor_id: ActorId,
    /// Original distribution ref
    pub distribution_ref: P3Digest,
    /// Clawback amount
    pub amount: Decimal,
    /// Reason
    pub reason: ClawbackReason,
    /// Status
    pub status: ClawbackRecordStatus,
    /// Created epoch
    pub created_epoch: EpochId,
    /// Execution epoch (if executed)
    pub execution_epoch: Option<EpochId>,
}

impl ClawbackRecord {
    /// Create new clawback
    pub fn new(
        clawback_id: impl Into<String>,
        actor_id: ActorId,
        distribution_ref: P3Digest,
        amount: Decimal,
        reason: ClawbackReason,
        epoch_id: EpochId,
    ) -> Self {
        Self {
            clawback_id: clawback_id.into(),
            actor_id,
            distribution_ref,
            amount,
            reason,
            status: ClawbackRecordStatus::Pending,
            created_epoch: epoch_id,
            execution_epoch: None,
        }
    }

    /// Execute clawback
    pub fn execute(&mut self, epoch_id: EpochId) -> P3Result<()> {
        if self.status != ClawbackRecordStatus::Pending {
            return Err(P3Error::InvalidState {
                reason: format!("Cannot execute clawback in {:?} status", self.status),
            });
        }
        self.status = ClawbackRecordStatus::Executed;
        self.execution_epoch = Some(epoch_id);
        Ok(())
    }

    /// Cancel clawback
    pub fn cancel(&mut self) -> P3Result<()> {
        if self.status != ClawbackRecordStatus::Pending {
            return Err(P3Error::InvalidState {
                reason: format!("Cannot cancel clawback in {:?} status", self.status),
            });
        }
        self.status = ClawbackRecordStatus::Cancelled;
        Ok(())
    }
}

/// Clawback reason
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClawbackReason {
    /// Fraud detection
    Fraud,
    /// Attribution error
    AttributionError,
    /// Duplicate distribution
    Duplicate,
    /// Court order
    CourtOrder,
}

/// Clawback status
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClawbackRecordStatus {
    /// Pending execution
    Pending,
    /// Executed
    Executed,
    /// Cancelled
    Cancelled,
    /// Partial recovery
    PartialRecovery,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clearing_context() {
        let ctx = ClearingContext::new(EpochId::new("epoch:1"))
            .with_mode(SettlementMode::Immediate)
            .with_rules_version("v2");

        assert_eq!(ctx.settlement_mode, SettlementMode::Immediate);
        assert_eq!(ctx.rules_version, "v2");
    }

    #[test]
    fn test_deposit_lifecycle() {
        let epoch = EpochId::new("epoch:1");
        let mut deposit = DepositRecord::new(
            "dep:1",
            ActorId::new("actor:1"),
            Decimal::new(100, 0),
            DepositType::Security,
            epoch.clone(),
        );

        assert!(deposit.is_active());
        assert_eq!(deposit.status, DepositStatus::Held);

        deposit.release(EpochId::new("epoch:5")).unwrap();
        assert!(!deposit.is_active());
        assert_eq!(deposit.status, DepositStatus::Released);
    }

    #[test]
    fn test_deposit_forfeit() {
        let epoch = EpochId::new("epoch:1");
        let mut deposit = DepositRecord::new(
            "dep:1",
            ActorId::new("actor:1"),
            Decimal::new(100, 0),
            DepositType::Challenge,
            epoch,
        );

        deposit.forfeit(EpochId::new("epoch:3")).unwrap();
        assert_eq!(deposit.status, DepositStatus::Forfeited);
    }

    #[test]
    fn test_fine_lifecycle() {
        let epoch = EpochId::new("epoch:1");
        // Use valid verdict_ref (not zero) - anti-black-box requirement
        let valid_verdict_ref = P3Digest::blake3(b"verdict:protocol:001");
        let mut fine = FineRecord::new(
            "fine:1",
            ActorId::new("actor:1"),
            Decimal::new(50, 0),
            FineType::ProtocolViolation,
            valid_verdict_ref,
            epoch,
        );

        assert_eq!(fine.status, FineStatus::Pending);

        fine.collect(EpochId::new("epoch:2")).unwrap();
        assert_eq!(fine.status, FineStatus::Collected);
    }

    #[test]
    fn test_clawback_lifecycle() {
        let epoch = EpochId::new("epoch:1");
        let mut clawback = ClawbackRecord::new(
            "claw:1",
            ActorId::new("actor:1"),
            P3Digest::zero(),
            Decimal::new(200, 0),
            ClawbackReason::Fraud,
            epoch,
        );

        assert_eq!(clawback.status, ClawbackRecordStatus::Pending);

        clawback.execute(EpochId::new("epoch:3")).unwrap();
        assert_eq!(clawback.status, ClawbackRecordStatus::Executed);
    }

    #[test]
    fn test_cannot_release_twice() {
        let epoch = EpochId::new("epoch:1");
        let mut deposit = DepositRecord::new(
            "dep:1",
            ActorId::new("actor:1"),
            Decimal::new(100, 0),
            DepositType::Security,
            epoch,
        );

        deposit.release(EpochId::new("epoch:2")).unwrap();
        let result = deposit.release(EpochId::new("epoch:3"));
        assert!(result.is_err());
    }

    #[test]
    fn test_can_forfeit_with_verdict() {
        let epoch = EpochId::new("epoch:1");
        let valid_verdict_ref = P3Digest::blake3(b"verdict:001");

        let deposit = DepositRecord::new(
            "dep:1",
            ActorId::new("actor:1"),
            Decimal::new(100, 0),
            DepositType::Challenge, // Requires verdict
            epoch,
        )
        .with_verdict_ref(valid_verdict_ref);

        assert!(deposit.can_forfeit());
    }

    #[test]
    fn test_cannot_forfeit_without_verdict() {
        let epoch = EpochId::new("epoch:1");
        let deposit = DepositRecord::new(
            "dep:1",
            ActorId::new("actor:1"),
            Decimal::new(100, 0),
            DepositType::Challenge, // Requires verdict
            epoch,
        );

        // No verdict_ref set, should not be able to forfeit
        assert!(!deposit.can_forfeit());
    }

    #[test]
    fn test_cannot_forfeit_with_zero_verdict() {
        let epoch = EpochId::new("epoch:1");
        let deposit = DepositRecord::new(
            "dep:1",
            ActorId::new("actor:1"),
            Decimal::new(100, 0),
            DepositType::Security, // Requires verdict
            epoch,
        )
        .with_verdict_ref(P3Digest::zero()); // Zero verdict should not be valid

        // Zero verdict_ref is invalid, should not be able to forfeit
        assert!(!deposit.can_forfeit());
    }

    #[test]
    fn test_performance_deposit_no_verdict_required() {
        let epoch = EpochId::new("epoch:1");
        let deposit = DepositRecord::new(
            "dep:1",
            ActorId::new("actor:1"),
            Decimal::new(100, 0),
            DepositType::Performance, // Performance does not require verdict
            epoch,
        );

        // Performance deposits don't require verdict
        assert!(deposit.can_forfeit());
    }
}
