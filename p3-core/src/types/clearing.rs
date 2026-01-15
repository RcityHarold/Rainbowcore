//! Clearing and Penalties
//!
//! Chapter 7: Clearing and Penalty Module
//!
//! Core invariants:
//! - Forfeit requires VerdictRef (core anti-black-box clause)
//! - Clawback requires target_epochs_digest (hard lock)
//! - Ancestor protection limits recovery from ancestor layers

use super::common::*;
use super::execution::ExecutionProofRef;
use l0_core::types::ActorId;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

/// Deposit object
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Deposit {
    pub deposit_id: String,
    pub payer_ref: String,
    pub reason_type: DepositReasonType,
    pub amount_digest: MoneyDigest,
    pub bound_epoch_id: EpochId,
    pub unlock_conditions_ref_digest: RefDigest,
    /// Forfeit requires VerdictRef (core anti-black-box clause)
    pub forfeit_requires_verdict: bool,
    pub verdict_ref_digest: Option<P3Digest>,
    pub status: DepositStatus,
    pub idempotency_key: IdempotencyKey,
    pub failure_reason_digest: Option<P3Digest>,
    pub supersedes_ref: Option<String>,
}

impl Deposit {
    /// Check if deposit can be forfeited
    pub fn can_forfeit(&self) -> bool {
        if self.forfeit_requires_verdict {
            self.verdict_ref_digest.is_some()
        } else {
            true
        }
    }

    /// Check if status transition is valid
    pub fn is_valid_transition(&self, new_status: &DepositStatus) -> bool {
        match (&self.status, new_status) {
            // From Created
            (DepositStatus::Created, DepositStatus::Locked) => true,
            (DepositStatus::Created, DepositStatus::Refund) => true,
            // From Locked
            (DepositStatus::Locked, DepositStatus::Refund) => true,
            (DepositStatus::Locked, DepositStatus::Forfeit) => true,
            (DepositStatus::Locked, DepositStatus::PendingExecution) => true,
            // From PendingExecution
            (DepositStatus::PendingExecution, DepositStatus::Forfeit) => true,
            (DepositStatus::PendingExecution, DepositStatus::Refund) => true,
            (DepositStatus::PendingExecution, DepositStatus::Resolved) => true,
            // From Forfeit/Refund to Resolved
            (DepositStatus::Forfeit, DepositStatus::Resolved) => true,
            (DepositStatus::Refund, DepositStatus::Resolved) => true,
            // Invalid transitions
            _ => false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepositReasonType {
    Dispute,
    Ticket,
    Backfill,
    ProviderBond,
}

/// Bond object (provider bond)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Bond {
    pub bond_id: String,
    pub provider_id: ProviderId,
    pub amount_digest: MoneyDigest,
    pub bound_epoch_id: EpochId,
    pub policy_ref: String,
    pub status: DepositStatus,
    pub forfeit_requires_verdict: bool,
    pub verdict_ref_digest: Option<P3Digest>,
    pub idempotency_key: IdempotencyKey,
}

/// Fine object
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Fine {
    pub fine_id: String,
    pub target_ref: String,
    pub amount_digest: MoneyDigest,
    pub bound_epoch_id: EpochId,
    pub verdict_ref_digest: P3Digest, // Required
    pub policy_ref: String,
    pub status: ExecutionStatus,
    pub idempotency_key: IdempotencyKey,
}

/// Clawback execution entry
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClawbackExecutionEntry {
    pub clawback_exec_id: String,
    pub bound_epoch_id: EpochId,
    pub verdict_ref_digest: P3Digest, // Required
    pub clawback_policy_ref: String,
    /// Target epochs digest (hard lock required)
    pub target_epochs_digest: RefDigest,
    /// Affected distribution IDs digest (entry level)
    pub affected_distribution_ids_digest: RefDigest,
    pub responsibility_shares_digest: Option<RefDigest>,
    pub violation_findings_digest: Option<P3Digest>,
    /// Lineage inputs
    pub lineage_inputs_digest: Option<RefDigest>,
    /// Original recovery plan
    pub recovery_plan_digest: P3Digest,
    /// Recovery plan after ancestor protection
    pub adjusted_recovery_plan_digest: P3Digest,
    /// Execution proof (required for strong clawback)
    pub execution_proof_ref: Option<ExecutionProofRef>,
    pub status: ClawbackStatus,
    pub idempotency_key: IdempotencyKey,
    pub failure_reason_digest: Option<P3Digest>,
    pub supersedes_ref: Option<String>,
}

impl ClawbackExecutionEntry {
    /// Check if clawback is ready for execution
    pub fn is_ready_for_execution(&self) -> bool {
        matches!(self.status, ClawbackStatus::Planned)
            && !self.target_epochs_digest.0.is_zero()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClawbackStatus {
    Planned,
    PendingEvidence,
    PendingExecution,
    PendingBudget,
    Executed,
    Resolved,
    Escalated,
}

/// Ancestor protection parameters
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AncestorProtectionParams {
    /// Ancestor layer recovery cap
    pub ancestor_recovery_cap: Decimal,
    /// Ancestor layer max recovery depth
    pub ancestor_max_depth: u32,
    /// Prioritize direct beneficiary layer
    pub direct_beneficiary_priority: bool,
}

impl Default for AncestorProtectionParams {
    fn default() -> Self {
        Self {
            ancestor_recovery_cap: Decimal::new(50, 2), // 50%
            ancestor_max_depth: 3,
            direct_beneficiary_priority: true,
        }
    }
}

/// Recovery plan
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryPlan {
    pub plan_id: String,
    pub clawback_exec_id: String,
    pub total_recovery_target: MoneyDigest,
    pub entries: Vec<RecoveryEntry>,
    pub plan_digest: P3Digest,
}

impl RecoveryPlan {
    /// Compute plan digest
    pub fn compute_digest(&self) -> P3Digest {
        let data = serde_json::to_vec(&self.entries).unwrap_or_default();
        P3Digest::blake3(&data)
    }
}

/// Recovery entry
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryEntry {
    pub entry_id: String,
    pub target_actor_id: ActorId,
    pub target_distribution_id: DistributionId,
    pub recovery_amount_digest: MoneyDigest,
    pub share_percentage: Decimal,
    pub depth: u32,
    pub status: RecoveryEntryStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryEntryStatus {
    Planned,
    Executed,
    Partial,
    Failed,
    Waived,
}

/// Settlement batch
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementBatch {
    pub batch_id: String,
    pub bound_epoch_id: EpochId,
    pub deposits: Vec<String>,
    pub bonds: Vec<String>,
    pub fines: Vec<String>,
    pub clawbacks: Vec<String>,
    pub batch_digest: P3Digest,
    pub status: SettlementBatchStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub settled_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementBatchStatus {
    Pending,
    Processing,
    Completed,
    PartiallyCompleted,
    Failed,
}

/// Clearing summary
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClearingSummary {
    pub epoch_id: EpochId,
    pub total_deposits_locked: u64,
    pub total_deposits_refunded: u64,
    pub total_deposits_forfeited: u64,
    pub total_fines_issued: u64,
    pub total_clawbacks_executed: u64,
    pub summary_digest: P3Digest,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deposit_can_forfeit() {
        let deposit_with_verdict = Deposit {
            deposit_id: "d1".to_string(),
            payer_ref: "payer1".to_string(),
            reason_type: DepositReasonType::Dispute,
            amount_digest: MoneyDigest::new(P3Digest::zero(), "USD"),
            bound_epoch_id: EpochId::new("epoch:test"),
            unlock_conditions_ref_digest: RefDigest::empty(),
            forfeit_requires_verdict: true,
            verdict_ref_digest: Some(P3Digest::zero()),
            status: DepositStatus::Locked,
            idempotency_key: IdempotencyKey::new("key1"),
            failure_reason_digest: None,
            supersedes_ref: None,
        };
        assert!(deposit_with_verdict.can_forfeit());

        let deposit_without_verdict = Deposit {
            deposit_id: "d2".to_string(),
            payer_ref: "payer2".to_string(),
            reason_type: DepositReasonType::Dispute,
            amount_digest: MoneyDigest::new(P3Digest::zero(), "USD"),
            bound_epoch_id: EpochId::new("epoch:test"),
            unlock_conditions_ref_digest: RefDigest::empty(),
            forfeit_requires_verdict: true,
            verdict_ref_digest: None,
            status: DepositStatus::Locked,
            idempotency_key: IdempotencyKey::new("key2"),
            failure_reason_digest: None,
            supersedes_ref: None,
        };
        assert!(!deposit_without_verdict.can_forfeit());
    }

    #[test]
    fn test_deposit_status_transitions() {
        let deposit = Deposit {
            deposit_id: "d1".to_string(),
            payer_ref: "payer1".to_string(),
            reason_type: DepositReasonType::Dispute,
            amount_digest: MoneyDigest::new(P3Digest::zero(), "USD"),
            bound_epoch_id: EpochId::new("epoch:test"),
            unlock_conditions_ref_digest: RefDigest::empty(),
            forfeit_requires_verdict: false,
            verdict_ref_digest: None,
            status: DepositStatus::Created,
            idempotency_key: IdempotencyKey::new("key1"),
            failure_reason_digest: None,
            supersedes_ref: None,
        };

        assert!(deposit.is_valid_transition(&DepositStatus::Locked));
        assert!(deposit.is_valid_transition(&DepositStatus::Refund));
        assert!(!deposit.is_valid_transition(&DepositStatus::Forfeit));
        assert!(!deposit.is_valid_transition(&DepositStatus::Resolved));
    }

    #[test]
    fn test_ancestor_protection_default() {
        let params = AncestorProtectionParams::default();
        assert_eq!(params.ancestor_recovery_cap, Decimal::new(50, 2));
        assert_eq!(params.ancestor_max_depth, 3);
        assert!(params.direct_beneficiary_priority);
    }
}
