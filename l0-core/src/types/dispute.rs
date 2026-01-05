//! Dispute resolution types for L0
//!
//! Handles verdicts, repairs, and clawbacks in the dispute resolution ledger.

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use super::common::Digest;
use super::actor::{ActorId, ReceiptId};

/// Dispute type - categorizes the nature of the dispute
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeType {
    /// Unauthorized access or action
    Unauthorized,
    /// Bypassing required processes
    BypassProcess,
    /// Harm or damage caused
    Harm,
    /// Clause/covenant conflict
    ClauseConflict,
    /// Evidence tampering
    EvidenceTampering,
    /// High-risk action without consent
    HighRiskNoConsent,
    /// Lineage/provenance risk
    LineageRisk,
    /// Backfill fraud attempt
    BackfillFraud,
    /// History rewrite suspected
    HistoryRewriteSuspected,
    /// Protocol violation
    ProtocolViolation,
    /// Other dispute type
    Other,
}

impl Default for DisputeType {
    fn default() -> Self {
        Self::Other
    }
}

/// Dispute status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeStatus {
    Filed,
    UnderReview,
    VerdictIssued,
    RepairInProgress,
    Resolved,
    Dismissed,
}

/// Appeal status - independent from DisputeStatus
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppealStatus {
    /// Appeal has been filed
    Pending,
    /// Appeal is being reviewed
    UnderReview,
    /// Appeal was accepted, verdict will be revised
    Accepted,
    /// Appeal was rejected, original verdict stands
    Rejected,
    /// Appeal was dismissed (procedural issues)
    Dismissed,
    /// Appeal has expired
    Expired,
}

impl Default for AppealStatus {
    fn default() -> Self {
        Self::Pending
    }
}

/// Repair checkpoint type - tracks repair process stages
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairCheckpointType {
    /// Repair process has started
    InRepairStart,
    /// Repair process has ended
    InRepairEnd,
    /// Repair plan has been accepted
    RepairPlanAccepted,
    /// Repair plan has been executed
    RepairPlanExecuted,
    /// Repair completed successfully
    RepairCompleted,
    /// Repair failed
    RepairFailed,
}

impl Default for RepairCheckpointType {
    fn default() -> Self {
        Self::InRepairStart
    }
}

/// Dispute priority level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputePriority {
    Normal,
    Urgent,
    Critical,
}

impl Default for DisputePriority {
    fn default() -> Self {
        Self::Normal
    }
}

/// Dispute record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeRecord {
    pub dispute_id: String,
    /// Type of dispute (matches document's dispute_type field)
    pub dispute_type: DisputeType,
    /// Actor who filed the dispute (initiator_actor_id in docs)
    pub filed_by: ActorId,
    /// Actors being disputed against (respondent_actor_ids in docs)
    pub filed_against: Vec<ActorId>,
    pub priority: DisputePriority,
    pub status: DisputeStatus,
    pub subject_commitment_ref: String,
    pub evidence_digest: Digest,
    /// Reason for filing the dispute
    pub reason_digest: Option<Digest>,
    pub filed_at: DateTime<Utc>,
    pub last_updated: DateTime<Utc>,
    pub receipt_id: Option<ReceiptId>,
}

/// Verdict type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictType {
    InFavor,
    Against,
    Mixed,
    Dismissed,
    Inconclusive,
}

/// Verdict record - the outcome of dispute adjudication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictRecord {
    pub verdict_id: String,
    pub dispute_id: String,
    pub verdict_type: VerdictType,
    pub verdict_digest: Digest,
    pub rationale_digest: Digest,
    /// Responsibility shares across dimensions (knowledge/policy/self/governance/human/platform/training/l0/lineage)
    pub responsibility_shares_digest: Option<Digest>,
    /// Violation findings (missing consent, bypassed process, violated HCC/CCC, etc.)
    pub violation_findings_digest: Option<Digest>,
    /// Sanctions (demotion, freeze, ban, deposit forfeiture, etc.)
    pub sanctions_digest: Option<Digest>,
    pub remedies_digest: Option<Digest>,
    /// Adjudicator reference (arbitrator_actor_id in docs)
    pub issued_by: String,
    pub issued_at: DateTime<Utc>,
    pub effective_at: DateTime<Utc>,
    pub appeal_deadline: Option<DateTime<Utc>>,
    pub receipt_id: Option<ReceiptId>,
}

/// Repair checkpoint - tracks state during repair process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairCheckpoint {
    pub checkpoint_id: String,
    /// Type of checkpoint (InRepairStart, InRepairEnd, RepairPlanAccepted, etc.)
    pub checkpoint_type: RepairCheckpointType,
    pub dispute_id: String,
    pub verdict_id: String,
    pub checkpoint_digest: Digest,
    pub affected_actors: Vec<ActorId>,
    pub repair_plan_digest: Digest,
    /// Expected outcome of the repair
    pub expected_outcome_digest: Option<Digest>,
    /// Current status of the repair (optional for backwards compatibility)
    pub current_status_digest: Option<Digest>,
    pub progress_percent: u8,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub receipt_id: Option<ReceiptId>,
}

impl RepairCheckpoint {
    /// Check if repair is complete
    pub fn is_complete(&self) -> bool {
        self.progress_percent >= 100 && self.completed_at.is_some()
    }
}

/// Clawback type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClawbackType {
    FullReverse,
    PartialReverse,
    Compensation,
    Penalty,
}

/// Clawback status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClawbackStatus {
    Pending,
    Approved,
    Executed,
    Failed,
    Cancelled,
}

/// Clawback record - undoes or compensates for problematic transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClawbackRecord {
    pub clawback_id: String,
    pub verdict_id: String,
    pub clawback_type: ClawbackType,
    pub status: ClawbackStatus,
    pub clawback_digest: Digest,
    pub target_commitment_refs: Vec<String>,
    pub affected_actors: Vec<ActorId>,
    pub compensation_digest: Option<Digest>,
    pub initiated_at: DateTime<Utc>,
    pub executed_at: Option<DateTime<Utc>>,
    pub receipt_id: Option<ReceiptId>,
}

impl ClawbackRecord {
    /// Check if this clawback requires A-level evidence
    pub fn requires_strong_evidence(&self) -> bool {
        matches!(
            self.clawback_type,
            ClawbackType::FullReverse | ClawbackType::Penalty
        )
    }
}

/// Appeal record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppealRecord {
    pub appeal_id: String,
    pub verdict_id: String,
    /// Actor who filed the appeal (appellant_actor_id in docs)
    pub filed_by: ActorId,
    /// Grounds for the appeal
    pub grounds_digest: Digest,
    /// New evidence submitted with appeal
    pub new_evidence_digest: Option<Digest>,
    pub filed_at: DateTime<Utc>,
    /// Appeal-specific status (not DisputeStatus)
    pub status: AppealStatus,
    /// Outcome of the appeal (uphold/revise/reverse)
    pub appeal_outcome: Option<AppealOutcome>,
    /// Appellate decision digest
    pub appellate_decision_digest: Option<Digest>,
    pub receipt_id: Option<ReceiptId>,
}

/// Appeal outcome - result of the appeal process
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppealOutcome {
    /// Original verdict upheld
    Uphold,
    /// Original verdict revised
    Revise,
    /// Original verdict reversed
    Reverse,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dispute_status_serialization() {
        let status = DisputeStatus::VerdictIssued;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"verdict_issued\"");
    }

    #[test]
    fn test_clawback_evidence_requirement() {
        let clawback = ClawbackRecord {
            clawback_id: "clb:001".to_string(),
            verdict_id: "vrd:001".to_string(),
            clawback_type: ClawbackType::FullReverse,
            status: ClawbackStatus::Pending,
            clawback_digest: Digest::zero(),
            target_commitment_refs: vec![],
            affected_actors: vec![],
            compensation_digest: None,
            initiated_at: Utc::now(),
            executed_at: None,
            receipt_id: None,
        };
        assert!(clawback.requires_strong_evidence());

        let partial = ClawbackRecord {
            clawback_type: ClawbackType::PartialReverse,
            ..clawback
        };
        assert!(!partial.requires_strong_evidence());
    }
}
