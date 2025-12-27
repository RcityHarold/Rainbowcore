//! Dispute resolution types for L0
//!
//! Handles verdicts, repairs, and clawbacks in the dispute resolution ledger.

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use super::common::Digest;
use super::actor::{ActorId, ReceiptId};

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
    pub filed_by: ActorId,
    pub filed_against: Vec<ActorId>,
    pub priority: DisputePriority,
    pub status: DisputeStatus,
    pub subject_commitment_ref: String,
    pub evidence_digest: Digest,
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
    pub remedies_digest: Option<Digest>,
    pub issued_by: String,  // Adjudicator reference
    pub issued_at: DateTime<Utc>,
    pub effective_at: DateTime<Utc>,
    pub appeal_deadline: Option<DateTime<Utc>>,
    pub receipt_id: Option<ReceiptId>,
}

/// Repair checkpoint - tracks state during repair process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairCheckpoint {
    pub checkpoint_id: String,
    pub dispute_id: String,
    pub verdict_id: String,
    pub checkpoint_digest: Digest,
    pub affected_actors: Vec<ActorId>,
    pub repair_plan_digest: Digest,
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
    pub filed_by: ActorId,
    pub grounds_digest: Digest,
    pub new_evidence_digest: Option<Digest>,
    pub filed_at: DateTime<Utc>,
    pub status: DisputeStatus,
    pub receipt_id: Option<ReceiptId>,
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
