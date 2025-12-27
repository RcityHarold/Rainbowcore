//! Backfill and TipWitness types for L0
//!
//! Handles the upgrade path from B-level (local) to A-level (receipt-backed)
//! evidence, and provides anti-history-rewrite protection through TipWitness.

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use super::common::{Digest, EvidenceLevel};
use super::actor::{ActorId, ReceiptId};

/// TipWitness - anti-history-rewrite marker (mandatory, free)
///
/// Every actor MUST submit a TipWitness when going online. This creates
/// an immutable reference point that prevents later claims of different
/// history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TipWitness {
    pub tip_witness_id: String,
    pub actor_id: ActorId,
    /// Hash of actor's current local state tip
    pub local_tip_digest: Digest,
    /// Sequence number of local state
    pub local_sequence_no: u64,
    /// Last known receipt from L0
    pub last_known_receipt_ref: Option<String>,
    /// Timestamp of witness submission
    pub witnessed_at: DateTime<Utc>,
    /// L0 receipt for this witness (always issued, no fee)
    pub receipt_id: Option<ReceiptId>,
}

impl TipWitness {
    /// Create a new TipWitness
    pub fn new(actor_id: ActorId, local_tip: Digest, seq: u64) -> Self {
        Self {
            tip_witness_id: format!("tip:{}:{}", actor_id, seq),
            actor_id,
            local_tip_digest: local_tip,
            local_sequence_no: seq,
            last_known_receipt_ref: None,
            witnessed_at: Utc::now(),
            receipt_id: None,
        }
    }
}

/// Backfill continuity check result
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContinuityCheckResult {
    /// Full continuity verified
    Pass,
    /// Continuity verified with acceptable gaps
    PassWithGaps,
    /// Continuity check failed
    Fail,
}

/// Backfill status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackfillStatus {
    Requested,
    PlanGenerated,
    InProgress,
    Completed,
    Failed,
    Cancelled,
}

/// Gap record in backfill
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GapRecord {
    pub gap_id: String,
    pub start_sequence: u64,
    pub end_sequence: u64,
    pub gap_type: GapType,
    pub acceptable: bool,
    pub reason_digest: Option<Digest>,
}

/// Type of gap encountered
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapType {
    /// Missing sequence numbers
    SequenceGap,
    /// Time discontinuity
    TimeGap,
    /// Hash chain break
    HashChainBreak,
    /// Unknown gap type
    Unknown,
}

/// Backfill request - initiates upgrade from B to A level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackfillRequest {
    pub request_id: String,
    pub actor_id: ActorId,
    pub status: BackfillStatus,
    /// Starting point of backfill (local state)
    pub start_digest: Digest,
    pub start_sequence_no: u64,
    /// Target endpoint (current tip)
    pub end_digest: Digest,
    pub end_sequence_no: u64,
    /// TipWitness that anchors the backfill
    pub tip_witness_ref: String,
    /// Scope of objects to backfill
    pub scope_filter: Option<BackfillScope>,
    pub requested_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub receipt_id: Option<ReceiptId>,
}

/// Scope filter for backfill operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackfillScope {
    pub object_types: Vec<String>,
    pub space_ids: Vec<String>,
    pub time_range_start: Option<DateTime<Utc>>,
    pub time_range_end: Option<DateTime<Utc>>,
}

/// Backfill plan - generated after request analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackfillPlan {
    pub plan_id: String,
    pub request_ref: String,
    /// Ordered list of objects to anchor
    pub anchor_sequence: Vec<BackfillItem>,
    /// Estimated total fee
    pub estimated_fee: String,
    /// Detected gaps
    pub gaps: Vec<GapRecord>,
    /// Continuity check result
    pub continuity_result: ContinuityCheckResult,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub plan_digest: Digest,
}

impl BackfillPlan {
    /// Check if this plan is acceptable for execution
    pub fn is_executable(&self) -> bool {
        matches!(
            self.continuity_result,
            ContinuityCheckResult::Pass | ContinuityCheckResult::PassWithGaps
        )
    }

    /// Get count of acceptable gaps
    pub fn acceptable_gap_count(&self) -> usize {
        self.gaps.iter().filter(|g| g.acceptable).count()
    }

    /// Get count of unacceptable gaps
    pub fn unacceptable_gap_count(&self) -> usize {
        self.gaps.iter().filter(|g| !g.acceptable).count()
    }
}

/// Individual item in backfill sequence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackfillItem {
    pub sequence_no: u64,
    pub object_type: String,
    pub object_digest: Digest,
    pub parent_digest: Option<Digest>,
    pub current_level: EvidenceLevel,
    pub target_level: EvidenceLevel,
    pub anchored: bool,
    pub receipt_ref: Option<String>,
}

/// Backfill receipt - final result of backfill operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackfillReceipt {
    pub backfill_receipt_id: String,
    pub request_ref: String,
    pub plan_ref: String,
    pub actor_id: ActorId,
    /// Total objects anchored
    pub objects_anchored: u64,
    /// Digest of all anchored object IDs
    pub anchored_objects_digest: Digest,
    /// Gaps acknowledged by actor
    pub gaps_acknowledged_digest: Option<Digest>,
    /// Total fee paid
    pub total_fee_paid: String,
    pub continuity_result: ContinuityCheckResult,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    /// The L0 receipt covering this backfill
    pub receipt_id: ReceiptId,
}

impl BackfillReceipt {
    /// Check if backfill resulted in A-level evidence
    pub fn achieved_a_level(&self) -> bool {
        matches!(
            self.continuity_result,
            ContinuityCheckResult::Pass | ContinuityCheckResult::PassWithGaps
        )
    }
}

/// Degraded mode marker for L0 unavailability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegradedModeMarker {
    pub marker_id: String,
    pub actor_id: ActorId,
    pub reason: DegradedModeReason,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub local_operations_digest: Digest,
    pub backfill_request_ref: Option<String>,
}

/// Reason for entering degraded mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradedModeReason {
    L0Unreachable,
    NetworkPartition,
    HighLatency,
    MaintenanceWindow,
    EmergencyFallback,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_continuity_check_serialization() {
        let result = ContinuityCheckResult::PassWithGaps;
        let json = serde_json::to_string(&result).unwrap();
        assert_eq!(json, "\"PASS_WITH_GAPS\"");
    }

    #[test]
    fn test_backfill_plan_executable() {
        let plan = BackfillPlan {
            plan_id: "plan:001".to_string(),
            request_ref: "req:001".to_string(),
            anchor_sequence: vec![],
            estimated_fee: "100".to_string(),
            gaps: vec![
                GapRecord {
                    gap_id: "gap:1".to_string(),
                    start_sequence: 10,
                    end_sequence: 15,
                    gap_type: GapType::SequenceGap,
                    acceptable: true,
                    reason_digest: None,
                },
            ],
            continuity_result: ContinuityCheckResult::PassWithGaps,
            created_at: Utc::now(),
            expires_at: Utc::now(),
            plan_digest: Digest::zero(),
        };

        assert!(plan.is_executable());
        assert_eq!(plan.acceptable_gap_count(), 1);
        assert_eq!(plan.unacceptable_gap_count(), 0);
    }

    #[test]
    fn test_tip_witness_creation() {
        let actor = ActorId::new("actor:test");
        let tip = Digest::new([0x42; 32]);
        let witness = TipWitness::new(actor.clone(), tip, 100);

        assert_eq!(witness.local_sequence_no, 100);
        assert!(witness.tip_witness_id.contains("actor:test"));
    }
}
