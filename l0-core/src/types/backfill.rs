//! Backfill and TipWitness types for L0
//!
//! Handles the upgrade path from B-level (local) to A-level (receipt-backed)
//! evidence, and provides anti-history-rewrite protection through TipWitness.
//!
//! # Backfill Types (per DSN Doc Chapter 8)
//!
//! - **P1 Backfill**: Initiated from P1 (ledger) side, commit-then-upload
//! - **P2 Backfill**: Initiated from P2 (storage) side, upload-then-commit
//! - **Joint Backfill**: Coordinated between P1 and P2

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Duration, Utc};
use super::common::{Digest, EvidenceLevel};
use super::actor::{ActorId, ReceiptId};

/// Backfill initiator type (per DSN Doc Chapter 8)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackfillType {
    /// P1-initiated backfill (Commit-Then-Upload)
    /// Ledger commits first, then storage uploads
    P1Initiated,
    /// P2-initiated backfill (Upload-Then-Commit)
    /// Storage uploads first, then ledger commits
    P2Initiated,
    /// Joint backfill (coordinated)
    /// Both sides coordinate simultaneously
    Joint,
}

impl BackfillType {
    /// Get the workflow order for this backfill type
    pub fn workflow_order(&self) -> BackfillWorkflowOrder {
        match self {
            BackfillType::P1Initiated => BackfillWorkflowOrder::CommitThenUpload,
            BackfillType::P2Initiated => BackfillWorkflowOrder::UploadThenCommit,
            BackfillType::Joint => BackfillWorkflowOrder::Coordinated,
        }
    }
}

/// Backfill workflow order
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackfillWorkflowOrder {
    /// Commit to P1 ledger first, then upload to P2 storage
    CommitThenUpload,
    /// Upload to P2 storage first, then commit to P1 ledger
    UploadThenCommit,
    /// Coordinated workflow with checkpoints
    Coordinated,
}

/// Default clock skew tolerance for distributed systems (30 seconds)
const DEFAULT_CLOCK_SKEW_TOLERANCE_SECS: i64 = 30;

/// Time window for backfill operations
///
/// Includes clock skew tolerance for distributed systems where
/// nodes may have slightly different system clocks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackfillTimeWindow {
    /// Window ID
    pub window_id: String,
    /// Window start time
    pub start_time: DateTime<Utc>,
    /// Window end time
    pub end_time: DateTime<Utc>,
    /// Original window reference (if this is a retry)
    pub original_window_ref: Option<String>,
    /// Maximum allowed duration
    pub max_duration: Duration,
    /// Extension count (how many times extended)
    pub extension_count: u32,
    /// Maximum extensions allowed
    pub max_extensions: u32,
    /// Clock skew tolerance (for distributed systems)
    #[serde(default = "default_clock_skew_tolerance")]
    pub clock_skew_tolerance: Duration,
}

fn default_clock_skew_tolerance() -> Duration {
    Duration::seconds(DEFAULT_CLOCK_SKEW_TOLERANCE_SECS)
}

impl BackfillTimeWindow {
    /// Create a new time window
    pub fn new(duration: Duration) -> Self {
        let now = Utc::now();
        Self {
            window_id: format!("window:{}", uuid::Uuid::new_v4()),
            start_time: now,
            end_time: now + duration,
            original_window_ref: None,
            max_duration: duration,
            extension_count: 0,
            max_extensions: 3,
            clock_skew_tolerance: default_clock_skew_tolerance(),
        }
    }

    /// Create a new time window with custom clock skew tolerance
    pub fn with_clock_skew_tolerance(duration: Duration, tolerance: Duration) -> Self {
        let now = Utc::now();
        Self {
            window_id: format!("window:{}", uuid::Uuid::new_v4()),
            start_time: now,
            end_time: now + duration,
            original_window_ref: None,
            max_duration: duration,
            extension_count: 0,
            max_extensions: 3,
            clock_skew_tolerance: tolerance,
        }
    }

    /// Check if window is still valid (with clock skew tolerance)
    ///
    /// Adds tolerance to account for clock differences between nodes
    pub fn is_valid(&self) -> bool {
        Utc::now() < self.end_time + self.clock_skew_tolerance
    }

    /// Check if window is valid at a specific timestamp
    ///
    /// Useful for validating timestamps from other nodes
    pub fn is_valid_at(&self, timestamp: DateTime<Utc>) -> bool {
        let start_with_tolerance = self.start_time - self.clock_skew_tolerance;
        let end_with_tolerance = self.end_time + self.clock_skew_tolerance;
        timestamp >= start_with_tolerance && timestamp < end_with_tolerance
    }

    /// Check if window is strictly valid (no tolerance)
    pub fn is_strictly_valid(&self) -> bool {
        Utc::now() < self.end_time
    }

    /// Check if window can be extended
    pub fn can_extend(&self) -> bool {
        self.extension_count < self.max_extensions
    }

    /// Extend the window
    pub fn extend(&mut self, additional: Duration) -> bool {
        if !self.can_extend() {
            return false;
        }
        self.end_time = self.end_time + additional;
        self.extension_count += 1;
        true
    }

    /// Get remaining time (with clock skew tolerance)
    pub fn remaining(&self) -> Duration {
        let now = Utc::now();
        let effective_end = self.end_time + self.clock_skew_tolerance;
        if now >= effective_end {
            Duration::zero()
        } else {
            effective_end - now
        }
    }

    /// Get remaining time without tolerance (strict)
    pub fn remaining_strict(&self) -> Duration {
        let now = Utc::now();
        if now >= self.end_time {
            Duration::zero()
        } else {
            self.end_time - now
        }
    }

    /// Set clock skew tolerance
    pub fn set_clock_skew_tolerance(&mut self, tolerance: Duration) {
        self.clock_skew_tolerance = tolerance;
    }
}

/// Backfill coordination state (for Joint backfill)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackfillCoordinationState {
    /// Coordination ID
    pub coordination_id: String,
    /// P1 side ready
    pub p1_ready: bool,
    /// P2 side ready
    pub p2_ready: bool,
    /// P1 checkpoint digest
    pub p1_checkpoint: Option<Digest>,
    /// P2 checkpoint digest
    pub p2_checkpoint: Option<Digest>,
    /// Coordination phase
    pub phase: CoordinationPhase,
    /// Last sync timestamp
    pub last_sync_at: DateTime<Utc>,
}

/// Coordination phase for joint backfill
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinationPhase {
    /// Initial handshake
    Handshake,
    /// Preparing data
    Preparing,
    /// Syncing checkpoints
    Syncing,
    /// Committing
    Committing,
    /// Verifying
    Verifying,
    /// Completed
    Completed,
    /// Failed
    Failed,
}

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
    /// Backfill type (P1-initiated, P2-initiated, or Joint)
    pub backfill_type: BackfillType,
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
    /// Time window for this backfill operation
    pub time_window: Option<BackfillTimeWindow>,
    /// Coordination state (for Joint backfill)
    pub coordination_state: Option<BackfillCoordinationState>,
    /// Original window reference (if this is a retry/continuation)
    pub original_window_ref: Option<String>,
    pub requested_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub receipt_id: Option<ReceiptId>,
}

impl BackfillRequest {
    /// Create a new P1-initiated backfill request
    pub fn new_p1_initiated(
        actor_id: ActorId,
        start_digest: Digest,
        start_seq: u64,
        end_digest: Digest,
        end_seq: u64,
        tip_witness_ref: String,
    ) -> Self {
        Self {
            request_id: format!("backfill:p1:{}", uuid::Uuid::new_v4()),
            actor_id,
            status: BackfillStatus::Requested,
            backfill_type: BackfillType::P1Initiated,
            start_digest,
            start_sequence_no: start_seq,
            end_digest,
            end_sequence_no: end_seq,
            tip_witness_ref,
            scope_filter: None,
            time_window: Some(BackfillTimeWindow::new(Duration::hours(24))),
            coordination_state: None,
            original_window_ref: None,
            requested_at: Utc::now(),
            completed_at: None,
            receipt_id: None,
        }
    }

    /// Create a new P2-initiated backfill request
    pub fn new_p2_initiated(
        actor_id: ActorId,
        start_digest: Digest,
        start_seq: u64,
        end_digest: Digest,
        end_seq: u64,
        tip_witness_ref: String,
    ) -> Self {
        Self {
            request_id: format!("backfill:p2:{}", uuid::Uuid::new_v4()),
            actor_id,
            status: BackfillStatus::Requested,
            backfill_type: BackfillType::P2Initiated,
            start_digest,
            start_sequence_no: start_seq,
            end_digest,
            end_sequence_no: end_seq,
            tip_witness_ref,
            scope_filter: None,
            time_window: Some(BackfillTimeWindow::new(Duration::hours(24))),
            coordination_state: None,
            original_window_ref: None,
            requested_at: Utc::now(),
            completed_at: None,
            receipt_id: None,
        }
    }

    /// Create a new Joint backfill request
    pub fn new_joint(
        actor_id: ActorId,
        start_digest: Digest,
        start_seq: u64,
        end_digest: Digest,
        end_seq: u64,
        tip_witness_ref: String,
    ) -> Self {
        Self {
            request_id: format!("backfill:joint:{}", uuid::Uuid::new_v4()),
            actor_id,
            status: BackfillStatus::Requested,
            backfill_type: BackfillType::Joint,
            start_digest,
            start_sequence_no: start_seq,
            end_digest,
            end_sequence_no: end_seq,
            tip_witness_ref,
            scope_filter: None,
            time_window: Some(BackfillTimeWindow::new(Duration::hours(48))),
            coordination_state: Some(BackfillCoordinationState {
                coordination_id: format!("coord:{}", uuid::Uuid::new_v4()),
                p1_ready: false,
                p2_ready: false,
                p1_checkpoint: None,
                p2_checkpoint: None,
                phase: CoordinationPhase::Handshake,
                last_sync_at: Utc::now(),
            }),
            original_window_ref: None,
            requested_at: Utc::now(),
            completed_at: None,
            receipt_id: None,
        }
    }

    /// Check if this is a retry of a previous backfill
    pub fn is_retry(&self) -> bool {
        self.original_window_ref.is_some()
    }

    /// Get workflow order for this request
    pub fn workflow_order(&self) -> BackfillWorkflowOrder {
        self.backfill_type.workflow_order()
    }

    /// Check if time window is still valid
    pub fn is_window_valid(&self) -> bool {
        self.time_window.as_ref().map(|w| w.is_valid()).unwrap_or(true)
    }
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

// ============================================================================
// TipWitness Mandatory Enforcement (ISSUE-015)
// ============================================================================

/// TipWitness enforcement configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TipWitnessEnforcementConfig {
    /// Whether TipWitness is mandatory on actor online
    pub mandatory_on_online: bool,
    /// Maximum staleness allowed before requiring new TipWitness
    pub max_staleness: Duration,
    /// Whether to block operations without valid TipWitness
    pub block_operations_without_witness: bool,
    /// Grace period for first-time actors (no previous TipWitness)
    pub first_time_grace_period: Duration,
    /// Operations exempt from TipWitness requirement
    pub exempt_operations: Vec<String>,
}

impl Default for TipWitnessEnforcementConfig {
    fn default() -> Self {
        Self {
            mandatory_on_online: true,
            max_staleness: Duration::hours(24),
            block_operations_without_witness: true,
            first_time_grace_period: Duration::minutes(5),
            exempt_operations: vec![
                "tip_witness_submit".to_string(),
                "actor_registration".to_string(),
            ],
        }
    }
}

/// TipWitness enforcement result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TipWitnessEnforcementResult {
    /// Whether the enforcement check passed
    pub passed: bool,
    /// Reason for failure (if any)
    pub failure_reason: Option<TipWitnessFailureReason>,
    /// Required action (if any)
    pub required_action: Option<TipWitnessRequiredAction>,
    /// Last valid TipWitness (if any)
    pub last_valid_witness: Option<TipWitness>,
    /// Time until TipWitness expires
    pub expires_in: Option<Duration>,
}

impl TipWitnessEnforcementResult {
    /// Create a passing result
    pub fn pass(last_witness: TipWitness, expires_in: Duration) -> Self {
        Self {
            passed: true,
            failure_reason: None,
            required_action: None,
            last_valid_witness: Some(last_witness),
            expires_in: Some(expires_in),
        }
    }

    /// Create a failing result
    pub fn fail(reason: TipWitnessFailureReason, action: TipWitnessRequiredAction) -> Self {
        Self {
            passed: false,
            failure_reason: Some(reason),
            required_action: Some(action),
            last_valid_witness: None,
            expires_in: None,
        }
    }
}

/// Reason why TipWitness enforcement failed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TipWitnessFailureReason {
    /// No TipWitness ever submitted
    NoWitnessFound,
    /// TipWitness is too old (stale)
    WitnessStale,
    /// TipWitness sequence mismatch
    SequenceMismatch,
    /// TipWitness digest mismatch (history rewrite detected)
    DigestMismatch,
    /// Actor is not registered
    ActorNotRegistered,
    /// TipWitness verification failed
    VerificationFailed,
}

/// Required action when TipWitness enforcement fails
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TipWitnessRequiredAction {
    /// Must submit a new TipWitness
    SubmitNewWitness,
    /// Must complete actor registration first
    RegisterActor,
    /// Operation blocked, contact support
    ContactSupport,
    /// Must resolve history rewrite alert
    ResolveHistoryRewrite,
    /// Must wait for grace period
    WaitForGracePeriod,
}

impl TipWitness {
    /// Check if TipWitness is stale based on configuration
    pub fn is_stale(&self, max_staleness: Duration) -> bool {
        Utc::now() - self.witnessed_at > max_staleness
    }

    /// Calculate time until this TipWitness becomes stale
    pub fn time_until_stale(&self, max_staleness: Duration) -> Duration {
        let stale_at = self.witnessed_at + max_staleness;
        let now = Utc::now();
        if now >= stale_at {
            Duration::zero()
        } else {
            stale_at - now
        }
    }

    /// Verify continuity with a previous TipWitness
    pub fn verify_continuity(&self, previous: &TipWitness) -> TipWitnessContinuityResult {
        // Sequence must be >= previous
        if self.local_sequence_no < previous.local_sequence_no {
            return TipWitnessContinuityResult::SequenceRegression;
        }

        // If sequence is the same, digest must match
        if self.local_sequence_no == previous.local_sequence_no
            && self.local_tip_digest != previous.local_tip_digest
        {
            return TipWitnessContinuityResult::DigestMismatch;
        }

        // Large gap is suspicious but not necessarily invalid
        if self.local_sequence_no > previous.local_sequence_no + 10000 {
            return TipWitnessContinuityResult::LargeGap;
        }

        TipWitnessContinuityResult::Valid
    }
}

/// Result of TipWitness continuity verification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TipWitnessContinuityResult {
    /// Continuity is valid
    Valid,
    /// Sequence number went backwards
    SequenceRegression,
    /// Same sequence but different digest (history rewrite)
    DigestMismatch,
    /// Unusually large gap in sequence
    LargeGap,
}

impl TipWitnessContinuityResult {
    /// Check if this result indicates a potential history rewrite
    pub fn is_history_rewrite(&self) -> bool {
        matches!(self, Self::SequenceRegression | Self::DigestMismatch)
    }

    /// Check if this result is acceptable
    pub fn is_acceptable(&self) -> bool {
        matches!(self, Self::Valid | Self::LargeGap)
    }
}

/// TipWitness enforcement gate - used to check operations
pub struct TipWitnessGate {
    config: TipWitnessEnforcementConfig,
}

impl TipWitnessGate {
    /// Create a new TipWitness gate with the given configuration
    pub fn new(config: TipWitnessEnforcementConfig) -> Self {
        Self { config }
    }

    /// Check if an operation is allowed based on TipWitness status
    pub fn check_operation(
        &self,
        operation: &str,
        actor_id: &ActorId,
        last_witness: Option<&TipWitness>,
        is_first_time: bool,
    ) -> TipWitnessEnforcementResult {
        self.check_operation_with_time(operation, actor_id, last_witness, is_first_time, None)
    }

    /// Check operation with explicit registration time for first-time grace period
    pub fn check_operation_with_time(
        &self,
        operation: &str,
        actor_id: &ActorId,
        last_witness: Option<&TipWitness>,
        is_first_time: bool,
        actor_registered_at: Option<DateTime<Utc>>,
    ) -> TipWitnessEnforcementResult {
        // Check if operation is exempt
        if self.config.exempt_operations.contains(&operation.to_string()) {
            return TipWitnessEnforcementResult {
                passed: true,
                failure_reason: None,
                required_action: None,
                last_valid_witness: last_witness.cloned(),
                expires_in: None,
            };
        }

        // First-time actors get a grace period
        if is_first_time && last_witness.is_none() {
            // Check if within grace period
            if let Some(registered_at) = actor_registered_at {
                let grace_period_end = registered_at + self.config.first_time_grace_period;
                let now = Utc::now();

                if now < grace_period_end {
                    // Within grace period - allow operation but warn
                    let remaining = grace_period_end - now;
                    return TipWitnessEnforcementResult {
                        passed: true,
                        failure_reason: None,
                        required_action: Some(TipWitnessRequiredAction::SubmitNewWitness),
                        last_valid_witness: None,
                        expires_in: Some(remaining),
                    };
                }
            }

            // Grace period expired or no registration time provided
            return TipWitnessEnforcementResult::fail(
                TipWitnessFailureReason::NoWitnessFound,
                TipWitnessRequiredAction::SubmitNewWitness,
            );
        }

        // Check for existing TipWitness
        match last_witness {
            None => TipWitnessEnforcementResult::fail(
                TipWitnessFailureReason::NoWitnessFound,
                TipWitnessRequiredAction::SubmitNewWitness,
            ),
            Some(witness) => {
                // Check staleness
                if witness.is_stale(self.config.max_staleness) {
                    return TipWitnessEnforcementResult::fail(
                        TipWitnessFailureReason::WitnessStale,
                        TipWitnessRequiredAction::SubmitNewWitness,
                    );
                }

                let expires_in = witness.time_until_stale(self.config.max_staleness);
                TipWitnessEnforcementResult::pass(witness.clone(), expires_in)
            }
        }
    }

    /// Check if operations should be blocked based on configuration
    pub fn should_block_operations(&self) -> bool {
        self.config.block_operations_without_witness
    }

    /// Get the grace period duration
    pub fn grace_period(&self) -> Duration {
        self.config.first_time_grace_period
    }
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
