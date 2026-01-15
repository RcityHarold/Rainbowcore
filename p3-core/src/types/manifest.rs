//! Four Sets Event Types
//!
//! Chapter 3: Economic Event Universe and Input Flow

use super::common::*;
use chrono::{DateTime, Utc};
use l0_core::types::ActorId;
use serde::{Deserialize, Serialize};

// ============================================================
// Event Common Structures
// ============================================================

/// Economy event reference (zero-plaintext)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EconomyEventRef {
    /// Event type
    pub event_type: EventType,
    /// Event ID (stable primary key)
    pub event_id: EventId,
    /// Anchor reference (P1 sequence)
    pub anchor_ref: AnchorRef,
    /// Object IDs digest
    pub object_ids_digest: RefDigest,
    /// Receipt references digest
    pub receipt_refs_digest: RefDigest,
    /// Status digest
    pub status_digest: Option<P3Digest>,
}

/// Anchor reference (P1 sequence fact)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnchorRef {
    pub batch_sequence_no: u64,
    pub receipt_id: String,
}

impl AnchorRef {
    pub fn new(batch_sequence_no: u64, receipt_id: impl Into<String>) -> Self {
        Self {
            batch_sequence_no,
            receipt_id: receipt_id.into(),
        }
    }
}

// ============================================================
// Event Type Enum
// ============================================================

/// Event type (enumerable registry)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    // === knowledge_events_set ===
    /// Knowledge minting
    Mint,
    /// Final use
    FinalUse,
    /// Non-final use (search/draft)
    NonFinalUse,
    /// Quality/compliance evaluation
    Eval,
    /// Abuse signal
    AbuseSignal,

    // === court_events_set ===
    /// Verdict issued
    VerdictIssued,
    /// Repair checkpoint
    RepairCheckpoint,
    /// Clawback order
    ClawbackOrder,
    /// Dispute filed
    DisputeFiled,
    /// Appeal filed
    AppealFiled,

    // === policy_state_set ===
    /// Covenant status change
    CovenantStatusChange,
    /// Revocation record
    RevocationRecord,
    /// Policy version publication
    PolicyVersionPublication,

    // === sampling_audit_set ===
    /// Audit sampling triggered
    AuditSamplingTriggered,
    /// Audit sampling result
    AuditSamplingResult,
    /// Missing audit
    MissingAudit,
    /// Fraud suspected
    FraudSuspected,
    /// Must open candidate
    MustOpenCandidate,

    // === System state signals ===
    /// DSN unavailable
    DsnDown,
    /// Backfill status
    BackfillStatus,
    /// Missing coverage proof
    MissingCoverageProof,
}

impl EventType {
    /// Get the set this event type belongs to
    pub fn set_name(&self) -> &'static str {
        match self {
            EventType::Mint
            | EventType::FinalUse
            | EventType::NonFinalUse
            | EventType::Eval
            | EventType::AbuseSignal => "knowledge_events",

            EventType::VerdictIssued
            | EventType::RepairCheckpoint
            | EventType::ClawbackOrder
            | EventType::DisputeFiled
            | EventType::AppealFiled => "court_events",

            EventType::CovenantStatusChange
            | EventType::RevocationRecord
            | EventType::PolicyVersionPublication => "policy_state",

            EventType::AuditSamplingTriggered
            | EventType::AuditSamplingResult
            | EventType::MissingAudit
            | EventType::FraudSuspected
            | EventType::MustOpenCandidate
            | EventType::DsnDown
            | EventType::BackfillStatus
            | EventType::MissingCoverageProof => "sampling_audit",
        }
    }
}

// ============================================================
// knowledge_events_set Events
// ============================================================

/// Mint event (knowledge minting)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintEvent {
    pub event_id: EventId,
    pub anchor_ref: AnchorRef,
    pub knowledge_object_id: String,
    pub minter_actor_id: ActorId,
    pub mint_kind: MintKind,
    pub receipt_refs_digest: RefDigest,
}

/// Mint type
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MintKind {
    /// New object
    NewObject,
    /// Version update
    VersionUpdate,
    /// Duplicate submission (idempotent fold)
    Duplicate,
}

/// Use event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UseEvent {
    pub event_id: EventId,
    pub anchor_ref: AnchorRef,
    pub knowledge_object_id: String,
    pub consumer_actor_id: ActorId,
    pub use_kind: UseKind,
    pub finality_tag: Option<String>,
    pub receipt_refs_digest: RefDigest,
}

/// Use type
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UseKind {
    /// Final use (scores)
    FinalUse,
    /// Non-final use (no score or very low weight)
    NonFinalUse,
}

/// Eval event (evaluation)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvalEvent {
    pub event_id: EventId,
    pub anchor_ref: AnchorRef,
    pub target_object_id: String,
    pub eval_type: EvalType,
    pub result_bucket: EvalBucket,
    pub receipt_refs_digest: RefDigest,
}

/// Evaluation type
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalType {
    Quality,
    Compliance,
    Stability,
}

/// Evaluation bucket (grading)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalBucket {
    High,
    Medium,
    Low,
    Pass,
    Fail,
    Inconclusive,
}

/// Abuse signal event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AbuseSignalEvent {
    pub event_id: EventId,
    pub anchor_ref: AnchorRef,
    pub target_object_id: String,
    pub signal_type: AbuseSignalType,
    pub reporter_actor_id: ActorId,
    pub receipt_refs_digest: RefDigest,
}

/// Abuse signal type
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbuseSignalType {
    Spam,
    Plagiarism,
    Harmful,
    Copyright,
    Other,
}

// ============================================================
// court_events_set Events
// ============================================================

/// Verdict issued event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerdictIssuedEvent {
    pub event_id: EventId,
    pub anchor_ref: AnchorRef,
    pub verdict_ref: P3Digest,
    pub dispute_id: String,
    pub outcome: VerdictOutcome,
    pub receipt_refs_digest: RefDigest,
}

/// Verdict outcome
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictOutcome {
    Upheld,
    Overturned,
    Partial,
    Dismissed,
}

/// Clawback order event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClawbackOrderEvent {
    pub event_id: EventId,
    pub anchor_ref: AnchorRef,
    pub verdict_ref: P3Digest,
    /// Target epochs digest (hard lock required)
    pub target_epochs_digest: RefDigest,
    pub amount_digest: MoneyDigest,
    pub justification_digest: P3Digest,
    pub policy_ref: String,
    pub appeal_link: Option<String>,
    pub receipt_refs_digest: RefDigest,
}

/// Dispute filed event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisputeFiledEvent {
    pub event_id: EventId,
    pub anchor_ref: AnchorRef,
    pub dispute_id: String,
    pub filer_actor_id: ActorId,
    pub target_ref: String,
    pub reason_digest: P3Digest,
    pub deposit_id: Option<String>,
    pub receipt_refs_digest: RefDigest,
}

/// Appeal filed event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppealFiledEvent {
    pub event_id: EventId,
    pub anchor_ref: AnchorRef,
    pub appeal_id: String,
    pub original_verdict_ref: P3Digest,
    pub appellant_actor_id: ActorId,
    pub grounds_digest: P3Digest,
    pub receipt_refs_digest: RefDigest,
}

/// Repair checkpoint event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RepairCheckpointEvent {
    pub event_id: EventId,
    pub anchor_ref: AnchorRef,
    pub verdict_ref: P3Digest,
    pub repair_plan_digest: P3Digest,
    pub checkpoint_status: RepairCheckpointStatus,
    pub receipt_refs_digest: RefDigest,
}

/// Repair checkpoint status
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairCheckpointStatus {
    Initiated,
    InProgress,
    Completed,
    Failed,
}

// ============================================================
// policy_state_set Events
// ============================================================

/// Covenant status change event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CovenantStatusChangeEvent {
    pub event_id: EventId,
    pub anchor_ref: AnchorRef,
    pub covenant_id: String,
    pub old_status: CovenantStatus,
    pub new_status: CovenantStatus,
    pub reason_digest: Option<P3Digest>,
    pub receipt_refs_digest: RefDigest,
}

/// Covenant status
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CovenantStatus {
    Active,
    Suspended,
    Terminated,
    InRepair,
}

/// Revocation record event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevocationRecordEvent {
    pub event_id: EventId,
    pub anchor_ref: AnchorRef,
    pub revoked_object_id: String,
    pub revocation_type: RevocationType,
    pub reason_digest: P3Digest,
    pub receipt_refs_digest: RefDigest,
}

/// Revocation type
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationType {
    KeyRevocation,
    LicenseRevocation,
    AccessRevocation,
}

/// Policy version publication event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyVersionPublicationEvent {
    pub event_id: EventId,
    pub anchor_ref: AnchorRef,
    pub policy_id: String,
    pub version_id: String,
    pub valid_from_epoch: EpochId,
    pub supersedes: Option<String>,
    pub policy_digest: P3Digest,
    pub receipt_refs_digest: RefDigest,
}

// ============================================================
// sampling_audit_set Events
// ============================================================

/// Audit sampling triggered event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditSamplingTriggeredEvent {
    pub event_id: EventId,
    pub anchor_ref: AnchorRef,
    pub sampling_run_id: String,
    pub trigger_type: SamplingTriggerType,
    pub target_set_digest: RefDigest,
    pub receipt_refs_digest: RefDigest,
}

/// Sampling trigger type
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SamplingTriggerType {
    Scheduled,
    Random,
    Escalated,
    Manual,
}

/// Audit sampling result event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditSamplingResultEvent {
    pub event_id: EventId,
    pub anchor_ref: AnchorRef,
    pub target_ref: String,
    /// Result (locked enum)
    pub result: AuditResult,
    pub attempt_chain_ref: Option<AttemptChainId>,
    pub receipt_refs_digest: RefDigest,
}

/// Audit result (non-extensible)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    Pass,
    Fail,
    Inconclusive,
}

/// Missing audit event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MissingAuditEvent {
    pub event_id: EventId,
    pub anchor_ref: AnchorRef,
    pub expected_audit_ref: String,
    pub reason_digest: P3Digest,
}

/// Fraud suspected event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FraudSuspectedEvent {
    pub event_id: EventId,
    pub anchor_ref: AnchorRef,
    pub target_ref: String,
    pub suspicion_type: SuspicionType,
    pub evidence_digest: P3Digest,
    pub receipt_refs_digest: RefDigest,
}

/// Suspicion type
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuspicionType {
    DataTampering,
    FakeReceipt,
    Collusion,
    SybilAttack,
    Other,
}

/// Must open candidate event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MustOpenCandidateEvent {
    pub event_id: EventId,
    pub anchor_ref: AnchorRef,
    pub payload_ref: String,
    pub must_open_reason: MustOpenReason,
    pub escalation_level: EscalationLevel,
    pub receipt_refs_digest: RefDigest,
}

/// Must open reason
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MustOpenReason {
    JudicialOrder,
    SamplingHit,
    FraudSuspicion,
    ComplianceCheck,
}

/// Escalation level
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationLevel {
    Standard,
    Elevated,
    Critical,
}

/// DSN down event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DsnDownEvent {
    pub event_id: EventId,
    pub anchor_ref: AnchorRef,
    pub affected_nodes_digest: RefDigest,
    pub downtime_start: DateTime<Utc>,
    pub severity: DsnDownSeverity,
}

/// DSN down severity
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DsnDownSeverity {
    Partial,
    Major,
    Complete,
}

/// Backfill status event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackfillStatusEvent {
    pub event_id: EventId,
    pub anchor_ref: AnchorRef,
    pub target_batch_range: (u64, u64),
    pub backfill_status: BackfillEventStatus,
    pub upgraded_count: u64,
    pub remaining_count: u64,
}

/// Backfill event status
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackfillEventStatus {
    InProgress,
    Completed,
    Failed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_set_name() {
        assert_eq!(EventType::Mint.set_name(), "knowledge_events");
        assert_eq!(EventType::VerdictIssued.set_name(), "court_events");
        assert_eq!(EventType::CovenantStatusChange.set_name(), "policy_state");
        assert_eq!(EventType::AuditSamplingResult.set_name(), "sampling_audit");
    }

    #[test]
    fn test_mint_kind_serialization() {
        let kind = MintKind::NewObject;
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, "\"new_object\"");
    }
}
