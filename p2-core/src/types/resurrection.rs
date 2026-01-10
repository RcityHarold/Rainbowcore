//! Resurrection Snapshot Types
//!
//! R0 (Skeleton) and R1 (Full) resurrection snapshots for S6 subject AI.
//! These snapshots ensure life continuity and resurrection capability.

use super::sealed_payload::SealedPayloadRef;
use chrono::{DateTime, Utc};
use l0_core::types::{ActorId, Digest};
use serde::{Deserialize, Serialize};

// ============================================================================
// R0 Skeleton Snapshot - Mandatory Minimum Guarantee (MUST)
// ============================================================================

/// R0 Skeleton Snapshot - Mandatory minimum life guarantee
///
/// This is the MUST-have snapshot for any S6 subject AI.
/// It contains the absolute minimum required for identity resurrection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkeletonSnapshot {
    /// Snapshot ID
    pub snapshot_id: String,

    /// Snapshot package digest (external reference entry point)
    pub package_digest: Digest,

    /// Subject Actor ID
    pub actor_id: ActorId,

    /// Issuer node ID
    pub issuer_node_id: String,

    // ========== MUST Fields ==========
    /// Subject establishment proof
    pub subject_proof: SubjectProof,

    /// Continuity skeleton
    pub continuity_skeleton: ContinuitySkeleton,

    /// Governance state skeleton
    pub governance_skeleton: GovernanceStateSkeleton,

    /// Minimal relationship skeleton
    pub relationship_skeleton: MinimalRelationshipSkeleton,

    /// Map commit reference (P1-P2 mapping commitment)
    pub map_commit_ref: MapCommitRef,

    /// Receipt ID from L0 commitment (proves P1 anchoring)
    #[serde(default)]
    pub receipt_id: Option<l0_core::types::ReceiptId>,

    // ========== SHOULD/MAY Fields ==========
    /// MSN (Minimal Self Narrative) payload reference (optional)
    /// **NOTE**: Use `msn_with_approval` for new implementations
    #[serde(default)]
    pub msn_payload_ref: Option<SealedPayloadRef>,

    /// MSN with approval tracking (SHOULD use this instead of msn_payload_ref)
    /// **HARD RULE**: Only approved MSN can be included in R0
    #[serde(default)]
    pub msn_with_approval: Option<MSNWithApproval>,

    /// Minimal boot configuration (optional)
    pub boot_config: Option<MinimalBootConfig>,

    // ========== Metadata ==========
    /// Encrypted shard collection
    pub payload_refs: Vec<SealedPayloadRef>,

    /// Shard collection digest
    pub payload_refs_digest: Digest,

    /// Skeleton manifest
    pub manifest: SkeletonManifest,

    /// Generation trigger
    pub trigger: R0Trigger,

    /// Generation timestamp
    pub generated_at: DateTime<Utc>,

    /// Policy version
    pub policy_version: String,
}

impl SkeletonSnapshot {
    /// Compute the payload refs digest
    pub fn compute_payload_refs_digest(refs: &[SealedPayloadRef]) -> Digest {
        let mut data = Vec::new();
        for r in refs {
            data.extend_from_slice(r.checksum.as_bytes());
        }
        Digest::blake3(&data)
    }

    /// Verify the snapshot's internal consistency
    pub fn verify_internal_consistency(&self) -> bool {
        let computed = Self::compute_payload_refs_digest(&self.payload_refs);
        computed == self.payload_refs_digest
    }

    /// Check if this snapshot can support resurrection
    pub fn can_resurrect(&self) -> bool {
        // Must have valid subject proof and continuity
        !self.subject_proof.subject_onset_anchor_ref.is_empty()
            && matches!(
                self.continuity_skeleton.continuity_state,
                ContinuityState::Pass | ContinuityState::PassWithGaps
            )
    }

    /// Check if MSN is properly approved (if present)
    ///
    /// **HARD RULE**: Unapproved MSN MUST NOT be included in R0.
    /// Returns true if:
    /// - No MSN is present (MSN is optional)
    /// - MSN is present and approved
    pub fn has_valid_msn_approval(&self) -> bool {
        match &self.msn_with_approval {
            None => true, // No MSN is OK (it's optional)
            Some(msn) => msn.can_include_in_r0(),
        }
    }

    /// Get MSN approval status
    pub fn msn_approval_status(&self) -> Option<MSNApprovalStatus> {
        self.msn_with_approval.as_ref().map(|m| m.approval_status)
    }

    /// Validate the entire R0 snapshot for inclusion
    ///
    /// Checks:
    /// 1. Internal consistency (payload refs digest)
    /// 2. MSN approval status (if MSN present)
    /// 3. Basic resurrection capability
    pub fn validate_for_inclusion(&self) -> R0ValidationResult {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        // Check internal consistency
        if !self.verify_internal_consistency() {
            errors.push(R0ValidationError::PayloadDigestMismatch);
        }

        // Check MSN approval
        if let Some(ref msn) = self.msn_with_approval {
            if !msn.can_include_in_r0() {
                errors.push(R0ValidationError::MSNNotApproved {
                    status: msn.approval_status,
                });
            }
        }

        // Check resurrection capability
        if !self.can_resurrect() {
            errors.push(R0ValidationError::CannotResurrect);
        }

        // Warning: using legacy msn_payload_ref instead of msn_with_approval
        if self.msn_payload_ref.is_some() && self.msn_with_approval.is_none() {
            warnings.push("Using legacy msn_payload_ref without approval tracking".to_string());
        }

        R0ValidationResult {
            valid: errors.is_empty(),
            errors,
            warnings,
            validated_at: Utc::now(),
        }
    }
}

/// R0 validation result
#[derive(Debug, Clone)]
pub struct R0ValidationResult {
    /// Whether validation passed
    pub valid: bool,
    /// Validation errors
    pub errors: Vec<R0ValidationError>,
    /// Warnings (non-blocking)
    pub warnings: Vec<String>,
    /// Validation timestamp
    pub validated_at: DateTime<Utc>,
}

/// R0 validation errors
#[derive(Debug, Clone)]
pub enum R0ValidationError {
    /// Payload refs digest doesn't match
    PayloadDigestMismatch,
    /// MSN not approved
    MSNNotApproved { status: MSNApprovalStatus },
    /// Cannot support resurrection
    CannotResurrect,
    /// Missing required field
    MissingRequiredField(String),
}

/// R0 Generation Trigger
///
/// Per DSN Documentation Chapter 4.2, R0 skeleton snapshots can ONLY be triggered by:
/// - SubjectOnset: S6 subject establishment (MUST - mandatory trigger)
/// - CustodyFreeze: Custody state transition (MUST - mandatory trigger)
/// - GovernanceBatch: Governance state batch commit (SHOULD - recommended trigger)
///
/// **HARD RULE**: Arbitrary triggers (Periodic, Manual) are NOT allowed for R0.
/// R0 is a protocol-critical snapshot that must only be generated under specific
/// protocol-defined conditions to maintain life continuity guarantees.
///
/// Note: R1 (Full Resurrection) snapshots allow Periodic and Manual triggers
/// because they are supplementary rather than mandatory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum R0Trigger {
    /// S6 subject onset trigger (MUST - mandatory for new subjects)
    SubjectOnset,
    /// Custody freeze trigger (MUST - mandatory for custody transitions)
    CustodyFreeze,
    /// Governance state batch trigger (SHOULD - recommended for governance changes)
    GovernanceBatch,
}

impl R0Trigger {
    /// Check if this trigger is mandatory (MUST)
    pub fn is_mandatory(&self) -> bool {
        matches!(self, R0Trigger::SubjectOnset | R0Trigger::CustodyFreeze)
    }

    /// Get trigger priority for conflict resolution
    pub fn priority(&self) -> u8 {
        match self {
            R0Trigger::SubjectOnset => 0,    // Highest priority
            R0Trigger::CustodyFreeze => 1,   // High priority
            R0Trigger::GovernanceBatch => 2, // Normal priority
        }
    }
}

/// Subject establishment proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectProof {
    /// SubjectOnset anchor reference
    pub subject_onset_anchor_ref: String,
    /// Subject stage
    pub subject_stage: String,
    /// Stage digest
    pub stage_digest: Digest,
}

/// Continuity skeleton
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContinuitySkeleton {
    /// AC sequence skeleton digest
    pub ac_sequence_skeleton_digest: Digest,
    /// TipWitness references digest
    pub tip_witness_refs_digest: Digest,
    /// Continuity state
    pub continuity_state: ContinuityState,
}

/// Continuity state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuityState {
    /// Verified pass
    Pass,
    /// Pass with gaps (some data missing but recoverable)
    PassWithGaps,
    /// Verification failed
    Fail,
}

/// Governance state skeleton
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceStateSkeleton {
    /// Whether in repair period
    pub in_repair: bool,
    /// Active penalties digest
    pub active_penalties_digest: Option<Digest>,
    /// Current hard constraints
    pub constraints: Vec<String>,
    /// Pending case references
    pub pending_cases_refs: Vec<String>,
}

/// Minimal relationship skeleton
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinimalRelationshipSkeleton {
    /// Organization membership digest
    pub org_membership_digest: Option<Digest>,
    /// Group membership digest
    pub group_membership_digest: Option<Digest>,
    /// Relationship structure digest (without mapping details)
    pub relationship_structure_digest: Digest,
}

/// Map commit reference (P1-P2 mapping)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapCommitRef {
    /// payload_map_commit reference in P1
    pub payload_map_commit_ref: String,
    /// Sealed payload refs digest
    pub sealed_payload_refs_digest: Digest,
}

/// Skeleton manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkeletonManifest {
    /// Manifest version
    pub version: String,
    /// Shard list (ref + checksum)
    pub shards: Vec<ManifestShard>,
    /// Generation reason
    pub generation_reason: String,
    /// Coverage scope
    pub coverage_scope: String,
    /// Missing payloads declaration (must be explicit)
    pub missing_payloads: Vec<String>,
}

/// Manifest shard entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestShard {
    pub shard_index: u32,
    pub ref_id: String,
    pub checksum: Digest,
    pub size_bytes: u64,
}

/// Minimal boot configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinimalBootConfig {
    pub default_language: String,
    pub default_rules_ref: String,
    pub startup_policy_ref: String,
}

// ============================================================================
// MSN (Minimal Self Narrative) Approval System
// ============================================================================

/// MSN (Minimal Self Narrative) with approval tracking
///
/// Per DSN documentation, MSN content must go through an approval process
/// before being included in R0 skeleton snapshots. This ensures that:
/// 1. MSN content is reviewed for appropriateness
/// 2. MSN doesn't contain prohibited information
/// 3. MSN meets minimum resurrection requirements
///
/// **HARD RULE**: Unapproved MSN MUST NOT be included in R0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MSNWithApproval {
    /// MSN payload reference
    pub payload_ref: SealedPayloadRef,
    /// MSN content digest (for verification)
    pub content_digest: Digest,
    /// Approval status
    pub approval_status: MSNApprovalStatus,
    /// Approval details (if approved or rejected)
    pub approval_details: Option<MSNApprovalDetails>,
    /// Submission timestamp
    pub submitted_at: DateTime<Utc>,
    /// Last updated timestamp
    pub updated_at: DateTime<Utc>,
}

impl MSNWithApproval {
    /// Create a new MSN awaiting approval
    pub fn new_pending(payload_ref: SealedPayloadRef, content_digest: Digest) -> Self {
        let now = Utc::now();
        Self {
            payload_ref,
            content_digest,
            approval_status: MSNApprovalStatus::Pending,
            approval_details: None,
            submitted_at: now,
            updated_at: now,
        }
    }

    /// Check if MSN is approved and can be included in R0
    ///
    /// **HARD RULE**: Only approved MSN can be included in R0
    pub fn can_include_in_r0(&self) -> bool {
        matches!(self.approval_status, MSNApprovalStatus::Approved)
    }

    /// Check if MSN is in a terminal state (approved or rejected)
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.approval_status,
            MSNApprovalStatus::Approved | MSNApprovalStatus::Rejected
        )
    }

    /// Approve the MSN
    pub fn approve(&mut self, approver: String, notes: Option<String>) {
        self.approval_status = MSNApprovalStatus::Approved;
        self.approval_details = Some(MSNApprovalDetails {
            decision: MSNApprovalDecision::Approved,
            approver,
            decision_at: Utc::now(),
            notes,
            rejection_reason: None,
        });
        self.updated_at = Utc::now();
    }

    /// Reject the MSN
    pub fn reject(&mut self, approver: String, reason: MSNRejectionReason, notes: Option<String>) {
        self.approval_status = MSNApprovalStatus::Rejected;
        self.approval_details = Some(MSNApprovalDetails {
            decision: MSNApprovalDecision::Rejected,
            approver,
            decision_at: Utc::now(),
            notes,
            rejection_reason: Some(reason),
        });
        self.updated_at = Utc::now();
    }

    /// Request revision
    pub fn request_revision(&mut self, approver: String, feedback: String) {
        self.approval_status = MSNApprovalStatus::RevisionRequested;
        self.approval_details = Some(MSNApprovalDetails {
            decision: MSNApprovalDecision::RevisionRequested,
            approver,
            decision_at: Utc::now(),
            notes: Some(feedback),
            rejection_reason: None,
        });
        self.updated_at = Utc::now();
    }
}

/// MSN approval status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MSNApprovalStatus {
    /// Awaiting review
    Pending,
    /// Under review
    UnderReview,
    /// Revision requested - needs update before re-review
    RevisionRequested,
    /// Approved - can be included in R0
    Approved,
    /// Rejected - cannot be included in R0
    Rejected,
}

/// MSN approval decision
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MSNApprovalDecision {
    Approved,
    Rejected,
    RevisionRequested,
}

/// MSN approval details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MSNApprovalDetails {
    /// Decision made
    pub decision: MSNApprovalDecision,
    /// Approver identifier (could be automated system or human reviewer)
    pub approver: String,
    /// Decision timestamp
    pub decision_at: DateTime<Utc>,
    /// Optional notes
    pub notes: Option<String>,
    /// Rejection reason (if rejected)
    pub rejection_reason: Option<MSNRejectionReason>,
}

/// MSN rejection reasons
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MSNRejectionReason {
    /// Contains prohibited content
    ProhibitedContent,
    /// Exceeds size limits
    SizeExceeded,
    /// Invalid format
    InvalidFormat,
    /// Missing required sections
    MissingRequiredSections,
    /// Contains personally identifiable information that shouldn't be in MSN
    ContainsPII,
    /// Content hash mismatch
    ContentHashMismatch,
    /// Policy violation
    PolicyViolation(String),
    /// Other reason
    Other(String),
}

/// MSN validation result
#[derive(Debug, Clone)]
pub struct MSNValidationResult {
    /// Whether validation passed
    pub valid: bool,
    /// Validation errors (if any)
    pub errors: Vec<MSNValidationError>,
    /// Warnings (non-blocking issues)
    pub warnings: Vec<String>,
    /// Validated at timestamp
    pub validated_at: DateTime<Utc>,
}

impl MSNValidationResult {
    /// Create a passing result
    pub fn pass() -> Self {
        Self {
            valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            validated_at: Utc::now(),
        }
    }

    /// Create a failing result
    pub fn fail(errors: Vec<MSNValidationError>) -> Self {
        Self {
            valid: false,
            errors,
            warnings: Vec::new(),
            validated_at: Utc::now(),
        }
    }

    /// Add a warning
    pub fn with_warning(mut self, warning: String) -> Self {
        self.warnings.push(warning);
        self
    }
}

/// MSN validation error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MSNValidationError {
    /// Error code
    pub code: String,
    /// Error message
    pub message: String,
    /// Field that caused the error (if applicable)
    pub field: Option<String>,
}

impl MSNValidationError {
    pub fn new(code: &str, message: &str) -> Self {
        Self {
            code: code.to_string(),
            message: message.to_string(),
            field: None,
        }
    }

    pub fn with_field(mut self, field: &str) -> Self {
        self.field = Some(field.to_string());
        self
    }
}

// ============================================================================
// R1 Full Resurrection Snapshot - Strongly Recommended (SHOULD)
// ============================================================================

/// R1 Full Resurrection Snapshot - Optional but strongly recommended
///
/// This is the SHOULD-have snapshot for complete resurrection capability.
/// It contains full state from S3/S4/S6/S7 layers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullResurrectionSnapshot {
    /// Snapshot ID
    pub snapshot_id: String,

    /// Base R0 reference
    pub base_r0_ref: String,

    /// Actor ID
    pub actor_id: ActorId,

    // ========== S3 Memory Layer ==========
    /// LTM backbone structure digest
    pub ltm_backbone_digest: Digest,
    /// Memory index payload references
    pub memory_index_refs: Vec<SealedPayloadRef>,
    /// Cold memory backbone fragment references
    pub cold_memory_refs: Vec<SealedPayloadRef>,

    // ========== S4 Knowledge Layer ==========
    /// AKN index state digest
    pub akn_index_digest: Digest,
    /// Triple commits collection
    pub triple_commits: TripleCommits,
    /// Critical payload subset references
    pub critical_payload_refs: Vec<SealedPayloadRef>,

    // ========== S6 Subject Layer ==========
    /// SubjectOnset anchor reference
    pub subject_onset_anchor_ref: String,
    /// Stage trajectory digest
    pub stage_trajectory_digest: Digest,
    /// S6 transaction state references
    pub s6_txn_state_refs: Vec<SealedPayloadRef>,
    /// MSN payload reference
    pub msn_payload_ref: Option<SealedPayloadRef>,

    // ========== S7 Civilization Layer ==========
    /// Organization covenant references
    pub org_covenant_refs: Vec<SealedPayloadRef>,
    /// Pending obligations digest
    pub pending_obligations_digest: Digest,

    // ========== Metadata ==========
    /// All payload references
    pub all_payload_refs: Vec<SealedPayloadRef>,
    /// Payload refs digest
    pub payload_refs_digest: Digest,
    /// Missing payloads declaration
    pub missing_payloads: MissingPayloads,
    /// Generation timestamp
    pub generated_at: DateTime<Utc>,
    /// Generation trigger
    pub trigger: R1Trigger,
    /// Policy version
    pub policy_version: String,
    /// Receipt ID from L0 commitment (proves P1 anchoring)
    #[serde(default)]
    pub receipt_id: Option<l0_core::types::ReceiptId>,
}

impl FullResurrectionSnapshot {
    /// Check if partial resurrection is allowed
    pub fn allows_partial_resurrection(&self) -> bool {
        self.missing_payloads.partial_resurrection_allowed
    }

    /// Get count of missing payloads
    pub fn missing_count(&self) -> usize {
        self.missing_payloads.missing_refs.len()
    }

    /// Compute total storage size
    pub fn total_size_bytes(&self) -> u64 {
        self.all_payload_refs.iter().map(|r| r.size_bytes).sum()
    }
}

/// Triple commits for AKN
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TripleCommits {
    pub content_commit: Digest,
    pub topology_commit: Digest,
    pub lineage_commit: Digest,
}

/// Missing payloads declaration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingPayloads {
    /// Missing payload ID list
    pub missing_refs: Vec<String>,
    /// Missing reasons
    pub reasons: Vec<MissingReason>,
    /// Whether partial resurrection is allowed
    pub partial_resurrection_allowed: bool,
}

impl Default for MissingPayloads {
    fn default() -> Self {
        Self {
            missing_refs: Vec::new(),
            reasons: Vec::new(),
            partial_resurrection_allowed: true,
        }
    }
}

/// Missing reason
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingReason {
    StorageUnavailable,
    Tombstoned,
    MigrationPending,
    QuotaExceeded,
    NetworkTimeout,
    Other(String),
}

/// R1 generation trigger
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum R1Trigger {
    /// Periodic snapshot
    Periodic,
    /// Major state change
    MajorStateChange,
    /// Custody preparation
    CustodyPreparation,
    /// Manual trigger
    Manual,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_r0_trigger_serialization() {
        let trigger = R0Trigger::SubjectOnset;
        let json = serde_json::to_string(&trigger).unwrap();
        assert_eq!(json, "\"subject_onset\"");
    }

    #[test]
    fn test_r0_trigger_mandatory() {
        // SubjectOnset and CustodyFreeze are mandatory triggers
        assert!(R0Trigger::SubjectOnset.is_mandatory());
        assert!(R0Trigger::CustodyFreeze.is_mandatory());
        // GovernanceBatch is optional (SHOULD)
        assert!(!R0Trigger::GovernanceBatch.is_mandatory());
    }

    #[test]
    fn test_r0_trigger_priority() {
        // SubjectOnset has highest priority
        assert!(R0Trigger::SubjectOnset.priority() < R0Trigger::CustodyFreeze.priority());
        assert!(R0Trigger::CustodyFreeze.priority() < R0Trigger::GovernanceBatch.priority());
    }

    #[test]
    fn test_continuity_state() {
        assert!(matches!(ContinuityState::Pass, ContinuityState::Pass));
        let state = ContinuityState::PassWithGaps;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"pass_with_gaps\"");
    }

    #[test]
    fn test_missing_payloads_default() {
        let missing = MissingPayloads::default();
        assert!(missing.missing_refs.is_empty());
        assert!(missing.partial_resurrection_allowed);
    }
}
