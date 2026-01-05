//! Data Transfer Objects for API requests and responses

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ============ Commitment DTOs ============

/// Submit commitment request
#[derive(Debug, Deserialize)]
pub struct SubmitCommitmentRequest {
    /// Actor ID making the commitment
    pub actor_id: String,
    /// Scope type (one of the 11 batch types)
    pub scope_type: String,
    /// Commitment digest (BLAKE3 hash, hex encoded)
    pub commitment_digest: String,
    /// Optional parent commitment reference
    pub parent_ref: Option<String>,
}

/// Commitment response
#[derive(Debug, Serialize)]
pub struct CommitmentResponse {
    pub commitment_id: String,
    pub actor_id: String,
    pub scope_type: String,
    pub commitment_digest: String,
    pub parent_commitment_ref: Option<String>,
    pub sequence_no: u64,
    pub created_at: DateTime<Utc>,
    pub receipt_id: Option<String>,
}

// ============ Actor DTOs ============

/// Register actor request
#[derive(Debug, Deserialize)]
pub struct RegisterActorRequest {
    /// Actor type (human_actor, ai_actor, node_actor, group_actor)
    pub actor_type: String,
    /// Public key (Ed25519, hex encoded)
    pub public_key: String,
    /// Node actor ID managing this actor
    pub node_actor_id: String,
}

/// Actor response
#[derive(Debug, Serialize)]
pub struct ActorResponse {
    pub actor_id: String,
    pub actor_type: String,
    pub node_actor_id: String,
    pub public_key: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Update actor status request
#[derive(Debug, Deserialize)]
pub struct UpdateActorStatusRequest {
    /// New status (active, suspended, in_repair, terminated)
    pub status: String,
    /// Optional reason digest
    pub reason_digest: Option<String>,
}

// ============ Receipt DTOs ============

/// Create receipt request
#[derive(Debug, Deserialize)]
pub struct CreateReceiptRequest {
    /// Scope type
    pub scope_type: String,
    /// Root kind (batch_root, epoch_root)
    pub root_kind: String,
    /// Root digest
    pub root: String,
    /// Time window start
    pub time_window_start: DateTime<Utc>,
    /// Time window end
    pub time_window_end: DateTime<Utc>,
    /// Batch sequence number
    pub batch_sequence_no: Option<u64>,
    /// Signer set version
    pub signer_set_version: String,
    /// Canonicalization version
    pub canonicalization_version: String,
    /// Anchor policy version
    pub anchor_policy_version: String,
    /// Fee schedule version
    pub fee_schedule_version: String,
    /// Signed snapshot reference
    pub signed_snapshot_ref: String,
    /// Fee receipt ID (if applicable)
    pub fee_receipt_id: String,
}

/// Receipt response
#[derive(Debug, Serialize)]
pub struct ReceiptResponse {
    pub receipt_id: String,
    pub scope_type: String,
    pub root_kind: String,
    pub root: String,
    pub time_window_start: DateTime<Utc>,
    pub time_window_end: DateTime<Utc>,
    pub batch_sequence_no: Option<u64>,
    pub signer_set_version: String,
    pub created_at: DateTime<Utc>,
    pub rejected: Option<bool>,
    pub reject_reason_code: Option<String>,
}

/// Receipt verification response
#[derive(Debug, Serialize)]
pub struct VerifyReceiptResponse {
    pub valid: bool,
    pub evidence_level: String,
    pub chain_anchored: bool,
    pub errors: Vec<String>,
}

/// Reject receipt request
#[derive(Debug, Deserialize)]
pub struct RejectReceiptRequest {
    /// Reason code
    pub reason_code: String,
    /// Optional observer reports digest
    pub observer_reports_digest: Option<String>,
}

/// Charge fee request
#[derive(Debug, Deserialize)]
pub struct ChargeFeeRequest {
    /// Payer actor ID
    pub payer_actor_id: String,
    /// Anchor type
    pub anchor_type: String,
    /// Fee units type (batch_root, entry_count, size_tier)
    pub units: String,
    /// Number of units
    pub units_count: u32,
    /// Fee schedule version
    pub fee_schedule_version: String,
    /// Linked anchor ID
    pub linked_anchor_id: String,
    /// Optional risk multiplier
    pub risk_multiplier: Option<String>,
    /// Optional deposit amount
    pub deposit_amount: Option<String>,
    /// Optional discount digest
    pub discount_digest: Option<String>,
    /// Optional subsidy digest
    pub subsidy_digest: Option<String>,
}

/// Fee receipt response
#[derive(Debug, Serialize)]
pub struct FeeReceiptResponse {
    pub fee_receipt_id: String,
    pub fee_schedule_version: String,
    pub payer_actor_id: String,
    pub anchor_type: String,
    pub units: String,
    pub units_count: u32,
    pub amount: String,
    pub status: String,
    pub timestamp: DateTime<Utc>,
    pub linked_receipt_id: Option<String>,
}

/// Update fee status request
#[derive(Debug, Deserialize)]
pub struct UpdateFeeStatusRequest {
    /// New status (charged_pending_receipt, charged, refunded, forfeited, charged_no_receipt)
    pub status: String,
}

/// TipWitness request
#[derive(Debug, Deserialize)]
pub struct SubmitTipWitnessRequest {
    /// Actor ID
    pub actor_id: String,
    /// Local tip digest
    pub local_tip_digest: String,
    /// Local sequence number
    pub local_sequence_no: u64,
    /// Last known receipt reference
    pub last_known_receipt_ref: Option<String>,
}

/// TipWitness response
#[derive(Debug, Serialize)]
pub struct TipWitnessResponse {
    pub tip_witness_id: String,
    pub actor_id: String,
    pub local_tip_digest: String,
    pub local_sequence_no: u64,
    pub last_known_receipt_ref: Option<String>,
    pub witnessed_at: DateTime<Utc>,
    pub receipt_id: Option<String>,
}

/// TipWitness chain verification response
#[derive(Debug, Serialize)]
pub struct TipWitnessChainResponse {
    pub is_valid: bool,
    pub witness_count: u64,
    pub earliest_sequence: Option<u64>,
    pub latest_sequence: Option<u64>,
    pub gaps: Vec<TipWitnessGapResponse>,
}

/// TipWitness gap response
#[derive(Debug, Serialize)]
pub struct TipWitnessGapResponse {
    pub from_sequence: u64,
    pub to_sequence: u64,
    pub gap_type: String,
}

// ============ Batch/Epoch DTOs ============

/// Batch snapshot response
#[derive(Debug, Serialize)]
pub struct BatchSnapshotResponse {
    pub snapshot_id: String,
    pub batch_root: String,
    pub batch_sequence_no: u64,
    pub time_window_start: DateTime<Utc>,
    pub time_window_end: DateTime<Utc>,
    pub parent_batch_root: Option<String>,
    pub signer_set_version: String,
    pub signature_bitmap: String,
    pub threshold_proof: String,
}

// ============ Backfill DTOs ============

/// Backfill request
#[derive(Debug, Deserialize)]
pub struct BackfillRequest {
    /// Actor ID requesting backfill
    pub requester_actor_id: String,
    /// Optional scope type to backfill
    pub scope_type: Option<String>,
    /// Start time
    pub start_time: DateTime<Utc>,
    /// End time
    pub end_time: DateTime<Utc>,
}

/// Backfill response
#[derive(Debug, Serialize)]
pub struct BackfillResponse {
    pub request_id: String,
    pub status: String,
    pub items_found: u64,
    pub created_at: DateTime<Utc>,
}

// ============ Health DTOs ============

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub node_id: Option<String>,
    pub current_batch_sequence: u64,
    pub current_epoch_sequence: u64,
}

/// API version information response
#[derive(Debug, Serialize)]
pub struct ApiVersionResponse {
    /// Current API version (e.g., "v1")
    pub current_version: String,
    /// All supported API versions
    pub supported_versions: Vec<String>,
    /// Deprecated versions (if any)
    pub deprecated_versions: Vec<String>,
    /// Node software version
    pub node_version: String,
    /// Protocol version information
    pub protocol_versions: ProtocolVersionsResponse,
}

/// Protocol version information
#[derive(Debug, Serialize)]
pub struct ProtocolVersionsResponse {
    /// Canonicalization algorithm version
    pub canonicalization: String,
    /// Fee schedule version
    pub fee_schedule: String,
    /// Anchor policy version
    pub anchor_policy: String,
    /// Signer set version
    pub signer_set: String,
    /// Threshold rule
    pub threshold_rule: String,
}

// ============ Pagination ============

/// Paginated list response
#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total: u64,
    pub limit: u32,
    pub offset: u32,
}

/// Query parameters for list endpoints
#[derive(Debug, Deserialize, Default)]
pub struct ListQueryParams {
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
    pub scope_type: Option<String>,
    pub actor_type: Option<String>,
    pub status: Option<String>,
}

fn default_limit() -> u32 {
    100
}

// ============ Knowledge DTOs ============

/// Index content request
#[derive(Debug, Deserialize)]
pub struct IndexContentRequest {
    /// Content digest (BLAKE3 hash, hex encoded)
    pub content_digest: String,
    /// Owner actor ID
    pub owner_actor_id: String,
    /// Optional space ID
    pub space_id: Option<String>,
    /// Optional parent digest
    pub parent_digest: Option<String>,
}

/// Knowledge index entry response
#[derive(Debug, Serialize)]
pub struct KnowledgeEntryResponse {
    pub entry_id: String,
    pub entry_type: String,
    pub content_digest: String,
    pub parent_digest: Option<String>,
    pub space_id: Option<String>,
    pub owner_actor_id: String,
    pub created_at: DateTime<Utc>,
    pub evidence_level: String,
    pub anchoring_state: String,
    pub receipt_id: Option<String>,
}

/// Create cross-reference request
#[derive(Debug, Deserialize)]
pub struct CreateCrossRefRequest {
    /// Source digest
    pub source_digest: String,
    /// Target digest
    pub target_digest: String,
    /// Reference type
    pub ref_type: String,
}

/// Cross-reference response
#[derive(Debug, Serialize)]
pub struct CrossReferenceResponse {
    pub ref_id: String,
    pub source_digest: String,
    pub target_digest: String,
    pub ref_type: String,
    pub created_at: DateTime<Utc>,
    pub receipt_id: Option<String>,
}

// ============ Consent DTOs ============

/// Grant consent request
#[derive(Debug, Deserialize)]
pub struct GrantConsentRequest {
    /// Consent type (explicit, implied, delegated, emergency)
    pub consent_type: String,
    /// Grantor actor ID
    pub grantor: String,
    /// Grantee actor ID
    pub grantee: String,
    /// Resource type
    pub resource_type: String,
    /// Optional resource ID
    pub resource_id: Option<String>,
    /// Allowed actions
    pub actions: Vec<String>,
    /// Terms digest
    pub terms_digest: String,
    /// Optional expiration time
    pub expires_at: Option<DateTime<Utc>>,
}

/// Consent record response
#[derive(Debug, Serialize)]
pub struct ConsentResponse {
    pub consent_id: String,
    pub consent_type: String,
    pub grantor: String,
    pub grantee: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub actions: Vec<String>,
    pub status: String,
    pub terms_digest: String,
    pub granted_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub receipt_id: Option<String>,
}

/// Revoke consent request
#[derive(Debug, Deserialize)]
pub struct RevokeConsentRequest {
    /// Optional reason digest
    pub reason_digest: Option<String>,
}

/// Verify consent request
#[derive(Debug, Deserialize)]
pub struct VerifyConsentRequest {
    /// Grantor actor ID
    pub grantor: String,
    /// Grantee actor ID
    pub grantee: String,
    /// Action to verify
    pub action: String,
    /// Resource type
    pub resource_type: String,
}

/// Verify consent response
#[derive(Debug, Serialize)]
pub struct VerifyConsentResponse {
    pub valid: bool,
    pub consent_ref: Option<String>,
    pub reason: Option<String>,
}

/// Issue ticket request
#[derive(Debug, Deserialize)]
pub struct IssueTicketRequest {
    /// Consent reference
    pub consent_ref: String,
    /// Ticket holder actor ID
    pub holder: String,
    /// Target resource
    pub target_resource: String,
    /// Permissions
    pub permissions: Vec<String>,
    /// Valid until
    pub valid_until: DateTime<Utc>,
    /// One-time use
    pub one_time: bool,
}

/// Access ticket response
#[derive(Debug, Serialize)]
pub struct AccessTicketResponse {
    pub ticket_id: String,
    pub consent_ref: String,
    pub holder: String,
    pub target_resource: String,
    pub permissions: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub one_time: bool,
    pub used_at: Option<DateTime<Utc>>,
    pub ticket_digest: String,
}

// ============ Dispute DTOs ============

/// File dispute request
#[derive(Debug, Deserialize)]
pub struct FileDisputeRequest {
    /// Filing actor ID
    pub filed_by: String,
    /// Actors filed against
    pub filed_against: Vec<String>,
    /// Priority (normal, urgent, critical)
    pub priority: String,
    /// Subject commitment reference
    pub subject_commitment_ref: String,
    /// Evidence digest
    pub evidence_digest: String,
}

/// Dispute record response
#[derive(Debug, Serialize)]
pub struct DisputeResponse {
    pub dispute_id: String,
    pub filed_by: String,
    pub filed_against: Vec<String>,
    pub priority: String,
    pub status: String,
    pub subject_commitment_ref: String,
    pub evidence_digest: String,
    pub filed_at: DateTime<Utc>,
    pub last_updated: DateTime<Utc>,
    pub receipt_id: Option<String>,
}

/// Issue verdict request
#[derive(Debug, Deserialize)]
pub struct IssueVerdictRequest {
    /// Verdict type (in_favor, against, mixed, dismissed, inconclusive)
    pub verdict_type: String,
    /// Verdict digest
    pub verdict_digest: String,
    /// Rationale digest
    pub rationale_digest: String,
    /// Optional remedies digest
    pub remedies_digest: Option<String>,
    /// Issued by (node or committee ID)
    pub issued_by: String,
    /// Optional appeal deadline
    pub appeal_deadline: Option<DateTime<Utc>>,
}

/// Verdict response
#[derive(Debug, Serialize)]
pub struct VerdictResponse {
    pub verdict_id: String,
    pub dispute_id: String,
    pub verdict_type: String,
    pub verdict_digest: String,
    pub rationale_digest: String,
    pub remedies_digest: Option<String>,
    pub issued_by: String,
    pub issued_at: DateTime<Utc>,
    pub effective_at: DateTime<Utc>,
    pub appeal_deadline: Option<DateTime<Utc>>,
    pub receipt_id: Option<String>,
}

/// Initiate clawback request
#[derive(Debug, Deserialize)]
pub struct InitiateClawbackRequest {
    /// Verdict ID
    pub verdict_id: String,
    /// Clawback type (full_reverse, partial_reverse, compensation, penalty)
    pub clawback_type: String,
    /// Target commitment references
    pub target_commitment_refs: Vec<String>,
    /// Affected actors
    pub affected_actors: Vec<String>,
    /// Optional compensation digest
    pub compensation_digest: Option<String>,
}

/// Clawback response
#[derive(Debug, Serialize)]
pub struct ClawbackResponse {
    pub clawback_id: String,
    pub verdict_id: String,
    pub clawback_type: String,
    pub status: String,
    pub clawback_digest: String,
    pub target_commitment_refs: Vec<String>,
    pub affected_actors: Vec<String>,
    pub compensation_digest: Option<String>,
    pub initiated_at: DateTime<Utc>,
    pub executed_at: Option<DateTime<Utc>>,
    pub receipt_id: Option<String>,
}
