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
}

/// Receipt verification response
#[derive(Debug, Serialize)]
pub struct VerifyReceiptResponse {
    pub valid: bool,
    pub evidence_level: String,
    pub chain_anchored: bool,
    pub errors: Vec<String>,
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
