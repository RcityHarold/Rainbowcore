//! Commitment endpoints

use axum::{
    extract::{Path, Query, State},
    Json,
};
use l0_core::ledger::{CausalityLedger, QueryOptions};
use l0_core::types::{ActorId, Digest, ScopeType};

use crate::dto::{
    BatchSnapshotResponse, CommitmentResponse, ListQueryParams, PaginatedResponse,
    SubmitCommitmentRequest,
};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Submit a new commitment
pub async fn submit_commitment(
    State(state): State<AppState>,
    Json(req): Json<SubmitCommitmentRequest>,
) -> ApiResult<Json<CommitmentResponse>> {
    // Parse scope type
    let scope_type = parse_scope_type(&req.scope_type)?;

    // Parse digest
    let commitment_digest = Digest::from_hex(&req.commitment_digest)
        .map_err(|_| ApiError::Validation("Invalid commitment digest hex".to_string()))?;

    // Submit commitment
    let record = state
        .causality
        .submit_commitment(
            &ActorId(req.actor_id),
            scope_type,
            commitment_digest,
            req.parent_ref,
        )
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(commitment_to_response(&record)))
}

/// Get commitment by ID
pub async fn get_commitment(
    State(state): State<AppState>,
    Path(commitment_id): Path<String>,
) -> ApiResult<Json<CommitmentResponse>> {
    let commitment = state
        .causality
        .get_commitment(&commitment_id)
        .await
        .map_err(ApiError::Ledger)?
        .ok_or_else(|| ApiError::NotFound(format!("Commitment {} not found", commitment_id)))?;

    Ok(Json(commitment_to_response(&commitment)))
}

/// Get commitment chain for an actor
pub async fn get_commitment_chain(
    State(state): State<AppState>,
    Path(actor_id): Path<String>,
    Query(params): Query<ListQueryParams>,
) -> ApiResult<Json<PaginatedResponse<CommitmentResponse>>> {
    let scope_type = params
        .scope_type
        .as_ref()
        .map(|s| parse_scope_type(s))
        .transpose()?;

    let options = QueryOptions {
        limit: Some(params.limit),
        offset: Some(params.offset),
        ..Default::default()
    };

    let commitments = state
        .causality
        .get_commitment_chain(&ActorId(actor_id), scope_type, options)
        .await
        .map_err(ApiError::Ledger)?;

    let items: Vec<CommitmentResponse> = commitments.iter().map(commitment_to_response).collect();
    let total = items.len() as u64;

    Ok(Json(PaginatedResponse {
        items,
        total,
        limit: params.limit,
        offset: params.offset,
    }))
}

/// Verify commitment chain integrity
pub async fn verify_chain(
    State(state): State<AppState>,
    Path(commitment_id): Path<String>,
    Query(params): Query<VerifyChainParams>,
) -> ApiResult<Json<serde_json::Value>> {
    let valid = state
        .causality
        .verify_chain(&commitment_id, params.depth)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(serde_json::json!({
        "commitment_id": commitment_id,
        "valid": valid,
        "depth_checked": params.depth.unwrap_or(1000)
    })))
}

/// Get batch snapshot by sequence number
pub async fn get_batch_snapshot(
    State(state): State<AppState>,
    Path(sequence): Path<u64>,
) -> ApiResult<Json<BatchSnapshotResponse>> {
    let snapshot = state
        .causality
        .get_batch_snapshot(sequence)
        .await
        .map_err(ApiError::Ledger)?
        .ok_or_else(|| ApiError::NotFound(format!("Batch {} not found", sequence)))?;

    Ok(Json(BatchSnapshotResponse {
        snapshot_id: snapshot.snapshot_id,
        batch_root: snapshot.batch_root.to_hex(),
        batch_sequence_no: snapshot.batch_sequence_no,
        time_window_start: snapshot.time_window_start,
        time_window_end: snapshot.time_window_end,
        parent_batch_root: snapshot.parent_batch_root.map(|d| d.to_hex()),
        signer_set_version: snapshot.signer_set_version,
        signature_bitmap: snapshot.signature_bitmap,
        threshold_proof: snapshot.threshold_proof,
    }))
}

// Helper types and functions

#[derive(Debug, serde::Deserialize)]
pub struct VerifyChainParams {
    pub depth: Option<u32>,
}

fn parse_scope_type(s: &str) -> ApiResult<ScopeType> {
    match s {
        "akn_batch" => Ok(ScopeType::AknBatch),
        "consent_batch" => Ok(ScopeType::ConsentBatch),
        "verdict_batch" => Ok(ScopeType::VerdictBatch),
        "dispute_batch" => Ok(ScopeType::DisputeBatch),
        "repair_batch" => Ok(ScopeType::RepairBatch),
        "clawback_batch" => Ok(ScopeType::ClawbackBatch),
        "log_batch" => Ok(ScopeType::LogBatch),
        "trace_batch" => Ok(ScopeType::TraceBatch),
        "backfill_batch" => Ok(ScopeType::BackfillBatch),
        "identity_batch" => Ok(ScopeType::IdentityBatch),
        "covenant_status_batch" => Ok(ScopeType::CovenantStatusBatch),
        _ => Err(ApiError::Validation(format!("Invalid scope type: {}", s))),
    }
}

fn scope_type_to_string(scope: ScopeType) -> &'static str {
    match scope {
        ScopeType::AknBatch => "akn_batch",
        ScopeType::ConsentBatch => "consent_batch",
        ScopeType::VerdictBatch => "verdict_batch",
        ScopeType::DisputeBatch => "dispute_batch",
        ScopeType::RepairBatch => "repair_batch",
        ScopeType::ClawbackBatch => "clawback_batch",
        ScopeType::LogBatch => "log_batch",
        ScopeType::TraceBatch => "trace_batch",
        ScopeType::BackfillBatch => "backfill_batch",
        ScopeType::IdentityBatch => "identity_batch",
        ScopeType::CovenantStatusBatch => "covenant_status_batch",
    }
}

fn commitment_to_response(record: &l0_core::ledger::CommitmentRecord) -> CommitmentResponse {
    CommitmentResponse {
        commitment_id: record.commitment_id.clone(),
        actor_id: record.actor_id.0.clone(),
        scope_type: scope_type_to_string(record.scope_type).to_string(),
        commitment_digest: record.commitment_digest.to_hex(),
        parent_commitment_ref: record.parent_commitment_ref.clone(),
        sequence_no: record.sequence_no,
        created_at: record.created_at,
        receipt_id: record.receipt_id.as_ref().map(|r| r.0.clone()),
    }
}
