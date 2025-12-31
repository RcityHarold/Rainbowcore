//! Backfill Ledger endpoints
//!
//! Endpoints for managing B-to-A level evidence upgrades.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use l0_core::ledger::{BackfillLedger, CreateBackfillRequest};
use l0_core::types::{ActorId, BackfillStatus, Digest};

use crate::dto::{ListQueryParams, PaginatedResponse};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ============ DTOs ============

/// Create backfill request
#[derive(Debug, Deserialize)]
pub struct CreateBackfillRequestDto {
    /// Actor ID
    pub actor_id: String,
    /// Start digest
    pub start_digest: String,
    /// Start sequence number
    pub start_sequence_no: u64,
    /// End digest
    pub end_digest: String,
    /// End sequence number
    pub end_sequence_no: u64,
    /// TipWitness reference
    pub tip_witness_ref: String,
}

/// Backfill request response
#[derive(Debug, Serialize)]
pub struct BackfillRequestResponse {
    pub request_id: String,
    pub actor_id: String,
    pub status: String,
    pub start_digest: String,
    pub start_sequence_no: u64,
    pub end_digest: String,
    pub end_sequence_no: u64,
    pub tip_witness_ref: String,
    pub requested_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub receipt_id: Option<String>,
}

/// Backfill plan response
#[derive(Debug, Serialize)]
pub struct BackfillPlanResponse {
    pub plan_id: String,
    pub request_ref: String,
    pub item_count: usize,
    pub estimated_fee: String,
    pub gap_count: usize,
    pub continuity_result: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Gap detection response
#[derive(Debug, Serialize)]
pub struct GapResponse {
    pub gap_id: String,
    pub start_sequence: u64,
    pub end_sequence: u64,
    pub gap_type: String,
    pub acceptable: bool,
}

/// Continuity check response
#[derive(Debug, Serialize)]
pub struct ContinuityCheckResponse {
    pub result: String,
    pub gaps: Vec<GapResponse>,
}

/// Cancel request
#[derive(Debug, Deserialize)]
pub struct CancelBackfillRequest {
    pub reason: String,
}

// ============ Endpoints ============

/// Create backfill request
pub async fn create_request(
    State(state): State<AppState>,
    Json(req): Json<CreateBackfillRequestDto>,
) -> ApiResult<Json<BackfillRequestResponse>> {
    let start_digest = Digest::from_hex(&req.start_digest)
        .map_err(|_| ApiError::Validation("Invalid start digest hex".to_string()))?;

    let end_digest = Digest::from_hex(&req.end_digest)
        .map_err(|_| ApiError::Validation("Invalid end digest hex".to_string()))?;

    let create_req = CreateBackfillRequest {
        actor_id: ActorId(req.actor_id),
        start_digest,
        start_sequence_no: req.start_sequence_no,
        end_digest,
        end_sequence_no: req.end_sequence_no,
        tip_witness_ref: req.tip_witness_ref,
        scope_filter: None,
    };

    let request = state
        .backfill
        .create_request(create_req)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(request_to_response(&request)))
}

/// Get backfill request by ID
pub async fn get_request(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
) -> ApiResult<Json<BackfillRequestResponse>> {
    let request = state
        .backfill
        .get_request(&request_id)
        .await
        .map_err(ApiError::Ledger)?
        .ok_or_else(|| ApiError::NotFound(format!("Request {} not found", request_id)))?;

    Ok(Json(request_to_response(&request)))
}

/// List backfill requests for an actor
pub async fn list_requests(
    State(state): State<AppState>,
    Path(actor_id): Path<String>,
    Query(params): Query<ListQueryParams>,
) -> ApiResult<Json<PaginatedResponse<BackfillRequestResponse>>> {
    let status = params.status.as_ref().map(|s| str_to_status(s));

    let requests = state
        .backfill
        .list_requests(&ActorId(actor_id), status)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(PaginatedResponse {
        total: requests.len() as u64,
        items: requests.iter().map(request_to_response).collect(),
        limit: params.limit,
        offset: params.offset,
    }))
}

/// Generate backfill plan
pub async fn generate_plan(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
) -> ApiResult<Json<BackfillPlanResponse>> {
    let plan = state
        .backfill
        .generate_plan(&request_id)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(BackfillPlanResponse {
        plan_id: plan.plan_id,
        request_ref: plan.request_ref,
        item_count: plan.anchor_sequence.len(),
        estimated_fee: plan.estimated_fee,
        gap_count: plan.gaps.len(),
        continuity_result: continuity_to_str(&plan.continuity_result).to_string(),
        created_at: plan.created_at,
        expires_at: plan.expires_at,
    }))
}

/// Execute backfill plan
pub async fn execute_plan(
    State(state): State<AppState>,
    Path(plan_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let receipt = state
        .backfill
        .execute_plan(&plan_id)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(serde_json::json!({
        "backfill_receipt_id": receipt.backfill_receipt_id,
        "request_ref": receipt.request_ref,
        "plan_ref": receipt.plan_ref,
        "actor_id": receipt.actor_id.0,
        "objects_anchored": receipt.objects_anchored,
        "total_fee_paid": receipt.total_fee_paid,
        "continuity_result": continuity_to_str(&receipt.continuity_result),
        "started_at": receipt.started_at,
        "completed_at": receipt.completed_at,
        "receipt_id": receipt.receipt_id.0,
    })))
}

/// Detect gaps in actor's commitment chain
pub async fn detect_gaps(
    State(state): State<AppState>,
    Path(actor_id): Path<String>,
    Query(params): Query<GapDetectionParams>,
) -> ApiResult<Json<Vec<GapResponse>>> {
    let gaps = state
        .backfill
        .detect_gaps(&ActorId(actor_id), params.start_sequence, params.end_sequence)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(gaps.iter().map(gap_to_response).collect()))
}

/// Verify continuity of actor's commitment chain
pub async fn verify_continuity(
    State(state): State<AppState>,
    Path(actor_id): Path<String>,
    Query(params): Query<GapDetectionParams>,
) -> ApiResult<Json<ContinuityCheckResponse>> {
    let actor = ActorId(actor_id);

    let result = state
        .backfill
        .verify_continuity(&actor, params.start_sequence, params.end_sequence)
        .await
        .map_err(ApiError::Ledger)?;

    let gaps = state
        .backfill
        .detect_gaps(&actor, params.start_sequence, params.end_sequence)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(ContinuityCheckResponse {
        result: continuity_to_str(&result).to_string(),
        gaps: gaps.iter().map(gap_to_response).collect(),
    }))
}

/// Cancel backfill request
pub async fn cancel_request(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
    Json(req): Json<CancelBackfillRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    state
        .backfill
        .cancel_request(&request_id, req.reason)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(serde_json::json!({
        "success": true,
        "request_id": request_id,
        "status": "cancelled"
    })))
}

/// Get backfill history for an actor
pub async fn get_history(
    State(state): State<AppState>,
    Path(actor_id): Path<String>,
    Query(params): Query<ListQueryParams>,
) -> ApiResult<Json<Vec<serde_json::Value>>> {
    let receipts = state
        .backfill
        .get_backfill_history(&ActorId(actor_id), params.limit)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(
        receipts
            .iter()
            .map(|r| {
                serde_json::json!({
                    "backfill_receipt_id": r.backfill_receipt_id,
                    "request_ref": r.request_ref,
                    "objects_anchored": r.objects_anchored,
                    "total_fee_paid": r.total_fee_paid,
                    "continuity_result": continuity_to_str(&r.continuity_result),
                    "completed_at": r.completed_at,
                })
            })
            .collect(),
    ))
}

// ============ Query Params ============

#[derive(Debug, Deserialize)]
pub struct GapDetectionParams {
    pub start_sequence: u64,
    pub end_sequence: u64,
}

// ============ Helpers ============

fn request_to_response(request: &l0_core::types::BackfillRequest) -> BackfillRequestResponse {
    BackfillRequestResponse {
        request_id: request.request_id.clone(),
        actor_id: request.actor_id.0.clone(),
        status: status_to_str(&request.status).to_string(),
        start_digest: request.start_digest.to_hex(),
        start_sequence_no: request.start_sequence_no,
        end_digest: request.end_digest.to_hex(),
        end_sequence_no: request.end_sequence_no,
        tip_witness_ref: request.tip_witness_ref.clone(),
        requested_at: request.requested_at,
        completed_at: request.completed_at,
        receipt_id: request.receipt_id.as_ref().map(|r| r.0.clone()),
    }
}

fn gap_to_response(gap: &l0_core::types::GapRecord) -> GapResponse {
    GapResponse {
        gap_id: gap.gap_id.clone(),
        start_sequence: gap.start_sequence,
        end_sequence: gap.end_sequence,
        gap_type: gap_type_to_str(&gap.gap_type).to_string(),
        acceptable: gap.acceptable,
    }
}

fn status_to_str(status: &BackfillStatus) -> &'static str {
    match status {
        BackfillStatus::Requested => "requested",
        BackfillStatus::PlanGenerated => "plan_generated",
        BackfillStatus::InProgress => "in_progress",
        BackfillStatus::Completed => "completed",
        BackfillStatus::Failed => "failed",
        BackfillStatus::Cancelled => "cancelled",
    }
}

fn str_to_status(s: &str) -> BackfillStatus {
    match s {
        "requested" => BackfillStatus::Requested,
        "plan_generated" => BackfillStatus::PlanGenerated,
        "in_progress" => BackfillStatus::InProgress,
        "completed" => BackfillStatus::Completed,
        "failed" => BackfillStatus::Failed,
        "cancelled" => BackfillStatus::Cancelled,
        _ => BackfillStatus::Requested,
    }
}

fn gap_type_to_str(gap_type: &l0_core::types::GapType) -> &'static str {
    use l0_core::types::GapType;
    match gap_type {
        GapType::SequenceGap => "sequence_gap",
        GapType::HashChainBreak => "hash_chain_break",
        GapType::TimeGap => "time_gap",
        GapType::Unknown => "unknown",
    }
}

fn continuity_to_str(result: &l0_core::types::ContinuityCheckResult) -> &'static str {
    use l0_core::types::ContinuityCheckResult;
    match result {
        ContinuityCheckResult::Pass => "pass",
        ContinuityCheckResult::PassWithGaps => "pass_with_gaps",
        ContinuityCheckResult::Fail => "fail",
    }
}
