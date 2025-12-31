//! Dispute-Resolution Ledger endpoints

use axum::{
    extract::{Path, Query, State},
    Json,
};
use l0_core::ledger::{DisputeLedger, QueryOptions};
use l0_core::types::{
    ActorId, ClawbackStatus, ClawbackType, Digest, DisputePriority, DisputeStatus, VerdictType,
};

use crate::dto::{
    ClawbackResponse, DisputeResponse, FileDisputeRequest, InitiateClawbackRequest,
    IssueVerdictRequest, ListQueryParams, PaginatedResponse, VerdictResponse,
};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// File a new dispute
pub async fn file_dispute(
    State(state): State<AppState>,
    Json(req): Json<FileDisputeRequest>,
) -> ApiResult<Json<DisputeResponse>> {
    let priority = parse_dispute_priority(&req.priority)?;

    let evidence_digest = Digest::from_hex(&req.evidence_digest)
        .map_err(|_| ApiError::Validation("Invalid evidence digest hex".to_string()))?;

    let filed_against: Vec<ActorId> = req.filed_against.iter().map(|s| ActorId(s.clone())).collect();

    let record = state
        .dispute
        .file_dispute(
            &ActorId(req.filed_by),
            filed_against,
            priority,
            req.subject_commitment_ref,
            evidence_digest,
        )
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(dispute_to_response(&record)))
}

/// Get dispute by ID
pub async fn get_dispute(
    State(state): State<AppState>,
    Path(dispute_id): Path<String>,
) -> ApiResult<Json<DisputeResponse>> {
    let record = state
        .dispute
        .get_dispute(&dispute_id)
        .await
        .map_err(ApiError::Ledger)?
        .ok_or_else(|| ApiError::NotFound(format!("Dispute {} not found", dispute_id)))?;

    Ok(Json(dispute_to_response(&record)))
}

/// Update dispute status
pub async fn update_dispute_status(
    State(state): State<AppState>,
    Path(dispute_id): Path<String>,
    Json(req): Json<serde_json::Value>,
) -> ApiResult<Json<serde_json::Value>> {
    let status_str = req
        .get("status")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::Validation("Missing status field".to_string()))?;

    let new_status = parse_dispute_status(status_str)?;

    let receipt_id = state
        .dispute
        .update_dispute_status(&dispute_id, new_status)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(serde_json::json!({
        "receipt_id": receipt_id.0,
        "dispute_id": dispute_id,
        "status": status_str
    })))
}

/// List disputes
pub async fn list_disputes(
    State(state): State<AppState>,
    Query(params): Query<ListQueryParams>,
) -> ApiResult<Json<PaginatedResponse<DisputeResponse>>> {
    let status = params
        .status
        .as_ref()
        .map(|s| parse_dispute_status(s))
        .transpose()?;

    let options = QueryOptions {
        limit: Some(params.limit),
        offset: Some(params.offset),
        ..Default::default()
    };

    let records = state
        .dispute
        .list_disputes(status, None, options)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(PaginatedResponse {
        total: records.len() as u64,
        items: records.iter().map(dispute_to_response).collect(),
        limit: params.limit,
        offset: params.offset,
    }))
}

/// List disputes for actor
pub async fn list_disputes_for_actor(
    State(state): State<AppState>,
    Path((actor_id, role)): Path<(String, String)>,
    Query(params): Query<ListQueryParams>,
) -> ApiResult<Json<PaginatedResponse<DisputeResponse>>> {
    let as_filer = role == "filed";

    let options = QueryOptions {
        limit: Some(params.limit),
        offset: Some(params.offset),
        ..Default::default()
    };

    let records = state
        .dispute
        .list_disputes_for_actor(&ActorId(actor_id), as_filer, options)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(PaginatedResponse {
        total: records.len() as u64,
        items: records.iter().map(dispute_to_response).collect(),
        limit: params.limit,
        offset: params.offset,
    }))
}

/// Issue verdict for dispute
pub async fn issue_verdict(
    State(state): State<AppState>,
    Path(dispute_id): Path<String>,
    Json(req): Json<IssueVerdictRequest>,
) -> ApiResult<Json<VerdictResponse>> {
    let verdict_type = parse_verdict_type(&req.verdict_type)?;

    let verdict_digest = Digest::from_hex(&req.verdict_digest)
        .map_err(|_| ApiError::Validation("Invalid verdict digest hex".to_string()))?;

    let rationale_digest = Digest::from_hex(&req.rationale_digest)
        .map_err(|_| ApiError::Validation("Invalid rationale digest hex".to_string()))?;

    let remedies_digest = req
        .remedies_digest
        .as_ref()
        .map(|d| Digest::from_hex(d))
        .transpose()
        .map_err(|_| ApiError::Validation("Invalid remedies digest hex".to_string()))?;

    let record = state
        .dispute
        .issue_verdict(
            &dispute_id,
            verdict_type,
            verdict_digest,
            rationale_digest,
            remedies_digest,
            req.issued_by,
            req.appeal_deadline,
        )
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(verdict_to_response(&record)))
}

/// Get verdict by ID
pub async fn get_verdict(
    State(state): State<AppState>,
    Path(verdict_id): Path<String>,
) -> ApiResult<Json<VerdictResponse>> {
    let record = state
        .dispute
        .get_verdict(&verdict_id)
        .await
        .map_err(ApiError::Ledger)?
        .ok_or_else(|| ApiError::NotFound(format!("Verdict {} not found", verdict_id)))?;

    Ok(Json(verdict_to_response(&record)))
}

/// Get verdict for dispute
pub async fn get_verdict_for_dispute(
    State(state): State<AppState>,
    Path(dispute_id): Path<String>,
) -> ApiResult<Json<VerdictResponse>> {
    let record = state
        .dispute
        .get_verdict_for_dispute(&dispute_id)
        .await
        .map_err(ApiError::Ledger)?
        .ok_or_else(|| ApiError::NotFound(format!("No verdict for dispute {}", dispute_id)))?;

    Ok(Json(verdict_to_response(&record)))
}

/// Initiate clawback
pub async fn initiate_clawback(
    State(state): State<AppState>,
    Json(req): Json<InitiateClawbackRequest>,
) -> ApiResult<Json<ClawbackResponse>> {
    let clawback_type = parse_clawback_type(&req.clawback_type)?;

    let compensation_digest = req
        .compensation_digest
        .as_ref()
        .map(|d| Digest::from_hex(d))
        .transpose()
        .map_err(|_| ApiError::Validation("Invalid compensation digest hex".to_string()))?;

    let affected_actors: Vec<ActorId> = req.affected_actors.iter().map(|s| ActorId(s.clone())).collect();

    let record = state
        .dispute
        .initiate_clawback(
            &req.verdict_id,
            clawback_type,
            req.target_commitment_refs,
            affected_actors,
            compensation_digest,
        )
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(clawback_to_response(&record)))
}

/// Execute clawback
pub async fn execute_clawback(
    State(state): State<AppState>,
    Path(clawback_id): Path<String>,
    Json(req): Json<serde_json::Value>,
) -> ApiResult<Json<serde_json::Value>> {
    let execution_digest_str = req
        .get("execution_digest")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::Validation("Missing execution_digest field".to_string()))?;

    let execution_digest = Digest::from_hex(execution_digest_str)
        .map_err(|_| ApiError::Validation("Invalid execution digest hex".to_string()))?;

    let receipt_id = state
        .dispute
        .execute_clawback(&clawback_id, execution_digest)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(serde_json::json!({
        "receipt_id": receipt_id.0,
        "clawback_id": clawback_id,
        "status": "executed"
    })))
}

/// Get clawback by ID
pub async fn get_clawback(
    State(state): State<AppState>,
    Path(clawback_id): Path<String>,
) -> ApiResult<Json<ClawbackResponse>> {
    let record = state
        .dispute
        .get_clawback(&clawback_id)
        .await
        .map_err(ApiError::Ledger)?
        .ok_or_else(|| ApiError::NotFound(format!("Clawback {} not found", clawback_id)))?;

    Ok(Json(clawback_to_response(&record)))
}

/// List clawbacks
pub async fn list_clawbacks(
    State(state): State<AppState>,
    Query(params): Query<ListQueryParams>,
) -> ApiResult<Json<PaginatedResponse<ClawbackResponse>>> {
    let status = params
        .status
        .as_ref()
        .map(|s| parse_clawback_status(s))
        .transpose()?;

    let options = QueryOptions {
        limit: Some(params.limit),
        offset: Some(params.offset),
        ..Default::default()
    };

    let records = state
        .dispute
        .list_clawbacks(status, options)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(PaginatedResponse {
        total: records.len() as u64,
        items: records.iter().map(clawback_to_response).collect(),
        limit: params.limit,
        offset: params.offset,
    }))
}

// Helper functions

fn parse_dispute_priority(s: &str) -> ApiResult<DisputePriority> {
    match s {
        "normal" => Ok(DisputePriority::Normal),
        "urgent" => Ok(DisputePriority::Urgent),
        "critical" => Ok(DisputePriority::Critical),
        _ => Err(ApiError::Validation(format!("Invalid dispute priority: {}", s))),
    }
}

fn parse_dispute_status(s: &str) -> ApiResult<DisputeStatus> {
    match s {
        "filed" => Ok(DisputeStatus::Filed),
        "under_review" => Ok(DisputeStatus::UnderReview),
        "verdict_issued" => Ok(DisputeStatus::VerdictIssued),
        "repair_in_progress" => Ok(DisputeStatus::RepairInProgress),
        "resolved" => Ok(DisputeStatus::Resolved),
        "dismissed" => Ok(DisputeStatus::Dismissed),
        _ => Err(ApiError::Validation(format!("Invalid dispute status: {}", s))),
    }
}

fn parse_verdict_type(s: &str) -> ApiResult<VerdictType> {
    match s {
        "in_favor" => Ok(VerdictType::InFavor),
        "against" => Ok(VerdictType::Against),
        "mixed" => Ok(VerdictType::Mixed),
        "dismissed" => Ok(VerdictType::Dismissed),
        "inconclusive" => Ok(VerdictType::Inconclusive),
        _ => Err(ApiError::Validation(format!("Invalid verdict type: {}", s))),
    }
}

fn parse_clawback_type(s: &str) -> ApiResult<ClawbackType> {
    match s {
        "full_reverse" => Ok(ClawbackType::FullReverse),
        "partial_reverse" => Ok(ClawbackType::PartialReverse),
        "compensation" => Ok(ClawbackType::Compensation),
        "penalty" => Ok(ClawbackType::Penalty),
        _ => Err(ApiError::Validation(format!("Invalid clawback type: {}", s))),
    }
}

fn parse_clawback_status(s: &str) -> ApiResult<ClawbackStatus> {
    match s {
        "pending" => Ok(ClawbackStatus::Pending),
        "approved" => Ok(ClawbackStatus::Approved),
        "executed" => Ok(ClawbackStatus::Executed),
        "failed" => Ok(ClawbackStatus::Failed),
        "cancelled" => Ok(ClawbackStatus::Cancelled),
        _ => Err(ApiError::Validation(format!("Invalid clawback status: {}", s))),
    }
}

fn dispute_to_response(record: &l0_core::types::DisputeRecord) -> DisputeResponse {
    DisputeResponse {
        dispute_id: record.dispute_id.clone(),
        filed_by: record.filed_by.0.clone(),
        filed_against: record.filed_against.iter().map(|a| a.0.clone()).collect(),
        priority: match record.priority {
            DisputePriority::Normal => "normal",
            DisputePriority::Urgent => "urgent",
            DisputePriority::Critical => "critical",
        }
        .to_string(),
        status: match record.status {
            DisputeStatus::Filed => "filed",
            DisputeStatus::UnderReview => "under_review",
            DisputeStatus::VerdictIssued => "verdict_issued",
            DisputeStatus::RepairInProgress => "repair_in_progress",
            DisputeStatus::Resolved => "resolved",
            DisputeStatus::Dismissed => "dismissed",
        }
        .to_string(),
        subject_commitment_ref: record.subject_commitment_ref.clone(),
        evidence_digest: record.evidence_digest.to_hex(),
        filed_at: record.filed_at,
        last_updated: record.last_updated,
        receipt_id: record.receipt_id.as_ref().map(|r| r.0.clone()),
    }
}

fn verdict_to_response(record: &l0_core::types::VerdictRecord) -> VerdictResponse {
    VerdictResponse {
        verdict_id: record.verdict_id.clone(),
        dispute_id: record.dispute_id.clone(),
        verdict_type: match record.verdict_type {
            VerdictType::InFavor => "in_favor",
            VerdictType::Against => "against",
            VerdictType::Mixed => "mixed",
            VerdictType::Dismissed => "dismissed",
            VerdictType::Inconclusive => "inconclusive",
        }
        .to_string(),
        verdict_digest: record.verdict_digest.to_hex(),
        rationale_digest: record.rationale_digest.to_hex(),
        remedies_digest: record.remedies_digest.as_ref().map(|d| d.to_hex()),
        issued_by: record.issued_by.clone(),
        issued_at: record.issued_at,
        effective_at: record.effective_at,
        appeal_deadline: record.appeal_deadline,
        receipt_id: record.receipt_id.as_ref().map(|r| r.0.clone()),
    }
}

fn clawback_to_response(record: &l0_core::types::ClawbackRecord) -> ClawbackResponse {
    ClawbackResponse {
        clawback_id: record.clawback_id.clone(),
        verdict_id: record.verdict_id.clone(),
        clawback_type: match record.clawback_type {
            ClawbackType::FullReverse => "full_reverse",
            ClawbackType::PartialReverse => "partial_reverse",
            ClawbackType::Compensation => "compensation",
            ClawbackType::Penalty => "penalty",
        }
        .to_string(),
        status: match record.status {
            ClawbackStatus::Pending => "pending",
            ClawbackStatus::Approved => "approved",
            ClawbackStatus::Executed => "executed",
            ClawbackStatus::Failed => "failed",
            ClawbackStatus::Cancelled => "cancelled",
        }
        .to_string(),
        clawback_digest: record.clawback_digest.to_hex(),
        target_commitment_refs: record.target_commitment_refs.clone(),
        affected_actors: record.affected_actors.iter().map(|a| a.0.clone()).collect(),
        compensation_digest: record.compensation_digest.as_ref().map(|d| d.to_hex()),
        initiated_at: record.initiated_at,
        executed_at: record.executed_at,
        receipt_id: record.receipt_id.as_ref().map(|r| r.0.clone()),
    }
}
