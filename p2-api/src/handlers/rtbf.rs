//! RTBF (Right To Be Forgotten) API Handlers
//!
//! REST API endpoints for GDPR/CCPA data deletion requests.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::error::ApiError;
use crate::state::AppState;

/// RTBF request submission
#[derive(Debug, Deserialize)]
pub struct SubmitRtbfRequest {
    /// Subject actor ID
    pub subject_id: String,
    /// Requestor actor ID (may differ from subject)
    pub requestor_id: String,
    /// Deletion scope
    pub scope: RtbfScopeConfig,
    /// Reason for deletion
    pub reason: RtbfReasonConfig,
    /// Authorization proof (optional)
    pub authorization_proof: Option<String>,
}

/// RTBF scope configuration
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RtbfScopeConfig {
    /// Delete all data
    Full,
    /// Selective deletion
    Selective {
        include_resurrection: bool,
        include_evidence: bool,
        include_audit: bool,
        specific_payloads: Vec<String>,
    },
    /// Delete data before a date
    Temporal {
        before: DateTime<Utc>,
    },
}

/// RTBF reason
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RtbfReasonConfig {
    GdprRequest,
    CcpaRequest,
    ConsentWithdrawal,
    DataUnnecessary,
    ObjectionToProcessing,
    UnlawfulProcessing,
    LegalObligation,
    Other { reason: String },
}

/// RTBF request response
#[derive(Debug, Serialize)]
pub struct RtbfRequestResponse {
    pub request_id: String,
    pub subject_id: String,
    pub status: String,
    pub requested_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// RTBF processing result
#[derive(Debug, Serialize)]
pub struct RtbfResultResponse {
    pub request_id: String,
    pub status: String,
    pub tombstoned_count: usize,
    pub retained_count: usize,
    pub retained_reasons: Vec<RetentionReasonInfo>,
    pub processing_duration_ms: u64,
    pub completed_at: DateTime<Utc>,
}

/// Retention reason information
#[derive(Debug, Serialize)]
pub struct RetentionReasonInfo {
    pub ref_id: String,
    pub reason_type: String,
    pub details: String,
}

/// RTBF status response
#[derive(Debug, Serialize)]
pub struct RtbfStatusResponse {
    pub request_id: String,
    pub subject_id: String,
    pub status: String,
    pub requested_at: DateTime<Utc>,
    pub processing_started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub current_phase: Option<String>,
}

/// Query parameters for listing RTBF requests
#[derive(Debug, Deserialize)]
pub struct RtbfListQuery {
    /// Filter by subject ID
    pub subject_id: Option<String>,
    /// Filter by status
    pub status: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
}

fn default_limit() -> usize {
    50
}

/// Submit an RTBF request
///
/// POST /api/v1/rtbf/requests
pub async fn submit_rtbf_request(
    State(_state): State<AppState>,
    Json(request): Json<SubmitRtbfRequest>,
) -> Result<impl IntoResponse, ApiError> {
    info!(
        subject_id = %request.subject_id,
        requestor_id = %request.requestor_id,
        "Submitting RTBF request"
    );

    // Validate request
    if request.subject_id.is_empty() {
        return Err(ApiError::BadRequest("subject_id is required".to_string()));
    }
    if request.requestor_id.is_empty() {
        return Err(ApiError::BadRequest("requestor_id is required".to_string()));
    }

    // TODO: Integrate with RtbfCoordinator
    // For now, return a placeholder response

    let request_id = format!("rtbf:{}", uuid::Uuid::new_v4());
    let now = Utc::now();

    let response = RtbfRequestResponse {
        request_id,
        subject_id: request.subject_id,
        status: "pending".to_string(),
        requested_at: now,
        expires_at: now + chrono::Duration::days(30),
    };

    info!("RTBF request submitted");
    Ok((StatusCode::ACCEPTED, Json(response)))
}

/// Get RTBF request status
///
/// GET /api/v1/rtbf/requests/:request_id
pub async fn get_rtbf_status(
    State(_state): State<AppState>,
    Path(request_id): Path<String>,
) -> Result<Json<RtbfStatusResponse>, ApiError> {
    info!(request_id = %request_id, "Getting RTBF request status");

    // TODO: Query from RtbfCoordinator
    Err(ApiError::NotFound(format!(
        "RTBF request not found: {}",
        request_id
    )))
}

/// Process (execute) an RTBF request
///
/// POST /api/v1/rtbf/requests/:request_id/process
pub async fn process_rtbf_request(
    State(_state): State<AppState>,
    Path(request_id): Path<String>,
) -> Result<Json<RtbfResultResponse>, ApiError> {
    info!(request_id = %request_id, "Processing RTBF request");

    // TODO: Call RtbfCoordinator.process_request()
    Err(ApiError::NotFound(format!(
        "RTBF request not found: {}",
        request_id
    )))
}

/// List RTBF requests
///
/// GET /api/v1/rtbf/requests
pub async fn list_rtbf_requests(
    State(_state): State<AppState>,
    Query(_query): Query<RtbfListQuery>,
) -> Result<Json<Vec<RtbfStatusResponse>>, ApiError> {
    info!("Listing RTBF requests");

    // TODO: Query from RtbfCoordinator
    Ok(Json(vec![]))
}

/// Legal hold check request
#[derive(Debug, Deserialize)]
pub struct CheckLegalHoldRequest {
    pub subject_id: String,
}

/// Legal hold check response
#[derive(Debug, Serialize)]
pub struct LegalHoldCheckResponse {
    pub subject_id: String,
    pub has_active_holds: bool,
    pub active_holds: Vec<LegalHoldInfo>,
    pub rtbf_allowed: bool,
    pub checked_at: DateTime<Utc>,
}

/// Legal hold information
#[derive(Debug, Serialize)]
pub struct LegalHoldInfo {
    pub hold_id: String,
    pub case_id: String,
    pub started_at: DateTime<Utc>,
    pub reason: String,
}

/// Check legal hold status for a subject
///
/// POST /api/v1/rtbf/check-legal-hold
pub async fn check_legal_hold(
    State(_state): State<AppState>,
    Json(request): Json<CheckLegalHoldRequest>,
) -> Result<Json<LegalHoldCheckResponse>, ApiError> {
    info!(subject_id = %request.subject_id, "Checking legal hold status");

    // TODO: Check legal hold status from ledger
    let response = LegalHoldCheckResponse {
        subject_id: request.subject_id,
        has_active_holds: false,
        active_holds: vec![],
        rtbf_allowed: true,
        checked_at: Utc::now(),
    };

    Ok(Json(response))
}

/// Cancel/withdraw an RTBF request
///
/// DELETE /api/v1/rtbf/requests/:request_id
pub async fn cancel_rtbf_request(
    State(_state): State<AppState>,
    Path(request_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    info!(request_id = %request_id, "Cancelling RTBF request");

    // TODO: Cancel request in RtbfCoordinator
    Err(ApiError::NotFound(format!(
        "RTBF request not found: {}",
        request_id
    )))
}

/// Build the RTBF router
pub fn rtbf_router() -> axum::Router<AppState> {
    use axum::routing::{delete, get, post};

    axum::Router::new()
        .route("/requests", post(submit_rtbf_request))
        .route("/requests", get(list_rtbf_requests))
        .route("/requests/:request_id", get(get_rtbf_status))
        .route("/requests/:request_id", delete(cancel_rtbf_request))
        .route("/requests/:request_id/process", post(process_rtbf_request))
        .route("/check-legal-hold", post(check_legal_hold))
}
