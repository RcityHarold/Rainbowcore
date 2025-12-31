//! Policy-Consent Ledger endpoints

use axum::{
    extract::{Path, Query, State},
    Json,
};
use l0_core::ledger::{ConsentLedger, QueryOptions};
use l0_core::types::{ActorId, ConsentScope, ConsentStatus, ConsentType, Digest};

use crate::dto::{
    AccessTicketResponse, ConsentResponse, GrantConsentRequest, IssueTicketRequest,
    ListQueryParams, PaginatedResponse, RevokeConsentRequest, VerifyConsentRequest,
    VerifyConsentResponse,
};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Grant consent
pub async fn grant_consent(
    State(state): State<AppState>,
    Json(req): Json<GrantConsentRequest>,
) -> ApiResult<Json<ConsentResponse>> {
    let consent_type = parse_consent_type(&req.consent_type)?;

    let terms_digest = Digest::from_hex(&req.terms_digest)
        .map_err(|_| ApiError::Validation("Invalid terms digest hex".to_string()))?;

    let scope = ConsentScope {
        resource_type: req.resource_type,
        resource_id: req.resource_id,
        actions: req.actions,
        constraints_digest: None,
    };

    let record = state
        .consent
        .grant_consent(
            consent_type,
            &ActorId(req.grantor),
            &ActorId(req.grantee),
            scope,
            terms_digest,
            req.expires_at,
        )
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(consent_to_response(&record)))
}

/// Revoke consent
pub async fn revoke_consent(
    State(state): State<AppState>,
    Path(consent_id): Path<String>,
    Json(req): Json<RevokeConsentRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let reason_digest = req
        .reason_digest
        .as_ref()
        .map(|d| Digest::from_hex(d))
        .transpose()
        .map_err(|_| ApiError::Validation("Invalid reason digest hex".to_string()))?;

    let receipt_id = state
        .consent
        .revoke_consent(&consent_id, reason_digest)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(serde_json::json!({
        "receipt_id": receipt_id.0,
        "consent_id": consent_id,
        "status": "revoked"
    })))
}

/// Get consent by ID
pub async fn get_consent(
    State(state): State<AppState>,
    Path(consent_id): Path<String>,
) -> ApiResult<Json<ConsentResponse>> {
    let record = state
        .consent
        .get_consent(&consent_id)
        .await
        .map_err(ApiError::Ledger)?
        .ok_or_else(|| ApiError::NotFound(format!("Consent {} not found", consent_id)))?;

    Ok(Json(consent_to_response(&record)))
}

/// Verify consent
pub async fn verify_consent(
    State(state): State<AppState>,
    Json(req): Json<VerifyConsentRequest>,
) -> ApiResult<Json<VerifyConsentResponse>> {
    let result = state
        .consent
        .verify_consent(
            &ActorId(req.grantor),
            &ActorId(req.grantee),
            &req.action,
            &req.resource_type,
        )
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(VerifyConsentResponse {
        valid: result.valid,
        consent_ref: result.consent_ref,
        reason: result.reason,
    }))
}

/// List granted consents
pub async fn list_granted_consents(
    State(state): State<AppState>,
    Path(grantor_id): Path<String>,
    Query(params): Query<ListQueryParams>,
) -> ApiResult<Json<PaginatedResponse<ConsentResponse>>> {
    let status = params
        .status
        .as_ref()
        .map(|s| parse_consent_status(s))
        .transpose()?;

    let options = QueryOptions {
        limit: Some(params.limit),
        offset: Some(params.offset),
        ..Default::default()
    };

    let records = state
        .consent
        .list_granted_consents(&ActorId(grantor_id), status, options)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(PaginatedResponse {
        total: records.len() as u64,
        items: records.iter().map(consent_to_response).collect(),
        limit: params.limit,
        offset: params.offset,
    }))
}

/// List received consents
pub async fn list_received_consents(
    State(state): State<AppState>,
    Path(grantee_id): Path<String>,
    Query(params): Query<ListQueryParams>,
) -> ApiResult<Json<PaginatedResponse<ConsentResponse>>> {
    let status = params
        .status
        .as_ref()
        .map(|s| parse_consent_status(s))
        .transpose()?;

    let options = QueryOptions {
        limit: Some(params.limit),
        offset: Some(params.offset),
        ..Default::default()
    };

    let records = state
        .consent
        .list_received_consents(&ActorId(grantee_id), status, options)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(PaginatedResponse {
        total: records.len() as u64,
        items: records.iter().map(consent_to_response).collect(),
        limit: params.limit,
        offset: params.offset,
    }))
}

/// Issue access ticket
pub async fn issue_ticket(
    State(state): State<AppState>,
    Json(req): Json<IssueTicketRequest>,
) -> ApiResult<Json<AccessTicketResponse>> {
    let ticket = state
        .consent
        .issue_ticket(
            &req.consent_ref,
            &ActorId(req.holder),
            req.target_resource,
            req.permissions,
            req.valid_until,
            req.one_time,
        )
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(ticket_to_response(&ticket)))
}

/// Use ticket
pub async fn use_ticket(
    State(state): State<AppState>,
    Path(ticket_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let success = state
        .consent
        .use_ticket(&ticket_id)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(serde_json::json!({
        "ticket_id": ticket_id,
        "success": success
    })))
}

/// Get ticket by ID
pub async fn get_ticket(
    State(state): State<AppState>,
    Path(ticket_id): Path<String>,
) -> ApiResult<Json<AccessTicketResponse>> {
    let ticket = state
        .consent
        .get_ticket(&ticket_id)
        .await
        .map_err(ApiError::Ledger)?
        .ok_or_else(|| ApiError::NotFound(format!("Ticket {} not found", ticket_id)))?;

    Ok(Json(ticket_to_response(&ticket)))
}

// Helper functions

fn parse_consent_type(s: &str) -> ApiResult<ConsentType> {
    match s {
        "explicit" => Ok(ConsentType::Explicit),
        "implied" => Ok(ConsentType::Implied),
        "delegated" => Ok(ConsentType::Delegated),
        "emergency" => Ok(ConsentType::Emergency),
        _ => Err(ApiError::Validation(format!("Invalid consent type: {}", s))),
    }
}

fn parse_consent_status(s: &str) -> ApiResult<ConsentStatus> {
    match s {
        "active" => Ok(ConsentStatus::Active),
        "expired" => Ok(ConsentStatus::Expired),
        "revoked" => Ok(ConsentStatus::Revoked),
        "superseded" => Ok(ConsentStatus::Superseded),
        _ => Err(ApiError::Validation(format!("Invalid consent status: {}", s))),
    }
}

fn consent_to_response(record: &l0_core::types::ConsentRecord) -> ConsentResponse {
    ConsentResponse {
        consent_id: record.consent_id.clone(),
        consent_type: match record.consent_type {
            ConsentType::Explicit => "explicit",
            ConsentType::Implied => "implied",
            ConsentType::Delegated => "delegated",
            ConsentType::Emergency => "emergency",
        }
        .to_string(),
        grantor: record.grantor.0.clone(),
        grantee: record.grantee.0.clone(),
        resource_type: record.scope.resource_type.clone(),
        resource_id: record.scope.resource_id.clone(),
        actions: record.scope.actions.clone(),
        status: match record.status {
            ConsentStatus::Active => "active",
            ConsentStatus::Expired => "expired",
            ConsentStatus::Revoked => "revoked",
            ConsentStatus::Superseded => "superseded",
        }
        .to_string(),
        terms_digest: record.terms_digest.to_hex(),
        granted_at: record.granted_at,
        expires_at: record.expires_at,
        revoked_at: record.revoked_at,
        receipt_id: record.receipt_id.as_ref().map(|r| r.0.clone()),
    }
}

fn ticket_to_response(ticket: &l0_core::types::AccessTicket) -> AccessTicketResponse {
    AccessTicketResponse {
        ticket_id: ticket.ticket_id.clone(),
        consent_ref: ticket.consent_ref.clone(),
        holder: ticket.holder.0.clone(),
        target_resource: ticket.target_resource.clone(),
        permissions: ticket.permissions.clone(),
        issued_at: ticket.issued_at,
        valid_from: ticket.valid_from,
        valid_until: ticket.valid_until,
        one_time: ticket.one_time,
        used_at: ticket.used_at,
        ticket_digest: ticket.ticket_digest.to_hex(),
    }
}
