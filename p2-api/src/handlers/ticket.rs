//! Ticket Handlers
//!
//! HTTP handlers for access ticket operations.
//!
//! # Mandatory Audit Enforcement (ISSUE-003)
//!
//! All ticket-based payload access MUST be audited BEFORE the actual data read.
//! This is enforced via `MandatoryAuditGuard` which ensures:
//! 1. Audit log is written BEFORE data read
//! 2. If audit write fails, data access is BLOCKED
//! 3. Operation completion status is tracked

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{
    dto::{AccessTicketResponse, CreateAccessTicketRequest},
    error::{ApiError, ApiResult},
    state::AppState,
};
use l0_core::types::{ActorId, Digest};
use p2_core::ledger::{AuditLedger, TicketLedger};
use p2_core::types::{
    AuditLogWriter, DecryptAuditLog, DecryptOutcome, MandatoryAuditGuard,
    PayloadSelector, TicketPermission, TicketRequest, TicketStatus,
    create_decrypt_audit_guard,
};
use p2_core::OperationType;
use p2_storage::P2StorageBackend;

/// Parse permission string to TicketPermission
fn parse_permission(p: &str) -> Option<TicketPermission> {
    match p.to_lowercase().as_str() {
        "read" => Some(TicketPermission::Read),
        "export" => Some(TicketPermission::Export),
        "verify" => Some(TicketPermission::Verify),
        "audit" => Some(TicketPermission::Audit),
        "delegate" => Some(TicketPermission::Delegate),
        _ => None,
    }
}

/// Convert TicketPermission to string
fn permission_to_string(p: &TicketPermission) -> String {
    match p {
        TicketPermission::Read => "read".to_string(),
        TicketPermission::Export => "export".to_string(),
        TicketPermission::Verify => "verify".to_string(),
        TicketPermission::Audit => "audit".to_string(),
        TicketPermission::Delegate => "delegate".to_string(),
    }
}

/// Create an access ticket
pub async fn create_ticket(
    State(state): State<AppState>,
    Json(request): Json<CreateAccessTicketRequest>,
) -> ApiResult<(StatusCode, Json<AccessTicketResponse>)> {
    // =========================================================================
    // ISSUE-015: Check degraded mode before ticket issuance
    // =========================================================================
    // Ticket issuance requires consent in degraded mode per degradation matrix
    state.check_degraded_mode_operation(OperationType::IssueTicket)
        .await
        .map_err(|e| {
            tracing::warn!(
                holder_id = %request.holder_id,
                error = %e,
                "Ticket creation blocked/requires consent due to degraded mode"
            );
            ApiError::Unavailable(format!(
                "Ticket creation unavailable: {}",
                e
            ))
        })?;

    // Validate that all referenced payloads exist
    for ref_id in &request.ref_ids {
        state.storage.get_metadata(ref_id).await.map_err(|e| match &e {
            p2_storage::StorageError::NotFound(_) => {
                ApiError::not_found(format!("Payload not found: {}", ref_id))
            }
            _ => ApiError::from(e),
        })?;
    }

    // Parse permissions
    let permissions: Vec<TicketPermission> = request
        .permissions
        .iter()
        .filter_map(|p| parse_permission(p))
        .collect();

    if permissions.is_empty() {
        return Err(ApiError::validation("No valid permissions specified"));
    }

    // Parse selector - default to DigestOnly (most restrictive)
    let selector = match &request.selector {
        None => {
            tracing::info!("No selector specified, defaulting to DigestOnly (minimal disclosure)");
            PayloadSelector::digest_only()
        }
        Some(crate::dto::SelectorConfig::Full) => {
            tracing::warn!("Full selector requested - maximum disclosure!");
            PayloadSelector::full()
        }
        Some(crate::dto::SelectorConfig::Span { start, end }) => {
            PayloadSelector::span(*start, *end)
        }
        Some(crate::dto::SelectorConfig::ByteRange { start_byte, end_byte }) => {
            PayloadSelector::byte_range(*start_byte, *end_byte)
        }
        Some(crate::dto::SelectorConfig::Fields { field_paths }) => {
            let paths: Vec<&str> = field_paths.iter().map(|s| s.as_str()).collect();
            PayloadSelector::fields(paths)
        }
        Some(crate::dto::SelectorConfig::DigestOnly) => {
            PayloadSelector::digest_only()
        }
        Some(crate::dto::SelectorConfig::Redacted { redaction_policy }) => {
            PayloadSelector::redacted(redaction_policy)
        }
    };

    tracing::info!(
        selector_type = ?selector.selector_type,
        disclosure_level = selector.disclosure_level(),
        "Ticket selector configured"
    );

    // Create ticket request
    let ticket_request = TicketRequest {
        consent_ref: format!("consent:{}", uuid::Uuid::new_v4()),
        holder: ActorId::new(&request.holder_id),
        target_resource_ref: request.ref_ids.join(","),
        permissions,
        selector,
        validity_seconds: request.validity_seconds,
        purpose: request.purpose.clone(),
        one_time: false,
    };

    // Issue ticket through ledger
    let issuer = ActorId::new("system");
    let ticket = state
        .ticket_ledger
        .issue_ticket(ticket_request, &issuer)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to issue ticket: {}", e)))?;

    let response = AccessTicketResponse {
        ticket_id: ticket.ticket_id.clone(),
        holder_id: request.holder_id,
        expires_at: ticket.valid_until,
        permissions: request.permissions,
        payload_count: request.ref_ids.len(),
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// Get ticket by ID
pub async fn get_ticket(
    State(state): State<AppState>,
    Path(ticket_id): Path<String>,
) -> ApiResult<Json<AccessTicketResponse>> {
    let ticket = state
        .ticket_ledger
        .get_ticket(&ticket_id)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to retrieve ticket: {}", e)))?
        .ok_or_else(|| ApiError::not_found(format!("Ticket not found: {}", ticket_id)))?;

    let permissions: Vec<String> = ticket
        .permissions
        .iter()
        .map(permission_to_string)
        .collect();

    // Count payloads from target resource ref
    let payload_count = ticket.target_resource_ref.split(',').count();

    let response = AccessTicketResponse {
        ticket_id: ticket.ticket_id,
        holder_id: ticket.holder.0,
        expires_at: ticket.valid_until,
        permissions,
        payload_count,
    };

    Ok(Json(response))
}

/// Ticket validation response
#[derive(Debug, Serialize)]
pub struct TicketValidationResponse {
    /// Ticket ID
    pub ticket_id: String,
    /// Whether the ticket is valid
    pub is_valid: bool,
    /// Ticket status
    pub status: TicketStatus,
    /// Reason if invalid
    pub reason: Option<String>,
    /// Remaining uses (if limited)
    pub remaining_uses: Option<u32>,
    /// Expires at
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Validate a ticket
pub async fn validate_ticket(
    State(state): State<AppState>,
    Path(ticket_id): Path<String>,
) -> ApiResult<Json<TicketValidationResponse>> {
    let ticket = state
        .ticket_ledger
        .get_ticket(&ticket_id)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to retrieve ticket: {}", e)))?
        .ok_or_else(|| ApiError::not_found(format!("Ticket not found: {}", ticket_id)))?;

    let is_valid = ticket.is_valid();
    let reason = if is_valid {
        None
    } else {
        Some(match ticket.status {
            TicketStatus::Revoked => "Ticket has been revoked".to_string(),
            TicketStatus::Used => "One-time ticket has been used".to_string(),
            TicketStatus::Expired => "Ticket has expired".to_string(),
            TicketStatus::Suspended => "Ticket is suspended pending review".to_string(),
            TicketStatus::Active => {
                if ticket.valid_until < Utc::now() {
                    "Ticket has expired".to_string()
                } else {
                    "Ticket is inactive".to_string()
                }
            }
        })
    };

    let remaining_uses = ticket.remaining_uses();
    let response = TicketValidationResponse {
        ticket_id: ticket.ticket_id,
        is_valid,
        status: ticket.status,
        reason,
        remaining_uses,
        expires_at: ticket.valid_until,
    };

    Ok(Json(response))
}

/// Revoke request body
#[derive(Debug, Deserialize)]
pub struct RevokeTicketRequest {
    /// Reason for revocation
    pub reason: Option<String>,
}

/// Revoke a ticket
pub async fn revoke_ticket(
    State(state): State<AppState>,
    Path(ticket_id): Path<String>,
    body: Option<Json<RevokeTicketRequest>>,
) -> ApiResult<StatusCode> {
    let reason = body
        .map(|b| b.reason.clone().unwrap_or_else(|| "No reason provided".to_string()))
        .unwrap_or_else(|| "No reason provided".to_string());

    state
        .ticket_ledger
        .revoke_ticket(&ticket_id, &reason)
        .await
        .map_err(|e| {
            if e.to_string().contains("not found") {
                ApiError::not_found(format!("Ticket not found: {}", ticket_id))
            } else {
                ApiError::internal(format!("Failed to revoke ticket: {}", e))
            }
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Use ticket to access payload
///
/// # Mandatory Audit (ISSUE-003 Fix)
///
/// This endpoint enforces **audit-before-access** semantics:
/// 1. Ticket is validated first
/// 2. Audit log is written BEFORE any data is read
/// 3. If audit write fails, the entire operation is BLOCKED
/// 4. This ensures no payload access can occur without audit trail
pub async fn use_ticket(
    State(state): State<AppState>,
    Path((ticket_id, ref_id)): Path<(String, String)>,
) -> ApiResult<Vec<u8>> {
    // =========================================================================
    // ISSUE-015: Check degraded mode before ticket access
    // =========================================================================
    // Ticket-based access requires full DSN availability per degradation matrix
    state.check_degraded_mode_operation(OperationType::Read)
        .await
        .map_err(|e| {
            tracing::warn!(
                ticket_id = %ticket_id,
                ref_id = %ref_id,
                error = %e,
                "Ticket access blocked due to degraded mode"
            );
            ApiError::Unavailable(format!(
                "Ticket access unavailable: {}",
                e
            ))
        })?;

    // 1. Validate and use the ticket
    let ticket = state
        .ticket_ledger
        .use_ticket(&ticket_id)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("not found") {
                ApiError::not_found(format!("Ticket not found: {}", ticket_id))
            } else if msg.contains("revoked") || msg.contains("expired") || msg.contains("used") {
                ApiError::TicketError(msg)
            } else {
                ApiError::internal(format!("Failed to use ticket: {}", e))
            }
        })?;

    // 2. Check if the payload is in the ticket's scope
    let target_refs: Vec<&str> = ticket.target_resource_ref.split(',').collect();
    if !target_refs.contains(&ref_id.as_str()) {
        return Err(ApiError::Forbidden(format!(
            "Payload {} is not covered by this ticket",
            ref_id
        )));
    }

    // 3. Check Read permission
    if !ticket.has_permission(TicketPermission::Read) {
        return Err(ApiError::Forbidden(
            "Ticket does not have Read permission".to_string(),
        ));
    }

    // =========================================================================
    // 4. MANDATORY AUDIT: Write audit log BEFORE accessing data (ISSUE-003)
    // =========================================================================
    //
    // Per DSN documentation: "Audit logging is NOT optional"
    // If audit write fails, the operation MUST be blocked.

    let audit_log = DecryptAuditLog::new(
        format!("audit:{}", uuid::Uuid::new_v4()),
        ticket.ticket_id.clone(),
        ticket.holder.clone(),
        ref_id.clone(),
        ticket.selector.clone(),
        ticket.purpose_digest.clone(),
        Digest::zero(), // Placeholder - actual digest computed after read
        "/api/v1/tickets/:ticket_id/access/:ref_id".to_string(),
    );

    // CRITICAL: Write audit FIRST - blocks if write fails
    let mut guard = create_decrypt_audit_guard(&audit_log, state.audit_ledger.as_ref())
        .await
        .map_err(|e| {
            tracing::error!(
                ticket_id = %ticket_id,
                ref_id = %ref_id,
                error = %e,
                "MANDATORY AUDIT WRITE FAILED - blocking ticket access"
            );
            ApiError::internal(format!(
                "Audit write failed - ticket access blocked for security: {}",
                e
            ))
        })?;

    // 5. Now safe to read the payload data (audit is already recorded)
    let data = match state.storage.read(&ref_id).await {
        Ok(data) => {
            guard.mark_completed();
            data
        }
        Err(e) => {
            guard.mark_failed();
            return Err(match &e {
                p2_storage::StorageError::NotFound(_) => {
                    ApiError::not_found(format!("Payload not found: {}", ref_id))
                }
                _ => ApiError::from(e),
            });
        }
    };

    // Log completion with result digest for verification
    let result_digest = Digest::blake3(&data);
    tracing::debug!(
        log_id = %guard.log_id(),
        ticket_id = %ticket_id,
        ref_id = %ref_id,
        result_digest = %result_digest.to_hex(),
        "Ticket access completed with mandatory audit"
    );

    Ok(data)
}
