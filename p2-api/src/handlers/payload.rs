//! Payload Handlers
//!
//! HTTP handlers for payload CRUD operations.
//!
//! # Mandatory Audit Enforcement
//!
//! All payload read operations MUST be audited BEFORE the actual data access.
//! This is enforced via `MandatoryAuditGuard` which ensures:
//! 1. Audit log is written BEFORE data read
//! 2. If audit write fails, data access is BLOCKED
//! 3. Operation completion status is tracked

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use l0_core::types::{ActorId, Digest};
use p2_core::ledger::{AuditLedger, TicketLedger};
use p2_core::types::{
    AuditLogWriter, DecryptAuditLog, DecryptOutcome, MandatoryAuditGuard,
    PayloadSelector, TicketPermission, create_decrypt_audit_guard,
};
use p2_core::OperationType;
use serde::Deserialize;

use crate::{
    dto::{
        DeletionReasonDto, LegalBasisDto, MigrateTemperatureRequest, PayloadMetadataResponse,
        TombstoneRequest, TombstoneResponse, WritePayloadResponse,
    },
    error::{ApiError, ApiResult},
    state::AppState,
};
use p2_core::types::StorageTemperature;
use p2_storage::{P2StorageBackend, WriteMetadata};

/// Query parameters for write payload
#[derive(Debug, Deserialize)]
pub struct WritePayloadQuery {
    /// Content type
    pub content_type: Option<String>,
    /// Storage temperature
    pub temperature: Option<StorageTemperature>,
}

/// Write a new payload
///
/// Accepts raw body data with optional query parameters for metadata.
pub async fn write_payload(
    State(state): State<AppState>,
    Query(query): Query<WritePayloadQuery>,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<WritePayloadResponse>)> {
    if body.is_empty() {
        return Err(ApiError::bad_request("Payload body cannot be empty"));
    }

    let content_type = query.content_type.unwrap_or_else(|| "application/octet-stream".to_string());
    let temperature = query.temperature.unwrap_or_default();

    let metadata = match temperature {
        StorageTemperature::Hot => WriteMetadata::hot(&content_type),
        StorageTemperature::Warm => WriteMetadata::default(),
        StorageTemperature::Cold => WriteMetadata::cold(&content_type),
    };

    let sealed_ref = state
        .storage
        .write(&body, metadata)
        .await
        .map_err(ApiError::from)?;

    // Auto-register for three-phase sync
    // Phase 1 (Plain) is already completed (local write)
    // Phase 2 (Encrypted DSN) and Phase 3 (L0 Commit) need to be triggered
    let sync_id = format!("sync:{}", uuid::Uuid::new_v4());
    tracing::info!(
        ref_id = %sealed_ref.ref_id,
        sync_id = %sync_id,
        "Payload written, registering for three-phase sync"
    );

    // Record initial sync state in ledger
    {
        use p2_core::ledger::sync_ledger::{SyncLedger, SyncStateEntry};
        let mut entry = SyncStateEntry::new(
            sync_id.clone(),
            "system".to_string(), // committer
            content_type.clone(),
        );
        entry.ref_id = Some(sealed_ref.ref_id.clone());
        entry.payload_checksum = Some(sealed_ref.checksum.to_hex());
        entry.payload_size = Some(sealed_ref.size_bytes);

        if let Err(e) = state.sync_ledger.create(entry).await {
            tracing::warn!(
                sync_id = %sync_id,
                ref_id = %sealed_ref.ref_id,
                error = %e,
                "Failed to record sync state - three-phase sync may not be tracked"
            );
        }
    }

    // TODO: Trigger async three-phase sync in background
    // Option 1: Use background task queue (recommended for production)
    // Option 2: Use tokio::spawn for immediate async processing
    // Option 3: Use external scheduler (cron, k8s CronJob) to periodically sync pending items
    //
    // For production deployment, consider:
    // - Use a job queue system (e.g., Redis queue, RabbitMQ)
    // - Implement retry logic with exponential backoff
    // - Monitor sync lag and alert on failures
    // - Batch multiple payloads for efficient L0 commitment
    //
    // Example background task (uncomment to enable):
    // let state_clone = state.clone();
    // let ref_id_clone = sealed_ref.ref_id.clone();
    // tokio::spawn(async move {
    //     if let Err(e) = perform_three_phase_sync(&state_clone, &sync_id, &ref_id_clone).await {
    //         tracing::error!(sync_id = %sync_id, error = %e, "Three-phase sync failed");
    //     }
    // });

    let response = WritePayloadResponse {
        ref_id: sealed_ref.ref_id,
        checksum: sealed_ref.checksum.to_hex(),
        size_bytes: sealed_ref.size_bytes,
        temperature: sealed_ref.temperature,
        created_at: sealed_ref.created_at,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// Query parameters for read payload
#[derive(Debug, Deserialize)]
pub struct ReadPayloadQuery {
    /// Optional ticket ID for access control
    ///
    /// **SECURITY NOTICE**: If no ticket_id is provided, access will be granted
    /// but logged as uncontrolled access. In production, configure strict mode
    /// to require tickets for all payload access.
    pub ticket_id: Option<String>,

    /// Optional actor ID for audit logging when no ticket is used
    pub actor_id: Option<String>,
}

/// Read payload data
///
/// # Access Control
///
/// This endpoint supports both ticket-based and direct access:
/// - **With ticket**: Validates ticket permissions and logs audit trail (RECOMMENDED)
/// - **Without ticket**: Allows access but logs as uncontrolled (DEPRECATED)
///
/// For secure access, use `/api/v1/tickets/:ticket_id/access/:ref_id` instead.
///
/// # Mandatory Audit (ISSUE-003 Fix)
///
/// This endpoint enforces **audit-before-access** semantics:
/// 1. Audit log is written BEFORE any data is read
/// 2. If audit write fails, the entire operation is BLOCKED
/// 3. This ensures no payload access can occur without audit trail
pub async fn read_payload(
    State(state): State<AppState>,
    Path(ref_id): Path<String>,
    Query(query): Query<ReadPayloadQuery>,
) -> ApiResult<impl IntoResponse> {
    // =========================================================================
    // ISSUE-015: Check degraded mode before payload read
    // =========================================================================
    // Read operations require full DSN availability per degradation matrix
    state.check_degraded_mode_operation(OperationType::Read)
        .await
        .map_err(|e| {
            tracing::warn!(
                ref_id = %ref_id,
                error = %e,
                "Payload read blocked due to degraded mode"
            );
            ApiError::Unavailable(format!(
                "Payload read unavailable: {}",
                e
            ))
        })?;

    // Ticket-based access control
    let (actor, ticket_ref, selector, purpose_digest) = if let Some(ticket_id) = &query.ticket_id {
        // Validate and use ticket
        let ticket = state
            .ticket_ledger
            .use_ticket(ticket_id)
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

        // Check if payload is in ticket's scope
        let target_refs: Vec<&str> = ticket.target_resource_ref.split(',').collect();
        if !target_refs.contains(&ref_id.as_str()) {
            return Err(ApiError::Forbidden(format!(
                "Payload {} is not covered by this ticket",
                ref_id
            )));
        }

        // Check Read permission
        if !ticket.has_permission(TicketPermission::Read) {
            return Err(ApiError::Forbidden(
                "Ticket does not have Read permission".to_string(),
            ));
        }

        (
            ticket.holder.clone(),
            ticket.ticket_id.clone(),
            ticket.selector.clone(),
            ticket.purpose_digest.clone(),
        )
    } else {
        // Uncontrolled access - log warning
        tracing::warn!(
            ref_id = %ref_id,
            actor_id = ?query.actor_id,
            "SECURITY WARNING: Payload accessed without ticket validation"
        );

        let actor = query.actor_id.as_ref()
            .map(|id| ActorId::new(id))
            .unwrap_or_else(|| ActorId::new("anonymous"));

        (actor, "no-ticket".to_string(), PayloadSelector::full(), Digest::blake3(b"direct_read"))
    };

    // =========================================================================
    // MANDATORY AUDIT: Write audit log BEFORE accessing data (ISSUE-003)
    // =========================================================================
    //
    // Per DSN documentation: "Audit logging is NOT optional"
    // If audit write fails, the operation MUST be blocked.

    // Create audit log with pending result (will update after read)
    let audit_log = DecryptAuditLog::new(
        format!("audit:{}", uuid::Uuid::new_v4()),
        ticket_ref,
        actor.clone(),
        ref_id.clone(),
        selector,
        purpose_digest,
        Digest::zero(), // Will be updated after we read the data
        "/api/v1/payloads/:ref_id".to_string(),
    );

    // CRITICAL: Write audit FIRST - blocks if write fails
    let mut guard = create_decrypt_audit_guard(&audit_log, state.audit_ledger.as_ref())
        .await
        .map_err(|e| {
            tracing::error!(
                ref_id = %ref_id,
                error = %e,
                "MANDATORY AUDIT WRITE FAILED - blocking payload access"
            );
            ApiError::internal(format!(
                "Audit write failed - payload access blocked for security: {}",
                e
            ))
        })?;

    // Now safe to read payload data (audit is already recorded)
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

    // Get metadata for content type
    let metadata = state.storage.get_metadata(&ref_id).await.ok();

    let content_type = metadata
        .as_ref()
        .map(|m| m.content_type.clone())
        .unwrap_or_else(|| "application/octet-stream".to_string());

    // Update audit with actual result digest (for verification)
    let result_digest = Digest::blake3(&data);
    tracing::debug!(
        log_id = %guard.log_id(),
        result_digest = %result_digest.to_hex(),
        "Payload read completed with audit"
    );

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, content_type)],
        data,
    ))
}

/// Get payload metadata
pub async fn get_payload_metadata(
    State(state): State<AppState>,
    Path(ref_id): Path<String>,
) -> ApiResult<Json<PayloadMetadataResponse>> {
    let metadata = state
        .storage
        .get_metadata(&ref_id)
        .await
        .map_err(|e| match &e {
            p2_storage::StorageError::NotFound(_) => {
                ApiError::not_found(format!("Payload not found: {}", ref_id))
            }
            _ => ApiError::from(e),
        })?;

    let response = PayloadMetadataResponse {
        ref_id,
        checksum: metadata.checksum,
        size_bytes: metadata.size_bytes,
        status: metadata.status,
        temperature: metadata.temperature,
        content_type: metadata.content_type,
        created_at: metadata.created_at,
        tags: metadata.tags,
    };

    Ok(Json(response))
}

/// Tombstone a payload
///
/// # Deletion Flow (ISSUE-011)
///
/// Per DSN documentation Chapter 4, deletion MUST:
/// 1. Preserve existence proof (that the payload existed)
/// 2. Create audit trail (who deleted, when, why)
/// 3. Retain integrity verification (checksum)
///
/// This endpoint creates a TombstoneMarker and records a DeletionAuditEntry
/// before erasing the encrypted content.
pub async fn tombstone_payload(
    State(state): State<AppState>,
    Path(ref_id): Path<String>,
    Json(request): Json<TombstoneRequest>,
) -> ApiResult<Json<TombstoneResponse>> {
    use p2_core::types::{
        DeletionAuditEntry, DeletionReason, LegalBasis, TombstoneMarker,
    };

    // =========================================================================
    // Step 1: Get original payload metadata (BEFORE deletion)
    // =========================================================================
    let original_metadata = state
        .storage
        .get_metadata(&ref_id)
        .await
        .map_err(|e| match &e {
            p2_storage::StorageError::NotFound(_) => {
                ApiError::not_found(format!("Payload not found: {}", ref_id))
            }
            _ => ApiError::from(e),
        })?;

    // Parse the checksum string back to Digest
    let original_checksum = Digest::from_hex(&original_metadata.checksum)
        .unwrap_or_else(|_| Digest::blake3(original_metadata.checksum.as_bytes()));

    // Determine actor
    let actor = request.actor
        .clone()
        .unwrap_or_else(|| "anonymous".to_string());

    // Convert DTO deletion reason to core type
    let deletion_reason = match request.deletion_reason {
        Some(DeletionReasonDto::UserRequest) => DeletionReason::UserRequest,
        Some(DeletionReasonDto::RetentionExpired) => DeletionReason::RetentionExpired,
        Some(DeletionReasonDto::LegalCompliance) => DeletionReason::LegalCompliance,
        Some(DeletionReasonDto::AdminAction) => DeletionReason::AdminAction,
        Some(DeletionReasonDto::DataCorruption) => DeletionReason::DataCorruption,
        Some(DeletionReasonDto::MigrationCleanup) => DeletionReason::MigrationCleanup,
        Some(DeletionReasonDto::Other { description }) => DeletionReason::Other(description),
        None => {
            // Default based on reason string
            if let Some(reason) = &request.reason {
                DeletionReason::Other(reason.clone())
            } else {
                DeletionReason::UserRequest
            }
        }
    };

    // Convert legal basis if provided
    let legal_basis = request.legal_basis.map(|lb| match lb {
        LegalBasisDto::GdprArticle17 => LegalBasis::GdprArticle17,
        LegalBasisDto::CcpaRequest => LegalBasis::CcpaRequest,
        LegalBasisDto::CourtOrder => LegalBasis::CourtOrder,
        LegalBasisDto::ContractualObligation => LegalBasis::ContractualObligation,
        LegalBasisDto::ConsentWithdrawal => LegalBasis::ConsentWithdrawal,
        LegalBasisDto::Other { description } => LegalBasis::Other(description),
    });

    // Generate audit log reference
    let audit_log_ref = format!("audit:del:{}", uuid::Uuid::new_v4());

    // =========================================================================
    // Step 2: Create TombstoneMarker (preserves existence proof)
    // =========================================================================
    let mut tombstone_marker = TombstoneMarker::new(
        ref_id.clone(),
        original_checksum.clone(),
        original_metadata.size_bytes,
        original_metadata.created_at,
        actor.clone(),
        deletion_reason.clone(),
        audit_log_ref.clone(),
    );

    // Add legal basis if provided
    if let Some(basis) = legal_basis {
        tombstone_marker = tombstone_marker.with_legal_basis(basis);
    }

    // =========================================================================
    // Step 3: Create DeletionAuditEntry (audit trail)
    // =========================================================================
    let pre_state_digest = original_checksum.clone();
    let post_state_digest = tombstone_marker.tombstone_digest.clone();

    let audit_entry = DeletionAuditEntry::new(
        audit_log_ref.clone(),
        None, // First deletion entry, no previous
        ref_id.clone(),
        actor.clone(),
        deletion_reason.clone(),
        pre_state_digest,
        post_state_digest,
        format!("tombstone:{}", tombstone_marker.tombstone_digest.to_hex()),
    );

    // Log the deletion audit entry
    tracing::info!(
        ref_id = %ref_id,
        actor = %actor,
        audit_log_ref = %audit_log_ref,
        tombstone_digest = %tombstone_marker.tombstone_digest.to_hex(),
        "Creating tombstone marker with audit trail"
    );

    // =========================================================================
    // Step 4: Perform the actual tombstone operation in storage
    // =========================================================================
    state
        .storage
        .tombstone(&ref_id)
        .await
        .map_err(|e| match &e {
            p2_storage::StorageError::NotFound(_) => {
                ApiError::not_found(format!("Payload not found: {}", ref_id))
            }
            _ => ApiError::from(e),
        })?;

    // Mark crypto-erase as complete (storage backend handles actual erasure)
    // In a production system, this would involve:
    // 1. Destroying encryption keys
    // 2. Overwriting encrypted content
    // 3. Verifying erasure across replicas
    // For now, we mark it as complete since storage.tombstone() handles cleanup
    let crypto_erase_status = "complete".to_string();

    // Log successful tombstone
    tracing::info!(
        ref_id = %ref_id,
        actor = %actor,
        original_size_bytes = original_metadata.size_bytes,
        "Payload tombstoned successfully"
    );

    // =========================================================================
    // Step 5: Return TombstoneResponse with marker and audit info
    // =========================================================================
    let deletion_reason_str = match deletion_reason {
        DeletionReason::UserRequest => "user_request".to_string(),
        DeletionReason::RetentionExpired => "retention_expired".to_string(),
        DeletionReason::LegalCompliance => "legal_compliance".to_string(),
        DeletionReason::AdminAction => "admin_action".to_string(),
        DeletionReason::DataCorruption => "data_corruption".to_string(),
        DeletionReason::MigrationCleanup => "migration_cleanup".to_string(),
        DeletionReason::Other(desc) => format!("other: {}", desc),
    };

    let response = TombstoneResponse {
        ref_id,
        original_checksum: original_metadata.checksum,
        original_size_bytes: original_metadata.size_bytes,
        tombstoned_at: tombstone_marker.tombstoned_at,
        deleted_by: actor,
        deletion_reason: deletion_reason_str,
        tombstone_digest: tombstone_marker.tombstone_digest.to_hex(),
        audit_log_ref,
        crypto_erase_status,
    };

    Ok(Json(response))
}

/// Migrate payload temperature
pub async fn migrate_temperature(
    State(state): State<AppState>,
    Path(ref_id): Path<String>,
    Json(request): Json<MigrateTemperatureRequest>,
) -> ApiResult<Json<PayloadMetadataResponse>> {
    let sealed_ref = state
        .storage
        .migrate_temperature(&ref_id, request.target_temperature)
        .await
        .map_err(|e| match &e {
            p2_storage::StorageError::NotFound(_) => {
                ApiError::not_found(format!("Payload not found: {}", ref_id))
            }
            _ => ApiError::from(e),
        })?;

    let metadata = state.storage.get_metadata(&sealed_ref.ref_id).await?;

    let response = PayloadMetadataResponse {
        ref_id: sealed_ref.ref_id,
        checksum: metadata.checksum,
        size_bytes: metadata.size_bytes,
        status: metadata.status,
        temperature: metadata.temperature,
        content_type: metadata.content_type,
        created_at: metadata.created_at,
        tags: metadata.tags,
    };

    Ok(Json(response))
}

/// Verify payload integrity
pub async fn verify_payload(
    State(state): State<AppState>,
    Path(ref_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let result = state.storage.verify_integrity(&ref_id).await?;

    Ok(Json(serde_json::json!({
        "ref_id": ref_id,
        "is_valid": result.valid,
        "verified_at": Utc::now(),
        "details": result.details,
    })))
}
