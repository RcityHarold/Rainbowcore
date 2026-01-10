//! Payload Handlers
//!
//! HTTP handlers for payload CRUD operations.

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
use p2_core::types::{DecryptAuditLog, DecryptOutcome, PayloadSelector, TicketPermission};
use serde::Deserialize;

use crate::{
    dto::{
        MigrateTemperatureRequest, PayloadMetadataResponse, TombstoneRequest,
        WritePayloadResponse,
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
pub async fn read_payload(
    State(state): State<AppState>,
    Path(ref_id): Path<String>,
    Query(query): Query<ReadPayloadQuery>,
) -> ApiResult<impl IntoResponse> {
    // Ticket-based access control
    let (actor, ticket, selector) = if let Some(ticket_id) = &query.ticket_id {
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

        (ticket.holder.clone(), Some(ticket.ticket_id.clone()), ticket.selector.clone())
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

        (actor, None, PayloadSelector::full())
    };

    // Read payload data
    let data = state
        .storage
        .read(&ref_id)
        .await
        .map_err(|e| match &e {
            p2_storage::StorageError::NotFound(_) => {
                ApiError::not_found(format!("Payload not found: {}", ref_id))
            }
            _ => ApiError::from(e),
        })?;

    // Get metadata for content type
    let metadata = state.storage.get_metadata(&ref_id).await.ok();

    let content_type = metadata
        .as_ref()
        .map(|m| m.content_type.clone())
        .unwrap_or_else(|| "application/octet-stream".to_string());

    // MANDATORY: Record audit log for every payload access
    let result_digest = Digest::blake3(&data);
    let purpose_digest = Digest::blake3(b"direct_read");

    let mut audit_log = DecryptAuditLog::new(
        format!("audit:{}", uuid::Uuid::new_v4()),
        ticket.unwrap_or_else(|| "no-ticket".to_string()),
        actor.clone(),
        ref_id.clone(),
        selector,
        purpose_digest,
        result_digest,
        "/api/v1/payloads/:ref_id".to_string(),
    );
    audit_log.outcome = DecryptOutcome::Success;

    // Log audit (non-blocking, failure logged but doesn't block response)
    if let Err(e) = state.audit_ledger.record_decrypt(audit_log).await {
        tracing::error!(
            ref_id = %ref_id,
            error = %e,
            "CRITICAL: Failed to record audit log for payload access"
        );
    }

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
pub async fn tombstone_payload(
    State(state): State<AppState>,
    Path(ref_id): Path<String>,
    Json(_request): Json<TombstoneRequest>,
) -> ApiResult<StatusCode> {
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

    Ok(StatusCode::NO_CONTENT)
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
