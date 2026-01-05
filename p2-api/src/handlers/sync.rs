//! Sync Handlers
//!
//! HTTP handlers for three-phase synchronization operations.

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;

use crate::{
    dto::{SyncResponse, VerifyCommitRequest, VerifyCommitResponse, VerifyMismatch},
    error::{ApiError, ApiResult},
    state::AppState,
};
use bridge::VerifyResult;
use l0_core::types::Digest;
use p2_storage::P2StorageBackend;

/// Query parameters for sync
#[derive(Debug, Deserialize)]
pub struct SyncQuery {
    /// Content type
    pub content_type: Option<String>,
    /// Committer identifier
    pub committer: Option<String>,
    /// Local path
    pub local_path: Option<String>,
}

/// Execute three-phase sync
///
/// Note: Full sync implementation requires L0 client integration.
/// This endpoint currently stores the payload and returns a placeholder sync response.
pub async fn sync_payload(
    State(state): State<AppState>,
    Query(query): Query<SyncQuery>,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<SyncResponse>)> {
    if body.is_empty() {
        return Err(ApiError::bad_request("Payload body cannot be empty"));
    }

    let content_type = query.content_type.unwrap_or_else(|| "application/octet-stream".to_string());

    // For now, just write to storage directly
    // Full three-phase sync requires L0 client integration
    let write_meta = p2_storage::WriteMetadata::hot(&content_type);
    let sealed_ref = state
        .storage
        .write(&body, write_meta)
        .await
        .map_err(ApiError::from)?;

    let sync_id = format!("sync:{}", uuid::Uuid::new_v4());

    let response = SyncResponse {
        sync_id,
        phase: "Completed".to_string(),
        ref_id: Some(sealed_ref.ref_id),
        commit_id: None, // Requires L0 integration
        receipt_id: None, // Requires L0 integration
        duration_ms: Some(0),
        is_complete: true,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// Get sync status by ID
pub async fn get_sync_status(
    State(_state): State<AppState>,
    Path(sync_id): Path<String>,
) -> ApiResult<Json<SyncResponse>> {
    // In a real implementation, we'd store and retrieve sync states
    Err(ApiError::not_found(format!(
        "Sync state lookup not yet implemented: {}",
        sync_id
    )))
}

/// Resume a failed sync
pub async fn resume_sync(
    State(_state): State<AppState>,
    Path(sync_id): Path<String>,
    body: Bytes,
) -> ApiResult<Json<SyncResponse>> {
    if body.is_empty() {
        return Err(ApiError::bad_request("Payload body required for resume"));
    }

    Err(ApiError::not_found(format!(
        "Sync state lookup not yet implemented: {}",
        sync_id
    )))
}

/// Verify a commit against P2 payloads
pub async fn verify_commit(
    State(state): State<AppState>,
    Json(request): Json<VerifyCommitRequest>,
) -> ApiResult<Json<VerifyCommitResponse>> {
    // Get all sealed refs for the requested ref_ids
    let mut refs = Vec::new();
    for ref_id in &request.ref_ids {
        match state.storage.get_metadata(ref_id).await {
            Ok(metadata) => {
                let checksum = Digest::from_hex(&metadata.checksum).map_err(|e| {
                    ApiError::internal(format!("Invalid checksum format: {}", e))
                })?;

                refs.push(p2_core::types::SealedPayloadRef {
                    ref_id: ref_id.clone(),
                    checksum,
                    encryption_meta_digest: Digest::zero(),
                    access_policy_version: "v1".to_string(),
                    size_bytes: metadata.size_bytes,
                    status: metadata.status,
                    temperature: metadata.temperature,
                    created_at: metadata.created_at,
                    last_accessed_at: None,
                    content_type: Some(metadata.content_type),
                    retention_policy_ref: None,
                });
            }
            Err(p2_storage::StorageError::NotFound(_)) => {
                return Ok(Json(VerifyCommitResponse {
                    is_valid: false,
                    evidence_level: p2_core::types::EvidenceLevel::B,
                    mismatch: Some(VerifyMismatch {
                        mismatch_type: "missing_payload".to_string(),
                        expected: ref_id.clone(),
                        actual: "not_found".to_string(),
                    }),
                }));
            }
            Err(e) => return Err(ApiError::from(e)),
        }
    }

    // Create a test commit for verification
    let test_commit =
        bridge::PayloadMapCommit::from_refs(&refs, "verify", bridge::CommitType::Batch);

    let result = test_commit.verify_against_p2(&refs);

    let (is_valid, mismatch) = match &result {
        VerifyResult::Valid => (true, None),
        VerifyResult::DigestMismatch { expected, actual } => (
            false,
            Some(VerifyMismatch {
                mismatch_type: "digest_mismatch".to_string(),
                expected: expected.to_hex(),
                actual: actual.to_hex(),
            }),
        ),
        VerifyResult::CountMismatch { expected, actual } => (
            false,
            Some(VerifyMismatch {
                mismatch_type: "count_mismatch".to_string(),
                expected: expected.to_string(),
                actual: actual.to_string(),
            }),
        ),
        VerifyResult::PayloadsMissing { missing_refs } => (
            false,
            Some(VerifyMismatch {
                mismatch_type: "payloads_missing".to_string(),
                expected: format!("{} payloads", request.ref_ids.len()),
                actual: format!("missing: {:?}", missing_refs),
            }),
        ),
    };

    Ok(Json(VerifyCommitResponse {
        is_valid,
        evidence_level: result.to_evidence_level(),
        mismatch,
    }))
}
