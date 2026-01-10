//! Sync Handlers
//!
//! HTTP handlers for three-phase synchronization operations.
//! Implements full L0 commitment anchoring for A-level evidence.

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use serde::Deserialize;
use tracing::{debug, error, info, warn};

use crate::{
    dto::{SyncResponse, VerifyCommitRequest, VerifyCommitResponse, VerifyMismatch},
    error::{ApiError, ApiResult},
    state::AppState,
};
use bridge::{
    CommitType, PayloadMapCommit, SyncMetadata, SyncPhase as BridgeSyncPhase,
    ThreePhaseSyncState, ThreePhaseSyncer, VerifyResult,
};
use l0_core::types::Digest;
use p2_core::ledger::{SyncLedger, SyncPhase, SyncStateEntry};
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

/// Execute three-phase sync with L0 commitment
///
/// This endpoint implements the full three-phase sync protocol:
/// 1. Plain (Local) - Compute digest of incoming data
/// 2. Encrypted (DSN) - Upload encrypted payload to storage
/// 3. Committed (L0) - Submit PayloadMapCommit to L0 for receipt
///
/// Returns A-level evidence when L0 commitment succeeds.
pub async fn sync_payload(
    State(state): State<AppState>,
    Query(query): Query<SyncQuery>,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<SyncResponse>)> {
    if body.is_empty() {
        return Err(ApiError::bad_request("Payload body cannot be empty"));
    }

    let content_type = query
        .content_type
        .unwrap_or_else(|| "application/octet-stream".to_string());
    let committer = query
        .committer
        .unwrap_or_else(|| "anonymous".to_string());
    let local_path = query.local_path.unwrap_or_default();

    let sync_id = format!("sync:{}", uuid::Uuid::new_v4());
    let start_time = Utc::now();

    // Create initial sync state entry
    let mut sync_entry = SyncStateEntry::new(
        sync_id.clone(),
        committer.clone(),
        content_type.clone(),
    );
    sync_entry.local_path = Some(local_path.clone());
    sync_entry.payload_size = Some(body.len() as u64);
    sync_entry.payload_checksum = Some(Digest::blake3(&body).to_hex());

    // Persist initial state
    state
        .sync_ledger
        .create(sync_entry.clone())
        .await
        .map_err(|e| {
            error!("Failed to create sync state: {}", e);
            ApiError::internal(format!("Failed to initialize sync: {}", e))
        })?;

    // Build sync metadata for ThreePhaseSyncer
    let write_meta = p2_storage::WriteMetadata::hot(&content_type);
    let sync_metadata = SyncMetadata {
        local_path,
        committer: committer.clone(),
        write_meta,
        content_type: content_type.clone(),
    };

    // Create syncer with storage backend and L0 client
    // Arc<T> implements P2StorageBackend, so we can clone the Arc directly
    let syncer = ThreePhaseSyncer::new(
        Arc::clone(&state.storage),
        SyncL0ClientWrapper {
            client: state.l0_client.clone(),
        },
    );

    // Execute three-phase sync
    let sync_result = syncer.sync(&body, sync_metadata).await;

    match sync_result {
        Ok(sync_state) => {
            let duration_ms = (Utc::now() - start_time).num_milliseconds();

            // Extract commit and receipt info
            let (commit_id, receipt_id) = sync_state
                .committed
                .as_ref()
                .map(|c| (Some(c.map_commit.commit_id.clone()), Some(c.receipt_id.clone())))
                .unwrap_or((None, None));

            let ref_id = sync_state
                .encrypted
                .as_ref()
                .map(|e| e.sealed_ref.ref_id.clone());

            // Update sync state entry
            sync_entry.phase = SyncPhase::Completed;
            sync_entry.ref_id = ref_id.clone();
            sync_entry.commit_id = commit_id.clone();
            sync_entry.receipt_id = receipt_id.clone();
            sync_entry.completed_at = Some(Utc::now());
            sync_entry.updated_at = Utc::now();

            state.sync_ledger.update(sync_entry).await.map_err(|e| {
                warn!("Failed to update sync state: {}", e);
                ApiError::internal(format!("Sync completed but state update failed: {}", e))
            })?;

            info!(
                sync_id = %sync_id,
                ref_id = ?ref_id,
                receipt_id = ?receipt_id,
                duration_ms = duration_ms,
                "Three-phase sync completed successfully"
            );

            let response = SyncResponse {
                sync_id,
                phase: "Completed".to_string(),
                ref_id,
                commit_id,
                receipt_id,
                duration_ms: Some(duration_ms),
                is_complete: true,
            };

            Ok((StatusCode::CREATED, Json(response)))
        }
        Err(e) => {
            error!(sync_id = %sync_id, error = %e, "Three-phase sync failed");

            // Determine which phase failed and update state
            sync_entry.phase = SyncPhase::Failed;
            sync_entry.error = Some(e.to_string());
            sync_entry.updated_at = Utc::now();

            let _ = state.sync_ledger.update(sync_entry).await;

            Err(ApiError::internal(format!("Sync failed: {}", e)))
        }
    }
}

/// Get sync status by ID
pub async fn get_sync_status(
    State(state): State<AppState>,
    Path(sync_id): Path<String>,
) -> ApiResult<Json<SyncResponse>> {
    let entry = state
        .sync_ledger
        .get(&sync_id)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to lookup sync state: {}", e)))?
        .ok_or_else(|| ApiError::not_found(format!("Sync not found: {}", sync_id)))?;

    let phase_str = match entry.phase {
        SyncPhase::Plain => "Plain",
        SyncPhase::Encrypted => "Encrypted",
        SyncPhase::Committed => "Committed",
        SyncPhase::Completed => "Completed",
        SyncPhase::Failed => "Failed",
    };

    let duration = entry.duration_ms();
    let is_complete = entry.is_complete();

    Ok(Json(SyncResponse {
        sync_id: entry.sync_id,
        phase: phase_str.to_string(),
        ref_id: entry.ref_id,
        commit_id: entry.commit_id,
        receipt_id: entry.receipt_id,
        duration_ms: duration,
        is_complete,
    }))
}

/// Resume a failed or incomplete sync
pub async fn resume_sync(
    State(state): State<AppState>,
    Path(sync_id): Path<String>,
    body: Bytes,
) -> ApiResult<Json<SyncResponse>> {
    if body.is_empty() {
        return Err(ApiError::bad_request("Payload body required for resume"));
    }

    // Get existing sync state
    let mut entry = state
        .sync_ledger
        .get(&sync_id)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to lookup sync state: {}", e)))?
        .ok_or_else(|| ApiError::not_found(format!("Sync not found: {}", sync_id)))?;

    if !entry.can_resume() {
        return Err(ApiError::bad_request(format!(
            "Sync cannot be resumed: phase={:?}, retry_count={}",
            entry.phase, entry.retry_count
        )));
    }

    // Verify payload checksum matches
    let provided_checksum = Digest::blake3(&body).to_hex();
    if let Some(ref expected_checksum) = entry.payload_checksum {
        if &provided_checksum != expected_checksum {
            return Err(ApiError::bad_request(
                "Payload checksum does not match original sync",
            ));
        }
    }

    entry.retry_count += 1;
    entry.error = None;
    entry.updated_at = Utc::now();

    // Build sync metadata
    let write_meta = p2_storage::WriteMetadata::hot(&entry.content_type);
    let sync_metadata = SyncMetadata {
        local_path: entry.local_path.clone().unwrap_or_default(),
        committer: entry.committer.clone(),
        write_meta,
        content_type: entry.content_type.clone(),
    };

    // Create syncer
    let syncer = ThreePhaseSyncer::new(
        Arc::clone(&state.storage),
        SyncL0ClientWrapper {
            client: state.l0_client.clone(),
        },
    );

    // Build partial ThreePhaseSyncState from entry
    let mut sync_state = ThreePhaseSyncState::new();
    sync_state.phase = match entry.phase {
        SyncPhase::Plain => BridgeSyncPhase::Plain,
        SyncPhase::Encrypted => BridgeSyncPhase::Encrypted,
        SyncPhase::Committed => BridgeSyncPhase::Committed,
        SyncPhase::Completed => BridgeSyncPhase::Completed,
        SyncPhase::Failed => BridgeSyncPhase::Failed,
    };

    // Resume sync
    let result = syncer.resume(sync_state, &body, &sync_metadata).await;

    match result {
        Ok(completed_state) => {
            let (commit_id, receipt_id) = completed_state
                .committed
                .as_ref()
                .map(|c| (Some(c.map_commit.commit_id.clone()), Some(c.receipt_id.clone())))
                .unwrap_or((None, None));

            let ref_id = completed_state
                .encrypted
                .as_ref()
                .map(|e| e.sealed_ref.ref_id.clone());

            // Update entry
            entry.phase = SyncPhase::Completed;
            entry.ref_id = ref_id.clone();
            entry.commit_id = commit_id.clone();
            entry.receipt_id = receipt_id.clone();
            entry.completed_at = Some(Utc::now());
            entry.updated_at = Utc::now();

            state.sync_ledger.update(entry.clone()).await.map_err(|e| {
                ApiError::internal(format!("Resume completed but state update failed: {}", e))
            })?;

            info!(
                sync_id = %sync_id,
                ref_id = ?ref_id,
                receipt_id = ?receipt_id,
                "Sync resumed and completed successfully"
            );

            Ok(Json(SyncResponse {
                sync_id,
                phase: "Completed".to_string(),
                ref_id,
                commit_id,
                receipt_id,
                duration_ms: entry.duration_ms(),
                is_complete: true,
            }))
        }
        Err(e) => {
            error!(sync_id = %sync_id, error = %e, "Sync resume failed");

            entry.phase = SyncPhase::Failed;
            entry.error = Some(e.to_string());
            entry.updated_at = Utc::now();

            let _ = state.sync_ledger.update(entry).await;

            Err(ApiError::internal(format!("Resume failed: {}", e)))
        }
    }
}

/// List incomplete syncs for recovery
#[derive(Debug, Deserialize)]
pub struct ListSyncsQuery {
    pub limit: Option<usize>,
    pub committer: Option<String>,
}

pub async fn list_incomplete_syncs(
    State(state): State<AppState>,
    Query(query): Query<ListSyncsQuery>,
) -> ApiResult<Json<Vec<SyncResponse>>> {
    let limit = query.limit.unwrap_or(100);

    let entries = if let Some(committer) = query.committer {
        state
            .sync_ledger
            .list_by_committer(&committer, limit)
            .await
            .map_err(|e| ApiError::internal(format!("Failed to list syncs: {}", e)))?
    } else {
        state
            .sync_ledger
            .list_incomplete(limit)
            .await
            .map_err(|e| ApiError::internal(format!("Failed to list syncs: {}", e)))?
    };

    let responses: Vec<SyncResponse> = entries
        .into_iter()
        .map(|entry| {
            let phase_str = match entry.phase {
                SyncPhase::Plain => "Plain",
                SyncPhase::Encrypted => "Encrypted",
                SyncPhase::Committed => "Committed",
                SyncPhase::Completed => "Completed",
                SyncPhase::Failed => "Failed",
            };

            let duration = entry.duration_ms();
            let is_complete = entry.is_complete();

            SyncResponse {
                sync_id: entry.sync_id,
                phase: phase_str.to_string(),
                ref_id: entry.ref_id,
                commit_id: entry.commit_id,
                receipt_id: entry.receipt_id,
                duration_ms: duration,
                is_complete,
            }
        })
        .collect();

    Ok(Json(responses))
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

                // Get or compute encryption metadata digest
                let encryption_meta_digest = Digest::from_hex(&metadata.get_encryption_meta_digest())
                    .map_err(|e| ApiError::internal(format!("Invalid encryption meta digest: {}", e)))?;

                refs.push(p2_core::types::SealedPayloadRef {
                    ref_id: ref_id.clone(),
                    checksum,
                    encryption_meta_digest,
                    access_policy_version: "v1".to_string(),
                    size_bytes: metadata.size_bytes,
                    status: metadata.status,
                    temperature: metadata.temperature,
                    created_at: metadata.created_at,
                    last_accessed_at: None,
                    content_type: Some(metadata.content_type),
                    retention_policy_ref: None,
                    format_version: p2_core::types::PayloadFormatVersion::current(),
                });
            }
            Err(p2_storage::StorageError::NotFound(_)) => {
                return Ok(Json(VerifyCommitResponse {
                    is_valid: false,
                    evidence_level: l0_core::types::EvidenceLevel::B,
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
        PayloadMapCommit::from_refs(&refs, "verify", CommitType::Batch);

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

// ============================================================================
// Helper wrapper for L0 client
// ============================================================================

use std::sync::Arc;

/// Wrapper to adapt Arc<dyn L0CommitClient> to L0CommitClient trait
struct SyncL0ClientWrapper {
    client: Arc<dyn bridge::L0CommitClient>,
}

#[async_trait::async_trait]
impl bridge::L0CommitClient for SyncL0ClientWrapper {
    async fn submit_commit(
        &self,
        commit: &PayloadMapCommit,
    ) -> bridge::L0ClientResult<l0_core::types::ReceiptId> {
        self.client.submit_commit(commit).await
    }

    async fn get_receipt(
        &self,
        receipt_id: &l0_core::types::ReceiptId,
    ) -> bridge::L0ClientResult<Option<l0_core::types::L0Receipt>> {
        self.client.get_receipt(receipt_id).await
    }

    async fn verify_receipt(
        &self,
        receipt_id: &l0_core::types::ReceiptId,
    ) -> bridge::L0ClientResult<l0_core::types::ReceiptVerifyResult> {
        self.client.verify_receipt(receipt_id).await
    }

    async fn get_receipts_by_batch(
        &self,
        batch_sequence: u64,
    ) -> bridge::L0ClientResult<Vec<l0_core::types::L0Receipt>> {
        self.client.get_receipts_by_batch(batch_sequence).await
    }

    async fn health_check(&self) -> bridge::L0ClientResult<bridge::L0HealthStatus> {
        self.client.health_check().await
    }

    async fn current_batch_sequence(&self) -> bridge::L0ClientResult<u64> {
        self.client.current_batch_sequence().await
    }

    async fn get_map_commits_by_batch(
        &self,
        batch_sequence: u64,
    ) -> bridge::L0ClientResult<std::collections::HashMap<String, PayloadMapCommit>> {
        self.client.get_map_commits_by_batch(batch_sequence).await
    }
}
