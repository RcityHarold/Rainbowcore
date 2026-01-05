//! Evidence Handlers
//!
//! HTTP handlers for evidence bundle operations.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Serialize;

use crate::{
    dto::{CreateEvidenceBundleRequest, EvidenceBundleResponse},
    error::{ApiError, ApiResult},
    state::AppState,
};
use l0_core::types::{ActorId, Digest};
use p2_core::ledger::EvidenceLedger;
use p2_core::types::EvidenceBundle;
use p2_storage::P2StorageBackend;

/// Create an evidence bundle
pub async fn create_evidence_bundle(
    State(state): State<AppState>,
    Json(request): Json<CreateEvidenceBundleRequest>,
) -> ApiResult<(StatusCode, Json<EvidenceBundleResponse>)> {
    // Collect all payload refs
    let mut payload_refs = Vec::new();
    let mut total_size = 0u64;

    for ref_id in &request.ref_ids {
        let metadata = state.storage.get_metadata(ref_id).await.map_err(|e| match &e {
            p2_storage::StorageError::NotFound(_) => {
                ApiError::not_found(format!("Payload not found: {}", ref_id))
            }
            _ => ApiError::from(e),
        })?;

        total_size += metadata.size_bytes;

        // Convert hex checksum to Digest
        let checksum = Digest::from_hex(&metadata.checksum)
            .map_err(|e| ApiError::internal(format!("Invalid checksum format: {}", e)))?;

        payload_refs.push(p2_core::types::SealedPayloadRef {
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

    // Create the submitter actor ID
    let submitter = ActorId::new(&request.requester);

    // Create the evidence bundle
    let bundle_id = format!("evidence:{}", uuid::Uuid::new_v4());
    let bundle = EvidenceBundle::new(
        bundle_id.clone(),
        request.case_id.clone(),
        submitter,
        payload_refs.clone(),
    );

    // Store bundle in ledger
    state
        .evidence_ledger
        .create_bundle(bundle.clone())
        .await
        .map_err(|e| ApiError::internal(format!("Failed to store evidence bundle: {}", e)))?;

    // Create a map commit for the bundle
    let map_commit = bridge::PayloadMapCommit::from_refs(
        &payload_refs,
        &request.requester,
        bridge::CommitType::Evidence,
    );

    let response = EvidenceBundleResponse {
        bundle_id: bundle.bundle_id.clone(),
        evidence_level: bundle.evidence_level(),
        payload_count: payload_refs.len() as u64,
        total_size_bytes: total_size,
        map_commit_ref: Some(map_commit.commit_id),
        receipt_id: bundle.receipt_id.as_ref().map(|r| r.0.clone()),
        created_at: bundle.created_at,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// Get evidence bundle by ID
pub async fn get_evidence_bundle(
    State(state): State<AppState>,
    Path(bundle_id): Path<String>,
) -> ApiResult<Json<EvidenceBundleResponse>> {
    let bundle = state
        .evidence_ledger
        .get_bundle(&bundle_id)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to retrieve bundle: {}", e)))?
        .ok_or_else(|| ApiError::not_found(format!("Evidence bundle not found: {}", bundle_id)))?;

    // Calculate total size from payload refs
    let total_size: u64 = bundle.payload_refs.iter().map(|r| r.size_bytes).sum();
    let evidence_level = bundle.evidence_level();
    let payload_count = bundle.payload_refs.len() as u64;

    let response = EvidenceBundleResponse {
        bundle_id: bundle.bundle_id,
        evidence_level,
        payload_count,
        total_size_bytes: total_size,
        map_commit_ref: bundle.map_commit_ref,
        receipt_id: bundle.receipt_id.map(|r| r.0),
        created_at: bundle.created_at,
    };

    Ok(Json(response))
}

/// Export evidence bundle response
#[derive(Debug, Serialize)]
pub struct ExportEvidenceBundleResponse {
    /// Bundle ID
    pub bundle_id: String,
    /// Case ID
    pub case_id: String,
    /// Evidence level
    pub evidence_level: p2_core::types::EvidenceLevel,
    /// Submitter
    pub submitter: String,
    /// Payload references with checksums
    pub payloads: Vec<ExportedPayloadInfo>,
    /// Map commit reference (for P1 verification)
    pub map_commit_ref: Option<String>,
    /// Receipt ID (L0 commitment proof)
    pub receipt_id: Option<String>,
    /// Created timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Export timestamp
    pub exported_at: chrono::DateTime<chrono::Utc>,
}

/// Exported payload info
#[derive(Debug, Serialize)]
pub struct ExportedPayloadInfo {
    /// Reference ID
    pub ref_id: String,
    /// Checksum (hex)
    pub checksum: String,
    /// Size in bytes
    pub size_bytes: u64,
    /// Content type
    pub content_type: Option<String>,
}

/// Export evidence bundle
pub async fn export_evidence_bundle(
    State(state): State<AppState>,
    Path(bundle_id): Path<String>,
) -> ApiResult<Json<ExportEvidenceBundleResponse>> {
    let bundle = state
        .evidence_ledger
        .get_bundle(&bundle_id)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to retrieve bundle: {}", e)))?
        .ok_or_else(|| ApiError::not_found(format!("Evidence bundle not found: {}", bundle_id)))?;

    let payloads: Vec<ExportedPayloadInfo> = bundle
        .payload_refs
        .iter()
        .map(|r| ExportedPayloadInfo {
            ref_id: r.ref_id.clone(),
            checksum: r.checksum.to_hex(),
            size_bytes: r.size_bytes,
            content_type: r.content_type.clone(),
        })
        .collect();

    let evidence_level = bundle.evidence_level();

    let response = ExportEvidenceBundleResponse {
        bundle_id: bundle.bundle_id,
        case_id: bundle.case_ref,
        evidence_level,
        submitter: bundle.submitter.0,
        payloads,
        map_commit_ref: bundle.map_commit_ref,
        receipt_id: bundle.receipt_id.map(|r| r.0),
        created_at: bundle.created_at,
        exported_at: chrono::Utc::now(),
    };

    Ok(Json(response))
}

/// List evidence bundles for a case
pub async fn list_case_evidence(
    State(state): State<AppState>,
    Path(case_id): Path<String>,
) -> ApiResult<Json<Vec<EvidenceBundleResponse>>> {
    let bundles = state
        .evidence_ledger
        .list_bundles_for_case(&case_id, 100)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to list bundles: {}", e)))?;

    let responses: Vec<EvidenceBundleResponse> = bundles
        .into_iter()
        .map(|bundle| {
            let total_size: u64 = bundle.payload_refs.iter().map(|r| r.size_bytes).sum();
            let evidence_level = bundle.evidence_level();
            let payload_count = bundle.payload_refs.len() as u64;
            EvidenceBundleResponse {
                bundle_id: bundle.bundle_id,
                evidence_level,
                payload_count,
                total_size_bytes: total_size,
                map_commit_ref: bundle.map_commit_ref,
                receipt_id: bundle.receipt_id.map(|r| r.0),
                created_at: bundle.created_at,
            }
        })
        .collect();

    Ok(Json(responses))
}
