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

    let response = WritePayloadResponse {
        ref_id: sealed_ref.ref_id,
        checksum: sealed_ref.checksum.to_hex(),
        size_bytes: sealed_ref.size_bytes,
        temperature: sealed_ref.temperature,
        created_at: sealed_ref.created_at,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// Read payload data
pub async fn read_payload(
    State(state): State<AppState>,
    Path(ref_id): Path<String>,
) -> ApiResult<impl IntoResponse> {
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
        .map(|m| m.content_type)
        .unwrap_or_else(|| "application/octet-stream".to_string());

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
