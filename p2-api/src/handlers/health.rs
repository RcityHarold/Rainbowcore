//! Health and Admin Handlers
//!
//! HTTP handlers for health checks and administrative operations.

use axum::{extract::State, Json};
use chrono::Utc;

use crate::{
    dto::{HealthResponse, StorageStatsResponse},
    error::ApiResult,
    state::AppState,
};
use p2_storage::P2StorageBackend;

/// Health check endpoint
pub async fn health_check(State(state): State<AppState>) -> ApiResult<Json<HealthResponse>> {
    let storage_health = state.storage.health_check().await?;

    // Check L0 bridge health
    let bridge_health = state.l0_client.health_check().await;
    let bridge_healthy = bridge_health
        .map(|h| h.available)
        .unwrap_or(false);

    // Determine overall status
    let status = match (storage_health.healthy, bridge_healthy) {
        (true, true) => "healthy",
        (true, false) => "degraded", // Storage OK but bridge down
        (false, true) => "degraded", // Bridge OK but storage down
        (false, false) => "unhealthy",
    };

    let response = HealthResponse {
        status: status.to_string(),
        version: crate::VERSION.to_string(),
        storage_healthy: storage_health.healthy,
        bridge_healthy,
        timestamp: Utc::now(),
    };

    Ok(Json(response))
}

/// Liveness probe (for Kubernetes)
pub async fn liveness() -> &'static str {
    "OK"
}

/// Readiness probe (for Kubernetes)
pub async fn readiness(State(state): State<AppState>) -> ApiResult<&'static str> {
    let health = state.storage.health_check().await?;
    if health.healthy {
        Ok("OK")
    } else {
        Err(crate::error::ApiError::Unavailable(
            "Storage backend not ready".to_string(),
        ))
    }
}

/// Get storage statistics
///
/// Note: Detailed storage statistics require scanning the storage backend.
/// The returned values may be estimates or unavailable for some backends.
pub async fn storage_stats(State(state): State<AppState>) -> ApiResult<Json<StorageStatsResponse>> {
    let health = state.storage.health_check().await?;

    // Use available data from health check
    // Note: Full statistics would require a dedicated index or scan
    let response = StorageStatsResponse {
        total_payloads: None, // Not available without index scan
        total_size_bytes: health.used_bytes,
        available_bytes: health.available_bytes,
        hot_count: None,
        warm_count: None,
        cold_count: None,
        backend_type: state.storage.backend_type().to_string(),
        backend_healthy: health.healthy,
    };

    Ok(Json(response))
}

/// Get backend capabilities
pub async fn backend_capabilities(
    State(state): State<AppState>,
) -> ApiResult<Json<serde_json::Value>> {
    let caps = state.storage.capabilities();

    Ok(Json(serde_json::json!({
        "backend_type": format!("{:?}", state.storage.backend_type()),
        "supports_temperature": caps.supports_temperature,
        "supports_streaming": caps.supports_streaming,
        "supports_atomic_write": caps.supports_atomic_write,
        "content_addressed": caps.content_addressed,
        "max_payload_size": caps.max_payload_size,
        "durability_nines": caps.durability_nines,
        "supported_temperatures": ["hot", "warm", "cold"],
    })))
}
