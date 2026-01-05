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

    let response = HealthResponse {
        status: if storage_health.healthy {
            "healthy".to_string()
        } else {
            "degraded".to_string()
        },
        version: crate::VERSION.to_string(),
        storage_healthy: storage_health.healthy,
        bridge_healthy: true, // TODO: Add bridge health check
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
pub async fn storage_stats(State(state): State<AppState>) -> ApiResult<Json<StorageStatsResponse>> {
    let _capabilities = state.storage.capabilities();

    // In a real implementation, we'd query actual stats
    let response = StorageStatsResponse {
        total_payloads: 0,
        total_size_bytes: 0,
        hot_count: 0,
        warm_count: 0,
        cold_count: 0,
        backend_type: format!("{:?}", state.storage.backend_type()),
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
