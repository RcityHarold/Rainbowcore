//! Health check endpoints

use axum::{extract::State, Json};
use l0_core::ledger::Ledger;
use l0_core::version::protocol_versions;

use crate::dto::{ApiVersionResponse, HealthResponse, ProtocolVersionsResponse};
use crate::error::ApiResult;
use crate::state::AppState;
use super::API_VERSION;

/// Health check endpoint
pub async fn health_check(State(state): State<AppState>) -> ApiResult<Json<HealthResponse>> {
    let batch_seq = state.causality.current_sequence().await.unwrap_or(0);
    let epoch_seq = state.causality.get_epoch_sequence().await.unwrap_or(0);

    Ok(Json(HealthResponse {
        status: "healthy".to_string(),
        version: state.version.clone(),
        node_id: state.node_id.clone(),
        current_batch_sequence: batch_seq,
        current_epoch_sequence: epoch_seq,
    }))
}

/// Ready check endpoint (verifies database connectivity)
pub async fn ready_check(State(state): State<AppState>) -> ApiResult<Json<HealthResponse>> {
    // Verify ledger integrity
    let identity_ok = state.identity.verify_integrity().await.unwrap_or(false);
    let causality_ok = state.causality.verify_integrity().await.unwrap_or(false);

    let status = if identity_ok && causality_ok {
        "ready"
    } else {
        "degraded"
    };

    let batch_seq = state.causality.current_sequence().await.unwrap_or(0);
    let epoch_seq = state.causality.get_epoch_sequence().await.unwrap_or(0);

    Ok(Json(HealthResponse {
        status: status.to_string(),
        version: state.version.clone(),
        node_id: state.node_id.clone(),
        current_batch_sequence: batch_seq,
        current_epoch_sequence: epoch_seq,
    }))
}

/// API version information endpoint
///
/// Returns information about supported API versions and protocol versions.
/// This endpoint is useful for clients to determine compatibility.
pub async fn api_version(State(state): State<AppState>) -> ApiResult<Json<ApiVersionResponse>> {
    let versions = protocol_versions();

    Ok(Json(ApiVersionResponse {
        current_version: API_VERSION.to_string(),
        supported_versions: vec![API_VERSION.to_string()],
        deprecated_versions: vec![],
        node_version: state.version.clone(),
        protocol_versions: ProtocolVersionsResponse {
            canonicalization: versions.canonicalization.to_string(),
            fee_schedule: versions.fee_schedule.to_string(),
            anchor_policy: versions.anchor_policy.to_string(),
            signer_set: versions.signer_set.to_string(),
            threshold_rule: versions.threshold_rule.to_string(),
        },
    }))
}
