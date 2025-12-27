//! Health check endpoints

use axum::{extract::State, Json};
use l0_core::ledger::Ledger;

use crate::dto::HealthResponse;
use crate::error::ApiResult;
use crate::state::AppState;

/// Health check endpoint
pub async fn health_check(State(state): State<AppState>) -> ApiResult<Json<HealthResponse>> {
    let batch_seq = state.causality.current_sequence().await.unwrap_or(0);

    Ok(Json(HealthResponse {
        status: "healthy".to_string(),
        version: state.version.clone(),
        node_id: state.node_id.clone(),
        current_batch_sequence: batch_seq,
        current_epoch_sequence: 0, // TODO: Track epoch sequence
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

    Ok(Json(HealthResponse {
        status: status.to_string(),
        version: state.version.clone(),
        node_id: state.node_id.clone(),
        current_batch_sequence: batch_seq,
        current_epoch_sequence: 0,
    }))
}
