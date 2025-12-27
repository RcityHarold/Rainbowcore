//! API route handlers

pub mod actor;
pub mod commitment;
pub mod health;

use axum::{routing::get, routing::post, Router};

use crate::state::AppState;

/// Create the API router
pub fn create_router(state: AppState) -> Router {
    Router::new()
        // Health endpoints
        .route("/health", get(health::health_check))
        .route("/ready", get(health::ready_check))
        // Actor endpoints
        .route("/actors", post(actor::register_actor))
        .route("/actors/:actor_id", get(actor::get_actor))
        .route("/actors/:actor_id/status", post(actor::update_status))
        .route("/actors/by-pubkey/:pubkey", get(actor::get_actor_by_pubkey))
        // Commitment endpoints
        .route("/commitments", post(commitment::submit_commitment))
        .route("/commitments/:commitment_id", get(commitment::get_commitment))
        .route("/commitments/actor/:actor_id", get(commitment::get_commitment_chain))
        .route("/commitments/:commitment_id/verify", get(commitment::verify_chain))
        // Batch endpoints
        .route("/batches/:sequence", get(commitment::get_batch_snapshot))
        // State
        .with_state(state)
}
