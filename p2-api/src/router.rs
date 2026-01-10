//! API Router
//!
//! Route definitions for the P2 API.

use axum::{
    routing::{delete, get, post, put},
    Router,
};

use crate::{handlers, state::AppState};

/// Create the API router
pub fn create_router(state: AppState) -> Router {
    Router::new()
        // Health endpoints
        .route("/health", get(handlers::health_check))
        .route("/health/live", get(handlers::liveness))
        .route("/health/ready", get(handlers::readiness))
        // Payload endpoints
        .route("/api/v1/payloads", post(handlers::write_payload))
        .route("/api/v1/payloads/:ref_id", get(handlers::read_payload))
        .route(
            "/api/v1/payloads/:ref_id/metadata",
            get(handlers::get_payload_metadata),
        )
        .route(
            "/api/v1/payloads/:ref_id/tombstone",
            post(handlers::tombstone_payload),
        )
        .route(
            "/api/v1/payloads/:ref_id/temperature",
            put(handlers::migrate_temperature),
        )
        .route(
            "/api/v1/payloads/:ref_id/verify",
            get(handlers::verify_payload),
        )
        // Sync endpoints
        .route("/api/v1/sync", post(handlers::sync_payload))
        .route("/api/v1/sync/:sync_id", get(handlers::get_sync_status))
        .route("/api/v1/sync/:sync_id/resume", post(handlers::resume_sync))
        .route("/api/v1/sync/verify", post(handlers::verify_commit))
        // Evidence endpoints
        .route("/api/v1/evidence", post(handlers::create_evidence_bundle))
        .route(
            "/api/v1/evidence/:bundle_id",
            get(handlers::get_evidence_bundle),
        )
        .route(
            "/api/v1/evidence/:bundle_id/export",
            get(handlers::export_evidence_bundle),
        )
        .route(
            "/api/v1/cases/:case_id/evidence",
            get(handlers::list_case_evidence),
        )
        // Ticket endpoints
        .route("/api/v1/tickets", post(handlers::create_ticket))
        .route("/api/v1/tickets/:ticket_id", get(handlers::get_ticket))
        .route(
            "/api/v1/tickets/:ticket_id/validate",
            get(handlers::validate_ticket),
        )
        .route(
            "/api/v1/tickets/:ticket_id/revoke",
            delete(handlers::revoke_ticket),
        )
        .route(
            "/api/v1/tickets/:ticket_id/access/:ref_id",
            get(handlers::use_ticket),
        )
        // Snapshot endpoints
        .nest("/api/v1/snapshots", handlers::snapshot::snapshot_router())
        // Audit endpoints
        .nest("/api/v1/audit", handlers::audit::audit_router())
        // Sampling audit endpoints
        .nest("/api/v1/sampling", handlers::sampling::sampling_router())
        // RTBF (Right To Be Forgotten) endpoints
        .nest("/api/v1/rtbf", handlers::rtbf::rtbf_router())
        // Admin endpoints
        .route("/api/v1/admin/stats", get(handlers::storage_stats))
        .route(
            "/api/v1/admin/capabilities",
            get(handlers::backend_capabilities),
        )
        .with_state(state)
}

/// Create a minimal router for testing
pub fn create_test_router(state: AppState) -> Router {
    create_router(state)
}
