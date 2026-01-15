//! API Routes
//!
//! Route definitions for the P3 API.

use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::auth::auth_middleware;
use crate::handlers::*;
use crate::metrics::metrics_middleware;
use crate::state::AppState;

/// Create the API router with all routes
pub fn create_router(state: Arc<AppState>) -> Router {
    let enable_cors = state.config.enable_cors;
    let auth_enabled = state.auth_config.enabled;

    let mut router = Router::new()
        // Health and status
        .route("/health", get(health_check))
        .route("/stats", get(get_stats))
        // Execution endpoints
        .route("/execute", post(execute_operation))
        .route("/verify", post(verify))
        // Provider endpoints
        .route("/providers", get(list_providers))
        .route("/providers/:provider_id", get(get_provider))
        // Clearing endpoints
        .route("/clearing/batches", get(list_clearing_batches))
        .route("/clearing/batches/:batch_id", get(get_clearing_batch))
        // Treasury endpoints
        .route("/treasury/pools", get(list_treasury_pools))
        .route("/treasury/pools/:pool_id", get(get_treasury_pool))
        // Proof batch endpoints
        .route("/proofs/batches", post(create_proof_batch))
        .route("/proofs/batches/:batch_id/seal", post(seal_proof_batch))
        // Disclosure endpoints
        .route("/disclosure/public/stats", get(get_public_stats))
        .route("/disclosure/context", post(create_viewer_context))
        .route("/disclosure/query", post(disclosure_query))
        .route("/disclosure/audit", get(list_audit_records))
        .route("/disclosure/export", post(create_export_ticket))
        .route("/disclosure/export/:ticket_id", get(get_export_ticket))
        // Conformance endpoints
        .route("/conformance/check", post(check_provider_conformance))
        .route("/conformance/providers/:provider_id", get(get_provider_conformance))
        .with_state(state.clone());

    // Add metrics middleware
    router = router.layer(middleware::from_fn_with_state(state.clone(), metrics_middleware));

    // Add authentication middleware (if enabled)
    if auth_enabled {
        router = router.layer(middleware::from_fn_with_state(state, auth_middleware));
    }

    // Add CORS middleware
    if enable_cors {
        router = router.layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        );
    }

    router = router.layer(TraceLayer::new_for_http());

    router
}

/// Create a router for the V1 API with /api/v1 prefix
pub fn create_v1_router(state: Arc<AppState>) -> Router {
    Router::new().nest("/api/v1", create_router(state))
}

/// Build the full application router
pub fn build_app(state: AppState) -> Router {
    let state = Arc::new(state);

    // Create a simple root handler that doesn't need state
    let root_router = Router::new()
        .route("/", get(|| async { "P3 API Service" }));

    // Create the health check route with state
    let health_router = Router::new()
        .route("/healthz", get(health_check))
        .with_state(state.clone());

    root_router
        .merge(health_router)
        .merge(create_v1_router(state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use p3_executor::P3Executor;
    use p3_verifier::Verifier;
    use tower::util::ServiceExt;

    fn create_test_state() -> AppState {
        let executor = P3Executor::default_config();
        let verifier = Verifier::l1();
        AppState::new(executor, verifier)
    }

    #[tokio::test]
    async fn test_root_endpoint() {
        let state = create_test_state();
        let app = build_app(state);

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let state = create_test_state();
        let app = build_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_v1_health_endpoint() {
        let state = create_test_state();
        let app = build_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_v1_stats_endpoint() {
        let state = create_test_state();
        let app = build_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/stats")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_providers_list_endpoint() {
        let state = create_test_state();
        let app = build_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/providers")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_provider_not_found() {
        let state = create_test_state();
        let app = build_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/providers/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
