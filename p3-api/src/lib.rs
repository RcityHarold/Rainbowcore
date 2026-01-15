//! P3 API - HTTP/gRPC Interface Layer
//!
//! This crate provides the HTTP and gRPC interfaces for the P3 Economy Layer.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │                  P3 API                      │
//! │  ┌─────────────────────────────────────┐    │
//! │  │           HTTP Routes               │    │
//! │  │   /execute, /quote, /verify        │    │
//! │  │   /providers, /clearing, /treasury │    │
//! │  └─────────────────────────────────────┘    │
//! │           │              │           │      │
//! │           ▼              ▼           ▼      │
//! │  ┌─────────────┐ ┌─────────────┐ ┌────────┐ │
//! │  │  Handlers   │ │    DTOs     │ │ State  │ │
//! │  └─────────────┘ └─────────────┘ └────────┘ │
//! └─────────────────────────────────────────────┘
//!           │              │           │
//!           ▼              ▼           ▼
//!     p3-executor     p3-store    p3-verifier
//! ```
//!
//! # Endpoints
//!
//! ## Health & Status
//! - `GET /health` - Service health check
//! - `GET /stats` - Executor statistics
//!
//! ## Execution
//! - `POST /execute` - Execute an operation
//! - `POST /quote` - Request a quote for an operation
//! - `POST /verify` - Verify data integrity
//!
//! ## Providers
//! - `GET /providers` - List providers
//! - `GET /providers/:id` - Get provider details
//!
//! ## Clearing
//! - `GET /clearing/batches` - List clearing batches
//! - `GET /clearing/batches/:id` - Get batch details
//!
//! ## Treasury
//! - `GET /treasury/pools` - List treasury pools
//! - `GET /treasury/pools/:id` - Get pool details
//!
//! ## Proof Batches
//! - `POST /proofs/batches` - Create proof batch
//! - `POST /proofs/batches/:id/seal` - Seal proof batch
//!
//! # Usage Example
//!
//! ```ignore
//! use p3_api::{ApiConfig, AppState, build_app};
//! use p3_executor::P3Executor;
//! use p3_verifier::Verifier;
//!
//! #[tokio::main]
//! async fn main() {
//!     let executor = P3Executor::default_config();
//!     let verifier = Verifier::l1();
//!
//!     let config = ApiConfig {
//!         listen_addr: "0.0.0.0:3000".to_string(),
//!         ..Default::default()
//!     };
//!
//!     let state = AppState::with_config(config, executor, verifier);
//!     let app = build_app(state);
//!
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
//!     axum::serve(listener, app).await.unwrap();
//! }
//! ```

pub mod auth;
pub mod dto;
pub mod error;
pub mod gateway;
pub mod handlers;
pub mod metrics;
pub mod routes;
pub mod state;

// Re-export main types
pub use auth::{AuthConfig, AuthErrorResponse, AuthInfo, AuthMethod};
pub use dto::*;
pub use error::{ApiError, ApiResult, ErrorResponse};
pub use gateway::{GatewayConfig, GatewayError, GatewayResult, OrgProofGateway};
pub use metrics::{MetricsConfig, MetricsSummary, init_metrics};
pub use routes::{build_app, create_router, create_v1_router};
pub use state::{ApiConfig, AppState, ComponentHealthCheck, HealthStatus};

/// P3 API version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default API port
pub const DEFAULT_PORT: u16 = 3000;

/// Start the API server with default configuration
pub async fn start_server(state: AppState) -> Result<(), std::io::Error> {
    let addr = state.config.listen_addr.clone();
    let app = build_app(state);

    tracing::info!("Starting P3 API server on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_executor::P3Executor;
    use p3_verifier::Verifier;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_default_port() {
        assert_eq!(DEFAULT_PORT, 3000);
    }

    #[test]
    fn test_api_config_defaults() {
        let config = ApiConfig::default();
        assert_eq!(config.listen_addr, "0.0.0.0:3000");
        assert!(config.enable_cors);
        assert_eq!(config.request_timeout_secs, 30);
    }

    #[test]
    fn test_build_app() {
        let executor = P3Executor::default_config();
        let verifier = Verifier::l1();
        let state = AppState::new(executor, verifier);

        let _app = build_app(state);
    }

    #[tokio::test]
    async fn test_app_state_uptime() {
        let executor = P3Executor::default_config();
        let verifier = Verifier::l1();
        let state = AppState::new(executor, verifier);

        // Sleep briefly to ensure some uptime
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        assert!(state.uptime_secs() < 5);
    }

    #[test]
    fn test_error_response() {
        let err = ApiError::validation("Test error");
        assert_eq!(err.error_code(), "VALIDATION_ERROR");
        assert_eq!(err.status_code(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_dto_serialization() {
        let response = ExecuteOperationResponse {
            execution_id: "exec:1".to_string(),
            status: "Completed".to_string(),
            resolution_type: "Automatic".to_string(),
            result_digest: Some("abc123".to_string()),
            proof_ref: None,
            completed_at: chrono::Utc::now(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("exec:1"));
        assert!(json.contains("Completed"));
    }

    #[test]
    fn test_paginated_response_creation() {
        let response: PaginatedResponse<String> = PaginatedResponse {
            items: vec!["item1".to_string(), "item2".to_string()],
            total: 100,
            page: 0,
            page_size: 20,
            has_more: true,
        };

        assert_eq!(response.items.len(), 2);
        assert_eq!(response.total, 100);
        assert!(response.has_more);
    }

    #[test]
    fn test_health_status_values() {
        assert_eq!(HealthStatus::Healthy.as_str(), "healthy");
        assert_eq!(HealthStatus::Degraded.as_str(), "degraded");
        assert_eq!(HealthStatus::Unhealthy.as_str(), "unhealthy");
    }

    #[test]
    fn test_component_health_creation() {
        let healthy = ComponentHealthCheck::healthy("test");
        assert_eq!(healthy.status, HealthStatus::Healthy);

        let degraded = ComponentHealthCheck::degraded("test", "slow");
        assert_eq!(degraded.status, HealthStatus::Degraded);
        assert_eq!(degraded.message.as_deref(), Some("slow"));

        let unhealthy = ComponentHealthCheck::unhealthy("test", "failed");
        assert_eq!(unhealthy.status, HealthStatus::Unhealthy);
    }
}
