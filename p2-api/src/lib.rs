//! P2/DSN REST API Layer
//!
//! HTTP REST API for the P2 Encrypted Permanence Domain.
//!
//! # Endpoints
//!
//! ## Health
//! - `GET /health` - Health check
//! - `GET /health/live` - Liveness probe
//! - `GET /health/ready` - Readiness probe
//!
//! ## Payloads
//! - `POST /api/v1/payloads` - Write a new payload
//! - `GET /api/v1/payloads/:ref_id` - Read payload data
//! - `GET /api/v1/payloads/:ref_id/metadata` - Get payload metadata
//! - `POST /api/v1/payloads/:ref_id/tombstone` - Tombstone a payload
//! - `PUT /api/v1/payloads/:ref_id/temperature` - Migrate temperature tier
//! - `GET /api/v1/payloads/:ref_id/verify` - Verify payload integrity
//!
//! ## Three-Phase Sync
//! - `POST /api/v1/sync` - Execute three-phase sync
//! - `GET /api/v1/sync/:sync_id` - Get sync status
//! - `POST /api/v1/sync/:sync_id/resume` - Resume failed sync
//! - `POST /api/v1/sync/verify` - Verify commit against P2
//!
//! ## Evidence
//! - `POST /api/v1/evidence` - Create evidence bundle
//! - `GET /api/v1/evidence/:bundle_id` - Get evidence bundle
//! - `GET /api/v1/evidence/:bundle_id/export` - Export evidence bundle
//! - `GET /api/v1/cases/:case_id/evidence` - List case evidence
//!
//! ## Access Tickets
//! - `POST /api/v1/tickets` - Create access ticket
//! - `GET /api/v1/tickets/:ticket_id` - Get ticket
//! - `GET /api/v1/tickets/:ticket_id/validate` - Validate ticket
//! - `DELETE /api/v1/tickets/:ticket_id/revoke` - Revoke ticket
//! - `GET /api/v1/tickets/:ticket_id/access/:ref_id` - Use ticket to access payload
//!
//! # Usage
//!
//! ```ignore
//! use p2_api::{AppState, create_router};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let state = AppState::new("/path/to/storage").await?;
//!     let app = create_router(state);
//!
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
//!     axum::serve(listener, app).await?;
//!
//!     Ok(())
//! }
//! ```

pub mod dto;
pub mod error;
pub mod handlers;
pub mod middleware;
pub mod openapi;
pub mod router;
pub mod services;
pub mod state;

pub use error::{ApiError, ApiResult};
pub use middleware::{AuthClaims, JwtConfig, Permission, RateLimitConfig, RateLimiter, RbacConfig, Role};
pub use services::{
    DsnHealthConfig, DsnHealthExt, DsnHealthHandle, DsnHealthMonitor,
    R0TriggerConfig, R0TriggerEvent, R0TriggerExt, R0TriggerHandle,
    R0TriggerResult, R0TriggerService,
};
pub use openapi::{OpenApiSpec, ApiInfo, PathItem, Components};
pub use router::create_router;
pub use state::AppState;

/// API version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default port
pub const DEFAULT_PORT: u16 = 3000;

/// Configuration for the P2 API server
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Bind address
    pub bind_addr: String,
    /// Port
    pub port: u16,
    /// Storage path
    pub storage_path: String,
    /// Maximum payload size in bytes
    pub max_payload_size: u64,
    /// Request timeout in seconds
    pub request_timeout_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0".to_string(),
            port: DEFAULT_PORT,
            storage_path: "/var/lib/p2/storage".to_string(),
            max_payload_size: 100 * 1024 * 1024, // 100 MB
            request_timeout_secs: 30,
        }
    }
}

impl ServerConfig {
    /// Create config from environment variables
    pub fn from_env() -> Self {
        Self {
            bind_addr: std::env::var("P2_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: std::env::var("P2_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(DEFAULT_PORT),
            storage_path: std::env::var("P2_STORAGE_PATH")
                .unwrap_or_else(|_| "/var/lib/p2/storage".to_string()),
            max_payload_size: std::env::var("P2_MAX_PAYLOAD_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100 * 1024 * 1024),
            request_timeout_secs: std::env::var("P2_REQUEST_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
        }
    }

    /// Get the full bind address
    pub fn bind_address(&self) -> String {
        format!("{}:{}", self.bind_addr, self.port)
    }
}
