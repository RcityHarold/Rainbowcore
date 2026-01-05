//! P2 API Error Types

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

/// API errors
#[derive(Debug, Error)]
pub enum ApiError {
    /// Bad request
    #[error("Bad request: {0}")]
    BadRequest(String),

    /// Unauthorized
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Forbidden
    #[error("Forbidden: {0}")]
    Forbidden(String),

    /// Not found
    #[error("Not found: {0}")]
    NotFound(String),

    /// Conflict
    #[error("Conflict: {0}")]
    Conflict(String),

    /// Payload too large
    #[error("Payload too large: {size_bytes} bytes exceeds limit of {limit_bytes} bytes")]
    PayloadTooLarge { size_bytes: u64, limit_bytes: u64 },

    /// Internal server error
    #[error("Internal error: {0}")]
    Internal(String),

    /// Service unavailable
    #[error("Service unavailable: {0}")]
    Unavailable(String),

    /// Storage error
    #[error("Storage error: {0}")]
    Storage(#[from] p2_storage::StorageError),

    /// Bridge error
    #[error("Bridge error: {0}")]
    Bridge(#[from] bridge::BridgeError),

    /// Validation error
    #[error("Validation error: {0}")]
    Validation(String),

    /// Ticket invalid or expired
    #[error("Ticket error: {0}")]
    TicketError(String),
}

/// API result type
pub type ApiResult<T> = Result<T, ApiError>;

/// Error response body
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    /// Error code
    pub code: String,
    /// Error message
    pub message: String,
    /// Request ID for tracing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Additional details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "BAD_REQUEST", msg.clone()),
            ApiError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED", msg.clone()),
            ApiError::Forbidden(msg) => (StatusCode::FORBIDDEN, "FORBIDDEN", msg.clone()),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, "NOT_FOUND", msg.clone()),
            ApiError::Conflict(msg) => (StatusCode::CONFLICT, "CONFLICT", msg.clone()),
            ApiError::PayloadTooLarge { .. } => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "PAYLOAD_TOO_LARGE",
                self.to_string(),
            ),
            ApiError::Internal(msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", msg.clone())
            }
            ApiError::Unavailable(msg) => {
                (StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", msg.clone())
            }
            ApiError::Storage(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "STORAGE_ERROR",
                e.to_string(),
            ),
            ApiError::Bridge(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "BRIDGE_ERROR",
                e.to_string(),
            ),
            ApiError::Validation(msg) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "VALIDATION_ERROR", msg.clone())
            }
            ApiError::TicketError(msg) => (StatusCode::FORBIDDEN, "TICKET_ERROR", msg.clone()),
        };

        let body = ErrorResponse {
            code: code.to_string(),
            message,
            request_id: None,
            details: None,
        };

        (status, Json(body)).into_response()
    }
}

impl ApiError {
    /// Create a bad request error
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::BadRequest(msg.into())
    }

    /// Create a not found error
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }

    /// Create an internal error
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    /// Create a validation error
    pub fn validation(msg: impl Into<String>) -> Self {
        Self::Validation(msg.into())
    }
}
