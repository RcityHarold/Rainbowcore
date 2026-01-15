//! API Error Types
//!
//! Error types for HTTP/gRPC API layer.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

/// API-specific errors
#[derive(Error, Debug)]
pub enum ApiError {
    /// Validation error
    #[error("Validation error: {message}")]
    ValidationError { message: String },

    /// Resource not found
    #[error("Resource not found: {resource_type} with id {id}")]
    NotFound { resource_type: String, id: String },

    /// Unauthorized access
    #[error("Unauthorized: {reason}")]
    Unauthorized { reason: String },

    /// Forbidden action
    #[error("Forbidden: {reason}")]
    Forbidden { reason: String },

    /// Conflict (duplicate, concurrent modification)
    #[error("Conflict: {message}")]
    Conflict { message: String },

    /// Rate limited
    #[error("Rate limited: {message}")]
    RateLimited { message: String },

    /// Internal error
    #[error("Internal error: {message}")]
    Internal { message: String },

    /// Service unavailable
    #[error("Service unavailable: {reason}")]
    ServiceUnavailable { reason: String },

    /// Executor error
    #[error("Executor error: {0}")]
    ExecutorError(#[from] p3_executor::ExecutorError),

    /// Store error
    #[error("Store error: {0}")]
    StoreError(#[from] p3_store::P3StoreError),

    /// Verifier error
    #[error("Verifier error: {0}")]
    VerifierError(#[from] p3_verifier::VerifierError),

    /// Core error
    #[error("Core error: {0}")]
    CoreError(#[from] p3_core::P3Error),
}

/// API result type
pub type ApiResult<T> = Result<T, ApiError>;

/// Error response body
#[derive(Serialize)]
pub struct ErrorResponse {
    /// Error code
    pub code: String,
    /// Error message
    pub message: String,
    /// Optional details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl ApiError {
    /// Get HTTP status code for this error
    pub fn status_code(&self) -> StatusCode {
        match self {
            ApiError::ValidationError { .. } => StatusCode::BAD_REQUEST,
            ApiError::NotFound { .. } => StatusCode::NOT_FOUND,
            ApiError::Unauthorized { .. } => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden { .. } => StatusCode::FORBIDDEN,
            ApiError::Conflict { .. } => StatusCode::CONFLICT,
            ApiError::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            ApiError::Internal { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::ServiceUnavailable { .. } => StatusCode::SERVICE_UNAVAILABLE,
            ApiError::ExecutorError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::StoreError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::VerifierError(_) => StatusCode::BAD_REQUEST,
            ApiError::CoreError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Get error code string
    pub fn error_code(&self) -> &'static str {
        match self {
            ApiError::ValidationError { .. } => "VALIDATION_ERROR",
            ApiError::NotFound { .. } => "NOT_FOUND",
            ApiError::Unauthorized { .. } => "UNAUTHORIZED",
            ApiError::Forbidden { .. } => "FORBIDDEN",
            ApiError::Conflict { .. } => "CONFLICT",
            ApiError::RateLimited { .. } => "RATE_LIMITED",
            ApiError::Internal { .. } => "INTERNAL_ERROR",
            ApiError::ServiceUnavailable { .. } => "SERVICE_UNAVAILABLE",
            ApiError::ExecutorError(_) => "EXECUTOR_ERROR",
            ApiError::StoreError(_) => "STORE_ERROR",
            ApiError::VerifierError(_) => "VERIFICATION_ERROR",
            ApiError::CoreError(_) => "CORE_ERROR",
        }
    }

    /// Create a validation error
    pub fn validation(message: impl Into<String>) -> Self {
        ApiError::ValidationError {
            message: message.into(),
        }
    }

    /// Create a not found error
    pub fn not_found(resource_type: impl Into<String>, id: impl Into<String>) -> Self {
        ApiError::NotFound {
            resource_type: resource_type.into(),
            id: id.into(),
        }
    }

    /// Create an internal error
    pub fn internal(message: impl Into<String>) -> Self {
        ApiError::Internal {
            message: message.into(),
        }
    }

    /// Create an unauthorized error
    pub fn unauthorized(reason: impl Into<String>) -> Self {
        ApiError::Unauthorized {
            reason: reason.into(),
        }
    }

    /// Create a forbidden error
    pub fn forbidden(reason: impl Into<String>) -> Self {
        ApiError::Forbidden {
            reason: reason.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let error_response = ErrorResponse {
            code: self.error_code().to_string(),
            message: self.to_string(),
            details: None,
        };

        (status, Json(error_response)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_error() {
        let err = ApiError::validation("Invalid amount");
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(err.error_code(), "VALIDATION_ERROR");
    }

    #[test]
    fn test_not_found_error() {
        let err = ApiError::not_found("Provider", "provider:123");
        assert_eq!(err.status_code(), StatusCode::NOT_FOUND);
        assert_eq!(err.error_code(), "NOT_FOUND");
    }

    #[test]
    fn test_internal_error() {
        let err = ApiError::internal("Database connection failed");
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.error_code(), "INTERNAL_ERROR");
    }

    #[test]
    fn test_unauthorized_error() {
        let err = ApiError::unauthorized("Invalid token");
        assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(err.error_code(), "UNAUTHORIZED");
    }

    #[test]
    fn test_forbidden_error() {
        let err = ApiError::forbidden("Operation not allowed");
        assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
        assert_eq!(err.error_code(), "FORBIDDEN");
    }
}
