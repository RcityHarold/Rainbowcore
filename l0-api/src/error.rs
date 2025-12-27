//! API Error types

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

/// API error types
#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Ledger error: {0}")]
    Ledger(#[from] l0_core::error::LedgerError),

    #[error("Validation error: {0}")]
    Validation(String),
}

/// Error response body
#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, "NOT_FOUND", msg.clone()),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "BAD_REQUEST", msg.clone()),
            ApiError::InternalError(msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", msg.clone())
            }
            ApiError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED", msg.clone()),
            ApiError::Ledger(e) => (StatusCode::INTERNAL_SERVER_ERROR, "LEDGER_ERROR", e.to_string()),
            ApiError::Validation(msg) => (StatusCode::BAD_REQUEST, "VALIDATION_ERROR", msg.clone()),
        };

        let body = ErrorResponse {
            error: message,
            code: code.to_string(),
        };

        (status, Json(body)).into_response()
    }
}

/// API result type
pub type ApiResult<T> = Result<T, ApiError>;
