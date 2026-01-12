//! Node Admission Middleware (ISSUE-004)
//!
//! Middleware for checking node admission status before allowing cross-node operations.
//! This ensures that only properly admitted nodes (with valid R0 skeleton and P1 connection)
//! can participate in cross-node operations.

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header::HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

use crate::error::ErrorResponse;
use crate::state::AppState;

/// Header name for the source node ID
pub const X_SOURCE_NODE_ID: &str = "x-source-node-id";

/// Header name for cross-node operation marker
pub const X_CROSS_NODE_OP: &str = "x-cross-node-operation";

/// Middleware to check node admission for cross-node operations
///
/// This middleware:
/// 1. Checks if the request is a cross-node operation (via header)
/// 2. If so, validates that the source node is properly admitted
/// 3. Blocks the request if admission requirements are not met
///
/// # Usage
///
/// Add to routes that involve cross-node communication:
/// ```ignore
/// Router::new()
///     .route("/sync", post(sync_handler))
///     .layer(axum::middleware::from_fn_with_state(
///         state.clone(),
///         require_node_admission,
///     ))
/// ```
pub async fn require_node_admission(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // Check if this is a cross-node operation
    let is_cross_node = request
        .headers()
        .get(X_CROSS_NODE_OP)
        .map(|v| v == "true")
        .unwrap_or(false);

    if !is_cross_node {
        // Not a cross-node operation, allow through
        return next.run(request).await;
    }

    // Get source node ID from header
    let source_node_id = match request.headers().get(X_SOURCE_NODE_ID) {
        Some(value) => match value.to_str() {
            Ok(id) => id.to_string(),
            Err(_) => {
                return create_error_response(
                    StatusCode::BAD_REQUEST,
                    "INVALID_NODE_ID",
                    "Invalid source node ID header encoding",
                );
            }
        },
        None => {
            return create_error_response(
                StatusCode::BAD_REQUEST,
                "MISSING_NODE_ID",
                "Cross-node operations require X-Source-Node-Id header",
            );
        }
    };

    // Check if the source node is admitted for cross-node operations
    match state
        .node_admission
        .check_cross_node_admission(&source_node_id)
        .await
    {
        Ok(_) => {
            tracing::debug!(
                source_node = %source_node_id,
                "Node admission check passed for cross-node operation"
            );
            next.run(request).await
        }
        Err(e) => {
            tracing::warn!(
                source_node = %source_node_id,
                error = %e,
                "Node admission check failed - blocking cross-node operation"
            );

            let (code, message) = match &e {
                p2_core::AdmissionError::NodeNotRegistered { node_id } => (
                    "NODE_NOT_REGISTERED",
                    format!("Node {} is not registered for cross-node operations", node_id),
                ),
                p2_core::AdmissionError::MissingR0Skeleton { node_id } => (
                    "R0_SKELETON_REQUIRED",
                    format!("Node {} must have valid R0 skeleton for cross-node operations", node_id),
                ),
                p2_core::AdmissionError::MissingP1Connection { node_id } => (
                    "P1_CONNECTION_REQUIRED",
                    format!("Node {} must have valid P1 connection for cross-node operations", node_id),
                ),
                p2_core::AdmissionError::NodeBanned { reason } => (
                    "NODE_BANNED",
                    format!("Node is banned: {}", reason),
                ),
                p2_core::AdmissionError::InsufficientTrust { score, required } => (
                    "TRUST_SCORE_LOW",
                    format!(
                        "Node trust score {} is below required threshold {}",
                        score, required
                    ),
                ),
                _ => ("ADMISSION_FAILED", format!("Node admission failed: {}", e)),
            };

            create_error_response(StatusCode::FORBIDDEN, code, &message)
        }
    }
}

/// Middleware to inject this node's ID into outgoing cross-node requests
///
/// This is used when this node initiates cross-node operations to other nodes.
/// It adds the necessary headers for the receiving node to validate admission.
pub async fn inject_node_id(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    // Add this node's ID to the request
    if let Ok(value) = HeaderValue::from_str(&state.node_id) {
        request
            .headers_mut()
            .insert(HeaderName::from_static(X_SOURCE_NODE_ID), value);
    }

    // Mark as cross-node operation
    request.headers_mut().insert(
        HeaderName::from_static(X_CROSS_NODE_OP),
        HeaderValue::from_static("true"),
    );

    next.run(request).await
}

/// Check if this node can perform cross-node operations
///
/// Returns true if this node has valid R0 skeleton and P1 connection.
/// Use this before initiating cross-node operations.
pub async fn can_perform_cross_node_ops(state: &AppState) -> bool {
    state.can_perform_cross_node_ops().await
}

/// Helper to create error responses
fn create_error_response(status: StatusCode, code: &str, message: &str) -> Response {
    let body = ErrorResponse {
        code: code.to_string(),
        message: message.to_string(),
        request_id: None,
        details: None,
    };
    (status, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_constants() {
        assert_eq!(X_SOURCE_NODE_ID, "x-source-node-id");
        assert_eq!(X_CROSS_NODE_OP, "x-cross-node-operation");
    }
}
