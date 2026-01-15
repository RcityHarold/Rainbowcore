//! Authentication and Authorization
//!
//! Provides API Key and Bearer Token authentication for the P3 API.
//!
//! # Authentication Methods
//!
//! ## API Key (Header)
//! ```text
//! X-API-Key: your-api-key-here
//! ```
//!
//! ## Bearer Token
//! ```text
//! Authorization: Bearer your-token-here
//! ```
//!
//! # Configuration
//!
//! Authentication can be configured via environment variables:
//! - `P3_API_KEY`: Required API key for authentication
//! - `P3_AUTH_ENABLED`: Enable/disable authentication (default: false)

use axum::{
    extract::{Request, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::state::AppState;

/// Authentication configuration
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Whether authentication is enabled
    pub enabled: bool,
    /// API keys (multiple keys supported)
    pub api_keys: Vec<String>,
    /// Bearer tokens (optional)
    pub bearer_tokens: Vec<String>,
    /// Paths that don't require authentication
    pub public_paths: Vec<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_keys: Vec::new(),
            bearer_tokens: Vec::new(),
            public_paths: vec![
                "/".to_string(),
                "/health".to_string(),
                "/healthz".to_string(),
                "/api/v1/health".to_string(),
            ],
        }
    }
}

impl AuthConfig {
    /// Create from environment variables
    pub fn from_env() -> Self {
        let enabled = std::env::var("P3_AUTH_ENABLED")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);

        let api_keys: Vec<String> = std::env::var("P3_API_KEYS")
            .or_else(|_| std::env::var("P3_API_KEY"))
            .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default();

        let bearer_tokens: Vec<String> = std::env::var("P3_BEARER_TOKENS")
            .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default();

        Self {
            enabled,
            api_keys,
            bearer_tokens,
            ..Default::default()
        }
    }

    /// Check if a path is public (doesn't require authentication)
    pub fn is_public_path(&self, path: &str) -> bool {
        self.public_paths.iter().any(|p| path == p || path.starts_with(&format!("{}/", p)))
    }

    /// Validate an API key
    pub fn validate_api_key(&self, key: &str) -> bool {
        self.api_keys.iter().any(|k| k == key)
    }

    /// Validate a bearer token
    pub fn validate_bearer_token(&self, token: &str) -> bool {
        self.bearer_tokens.iter().any(|t| t == token)
    }
}

/// Authentication error response
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthErrorResponse {
    pub error: String,
    pub error_code: String,
    pub message: String,
}

impl AuthErrorResponse {
    pub fn unauthorized(message: &str) -> Self {
        Self {
            error: "Unauthorized".to_string(),
            error_code: "AUTH_UNAUTHORIZED".to_string(),
            message: message.to_string(),
        }
    }

    pub fn forbidden(message: &str) -> Self {
        Self {
            error: "Forbidden".to_string(),
            error_code: "AUTH_FORBIDDEN".to_string(),
            message: message.to_string(),
        }
    }
}

/// Authentication middleware
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let auth_config = &state.auth_config;

    // If auth is disabled, pass through
    if !auth_config.enabled {
        return next.run(request).await;
    }

    // Check if path is public
    let path = request.uri().path();
    if auth_config.is_public_path(path) {
        return next.run(request).await;
    }

    // Try API Key authentication (X-API-Key header)
    if let Some(api_key) = request.headers().get("X-API-Key") {
        if let Ok(key) = api_key.to_str() {
            if auth_config.validate_api_key(key) {
                return next.run(request).await;
            }
        }
        return (
            StatusCode::UNAUTHORIZED,
            Json(AuthErrorResponse::unauthorized("Invalid API key")),
        )
            .into_response();
    }

    // Try Bearer Token authentication
    if let Some(auth_header) = request.headers().get(AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                if auth_config.validate_bearer_token(token) {
                    return next.run(request).await;
                }
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(AuthErrorResponse::unauthorized("Invalid bearer token")),
                )
                    .into_response();
            }
        }
    }

    // No valid authentication provided
    (
        StatusCode::UNAUTHORIZED,
        Json(AuthErrorResponse::unauthorized(
            "Authentication required. Provide X-API-Key header or Authorization: Bearer <token>",
        )),
    )
        .into_response()
}

/// Extracted authentication info (for use in handlers)
#[derive(Debug, Clone)]
pub struct AuthInfo {
    /// Authentication method used
    pub method: AuthMethod,
    /// The key or token used (for audit logging)
    pub credential_hint: String,
}

/// Authentication method
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    /// API Key authentication
    ApiKey,
    /// Bearer token authentication
    BearerToken,
    /// No authentication (public endpoint or auth disabled)
    None,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_config_default() {
        let config = AuthConfig::default();
        assert!(!config.enabled);
        assert!(config.api_keys.is_empty());
        assert!(config.is_public_path("/health"));
        assert!(config.is_public_path("/healthz"));
    }

    #[test]
    fn test_auth_config_public_paths() {
        let config = AuthConfig::default();
        assert!(config.is_public_path("/"));
        assert!(config.is_public_path("/health"));
        assert!(config.is_public_path("/api/v1/health"));
        assert!(!config.is_public_path("/api/v1/execute"));
    }

    #[test]
    fn test_api_key_validation() {
        let config = AuthConfig {
            enabled: true,
            api_keys: vec!["key1".to_string(), "key2".to_string()],
            ..Default::default()
        };

        assert!(config.validate_api_key("key1"));
        assert!(config.validate_api_key("key2"));
        assert!(!config.validate_api_key("key3"));
        assert!(!config.validate_api_key(""));
    }

    #[test]
    fn test_bearer_token_validation() {
        let config = AuthConfig {
            enabled: true,
            bearer_tokens: vec!["token1".to_string(), "token2".to_string()],
            ..Default::default()
        };

        assert!(config.validate_bearer_token("token1"));
        assert!(config.validate_bearer_token("token2"));
        assert!(!config.validate_bearer_token("token3"));
    }

    #[test]
    fn test_auth_error_response() {
        let err = AuthErrorResponse::unauthorized("Test message");
        assert_eq!(err.error, "Unauthorized");
        assert_eq!(err.error_code, "AUTH_UNAUTHORIZED");

        let err = AuthErrorResponse::forbidden("Forbidden message");
        assert_eq!(err.error, "Forbidden");
        assert_eq!(err.error_code, "AUTH_FORBIDDEN");
    }
}
