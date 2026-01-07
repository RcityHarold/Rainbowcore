//! JWT Authentication Middleware
//!
//! Validates JWT tokens and extracts claims for authenticated requests.

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::error::ErrorResponse;

/// JWT configuration
#[derive(Debug, Clone)]
pub struct JwtConfig {
    /// Secret key for HS256 (or public key for RS256)
    pub secret: String,
    /// Algorithm to use
    pub algorithm: Algorithm,
    /// Issuer to validate
    pub issuer: Option<String>,
    /// Audience to validate
    pub audience: Option<String>,
    /// Whether to validate expiration
    pub validate_exp: bool,
}

/// Error type for JWT configuration
#[derive(Debug, Clone)]
pub struct JwtConfigError {
    pub message: String,
}

impl std::fmt::Display for JwtConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "JWT config error: {}", self.message)
    }
}

impl std::error::Error for JwtConfigError {}

impl JwtConfig {
    /// Minimum secret length for security
    const MIN_SECRET_LENGTH: usize = 32;

    /// Create a new JWT config with secret (fallible)
    ///
    /// # Arguments
    /// * `secret` - The secret key. Must be at least 32 bytes for security.
    ///
    /// # Returns
    /// Error if the secret is too short (less than 32 bytes).
    pub fn try_new(secret: impl Into<String>) -> Result<Self, JwtConfigError> {
        let secret = secret.into();
        if secret.len() < Self::MIN_SECRET_LENGTH {
            return Err(JwtConfigError {
                message: format!(
                    "JWT secret must be at least {} bytes for security. Got {} bytes. \
                    Use a cryptographically secure random secret.",
                    Self::MIN_SECRET_LENGTH,
                    secret.len()
                ),
            });
        }
        Ok(Self {
            secret,
            algorithm: Algorithm::HS256,
            issuer: None,
            audience: None,
            validate_exp: true,
        })
    }

    /// Create a new JWT config with secret
    ///
    /// # Arguments
    /// * `secret` - The secret key. Must be at least 32 bytes for security.
    ///
    /// # Panics
    /// Panics if the secret is too short (less than 32 bytes).
    /// Use `try_new()` for fallible initialization.
    pub fn new(secret: impl Into<String>) -> Self {
        Self::try_new(secret).expect("Invalid JWT configuration")
    }

    /// Create a new JWT config from environment variable (fallible)
    ///
    /// # Arguments
    /// * `env_var` - Name of the environment variable containing the secret
    ///
    /// # Returns
    /// Error if the environment variable is not set or the secret is too short.
    pub fn try_from_env(env_var: &str) -> Result<Self, JwtConfigError> {
        let secret = std::env::var(env_var).map_err(|_| JwtConfigError {
            message: format!(
                "JWT secret environment variable '{}' is not set. \
                Set it to a cryptographically secure random value (at least 32 bytes).",
                env_var
            ),
        })?;
        Self::try_new(secret)
    }

    /// Create a new JWT config from environment variable
    ///
    /// # Arguments
    /// * `env_var` - Name of the environment variable containing the secret
    ///
    /// # Panics
    /// Panics if the environment variable is not set or the secret is too short.
    /// Use `try_from_env()` for fallible initialization.
    pub fn from_env(env_var: &str) -> Self {
        Self::try_from_env(env_var).expect("Invalid JWT configuration")
    }

    /// Create JWT config with secret (alias for new)
    pub fn with_secret(secret: impl Into<String>) -> Self {
        Self::new(secret)
    }

    /// Create a test config with a weak secret (FOR TESTING ONLY)
    ///
    /// # Security Warning
    /// This method creates a config with a short secret that is NOT SECURE.
    /// Only use in test code.
    #[cfg(test)]
    pub fn for_testing(secret: impl Into<String>) -> Self {
        let secret = secret.into();
        Self {
            secret,
            algorithm: Algorithm::HS256,
            issuer: None,
            audience: None,
            validate_exp: true,
        }
    }

    /// Set issuer validation
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Set audience validation
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.secret.len() < Self::MIN_SECRET_LENGTH {
            return Err(format!(
                "JWT secret must be at least {} bytes for security",
                Self::MIN_SECRET_LENGTH
            ));
        }
        Ok(())
    }
}

/// JWT claims structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthClaims {
    /// Subject (user/actor ID)
    pub sub: String,
    /// Expiration time (Unix timestamp)
    pub exp: u64,
    /// Issued at (Unix timestamp)
    pub iat: u64,
    /// Issuer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Audience
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// Roles
    #[serde(default)]
    pub roles: Vec<String>,
    /// Custom claims - actor type
    #[serde(default)]
    pub actor_type: Option<String>,
    /// Custom claims - organization
    #[serde(default)]
    pub org_id: Option<String>,
}

impl AuthClaims {
    /// Get the actor ID from subject
    pub fn actor_id(&self) -> l0_core::types::ActorId {
        l0_core::types::ActorId::new(&self.sub)
    }

    /// Check if user has a specific role
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// Check if user is admin
    pub fn is_admin(&self) -> bool {
        self.has_role("admin") || self.has_role("super_admin")
    }
}

/// Authentication error
#[derive(Debug)]
pub enum AuthError {
    /// Missing authorization header
    MissingToken,
    /// Invalid token format
    InvalidTokenFormat,
    /// Token validation failed
    ValidationFailed(String),
    /// Token expired
    TokenExpired,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            AuthError::MissingToken => (
                StatusCode::UNAUTHORIZED,
                "MISSING_TOKEN",
                "Authorization header is required".to_string(),
            ),
            AuthError::InvalidTokenFormat => (
                StatusCode::UNAUTHORIZED,
                "INVALID_TOKEN_FORMAT",
                "Invalid authorization header format. Expected: Bearer <token>".to_string(),
            ),
            AuthError::ValidationFailed(msg) => (
                StatusCode::UNAUTHORIZED,
                "TOKEN_VALIDATION_FAILED",
                msg,
            ),
            AuthError::TokenExpired => (
                StatusCode::UNAUTHORIZED,
                "TOKEN_EXPIRED",
                "Token has expired".to_string(),
            ),
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

/// Extract and validate JWT token from request
pub fn extract_token(auth_header: &str) -> Result<&str, AuthError> {
    if !auth_header.starts_with("Bearer ") {
        return Err(AuthError::InvalidTokenFormat);
    }
    Ok(&auth_header[7..])
}

/// Validate JWT token and extract claims
pub fn validate_token(token: &str, config: &JwtConfig) -> Result<AuthClaims, AuthError> {
    let mut validation = Validation::new(config.algorithm);
    validation.validate_exp = config.validate_exp;

    if let Some(ref iss) = config.issuer {
        validation.set_issuer(&[iss]);
    }

    if let Some(ref aud) = config.audience {
        validation.set_audience(&[aud]);
    }

    let key = DecodingKey::from_secret(config.secret.as_bytes());

    let token_data = decode::<AuthClaims>(token, &key, &validation)
        .map_err(|e| {
            if e.kind() == &jsonwebtoken::errors::ErrorKind::ExpiredSignature {
                AuthError::TokenExpired
            } else {
                AuthError::ValidationFailed(e.to_string())
            }
        })?;

    Ok(token_data.claims)
}

/// Authentication state for sharing config
#[derive(Clone)]
pub struct AuthState {
    pub config: Arc<JwtConfig>,
}

impl AuthState {
    pub fn new(config: JwtConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

/// Require authentication middleware
///
/// Validates the JWT token and stores claims in request extensions.
pub async fn require_auth(
    State(auth_state): State<AuthState>,
    mut request: Request,
    next: Next,
) -> Result<Response, AuthError> {
    // Extract authorization header
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or(AuthError::MissingToken)?;

    // Extract and validate token
    let token = extract_token(auth_header)?;
    let claims = validate_token(token, &auth_state.config)?;

    // Store claims in request extensions for downstream handlers
    request.extensions_mut().insert(claims);

    Ok(next.run(request).await)
}

/// Optional authentication middleware
///
/// Validates JWT if present, but allows unauthenticated requests.
pub async fn optional_auth(
    State(auth_state): State<AuthState>,
    mut request: Request,
    next: Next,
) -> Response {
    if let Some(auth_header) = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
    {
        if let Ok(token) = extract_token(auth_header) {
            if let Ok(claims) = validate_token(token, &auth_state.config) {
                request.extensions_mut().insert(claims);
            }
        }
    }

    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    fn create_test_token(claims: &AuthClaims, secret: &str) -> String {
        encode(
            &Header::default(),
            claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    #[test]
    fn test_extract_token() {
        assert!(extract_token("Bearer abc123").is_ok());
        assert!(extract_token("Basic abc123").is_err());
        assert!(extract_token("abc123").is_err());
    }

    #[test]
    fn test_validate_token() {
        let secret = "test-secret-for-unit-testing-only";
        let config = JwtConfig::for_testing(secret);

        let claims = AuthClaims {
            sub: "user:123".to_string(),
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as u64,
            iat: chrono::Utc::now().timestamp() as u64,
            iss: None,
            aud: None,
            roles: vec!["user".to_string()],
            actor_type: None,
            org_id: None,
        };

        let token = create_test_token(&claims, secret);
        let validated = validate_token(&token, &config).unwrap();

        assert_eq!(validated.sub, "user:123");
        assert!(validated.has_role("user"));
    }

    #[test]
    fn test_expired_token() {
        let secret = "test-secret-for-unit-testing-only";
        let config = JwtConfig::for_testing(secret);

        let claims = AuthClaims {
            sub: "user:123".to_string(),
            exp: (chrono::Utc::now() - chrono::Duration::hours(1)).timestamp() as u64,
            iat: chrono::Utc::now().timestamp() as u64,
            iss: None,
            aud: None,
            roles: vec![],
            actor_type: None,
            org_id: None,
        };

        let token = create_test_token(&claims, secret);
        let result = validate_token(&token, &config);

        assert!(matches!(result, Err(AuthError::TokenExpired)));
    }

    #[test]
    fn test_claims_methods() {
        let claims = AuthClaims {
            sub: "actor:test".to_string(),
            exp: 0,
            iat: 0,
            iss: None,
            aud: None,
            roles: vec!["admin".to_string(), "user".to_string()],
            actor_type: None,
            org_id: None,
        };

        assert!(claims.has_role("admin"));
        assert!(claims.has_role("user"));
        assert!(!claims.has_role("guest"));
        assert!(claims.is_admin());
        assert_eq!(claims.actor_id().0, "actor:test");
    }
}
