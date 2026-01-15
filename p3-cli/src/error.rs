//! CLI Error Types
//!
//! Error types for the P3 CLI application.

use thiserror::Error;

/// CLI-specific errors
#[derive(Error, Debug)]
pub enum CliError {
    /// Configuration error
    #[error("Configuration error: {message}")]
    ConfigError { message: String },

    /// Invalid argument
    #[error("Invalid argument: {message}")]
    InvalidArgument { message: String },

    /// API connection error
    #[error("API connection error: {message}")]
    ConnectionError { message: String },

    /// API request failed
    #[error("API request failed: {status} - {message}")]
    ApiError { status: u16, message: String },

    /// File I/O error
    #[error("File I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// JSON parsing error
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// HTTP client error
    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),

    /// Executor error
    #[error("Executor error: {0}")]
    ExecutorError(#[from] p3_executor::ExecutorError),

    /// Verifier error
    #[error("Verifier error: {0}")]
    VerifierError(#[from] p3_verifier::VerifierError),

    /// Core error
    #[error("Core error: {0}")]
    CoreError(#[from] p3_core::P3Error),

    /// Digest parsing error
    #[error("Invalid digest: {message}")]
    DigestError { message: String },

    /// Operation not found
    #[error("Operation not found: {id}")]
    NotFound { id: String },

    /// Operation timed out
    #[error("Operation timed out after {seconds}s")]
    Timeout { seconds: u64 },

    /// Server error
    #[error("Server error: {message}")]
    ServerError { message: String },

    /// Database error
    #[error("Database error: {message}")]
    DatabaseError { message: String },
}

/// CLI result type
pub type CliResult<T> = Result<T, CliError>;

impl CliError {
    /// Create a configuration error
    pub fn config(message: impl Into<String>) -> Self {
        CliError::ConfigError {
            message: message.into(),
        }
    }

    /// Create an invalid argument error
    pub fn invalid_arg(message: impl Into<String>) -> Self {
        CliError::InvalidArgument {
            message: message.into(),
        }
    }

    /// Create a connection error
    pub fn connection(message: impl Into<String>) -> Self {
        CliError::ConnectionError {
            message: message.into(),
        }
    }

    /// Create an API error
    pub fn api(status: u16, message: impl Into<String>) -> Self {
        CliError::ApiError {
            status,
            message: message.into(),
        }
    }

    /// Create a digest error
    pub fn digest(message: impl Into<String>) -> Self {
        CliError::DigestError {
            message: message.into(),
        }
    }

    /// Create a not found error
    pub fn not_found(id: impl Into<String>) -> Self {
        CliError::NotFound { id: id.into() }
    }

    /// Create a timeout error
    pub fn timeout(seconds: u64) -> Self {
        CliError::Timeout { seconds }
    }

    /// Create a server error
    pub fn server(message: impl Into<String>) -> Self {
        CliError::ServerError {
            message: message.into(),
        }
    }

    /// Create a database error
    pub fn database(message: impl Into<String>) -> Self {
        CliError::DatabaseError {
            message: message.into(),
        }
    }

    /// Get exit code for this error
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::ConfigError { .. } => 1,
            CliError::InvalidArgument { .. } => 2,
            CliError::ConnectionError { .. } => 3,
            CliError::ApiError { .. } => 4,
            CliError::IoError(_) => 5,
            CliError::JsonError(_) => 6,
            CliError::HttpError(_) => 7,
            CliError::ExecutorError(_) => 10,
            CliError::VerifierError(_) => 11,
            CliError::CoreError(_) => 12,
            CliError::DigestError { .. } => 20,
            CliError::NotFound { .. } => 21,
            CliError::Timeout { .. } => 22,
            CliError::ServerError { .. } => 30,
            CliError::DatabaseError { .. } => 31,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_error() {
        let err = CliError::config("Missing API URL");
        assert_eq!(err.exit_code(), 1);
        assert!(err.to_string().contains("Missing API URL"));
    }

    #[test]
    fn test_invalid_argument() {
        let err = CliError::invalid_arg("Amount must be positive");
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn test_api_error() {
        let err = CliError::api(404, "Resource not found");
        assert_eq!(err.exit_code(), 4);
        assert!(err.to_string().contains("404"));
    }

    #[test]
    fn test_timeout_error() {
        let err = CliError::timeout(30);
        assert_eq!(err.exit_code(), 22);
        assert!(err.to_string().contains("30s"));
    }
}
