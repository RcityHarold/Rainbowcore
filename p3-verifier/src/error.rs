//! Verifier Error Types

use thiserror::Error;

/// Verifier result type
pub type VerifierResult<T> = Result<T, VerifierError>;

/// Verifier error
#[derive(Error, Debug, Clone)]
pub enum VerifierError {
    /// Bundle verification error
    #[error("Bundle verification error: {0}")]
    BundleError(String),

    /// Manifest verification error
    #[error("Manifest verification error: {0}")]
    ManifestError(String),

    /// Root verification error
    #[error("Root verification error: {0}")]
    RootError(String),

    /// Gates verification error
    #[error("Gates verification error: {0}")]
    GatesError(String),

    /// Proof verification error
    #[error("Proof verification error: {0}")]
    ProofError(String),

    /// Idempotency verification error
    #[error("Idempotency verification error: {0}")]
    IdempotencyError(String),

    /// Fee split verification error
    #[error("Fee split verification error: {0}")]
    FeeSplitError(String),

    /// Invalid input
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Missing required field
    #[error("Missing required field: {0}")]
    MissingField(String),

    /// Digest mismatch
    #[error("Digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch { expected: String, actual: String },

    /// Computation error
    #[error("Computation error: {0}")]
    ComputationError(String),

    /// Internal error
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl From<p3_core::P3Error> for VerifierError {
    fn from(err: p3_core::P3Error) -> Self {
        VerifierError::InternalError(err.to_string())
    }
}

impl From<serde_json::Error> for VerifierError {
    fn from(err: serde_json::Error) -> Self {
        VerifierError::InternalError(err.to_string())
    }
}
