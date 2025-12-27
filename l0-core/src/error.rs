//! Error types for L0 Core
//!
//! Integrates with soulbase_errors for consistent error handling.

use thiserror::Error;

/// L0 Core errors
#[derive(Error, Debug)]
pub enum L0Error {
    #[error("Ledger error: {0}")]
    Ledger(#[from] LedgerError),

    #[error("Canonicalization error: {0}")]
    Canon(#[from] soulbase_crypto::errors::CryptoError),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Storage error: {0}")]
    Storage(String),
}

/// Ledger operation errors
#[derive(Error, Debug)]
pub enum LedgerError {
    #[error("Object not found: {0}")]
    NotFound(String),

    #[error("Object already exists: {0}")]
    AlreadyExists(String),

    #[error("Invalid state transition: {0}")]
    InvalidStateTransition(String),

    #[error("Receipt required but not found")]
    ReceiptRequired,

    #[error("Evidence level insufficient: expected {expected:?}, got {actual:?}")]
    InsufficientEvidenceLevel {
        expected: crate::types::EvidenceLevel,
        actual: crate::types::EvidenceLevel,
    },

    #[error("Continuity check failed: {0}")]
    ContinuityFailed(String),

    #[error("Version mismatch: {0}")]
    VersionMismatch(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Threshold not met: required {required}, got {actual}")]
    ThresholdNotMet { required: u32, actual: u32 },

    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    #[error("Merkle proof invalid: {0}")]
    MerkleProofInvalid(String),
}

/// Result type alias for L0 operations
pub type L0Result<T> = Result<T, L0Error>;

/// Result type alias for Ledger operations
pub type LedgerResult<T> = Result<T, LedgerError>;
