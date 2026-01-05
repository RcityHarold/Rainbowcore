//! Bridge Error Types
//!
//! Error types for P1-P2 bridge operations including payload mapping,
//! three-phase sync, and reconciliation.

use thiserror::Error;

/// Bridge errors
#[derive(Debug, Error)]
pub enum BridgeError {
    /// Upload to P2 failed
    #[error("Upload failed: {0}")]
    UploadFailed(String),

    /// Commit to L0 failed
    #[error("Commit failed: {0}")]
    CommitFailed(String),

    /// Verification failed
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    /// Invalid state for operation
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// Sync operation failed
    #[error("Sync failed: {0}")]
    SyncFailed(String),

    /// Missing required data
    #[error("Missing data: {0}")]
    MissingData(String),

    /// Reconciliation failed
    #[error("Reconciliation failed: {0}")]
    ReconciliationFailed(String),

    /// Digest mismatch
    #[error("Digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch { expected: String, actual: String },

    /// Count mismatch
    #[error("Count mismatch: expected {expected}, got {actual}")]
    CountMismatch { expected: u64, actual: u64 },

    /// Payloads missing from P2
    #[error("Payloads missing: {0:?}")]
    PayloadsMissing(Vec<String>),

    /// Storage backend error
    #[error("Storage error: {0}")]
    Storage(#[from] p2_storage::StorageError),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Timeout error
    #[error("Operation timed out: {0}")]
    Timeout(String),

    /// Retry limit exceeded
    #[error("Retry limit exceeded after {attempts} attempts: {reason}")]
    RetryLimitExceeded { attempts: u32, reason: String },

    /// L0 unavailable
    #[error("L0 unavailable: {0}")]
    L0Unavailable(String),

    /// Receipt not found
    #[error("Receipt not found: {0}")]
    ReceiptNotFound(String),

    /// Evidence level downgrade (map_commit missing)
    #[error("Evidence level downgrade: {0}")]
    EvidenceLevelDowngrade(String),

    /// Resource not found
    #[error("Not found: {0}")]
    NotFound(String),
}

/// Bridge result type
pub type BridgeResult<T> = Result<T, BridgeError>;

impl BridgeError {
    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            BridgeError::UploadFailed(_)
                | BridgeError::CommitFailed(_)
                | BridgeError::SyncFailed(_)
                | BridgeError::Timeout(_)
                | BridgeError::Storage(_)
                | BridgeError::L0Unavailable(_)
        )
    }

    /// Get suggested retry delay in milliseconds
    pub fn suggested_retry_delay_ms(&self) -> Option<u64> {
        match self {
            BridgeError::UploadFailed(_) => Some(1000),
            BridgeError::CommitFailed(_) => Some(2000),
            BridgeError::SyncFailed(_) => Some(1500),
            BridgeError::Timeout(_) => Some(5000),
            BridgeError::Storage(_) => Some(500),
            BridgeError::L0Unavailable(_) => Some(3000),
            _ => None,
        }
    }

    /// Check if this is a hard invariant violation (non-recoverable)
    pub fn is_invariant_violation(&self) -> bool {
        matches!(
            self,
            BridgeError::DigestMismatch { .. }
                | BridgeError::EvidenceLevelDowngrade(_)
        )
    }
}
