//! P2 Storage Error Types

use thiserror::Error;

/// Storage errors
#[derive(Debug, Error)]
pub enum StorageError {
    /// Payload not found
    #[error("Payload not found: {0}")]
    NotFound(String),

    /// Write operation failed
    #[error("Write failed: {0}")]
    WriteFailed(String),

    /// Read operation failed
    #[error("Read failed: {0}")]
    ReadFailed(String),

    /// Integrity check failed
    #[error("Integrity check failed: {0}")]
    IntegrityFailed(String),

    /// Backend error
    #[error("Backend error: {0}")]
    Backend(String),

    /// Migration failed
    #[error("Migration failed: {0}")]
    MigrationFailed(String),

    /// Backend unavailable
    #[error("Backend unavailable: {0}")]
    Unavailable(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Operation failed
    #[error("Operation failed: {0}")]
    OperationFailed(String),

    /// Replication failed
    #[error("Replication failed: {0}")]
    ReplicationFailed(String),

    /// Consistency error
    #[error("Consistency error: {0}")]
    ConsistencyError(String),
}

/// Storage result type
pub type StorageResult<T> = Result<T, StorageError>;
