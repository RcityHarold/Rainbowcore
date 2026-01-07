//! P2/DSN Error Types
//!
//! Error definitions for the P2 encrypted permanence domain.

use thiserror::Error;

/// P2 layer errors
#[derive(Debug, Error)]
pub enum P2Error {
    /// Storage backend error
    #[error("Storage error: {0}")]
    Storage(String),

    /// Payload not found
    #[error("Payload not found: {0}")]
    PayloadNotFound(String),

    /// Integrity check failed
    #[error("Integrity check failed: {0}")]
    IntegrityFailed(String),

    /// Encryption error
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Decryption error
    #[error("Decryption error: {0}")]
    Decryption(String),

    /// Invalid ticket
    #[error("Invalid access ticket: {0}")]
    InvalidTicket(String),

    /// Ticket expired
    #[error("Access ticket expired")]
    TicketExpired,

    /// Ticket already used
    #[error("Access ticket already used")]
    TicketAlreadyUsed,

    /// Ticket use limit exceeded
    #[error("Access ticket use limit exceeded")]
    TicketUseLimitExceeded,

    /// Selector out of scope
    #[error("Selector out of scope: {0}")]
    SelectorOutOfScope(String),

    /// Missing map commit
    #[error("Missing payload_map_commit - evidence level B")]
    MissingMapCommit,

    /// Sync error
    #[error("Sync error: {0}")]
    SyncError(String),

    /// Validation error
    #[error("Validation error: {0}")]
    Validation(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Tombstoned payload
    #[error("Payload has been tombstoned: {0}")]
    Tombstoned(String),

    /// Payload unavailable
    #[error("Payload unavailable: {0}")]
    Unavailable(String),

    /// Migration in progress
    #[error("Migration in progress for payload: {0}")]
    MigrationInProgress(String),

    /// Audit required
    #[error("Audit log required for this operation")]
    AuditRequired,

    /// Backend unavailable
    #[error("Storage backend unavailable: {0}")]
    BackendUnavailable(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Key management error
    #[error("Key management error: {0}")]
    KeyManagement(String),
}

/// P2 Result type
pub type P2Result<T> = Result<T, P2Error>;

impl From<serde_json::Error> for P2Error {
    fn from(err: serde_json::Error) -> Self {
        P2Error::Serialization(err.to_string())
    }
}
