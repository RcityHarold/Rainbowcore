//! P3 Store Error Types

use thiserror::Error;

/// P3 Store Result type
pub type P3StoreResult<T> = Result<T, P3StoreError>;

/// P3 Store Error
#[derive(Debug, Error)]
pub enum P3StoreError {
    /// Entity not found
    #[error("Entity not found: {entity_type} with id {id}")]
    NotFound { entity_type: String, id: String },

    /// Duplicate entity
    #[error("Duplicate entity: {entity_type} with id {id}")]
    Duplicate { entity_type: String, id: String },

    /// Invalid entity state
    #[error("Invalid entity state: {message}")]
    InvalidState { message: String },

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Database error
    #[error("Database error: {0}")]
    Database(String),

    /// Connection error
    #[error("Connection error: {0}")]
    Connection(String),

    /// Transaction error
    #[error("Transaction error: {0}")]
    Transaction(String),

    /// Validation error
    #[error("Validation error: {0}")]
    Validation(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl P3StoreError {
    /// Create a not found error
    pub fn not_found(entity_type: impl Into<String>, id: impl Into<String>) -> Self {
        Self::NotFound {
            entity_type: entity_type.into(),
            id: id.into(),
        }
    }

    /// Create a duplicate error
    pub fn duplicate(entity_type: impl Into<String>, id: impl Into<String>) -> Self {
        Self::Duplicate {
            entity_type: entity_type.into(),
            id: id.into(),
        }
    }

    /// Create an invalid state error
    pub fn invalid_state(message: impl Into<String>) -> Self {
        Self::InvalidState {
            message: message.into(),
        }
    }

    /// Create a validation error
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation(message.into())
    }
}

impl From<serde_json::Error> for P3StoreError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialization(err.to_string())
    }
}

impl From<soulbase_storage::StorageError> for P3StoreError {
    fn from(err: soulbase_storage::StorageError) -> Self {
        Self::Database(err.to_string())
    }
}
