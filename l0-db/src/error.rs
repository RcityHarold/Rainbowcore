//! L0 Database error types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum L0DbError {
    #[error("Storage error: {0}")]
    Storage(soulbase_storage::StorageError),

    #[error("Query error: {0}")]
    QueryError(String),

    #[error("Entity not found: {0}")]
    NotFound(String),

    #[error("Entity already exists: {0}")]
    AlreadyExists(String),

    #[error("Invalid query: {0}")]
    InvalidQuery(String),

    #[error("Schema error: {0}")]
    SchemaError(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type L0DbResult<T> = Result<T, L0DbError>;
