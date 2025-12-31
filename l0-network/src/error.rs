//! L0 Network Error Types

use thiserror::Error;

/// Network errors
#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Not connected to node: {0}")]
    NotConnected(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Node not found: {0}")]
    NodeNotFound(String),

    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("Session expired: {0}")]
    SessionExpired(String),

    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    #[error("Not enough signers connected: have {have}, need {need}")]
    InsufficientSigners { have: usize, need: usize },

    #[error("Send failed: {0}")]
    SendFailed(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("IO error: {0}")]
    Io(String),
}

/// Result type for network operations
pub type NetworkResult<T> = Result<T, NetworkError>;
