//! P4 Layer Error Types
//!
//! Error definitions for blockchain anchoring operations.

use thiserror::Error;

/// P4 Layer Error
#[derive(Error, Debug)]
pub enum P4Error {
    /// Bitcoin RPC connection error
    #[error("Bitcoin RPC connection failed: {0}")]
    RpcConnection(String),

    /// Bitcoin RPC request error
    #[error("Bitcoin RPC request failed: {0}")]
    RpcRequest(String),

    /// Bitcoin RPC response error
    #[error("Bitcoin RPC response error: {message}")]
    RpcResponse { code: i32, message: String },

    /// Transaction building error
    #[error("Transaction build failed: {0}")]
    TransactionBuild(String),

    /// Transaction signing error
    #[error("Transaction signing failed: {0}")]
    TransactionSign(String),

    /// Transaction broadcast error
    #[error("Transaction broadcast failed: {0}")]
    TransactionBroadcast(String),

    /// Transaction not found
    #[error("Transaction not found: {0}")]
    TransactionNotFound(String),

    /// Insufficient funds
    #[error("Insufficient funds: required {required} satoshis, available {available}")]
    InsufficientFunds { required: u64, available: u64 },

    /// Invalid address
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    /// Invalid transaction
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    /// Confirmation timeout
    #[error("Confirmation timeout after {attempts} attempts")]
    ConfirmationTimeout { attempts: u32 },

    /// Atomicals protocol error
    #[error("Atomicals protocol error: {0}")]
    AtomicalsProtocol(String),

    /// Atomicals mint error
    #[error("Atomicals mint failed: {0}")]
    AtomicalsMint(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Network error
    #[error("Network error: {0}")]
    Network(String),

    /// Retry exhausted
    #[error("Retry exhausted after {attempts} attempts: {last_error}")]
    RetryExhausted { attempts: u32, last_error: String },

    /// Chain not supported
    #[error("Chain not supported: {0}")]
    ChainNotSupported(String),

    /// Invalid epoch root
    #[error("Invalid epoch root: {0}")]
    InvalidEpochRoot(String),

    /// Invalid input
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Storage error
    #[error("Storage error: {0}")]
    Storage(String),

    /// State transition error
    #[error("State transition error: {0}")]
    StateTransition(String),
}

/// P4 Result type
pub type P4Result<T> = Result<T, P4Error>;

impl From<reqwest::Error> for P4Error {
    fn from(e: reqwest::Error) -> Self {
        P4Error::Network(e.to_string())
    }
}

impl From<serde_json::Error> for P4Error {
    fn from(e: serde_json::Error) -> Self {
        P4Error::Serialization(e.to_string())
    }
}

impl From<hex::FromHexError> for P4Error {
    fn from(e: hex::FromHexError) -> Self {
        P4Error::Serialization(format!("Hex decode error: {}", e))
    }
}
