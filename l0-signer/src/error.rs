//! Error types for L0 Signer

use thiserror::Error;

/// Signer errors
#[derive(Error, Debug)]
pub enum SignerError {
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    #[error("Threshold not met: got {got}, need {need}")]
    ThresholdNotMet { got: u32, need: u32 },

    #[error("Invalid signer: {0}")]
    InvalidSigner(String),

    #[error("Signer not in set: {0}")]
    SignerNotInSet(String),

    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("Session already complete")]
    SessionComplete,

    #[error("Session expired")]
    SessionExpired,

    #[error("Duplicate signature from signer: {0}")]
    DuplicateSignature(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Crypto error: {0}")]
    Crypto(String),
}

/// Result type for signer operations
pub type SignerResult<T> = Result<T, SignerError>;

/// Signing session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Waiting for signatures
    Pending,
    /// Collecting signatures
    Collecting,
    /// Threshold met, can finalize
    ThresholdMet,
    /// Successfully signed
    Signed,
    /// Failed or expired
    Failed,
}

impl SessionState {
    /// Check if the session can accept more signatures
    pub fn can_accept_signature(&self) -> bool {
        matches!(self, Self::Pending | Self::Collecting | Self::ThresholdMet)
    }

    /// Check if the session is terminal
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Signed | Self::Failed)
    }
}
