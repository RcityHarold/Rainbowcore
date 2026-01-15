//! P3 Executor Error Types

use thiserror::Error;

/// P3 Executor Result type
pub type ExecutorResult<T> = Result<T, ExecutorError>;

/// P3 Executor Error
#[derive(Debug, Error)]
pub enum ExecutorError {
    /// Verification failed
    #[error("Verification failed: {reason}")]
    VerificationFailed { reason: String },

    /// Execution failed
    #[error("Execution failed: {reason}")]
    ExecutionFailed { reason: String },

    /// Invalid phase transition
    #[error("Invalid phase transition from {from} to {to}")]
    InvalidPhaseTransition { from: String, to: String },

    /// Quote expired
    #[error("Quote expired: {quote_id}")]
    QuoteExpired { quote_id: String },

    /// Execution timeout
    #[error("Execution timeout: {execution_id}")]
    ExecutionTimeout { execution_id: String },

    /// Idempotency conflict
    #[error("Idempotency conflict: key {key} already exists with different result")]
    IdempotencyConflict { key: String },

    /// Attempt chain exhausted
    #[error("Attempt chain exhausted after {attempts} attempts")]
    AttemptChainExhausted { attempts: u32 },

    /// Gate check failed
    #[error("Gate check failed: {gate}")]
    GateCheckFailed { gate: String },

    /// Resource lock failed
    #[error("Resource lock failed: {resource}")]
    ResourceLockFailed { resource: String },

    /// Proof generation failed
    #[error("Proof generation failed: {reason}")]
    ProofGenerationFailed { reason: String },

    /// Storage error
    #[error("Storage error: {0}")]
    Storage(String),

    /// Core error
    #[error("Core error: {0}")]
    Core(String),

    /// Verifier error
    #[error("Verifier error: {0}")]
    Verifier(String),

    /// Not found
    #[error("{entity_type} not found: {id}")]
    NotFound { entity_type: String, id: String },

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl ExecutorError {
    /// Create a verification failed error
    pub fn verification_failed(reason: impl Into<String>) -> Self {
        Self::VerificationFailed {
            reason: reason.into(),
        }
    }

    /// Create an execution failed error
    pub fn execution_failed(reason: impl Into<String>) -> Self {
        Self::ExecutionFailed {
            reason: reason.into(),
        }
    }

    /// Create a not found error
    pub fn not_found(entity_type: impl Into<String>, id: impl Into<String>) -> Self {
        Self::NotFound {
            entity_type: entity_type.into(),
            id: id.into(),
        }
    }

    /// Check if error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            ExecutorError::ExecutionTimeout { .. }
                | ExecutorError::ResourceLockFailed { .. }
                | ExecutorError::Storage(_)
        )
    }
}

impl From<p3_core::P3Error> for ExecutorError {
    fn from(err: p3_core::P3Error) -> Self {
        Self::Core(err.to_string())
    }
}

impl From<p3_verifier::VerifierError> for ExecutorError {
    fn from(err: p3_verifier::VerifierError) -> Self {
        Self::Verifier(err.to_string())
    }
}

impl From<p3_store::P3StoreError> for ExecutorError {
    fn from(err: p3_store::P3StoreError) -> Self {
        Self::Storage(err.to_string())
    }
}
