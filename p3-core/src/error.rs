//! P3 Error Codes Registry
//!
//! Based on Chapter 10: Error Code Registry (v1)
//!
//! Error code format: P3-{module}-{sequence}
//! - P3-GATE: Gate violations
//! - P3-EPOCH: Epoch errors
//! - P3-MANIFEST: Manifest errors
//! - P3-POINTS: Points calculation errors
//! - P3-TREASURY: Treasury errors
//! - P3-CLEARING: Clearing errors
//! - P3-EXEC: Execution errors
//! - P3-VERSION: Version errors

use thiserror::Error;

/// P3 Result type
pub type P3Result<T> = Result<T, P3Error>;

/// P3 Error type
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum P3Error {
    // ============================================================
    // Gate Errors (P3-GATE-*)
    // ============================================================
    /// [P3-GATE-001] Evidence level below threshold
    #[error("[P3-GATE-001] Evidence level {actual:?} below required threshold {required:?}")]
    EvidenceBelowThreshold {
        required: EvidenceLevelThreshold,
        actual: EvidenceLevelThreshold,
    },

    /// [P3-GATE-002] Degraded mode blocks operation
    #[error("[P3-GATE-002] Degraded mode {flag:?} blocks strong economic action")]
    DegradedModeBlocks { flag: String },

    /// [P3-GATE-003] Unknown version blocks operation
    #[error("[P3-GATE-003] Unknown version {version} blocks operation")]
    UnknownVersionBlocks { version: String },

    /// [P3-GATE-004] Execution proof required but missing
    #[error("[P3-GATE-004] Execution proof required for action {action}")]
    ExecutionProofRequired { action: String },

    /// [P3-GATE-005] Strong action gate violation
    #[error("[P3-GATE-005] Strong economic action {action} requires {required}")]
    StrongActionGateViolation { action: String, required: String },

    /// [P3-GATE-006] Append-only violation
    #[error("[P3-GATE-006] Append-only violation: cannot modify sealed epoch {epoch_id}")]
    AppendOnlyViolation { epoch_id: String },

    /// [P3-GATE-007] Verdict reference required
    #[error("[P3-GATE-007] Verdict reference required for forfeit/fine operation")]
    VerdictRefRequired,

    // ============================================================
    // Epoch Errors (P3-EPOCH-*)
    // ============================================================
    /// [P3-EPOCH-001] Epoch not found
    #[error("[P3-EPOCH-001] Epoch {epoch_id} not found")]
    EpochNotFound { epoch_id: String },

    /// [P3-EPOCH-002] Epoch already sealed
    #[error("[P3-EPOCH-002] Epoch {epoch_id} already sealed")]
    EpochAlreadySealed { epoch_id: String },

    /// [P3-EPOCH-003] Invalid epoch window
    #[error("[P3-EPOCH-003] Invalid epoch window: start >= end")]
    InvalidEpochWindow,

    /// [P3-EPOCH-004] Cutoff reference mismatch
    #[error("[P3-EPOCH-004] Cutoff reference does not match P1 sequence")]
    CutoffRefMismatch,

    /// [P3-EPOCH-005] Epoch ID verification failed
    #[error("[P3-EPOCH-005] Epoch ID verification failed")]
    EpochIdVerificationFailed,

    // ============================================================
    // Manifest Errors (P3-MANIFEST-*)
    // ============================================================
    /// [P3-MANIFEST-001] Manifest digest mismatch
    #[error("[P3-MANIFEST-001] Manifest digest mismatch: expected {expected}, got {actual}")]
    ManifestDigestMismatch { expected: String, actual: String },

    /// [P3-MANIFEST-002] Event not in manifest
    #[error("[P3-MANIFEST-002] Event {event_id} not in manifest")]
    EventNotInManifest { event_id: String },

    /// [P3-MANIFEST-003] Invalid event type
    #[error("[P3-MANIFEST-003] Invalid event type {event_type}")]
    InvalidEventType { event_type: String },

    /// [P3-MANIFEST-004] Set digest verification failed
    #[error("[P3-MANIFEST-004] Set {set_name} digest verification failed")]
    SetDigestVerificationFailed { set_name: String },

    // ============================================================
    // Points Errors (P3-POINTS-*)
    // ============================================================
    /// [P3-POINTS-001] Weights version not found
    #[error("[P3-POINTS-001] Weights version {version} not found")]
    WeightsVersionNotFound { version: String },

    /// [P3-POINTS-002] Points calculation overflow
    #[error("[P3-POINTS-002] Points calculation overflow")]
    PointsCalculationOverflow,

    /// [P3-POINTS-003] Invalid points value
    #[error("[P3-POINTS-003] Invalid points value: {reason}")]
    InvalidPointsValue { reason: String },

    /// [P3-POINTS-004] Rounding error
    #[error("[P3-POINTS-004] Rounding error: {reason}")]
    RoundingError { reason: String },

    // ============================================================
    // Treasury Errors (P3-TREASURY-*)
    // ============================================================
    /// [P3-TREASURY-001] Pool ratio sum not equal to 1
    #[error("[P3-TREASURY-001] Pool ratio sum {sum} != 1.0")]
    InvalidPoolRatioSum { sum: String },

    /// [P3-TREASURY-002] Pool not found
    #[error("[P3-TREASURY-002] Pool {pool} not found")]
    PoolNotFound { pool: String },

    /// [P3-TREASURY-003] Fee split violation (mixing tax)
    #[error("[P3-TREASURY-003] Fee split violation: cannot mix {column1} and {column2}")]
    FeeSplitViolation { column1: String, column2: String },

    /// [P3-TREASURY-004] Budget exceeded
    #[error("[P3-TREASURY-004] Budget exceeded: requested {requested}, available {available}")]
    BudgetExceeded { requested: String, available: String },

    // ============================================================
    // Clearing Errors (P3-CLEARING-*)
    // ============================================================
    /// [P3-CLEARING-001] Deposit not found
    #[error("[P3-CLEARING-001] Deposit {deposit_id} not found")]
    DepositNotFound { deposit_id: String },

    /// [P3-CLEARING-002] Invalid deposit status transition
    #[error("[P3-CLEARING-002] Invalid deposit status transition: {from} -> {to}")]
    InvalidDepositStatusTransition { from: String, to: String },

    /// [P3-CLEARING-003] Clawback target epochs missing
    #[error("[P3-CLEARING-003] Clawback requires target_epochs_digest")]
    ClawbackTargetEpochsMissing,

    /// [P3-CLEARING-004] Ancestor protection exceeded
    #[error("[P3-CLEARING-004] Ancestor layer recovery cap exceeded")]
    AncestorProtectionExceeded,

    // ============================================================
    // Execution Errors (P3-EXEC-*)
    // ============================================================
    /// [P3-EXEC-001] Idempotency key collision
    #[error("[P3-EXEC-001] Idempotency key {key} already exists with different parameters")]
    IdempotencyKeyCollision { key: String },

    /// [P3-EXEC-002] Pending not resolved
    #[error("[P3-EXEC-002] Pending {pending_id} not resolved: {reason}")]
    PendingNotResolved { pending_id: String, reason: String },

    /// [P3-EXEC-003] Attempt chain exhausted
    #[error("[P3-EXEC-003] Attempt chain {chain_id} exhausted after {attempts} attempts")]
    AttemptChainExhausted { chain_id: String, attempts: u32 },

    /// [P3-EXEC-004] Invalid execution status
    #[error("[P3-EXEC-004] Invalid execution status: {status}")]
    InvalidExecutionStatus { status: String },

    // ============================================================
    // Version Errors (P3-VERSION-*)
    // ============================================================
    /// [P3-VERSION-001] Version rollback attempted
    #[error("[P3-VERSION-001] Version rollback not allowed: {from} -> {to}")]
    VersionRollbackAttempted { from: String, to: String },

    /// [P3-VERSION-002] Incompatible version
    #[error("[P3-VERSION-002] Incompatible version {version}: {reason}")]
    IncompatibleVersion { version: String, reason: String },

    /// [P3-VERSION-003] Version not found
    #[error("[P3-VERSION-003] Version {version_id} not found")]
    VersionNotFound { version_id: String },

    // ============================================================
    // General Errors
    // ============================================================
    /// Invalid digest format
    #[error("Invalid digest format")]
    InvalidDigest,

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Internal error
    #[error("Internal error: {0}")]
    InternalError(String),

    /// Invalid state
    #[error("Invalid state: {reason}")]
    InvalidState { reason: String },

    /// Entity not found
    #[error("{entity} not found: {id}")]
    NotFound { entity: String, id: String },

    /// Invalid amount
    #[error("Invalid amount: {reason}")]
    InvalidAmount { reason: String },

    /// Insufficient balance
    #[error("Insufficient balance in {pool}: required {required}, available {available}")]
    InsufficientBalance {
        pool: String,
        required: rust_decimal::Decimal,
        available: rust_decimal::Decimal,
    },

    /// Invariant violation
    #[error("Invariant violation: {invariant} - {details}")]
    InvariantViolation { invariant: String, details: String },
}

/// Evidence level threshold for gate checks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceLevelThreshold {
    A,
    B,
    Pending,
}

impl std::fmt::Display for EvidenceLevelThreshold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvidenceLevelThreshold::A => write!(f, "A"),
            EvidenceLevelThreshold::B => write!(f, "B"),
            EvidenceLevelThreshold::Pending => write!(f, "Pending"),
        }
    }
}

impl From<serde_json::Error> for P3Error {
    fn from(err: serde_json::Error) -> Self {
        P3Error::SerializationError(err.to_string())
    }
}
