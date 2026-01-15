//! Execution Loop and Idempotency
//!
//! Chapter 8: Execution Loop and Idempotency
//!
//! Core invariants:
//! - Strong economic actions require ExecutionProof
//! - Idempotency key collision detection
//! - AttemptChain for retry management

use super::common::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Execution proof reference
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionProofRef {
    pub proof_id: String,
    pub proof_type: ExecutionProofType,
    pub executor_ref: String,
    pub executed_at: DateTime<Utc>,
    pub receipt_ref: Option<String>,
    pub proof_digest: P3Digest,
}

impl ExecutionProofRef {
    /// Verify proof is valid
    pub fn is_valid(&self) -> bool {
        !self.proof_id.is_empty() && !self.executor_ref.is_empty()
    }
}

/// Execution proof type
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionProofType {
    /// On-chain transaction
    OnChain,
    /// Off-chain with receipt
    OffChain,
    /// Internal credit
    Credit,
    /// Multi-signature
    MultiSig,
}

/// Pending entry
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingEntry {
    pub pending_id: PendingId,
    pub pending_kind: PendingKind,
    pub bound_epoch_id: EpochId,
    pub target_ref: String,
    pub reason_digest: P3Digest,
    pub created_at: DateTime<Utc>,
    pub deadline: Option<DateTime<Utc>>,
    pub attempt_chain_id: Option<AttemptChainId>,
    pub resolution: Option<PendingResolution>,
    pub supersedes_ref: Option<PendingId>,
}

impl PendingEntry {
    /// Check if pending is expired
    pub fn is_expired(&self, now: &DateTime<Utc>) -> bool {
        self.deadline.map(|d| now > &d).unwrap_or(false)
    }

    /// Check if pending is resolved
    pub fn is_resolved(&self) -> bool {
        self.resolution.is_some()
    }
}

/// Pending resolution
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingResolution {
    pub resolved_at: DateTime<Utc>,
    pub resolution_type: ResolutionType,
    pub resolution_proof_digest: Option<P3Digest>,
    pub resolver_ref: String,
}

/// Resolution type
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionType {
    /// Successfully resolved
    Resolved,
    /// Escalated to higher level
    Escalated,
    /// Expired and closed
    Expired,
    /// Waived by policy
    Waived,
    /// Superseded by new entry
    Superseded,
}

/// Attempt chain
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttemptChain {
    pub chain_id: AttemptChainId,
    pub target_operation: String,
    pub target_ref: P3Digest,
    pub max_attempts: u32,
    pub attempts: Vec<Attempt>,
    pub status: AttemptChainStatus,
    pub created_at: DateTime<Utc>,
    pub last_attempt_at: Option<DateTime<Utc>>,
    pub backoff_policy: BackoffPolicy,
}

impl AttemptChain {
    /// Get current attempt count
    pub fn attempt_count(&self) -> u32 {
        self.attempts.len() as u32
    }

    /// Check if can retry
    pub fn can_retry(&self) -> bool {
        self.attempt_count() < self.max_attempts
            && matches!(self.status, AttemptChainStatus::InProgress | AttemptChainStatus::Pending)
    }

    /// Get latest attempt
    pub fn latest_attempt(&self) -> Option<&Attempt> {
        self.attempts.last()
    }

    /// Calculate next retry time
    pub fn next_retry_at(&self) -> Option<DateTime<Utc>> {
        if !self.can_retry() {
            return None;
        }
        let attempt_count = self.attempt_count();
        let delay_secs = self.backoff_policy.delay_for_attempt(attempt_count);
        self.last_attempt_at
            .map(|t| t + chrono::Duration::seconds(delay_secs as i64))
    }
}

/// Attempt chain status
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptChainStatus {
    Pending,
    InProgress,
    Succeeded,
    Failed,
    Exhausted,
    Cancelled,
}

/// Single attempt
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attempt {
    pub attempt_no: u32,
    pub attempted_at: DateTime<Utc>,
    pub result: AttemptResult,
    pub error_digest: Option<P3Digest>,
    pub executor_ref: Option<String>,
}

/// Attempt result
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptResult {
    Success,
    RetryableError,
    PermanentError,
    Timeout,
}

/// Backoff policy
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackoffPolicy {
    pub initial_delay_secs: u32,
    pub max_delay_secs: u32,
    pub multiplier: f64,
    pub jitter: bool,
}

impl BackoffPolicy {
    /// Calculate delay for a specific attempt
    pub fn delay_for_attempt(&self, attempt: u32) -> u32 {
        let delay = (self.initial_delay_secs as f64) * self.multiplier.powi(attempt as i32);
        (delay as u32).min(self.max_delay_secs)
    }
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            initial_delay_secs: 1,
            max_delay_secs: 300,
            multiplier: 2.0,
            jitter: true,
        }
    }
}

/// Idempotency record
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdempotencyRecord {
    pub key: IdempotencyKey,
    pub operation_type: String,
    pub parameters_digest: P3Digest,
    pub result_digest: Option<P3Digest>,
    pub status: IdempotencyStatus,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub ttl_secs: Option<u64>,
}

impl IdempotencyRecord {
    /// Check if record is expired
    pub fn is_expired(&self, now: &DateTime<Utc>) -> bool {
        if let (Some(ttl), Some(completed)) = (self.ttl_secs, self.completed_at) {
            let expiry = completed + chrono::Duration::seconds(ttl as i64);
            now > &expiry
        } else {
            false
        }
    }

    /// Check if parameters match
    pub fn parameters_match(&self, params_digest: &P3Digest) -> bool {
        self.parameters_digest == *params_digest
    }
}

/// Idempotency status
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdempotencyStatus {
    InProgress,
    Completed,
    Failed,
}

/// Execution context
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionContext {
    pub execution_id: String,
    pub bound_epoch_id: EpochId,
    pub operation_type: OperationType,
    pub initiator_ref: String,
    pub idempotency_key: IdempotencyKey,
    pub started_at: DateTime<Utc>,
    pub deadline: Option<DateTime<Utc>>,
    pub dependencies: Vec<P3Digest>,
    pub state: ExecutionState,
}

/// Operation type
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationType {
    PointsCalculation,
    Attribution,
    Distribution,
    Clawback,
    DepositOperation,
    Fine,
    Subsidy,
    BudgetSpend,
}

/// Execution state
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionState {
    Pending,
    Validating,
    Executing,
    Committing,
    Completed,
    Failed,
    Rolledback,
}

/// Execution result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub execution_id: String,
    pub success: bool,
    pub result_digest: Option<P3Digest>,
    pub error_code: Option<String>,
    pub error_digest: Option<P3Digest>,
    pub completed_at: DateTime<Utc>,
    pub execution_proof: Option<ExecutionProofRef>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attempt_chain_can_retry() {
        let chain = AttemptChain {
            chain_id: AttemptChainId::new("chain1"),
            target_operation: "test".to_string(),
            target_ref: P3Digest::zero(),
            max_attempts: 3,
            attempts: vec![],
            status: AttemptChainStatus::InProgress,
            created_at: Utc::now(),
            last_attempt_at: None,
            backoff_policy: BackoffPolicy::default(),
        };
        assert!(chain.can_retry());
        assert_eq!(chain.attempt_count(), 0);
    }

    #[test]
    fn test_backoff_policy_delay() {
        let policy = BackoffPolicy {
            initial_delay_secs: 1,
            max_delay_secs: 60,
            multiplier: 2.0,
            jitter: false,
        };
        assert_eq!(policy.delay_for_attempt(0), 1);
        assert_eq!(policy.delay_for_attempt(1), 2);
        assert_eq!(policy.delay_for_attempt(2), 4);
        assert_eq!(policy.delay_for_attempt(10), 60); // Capped
    }

    #[test]
    fn test_pending_entry_expiry() {
        let now = Utc::now();
        let past = now - chrono::Duration::hours(1);
        let future = now + chrono::Duration::hours(1);

        let expired = PendingEntry {
            pending_id: PendingId::new("p1"),
            pending_kind: PendingKind::Evidence,
            bound_epoch_id: EpochId::new("epoch:test"),
            target_ref: "target".to_string(),
            reason_digest: P3Digest::zero(),
            created_at: past,
            deadline: Some(past),
            attempt_chain_id: None,
            resolution: None,
            supersedes_ref: None,
        };
        assert!(expired.is_expired(&now));

        let not_expired = PendingEntry {
            pending_id: PendingId::new("p2"),
            pending_kind: PendingKind::Evidence,
            bound_epoch_id: EpochId::new("epoch:test"),
            target_ref: "target".to_string(),
            reason_digest: P3Digest::zero(),
            created_at: now,
            deadline: Some(future),
            attempt_chain_id: None,
            resolution: None,
            supersedes_ref: None,
        };
        assert!(!not_expired.is_expired(&now));
    }

    #[test]
    fn test_idempotency_record_match() {
        let params = P3Digest::blake3(b"params");
        let record = IdempotencyRecord {
            key: IdempotencyKey::new("key1"),
            operation_type: "test".to_string(),
            parameters_digest: params.clone(),
            result_digest: None,
            status: IdempotencyStatus::Completed,
            created_at: Utc::now(),
            completed_at: Some(Utc::now()),
            ttl_secs: Some(3600),
        };
        assert!(record.parameters_match(&params));
        assert!(!record.parameters_match(&P3Digest::zero()));
    }
}
