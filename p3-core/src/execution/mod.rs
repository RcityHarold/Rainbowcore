//! Execution Loop Module
//!
//! Chapter 8: Execution Loop and Idempotency
//!
//! Implements the quote → commit → execute → resolve state machine:
//! - Quote: Estimate and lock resources
//! - Commit: Finalize the execution plan
//! - Execute: Perform the operation
//! - Resolve: Confirm completion or handle failure

mod engine;
mod idempotency;
mod attempt;

pub use engine::*;
pub use idempotency::*;
pub use attempt::*;

use crate::error::{P3Error, P3Result};
use crate::types::*;
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use std::collections::HashMap;

/// Execution phase in the state machine
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutionPhase {
    /// Initial phase - estimating resources
    Quote,
    /// Resources locked, ready to commit
    Commit,
    /// Executing the operation
    Execute,
    /// Resolving the outcome
    Resolve,
    /// Terminal: Successfully completed
    Completed,
    /// Terminal: Failed
    Failed,
    /// Terminal: Rolled back
    RolledBack,
}

impl ExecutionPhase {
    /// Check if phase is terminal
    pub fn is_terminal(&self) -> bool {
        matches!(self, ExecutionPhase::Completed | ExecutionPhase::Failed | ExecutionPhase::RolledBack)
    }

    /// Get valid transitions from current phase
    pub fn valid_transitions(&self) -> Vec<ExecutionPhase> {
        match self {
            ExecutionPhase::Quote => vec![ExecutionPhase::Commit, ExecutionPhase::Failed],
            ExecutionPhase::Commit => vec![ExecutionPhase::Execute, ExecutionPhase::RolledBack],
            ExecutionPhase::Execute => vec![ExecutionPhase::Resolve, ExecutionPhase::Failed],
            ExecutionPhase::Resolve => vec![ExecutionPhase::Completed, ExecutionPhase::Failed],
            _ => vec![], // Terminal states have no transitions
        }
    }

    /// Check if transition to target phase is valid
    pub fn can_transition_to(&self, target: &ExecutionPhase) -> bool {
        self.valid_transitions().contains(target)
    }
}

/// Quote request for an operation
#[derive(Clone, Debug)]
pub struct QuoteRequest {
    /// Operation type
    pub operation_type: OperationType,
    /// Target reference
    pub target_ref: P3Digest,
    /// Epoch ID
    pub epoch_id: EpochId,
    /// Requested amount (if applicable)
    pub amount: Option<Decimal>,
    /// Additional parameters
    pub params_digest: P3Digest,
    /// Initiator
    pub initiator_ref: String,
    /// Deadline for execution
    pub deadline: Option<DateTime<Utc>>,
}

impl QuoteRequest {
    /// Create new quote request
    pub fn new(
        operation_type: OperationType,
        target_ref: P3Digest,
        epoch_id: EpochId,
        initiator_ref: impl Into<String>,
    ) -> Self {
        Self {
            operation_type,
            target_ref,
            epoch_id,
            amount: None,
            params_digest: P3Digest::zero(),
            initiator_ref: initiator_ref.into(),
            deadline: None,
        }
    }

    /// Set amount
    pub fn with_amount(mut self, amount: Decimal) -> Self {
        self.amount = Some(amount);
        self
    }

    /// Set params digest
    pub fn with_params(mut self, params_digest: P3Digest) -> Self {
        self.params_digest = params_digest;
        self
    }

    /// Set deadline
    pub fn with_deadline(mut self, deadline: DateTime<Utc>) -> Self {
        self.deadline = Some(deadline);
        self
    }
}

/// Quote response
#[derive(Clone, Debug)]
pub struct QuoteResponse {
    /// Quote ID
    pub quote_id: String,
    /// Quoted amount
    pub quoted_amount: Decimal,
    /// Fees
    pub fees: Decimal,
    /// Resource locks required
    pub resource_locks: Vec<ResourceLock>,
    /// Quote validity
    pub valid_until: DateTime<Utc>,
    /// Quote digest for verification
    pub quote_digest: P3Digest,
}

impl QuoteResponse {
    /// Check if quote is expired
    pub fn is_expired(&self, now: &DateTime<Utc>) -> bool {
        now > &self.valid_until
    }

    /// Total cost (amount + fees)
    pub fn total_cost(&self) -> Decimal {
        self.quoted_amount + self.fees
    }
}

/// Resource lock
#[derive(Clone, Debug)]
pub struct ResourceLock {
    /// Lock ID
    pub lock_id: String,
    /// Resource type
    pub resource_type: ResourceType,
    /// Amount locked
    pub amount: Decimal,
    /// Pool (if applicable)
    pub pool: Option<TreasuryPool>,
    /// Lock expiry
    pub expires_at: DateTime<Utc>,
}

/// Resource type
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResourceType {
    /// Treasury pool balance
    PoolBalance,
    /// Escrow funds
    Escrow,
    /// Deposit
    Deposit,
    /// Rate limit quota
    RateLimit,
}

/// Commit request
#[derive(Clone, Debug)]
pub struct CommitRequest {
    /// Quote ID to commit
    pub quote_id: String,
    /// Quote digest for verification
    pub quote_digest: P3Digest,
    /// Idempotency key
    pub idempotency_key: IdempotencyKey,
    /// Commit time
    pub committed_at: DateTime<Utc>,
}

/// Commit response
#[derive(Clone, Debug)]
pub struct CommitResponse {
    /// Execution ID
    pub execution_id: String,
    /// Committed locks
    pub committed_locks: Vec<String>,
    /// Expected completion time
    pub expected_completion: Option<DateTime<Utc>>,
    /// Commit digest
    pub commit_digest: P3Digest,
}

/// Execute request
#[derive(Clone, Debug)]
pub struct ExecuteRequest {
    /// Execution ID
    pub execution_id: String,
    /// Commit digest for verification
    pub commit_digest: P3Digest,
    /// Executor reference
    pub executor_ref: String,
}

/// Execute response
#[derive(Clone, Debug)]
pub struct ExecuteResponse {
    /// Execution ID
    pub execution_id: String,
    /// Success flag
    pub success: bool,
    /// Result digest
    pub result_digest: Option<P3Digest>,
    /// Error (if failed)
    pub error: Option<ExecutionError>,
    /// Execution proof
    pub execution_proof: Option<ExecutionProofRef>,
}

/// Execution error
#[derive(Clone, Debug)]
pub struct ExecutionError {
    /// Error code
    pub code: String,
    /// Error digest
    pub error_digest: P3Digest,
    /// Is retryable
    pub retryable: bool,
    /// Suggested retry delay
    pub retry_after: Option<chrono::Duration>,
}

/// Resolve request
#[derive(Clone, Debug)]
pub struct ResolveRequest {
    /// Execution ID
    pub execution_id: String,
    /// Resolution type
    pub resolution_type: ExecutionResolutionType,
    /// Resolution proof
    pub resolution_proof: Option<P3Digest>,
    /// Resolver reference
    pub resolver_ref: String,
}

/// Execution resolution type
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutionResolutionType {
    /// Successfully completed
    Success,
    /// Failed permanently
    PermanentFailure,
    /// Needs retry
    RetryRequired,
    /// Requires manual intervention
    ManualIntervention,
    /// Escalated
    Escalated,
}

/// Resolve response
#[derive(Clone, Debug)]
pub struct ResolveResponse {
    /// Execution ID
    pub execution_id: String,
    /// Final status
    pub final_status: ExecutionFinalStatus,
    /// Resolution digest
    pub resolution_digest: P3Digest,
    /// Next steps (if any)
    pub next_steps: Option<NextSteps>,
}

/// Execution final status
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutionFinalStatus {
    /// Completed successfully
    Completed,
    /// Failed
    Failed,
    /// Rolled back
    RolledBack,
    /// Pending further action
    Pending,
}

/// Next steps after resolution
#[derive(Clone, Debug)]
pub struct NextSteps {
    /// Action required
    pub action: NextAction,
    /// New attempt chain ID
    pub attempt_chain_id: Option<AttemptChainId>,
    /// Suggested retry time
    pub retry_at: Option<DateTime<Utc>>,
}

/// Next action type
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NextAction {
    /// Retry the operation
    Retry,
    /// Create new pending entry
    CreatePending,
    /// Escalate to governance
    Escalate,
    /// No action needed
    None,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_phase_terminal() {
        assert!(!ExecutionPhase::Quote.is_terminal());
        assert!(!ExecutionPhase::Execute.is_terminal());
        assert!(ExecutionPhase::Completed.is_terminal());
        assert!(ExecutionPhase::Failed.is_terminal());
    }

    #[test]
    fn test_execution_phase_transitions() {
        assert!(ExecutionPhase::Quote.can_transition_to(&ExecutionPhase::Commit));
        assert!(ExecutionPhase::Commit.can_transition_to(&ExecutionPhase::Execute));
        assert!(!ExecutionPhase::Quote.can_transition_to(&ExecutionPhase::Resolve));
        assert!(!ExecutionPhase::Completed.can_transition_to(&ExecutionPhase::Quote));
    }

    #[test]
    fn test_quote_request() {
        let request = QuoteRequest::new(
            OperationType::Distribution,
            P3Digest::zero(),
            EpochId::new("epoch:1"),
            "actor:1",
        )
        .with_amount(Decimal::new(100, 0));

        assert_eq!(request.amount, Some(Decimal::new(100, 0)));
    }

    #[test]
    fn test_quote_response_expired() {
        let now = Utc::now();
        let past = now - chrono::Duration::hours(1);
        let future = now + chrono::Duration::hours(1);

        let expired_quote = QuoteResponse {
            quote_id: "q1".to_string(),
            quoted_amount: Decimal::new(100, 0),
            fees: Decimal::new(5, 0),
            resource_locks: vec![],
            valid_until: past,
            quote_digest: P3Digest::zero(),
        };
        assert!(expired_quote.is_expired(&now));

        let valid_quote = QuoteResponse {
            quote_id: "q2".to_string(),
            quoted_amount: Decimal::new(100, 0),
            fees: Decimal::new(5, 0),
            resource_locks: vec![],
            valid_until: future,
            quote_digest: P3Digest::zero(),
        };
        assert!(!valid_quote.is_expired(&now));
    }

    #[test]
    fn test_quote_response_total_cost() {
        let quote = QuoteResponse {
            quote_id: "q1".to_string(),
            quoted_amount: Decimal::new(100, 0),
            fees: Decimal::new(5, 0),
            resource_locks: vec![],
            valid_until: Utc::now(),
            quote_digest: P3Digest::zero(),
        };
        assert_eq!(quote.total_cost(), Decimal::new(105, 0));
    }
}
