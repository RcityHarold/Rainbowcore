//! Execution Engine
//!
//! Implements the execution state machine: quote → commit → execute → resolve

use super::*;
use crate::error::{P3Error, P3Result};
use crate::types::*;
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use std::collections::HashMap;

/// Execution engine
pub struct ExecutionEngine {
    /// Active executions
    executions: HashMap<String, ExecutionRecord>,
    /// Active quotes
    quotes: HashMap<String, QuoteRecord>,
    /// Resource locks
    resource_locks: HashMap<String, ResourceLock>,
    /// Quote validity duration
    quote_validity_secs: i64,
    /// Execution timeout
    execution_timeout_secs: i64,
}

impl ExecutionEngine {
    /// Create new execution engine
    pub fn new() -> Self {
        Self {
            executions: HashMap::new(),
            quotes: HashMap::new(),
            resource_locks: HashMap::new(),
            quote_validity_secs: 300, // 5 minutes
            execution_timeout_secs: 3600, // 1 hour
        }
    }

    /// Set quote validity duration
    pub fn with_quote_validity(mut self, secs: i64) -> Self {
        self.quote_validity_secs = secs;
        self
    }

    /// Set execution timeout
    pub fn with_execution_timeout(mut self, secs: i64) -> Self {
        self.execution_timeout_secs = secs;
        self
    }

    /// Phase 1: Quote - Estimate and prepare resource locks
    pub fn quote(&mut self, request: QuoteRequest) -> P3Result<QuoteResponse> {
        let now = Utc::now();
        let quote_id = format!(
            "quote:{}:{}",
            request.epoch_id.as_str(),
            now.timestamp_millis()
        );

        // Calculate quoted amount and fees
        let (quoted_amount, fees) = self.calculate_quote(&request)?;

        // Create resource locks
        let locks = self.create_resource_locks(&quote_id, &request, quoted_amount)?;

        let valid_until = now + chrono::Duration::seconds(self.quote_validity_secs);

        // Compute quote digest
        let quote_data = format!(
            "{}:{}:{}:{}:{}",
            quote_id,
            request.operation_type.name(),
            quoted_amount,
            fees,
            valid_until.timestamp()
        );
        let quote_digest = P3Digest::blake3(quote_data.as_bytes());

        let response = QuoteResponse {
            quote_id: quote_id.clone(),
            quoted_amount,
            fees,
            resource_locks: locks.clone(),
            valid_until,
            quote_digest: quote_digest.clone(),
        };

        // Store quote record
        let record = QuoteRecord {
            quote_id: quote_id.clone(),
            request: request.clone(),
            response: response.clone(),
            status: QuoteStatus::Active,
            created_at: now,
        };
        self.quotes.insert(quote_id, record);

        // Store resource locks
        for lock in locks {
            self.resource_locks.insert(lock.lock_id.clone(), lock);
        }

        Ok(response)
    }

    /// Phase 2: Commit - Lock resources and prepare for execution
    pub fn commit(&mut self, request: CommitRequest) -> P3Result<CommitResponse> {
        let now = Utc::now();

        // Find and validate quote
        let quote = self.quotes.get_mut(&request.quote_id).ok_or_else(|| {
            P3Error::NotFound {
                entity: "Quote".to_string(),
                id: request.quote_id.clone(),
            }
        })?;

        // Verify quote digest
        if quote.response.quote_digest != request.quote_digest {
            return Err(P3Error::InvalidState {
                reason: "Quote digest mismatch".to_string(),
            });
        }

        // Check if quote is expired
        if quote.response.is_expired(&now) {
            quote.status = QuoteStatus::Expired;
            return Err(P3Error::InvalidState {
                reason: "Quote has expired".to_string(),
            });
        }

        // Check if already committed
        if quote.status != QuoteStatus::Active {
            return Err(P3Error::InvalidState {
                reason: format!("Quote is in {:?} status", quote.status),
            });
        }

        // Create execution record
        let execution_id = format!(
            "exec:{}:{}",
            quote.request.epoch_id.as_str(),
            now.timestamp_millis()
        );

        // Compute commit digest
        let commit_data = format!(
            "{}:{}:{}",
            execution_id,
            request.quote_digest.to_hex(),
            request.idempotency_key.as_str()
        );
        let commit_digest = P3Digest::blake3(commit_data.as_bytes());

        let deadline = now + chrono::Duration::seconds(self.execution_timeout_secs);

        let execution = ExecutionRecord {
            execution_id: execution_id.clone(),
            quote_id: request.quote_id.clone(),
            phase: ExecutionPhase::Commit,
            idempotency_key: request.idempotency_key.clone(),
            created_at: now,
            committed_at: Some(now),
            executed_at: None,
            resolved_at: None,
            deadline: Some(deadline),
            result: None,
            error: None,
            execution_proof: None,
            commit_digest: commit_digest.clone(),
        };

        // Update quote status
        quote.status = QuoteStatus::Committed;

        // Get committed lock IDs
        let committed_locks: Vec<String> = quote
            .response
            .resource_locks
            .iter()
            .map(|l| l.lock_id.clone())
            .collect();

        self.executions.insert(execution_id.clone(), execution);

        Ok(CommitResponse {
            execution_id,
            committed_locks,
            expected_completion: Some(deadline),
            commit_digest,
        })
    }

    /// Phase 3: Execute - Perform the operation
    pub fn execute(&mut self, request: ExecuteRequest) -> P3Result<ExecuteResponse> {
        let now = Utc::now();

        // Find execution
        let execution = self.executions.get_mut(&request.execution_id).ok_or_else(|| {
            P3Error::NotFound {
                entity: "Execution".to_string(),
                id: request.execution_id.clone(),
            }
        })?;

        // Verify commit digest
        if execution.commit_digest != request.commit_digest {
            return Err(P3Error::InvalidState {
                reason: "Commit digest mismatch".to_string(),
            });
        }

        // Check phase
        if execution.phase != ExecutionPhase::Commit {
            return Err(P3Error::InvalidState {
                reason: format!("Execution is in {:?} phase", execution.phase),
            });
        }

        // Check deadline
        if let Some(deadline) = execution.deadline {
            if now > deadline {
                execution.phase = ExecutionPhase::Failed;
                execution.error = Some(ExecutionError {
                    code: "TIMEOUT".to_string(),
                    error_digest: P3Digest::blake3(b"Execution timeout"),
                    retryable: true,
                    retry_after: Some(chrono::Duration::seconds(60)),
                });
                return Ok(ExecuteResponse {
                    execution_id: request.execution_id,
                    success: false,
                    result_digest: None,
                    error: execution.error.clone(),
                    execution_proof: None,
                });
            }
        }

        // Transition to Execute phase
        execution.phase = ExecutionPhase::Execute;
        execution.executed_at = Some(now);

        // Here the actual operation would be performed
        // For now, we simulate success
        let result_digest = P3Digest::blake3(format!("result:{}", execution.execution_id).as_bytes());

        // Create execution proof
        let proof = ExecutionProofRef {
            proof_id: format!("proof:{}", execution.execution_id),
            proof_type: ExecutionProofType::Credit,
            executor_ref: request.executor_ref.clone(),
            executed_at: now,
            receipt_ref: None,
            proof_digest: result_digest.clone(),
        };

        execution.result = Some(result_digest.clone());
        execution.execution_proof = Some(proof.clone());

        // Transition to Resolve phase
        execution.phase = ExecutionPhase::Resolve;

        Ok(ExecuteResponse {
            execution_id: request.execution_id,
            success: true,
            result_digest: Some(result_digest),
            error: None,
            execution_proof: Some(proof),
        })
    }

    /// Phase 4: Resolve - Confirm completion or handle failure
    pub fn resolve(&mut self, request: ResolveRequest) -> P3Result<ResolveResponse> {
        let now = Utc::now();

        // Find execution
        let execution = self.executions.get_mut(&request.execution_id).ok_or_else(|| {
            P3Error::NotFound {
                entity: "Execution".to_string(),
                id: request.execution_id.clone(),
            }
        })?;

        // Check phase
        if execution.phase != ExecutionPhase::Resolve && execution.phase != ExecutionPhase::Execute {
            return Err(P3Error::InvalidState {
                reason: format!("Cannot resolve execution in {:?} phase", execution.phase),
            });
        }

        execution.resolved_at = Some(now);

        let (final_status, next_steps) = match request.resolution_type {
            ExecutionResolutionType::Success => {
                execution.phase = ExecutionPhase::Completed;
                self.release_locks(&request.execution_id)?;
                (ExecutionFinalStatus::Completed, None)
            }
            ExecutionResolutionType::PermanentFailure => {
                execution.phase = ExecutionPhase::Failed;
                self.release_locks(&request.execution_id)?;
                (ExecutionFinalStatus::Failed, None)
            }
            ExecutionResolutionType::RetryRequired => {
                execution.phase = ExecutionPhase::Failed;
                (
                    ExecutionFinalStatus::Pending,
                    Some(NextSteps {
                        action: NextAction::Retry,
                        attempt_chain_id: None,
                        retry_at: Some(now + chrono::Duration::seconds(60)),
                    }),
                )
            }
            ExecutionResolutionType::ManualIntervention => {
                (
                    ExecutionFinalStatus::Pending,
                    Some(NextSteps {
                        action: NextAction::CreatePending,
                        attempt_chain_id: None,
                        retry_at: None,
                    }),
                )
            }
            ExecutionResolutionType::Escalated => {
                (
                    ExecutionFinalStatus::Pending,
                    Some(NextSteps {
                        action: NextAction::Escalate,
                        attempt_chain_id: None,
                        retry_at: None,
                    }),
                )
            }
        };

        // Compute resolution digest
        let resolution_data = format!(
            "{}:{}:{:?}",
            request.execution_id, request.resolver_ref, final_status
        );
        let resolution_digest = P3Digest::blake3(resolution_data.as_bytes());

        Ok(ResolveResponse {
            execution_id: request.execution_id,
            final_status,
            resolution_digest,
            next_steps,
        })
    }

    /// Rollback an execution
    pub fn rollback(&mut self, execution_id: &str) -> P3Result<()> {
        let execution = self.executions.get_mut(execution_id).ok_or_else(|| {
            P3Error::NotFound {
                entity: "Execution".to_string(),
                id: execution_id.to_string(),
            }
        })?;

        if execution.phase.is_terminal() {
            return Err(P3Error::InvalidState {
                reason: "Cannot rollback terminal execution".to_string(),
            });
        }

        execution.phase = ExecutionPhase::RolledBack;
        self.release_locks(execution_id)?;

        Ok(())
    }

    /// Get execution status
    pub fn get_execution(&self, execution_id: &str) -> Option<&ExecutionRecord> {
        self.executions.get(execution_id)
    }

    /// Get quote
    pub fn get_quote(&self, quote_id: &str) -> Option<&QuoteRecord> {
        self.quotes.get(quote_id)
    }

    /// Calculate quote for operation
    fn calculate_quote(&self, request: &QuoteRequest) -> P3Result<(Decimal, Decimal)> {
        // Base calculation - would be more complex in production
        let base_amount = request.amount.unwrap_or(Decimal::ZERO);
        let fee_rate = Decimal::new(1, 2); // 1% fee
        let fees = base_amount * fee_rate;

        Ok((base_amount, fees))
    }

    /// Create resource locks for a quote
    fn create_resource_locks(
        &self,
        quote_id: &str,
        request: &QuoteRequest,
        amount: Decimal,
    ) -> P3Result<Vec<ResourceLock>> {
        let now = Utc::now();
        let expiry = now + chrono::Duration::seconds(self.quote_validity_secs * 2);

        let mut locks = Vec::new();

        // Create pool balance lock if amount specified
        if amount > Decimal::ZERO {
            locks.push(ResourceLock {
                lock_id: format!("lock:{}:pool", quote_id),
                resource_type: ResourceType::PoolBalance,
                amount,
                pool: Some(TreasuryPool::RewardPool),
                expires_at: expiry,
            });
        }

        Ok(locks)
    }

    /// Release locks for an execution
    fn release_locks(&mut self, execution_id: &str) -> P3Result<()> {
        // Find quote for this execution
        let execution = self.executions.get(execution_id).ok_or_else(|| {
            P3Error::NotFound {
                entity: "Execution".to_string(),
                id: execution_id.to_string(),
            }
        })?;

        let quote = self.quotes.get(&execution.quote_id).ok_or_else(|| {
            P3Error::NotFound {
                entity: "Quote".to_string(),
                id: execution.quote_id.clone(),
            }
        })?;

        // Remove all locks for this quote
        for lock in &quote.response.resource_locks {
            self.resource_locks.remove(&lock.lock_id);
        }

        Ok(())
    }

    /// Cleanup expired quotes and locks
    pub fn cleanup_expired(&mut self, now: &DateTime<Utc>) {
        // Expire quotes
        for quote in self.quotes.values_mut() {
            if quote.status == QuoteStatus::Active && quote.response.is_expired(now) {
                quote.status = QuoteStatus::Expired;
            }
        }

        // Remove expired locks
        self.resource_locks
            .retain(|_, lock| &lock.expires_at > now);
    }
}

impl Default for ExecutionEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Execution record
#[derive(Clone, Debug)]
pub struct ExecutionRecord {
    /// Execution ID
    pub execution_id: String,
    /// Quote ID
    pub quote_id: String,
    /// Current phase
    pub phase: ExecutionPhase,
    /// Idempotency key
    pub idempotency_key: IdempotencyKey,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Committed at
    pub committed_at: Option<DateTime<Utc>>,
    /// Executed at
    pub executed_at: Option<DateTime<Utc>>,
    /// Resolved at
    pub resolved_at: Option<DateTime<Utc>>,
    /// Deadline
    pub deadline: Option<DateTime<Utc>>,
    /// Result digest
    pub result: Option<P3Digest>,
    /// Error if failed
    pub error: Option<ExecutionError>,
    /// Execution proof
    pub execution_proof: Option<ExecutionProofRef>,
    /// Commit digest
    pub commit_digest: P3Digest,
}

/// Quote record
#[derive(Clone, Debug)]
pub struct QuoteRecord {
    /// Quote ID
    pub quote_id: String,
    /// Original request
    pub request: QuoteRequest,
    /// Quote response
    pub response: QuoteResponse,
    /// Quote status
    pub status: QuoteStatus,
    /// Created at
    pub created_at: DateTime<Utc>,
}

/// Quote status
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuoteStatus {
    /// Active and valid
    Active,
    /// Committed to execution
    Committed,
    /// Expired
    Expired,
    /// Cancelled
    Cancelled,
}

/// Operation type name extension
impl OperationType {
    /// Get operation type name
    pub fn name(&self) -> &'static str {
        match self {
            OperationType::PointsCalculation => "PointsCalculation",
            OperationType::Attribution => "Attribution",
            OperationType::Distribution => "Distribution",
            OperationType::Clawback => "Clawback",
            OperationType::DepositOperation => "DepositOperation",
            OperationType::Fine => "Fine",
            OperationType::Subsidy => "Subsidy",
            OperationType::BudgetSpend => "BudgetSpend",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_engine_creation() {
        let engine = ExecutionEngine::new();
        assert!(engine.executions.is_empty());
        assert!(engine.quotes.is_empty());
    }

    #[test]
    fn test_quote_flow() {
        let mut engine = ExecutionEngine::new();

        let request = QuoteRequest::new(
            OperationType::Distribution,
            P3Digest::zero(),
            EpochId::new("epoch:1"),
            "actor:1",
        )
        .with_amount(Decimal::new(100, 0));

        let quote = engine.quote(request).unwrap();

        assert!(!quote.quote_id.is_empty());
        assert_eq!(quote.quoted_amount, Decimal::new(100, 0));
        assert_eq!(quote.fees, Decimal::new(1, 0)); // 1% fee
    }

    #[test]
    fn test_commit_flow() {
        let mut engine = ExecutionEngine::new();

        let request = QuoteRequest::new(
            OperationType::Distribution,
            P3Digest::zero(),
            EpochId::new("epoch:1"),
            "actor:1",
        )
        .with_amount(Decimal::new(100, 0));

        let quote = engine.quote(request).unwrap();

        let commit_request = CommitRequest {
            quote_id: quote.quote_id.clone(),
            quote_digest: quote.quote_digest.clone(),
            idempotency_key: IdempotencyKey::generate(),
            committed_at: Utc::now(),
        };

        let commit = engine.commit(commit_request).unwrap();

        assert!(!commit.execution_id.is_empty());
        assert!(!commit.committed_locks.is_empty());
    }

    #[test]
    fn test_full_execution_flow() {
        let mut engine = ExecutionEngine::new();

        // Quote
        let request = QuoteRequest::new(
            OperationType::Distribution,
            P3Digest::zero(),
            EpochId::new("epoch:1"),
            "actor:1",
        )
        .with_amount(Decimal::new(100, 0));

        let quote = engine.quote(request).unwrap();

        // Commit
        let commit_request = CommitRequest {
            quote_id: quote.quote_id,
            quote_digest: quote.quote_digest,
            idempotency_key: IdempotencyKey::generate(),
            committed_at: Utc::now(),
        };

        let commit = engine.commit(commit_request).unwrap();

        // Execute
        let execute_request = ExecuteRequest {
            execution_id: commit.execution_id.clone(),
            commit_digest: commit.commit_digest,
            executor_ref: "executor:1".to_string(),
        };

        let execute = engine.execute(execute_request).unwrap();
        assert!(execute.success);
        assert!(execute.result_digest.is_some());
        assert!(execute.execution_proof.is_some());

        // Resolve
        let resolve_request = ResolveRequest {
            execution_id: commit.execution_id.clone(),
            resolution_type: ExecutionResolutionType::Success,
            resolution_proof: None,
            resolver_ref: "resolver:1".to_string(),
        };

        let resolve = engine.resolve(resolve_request).unwrap();
        assert_eq!(resolve.final_status, ExecutionFinalStatus::Completed);

        // Verify execution record
        let record = engine.get_execution(&commit.execution_id).unwrap();
        assert_eq!(record.phase, ExecutionPhase::Completed);
    }

    #[test]
    fn test_expired_quote() {
        let mut engine = ExecutionEngine::new().with_quote_validity(0); // Immediate expiry

        let request = QuoteRequest::new(
            OperationType::Distribution,
            P3Digest::zero(),
            EpochId::new("epoch:1"),
            "actor:1",
        );

        let quote = engine.quote(request).unwrap();

        // Wait a moment for expiry
        std::thread::sleep(std::time::Duration::from_millis(10));

        let commit_request = CommitRequest {
            quote_id: quote.quote_id,
            quote_digest: quote.quote_digest,
            idempotency_key: IdempotencyKey::generate(),
            committed_at: Utc::now(),
        };

        let result = engine.commit(commit_request);
        assert!(result.is_err());
    }

    #[test]
    fn test_rollback() {
        let mut engine = ExecutionEngine::new();

        let request = QuoteRequest::new(
            OperationType::Distribution,
            P3Digest::zero(),
            EpochId::new("epoch:1"),
            "actor:1",
        );

        let quote = engine.quote(request).unwrap();

        let commit_request = CommitRequest {
            quote_id: quote.quote_id,
            quote_digest: quote.quote_digest,
            idempotency_key: IdempotencyKey::generate(),
            committed_at: Utc::now(),
        };

        let commit = engine.commit(commit_request).unwrap();

        engine.rollback(&commit.execution_id).unwrap();

        let record = engine.get_execution(&commit.execution_id).unwrap();
        assert_eq!(record.phase, ExecutionPhase::RolledBack);
    }
}
