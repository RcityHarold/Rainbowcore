//! Executor Core Module
//!
//! The main execution orchestration engine that coordinates verification,
//! storage, and the execution state machine.

use crate::attempt::{AttemptChainConfig, AttemptChainManager, AttemptOutcome};
use crate::error::{ExecutorError, ExecutorResult};
use crate::proof::{ProofBatch, ProofGenerator, ProofVerifier};
use chrono::{DateTime, Utc};
use p3_core::{
    AttemptChainId, CommitRequest, CommitResponse, EpochId,
    ExecuteRequest, ExecuteResponse, ExecutionEngine, ExecutionPhase,
    ExecutionProofRef, GateChecker, GateContext, IdempotencyKey, OperationType,
    P3Digest, QuoteRequest, QuoteResponse, ResolveRequest, ResolveResponse,
    StrongEconomicAction,
};
use p3_core::execution::{ExecutionResolutionType, ExecutionFinalStatus};
use rust_decimal::Decimal;
use std::collections::HashMap;
use tokio::sync::RwLock;

/// Executor configuration
#[derive(Clone, Debug)]
pub struct ExecutorConfig {
    /// Quote validity in seconds
    pub quote_validity_secs: i64,
    /// Execution timeout in seconds
    pub execution_timeout_secs: i64,
    /// Enable gate checks
    pub enable_gate_checks: bool,
    /// Enable verification
    pub enable_verification: bool,
    /// Attempt chain configuration
    pub attempt_config: AttemptChainConfig,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            quote_validity_secs: 300,
            execution_timeout_secs: 3600,
            enable_gate_checks: true,
            enable_verification: true,
            attempt_config: AttemptChainConfig::default(),
        }
    }
}

/// Execution context
#[derive(Clone, Debug)]
pub struct ExecutionContext {
    /// Epoch ID
    pub epoch_id: EpochId,
    /// Initiator reference
    pub initiator_ref: String,
    /// Executor reference
    pub executor_ref: String,
    /// Gate context
    pub gate_context: GateContext,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

impl ExecutionContext {
    /// Create a new execution context
    pub fn new(epoch_id: EpochId, initiator_ref: impl Into<String>) -> Self {
        Self {
            epoch_id: epoch_id.clone(),
            initiator_ref: initiator_ref.into(),
            executor_ref: String::new(),
            gate_context: GateContext::new(epoch_id),
            timestamp: Utc::now(),
        }
    }

    /// Set executor reference
    pub fn with_executor(mut self, executor_ref: impl Into<String>) -> Self {
        self.executor_ref = executor_ref.into();
        self
    }

    /// Set gate context
    pub fn with_gate_context(mut self, gate_context: GateContext) -> Self {
        self.gate_context = gate_context;
        self
    }
}

/// Execution result
#[derive(Clone, Debug)]
pub struct ExecutionResult {
    /// Execution ID
    pub execution_id: String,
    /// Final status
    pub status: ExecutionFinalStatus,
    /// Result digest
    pub result_digest: Option<P3Digest>,
    /// Execution proof
    pub proof: Option<ExecutionProofRef>,
    /// Attempt chain ID
    pub attempt_chain_id: Option<AttemptChainId>,
    /// Error message
    pub error: Option<String>,
}

/// Orchestration state for an execution
#[derive(Clone, Debug)]
struct OrchestrationState {
    /// Execution ID
    execution_id: String,
    /// Quote ID
    quote_id: Option<String>,
    /// Current phase
    phase: ExecutionPhase,
    /// Context
    context: ExecutionContext,
    /// Created at
    created_at: DateTime<Utc>,
    /// Proofs generated
    proofs: Vec<ExecutionProofRef>,
}

/// P3 Executor - Main orchestration engine
pub struct P3Executor {
    /// Configuration
    config: ExecutorConfig,
    /// Core execution engine
    engine: RwLock<ExecutionEngine>,
    /// Gate checker
    gate_checker: GateChecker,
    /// Proof generator
    proof_generator: RwLock<ProofGenerator>,
    /// Proof verifier
    proof_verifier: ProofVerifier,
    /// Attempt chain manager
    attempt_manager: RwLock<AttemptChainManager>,
    /// Orchestration states
    states: RwLock<HashMap<String, OrchestrationState>>,
    /// Proof batches
    proof_batches: RwLock<HashMap<String, ProofBatch>>,
}

impl P3Executor {
    /// Create a new P3 Executor
    pub fn new(config: ExecutorConfig) -> Self {
        let engine = ExecutionEngine::new()
            .with_quote_validity(config.quote_validity_secs)
            .with_execution_timeout(config.execution_timeout_secs);

        let attempt_manager =
            AttemptChainManager::new().with_default_config(config.attempt_config.clone());

        Self {
            config,
            engine: RwLock::new(engine),
            gate_checker: GateChecker::new(),
            proof_generator: RwLock::new(ProofGenerator::new("p3-executor")),
            proof_verifier: ProofVerifier::new(),
            attempt_manager: RwLock::new(attempt_manager),
            states: RwLock::new(HashMap::new()),
            proof_batches: RwLock::new(HashMap::new()),
        }
    }

    /// Create with default configuration
    pub fn default_config() -> Self {
        Self::new(ExecutorConfig::default())
    }

    /// Execute a complete operation
    pub async fn execute_operation(
        &self,
        operation_type: OperationType,
        target_ref: P3Digest,
        amount: Option<Decimal>,
        context: ExecutionContext,
    ) -> ExecutorResult<ExecutionResult> {
        // Step 1: Gate checks
        if self.config.enable_gate_checks {
            self.check_gates(&operation_type, &context).await?;
        }

        // Step 2: Quote
        let quote = self.quote(operation_type.clone(), target_ref.clone(), amount, &context).await?;

        // Step 3: Commit
        let commit = self.commit(&quote, &context).await?;

        // Step 4: Execute
        let execute = self.execute_phase(&commit, &context).await?;

        // Step 5: Resolve
        let resolve = self.resolve(&commit.execution_id, execute.success, &context).await?;

        Ok(ExecutionResult {
            execution_id: commit.execution_id,
            status: resolve.final_status,
            result_digest: execute.result_digest,
            proof: execute.execution_proof,
            attempt_chain_id: None,
            error: execute.error.map(|e| e.code),
        })
    }

    /// Execute with retry chain
    pub async fn execute_with_retry(
        &self,
        operation_type: OperationType,
        target_ref: P3Digest,
        amount: Option<Decimal>,
        context: ExecutionContext,
    ) -> ExecutorResult<ExecutionResult> {
        // Create attempt chain
        let chain_id = {
            let mut manager = self.attempt_manager.write().await;
            manager.create_chain(
                operation_type.name(),
                target_ref.clone(),
                Some(self.config.attempt_config.clone()),
            )
        };

        loop {
            // Start attempt
            {
                let mut manager = self.attempt_manager.write().await;
                manager.start_attempt(&chain_id)?;
            }

            // Execute
            let result = self
                .execute_operation(
                    operation_type.clone(),
                    target_ref.clone(),
                    amount,
                    context.clone(),
                )
                .await;

            // Handle result
            match result {
                Ok(mut exec_result) => {
                    // Complete attempt
                    {
                        let mut manager = self.attempt_manager.write().await;
                        manager.complete_attempt(&chain_id, AttemptOutcome::Success)?;
                    }
                    exec_result.attempt_chain_id = Some(chain_id);
                    return Ok(exec_result);
                }
                Err(e) => {
                    let retryable = e.is_retryable();
                    let error_digest = P3Digest::blake3(e.to_string().as_bytes());

                    // Complete attempt with failure
                    {
                        let mut manager = self.attempt_manager.write().await;
                        let chain = manager
                            .get_chain_mut(&chain_id)
                            .ok_or_else(|| ExecutorError::not_found("AttemptChain", chain_id.as_str()))?;
                        chain.fail_attempt(error_digest, retryable)?;

                        if !chain.has_attempts_remaining() {
                            return Err(ExecutorError::AttemptChainExhausted {
                                attempts: chain.current_attempt(),
                            });
                        }
                    }

                    // Wait for retry
                    let next_retry = {
                        let manager = self.attempt_manager.read().await;
                        let chain = manager.get_chain(&chain_id).unwrap();
                        chain.next_retry_at()
                    };

                    if let Some(retry_at) = next_retry {
                        let now = Utc::now();
                        if retry_at > now {
                            let delay = (retry_at - now).to_std().unwrap_or_default();
                            tokio::time::sleep(delay).await;
                        }
                    }
                }
            }
        }
    }

    /// Quote phase
    async fn quote(
        &self,
        operation_type: OperationType,
        target_ref: P3Digest,
        amount: Option<Decimal>,
        context: &ExecutionContext,
    ) -> ExecutorResult<QuoteResponse> {
        let mut request = QuoteRequest::new(
            operation_type,
            target_ref,
            context.epoch_id.clone(),
            &context.initiator_ref,
        );

        if let Some(amt) = amount {
            request = request.with_amount(amt);
        }

        let mut engine = self.engine.write().await;
        let quote = engine.quote(request)?;

        // Record orchestration state
        let state = OrchestrationState {
            execution_id: String::new(),
            quote_id: Some(quote.quote_id.clone()),
            phase: ExecutionPhase::Quote,
            context: context.clone(),
            created_at: Utc::now(),
            proofs: Vec::new(),
        };

        let mut states = self.states.write().await;
        states.insert(quote.quote_id.clone(), state);

        Ok(quote)
    }

    /// Commit phase
    async fn commit(
        &self,
        quote: &QuoteResponse,
        context: &ExecutionContext,
    ) -> ExecutorResult<CommitResponse> {
        let request = CommitRequest {
            quote_id: quote.quote_id.clone(),
            quote_digest: quote.quote_digest.clone(),
            idempotency_key: IdempotencyKey::generate(),
            committed_at: Utc::now(),
        };

        let mut engine = self.engine.write().await;
        let commit = engine.commit(request)?;

        // Update orchestration state
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(&quote.quote_id) {
            state.execution_id = commit.execution_id.clone();
            state.phase = ExecutionPhase::Commit;
        }

        Ok(commit)
    }

    /// Execute phase
    async fn execute_phase(
        &self,
        commit: &CommitResponse,
        context: &ExecutionContext,
    ) -> ExecutorResult<ExecuteResponse> {
        let request = ExecuteRequest {
            execution_id: commit.execution_id.clone(),
            commit_digest: commit.commit_digest.clone(),
            executor_ref: context.executor_ref.clone(),
        };

        let mut engine = self.engine.write().await;
        let response = engine.execute(request)?;

        // Generate proof if successful
        if response.success {
            if let Some(result_digest) = &response.result_digest {
                let mut generator = self.proof_generator.write().await;
                let _proof = generator.generate_credit_proof(
                    &commit.execution_id,
                    &context.executor_ref,
                    result_digest,
                    None,
                )?;
            }
        }

        Ok(response)
    }

    /// Resolve phase
    async fn resolve(
        &self,
        execution_id: &str,
        success: bool,
        context: &ExecutionContext,
    ) -> ExecutorResult<ResolveResponse> {
        let resolution_type = if success {
            ExecutionResolutionType::Success
        } else {
            ExecutionResolutionType::PermanentFailure
        };

        let request = ResolveRequest {
            execution_id: execution_id.to_string(),
            resolution_type,
            resolution_proof: None,
            resolver_ref: context.executor_ref.clone(),
        };

        let mut engine = self.engine.write().await;
        let response = engine.resolve(request)?;

        Ok(response)
    }

    /// Check gates for operation
    async fn check_gates(
        &self,
        operation_type: &OperationType,
        _context: &ExecutionContext,
    ) -> ExecutorResult<()> {
        // Map operation type to strong economic action for gate checking
        let action = match operation_type {
            OperationType::Distribution => StrongEconomicAction::FinalRewardPayout,
            OperationType::Clawback => StrongEconomicAction::FinalClawbackExecute,
            OperationType::Fine => StrongEconomicAction::PermanentDepositForfeit,
            OperationType::PointsCalculation |
            OperationType::Attribution |
            OperationType::DepositOperation |
            OperationType::Subsidy |
            OperationType::BudgetSpend => StrongEconomicAction::FinalRewardPayout,
        };

        let result = self.gate_checker.check_strong_action(
            &_context.gate_context,
            &action,
            None,
            None,
        );

        if !result.passed {
            let gate_name = result.error
                .map(|e| e.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            return Err(ExecutorError::GateCheckFailed {
                gate: gate_name,
            });
        }

        Ok(())
    }

    /// Create a proof batch for an epoch
    pub async fn create_proof_batch(&self, batch_id: &str, epoch_id: EpochId) -> ExecutorResult<()> {
        let batch = ProofBatch::new(batch_id, epoch_id);

        let mut batches = self.proof_batches.write().await;
        batches.insert(batch_id.to_string(), batch);

        Ok(())
    }

    /// Add proof to batch
    pub async fn add_proof_to_batch(
        &self,
        batch_id: &str,
        proof: ExecutionProofRef,
    ) -> ExecutorResult<()> {
        let mut batches = self.proof_batches.write().await;
        let batch = batches
            .get_mut(batch_id)
            .ok_or_else(|| ExecutorError::not_found("ProofBatch", batch_id))?;

        batch.add_proof(proof);
        Ok(())
    }

    /// Seal proof batch
    pub async fn seal_proof_batch(&self, batch_id: &str) -> ExecutorResult<ProofBatch> {
        let mut batches = self.proof_batches.write().await;
        let batch = batches
            .get_mut(batch_id)
            .ok_or_else(|| ExecutorError::not_found("ProofBatch", batch_id))?;

        batch.seal();
        Ok(batch.clone())
    }

    /// Rollback an execution
    pub async fn rollback(&self, execution_id: &str) -> ExecutorResult<()> {
        let mut engine = self.engine.write().await;
        engine.rollback(execution_id)?;

        // Generate rollback proof
        let rollback_digest = P3Digest::blake3(format!("rollback:{}", execution_id).as_bytes());
        let mut generator = self.proof_generator.write().await;
        let _proof = generator.generate_rollback_proof(execution_id, "system", &rollback_digest)?;

        Ok(())
    }

    /// Cleanup expired quotes and locks
    pub async fn cleanup_expired(&self) {
        let now = Utc::now();
        let mut engine = self.engine.write().await;
        engine.cleanup_expired(&now);
    }

    /// Get executor statistics
    pub async fn stats(&self) -> ExecutorStats {
        let attempt_manager = self.attempt_manager.read().await;
        let proof_generator = self.proof_generator.read().await;
        let states = self.states.read().await;
        let batches = self.proof_batches.read().await;

        ExecutorStats {
            active_executions: states.len(),
            active_attempt_chains: attempt_manager.active_chain_count(),
            proofs_generated: proof_generator.proof_count(),
            active_batches: batches.len(),
        }
    }
}

/// Executor statistics
#[derive(Clone, Debug)]
pub struct ExecutorStats {
    /// Active executions
    pub active_executions: usize,
    /// Active attempt chains
    pub active_attempt_chains: usize,
    /// Proofs generated
    pub proofs_generated: u64,
    /// Active proof batches
    pub active_batches: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_core::EvidenceLevel;

    #[test]
    fn test_executor_config_default() {
        let config = ExecutorConfig::default();
        assert_eq!(config.quote_validity_secs, 300);
        assert_eq!(config.execution_timeout_secs, 3600);
        assert!(config.enable_gate_checks);
    }

    #[test]
    fn test_execution_context_creation() {
        let epoch_id = EpochId::new("epoch:2024:001");
        let context = ExecutionContext::new(epoch_id.clone(), "actor:1")
            .with_executor("executor:1");

        assert_eq!(context.epoch_id, epoch_id);
        assert_eq!(context.initiator_ref, "actor:1");
        assert_eq!(context.executor_ref, "executor:1");
    }

    #[test]
    fn test_executor_creation() {
        let executor = P3Executor::default_config();
        assert!(executor.config.enable_gate_checks);
    }

    #[tokio::test]
    async fn test_executor_stats() {
        let executor = P3Executor::default_config();
        let stats = executor.stats().await;

        assert_eq!(stats.active_executions, 0);
        assert_eq!(stats.active_attempt_chains, 0);
        assert_eq!(stats.proofs_generated, 0);
    }

    #[tokio::test]
    async fn test_create_proof_batch() {
        let executor = P3Executor::default_config();
        let epoch_id = EpochId::new("epoch:2024:001");

        executor.create_proof_batch("batch:1", epoch_id).await.unwrap();

        let stats = executor.stats().await;
        assert_eq!(stats.active_batches, 1);
    }

    #[tokio::test]
    async fn test_seal_proof_batch() {
        let executor = P3Executor::default_config();
        let epoch_id = EpochId::new("epoch:2024:001");

        executor.create_proof_batch("batch:1", epoch_id).await.unwrap();
        let batch = executor.seal_proof_batch("batch:1").await.unwrap();

        assert!(batch.is_sealed());
    }

    #[tokio::test]
    async fn test_execute_operation() {
        let config = ExecutorConfig {
            enable_gate_checks: false,
            enable_verification: false,
            ..Default::default()
        };
        let executor = P3Executor::new(config);

        let epoch_id = EpochId::new("epoch:2024:001");
        let context = ExecutionContext::new(epoch_id, "actor:1")
            .with_executor("executor:1");

        let target = P3Digest::blake3(b"test-target");
        let result = executor
            .execute_operation(
                OperationType::Distribution,
                target,
                Some(Decimal::new(100, 0)),
                context,
            )
            .await
            .unwrap();

        assert_eq!(result.status, ExecutionFinalStatus::Completed);
        assert!(result.result_digest.is_some());
    }

    #[tokio::test]
    async fn test_rollback() {
        let config = ExecutorConfig {
            enable_gate_checks: false,
            enable_verification: false,
            ..Default::default()
        };
        let executor = P3Executor::new(config);

        let epoch_id = EpochId::new("epoch:2024:001");
        let context = ExecutionContext::new(epoch_id, "actor:1")
            .with_executor("executor:1");

        let target = P3Digest::blake3(b"test-target");

        // Quote and commit but don't execute
        let quote = executor
            .quote(OperationType::Distribution, target, Some(Decimal::new(100, 0)), &context)
            .await
            .unwrap();

        let commit = executor.commit(&quote, &context).await.unwrap();

        // Rollback
        executor.rollback(&commit.execution_id).await.unwrap();
    }
}
