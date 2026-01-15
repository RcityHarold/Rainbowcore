//! P3 Executor - Execution Orchestration Layer
//!
//! This crate provides the execution orchestration layer for P3 Economy Layer.
//! It coordinates verification, storage, and the execution state machine.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │              P3 Executor                     │
//! │  ┌─────────────────────────────────────┐    │
//! │  │         ExecutionOrchestrator       │    │
//! │  │  - Quote → Commit → Execute → Resolve│    │
//! │  └─────────────────────────────────────┘    │
//! │           │              │           │      │
//! │           ▼              ▼           ▼      │
//! │  ┌─────────────┐ ┌─────────────┐ ┌────────┐ │
//! │  │   Proofs    │ │  Attempts   │ │ Gates  │ │
//! │  └─────────────┘ └─────────────┘ └────────┘ │
//! └─────────────────────────────────────────────┘
//!           │              │           │
//!           ▼              ▼           ▼
//!     p3-verifier      p3-store     p3-core
//! ```
//!
//! # Modules
//!
//! - [`executor`] - Main execution orchestration engine
//! - [`proof`] - Execution proof generation
//! - [`attempt`] - Attempt chain management for retries
//! - [`error`] - Error types
//!
//! # Usage Example
//!
//! ```ignore
//! use p3_executor::{P3Executor, ExecutorConfig, ExecutionContext};
//! use p3_core::{EpochId, OperationType, P3Digest};
//! use rust_decimal::Decimal;
//!
//! async fn example() {
//!     let executor = P3Executor::default_config();
//!
//!     let epoch_id = EpochId::new("epoch:2024:001");
//!     let context = ExecutionContext::new(epoch_id, "actor:1")
//!         .with_executor("executor:1");
//!
//!     let target = P3Digest::blake3(b"target");
//!     let result = executor.execute_operation(
//!         OperationType::Distribution,
//!         target,
//!         Some(Decimal::new(100, 0)),
//!         context,
//!     ).await.unwrap();
//! }
//! ```

pub mod anchor;
pub mod attempt;
pub mod error;
pub mod executor;
pub mod proof;

// Re-export main types
pub use anchor::{
    AnchorStats, MockP3Anchor, P3AnchorConfig, P3AnchorManager, P3AnchorRecord,
    P3AnchorService, P3AnchorStatus, PendingEpochAnchor,
};
pub use attempt::{AttemptChain, AttemptChainConfig, AttemptChainManager, AttemptRecord, AttemptOutcome};
pub use error::{ExecutorError, ExecutorResult};
pub use executor::{
    ExecutionContext, ExecutionResult, ExecutorConfig, ExecutorStats, P3Executor,
};
pub use proof::{ExtendedProofType, ProofBatch, ProofGenerator, ProofVerifier};

// Re-export common types from p3-core
pub use p3_core::{
    AttemptChainId, CommitRequest, CommitResponse, EpochId,
    ExecuteRequest, ExecuteResponse, ExecutionEngine, ExecutionPhase,
    ExecutionProofRef, ExecutionProofType, GateChecker, GateContext,
    IdempotencyKey, OperationType, P3Digest, QuoteRequest, QuoteResponse,
    ResolveRequest, ResolveResponse,
};
pub use p3_core::execution::{ExecutionResolutionType, ExecutionFinalStatus};

/// P3 Executor version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_executor_config_builder() {
        let config = ExecutorConfig {
            quote_validity_secs: 600,
            execution_timeout_secs: 7200,
            enable_gate_checks: true,
            enable_verification: true,
            attempt_config: AttemptChainConfig::default(),
        };

        assert_eq!(config.quote_validity_secs, 600);
    }

    #[test]
    fn test_attempt_chain_config() {
        let config = AttemptChainConfig::default()
            .with_max_attempts(5)
            .with_initial_delay(2);

        assert_eq!(config.max_attempts, 5);
        assert_eq!(config.initial_delay_secs, 2);
    }

    #[tokio::test]
    async fn test_full_execution_flow() {
        use rust_decimal::Decimal;

        let config = ExecutorConfig {
            enable_gate_checks: false,
            enable_verification: false,
            ..Default::default()
        };
        let executor = P3Executor::new(config);

        let epoch_id = EpochId::new("epoch:test:001");
        let context = ExecutionContext::new(epoch_id, "initiator:test")
            .with_executor("executor:test");

        let target = P3Digest::blake3(b"test-operation");

        let result = executor
            .execute_operation(
                OperationType::Distribution,
                target,
                Some(Decimal::new(1000, 2)), // 10.00
                context,
            )
            .await
            .unwrap();

        assert_eq!(result.status, ExecutionFinalStatus::Completed);
        assert!(result.result_digest.is_some());
        assert!(!result.execution_id.is_empty());
    }

    #[tokio::test]
    async fn test_proof_batch_workflow() {
        let executor = P3Executor::default_config();
        let epoch_id = EpochId::new("epoch:test:001");

        // Create batch
        executor
            .create_proof_batch("batch:test:1", epoch_id.clone())
            .await
            .unwrap();

        // Generate and add proof
        let mut generator = ProofGenerator::new("test");
        let proof = generator
            .generate_credit_proof(
                "exec:1",
                "executor:1",
                &P3Digest::blake3(b"100.00"),
                None,
            )
            .unwrap();

        executor
            .add_proof_to_batch("batch:test:1", proof)
            .await
            .unwrap();

        // Seal batch
        let batch = executor.seal_proof_batch("batch:test:1").await.unwrap();

        assert!(batch.is_sealed());
        assert_eq!(batch.len(), 1);
    }

    #[test]
    fn test_error_retryable() {
        let timeout_error = ExecutorError::ExecutionTimeout {
            execution_id: "exec:1".to_string(),
        };
        assert!(timeout_error.is_retryable());

        let verification_error = ExecutorError::VerificationFailed {
            reason: "test".to_string(),
        };
        assert!(!verification_error.is_retryable());
    }

    #[test]
    fn test_proof_generator() {
        let mut generator = ProofGenerator::new("test-gen");

        let digest = P3Digest::blake3(b"test-data");
        let proof = generator
            .generate_settlement_proof("exec:1", "executor:1", &digest)
            .unwrap();

        assert!(proof.proof_id.starts_with("proof:test-gen:"));
        // Settlement maps to OnChain in the core type
        assert_eq!(proof.proof_type, ExecutionProofType::OnChain);
    }

    #[test]
    fn test_proof_verifier() {
        let mut generator = ProofGenerator::new("test");
        let verifier = ProofVerifier::new();

        let digest = P3Digest::blake3(b"test");
        let proof = generator
            .generate_credit_proof("exec:1", "executor:1", &digest, None)
            .unwrap();

        assert!(verifier.verify_proof(&proof).unwrap());
    }
}
