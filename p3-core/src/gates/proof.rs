//! Execution Proof Gate
//!
//! require_execution_proof: Execution proof required for final payouts

use crate::error::P3Error;
use crate::types::{ExecutionProofRef, PendingKind};
use super::GateCheckResult;

/// Execution proof gate
pub struct ProofGate;

impl ProofGate {
    pub fn new() -> Self {
        Self
    }

    /// Require execution proof is present and valid
    pub fn require_proof(&self, proof: Option<&ExecutionProofRef>) -> GateCheckResult {
        match proof {
            Some(p) if p.is_valid() => GateCheckResult::pass(),
            Some(_) => GateCheckResult::pending(
                P3Error::ExecutionProofRequired {
                    action: "invalid_proof".to_string(),
                },
                PendingKind::Execution,
            ),
            None => GateCheckResult::pending(
                P3Error::ExecutionProofRequired {
                    action: "missing_proof".to_string(),
                },
                PendingKind::Execution,
            ),
        }
    }

    /// Check if proof has the required executor
    pub fn require_executor(&self, proof: &ExecutionProofRef, expected_executor: &str) -> GateCheckResult {
        if proof.executor_ref == expected_executor {
            GateCheckResult::pass()
        } else {
            GateCheckResult::fail(P3Error::ExecutionProofRequired {
                action: format!("executor_mismatch: expected {}", expected_executor),
            })
        }
    }

    /// Check if proof is within valid time window
    pub fn require_valid_time(&self, proof: &ExecutionProofRef) -> GateCheckResult {
        let now = chrono::Utc::now();
        if proof.executed_at <= now {
            GateCheckResult::pass()
        } else {
            GateCheckResult::fail(P3Error::ExecutionProofRequired {
                action: "future_execution_time".to_string(),
            })
        }
    }
}

impl Default for ProofGate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ExecutionProofType, P3Digest};
    use chrono::Utc;

    fn create_valid_proof() -> ExecutionProofRef {
        ExecutionProofRef {
            proof_id: "proof:1".to_string(),
            proof_type: ExecutionProofType::OnChain,
            executor_ref: "executor:1".to_string(),
            executed_at: Utc::now(),
            receipt_ref: Some("receipt:1".to_string()),
            proof_digest: P3Digest::zero(),
        }
    }

    #[test]
    fn test_require_proof_passes() {
        let gate = ProofGate::new();
        let proof = create_valid_proof();
        let result = gate.require_proof(Some(&proof));
        assert!(result.passed);
    }

    #[test]
    fn test_require_proof_fails_none() {
        let gate = ProofGate::new();
        let result = gate.require_proof(None);
        assert!(!result.passed);
        assert!(result.pending_kind.is_some());
    }

    #[test]
    fn test_require_executor() {
        let gate = ProofGate::new();
        let proof = create_valid_proof();

        let result = gate.require_executor(&proof, "executor:1");
        assert!(result.passed);

        let result = gate.require_executor(&proof, "executor:2");
        assert!(!result.passed);
    }
}
