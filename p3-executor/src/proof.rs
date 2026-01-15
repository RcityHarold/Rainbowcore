//! Proof Generation Module
//!
//! Generates execution proofs and proof references for verifiable execution.

use crate::error::ExecutorResult;
use chrono::{DateTime, Utc};
use p3_core::{ExecutionProofRef, ExecutionProofType, P3Digest, EpochId};

/// Extended proof type for executor operations
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExtendedProofType {
    /// Credit (maps to p3-core Credit)
    Credit,
    /// Debit (executor-specific)
    Debit,
    /// Settlement (executor-specific)
    Settlement,
    /// Rollback (executor-specific)
    Rollback,
}

impl ExtendedProofType {
    /// Convert to core ExecutionProofType
    pub fn to_core(&self) -> ExecutionProofType {
        match self {
            ExtendedProofType::Credit => ExecutionProofType::Credit,
            ExtendedProofType::Debit => ExecutionProofType::OffChain,
            ExtendedProofType::Settlement => ExecutionProofType::OnChain,
            ExtendedProofType::Rollback => ExecutionProofType::OffChain,
        }
    }

    /// Get type name
    pub fn name(&self) -> &'static str {
        match self {
            ExtendedProofType::Credit => "credit",
            ExtendedProofType::Debit => "debit",
            ExtendedProofType::Settlement => "settlement",
            ExtendedProofType::Rollback => "rollback",
        }
    }
}

/// Proof generator for execution operations
pub struct ProofGenerator {
    /// Generator ID
    generator_id: String,
    /// Proof counter for uniqueness
    proof_counter: u64,
}

impl ProofGenerator {
    /// Create a new proof generator
    pub fn new(generator_id: impl Into<String>) -> Self {
        Self {
            generator_id: generator_id.into(),
            proof_counter: 0,
        }
    }

    /// Generate an execution proof reference
    pub fn generate_proof(
        &mut self,
        execution_id: &str,
        proof_type: ExtendedProofType,
        executor_ref: &str,
        result_digest: &P3Digest,
    ) -> ExecutorResult<ExecutionProofRef> {
        self.proof_counter += 1;
        let now = Utc::now();

        let proof_id = format!(
            "proof:{}:{}:{}",
            self.generator_id,
            now.timestamp_millis(),
            self.proof_counter
        );

        // Generate proof digest from execution details
        let proof_data = format!(
            "{}:{}:{}:{}:{}",
            proof_id,
            execution_id,
            proof_type.name(),
            executor_ref,
            result_digest.to_hex()
        );
        let proof_digest = P3Digest::blake3(proof_data.as_bytes());

        Ok(ExecutionProofRef {
            proof_id,
            proof_type: proof_type.to_core(),
            executor_ref: executor_ref.to_string(),
            executed_at: now,
            receipt_ref: None,
            proof_digest,
        })
    }

    /// Generate a credit proof for successful payment
    pub fn generate_credit_proof(
        &mut self,
        execution_id: &str,
        executor_ref: &str,
        amount_digest: &P3Digest,
        receipt_ref: Option<String>,
    ) -> ExecutorResult<ExecutionProofRef> {
        let mut proof = self.generate_proof(
            execution_id,
            ExtendedProofType::Credit,
            executor_ref,
            amount_digest,
        )?;
        proof.receipt_ref = receipt_ref;
        Ok(proof)
    }

    /// Generate a debit proof for successful deduction
    pub fn generate_debit_proof(
        &mut self,
        execution_id: &str,
        executor_ref: &str,
        amount_digest: &P3Digest,
        receipt_ref: Option<String>,
    ) -> ExecutorResult<ExecutionProofRef> {
        let mut proof = self.generate_proof(
            execution_id,
            ExtendedProofType::Debit,
            executor_ref,
            amount_digest,
        )?;
        proof.receipt_ref = receipt_ref;
        Ok(proof)
    }

    /// Generate a settlement proof
    pub fn generate_settlement_proof(
        &mut self,
        execution_id: &str,
        executor_ref: &str,
        settlement_digest: &P3Digest,
    ) -> ExecutorResult<ExecutionProofRef> {
        self.generate_proof(
            execution_id,
            ExtendedProofType::Settlement,
            executor_ref,
            settlement_digest,
        )
    }

    /// Generate a rollback proof
    pub fn generate_rollback_proof(
        &mut self,
        execution_id: &str,
        executor_ref: &str,
        rollback_reason_digest: &P3Digest,
    ) -> ExecutorResult<ExecutionProofRef> {
        self.generate_proof(
            execution_id,
            ExtendedProofType::Rollback,
            executor_ref,
            rollback_reason_digest,
        )
    }

    /// Get the current proof count
    pub fn proof_count(&self) -> u64 {
        self.proof_counter
    }
}

/// Proof batch for multiple operations
#[derive(Clone, Debug)]
pub struct ProofBatch {
    /// Batch ID
    pub batch_id: String,
    /// Epoch ID
    pub epoch_id: EpochId,
    /// Individual proofs
    pub proofs: Vec<ExecutionProofRef>,
    /// Batch digest
    pub batch_digest: P3Digest,
    /// Created at
    pub created_at: DateTime<Utc>,
}

impl ProofBatch {
    /// Create a new proof batch
    pub fn new(batch_id: impl Into<String>, epoch_id: EpochId) -> Self {
        Self {
            batch_id: batch_id.into(),
            epoch_id,
            proofs: Vec::new(),
            batch_digest: P3Digest::zero(),
            created_at: Utc::now(),
        }
    }

    /// Add a proof to the batch
    pub fn add_proof(&mut self, proof: ExecutionProofRef) {
        self.proofs.push(proof);
    }

    /// Seal the batch and compute batch digest
    pub fn seal(&mut self) {
        let mut digest_data = format!("batch:{}:", self.batch_id);
        for proof in &self.proofs {
            digest_data.push_str(&proof.proof_digest.to_hex());
            digest_data.push(':');
        }
        self.batch_digest = P3Digest::blake3(digest_data.as_bytes());
    }

    /// Check if batch is sealed
    pub fn is_sealed(&self) -> bool {
        !self.batch_digest.is_zero()
    }

    /// Get proof count
    pub fn len(&self) -> usize {
        self.proofs.len()
    }

    /// Check if batch is empty
    pub fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }
}

/// Proof verifier for validating execution proofs
pub struct ProofVerifier;

impl ProofVerifier {
    /// Create a new proof verifier
    pub fn new() -> Self {
        Self
    }

    /// Verify an execution proof
    pub fn verify_proof(&self, proof: &ExecutionProofRef) -> ExecutorResult<bool> {
        // Check proof ID format
        if !proof.proof_id.starts_with("proof:") {
            return Ok(false);
        }

        // Check proof digest is not zero
        if proof.proof_digest.is_zero() {
            return Ok(false);
        }

        // Check executed_at is in the past
        if proof.executed_at > Utc::now() {
            return Ok(false);
        }

        Ok(true)
    }

    /// Verify a proof batch
    pub fn verify_batch(&self, batch: &ProofBatch) -> ExecutorResult<bool> {
        // Check batch is sealed
        if !batch.is_sealed() {
            return Ok(false);
        }

        // Verify each proof
        for proof in &batch.proofs {
            if !self.verify_proof(proof)? {
                return Ok(false);
            }
        }

        // Recompute and verify batch digest
        let mut digest_data = format!("batch:{}:", batch.batch_id);
        for proof in &batch.proofs {
            digest_data.push_str(&proof.proof_digest.to_hex());
            digest_data.push(':');
        }
        let computed_digest = P3Digest::blake3(digest_data.as_bytes());

        Ok(computed_digest == batch.batch_digest)
    }
}

impl Default for ProofVerifier {
    fn default() -> Self {
        Self::new()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_generator_creation() {
        let generator = ProofGenerator::new("test-generator");
        assert_eq!(generator.proof_count(), 0);
    }

    #[test]
    fn test_generate_credit_proof() {
        let mut generator = ProofGenerator::new("test");
        let amount_digest = P3Digest::blake3(b"100.00");

        let proof = generator
            .generate_credit_proof("exec:1", "executor:1", &amount_digest, None)
            .unwrap();

        assert!(proof.proof_id.starts_with("proof:test:"));
        assert!(!proof.proof_digest.is_zero());
        assert_eq!(generator.proof_count(), 1);
    }

    #[test]
    fn test_generate_debit_proof() {
        let mut generator = ProofGenerator::new("test");
        let amount_digest = P3Digest::blake3(b"50.00");

        let proof = generator
            .generate_debit_proof(
                "exec:2",
                "executor:1",
                &amount_digest,
                Some("receipt:123".to_string()),
            )
            .unwrap();

        assert!(proof.proof_id.starts_with("proof:test:"));
        assert_eq!(proof.receipt_ref, Some("receipt:123".to_string()));
    }

    #[test]
    fn test_proof_batch() {
        let mut generator = ProofGenerator::new("test");
        let epoch_id = EpochId::new("epoch:2024:001");
        let mut batch = ProofBatch::new("batch:1", epoch_id);

        let digest1 = P3Digest::blake3(b"100.00");
        let digest2 = P3Digest::blake3(b"200.00");

        let proof1 = generator
            .generate_credit_proof("exec:1", "executor:1", &digest1, None)
            .unwrap();
        let proof2 = generator
            .generate_credit_proof("exec:2", "executor:1", &digest2, None)
            .unwrap();

        batch.add_proof(proof1);
        batch.add_proof(proof2);

        assert!(!batch.is_sealed());
        assert_eq!(batch.len(), 2);

        batch.seal();

        assert!(batch.is_sealed());
        assert!(!batch.batch_digest.is_zero());
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

    #[test]
    fn test_batch_verification() {
        let mut generator = ProofGenerator::new("test");
        let verifier = ProofVerifier::new();

        let epoch_id = EpochId::new("epoch:2024:001");
        let mut batch = ProofBatch::new("batch:1", epoch_id);

        let digest = P3Digest::blake3(b"test");
        let proof = generator
            .generate_credit_proof("exec:1", "executor:1", &digest, None)
            .unwrap();

        batch.add_proof(proof);
        batch.seal();

        assert!(verifier.verify_batch(&batch).unwrap());
    }

    #[test]
    fn test_unsealed_batch_fails_verification() {
        let mut generator = ProofGenerator::new("test");
        let verifier = ProofVerifier::new();

        let epoch_id = EpochId::new("epoch:2024:001");
        let mut batch = ProofBatch::new("batch:1", epoch_id);

        let digest = P3Digest::blake3(b"test");
        let proof = generator
            .generate_credit_proof("exec:1", "executor:1", &digest, None)
            .unwrap();

        batch.add_proof(proof);
        // Not sealed

        assert!(!verifier.verify_batch(&batch).unwrap());
    }
}
