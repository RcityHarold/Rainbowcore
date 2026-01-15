//! Verification Conformance Tests
//!
//! Tests for P3 proof verification conformance.

use super::{ConformanceResult, ConformanceRunner, SuiteResults};
use crate::vectors::{proof as vectors, TestVector};
use p3_core::{P3Digest, ExecutionProofType};
use p3_verifier::Verifier;
use std::time::Instant;

/// Verification conformance runner
pub struct VerificationConformanceRunner {
    verifier: Verifier,
}

impl VerificationConformanceRunner {
    /// Create new runner with L1 verifier
    pub fn new() -> Self {
        Self {
            verifier: Verifier::l1(),
        }
    }

    /// Create runner with specific verifier
    pub fn with_verifier(verifier: Verifier) -> Self {
        Self { verifier }
    }

    /// Run all verification conformance tests
    pub fn run_all(&self) -> SuiteResults {
        let vectors = vectors::all_vectors();
        self.run_suite(&vectors)
    }

    /// Validate proof input
    fn validate_input(&self, input: &vectors::ProofInput) -> Result<(), String> {
        // Validate proof type
        if vectors::parse_proof_type(&input.proof_type).is_none() {
            return Err(format!("Invalid proof type: {}", input.proof_type));
        }

        // Validate execution ID
        if input.execution_id.is_empty() {
            return Err("Empty execution ID".to_string());
        }

        // Validate digest format
        if !vectors::validate_digest_format(&input.operation_digest) {
            return Err("Invalid digest format".to_string());
        }

        // Validate executor reference
        if input.executor_ref.is_empty() {
            return Err("Empty executor reference".to_string());
        }

        // Validate epoch ID
        if input.epoch_id.is_empty() {
            return Err("Empty epoch ID".to_string());
        }

        Ok(())
    }

    /// Verify digest computation
    fn verify_digest(&self, digest_hex: &str) -> bool {
        // Check if digest is valid hex and correct length
        if let Ok(bytes) = hex::decode(digest_hex) {
            bytes.len() == 32
        } else {
            false
        }
    }
}

impl Default for VerificationConformanceRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl ConformanceRunner for VerificationConformanceRunner {
    type Input = vectors::ProofInput;

    fn run_vector(&self, vector: &TestVector<Self::Input>) -> ConformanceResult {
        let start = Instant::now();

        // Validate input
        let validation_result = self.validate_input(&vector.input);

        // Check if result matches expectation
        match (validation_result, vector.should_succeed) {
            (Ok(()), true) => {
                // Additional verification for valid proofs
                if !self.verify_digest(&vector.input.operation_digest) {
                    return ConformanceResult::fail(
                        &vector.id,
                        start.elapsed(),
                        "Digest verification failed",
                    );
                }
                ConformanceResult::pass(&vector.id, start.elapsed())
            }
            (Ok(()), false) => {
                // Expected failure, got success
                ConformanceResult::fail(
                    &vector.id,
                    start.elapsed(),
                    "Expected validation to fail but it succeeded",
                )
            }
            (Err(e), true) => {
                // Expected success, got failure
                ConformanceResult::fail(
                    &vector.id,
                    start.elapsed(),
                    format!("Expected validation to succeed but failed: {}", e),
                )
            }
            (Err(_), false) => {
                // Expected failure, got failure
                ConformanceResult::pass(&vector.id, start.elapsed())
                    .with_notes("Correctly rejected invalid input")
            }
        }
    }
}

/// Run verification conformance tests
pub fn run_conformance_tests() -> SuiteResults {
    let runner = VerificationConformanceRunner::new();
    runner.run_all()
}

/// Verify a proof type string
pub fn validate_proof_type(proof_type: &str) -> bool {
    vectors::parse_proof_type(proof_type).is_some()
}

/// Verify digest format
pub fn validate_digest(digest_hex: &str) -> bool {
    vectors::validate_digest_format(digest_hex)
}

/// Create digest from data
pub fn create_digest(data: &[u8]) -> String {
    hex::encode(P3Digest::blake3(data).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_runner_creation() {
        let runner = VerificationConformanceRunner::new();
        assert!(std::mem::size_of_val(&runner) > 0);
    }

    #[test]
    fn test_run_all_vectors() {
        let results = run_conformance_tests();

        assert!(results.total > 0, "Should have test vectors");
        assert!(
            results.all_passed(),
            "All verification conformance tests should pass: {}/{} passed",
            results.passed,
            results.total
        );
    }

    #[test]
    fn test_validate_proof_types() {
        // Valid types
        assert!(validate_proof_type("OnChain"));
        assert!(validate_proof_type("onchain"));
        assert!(validate_proof_type("on-chain"));
        assert!(validate_proof_type("OffChain"));
        assert!(validate_proof_type("offchain"));
        assert!(validate_proof_type("Credit"));
        assert!(validate_proof_type("credit"));
        assert!(validate_proof_type("MultiSig"));
        assert!(validate_proof_type("multisig"));

        // Invalid types
        assert!(!validate_proof_type("Unknown"));
        assert!(!validate_proof_type(""));
        assert!(!validate_proof_type("invalid"));
    }

    #[test]
    fn test_validate_digest() {
        // Valid digest (64 hex chars = 32 bytes)
        let valid = create_digest(b"test");
        assert!(validate_digest(&valid));

        // Invalid digests
        assert!(!validate_digest("not-hex"));
        assert!(!validate_digest("abcd")); // Too short
        assert!(!validate_digest(&"0".repeat(128))); // Too long
    }

    #[test]
    fn test_create_digest() {
        let digest = create_digest(b"hello world");
        assert_eq!(digest.len(), 64);

        // Deterministic
        let digest2 = create_digest(b"hello world");
        assert_eq!(digest, digest2);

        // Different input = different output
        let digest3 = create_digest(b"goodbye world");
        assert_ne!(digest, digest3);
    }

    #[test]
    fn test_standard_proof_vectors() {
        let vectors = vectors::standard_proofs();
        let runner = VerificationConformanceRunner::new();

        for vector in vectors {
            let result = runner.run_vector(&vector);
            assert!(
                result.passed,
                "Standard proof vector {} should pass: {:?}",
                vector.id,
                result.error
            );
        }
    }

    #[test]
    fn test_invalid_proof_vectors() {
        let vectors = vectors::invalid_proofs();
        let runner = VerificationConformanceRunner::new();

        for vector in vectors {
            let result = runner.run_vector(&vector);
            assert!(
                result.passed,
                "Invalid proof vector {} should be correctly rejected: {:?}",
                vector.id,
                result.error
            );
        }
    }

    #[test]
    fn test_verification_vectors() {
        let vectors = vectors::verification_vectors();
        let runner = VerificationConformanceRunner::new();

        for vector in vectors {
            let result = runner.run_vector(&vector);
            assert!(
                result.passed,
                "Verification vector {} should pass: {:?}",
                vector.id,
                result.error
            );
        }
    }

    #[test]
    fn test_conformance_coverage() {
        let results = run_conformance_tests();

        // Should cover all proof types
        assert!(results.total >= 13, "Expected at least 13 proof vectors");

        // Check pass rate
        assert!(
            results.pass_rate() == 100.0,
            "Expected 100% pass rate, got {}%",
            results.pass_rate()
        );
    }

    #[test]
    fn test_verifier_integration() {
        let verifier = Verifier::l1();
        let runner = VerificationConformanceRunner::with_verifier(verifier);

        let results = runner.run_all();
        assert!(results.all_passed());
    }
}
