//! P3 Conformance Testing Framework
//!
//! This crate provides conformance testing infrastructure for the P3 Economy Layer.
//! It ensures consistent behavior across implementations through standardized test vectors
//! and conformance test suites.
//!
//! # Overview
//!
//! The conformance framework consists of:
//!
//! - **Test Vectors**: Standardized inputs and expected outputs for deterministic testing
//! - **Conformance Runners**: Test execution infrastructure with result tracking
//! - **Conformance Levels**: L1 (Basic), L2 (Standard), L3 (Full) verification levels
//!
//! # Usage
//!
//! ## Running All Conformance Tests
//!
//! ```rust
//! use p3_conformance::run_all_conformance_tests;
//!
//! let results = run_all_conformance_tests();
//! assert!(results.all_passed(), "All conformance tests should pass");
//! ```
//!
//! ## Running Specific Test Suites
//!
//! ```rust
//! use p3_conformance::conformance::{digest, execution, verification};
//!
//! // Run digest conformance tests
//! let digest_results = digest::run_conformance_tests();
//! println!("Digest tests: {}/{} passed", digest_results.passed, digest_results.total);
//!
//! // Run execution conformance tests
//! let exec_results = execution::run_conformance_tests();
//! println!("Execution tests: {}/{} passed", exec_results.passed, exec_results.total);
//!
//! // Run verification conformance tests
//! let verify_results = verification::run_conformance_tests();
//! println!("Verification tests: {}/{} passed", verify_results.passed, verify_results.total);
//! ```
//!
//! ## Using Test Vectors
//!
//! ```rust
//! use p3_conformance::vectors::{digest, execution, epoch, proof};
//!
//! // Get all digest test vectors
//! let digest_vectors = digest::all_vectors();
//!
//! // Get all execution test vectors
//! let exec_vectors = execution::all_vectors();
//! ```
//!
//! # Conformance Levels
//!
//! - **L1 (Basic)**: Core digest and basic proof verification
//! - **L2 (Standard)**: Full execution flow and state machine validation
//! - **L3 (Full)**: Complete cross-layer integration and batch processing
//!
//! # Test Vector Categories
//!
//! - **Digest Vectors**: Blake3 hash computation test cases
//! - **Execution Vectors**: Operation execution flow test cases
//! - **Epoch Vectors**: Epoch management and transition test cases
//! - **Proof Vectors**: Proof generation and verification test cases

pub mod conformance;
pub mod vectors;

pub use conformance::{
    ConformanceLevel, ConformanceResult, ConformanceRunner, SuiteResults,
};

/// P3 Conformance version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Run all conformance test suites
pub fn run_all_conformance_tests() -> AllConformanceResults {
    let digest_results = conformance::digest::run_conformance_tests();
    let execution_results = conformance::execution::run_conformance_tests();
    let verification_results = conformance::verification::run_conformance_tests();

    AllConformanceResults {
        digest: digest_results,
        execution: execution_results,
        verification: verification_results,
    }
}

/// Results from all conformance test suites
#[derive(Debug)]
pub struct AllConformanceResults {
    /// Digest conformance results
    pub digest: SuiteResults,
    /// Execution conformance results
    pub execution: SuiteResults,
    /// Verification conformance results
    pub verification: SuiteResults,
}

impl AllConformanceResults {
    /// Check if all tests passed
    pub fn all_passed(&self) -> bool {
        self.digest.all_passed()
            && self.execution.all_passed()
            && self.verification.all_passed()
    }

    /// Get total test count
    pub fn total_tests(&self) -> usize {
        self.digest.total + self.execution.total + self.verification.total
    }

    /// Get total passed count
    pub fn total_passed(&self) -> usize {
        self.digest.passed + self.execution.passed + self.verification.passed
    }

    /// Get total failed count
    pub fn total_failed(&self) -> usize {
        self.digest.failed + self.execution.failed + self.verification.failed
    }

    /// Get total duration in milliseconds
    pub fn total_duration_ms(&self) -> u64 {
        self.digest.duration_ms + self.execution.duration_ms + self.verification.duration_ms
    }

    /// Get overall pass rate as percentage
    pub fn pass_rate(&self) -> f64 {
        let total = self.total_tests();
        if total == 0 {
            100.0
        } else {
            (self.total_passed() as f64 / total as f64) * 100.0
        }
    }

    /// Print summary to stdout
    pub fn print_summary(&self) {
        println!("=== P3 Conformance Test Results ===\n");

        println!("Digest Tests:       {}/{} passed", self.digest.passed, self.digest.total);
        println!("Execution Tests:    {}/{} passed", self.execution.passed, self.execution.total);
        println!("Verification Tests: {}/{} passed", self.verification.passed, self.verification.total);

        println!("\n---");
        println!("Total: {}/{} tests passed ({:.1}%)",
            self.total_passed(),
            self.total_tests(),
            self.pass_rate()
        );
        println!("Duration: {}ms", self.total_duration_ms());

        if self.all_passed() {
            println!("\n✓ All conformance tests passed!");
        } else {
            println!("\n✗ Some conformance tests failed!");

            // Print failed tests
            for result in &self.digest.results {
                if !result.passed {
                    println!("  FAIL: {} - {:?}", result.vector_id, result.error);
                }
            }
            for result in &self.execution.results {
                if !result.passed {
                    println!("  FAIL: {} - {:?}", result.vector_id, result.error);
                }
            }
            for result in &self.verification.results {
                if !result.passed {
                    println!("  FAIL: {} - {:?}", result.vector_id, result.error);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_run_all_conformance_tests() {
        let results = run_all_conformance_tests();

        assert!(results.total_tests() > 0, "Should have conformance tests");
        assert!(
            results.all_passed(),
            "All conformance tests should pass: {}/{} passed",
            results.total_passed(),
            results.total_tests()
        );
    }

    #[test]
    fn test_all_results_structure() {
        let results = run_all_conformance_tests();

        // Verify counts add up
        assert_eq!(
            results.total_tests(),
            results.total_passed() + results.total_failed()
        );

        // Verify pass rate calculation
        if results.total_tests() > 0 {
            let expected_rate = (results.total_passed() as f64 / results.total_tests() as f64) * 100.0;
            assert!((results.pass_rate() - expected_rate).abs() < 0.01);
        }
    }

    #[test]
    fn test_digest_conformance() {
        let results = conformance::digest::run_conformance_tests();
        assert!(results.all_passed(), "Digest conformance tests should pass");
    }

    #[test]
    fn test_execution_conformance() {
        let results = conformance::execution::run_conformance_tests();
        assert!(results.all_passed(), "Execution conformance tests should pass");
    }

    #[test]
    fn test_verification_conformance() {
        let results = conformance::verification::run_conformance_tests();
        assert!(results.all_passed(), "Verification conformance tests should pass");
    }

    #[test]
    fn test_vector_counts() {
        // Ensure we have reasonable coverage
        let digest_vectors = vectors::digest::all_vectors();
        let execution_vectors = vectors::execution::all_vectors();
        let epoch_vectors = vectors::epoch::all_vectors();
        let proof_vectors = vectors::proof::all_vectors();

        assert!(digest_vectors.len() >= 9, "Expected at least 9 digest vectors");
        assert!(execution_vectors.len() >= 16, "Expected at least 16 execution vectors");
        assert!(epoch_vectors.len() >= 16, "Expected at least 16 epoch vectors");
        assert!(proof_vectors.len() >= 13, "Expected at least 13 proof vectors");
    }

    #[test]
    fn test_conformance_levels() {
        assert_eq!(ConformanceLevel::L1.name(), "L1 (Basic)");
        assert_eq!(ConformanceLevel::L2.name(), "L2 (Standard)");
        assert_eq!(ConformanceLevel::L3.name(), "L3 (Full)");
    }
}
