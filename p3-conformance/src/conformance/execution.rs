//! Execution Conformance Tests
//!
//! Tests for P3 execution flow conformance.

use super::{ConformanceResult, ConformanceRunner, SuiteResults};
use crate::vectors::{execution as vectors, TestVector};
use p3_core::{EpochId, OperationType};
use rust_decimal::Decimal;
use std::time::Instant;

/// Execution conformance runner
pub struct ExecutionConformanceRunner;

impl ExecutionConformanceRunner {
    /// Create new runner
    pub fn new() -> Self {
        Self
    }

    /// Run all execution conformance tests
    pub fn run_all(&self) -> SuiteResults {
        let vectors = vectors::all_vectors();
        self.run_suite(&vectors)
    }

    /// Validate execution input
    fn validate_input(&self, input: &vectors::ExecutionInput) -> Result<(), String> {
        // Validate operation type
        if vectors::parse_operation_type(&input.operation_type).is_none() {
            return Err(format!("Invalid operation type: {}", input.operation_type));
        }

        // Validate target
        if input.target.is_empty() {
            return Err("Empty target".to_string());
        }

        // Validate amount
        let amount: Decimal = input
            .amount
            .parse()
            .map_err(|_| format!("Invalid amount: {}", input.amount))?;

        // Negative amounts are invalid for most operations
        if amount < Decimal::ZERO {
            return Err("Negative amount".to_string());
        }

        // Validate epoch
        if input.epoch_id.is_empty() {
            return Err("Empty epoch ID".to_string());
        }

        Ok(())
    }
}

impl Default for ExecutionConformanceRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl ConformanceRunner for ExecutionConformanceRunner {
    type Input = vectors::ExecutionInput;

    fn run_vector(&self, vector: &TestVector<Self::Input>) -> ConformanceResult {
        let start = Instant::now();

        // Validate input
        let validation_result = self.validate_input(&vector.input);

        // Check if result matches expectation
        match (validation_result, vector.should_succeed) {
            (Ok(()), true) => {
                // Expected success, got success
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

/// Run execution conformance tests
pub fn run_conformance_tests() -> SuiteResults {
    let runner = ExecutionConformanceRunner::new();
    runner.run_all()
}

/// Validate an operation type string
pub fn validate_operation_type(op_type: &str) -> bool {
    vectors::parse_operation_type(op_type).is_some()
}

/// Parse and validate amount
pub fn validate_amount(amount_str: &str) -> Result<Decimal, String> {
    let amount: Decimal = amount_str
        .parse()
        .map_err(|_| format!("Invalid amount format: {}", amount_str))?;

    if amount < Decimal::ZERO {
        return Err("Amount cannot be negative".to_string());
    }

    Ok(amount)
}

/// Validate epoch ID format
pub fn validate_epoch(epoch_str: &str) -> bool {
    !epoch_str.is_empty() && epoch_str.starts_with("epoch:")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_runner_creation() {
        let runner = ExecutionConformanceRunner::new();
        assert!(std::mem::size_of_val(&runner) >= 0);
    }

    #[test]
    fn test_run_all_vectors() {
        let results = run_conformance_tests();

        assert!(results.total > 0, "Should have test vectors");
        assert!(
            results.all_passed(),
            "All execution conformance tests should pass: {}/{} passed",
            results.passed,
            results.total
        );
    }

    #[test]
    fn test_validate_operation_types() {
        // Valid types
        assert!(validate_operation_type("Distribution"));
        assert!(validate_operation_type("distribution"));
        assert!(validate_operation_type("Clawback"));
        assert!(validate_operation_type("Fine"));
        assert!(validate_operation_type("Subsidy"));
        assert!(validate_operation_type("DepositOperation"));
        assert!(validate_operation_type("deposit"));
        assert!(validate_operation_type("PointsCalculation"));
        assert!(validate_operation_type("points"));
        assert!(validate_operation_type("Attribution"));
        assert!(validate_operation_type("BudgetSpend"));
        assert!(validate_operation_type("budget"));

        // Invalid types
        assert!(!validate_operation_type("Unknown"));
        assert!(!validate_operation_type(""));
        assert!(!validate_operation_type("invalid"));
    }

    #[test]
    fn test_validate_amount() {
        // Valid amounts
        assert!(validate_amount("100.00").is_ok());
        assert!(validate_amount("0.01").is_ok());
        assert!(validate_amount("0").is_ok());
        assert!(validate_amount("1000000.00").is_ok());

        // Invalid amounts
        assert!(validate_amount("-100.00").is_err());
        assert!(validate_amount("invalid").is_err());
        assert!(validate_amount("").is_err());
    }

    #[test]
    fn test_validate_epoch() {
        // Valid epochs
        assert!(validate_epoch("epoch:2024:001"));
        assert!(validate_epoch("epoch:2024:365"));

        // Invalid epochs
        assert!(!validate_epoch(""));
        assert!(!validate_epoch("2024:001"));
        assert!(!validate_epoch("period:2024:001"));
    }

    #[test]
    fn test_valid_operation_vectors() {
        let vectors = vectors::valid_operations();
        let runner = ExecutionConformanceRunner::new();

        for vector in vectors {
            let result = runner.run_vector(&vector);
            assert!(
                result.passed,
                "Valid operation vector {} should pass: {:?}",
                vector.id,
                result.error
            );
        }
    }

    #[test]
    fn test_invalid_operation_vectors() {
        let vectors = vectors::invalid_operations();
        let runner = ExecutionConformanceRunner::new();

        for vector in vectors {
            let result = runner.run_vector(&vector);
            assert!(
                result.passed,
                "Invalid operation vector {} should be correctly rejected: {:?}",
                vector.id,
                result.error
            );
        }
    }

    #[test]
    fn test_edge_case_vectors() {
        let vectors = vectors::edge_cases();
        let runner = ExecutionConformanceRunner::new();

        for vector in vectors {
            let result = runner.run_vector(&vector);
            assert!(
                result.passed,
                "Edge case vector {} should pass: {:?}",
                vector.id,
                result.error
            );
        }
    }

    #[test]
    fn test_conformance_coverage() {
        let results = run_conformance_tests();

        // Should cover all operation types
        assert!(results.total >= 16, "Expected at least 16 execution vectors");

        // Check pass rate
        assert!(
            results.pass_rate() == 100.0,
            "Expected 100% pass rate, got {}%",
            results.pass_rate()
        );
    }
}
