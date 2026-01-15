//! Conformance Test Module
//!
//! Provides conformance testing infrastructure for P3 implementations.

pub mod digest;
pub mod execution;
pub mod verification;

use crate::vectors::TestVector;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Conformance test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceResult {
    /// Test vector ID
    pub vector_id: String,
    /// Whether the test passed
    pub passed: bool,
    /// Execution time
    pub duration_ms: u64,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Additional notes
    pub notes: Option<String>,
}

impl ConformanceResult {
    /// Create a passing result
    pub fn pass(vector_id: impl Into<String>, duration: Duration) -> Self {
        Self {
            vector_id: vector_id.into(),
            passed: true,
            duration_ms: duration.as_millis() as u64,
            error: None,
            notes: None,
        }
    }

    /// Create a failing result
    pub fn fail(vector_id: impl Into<String>, duration: Duration, error: impl Into<String>) -> Self {
        Self {
            vector_id: vector_id.into(),
            passed: false,
            duration_ms: duration.as_millis() as u64,
            error: Some(error.into()),
            notes: None,
        }
    }

    /// Add notes to result
    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = Some(notes.into());
        self
    }
}

/// Conformance test suite results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuiteResults {
    /// Suite name
    pub name: String,
    /// Total tests
    pub total: usize,
    /// Passed tests
    pub passed: usize,
    /// Failed tests
    pub failed: usize,
    /// Skipped tests
    pub skipped: usize,
    /// Total duration
    pub duration_ms: u64,
    /// Individual results
    pub results: Vec<ConformanceResult>,
}

impl SuiteResults {
    /// Create new suite results
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            total: 0,
            passed: 0,
            failed: 0,
            skipped: 0,
            duration_ms: 0,
            results: Vec::new(),
        }
    }

    /// Add a result
    pub fn add_result(&mut self, result: ConformanceResult) {
        self.total += 1;
        self.duration_ms += result.duration_ms;

        if result.passed {
            self.passed += 1;
        } else {
            self.failed += 1;
        }

        self.results.push(result);
    }

    /// Check if all tests passed
    pub fn all_passed(&self) -> bool {
        self.failed == 0
    }

    /// Get pass rate as percentage
    pub fn pass_rate(&self) -> f64 {
        if self.total == 0 {
            100.0
        } else {
            (self.passed as f64 / self.total as f64) * 100.0
        }
    }
}

/// Conformance level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConformanceLevel {
    /// L1: Basic conformance
    L1,
    /// L2: Standard conformance
    L2,
    /// L3: Full conformance
    L3,
}

impl ConformanceLevel {
    /// Get level name
    pub fn name(&self) -> &'static str {
        match self {
            ConformanceLevel::L1 => "L1 (Basic)",
            ConformanceLevel::L2 => "L2 (Standard)",
            ConformanceLevel::L3 => "L3 (Full)",
        }
    }
}

/// Trait for conformance test runners
pub trait ConformanceRunner {
    /// The input type for test vectors
    type Input;

    /// Run a single test vector
    fn run_vector(&self, vector: &TestVector<Self::Input>) -> ConformanceResult;

    /// Run all vectors in a suite
    fn run_suite(&self, vectors: &[TestVector<Self::Input>]) -> SuiteResults
    where
        Self: Sized,
    {
        let mut results = SuiteResults::new(std::any::type_name::<Self>());

        for vector in vectors {
            let result = self.run_vector(vector);
            results.add_result(result);
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conformance_result_pass() {
        let result = ConformanceResult::pass("test-001", Duration::from_millis(100));
        assert!(result.passed);
        assert_eq!(result.duration_ms, 100);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_conformance_result_fail() {
        let result = ConformanceResult::fail("test-002", Duration::from_millis(50), "Test failed");
        assert!(!result.passed);
        assert_eq!(result.error, Some("Test failed".to_string()));
    }

    #[test]
    fn test_suite_results() {
        let mut suite = SuiteResults::new("Test Suite");

        suite.add_result(ConformanceResult::pass("test-001", Duration::from_millis(100)));
        suite.add_result(ConformanceResult::pass("test-002", Duration::from_millis(50)));
        suite.add_result(ConformanceResult::fail("test-003", Duration::from_millis(75), "Error"));

        assert_eq!(suite.total, 3);
        assert_eq!(suite.passed, 2);
        assert_eq!(suite.failed, 1);
        assert!(!suite.all_passed());
        assert!((suite.pass_rate() - 66.67).abs() < 1.0);
    }

    #[test]
    fn test_conformance_levels() {
        assert_eq!(ConformanceLevel::L1.name(), "L1 (Basic)");
        assert_eq!(ConformanceLevel::L2.name(), "L2 (Standard)");
        assert_eq!(ConformanceLevel::L3.name(), "L3 (Full)");
    }
}
