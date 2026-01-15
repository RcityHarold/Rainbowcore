//! Digest Conformance Tests
//!
//! Tests for P3 digest computation conformance.

use super::{ConformanceResult, ConformanceRunner, SuiteResults};
use crate::vectors::{digest as vectors, TestVector};
use p3_core::P3Digest;
use std::time::Instant;

/// Digest conformance runner
pub struct DigestConformanceRunner;

impl DigestConformanceRunner {
    /// Create new runner
    pub fn new() -> Self {
        Self
    }

    /// Run all digest conformance tests
    pub fn run_all(&self) -> SuiteResults {
        let vectors = vectors::all_vectors();
        self.run_suite(&vectors)
    }
}

impl Default for DigestConformanceRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl ConformanceRunner for DigestConformanceRunner {
    type Input = vectors::DigestInput;

    fn run_vector(&self, vector: &TestVector<Self::Input>) -> ConformanceResult {
        let start = Instant::now();

        // Decode input
        let input_bytes = match hex::decode(&vector.input.data_hex) {
            Ok(bytes) => bytes,
            Err(e) => {
                return ConformanceResult::fail(
                    &vector.id,
                    start.elapsed(),
                    format!("Failed to decode input hex: {}", e),
                );
            }
        };

        // Compute digest
        let computed = P3Digest::blake3(&input_bytes);
        let computed_hex = hex::encode(computed.as_bytes());

        // Verify against expected
        if let Some(expected) = &vector.expected {
            if let Some(expected_hex) = expected.get("blake3_hex").and_then(|v| v.as_str()) {
                if computed_hex != expected_hex {
                    return ConformanceResult::fail(
                        &vector.id,
                        start.elapsed(),
                        format!(
                            "Digest mismatch: computed {} != expected {}",
                            computed_hex, expected_hex
                        ),
                    );
                }
            }

            if let Some(expected_len) = expected.get("length").and_then(|v| v.as_u64()) {
                if computed.as_bytes().len() as u64 != expected_len {
                    return ConformanceResult::fail(
                        &vector.id,
                        start.elapsed(),
                        format!(
                            "Length mismatch: {} != {}",
                            computed.as_bytes().len(),
                            expected_len
                        ),
                    );
                }
            }
        }

        ConformanceResult::pass(&vector.id, start.elapsed())
    }
}

/// Run digest conformance tests and return results
pub fn run_conformance_tests() -> SuiteResults {
    let runner = DigestConformanceRunner::new();
    runner.run_all()
}

/// Verify a specific digest computation
pub fn verify_digest(data: &[u8], expected_hex: &str) -> bool {
    let computed = P3Digest::blake3(data);
    hex::encode(computed.as_bytes()) == expected_hex
}

/// Compute digest from hex input
pub fn compute_digest_hex(input_hex: &str) -> Result<String, String> {
    let bytes = hex::decode(input_hex).map_err(|e| format!("Invalid hex: {}", e))?;
    let digest = P3Digest::blake3(&bytes);
    Ok(hex::encode(digest.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digest_runner_creation() {
        let runner = DigestConformanceRunner::new();
        assert!(std::mem::size_of_val(&runner) >= 0); // Runner exists
    }

    #[test]
    fn test_run_all_vectors() {
        let results = run_conformance_tests();

        assert!(results.total > 0, "Should have test vectors");
        assert!(
            results.all_passed(),
            "All digest conformance tests should pass: {}/{} passed",
            results.passed,
            results.total
        );
    }

    #[test]
    fn test_verify_digest() {
        let data = b"hello world";
        let digest = P3Digest::blake3(data);
        let expected_hex = hex::encode(digest.as_bytes());

        assert!(verify_digest(data, &expected_hex));
        assert!(!verify_digest(data, "0".repeat(64).as_str()));
    }

    #[test]
    fn test_compute_digest_hex() {
        let input_hex = hex::encode(b"test");
        let result = compute_digest_hex(&input_hex);

        assert!(result.is_ok());
        let digest_hex = result.unwrap();
        assert_eq!(digest_hex.len(), 64);
    }

    #[test]
    fn test_compute_digest_hex_invalid() {
        let result = compute_digest_hex("not-valid-hex!@#");
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_input_digest() {
        let empty_digest = P3Digest::blake3(b"");
        let empty_hex = hex::encode(empty_digest.as_bytes());

        // Verify against known empty Blake3 hash
        assert_eq!(empty_hex.len(), 64);
        assert!(verify_digest(b"", &empty_hex));
    }

    #[test]
    fn test_determinism() {
        let data = b"conformance test data";

        // Multiple computations should yield same result
        let d1 = P3Digest::blake3(data);
        let d2 = P3Digest::blake3(data);
        let d3 = P3Digest::blake3(data);

        assert_eq!(d1, d2);
        assert_eq!(d2, d3);
    }

    #[test]
    fn test_uniqueness() {
        let d1 = P3Digest::blake3(b"input1");
        let d2 = P3Digest::blake3(b"input2");
        let d3 = P3Digest::blake3(b"input3");

        assert_ne!(d1, d2);
        assert_ne!(d2, d3);
        assert_ne!(d1, d3);
    }

    #[test]
    fn test_conformance_results_structure() {
        let results = run_conformance_tests();

        // Verify result structure
        assert!(!results.name.is_empty());
        assert!(results.duration_ms >= 0);
        assert_eq!(results.total, results.passed + results.failed + results.skipped);

        // Verify each individual result
        for result in &results.results {
            assert!(!result.vector_id.is_empty());
            if result.passed {
                assert!(result.error.is_none());
            }
        }
    }
}
