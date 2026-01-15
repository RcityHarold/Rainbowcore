//! Test Vectors Module
//!
//! Standardized test vectors for P3 conformance testing.
//! These vectors ensure consistent behavior across implementations.

pub mod digest;
pub mod disclosure;
pub mod execution;
pub mod epoch;
pub mod proof;

use p3_core::{EpochId, P3Digest};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

/// Test vector for any operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestVector<T> {
    /// Test vector ID
    pub id: String,
    /// Description
    pub description: String,
    /// Input data
    pub input: T,
    /// Expected output (if applicable)
    pub expected: Option<serde_json::Value>,
    /// Whether this should succeed
    pub should_succeed: bool,
    /// Tags for categorization
    pub tags: Vec<String>,
}

impl<T> TestVector<T> {
    /// Create a new test vector
    pub fn new(id: impl Into<String>, description: impl Into<String>, input: T) -> Self {
        Self {
            id: id.into(),
            description: description.into(),
            input,
            expected: None,
            should_succeed: true,
            tags: Vec::new(),
        }
    }

    /// Set expected output
    pub fn with_expected(mut self, expected: serde_json::Value) -> Self {
        self.expected = Some(expected);
        self
    }

    /// Mark as should fail
    pub fn should_fail(mut self) -> Self {
        self.should_succeed = false;
        self
    }

    /// Add tags
    pub fn with_tags(mut self, tags: Vec<&str>) -> Self {
        self.tags = tags.into_iter().map(String::from).collect();
        self
    }
}

/// Standard epoch IDs for testing
pub mod epochs {
    use super::*;

    /// Test epoch 2024:001
    pub fn epoch_2024_001() -> EpochId {
        EpochId::new("epoch:2024:001")
    }

    /// Test epoch 2024:002
    pub fn epoch_2024_002() -> EpochId {
        EpochId::new("epoch:2024:002")
    }

    /// Test epoch 2024:003
    pub fn epoch_2024_003() -> EpochId {
        EpochId::new("epoch:2024:003")
    }

    /// Invalid epoch (for negative testing)
    pub fn invalid_epoch() -> EpochId {
        EpochId::new("")
    }
}

/// Standard amounts for testing
pub mod amounts {
    use super::*;

    /// Zero amount
    pub fn zero() -> Decimal {
        Decimal::ZERO
    }

    /// Small amount (0.01)
    pub fn small() -> Decimal {
        Decimal::new(1, 2)
    }

    /// Medium amount (100.00)
    pub fn medium() -> Decimal {
        Decimal::new(10000, 2)
    }

    /// Large amount (1,000,000.00)
    pub fn large() -> Decimal {
        Decimal::new(100_000_000, 2)
    }

    /// Negative amount (for negative testing)
    pub fn negative() -> Decimal {
        Decimal::new(-100, 2)
    }

    /// Maximum safe amount
    pub fn max_safe() -> Decimal {
        Decimal::new(i64::MAX / 100, 2)
    }
}

/// Standard actor references for testing
pub mod actors {
    /// Provider actor
    pub fn provider_1() -> &'static str {
        "provider:test:001"
    }

    /// Provider actor 2
    pub fn provider_2() -> &'static str {
        "provider:test:002"
    }

    /// Executor actor
    pub fn executor_1() -> &'static str {
        "executor:test:001"
    }

    /// Initiator actor
    pub fn initiator_1() -> &'static str {
        "initiator:test:001"
    }

    /// System actor
    pub fn system() -> &'static str {
        "system:p3"
    }
}

/// Standard digests for testing
pub mod digests {
    use super::*;

    /// Zero digest
    pub fn zero() -> P3Digest {
        P3Digest::zero()
    }

    /// Digest of "test"
    pub fn test_digest() -> P3Digest {
        P3Digest::blake3(b"test")
    }

    /// Digest of empty data
    pub fn empty_digest() -> P3Digest {
        P3Digest::blake3(b"")
    }

    /// Digest of "hello world"
    pub fn hello_world() -> P3Digest {
        P3Digest::blake3(b"hello world")
    }

    /// Known digest for deterministic testing
    pub fn known_digest_1() -> P3Digest {
        P3Digest::blake3(b"conformance:test:vector:001")
    }

    /// Known digest for deterministic testing
    pub fn known_digest_2() -> P3Digest {
        P3Digest::blake3(b"conformance:test:vector:002")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_test_vector_creation() {
        let vector: TestVector<String> = TestVector::new(
            "test-001",
            "Test vector description",
            "input data".to_string(),
        );

        assert_eq!(vector.id, "test-001");
        assert!(vector.should_succeed);
        assert!(vector.expected.is_none());
    }

    #[test]
    fn test_test_vector_with_expected() {
        let vector: TestVector<String> = TestVector::new("test-002", "Test", "input".to_string())
            .with_expected(serde_json::json!({"result": "success"}));

        assert!(vector.expected.is_some());
    }

    #[test]
    fn test_test_vector_should_fail() {
        let vector: TestVector<String> =
            TestVector::new("test-003", "Failure test", "bad input".to_string()).should_fail();

        assert!(!vector.should_succeed);
    }

    #[test]
    fn test_epochs() {
        let epoch = epochs::epoch_2024_001();
        assert_eq!(epoch.as_str(), "epoch:2024:001");
    }

    #[test]
    fn test_amounts() {
        assert_eq!(amounts::zero(), Decimal::ZERO);
        assert_eq!(amounts::small(), Decimal::new(1, 2));
        assert!(amounts::negative() < Decimal::ZERO);
    }

    #[test]
    fn test_digests_deterministic() {
        // Same input should always produce same digest
        let d1 = digests::test_digest();
        let d2 = digests::test_digest();
        assert_eq!(d1, d2);

        // Different inputs produce different digests
        let d3 = digests::hello_world();
        assert_ne!(d1, d3);
    }
}
