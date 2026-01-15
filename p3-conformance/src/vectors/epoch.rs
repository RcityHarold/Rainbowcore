//! Epoch Test Vectors
//!
//! Test vectors for P3 epoch management conformance.

use super::TestVector;
use p3_core::EpochId;
use serde::{Deserialize, Serialize};

/// Epoch test input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochInput {
    /// Epoch ID string
    pub epoch_id: String,
    /// Whether this is expected to be a valid epoch
    pub is_valid: bool,
    /// Description of the epoch
    pub description: String,
}

/// Epoch expected output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochExpected {
    /// Parsed epoch ID (if valid)
    pub parsed_id: Option<String>,
    /// Year component (if extractable)
    pub year: Option<u32>,
    /// Sequence component (if extractable)
    pub sequence: Option<u32>,
}

/// Get all epoch test vectors
pub fn all_vectors() -> Vec<TestVector<EpochInput>> {
    let mut vectors = Vec::new();

    // Valid epoch vectors
    vectors.extend(valid_epochs());

    // Invalid epoch vectors
    vectors.extend(invalid_epochs());

    // Edge case vectors
    vectors.extend(edge_cases());

    // Comparison vectors
    vectors.extend(comparison_vectors());

    vectors
}

/// Valid epoch test vectors
pub fn valid_epochs() -> Vec<TestVector<EpochInput>> {
    vec![
        TestVector::new(
            "epoch-001",
            "Standard epoch format 2024:001",
            EpochInput {
                epoch_id: "epoch:2024:001".to_string(),
                is_valid: true,
                description: "First epoch of 2024".to_string(),
            },
        )
        .with_expected(serde_json::json!({
            "parsed_id": "epoch:2024:001",
            "year": 2024,
            "sequence": 1
        }))
        .with_tags(vec!["valid", "standard"]),

        TestVector::new(
            "epoch-002",
            "Standard epoch format 2024:002",
            EpochInput {
                epoch_id: "epoch:2024:002".to_string(),
                is_valid: true,
                description: "Second epoch of 2024".to_string(),
            },
        )
        .with_expected(serde_json::json!({
            "parsed_id": "epoch:2024:002",
            "year": 2024,
            "sequence": 2
        }))
        .with_tags(vec!["valid", "standard"]),

        TestVector::new(
            "epoch-003",
            "Standard epoch format 2024:365",
            EpochInput {
                epoch_id: "epoch:2024:365".to_string(),
                is_valid: true,
                description: "365th epoch of 2024".to_string(),
            },
        )
        .with_expected(serde_json::json!({
            "parsed_id": "epoch:2024:365",
            "year": 2024,
            "sequence": 365
        }))
        .with_tags(vec!["valid", "end-year"]),

        TestVector::new(
            "epoch-004",
            "Future epoch format 2025:001",
            EpochInput {
                epoch_id: "epoch:2025:001".to_string(),
                is_valid: true,
                description: "First epoch of 2025".to_string(),
            },
        )
        .with_expected(serde_json::json!({
            "parsed_id": "epoch:2025:001",
            "year": 2025,
            "sequence": 1
        }))
        .with_tags(vec!["valid", "future"]),

        TestVector::new(
            "epoch-005",
            "Past epoch format 2023:100",
            EpochInput {
                epoch_id: "epoch:2023:100".to_string(),
                is_valid: true,
                description: "100th epoch of 2023".to_string(),
            },
        )
        .with_expected(serde_json::json!({
            "parsed_id": "epoch:2023:100",
            "year": 2023,
            "sequence": 100
        }))
        .with_tags(vec!["valid", "past"]),
    ]
}

/// Invalid epoch test vectors
pub fn invalid_epochs() -> Vec<TestVector<EpochInput>> {
    vec![
        TestVector::new(
            "epoch-101",
            "Empty epoch ID",
            EpochInput {
                epoch_id: "".to_string(),
                is_valid: false,
                description: "Empty string epoch".to_string(),
            },
        )
        .should_fail()
        .with_expected(serde_json::json!({
            "parsed_id": null,
            "error": "EmptyEpochId"
        }))
        .with_tags(vec!["invalid", "empty"]),

        TestVector::new(
            "epoch-102",
            "Missing prefix epoch ID",
            EpochInput {
                epoch_id: "2024:001".to_string(),
                is_valid: false,
                description: "Missing 'epoch:' prefix".to_string(),
            },
        )
        .should_fail()
        .with_expected(serde_json::json!({
            "parsed_id": null,
            "error": "InvalidFormat"
        }))
        .with_tags(vec!["invalid", "format"]),

        TestVector::new(
            "epoch-103",
            "Wrong prefix epoch ID",
            EpochInput {
                epoch_id: "period:2024:001".to_string(),
                is_valid: false,
                description: "Wrong prefix 'period:'".to_string(),
            },
        )
        .should_fail()
        .with_expected(serde_json::json!({
            "parsed_id": null,
            "error": "InvalidPrefix"
        }))
        .with_tags(vec!["invalid", "prefix"]),

        TestVector::new(
            "epoch-104",
            "Whitespace in epoch ID",
            EpochInput {
                epoch_id: "epoch: 2024 : 001".to_string(),
                is_valid: false,
                description: "Epoch with whitespace".to_string(),
            },
        )
        .should_fail()
        .with_expected(serde_json::json!({
            "parsed_id": null,
            "error": "InvalidCharacters"
        }))
        .with_tags(vec!["invalid", "whitespace"]),

        TestVector::new(
            "epoch-105",
            "Special characters in epoch ID",
            EpochInput {
                epoch_id: "epoch:2024:001!@#".to_string(),
                is_valid: false,
                description: "Epoch with special characters".to_string(),
            },
        )
        .should_fail()
        .with_expected(serde_json::json!({
            "parsed_id": null,
            "error": "InvalidCharacters"
        }))
        .with_tags(vec!["invalid", "special-chars"]),
    ]
}

/// Edge case test vectors
pub fn edge_cases() -> Vec<TestVector<EpochInput>> {
    vec![
        TestVector::new(
            "epoch-201",
            "Epoch with zero sequence",
            EpochInput {
                epoch_id: "epoch:2024:000".to_string(),
                is_valid: true,
                description: "Zero sequence number".to_string(),
            },
        )
        .with_expected(serde_json::json!({
            "parsed_id": "epoch:2024:000",
            "year": 2024,
            "sequence": 0
        }))
        .with_tags(vec!["edge-case", "zero"]),

        TestVector::new(
            "epoch-202",
            "Epoch with large sequence",
            EpochInput {
                epoch_id: "epoch:2024:999".to_string(),
                is_valid: true,
                description: "Large sequence number".to_string(),
            },
        )
        .with_expected(serde_json::json!({
            "parsed_id": "epoch:2024:999",
            "year": 2024,
            "sequence": 999
        }))
        .with_tags(vec!["edge-case", "large"]),

        TestVector::new(
            "epoch-203",
            "Epoch far in the future",
            EpochInput {
                epoch_id: "epoch:2099:001".to_string(),
                is_valid: true,
                description: "Year 2099".to_string(),
            },
        )
        .with_expected(serde_json::json!({
            "parsed_id": "epoch:2099:001",
            "year": 2099,
            "sequence": 1
        }))
        .with_tags(vec!["edge-case", "far-future"]),

        TestVector::new(
            "epoch-204",
            "Epoch with single digit sequence",
            EpochInput {
                epoch_id: "epoch:2024:1".to_string(),
                is_valid: true,
                description: "Single digit sequence".to_string(),
            },
        )
        .with_expected(serde_json::json!({
            "parsed_id": "epoch:2024:1",
            "year": 2024,
            "sequence": 1
        }))
        .with_tags(vec!["edge-case", "format"]),
    ]
}

/// Comparison test vectors
pub fn comparison_vectors() -> Vec<TestVector<EpochInput>> {
    vec![
        TestVector::new(
            "epoch-301",
            "Epoch comparison base: 2024:050",
            EpochInput {
                epoch_id: "epoch:2024:050".to_string(),
                is_valid: true,
                description: "Base epoch for comparison".to_string(),
            },
        )
        .with_expected(serde_json::json!({
            "parsed_id": "epoch:2024:050",
            "comparison_notes": "Earlier than epoch:2024:100, later than epoch:2024:001"
        }))
        .with_tags(vec!["comparison", "base"]),

        TestVector::new(
            "epoch-302",
            "Cross-year comparison: 2023:365 vs 2024:001",
            EpochInput {
                epoch_id: "epoch:2023:365".to_string(),
                is_valid: true,
                description: "Last day of previous year".to_string(),
            },
        )
        .with_expected(serde_json::json!({
            "parsed_id": "epoch:2023:365",
            "comparison_notes": "Should be earlier than epoch:2024:001"
        }))
        .with_tags(vec!["comparison", "cross-year"]),
    ]
}

/// Helper to create EpochId from input
pub fn create_epoch_id(input: &EpochInput) -> EpochId {
    EpochId::new(&input.epoch_id)
}

/// Validate epoch ID format
pub fn validate_epoch_format(epoch_str: &str) -> bool {
    if epoch_str.is_empty() {
        return false;
    }

    // Must start with "epoch:"
    if !epoch_str.starts_with("epoch:") {
        return false;
    }

    // Check for invalid characters
    let allowed_chars: fn(char) -> bool = |c| c.is_alphanumeric() || c == ':';
    if !epoch_str.chars().all(allowed_chars) {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_vectors_count() {
        let vectors = all_vectors();
        assert!(vectors.len() >= 16, "Expected at least 16 epoch vectors");
    }

    #[test]
    fn test_valid_epochs_marked_valid() {
        for vector in valid_epochs() {
            assert!(vector.should_succeed, "Valid vector {} should succeed", vector.id);
            assert!(vector.input.is_valid, "Valid vector {} should be marked is_valid", vector.id);
        }
    }

    #[test]
    fn test_invalid_epochs_marked_invalid() {
        for vector in invalid_epochs() {
            assert!(!vector.should_succeed, "Invalid vector {} should fail", vector.id);
            assert!(!vector.input.is_valid, "Invalid vector {} should be marked !is_valid", vector.id);
        }
    }

    #[test]
    fn test_epoch_id_creation() {
        let valid_input = EpochInput {
            epoch_id: "epoch:2024:001".to_string(),
            is_valid: true,
            description: "Test".to_string(),
        };

        let epoch = create_epoch_id(&valid_input);
        assert_eq!(epoch.as_str(), "epoch:2024:001");
    }

    #[test]
    fn test_validate_epoch_format() {
        assert!(validate_epoch_format("epoch:2024:001"));
        assert!(validate_epoch_format("epoch:2024:365"));
        assert!(!validate_epoch_format(""));
        assert!(!validate_epoch_format("2024:001"));
        assert!(!validate_epoch_format("epoch:2024:001 "));
    }

    #[test]
    fn test_epoch_equality() {
        let e1 = EpochId::new("epoch:2024:001");
        let e2 = EpochId::new("epoch:2024:001");
        let e3 = EpochId::new("epoch:2024:002");

        assert_eq!(e1, e2);
        assert_ne!(e1, e3);
    }

    #[test]
    fn test_vector_ids_unique() {
        let vectors = all_vectors();
        let mut ids: Vec<&str> = vectors.iter().map(|v| v.id.as_str()).collect();
        let original_len = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), original_len, "Vector IDs must be unique");
    }
}
