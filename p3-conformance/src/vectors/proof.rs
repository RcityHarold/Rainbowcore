//! Proof Test Vectors
//!
//! Test vectors for P3 proof generation and verification conformance.

use super::TestVector;
use p3_core::{P3Digest, ExecutionProofType};
use serde::{Deserialize, Serialize};

/// Proof test input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofInput {
    /// Proof type
    pub proof_type: String,
    /// Execution ID
    pub execution_id: String,
    /// Operation digest (hex)
    pub operation_digest: String,
    /// Executor reference
    pub executor_ref: String,
    /// Epoch ID
    pub epoch_id: String,
}

/// Proof expected output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofExpected {
    /// Whether proof generation should succeed
    pub should_succeed: bool,
    /// Expected proof type
    pub proof_type: Option<String>,
    /// Expected proof digest length
    pub digest_length: Option<usize>,
}

/// Get all proof test vectors
pub fn all_vectors() -> Vec<TestVector<ProofInput>> {
    let mut vectors = Vec::new();

    // Standard proof vectors
    vectors.extend(standard_proofs());

    // Invalid proof vectors
    vectors.extend(invalid_proofs());

    // Verification vectors
    vectors.extend(verification_vectors());

    vectors
}

/// Standard proof test vectors
pub fn standard_proofs() -> Vec<TestVector<ProofInput>> {
    vec![
        // OnChain proof
        TestVector::new(
            "proof-001",
            "Standard on-chain proof",
            ProofInput {
                proof_type: "OnChain".to_string(),
                execution_id: "exec:2024:001:0001".to_string(),
                operation_digest: hex::encode(P3Digest::blake3(b"operation:001").as_bytes()),
                executor_ref: "executor:test:001".to_string(),
                epoch_id: "epoch:2024:001".to_string(),
            },
        )
        .with_expected(serde_json::json!({
            "should_succeed": true,
            "proof_type": "OnChain",
            "digest_length": 32
        }))
        .with_tags(vec!["standard", "on-chain"]),

        // OffChain proof
        TestVector::new(
            "proof-002",
            "Standard off-chain proof",
            ProofInput {
                proof_type: "OffChain".to_string(),
                execution_id: "exec:2024:001:0002".to_string(),
                operation_digest: hex::encode(P3Digest::blake3(b"offchain:operation:001").as_bytes()),
                executor_ref: "executor:test:001".to_string(),
                epoch_id: "epoch:2024:001".to_string(),
            },
        )
        .with_expected(serde_json::json!({
            "should_succeed": true,
            "proof_type": "OffChain",
            "digest_length": 32
        }))
        .with_tags(vec!["standard", "off-chain"]),

        // Credit proof
        TestVector::new(
            "proof-003",
            "Standard credit proof",
            ProofInput {
                proof_type: "Credit".to_string(),
                execution_id: "exec:2024:001:0003".to_string(),
                operation_digest: hex::encode(P3Digest::blake3(b"credit:operation:001").as_bytes()),
                executor_ref: "executor:test:001".to_string(),
                epoch_id: "epoch:2024:001".to_string(),
            },
        )
        .with_expected(serde_json::json!({
            "should_succeed": true,
            "proof_type": "Credit",
            "digest_length": 32
        }))
        .with_tags(vec!["standard", "credit"]),

        // MultiSig proof
        TestVector::new(
            "proof-004",
            "Standard multi-signature proof",
            ProofInput {
                proof_type: "MultiSig".to_string(),
                execution_id: "exec:2024:001:0004".to_string(),
                operation_digest: hex::encode(P3Digest::blake3(b"multisig:operation:001").as_bytes()),
                executor_ref: "executor:test:001".to_string(),
                epoch_id: "epoch:2024:001".to_string(),
            },
        )
        .with_expected(serde_json::json!({
            "should_succeed": true,
            "proof_type": "MultiSig",
            "digest_length": 32
        }))
        .with_tags(vec!["standard", "multi-sig"]),

        // OnChain with different executor
        TestVector::new(
            "proof-005",
            "On-chain proof with different executor",
            ProofInput {
                proof_type: "OnChain".to_string(),
                execution_id: "exec:2024:001:0005".to_string(),
                operation_digest: hex::encode(P3Digest::blake3(b"operation:002").as_bytes()),
                executor_ref: "executor:test:002".to_string(),
                epoch_id: "epoch:2024:001".to_string(),
            },
        )
        .with_expected(serde_json::json!({
            "should_succeed": true,
            "proof_type": "OnChain",
            "digest_length": 32
        }))
        .with_tags(vec!["standard", "on-chain"]),

        // OffChain in different epoch
        TestVector::new(
            "proof-006",
            "Off-chain proof in different epoch",
            ProofInput {
                proof_type: "OffChain".to_string(),
                execution_id: "exec:2024:002:0001".to_string(),
                operation_digest: hex::encode(P3Digest::blake3(b"offchain:epoch2").as_bytes()),
                executor_ref: "executor:test:001".to_string(),
                epoch_id: "epoch:2024:002".to_string(),
            },
        )
        .with_expected(serde_json::json!({
            "should_succeed": true,
            "proof_type": "OffChain",
            "digest_length": 32
        }))
        .with_tags(vec!["standard", "off-chain", "epoch"]),
    ]
}

/// Invalid proof test vectors
pub fn invalid_proofs() -> Vec<TestVector<ProofInput>> {
    vec![
        // Unknown proof type
        TestVector::new(
            "proof-101",
            "Invalid proof type",
            ProofInput {
                proof_type: "UnknownType".to_string(),
                execution_id: "exec:2024:001:0001".to_string(),
                operation_digest: hex::encode(P3Digest::blake3(b"test").as_bytes()),
                executor_ref: "executor:test:001".to_string(),
                epoch_id: "epoch:2024:001".to_string(),
            },
        )
        .should_fail()
        .with_expected(serde_json::json!({
            "should_succeed": false,
            "error": "InvalidProofType"
        }))
        .with_tags(vec!["invalid", "type"]),

        // Empty execution ID
        TestVector::new(
            "proof-102",
            "Empty execution ID",
            ProofInput {
                proof_type: "OnChain".to_string(),
                execution_id: "".to_string(),
                operation_digest: hex::encode(P3Digest::blake3(b"test").as_bytes()),
                executor_ref: "executor:test:001".to_string(),
                epoch_id: "epoch:2024:001".to_string(),
            },
        )
        .should_fail()
        .with_expected(serde_json::json!({
            "should_succeed": false,
            "error": "EmptyExecutionId"
        }))
        .with_tags(vec!["invalid", "empty"]),

        // Invalid digest (not hex)
        TestVector::new(
            "proof-103",
            "Invalid operation digest (not hex)",
            ProofInput {
                proof_type: "OnChain".to_string(),
                execution_id: "exec:2024:001:0001".to_string(),
                operation_digest: "not-a-valid-hex-string!@#$".to_string(),
                executor_ref: "executor:test:001".to_string(),
                epoch_id: "epoch:2024:001".to_string(),
            },
        )
        .should_fail()
        .with_expected(serde_json::json!({
            "should_succeed": false,
            "error": "InvalidDigestFormat"
        }))
        .with_tags(vec!["invalid", "digest"]),

        // Empty executor reference
        TestVector::new(
            "proof-104",
            "Empty executor reference",
            ProofInput {
                proof_type: "Credit".to_string(),
                execution_id: "exec:2024:001:0001".to_string(),
                operation_digest: hex::encode(P3Digest::blake3(b"test").as_bytes()),
                executor_ref: "".to_string(),
                epoch_id: "epoch:2024:001".to_string(),
            },
        )
        .should_fail()
        .with_expected(serde_json::json!({
            "should_succeed": false,
            "error": "EmptyExecutorRef"
        }))
        .with_tags(vec!["invalid", "empty"]),

        // Empty epoch ID
        TestVector::new(
            "proof-105",
            "Empty epoch ID",
            ProofInput {
                proof_type: "MultiSig".to_string(),
                execution_id: "exec:2024:001:0001".to_string(),
                operation_digest: hex::encode(P3Digest::blake3(b"test").as_bytes()),
                executor_ref: "executor:test:001".to_string(),
                epoch_id: "".to_string(),
            },
        )
        .should_fail()
        .with_expected(serde_json::json!({
            "should_succeed": false,
            "error": "EmptyEpochId"
        }))
        .with_tags(vec!["invalid", "empty"]),
    ]
}

/// Verification test vectors
pub fn verification_vectors() -> Vec<TestVector<ProofInput>> {
    vec![
        // Verification with valid on-chain proof
        TestVector::new(
            "proof-201",
            "Verify valid on-chain proof",
            ProofInput {
                proof_type: "OnChain".to_string(),
                execution_id: "exec:2024:001:verify:001".to_string(),
                operation_digest: hex::encode(P3Digest::blake3(b"verify:operation:001").as_bytes()),
                executor_ref: "executor:test:001".to_string(),
                epoch_id: "epoch:2024:001".to_string(),
            },
        )
        .with_expected(serde_json::json!({
            "should_succeed": true,
            "verification_result": "Valid",
            "conformance_level": "L1"
        }))
        .with_tags(vec!["verification", "valid"]),

        // Verification with valid off-chain proof
        TestVector::new(
            "proof-202",
            "Verify valid off-chain proof",
            ProofInput {
                proof_type: "OffChain".to_string(),
                execution_id: "exec:2024:001:verify:002".to_string(),
                operation_digest: hex::encode(P3Digest::blake3(b"verify:offchain:002").as_bytes()),
                executor_ref: "executor:test:001".to_string(),
                epoch_id: "epoch:2024:001".to_string(),
            },
        )
        .with_expected(serde_json::json!({
            "should_succeed": true,
            "verification_result": "Valid"
        }))
        .with_tags(vec!["verification", "valid"]),

        // Verification with tampered digest
        TestVector::new(
            "proof-203",
            "Verify proof with tampered digest",
            ProofInput {
                proof_type: "Credit".to_string(),
                execution_id: "exec:2024:001:verify:003".to_string(),
                operation_digest: "0".repeat(64), // All zeros - tampered
                executor_ref: "executor:test:001".to_string(),
                epoch_id: "epoch:2024:001".to_string(),
            },
        )
        .with_expected(serde_json::json!({
            "should_succeed": true,
            "verification_notes": "Digest verification should detect tampering"
        }))
        .with_tags(vec!["verification", "tampering"]),
    ]
}

/// Parse proof type from string
pub fn parse_proof_type(s: &str) -> Option<ExecutionProofType> {
    match s.to_lowercase().as_str() {
        "onchain" | "on_chain" | "on-chain" => Some(ExecutionProofType::OnChain),
        "offchain" | "off_chain" | "off-chain" => Some(ExecutionProofType::OffChain),
        "credit" => Some(ExecutionProofType::Credit),
        "multisig" | "multi_sig" | "multi-sig" => Some(ExecutionProofType::MultiSig),
        _ => None,
    }
}

/// Validate proof digest format
pub fn validate_digest_format(digest_hex: &str) -> bool {
    // Must be valid hex
    if hex::decode(digest_hex).is_err() {
        return false;
    }

    // Must be 32 bytes (64 hex chars)
    digest_hex.len() == 64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_vectors_count() {
        let vectors = all_vectors();
        assert!(vectors.len() >= 14, "Expected at least 14 proof vectors");
    }

    #[test]
    fn test_standard_proofs_succeed() {
        for vector in standard_proofs() {
            assert!(vector.should_succeed, "Standard vector {} should succeed", vector.id);
        }
    }

    #[test]
    fn test_invalid_proofs_fail() {
        for vector in invalid_proofs() {
            assert!(!vector.should_succeed, "Invalid vector {} should fail", vector.id);
        }
    }

    #[test]
    fn test_parse_proof_types() {
        assert!(matches!(parse_proof_type("OnChain"), Some(ExecutionProofType::OnChain)));
        assert!(matches!(parse_proof_type("onchain"), Some(ExecutionProofType::OnChain)));
        assert!(matches!(parse_proof_type("on-chain"), Some(ExecutionProofType::OnChain)));
        assert!(matches!(parse_proof_type("OffChain"), Some(ExecutionProofType::OffChain)));
        assert!(matches!(parse_proof_type("offchain"), Some(ExecutionProofType::OffChain)));
        assert!(matches!(parse_proof_type("Credit"), Some(ExecutionProofType::Credit)));
        assert!(matches!(parse_proof_type("credit"), Some(ExecutionProofType::Credit)));
        assert!(matches!(parse_proof_type("MultiSig"), Some(ExecutionProofType::MultiSig)));
        assert!(matches!(parse_proof_type("multisig"), Some(ExecutionProofType::MultiSig)));
        assert!(parse_proof_type("Unknown").is_none());
    }

    #[test]
    fn test_validate_digest_format() {
        // Valid 32-byte hex
        let valid = hex::encode(P3Digest::blake3(b"test").as_bytes());
        assert!(validate_digest_format(&valid));

        // Invalid hex
        assert!(!validate_digest_format("not-hex!@#"));

        // Wrong length
        assert!(!validate_digest_format("abcd"));
    }

    #[test]
    fn test_proof_type_coverage() {
        let standard = standard_proofs();
        let proof_types: Vec<&str> = standard.iter()
            .map(|v| v.input.proof_type.as_str())
            .collect();

        assert!(proof_types.contains(&"OnChain"));
        assert!(proof_types.contains(&"OffChain"));
        assert!(proof_types.contains(&"Credit"));
        assert!(proof_types.contains(&"MultiSig"));
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
