//! Digest Test Vectors
//!
//! Test vectors for P3 digest computation conformance.

use p3_core::P3Digest;
use super::TestVector;
use serde::{Deserialize, Serialize};

/// Digest test input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigestInput {
    /// Raw bytes to hash (hex encoded)
    pub data_hex: String,
    /// Description of the data
    pub data_description: String,
}

/// Expected digest output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigestExpected {
    /// Expected Blake3 digest (hex encoded)
    pub blake3_hex: String,
    /// Expected digest bytes length
    pub length: usize,
}

/// Get all digest test vectors
pub fn all_vectors() -> Vec<TestVector<DigestInput>> {
    vec![
        // Basic vectors
        empty_input(),
        single_byte(),
        hello_world(),
        conformance_marker(),
        // Edge cases
        null_bytes(),
        large_input(),
        unicode_input(),
        // Determinism vectors
        determinism_vector_1(),
        determinism_vector_2(),
    ]
}

/// Empty input vector
pub fn empty_input() -> TestVector<DigestInput> {
    TestVector::new(
        "digest-001",
        "Blake3 digest of empty input",
        DigestInput {
            data_hex: "".to_string(),
            data_description: "Empty byte array".to_string(),
        },
    )
    .with_expected(serde_json::json!({
        "blake3_hex": hex::encode(P3Digest::blake3(b"").as_bytes()),
        "length": 32
    }))
    .with_tags(vec!["basic", "empty"])
}

/// Single byte vector
pub fn single_byte() -> TestVector<DigestInput> {
    TestVector::new(
        "digest-002",
        "Blake3 digest of single byte",
        DigestInput {
            data_hex: hex::encode(b"x"),
            data_description: "Single byte 'x'".to_string(),
        },
    )
    .with_expected(serde_json::json!({
        "blake3_hex": hex::encode(P3Digest::blake3(b"x").as_bytes()),
        "length": 32
    }))
    .with_tags(vec!["basic", "single"])
}

/// Hello world vector
pub fn hello_world() -> TestVector<DigestInput> {
    TestVector::new(
        "digest-003",
        "Blake3 digest of 'hello world'",
        DigestInput {
            data_hex: hex::encode(b"hello world"),
            data_description: "ASCII string 'hello world'".to_string(),
        },
    )
    .with_expected(serde_json::json!({
        "blake3_hex": hex::encode(P3Digest::blake3(b"hello world").as_bytes()),
        "length": 32
    }))
    .with_tags(vec!["basic", "common"])
}

/// Conformance marker vector
pub fn conformance_marker() -> TestVector<DigestInput> {
    let data = b"p3:conformance:test:marker:v1";
    TestVector::new(
        "digest-004",
        "Blake3 digest of P3 conformance marker",
        DigestInput {
            data_hex: hex::encode(data),
            data_description: "P3 conformance test marker string".to_string(),
        },
    )
    .with_expected(serde_json::json!({
        "blake3_hex": hex::encode(P3Digest::blake3(data).as_bytes()),
        "length": 32
    }))
    .with_tags(vec!["conformance", "marker"])
}

/// Null bytes vector
pub fn null_bytes() -> TestVector<DigestInput> {
    let data = [0u8; 32];
    TestVector::new(
        "digest-005",
        "Blake3 digest of 32 null bytes",
        DigestInput {
            data_hex: hex::encode(&data),
            data_description: "32 null bytes".to_string(),
        },
    )
    .with_expected(serde_json::json!({
        "blake3_hex": hex::encode(P3Digest::blake3(&data).as_bytes()),
        "length": 32
    }))
    .with_tags(vec!["edge-case", "null"])
}

/// Large input vector (1KB)
pub fn large_input() -> TestVector<DigestInput> {
    let data: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
    TestVector::new(
        "digest-006",
        "Blake3 digest of 1KB sequential data",
        DigestInput {
            data_hex: hex::encode(&data),
            data_description: "1024 bytes of sequential data (0-255 repeated)".to_string(),
        },
    )
    .with_expected(serde_json::json!({
        "blake3_hex": hex::encode(P3Digest::blake3(&data).as_bytes()),
        "length": 32
    }))
    .with_tags(vec!["edge-case", "large"])
}

/// Unicode input vector
pub fn unicode_input() -> TestVector<DigestInput> {
    let data = "彩虹城P3经济层🌈".as_bytes();
    TestVector::new(
        "digest-007",
        "Blake3 digest of Unicode string with emoji",
        DigestInput {
            data_hex: hex::encode(data),
            data_description: "Chinese characters with rainbow emoji".to_string(),
        },
    )
    .with_expected(serde_json::json!({
        "blake3_hex": hex::encode(P3Digest::blake3(data).as_bytes()),
        "length": 32
    }))
    .with_tags(vec!["edge-case", "unicode"])
}

/// Determinism vector 1
pub fn determinism_vector_1() -> TestVector<DigestInput> {
    let data = b"conformance:test:vector:001";
    TestVector::new(
        "digest-008",
        "Deterministic test vector 1",
        DigestInput {
            data_hex: hex::encode(data),
            data_description: "Conformance test vector 001".to_string(),
        },
    )
    .with_expected(serde_json::json!({
        "blake3_hex": hex::encode(P3Digest::blake3(data).as_bytes()),
        "length": 32
    }))
    .with_tags(vec!["determinism", "reference"])
}

/// Determinism vector 2
pub fn determinism_vector_2() -> TestVector<DigestInput> {
    let data = b"conformance:test:vector:002";
    TestVector::new(
        "digest-009",
        "Deterministic test vector 2",
        DigestInput {
            data_hex: hex::encode(data),
            data_description: "Conformance test vector 002".to_string(),
        },
    )
    .with_expected(serde_json::json!({
        "blake3_hex": hex::encode(P3Digest::blake3(data).as_bytes()),
        "length": 32
    }))
    .with_tags(vec!["determinism", "reference"])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_vectors_have_expected() {
        for vector in all_vectors() {
            assert!(vector.expected.is_some(), "Vector {} missing expected", vector.id);
        }
    }

    #[test]
    fn test_digest_determinism() {
        // Same input always produces same output
        let data = b"test data for determinism";
        let d1 = P3Digest::blake3(data);
        let d2 = P3Digest::blake3(data);
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_digest_uniqueness() {
        // Different inputs produce different outputs
        let d1 = P3Digest::blake3(b"input1");
        let d2 = P3Digest::blake3(b"input2");
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_vector_verification() {
        for vector in all_vectors() {
            let input_bytes = hex::decode(&vector.input.data_hex).unwrap();
            let computed = P3Digest::blake3(&input_bytes);

            let expected = vector.expected.as_ref().unwrap();
            let expected_hex = expected["blake3_hex"].as_str().unwrap();

            assert_eq!(
                hex::encode(computed.as_bytes()),
                expected_hex,
                "Vector {} failed verification",
                vector.id
            );
        }
    }
}
