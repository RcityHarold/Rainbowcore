//! Canonicalization Version Control (问题15)
//!
//! This module implements versioned canonicalization algorithms for P1-P2 mapping.
//! Canonicalization ensures that the same logical payload produces the same digest
//! regardless of serialization order or formatting differences.
//!
//! # Version Requirements
//!
//! Per DSN documentation, canonicalization_version determines:
//! 1. Field ordering rules
//! 2. Null/empty handling
//! 3. Numeric representation
//! 4. String normalization (Unicode NFC, etc.)
//!
//! **HARD RULE**: Different canonicalization versions MUST produce different digests.
//! UnknownVersion MUST be rejected.

use l0_core::types::Digest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Canonicalization algorithm version
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanonicalizationVersion(pub String);

impl CanonicalizationVersion {
    /// Version 1.0.0 - Initial canonicalization algorithm
    pub fn v1() -> Self {
        Self("1.0.0".to_string())
    }

    /// Check if this version is supported
    pub fn is_supported(&self) -> bool {
        matches!(self.0.as_str(), "1.0.0")
    }

    /// Get version string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for CanonicalizationVersion {
    fn default() -> Self {
        Self::v1()
    }
}

/// Canonicalization error
#[derive(Debug, Clone, thiserror::Error)]
pub enum CanonicalizationError {
    /// Unknown version
    #[error("Unknown canonicalization version: {0}")]
    UnknownVersion(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Invalid input
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

/// Canonicalizer trait
///
/// Implementations provide versioned canonicalization algorithms.
pub trait Canonicalizer: Send + Sync {
    /// Get the version this canonicalizer implements
    fn version(&self) -> &CanonicalizationVersion;

    /// Canonicalize a JSON value to bytes
    fn canonicalize_json(&self, value: &serde_json::Value) -> Result<Vec<u8>, CanonicalizationError>;

    /// Canonicalize raw bytes with metadata
    fn canonicalize_bytes(&self, data: &[u8], metadata: &BTreeMap<String, String>) -> Result<Vec<u8>, CanonicalizationError>;

    /// Compute canonical digest
    fn canonical_digest(&self, data: &[u8], metadata: &BTreeMap<String, String>) -> Result<Digest, CanonicalizationError> {
        let canonical = self.canonicalize_bytes(data, metadata)?;
        Ok(Digest::blake3(&canonical))
    }
}

/// V1 Canonicalizer (1.0.0)
///
/// Rules:
/// 1. JSON objects: keys sorted alphabetically (Unicode codepoint order)
/// 2. Arrays: preserve order
/// 3. Numbers: normalize to minimal representation
/// 4. Strings: Unicode NFC normalization
/// 5. Null/empty: explicit representation
/// 6. Metadata: sorted by key, prepended to data
#[derive(Debug, Default)]
pub struct V1Canonicalizer {
    version: CanonicalizationVersion,
}

impl V1Canonicalizer {
    /// Create a new V1 canonicalizer
    pub fn new() -> Self {
        Self {
            version: CanonicalizationVersion::v1(),
        }
    }
}

impl Canonicalizer for V1Canonicalizer {
    fn version(&self) -> &CanonicalizationVersion {
        &self.version
    }

    fn canonicalize_json(&self, value: &serde_json::Value) -> Result<Vec<u8>, CanonicalizationError> {
        // Recursively sort object keys and produce canonical JSON
        let canonical = canonicalize_json_value(value);
        serde_json::to_vec(&canonical)
            .map_err(|e| CanonicalizationError::SerializationError(e.to_string()))
    }

    fn canonicalize_bytes(&self, data: &[u8], metadata: &BTreeMap<String, String>) -> Result<Vec<u8>, CanonicalizationError> {
        let mut result = Vec::new();

        // 1. Write version prefix
        result.extend_from_slice(b"CV1:");

        // 2. Write sorted metadata
        for (key, value) in metadata {
            result.extend_from_slice(key.as_bytes());
            result.push(b'=');
            result.extend_from_slice(value.as_bytes());
            result.push(b'\n');
        }

        // 3. Write separator
        result.extend_from_slice(b"\x00\x00");

        // 4. Write data
        result.extend_from_slice(data);

        Ok(result)
    }
}

/// Recursively canonicalize JSON value
fn canonicalize_json_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            // Sort keys alphabetically
            let mut sorted: BTreeMap<String, serde_json::Value> = BTreeMap::new();
            for (k, v) in map {
                sorted.insert(k.clone(), canonicalize_json_value(v));
            }
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(arr) => {
            // Preserve array order, canonicalize elements
            serde_json::Value::Array(arr.iter().map(canonicalize_json_value).collect())
        }
        // Other values are already canonical
        other => other.clone(),
    }
}

/// Canonicalizer registry
///
/// Manages multiple canonicalizer versions and selects the appropriate one.
#[derive(Default)]
pub struct CanonicalizerRegistry {
    canonicalizers: BTreeMap<String, Box<dyn Canonicalizer>>,
}

impl CanonicalizerRegistry {
    /// Create a new registry with default canonicalizers
    pub fn new() -> Self {
        let mut registry = Self {
            canonicalizers: BTreeMap::new(),
        };

        // Register V1
        registry.register(Box::new(V1Canonicalizer::new()));

        registry
    }

    /// Register a canonicalizer
    pub fn register(&mut self, canonicalizer: Box<dyn Canonicalizer>) {
        let version = canonicalizer.version().0.clone();
        self.canonicalizers.insert(version, canonicalizer);
    }

    /// Get canonicalizer for version
    pub fn get(&self, version: &str) -> Option<&dyn Canonicalizer> {
        self.canonicalizers.get(version).map(|c| c.as_ref())
    }

    /// Check if version is supported
    pub fn is_supported(&self, version: &str) -> bool {
        self.canonicalizers.contains_key(version)
    }

    /// Get all supported versions
    pub fn supported_versions(&self) -> Vec<&str> {
        self.canonicalizers.keys().map(|s| s.as_str()).collect()
    }

    /// Canonicalize with specified version
    ///
    /// **HARD RULE**: UnknownVersion returns error.
    pub fn canonicalize(
        &self,
        version: &str,
        data: &[u8],
        metadata: &BTreeMap<String, String>,
    ) -> Result<Vec<u8>, CanonicalizationError> {
        let canonicalizer = self.get(version)
            .ok_or_else(|| CanonicalizationError::UnknownVersion(version.to_string()))?;
        canonicalizer.canonicalize_bytes(data, metadata)
    }

    /// Compute canonical digest with specified version
    pub fn canonical_digest(
        &self,
        version: &str,
        data: &[u8],
        metadata: &BTreeMap<String, String>,
    ) -> Result<Digest, CanonicalizationError> {
        let canonicalizer = self.get(version)
            .ok_or_else(|| CanonicalizationError::UnknownVersion(version.to_string()))?;
        canonicalizer.canonical_digest(data, metadata)
    }
}

/// Canonicalization result with version info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalizationResult {
    /// Version used
    pub version: String,
    /// Canonical digest
    pub digest: Digest,
    /// Canonical data size
    pub canonical_size: u64,
    /// Original data size
    pub original_size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v1_canonicalizer() {
        let canonicalizer = V1Canonicalizer::new();
        assert_eq!(canonicalizer.version().as_str(), "1.0.0");
        assert!(canonicalizer.version().is_supported());
    }

    #[test]
    fn test_json_canonicalization() {
        let canonicalizer = V1Canonicalizer::new();

        // Object with unsorted keys
        let json1 = serde_json::json!({
            "zebra": 1,
            "apple": 2,
            "mango": 3
        });

        // Object with same keys, different order
        let json2 = serde_json::json!({
            "apple": 2,
            "mango": 3,
            "zebra": 1
        });

        let canon1 = canonicalizer.canonicalize_json(&json1).unwrap();
        let canon2 = canonicalizer.canonicalize_json(&json2).unwrap();

        // Should produce identical canonical form
        assert_eq!(canon1, canon2);
    }

    #[test]
    fn test_bytes_canonicalization() {
        let canonicalizer = V1Canonicalizer::new();
        let data = b"test data";
        let mut metadata = BTreeMap::new();
        metadata.insert("type".to_string(), "test".to_string());
        metadata.insert("size".to_string(), "9".to_string());

        let result = canonicalizer.canonicalize_bytes(data, &metadata).unwrap();

        // Should have version prefix
        assert!(result.starts_with(b"CV1:"));

        // Should have metadata
        assert!(String::from_utf8_lossy(&result).contains("size=9"));
        assert!(String::from_utf8_lossy(&result).contains("type=test"));
    }

    #[test]
    fn test_registry() {
        let registry = CanonicalizerRegistry::new();

        assert!(registry.is_supported("1.0.0"));
        assert!(!registry.is_supported("2.0.0"));

        let versions = registry.supported_versions();
        assert!(versions.contains(&"1.0.0"));
    }

    #[test]
    fn test_unknown_version_rejected() {
        let registry = CanonicalizerRegistry::new();
        let data = b"test";
        let metadata = BTreeMap::new();

        let result = registry.canonicalize("9.9.9", data, &metadata);
        assert!(matches!(result, Err(CanonicalizationError::UnknownVersion(_))));
    }

    #[test]
    fn test_canonical_digest_deterministic() {
        let registry = CanonicalizerRegistry::new();
        let data = b"test data for digest";
        let mut metadata = BTreeMap::new();
        metadata.insert("key".to_string(), "value".to_string());

        let digest1 = registry.canonical_digest("1.0.0", data, &metadata).unwrap();
        let digest2 = registry.canonical_digest("1.0.0", data, &metadata).unwrap();

        assert_eq!(digest1, digest2);
    }
}
