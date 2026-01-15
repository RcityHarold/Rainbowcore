//! Canonicalization Engine
//!
//! Chapter 2/Chapter 13: Canonicalization Triple Lock
//!
//! Provides deterministic serialization for computing digests.
//! All objects must be canonicalized before hashing.

mod rules;

pub use rules::*;

use crate::error::P3Result;
use crate::types::*;
use serde::Serialize;

/// Canonicalization specification
#[derive(Clone, Debug)]
pub struct CanonSpec {
    /// Version
    pub version: CanonVersion,
    /// Field ordering rule
    pub field_order: FieldOrderRule,
    /// String normalization
    pub string_norm: StringNormRule,
    /// Numeric encoding
    pub numeric_encoding: NumericEncodingRule,
    /// Array processing
    pub array_rule: ArrayRule,
    /// Hash algorithm
    pub hash_algorithm: HashAlgorithm,
    /// Domain separation tags
    pub domain_tags: DomainTags,
}

impl CanonSpec {
    /// Create v1 spec
    pub fn v1() -> Self {
        Self {
            version: CanonVersion::v1(),
            field_order: FieldOrderRule::Alphabetical,
            string_norm: StringNormRule::default(),
            numeric_encoding: NumericEncodingRule::default(),
            array_rule: ArrayRule::default(),
            hash_algorithm: HashAlgorithm::Blake3,
            domain_tags: DomainTags::default(),
        }
    }
}

impl Default for CanonSpec {
    fn default() -> Self {
        Self::v1()
    }
}

/// Canonicalizer
pub struct Canonicalizer {
    spec: CanonSpec,
}

impl Canonicalizer {
    pub fn new(spec: CanonSpec) -> Self {
        Self { spec }
    }

    pub fn v1() -> Self {
        Self::new(CanonSpec::v1())
    }

    /// Canonicalize and compute digest
    pub fn canonicalize_and_hash<T: Serialize>(&self, value: &T) -> P3Result<P3Digest> {
        let canonical = self.canonicalize(value)?;
        Ok(self.hash_with_domain(&canonical, &self.spec.domain_tags.default_tag))
    }

    /// Canonicalize to bytes
    pub fn canonicalize<T: Serialize>(&self, value: &T) -> P3Result<Vec<u8>> {
        // Use serde_json with sorted keys for deterministic output
        let json = serde_json::to_value(value)?;
        let sorted = self.sort_json_keys(&json);
        let canonical = serde_json::to_vec(&sorted)?;
        Ok(canonical)
    }

    /// Sort JSON keys alphabetically (recursive)
    fn sort_json_keys(&self, value: &serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(map) => {
                let mut sorted_map = serde_json::Map::new();
                let mut keys: Vec<_> = map.keys().collect();
                keys.sort();
                for key in keys {
                    if let Some(v) = map.get(key) {
                        sorted_map.insert(key.clone(), self.sort_json_keys(v));
                    }
                }
                serde_json::Value::Object(sorted_map)
            }
            serde_json::Value::Array(arr) => {
                serde_json::Value::Array(arr.iter().map(|v| self.sort_json_keys(v)).collect())
            }
            _ => value.clone(),
        }
    }

    /// Hash with domain separation
    fn hash_with_domain(&self, data: &[u8], domain: &str) -> P3Digest {
        let mut tagged = Vec::with_capacity(domain.len() + 1 + data.len());
        tagged.extend_from_slice(domain.as_bytes());
        tagged.push(0x00); // Separator
        tagged.extend_from_slice(data);

        match self.spec.hash_algorithm {
            HashAlgorithm::Blake3 => P3Digest::blake3(&tagged),
            HashAlgorithm::Sha256 => {
                use sha2::{Sha256, Digest};
                let mut hasher = Sha256::new();
                hasher.update(&tagged);
                let result = hasher.finalize();
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&result);
                P3Digest(bytes)
            }
        }
    }

    /// Canonicalize manifest four sets
    pub fn canonicalize_manifest(&self, sets: &ManifestFourSets) -> P3Result<P3Digest> {
        // Concatenate the four set digests in fixed order
        let mut data = Vec::with_capacity(128);
        data.extend_from_slice(&sets.knowledge_events.set_digest.0.0);
        data.extend_from_slice(&sets.court_events.set_digest.0.0);
        data.extend_from_slice(&sets.policy_state.set_digest.0.0);
        data.extend_from_slice(&sets.sampling_audit.set_digest.0.0);

        Ok(self.hash_with_domain(&data, "p3:manifest"))
    }

    /// Canonicalize event set
    pub fn canonicalize_event_set(&self, events: &[EconomyEventRef]) -> P3Result<SetDigest> {
        if events.is_empty() {
            return Ok(SetDigest::empty());
        }

        // Canonicalize each event
        let mut digests: Vec<P3Digest> = events
            .iter()
            .map(|e| self.canonicalize_and_hash(e))
            .collect::<P3Result<Vec<_>>>()?;

        // Sort digests for deterministic ordering
        digests.sort_by(|a, b| a.0.cmp(&b.0));

        // Combine into single digest
        let mut combined = Vec::with_capacity(digests.len() * 32);
        for d in &digests {
            combined.extend_from_slice(&d.0);
        }

        Ok(SetDigest(self.hash_with_domain(&combined, "p3:event_set")))
    }

    /// Canonicalize version object
    pub fn canonicalize_version<T: Serialize>(&self, version: &T) -> P3Result<P3Digest> {
        let canonical = self.canonicalize(version)?;
        Ok(self.hash_with_domain(&canonical, "p3:version"))
    }

    /// Get the spec version
    pub fn version(&self) -> &CanonVersion {
        &self.spec.version
    }
}

impl Default for Canonicalizer {
    fn default() -> Self {
        Self::v1()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonicalize_deterministic() {
        let canon = Canonicalizer::v1();

        #[derive(Serialize)]
        struct Test {
            b: String,
            a: i32,
        }

        let t1 = Test { a: 1, b: "hello".to_string() };
        let t2 = Test { a: 1, b: "hello".to_string() };

        let d1 = canon.canonicalize_and_hash(&t1).unwrap();
        let d2 = canon.canonicalize_and_hash(&t2).unwrap();

        assert_eq!(d1, d2);
    }

    #[test]
    fn test_canonicalize_different_values() {
        let canon = Canonicalizer::v1();

        #[derive(Serialize)]
        struct Test {
            value: i32,
        }

        let t1 = Test { value: 1 };
        let t2 = Test { value: 2 };

        let d1 = canon.canonicalize_and_hash(&t1).unwrap();
        let d2 = canon.canonicalize_and_hash(&t2).unwrap();

        assert_ne!(d1, d2);
    }

    #[test]
    fn test_sort_json_keys() {
        let canon = Canonicalizer::v1();

        let json = serde_json::json!({
            "z": 1,
            "a": 2,
            "m": {
                "y": 3,
                "b": 4
            }
        });

        let sorted = canon.sort_json_keys(&json);
        let keys: Vec<_> = sorted.as_object().unwrap().keys().collect();
        assert_eq!(keys, vec!["a", "m", "z"]);

        // Check nested keys are also sorted
        let nested = sorted.get("m").unwrap().as_object().unwrap();
        let nested_keys: Vec<_> = nested.keys().collect();
        assert_eq!(nested_keys, vec!["b", "y"]);
    }

    #[test]
    fn test_empty_event_set() {
        let canon = Canonicalizer::v1();
        let result = canon.canonicalize_event_set(&[]).unwrap();
        assert!(result.is_empty());
    }
}
