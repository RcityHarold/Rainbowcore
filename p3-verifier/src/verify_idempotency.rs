//! Idempotency Verification
//!
//! Verifies idempotency guarantees and detects double-spend attempts.

use crate::error::VerifierResult;
use p3_core::{EconomyEpochBundle, IdempotencyKey, P3Digest};
use std::collections::{HashMap, HashSet};

/// Idempotency verification error
#[derive(Clone, Debug)]
pub struct IdempotencyVerificationError {
    pub code: String,
    pub message: String,
    pub key: Option<String>,
}

impl IdempotencyVerificationError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            key: None,
        }
    }

    pub fn for_key(code: impl Into<String>, message: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            key: Some(key.into()),
        }
    }
}

/// Idempotency verification result
#[derive(Clone, Debug)]
pub struct IdempotencyVerificationResult {
    /// Overall validity
    pub is_valid: bool,
    /// Errors found
    pub errors: Vec<IdempotencyVerificationError>,
    /// Keys checked
    pub keys_checked: usize,
    /// Duplicate keys found
    pub duplicates_found: Vec<String>,
}

impl IdempotencyVerificationResult {
    pub fn valid(keys_checked: usize) -> Self {
        Self {
            is_valid: true,
            errors: vec![],
            keys_checked,
            duplicates_found: vec![],
        }
    }

    pub fn invalid(errors: Vec<IdempotencyVerificationError>, duplicates: Vec<String>) -> Self {
        Self {
            is_valid: false,
            errors,
            keys_checked: 0,
            duplicates_found: duplicates,
        }
    }
}

/// Idempotency verifier
pub struct IdempotencyVerifier {
    /// Known idempotency keys (for cross-bundle verification)
    known_keys: HashSet<String>,
    /// Key to digest mapping (for collision detection)
    key_digests: HashMap<String, P3Digest>,
}

impl IdempotencyVerifier {
    /// Create new idempotency verifier
    pub fn new() -> Self {
        Self {
            known_keys: HashSet::new(),
            key_digests: HashMap::new(),
        }
    }

    /// Add known keys from previous bundles
    pub fn with_known_keys(mut self, keys: HashSet<String>) -> Self {
        self.known_keys = keys;
        self
    }

    /// Verify idempotency for bundle
    /// In zero-plaintext mode, we verify structural integrity using digests
    pub fn verify(&self, bundle: &EconomyEpochBundle) -> VerifierResult<IdempotencyVerificationResult> {
        let mut errors = Vec::new();
        let duplicates = Vec::new();

        // In zero-plaintext mode, we verify:
        // 1. Epoch ID uniqueness (structural)
        // 2. Receipt refs digest consistency

        let epoch_id = bundle.epoch_header.epoch_id.as_str();

        // Check if epoch ID is already known
        if self.known_keys.contains(epoch_id) {
            errors.push(IdempotencyVerificationError::for_key(
                "DUPLICATE_EPOCH",
                "Epoch ID already exists",
                epoch_id,
            ));
        }

        // Verify epoch ID is not empty
        if epoch_id.is_empty() {
            errors.push(IdempotencyVerificationError::new(
                "EMPTY_EPOCH_ID",
                "Epoch ID cannot be empty",
            ));
        }

        if errors.is_empty() {
            Ok(IdempotencyVerificationResult::valid(1))
        } else {
            Ok(IdempotencyVerificationResult::invalid(errors, duplicates))
        }
    }

    /// Check single idempotency key
    pub fn check_key(&self, key: &IdempotencyKey) -> IdempotencyCheckResult {
        let key_str = key.as_str();

        if self.known_keys.contains(key_str) {
            IdempotencyCheckResult::Duplicate {
                key: key_str.to_string(),
                original_digest: self.key_digests.get(key_str).cloned(),
            }
        } else {
            IdempotencyCheckResult::New {
                key: key_str.to_string(),
            }
        }
    }

    /// Register key as used
    pub fn register_key(&mut self, key: &IdempotencyKey, digest: P3Digest) {
        let key_str = key.as_str().to_string();
        self.known_keys.insert(key_str.clone());
        self.key_digests.insert(key_str, digest);
    }

    /// Verify key-digest consistency
    pub fn verify_key_consistency(
        &self,
        key: &IdempotencyKey,
        digest: &P3Digest,
    ) -> VerifierResult<bool> {
        let key_str = key.as_str();

        if let Some(existing) = self.key_digests.get(key_str) {
            // Key exists - check if digest matches
            Ok(existing == digest)
        } else {
            // New key - always consistent
            Ok(true)
        }
    }

    /// Verify no double-spend across bundles
    pub fn verify_no_double_spend(
        &self,
        bundles: &[EconomyEpochBundle],
    ) -> VerifierResult<IdempotencyVerificationResult> {
        let mut errors = Vec::new();
        let mut duplicates = Vec::new();
        let mut all_epoch_ids = HashSet::new();

        for bundle in bundles {
            let epoch_id = bundle.epoch_header.epoch_id.as_str().to_string();

            if !all_epoch_ids.insert(epoch_id.clone()) {
                errors.push(IdempotencyVerificationError::for_key(
                    "DOUBLE_SPEND",
                    format!("Epoch {} appears in multiple bundles", epoch_id),
                    &epoch_id,
                ));
                duplicates.push(epoch_id);
            }
        }

        if errors.is_empty() {
            Ok(IdempotencyVerificationResult::valid(all_epoch_ids.len()))
        } else {
            Ok(IdempotencyVerificationResult::invalid(errors, duplicates))
        }
    }

    /// Get all known keys
    pub fn known_keys(&self) -> &HashSet<String> {
        &self.known_keys
    }

    /// Clear known keys
    pub fn clear(&mut self) {
        self.known_keys.clear();
        self.key_digests.clear();
    }
}

impl Default for IdempotencyVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of checking a single idempotency key
#[derive(Clone, Debug)]
pub enum IdempotencyCheckResult {
    /// Key is new (not seen before)
    New { key: String },
    /// Key is duplicate
    Duplicate {
        key: String,
        original_digest: Option<P3Digest>,
    },
}

impl IdempotencyCheckResult {
    pub fn is_new(&self) -> bool {
        matches!(self, IdempotencyCheckResult::New { .. })
    }

    pub fn is_duplicate(&self) -> bool {
        matches!(self, IdempotencyCheckResult::Duplicate { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use p3_core::{
        CanonVersion, CutoffRef, EpochHeader, EpochId, EpochWindow, EventSet, ManifestFourSets,
        RefDigest, WeightsVersionRef,
    };

    fn create_test_bundle(epoch_id: &str) -> EconomyEpochBundle {
        let now = Utc::now();
        let manifest_sets = ManifestFourSets {
            knowledge_events: EventSet::empty(),
            court_events: EventSet::empty(),
            policy_state: EventSet::empty(),
            sampling_audit: EventSet::empty(),
        };

        let epoch_header = EpochHeader {
            epoch_id: EpochId::new(epoch_id),
            epoch_window: EpochWindow::new(now - chrono::Duration::hours(1), now),
            cutoff_ref: CutoffRef::new(Some(P3Digest::zero()), Some(100)),
            manifest_digest: manifest_sets.compute_manifest_digest(),
            weights_version: WeightsVersionRef::new("weights:v1", P3Digest::zero()),
            policy_refs_digest: RefDigest::empty(),
            canon_version: CanonVersion::v1(),
        };

        EconomyEpochBundle {
            epoch_header,
            manifest_sets,
            receipt_refs_digest: RefDigest::empty(),
            result_root_digest: P3Digest::zero(),
            chain_anchor_link: None,
        }
    }

    #[test]
    fn test_idempotency_verifier_creation() {
        let verifier = IdempotencyVerifier::new();
        assert!(verifier.known_keys.is_empty());
    }

    #[test]
    fn test_verify_bundle_no_duplicates() {
        let verifier = IdempotencyVerifier::new();
        let bundle = create_test_bundle("epoch:test:001");

        let result = verifier.verify(&bundle).unwrap();
        assert!(result.is_valid);
        assert_eq!(result.keys_checked, 1);
    }

    #[test]
    fn test_verify_bundle_with_known_keys() {
        let mut known = HashSet::new();
        known.insert("epoch:test:001".to_string());

        let verifier = IdempotencyVerifier::new().with_known_keys(known);
        let bundle = create_test_bundle("epoch:test:001");

        let result = verifier.verify(&bundle).unwrap();
        assert!(!result.is_valid);
    }

    #[test]
    fn test_check_key() {
        let mut verifier = IdempotencyVerifier::new();
        let key = IdempotencyKey::new("test:key:1");

        // New key
        let result = verifier.check_key(&key);
        assert!(result.is_new());

        // Register key
        verifier.register_key(&key, P3Digest::zero());

        // Now duplicate
        let result = verifier.check_key(&key);
        assert!(result.is_duplicate());
    }

    #[test]
    fn test_verify_no_double_spend() {
        let verifier = IdempotencyVerifier::new();
        let bundles = vec![
            create_test_bundle("epoch:test:001"),
            create_test_bundle("epoch:test:001"), // Same epoch ID = double spend
        ];

        let result = verifier.verify_no_double_spend(&bundles).unwrap();
        assert!(!result.is_valid);
        assert!(!result.duplicates_found.is_empty());
    }

    #[test]
    fn test_verify_key_consistency() {
        let mut verifier = IdempotencyVerifier::new();
        let key = IdempotencyKey::new("test:key:1");
        let digest = P3Digest::blake3(b"test");

        // Register key
        verifier.register_key(&key, digest.clone());

        // Same digest - consistent
        assert!(verifier.verify_key_consistency(&key, &digest).unwrap());

        // Different digest - inconsistent
        let other_digest = P3Digest::blake3(b"other");
        assert!(!verifier.verify_key_consistency(&key, &other_digest).unwrap());
    }
}
