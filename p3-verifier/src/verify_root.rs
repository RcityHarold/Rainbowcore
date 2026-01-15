//! Root Verification
//!
//! Verifies result_root_digest computation and consistency.

use crate::error::VerifierResult;
use p3_core::{EconomyEpochBundle, P3Digest, MerkleRoot};

/// Root verification error
#[derive(Clone, Debug)]
pub struct RootVerificationError {
    pub code: String,
    pub message: String,
}

impl RootVerificationError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

/// Root verification result
#[derive(Clone, Debug)]
pub struct RootVerificationResult {
    /// Overall validity
    pub is_valid: bool,
    /// Errors found
    pub errors: Vec<RootVerificationError>,
    /// Computed root digest
    pub computed_root: Option<P3Digest>,
}

impl RootVerificationResult {
    pub fn valid(computed_root: P3Digest) -> Self {
        Self {
            is_valid: true,
            errors: vec![],
            computed_root: Some(computed_root),
        }
    }

    pub fn invalid(errors: Vec<RootVerificationError>) -> Self {
        Self {
            is_valid: false,
            errors,
            computed_root: None,
        }
    }
}

/// Root verifier
pub struct RootVerifier {
    /// Allow zero root
    allow_zero_root: bool,
}

impl RootVerifier {
    /// Create new root verifier
    pub fn new() -> Self {
        Self {
            allow_zero_root: true,
        }
    }

    /// Disallow zero root
    pub fn with_strict_root(mut self) -> Self {
        self.allow_zero_root = false;
        self
    }

    /// Verify result root
    pub fn verify(&self, bundle: &EconomyEpochBundle) -> VerifierResult<RootVerificationResult> {
        let mut errors = Vec::new();

        // 1. Check if result_root_digest is zero
        if bundle.result_root_digest.is_zero() {
            if !self.allow_zero_root {
                errors.push(RootVerificationError::new(
                    "ZERO_RESULT_ROOT",
                    "Result root digest cannot be zero",
                ));
            }
        }

        // 2. Verify the root is derived from the correct inputs
        // In zero-plaintext mode, we verify the structural integrity
        let computed_root = self.compute_expected_root(bundle);

        // 3. Compare computed vs declared
        if !bundle.result_root_digest.is_zero() && computed_root != bundle.result_root_digest {
            errors.push(RootVerificationError::new(
                "ROOT_MISMATCH",
                "Computed result root does not match declared root",
            ));
        }

        if errors.is_empty() {
            Ok(RootVerificationResult::valid(computed_root))
        } else {
            Ok(RootVerificationResult::invalid(errors))
        }
    }

    /// Compute expected result root from bundle
    fn compute_expected_root(&self, bundle: &EconomyEpochBundle) -> P3Digest {
        // Result root = H(epoch_header_digest || manifest_combined_digest || receipt_refs_digest)
        let header_digest = self.compute_header_digest(&bundle.epoch_header);
        let manifest_digest = bundle.epoch_header.manifest_digest.combined_digest();
        let receipt_digest = &bundle.receipt_refs_digest.0;

        let mut data = Vec::with_capacity(96);
        data.extend_from_slice(&header_digest.0);
        data.extend_from_slice(&manifest_digest.0);
        data.extend_from_slice(&receipt_digest.0);

        P3Digest::blake3(&data)
    }

    /// Compute header digest
    fn compute_header_digest(&self, header: &p3_core::EpochHeader) -> P3Digest {
        // Header digest = H(epoch_id || epoch_window || cutoff_ref || weights_version || policy_refs)
        let data = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            header.epoch_id.as_str(),
            header.epoch_window.start.timestamp(),
            header.epoch_window.end.timestamp(),
            header.cutoff_ref.batch_sequence_no_ref.unwrap_or(0),
            header.weights_version.version_id,
            header.policy_refs_digest.0.to_hex(),
            header.canon_version.0
        );
        P3Digest::blake3(data.as_bytes())
    }

    /// Verify root is anchored to chain (if chain_anchor_link present)
    pub fn verify_chain_anchor(&self, bundle: &EconomyEpochBundle) -> VerifierResult<bool> {
        if let Some(ref anchor) = bundle.chain_anchor_link {
            // Verify anchor references the result root
            // In a real implementation, this would verify on-chain
            Ok(!anchor.tx_id.is_empty() && anchor.block_number > 0)
        } else {
            // No anchor is valid (optional)
            Ok(true)
        }
    }

    /// Verify root inclusion proof
    pub fn verify_inclusion_proof(
        &self,
        leaf: &P3Digest,
        proof: &[P3Digest],
        root: &P3Digest,
    ) -> VerifierResult<bool> {
        let mut current = leaf.clone();

        for sibling in proof {
            current = P3Digest::combine(&current, sibling);
        }

        Ok(current == *root)
    }
}

impl Default for RootVerifier {
    fn default() -> Self {
        Self::new()
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

    fn create_test_bundle() -> EconomyEpochBundle {
        let now = Utc::now();
        let manifest_sets = ManifestFourSets {
            knowledge_events: EventSet::empty(),
            court_events: EventSet::empty(),
            policy_state: EventSet::empty(),
            sampling_audit: EventSet::empty(),
        };

        let epoch_header = EpochHeader {
            epoch_id: EpochId::new("epoch:test:001"),
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
    fn test_root_verifier_creation() {
        let verifier = RootVerifier::new();
        assert!(verifier.allow_zero_root);
    }

    #[test]
    fn test_verify_zero_root_allowed() {
        let verifier = RootVerifier::new();
        let bundle = create_test_bundle();

        let result = verifier.verify(&bundle).unwrap();
        assert!(result.is_valid);
    }

    #[test]
    fn test_verify_zero_root_strict() {
        let verifier = RootVerifier::new().with_strict_root();
        let bundle = create_test_bundle();

        let result = verifier.verify(&bundle).unwrap();
        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| e.code == "ZERO_RESULT_ROOT"));
    }

    #[test]
    fn test_verify_inclusion_proof() {
        let verifier = RootVerifier::new();
        let leaf = P3Digest::blake3(b"leaf");
        let sibling = P3Digest::blake3(b"sibling");
        let root = P3Digest::combine(&leaf, &sibling);

        let valid = verifier
            .verify_inclusion_proof(&leaf, &[sibling], &root)
            .unwrap();
        assert!(valid);
    }
}
