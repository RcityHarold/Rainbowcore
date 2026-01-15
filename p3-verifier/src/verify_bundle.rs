//! Bundle Verification
//!
//! Verifies EconomyEpochBundle structural integrity.

use crate::error::VerifierResult;
use chrono::{DateTime, Utc};
use p3_core::{EconomyEpochBundle, EpochHeader, ManifestFourSets, P3Digest};

/// Bundle verification error
#[derive(Clone, Debug)]
pub struct BundleVerificationError {
    pub code: String,
    pub message: String,
}

impl BundleVerificationError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

/// Bundle verification result
#[derive(Clone, Debug)]
pub struct BundleVerificationResult {
    /// Overall validity
    pub is_valid: bool,
    /// Errors found
    pub errors: Vec<BundleVerificationError>,
    /// Warnings (non-blocking)
    pub warnings: Vec<String>,
    /// Verification timestamp
    pub verified_at: DateTime<Utc>,
}

impl BundleVerificationResult {
    pub fn valid() -> Self {
        Self {
            is_valid: true,
            errors: vec![],
            warnings: vec![],
            verified_at: Utc::now(),
        }
    }

    pub fn invalid(errors: Vec<BundleVerificationError>) -> Self {
        Self {
            is_valid: false,
            errors,
            warnings: vec![],
            verified_at: Utc::now(),
        }
    }
}

/// Bundle verifier
pub struct BundleVerifier {
    /// Check epoch window validity
    check_epoch_window: bool,
    /// Check cutoff reference
    check_cutoff_ref: bool,
}

impl BundleVerifier {
    /// Create new bundle verifier
    pub fn new() -> Self {
        Self {
            check_epoch_window: true,
            check_cutoff_ref: true,
        }
    }

    /// Disable epoch window check
    pub fn without_epoch_window_check(mut self) -> Self {
        self.check_epoch_window = false;
        self
    }

    /// Verify bundle
    pub fn verify(&self, bundle: &EconomyEpochBundle) -> VerifierResult<BundleVerificationResult> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        // 1. Verify epoch header
        self.verify_epoch_header(&bundle.epoch_header, &mut errors);

        // 2. Verify manifest sets digest consistency
        self.verify_manifest_digest_consistency(
            &bundle.epoch_header,
            &bundle.manifest_sets,
            &mut errors,
        );

        // 3. Verify result root is not zero (optional but recommended)
        if bundle.result_root_digest.is_zero() {
            warnings.push("result_root_digest is zero".to_string());
        }

        // 4. Verify receipt refs digest consistency
        if bundle.receipt_refs_digest.0.is_zero() {
            warnings.push("receipt_refs_digest is zero".to_string());
        }

        if errors.is_empty() {
            let mut result = BundleVerificationResult::valid();
            result.warnings = warnings;
            Ok(result)
        } else {
            let mut result = BundleVerificationResult::invalid(errors);
            result.warnings = warnings;
            Ok(result)
        }
    }

    /// Verify epoch header
    fn verify_epoch_header(
        &self,
        header: &EpochHeader,
        errors: &mut Vec<BundleVerificationError>,
    ) {
        // 1. Epoch ID must not be empty
        if header.epoch_id.as_str().is_empty() {
            errors.push(BundleVerificationError::new(
                "EMPTY_EPOCH_ID",
                "Epoch ID cannot be empty",
            ));
        }

        // 2. Epoch window must be valid
        if self.check_epoch_window && !header.epoch_window.is_valid() {
            errors.push(BundleVerificationError::new(
                "INVALID_EPOCH_WINDOW",
                "Epoch window start must be before end",
            ));
        }

        // 3. Cutoff reference must be valid
        if self.check_cutoff_ref && !header.cutoff_ref.is_valid() {
            errors.push(BundleVerificationError::new(
                "INVALID_CUTOFF_REF",
                "Cutoff reference must have at least one reference set",
            ));
        }

        // 4. Weights version must not be empty
        if header.weights_version.version_id.is_empty() {
            errors.push(BundleVerificationError::new(
                "EMPTY_WEIGHTS_VERSION",
                "Weights version ID cannot be empty",
            ));
        }
    }

    /// Verify manifest digest consistency
    fn verify_manifest_digest_consistency(
        &self,
        header: &EpochHeader,
        manifest_sets: &ManifestFourSets,
        errors: &mut Vec<BundleVerificationError>,
    ) {
        // Compute manifest digest from four sets
        let computed_digest = manifest_sets.compute_manifest_digest();

        // Compare with header's manifest digest
        if computed_digest.knowledge_events_set_digest != header.manifest_digest.knowledge_events_set_digest {
            errors.push(BundleVerificationError::new(
                "KNOWLEDGE_EVENTS_DIGEST_MISMATCH",
                "Knowledge events set digest does not match header",
            ));
        }

        if computed_digest.court_events_set_digest != header.manifest_digest.court_events_set_digest {
            errors.push(BundleVerificationError::new(
                "COURT_EVENTS_DIGEST_MISMATCH",
                "Court events set digest does not match header",
            ));
        }

        if computed_digest.policy_state_set_digest != header.manifest_digest.policy_state_set_digest {
            errors.push(BundleVerificationError::new(
                "POLICY_STATE_DIGEST_MISMATCH",
                "Policy state set digest does not match header",
            ));
        }

        if computed_digest.sampling_audit_set_digest != header.manifest_digest.sampling_audit_set_digest {
            errors.push(BundleVerificationError::new(
                "SAMPLING_AUDIT_DIGEST_MISMATCH",
                "Sampling audit set digest does not match header",
            ));
        }
    }

    /// Verify chain anchor link if present
    pub fn verify_chain_anchor(&self, bundle: &EconomyEpochBundle) -> VerifierResult<bool> {
        if let Some(ref anchor) = bundle.chain_anchor_link {
            // Verify anchor has non-empty tx_id
            if anchor.tx_id.is_empty() {
                return Ok(false);
            }
            // Verify anchor has valid chain type
            if anchor.chain_type.is_empty() {
                return Ok(false);
            }
            Ok(true)
        } else {
            // No anchor is valid (optional)
            Ok(true)
        }
    }
}

impl Default for BundleVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_core::{
        CanonVersion, CutoffRef, EpochWindow, EventSet, ManifestDigest, RefDigest, WeightsVersionRef, EpochId,
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
    fn test_bundle_verifier_creation() {
        let verifier = BundleVerifier::new();
        assert!(verifier.check_epoch_window);
        assert!(verifier.check_cutoff_ref);
    }

    #[test]
    fn test_verify_valid_bundle() {
        let verifier = BundleVerifier::new();
        let bundle = create_test_bundle();

        let result = verifier.verify(&bundle).unwrap();
        assert!(result.is_valid);
    }

    #[test]
    fn test_verify_invalid_epoch_window() {
        let verifier = BundleVerifier::new();
        let now = Utc::now();

        let manifest_sets = ManifestFourSets {
            knowledge_events: EventSet::empty(),
            court_events: EventSet::empty(),
            policy_state: EventSet::empty(),
            sampling_audit: EventSet::empty(),
        };

        let epoch_header = EpochHeader {
            epoch_id: EpochId::new("epoch:test:001"),
            epoch_window: EpochWindow::new(now, now - chrono::Duration::hours(1)), // Invalid: end before start
            cutoff_ref: CutoffRef::new(Some(P3Digest::zero()), Some(100)),
            manifest_digest: manifest_sets.compute_manifest_digest(),
            weights_version: WeightsVersionRef::new("weights:v1", P3Digest::zero()),
            policy_refs_digest: RefDigest::empty(),
            canon_version: CanonVersion::v1(),
        };

        let bundle = EconomyEpochBundle {
            epoch_header,
            manifest_sets,
            receipt_refs_digest: RefDigest::empty(),
            result_root_digest: P3Digest::zero(),
            chain_anchor_link: None,
        };

        let result = verifier.verify(&bundle).unwrap();
        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| e.code == "INVALID_EPOCH_WINDOW"));
    }
}
