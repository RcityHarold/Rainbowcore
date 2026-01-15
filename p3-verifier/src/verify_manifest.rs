//! Manifest Verification
//!
//! Verifies ManifestFourSets consistency and digest computation.

use crate::error::VerifierResult;
use p3_core::{EpochHeader, EventSet, ManifestDigest, ManifestFourSets, P3Digest};

/// Manifest verification error
#[derive(Clone, Debug)]
pub struct ManifestVerificationError {
    pub code: String,
    pub message: String,
}

impl ManifestVerificationError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

/// Manifest verification result
#[derive(Clone, Debug)]
pub struct ManifestVerificationResult {
    /// Overall validity
    pub is_valid: bool,
    /// Errors found
    pub errors: Vec<ManifestVerificationError>,
    /// Warnings (non-blocking)
    pub warnings: Vec<String>,
}

impl ManifestVerificationResult {
    pub fn valid() -> Self {
        Self {
            is_valid: true,
            errors: vec![],
            warnings: vec![],
        }
    }

    pub fn invalid(errors: Vec<ManifestVerificationError>) -> Self {
        Self {
            is_valid: false,
            errors,
            warnings: vec![],
        }
    }
}

/// Manifest verifier
pub struct ManifestVerifier {
    /// Require non-empty sets
    require_non_empty: bool,
}

impl ManifestVerifier {
    /// Create new manifest verifier
    pub fn new() -> Self {
        Self {
            require_non_empty: false,
        }
    }

    /// Require non-empty manifest sets
    pub fn with_non_empty_requirement(mut self) -> Self {
        self.require_non_empty = true;
        self
    }

    /// Verify manifest against header
    pub fn verify(
        &self,
        header: &EpochHeader,
        manifest_sets: &ManifestFourSets,
    ) -> VerifierResult<ManifestVerificationResult> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        // 1. Verify each set digest matches
        self.verify_set_digests(header, manifest_sets, &mut errors);

        // 2. Check for empty sets if required
        if self.require_non_empty {
            self.check_empty_sets(manifest_sets, &mut errors);
        } else {
            // Just warn about empty sets
            self.warn_empty_sets(manifest_sets, &mut warnings);
        }

        // 3. Verify combined digest
        self.verify_combined_digest(header, &mut errors);

        if errors.is_empty() {
            let mut result = ManifestVerificationResult::valid();
            result.warnings = warnings;
            Ok(result)
        } else {
            let mut result = ManifestVerificationResult::invalid(errors);
            result.warnings = warnings;
            Ok(result)
        }
    }

    /// Verify individual set digests
    fn verify_set_digests(
        &self,
        header: &EpochHeader,
        manifest_sets: &ManifestFourSets,
        errors: &mut Vec<ManifestVerificationError>,
    ) {
        // Knowledge events
        if manifest_sets.knowledge_events.set_digest != header.manifest_digest.knowledge_events_set_digest {
            errors.push(ManifestVerificationError::new(
                "KNOWLEDGE_EVENTS_MISMATCH",
                "Knowledge events set digest does not match header",
            ));
        }

        // Court events
        if manifest_sets.court_events.set_digest != header.manifest_digest.court_events_set_digest {
            errors.push(ManifestVerificationError::new(
                "COURT_EVENTS_MISMATCH",
                "Court events set digest does not match header",
            ));
        }

        // Policy state
        if manifest_sets.policy_state.set_digest != header.manifest_digest.policy_state_set_digest {
            errors.push(ManifestVerificationError::new(
                "POLICY_STATE_MISMATCH",
                "Policy state set digest does not match header",
            ));
        }

        // Sampling audit
        if manifest_sets.sampling_audit.set_digest != header.manifest_digest.sampling_audit_set_digest {
            errors.push(ManifestVerificationError::new(
                "SAMPLING_AUDIT_MISMATCH",
                "Sampling audit set digest does not match header",
            ));
        }
    }

    /// Check for empty sets (error)
    fn check_empty_sets(
        &self,
        manifest_sets: &ManifestFourSets,
        errors: &mut Vec<ManifestVerificationError>,
    ) {
        if manifest_sets.knowledge_events.set_digest.is_empty() {
            errors.push(ManifestVerificationError::new(
                "EMPTY_KNOWLEDGE_EVENTS",
                "Knowledge events set is empty",
            ));
        }
        // Note: Other sets being empty might be valid depending on the epoch
    }

    /// Warn about empty sets
    fn warn_empty_sets(&self, manifest_sets: &ManifestFourSets, warnings: &mut Vec<String>) {
        if manifest_sets.knowledge_events.set_digest.is_empty() {
            warnings.push("knowledge_events set is empty".to_string());
        }
        if manifest_sets.court_events.set_digest.is_empty() {
            warnings.push("court_events set is empty".to_string());
        }
        if manifest_sets.policy_state.set_digest.is_empty() {
            warnings.push("policy_state set is empty".to_string());
        }
        if manifest_sets.sampling_audit.set_digest.is_empty() {
            warnings.push("sampling_audit set is empty".to_string());
        }
    }

    /// Verify combined digest
    fn verify_combined_digest(&self, header: &EpochHeader, errors: &mut Vec<ManifestVerificationError>) {
        // Verify the manifest_digest itself is not all zeros when we have data
        let combined = header.manifest_digest.combined_digest();
        if combined.is_zero() && !header.manifest_digest.is_empty() {
            errors.push(ManifestVerificationError::new(
                "INVALID_COMBINED_DIGEST",
                "Combined digest is zero but sets are not empty",
            ));
        }
    }

    /// Verify event set structure
    pub fn verify_event_set(&self, event_set: &EventSet) -> VerifierResult<bool> {
        // An event set is valid if its internal digests are consistent
        // In zero-plaintext mode, we only have digests to verify

        // Check that set_digest is not zero if refs_digest is not zero
        if !event_set.refs_digest.0.is_zero() && event_set.set_digest.is_empty() {
            return Ok(false);
        }

        Ok(true)
    }
}

impl Default for ManifestVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use p3_core::{CanonVersion, CutoffRef, EpochId, EpochWindow, RefDigest, WeightsVersionRef};

    fn create_test_manifest() -> ManifestFourSets {
        ManifestFourSets {
            knowledge_events: EventSet::empty(),
            court_events: EventSet::empty(),
            policy_state: EventSet::empty(),
            sampling_audit: EventSet::empty(),
        }
    }

    fn create_test_header(manifest_sets: &ManifestFourSets) -> EpochHeader {
        let now = Utc::now();
        EpochHeader {
            epoch_id: EpochId::new("epoch:test:001"),
            epoch_window: EpochWindow::new(now - chrono::Duration::hours(1), now),
            cutoff_ref: CutoffRef::new(Some(P3Digest::zero()), Some(100)),
            manifest_digest: manifest_sets.compute_manifest_digest(),
            weights_version: WeightsVersionRef::new("weights:v1", P3Digest::zero()),
            policy_refs_digest: RefDigest::empty(),
            canon_version: CanonVersion::v1(),
        }
    }

    #[test]
    fn test_manifest_verifier_creation() {
        let verifier = ManifestVerifier::new();
        assert!(!verifier.require_non_empty);
    }

    #[test]
    fn test_verify_valid_manifest() {
        let verifier = ManifestVerifier::new();
        let manifest_sets = create_test_manifest();
        let header = create_test_header(&manifest_sets);

        let result = verifier.verify(&header, &manifest_sets).unwrap();
        assert!(result.is_valid);
    }

    #[test]
    fn test_verify_event_set() {
        let verifier = ManifestVerifier::new();
        let event_set = EventSet::empty();

        let valid = verifier.verify_event_set(&event_set).unwrap();
        assert!(valid);
    }
}
