//! Gate Verification
//!
//! Verifies gate checks for strong economic actions.

use crate::error::VerifierResult;
use p3_core::{EconomyEpochBundle, GateContext, EvidenceLevel, KnownVersionSet};

/// Gate verification error
#[derive(Clone, Debug)]
pub struct GateVerificationError {
    pub code: String,
    pub message: String,
    pub gate_name: Option<String>,
}

impl GateVerificationError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            gate_name: None,
        }
    }

    pub fn for_gate(
        code: impl Into<String>,
        message: impl Into<String>,
        gate: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            gate_name: Some(gate.into()),
        }
    }
}

/// Gate verification result
#[derive(Clone, Debug)]
pub struct GatesVerificationResult {
    /// Overall validity
    pub is_valid: bool,
    /// Errors found
    pub errors: Vec<GateVerificationError>,
    /// Gates checked
    pub gates_checked: usize,
    /// Gates passed
    pub gates_passed: usize,
}

impl GatesVerificationResult {
    pub fn valid(gates_checked: usize) -> Self {
        Self {
            is_valid: true,
            errors: vec![],
            gates_checked,
            gates_passed: gates_checked,
        }
    }

    pub fn invalid(errors: Vec<GateVerificationError>, gates_checked: usize, gates_passed: usize) -> Self {
        Self {
            is_valid: false,
            errors,
            gates_checked,
            gates_passed,
        }
    }
}

/// Gates verifier
pub struct GatesVerifier {
    /// Required evidence level
    required_evidence_level: EvidenceLevel,
    /// Check for degraded mode
    check_degraded: bool,
}

impl GatesVerifier {
    /// Create new gates verifier
    pub fn new() -> Self {
        Self {
            required_evidence_level: EvidenceLevel::A,
            check_degraded: true,
        }
    }

    /// Set required evidence level
    pub fn with_evidence_level(mut self, level: EvidenceLevel) -> Self {
        self.required_evidence_level = level;
        self
    }

    /// Disable degraded mode check
    pub fn without_degraded_check(mut self) -> Self {
        self.check_degraded = false;
        self
    }

    /// Verify gates for bundle
    pub fn verify(&self, bundle: &EconomyEpochBundle) -> VerifierResult<GatesVerificationResult> {
        let mut errors = Vec::new();
        let mut gates_checked = 0;
        let mut gates_passed = 0;

        // 1. Verify epoch header completeness
        gates_checked += 1;
        if self.verify_epoch_header_complete(bundle) {
            gates_passed += 1;
        } else {
            errors.push(GateVerificationError::for_gate(
                "INCOMPLETE_EPOCH_HEADER",
                "Epoch header is missing required fields",
                "epoch_header_complete",
            ));
        }

        // 2. Verify cutoff reference is valid
        gates_checked += 1;
        if bundle.epoch_header.cutoff_ref.is_valid() {
            gates_passed += 1;
        } else {
            errors.push(GateVerificationError::for_gate(
                "INVALID_CUTOFF_REF",
                "Cutoff reference is invalid",
                "cutoff_ref_valid",
            ));
        }

        // 3. Verify weights version is known
        gates_checked += 1;
        if !bundle.epoch_header.weights_version.version_id.is_empty() {
            gates_passed += 1;
        } else {
            errors.push(GateVerificationError::for_gate(
                "UNKNOWN_WEIGHTS_VERSION",
                "Weights version is not set",
                "weights_version_known",
            ));
        }

        // 4. Verify canon version is known
        gates_checked += 1;
        if !bundle.epoch_header.canon_version.0.is_empty() {
            gates_passed += 1;
        } else {
            errors.push(GateVerificationError::for_gate(
                "UNKNOWN_CANON_VERSION",
                "Canon version is not set",
                "canon_version_known",
            ));
        }

        // 5. Verify chain anchor if present
        if let Some(ref anchor) = bundle.chain_anchor_link {
            gates_checked += 1;
            if !anchor.tx_id.is_empty() && !anchor.chain_type.is_empty() {
                gates_passed += 1;
            } else {
                errors.push(GateVerificationError::for_gate(
                    "INVALID_CHAIN_ANCHOR",
                    "Chain anchor is invalid",
                    "chain_anchor_valid",
                ));
            }
        }

        if errors.is_empty() {
            Ok(GatesVerificationResult::valid(gates_checked))
        } else {
            Ok(GatesVerificationResult::invalid(errors, gates_checked, gates_passed))
        }
    }

    /// Verify epoch header completeness
    fn verify_epoch_header_complete(&self, bundle: &EconomyEpochBundle) -> bool {
        let header = &bundle.epoch_header;

        // Check required fields
        !header.epoch_id.as_str().is_empty()
            && header.epoch_window.is_valid()
            && !header.weights_version.version_id.is_empty()
    }

    /// Verify evidence level meets requirement
    pub fn verify_evidence_level(&self, level: EvidenceLevel) -> VerifierResult<bool> {
        match (self.required_evidence_level, level) {
            (EvidenceLevel::A, EvidenceLevel::A) => Ok(true),
            (EvidenceLevel::A, _) => Ok(false),
            (EvidenceLevel::B, EvidenceLevel::A) | (EvidenceLevel::B, EvidenceLevel::B) => Ok(true),
            (EvidenceLevel::B, _) => Ok(false),
            (EvidenceLevel::Pending, _) => Ok(true),
        }
    }

    /// Create gate context for checking
    pub fn create_gate_context(&self, bundle: &EconomyEpochBundle) -> GateContext {
        GateContext {
            epoch_id: bundle.epoch_header.epoch_id.clone(),
            evidence_level: EvidenceLevel::B, // Default, would be set by actual evidence
            degraded_flags: vec![],
            known_versions: KnownVersionSet::default_v1(),
        }
    }
}

impl Default for GatesVerifier {
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
        P3Digest, RefDigest, WeightsVersionRef,
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
    fn test_gates_verifier_creation() {
        let verifier = GatesVerifier::new();
        assert_eq!(verifier.required_evidence_level, EvidenceLevel::A);
        assert!(verifier.check_degraded);
    }

    #[test]
    fn test_verify_valid_bundle() {
        let verifier = GatesVerifier::new();
        let bundle = create_test_bundle();

        let result = verifier.verify(&bundle).unwrap();
        assert!(result.is_valid);
        assert_eq!(result.gates_checked, result.gates_passed);
    }

    #[test]
    fn test_verify_evidence_level() {
        let verifier = GatesVerifier::new().with_evidence_level(EvidenceLevel::A);

        assert!(verifier.verify_evidence_level(EvidenceLevel::A).unwrap());
        assert!(!verifier.verify_evidence_level(EvidenceLevel::B).unwrap());
        assert!(!verifier.verify_evidence_level(EvidenceLevel::Pending).unwrap());
    }

    #[test]
    fn test_verify_evidence_level_b() {
        let verifier = GatesVerifier::new().with_evidence_level(EvidenceLevel::B);

        assert!(verifier.verify_evidence_level(EvidenceLevel::A).unwrap());
        assert!(verifier.verify_evidence_level(EvidenceLevel::B).unwrap());
        assert!(!verifier.verify_evidence_level(EvidenceLevel::Pending).unwrap());
    }
}
