//! P3 Verifier SDK
//!
//! Third-party verifiable settlement verification library.
//!
//! This crate provides independent verification capabilities for P3 Economy Layer,
//! allowing any party to verify:
//! - Epoch bundle integrity
//! - Manifest four-set consistency
//! - Result root computation
//! - Gate check compliance
//! - Execution proof validity
//! - Idempotency guarantees
//! - Fee split correctness

pub mod verify_bundle;
pub mod verify_manifest;
pub mod verify_root;
pub mod verify_gates;
pub mod verify_proof;
pub mod verify_idempotency;
pub mod verify_fee_split;

mod error;

pub use error::{VerifierError, VerifierResult};

// Re-export verification modules
pub use verify_bundle::{BundleVerifier, BundleVerificationResult};
pub use verify_manifest::{ManifestVerifier, ManifestVerificationResult};
pub use verify_root::{RootVerifier, RootVerificationResult};
pub use verify_gates::{GatesVerifier, GatesVerificationResult};
pub use verify_proof::{ProofVerifier, ProofVerificationResult};
pub use verify_idempotency::{IdempotencyVerifier, IdempotencyVerificationResult};
pub use verify_fee_split::{FeeSplitVerifier, FeeSplitVerificationResult};

use p3_core::{ConformanceLevel, EconomyEpochBundle, P3Digest};

/// Unified verifier interface
pub struct Verifier {
    /// Verification level
    level: ConformanceLevel,
    /// Bundle verifier
    bundle_verifier: BundleVerifier,
    /// Manifest verifier
    manifest_verifier: ManifestVerifier,
    /// Root verifier
    root_verifier: RootVerifier,
    /// Gates verifier
    gates_verifier: GatesVerifier,
    /// Proof verifier
    proof_verifier: ProofVerifier,
    /// Idempotency verifier
    idempotency_verifier: IdempotencyVerifier,
    /// Fee split verifier
    fee_split_verifier: FeeSplitVerifier,
}

impl Verifier {
    /// Create new verifier with specified level
    pub fn new(level: ConformanceLevel) -> Self {
        Self {
            level,
            bundle_verifier: BundleVerifier::new(),
            manifest_verifier: ManifestVerifier::new(),
            root_verifier: RootVerifier::new(),
            gates_verifier: GatesVerifier::new(),
            proof_verifier: ProofVerifier::new(),
            idempotency_verifier: IdempotencyVerifier::new(),
            fee_split_verifier: FeeSplitVerifier::new(),
        }
    }

    /// Create L1 verifier (read-only)
    pub fn l1() -> Self {
        Self::new(ConformanceLevel::L1)
    }

    /// Create L2 verifier (weak execution)
    pub fn l2() -> Self {
        Self::new(ConformanceLevel::L2)
    }

    /// Create L3 verifier (full verification)
    pub fn l3() -> Self {
        Self::new(ConformanceLevel::L3)
    }

    /// Get verification level
    pub fn level(&self) -> &ConformanceLevel {
        &self.level
    }

    /// Verify epoch bundle (comprehensive verification based on level)
    pub fn verify_bundle(&self, bundle: &EconomyEpochBundle) -> VerifierResult<FullVerificationResult> {
        let mut result = FullVerificationResult::new(self.level.clone());

        // L1: Basic verification (always performed)
        result.bundle_result = Some(self.bundle_verifier.verify(bundle)?);
        result.manifest_result = Some(self.manifest_verifier.verify(
            &bundle.epoch_header,
            &bundle.manifest_sets,
        )?);
        result.root_result = Some(self.root_verifier.verify(bundle)?);

        // L2: Execution verification
        if self.level >= ConformanceLevel::L2 {
            result.idempotency_result = Some(self.idempotency_verifier.verify(bundle)?);
        }

        // L3: Full verification
        if self.level >= ConformanceLevel::L3 {
            result.gates_result = Some(self.gates_verifier.verify(bundle)?);
            result.proof_result = Some(self.proof_verifier.verify(bundle)?);
            result.fee_split_result = Some(self.fee_split_verifier.verify(bundle)?);
        }

        // Compute overall result
        result.compute_overall();

        Ok(result)
    }

    /// Quick verify - returns true/false without details
    pub fn quick_verify(&self, bundle: &EconomyEpochBundle) -> bool {
        self.verify_bundle(bundle)
            .map(|r| r.is_valid)
            .unwrap_or(false)
    }

    /// Verify and return digest of verification result
    pub fn verify_with_digest(&self, bundle: &EconomyEpochBundle) -> VerifierResult<(FullVerificationResult, P3Digest)> {
        let result = self.verify_bundle(bundle)?;
        let digest = result.compute_digest();
        Ok((result, digest))
    }
}

impl Default for Verifier {
    fn default() -> Self {
        Self::l1()
    }
}

/// Full verification result
#[derive(Clone, Debug)]
pub struct FullVerificationResult {
    /// Verification level used
    pub level: ConformanceLevel,
    /// Overall validity
    pub is_valid: bool,
    /// Bundle verification result
    pub bundle_result: Option<BundleVerificationResult>,
    /// Manifest verification result
    pub manifest_result: Option<ManifestVerificationResult>,
    /// Root verification result
    pub root_result: Option<RootVerificationResult>,
    /// Gates verification result (L3 only)
    pub gates_result: Option<GatesVerificationResult>,
    /// Proof verification result (L3 only)
    pub proof_result: Option<ProofVerificationResult>,
    /// Idempotency verification result (L2+)
    pub idempotency_result: Option<IdempotencyVerificationResult>,
    /// Fee split verification result (L3 only)
    pub fee_split_result: Option<FeeSplitVerificationResult>,
    /// Error messages
    pub errors: Vec<String>,
}

impl FullVerificationResult {
    /// Create new result
    pub fn new(level: ConformanceLevel) -> Self {
        Self {
            level,
            is_valid: false,
            bundle_result: None,
            manifest_result: None,
            root_result: None,
            gates_result: None,
            proof_result: None,
            idempotency_result: None,
            fee_split_result: None,
            errors: Vec::new(),
        }
    }

    /// Compute overall validity
    pub fn compute_overall(&mut self) {
        self.errors.clear();

        // Check L1 results
        if let Some(ref r) = self.bundle_result {
            if !r.is_valid {
                self.errors.push(format!("Bundle verification failed: {:?}", r.errors));
            }
        }
        if let Some(ref r) = self.manifest_result {
            if !r.is_valid {
                self.errors.push(format!("Manifest verification failed: {:?}", r.errors));
            }
        }
        if let Some(ref r) = self.root_result {
            if !r.is_valid {
                self.errors.push(format!("Root verification failed: {:?}", r.errors));
            }
        }

        // Check L2 results
        if let Some(ref r) = self.idempotency_result {
            if !r.is_valid {
                self.errors.push(format!("Idempotency verification failed: {:?}", r.errors));
            }
        }

        // Check L3 results
        if let Some(ref r) = self.gates_result {
            if !r.is_valid {
                self.errors.push(format!("Gates verification failed: {:?}", r.errors));
            }
        }
        if let Some(ref r) = self.proof_result {
            if !r.is_valid {
                self.errors.push(format!("Proof verification failed: {:?}", r.errors));
            }
        }
        if let Some(ref r) = self.fee_split_result {
            if !r.is_valid {
                self.errors.push(format!("Fee split verification failed: {:?}", r.errors));
            }
        }

        self.is_valid = self.errors.is_empty();
    }

    /// Compute verification result digest
    pub fn compute_digest(&self) -> P3Digest {
        let data = format!(
            "verify:{}:{}:{}",
            self.level.name(),
            self.is_valid,
            self.errors.len()
        );
        P3Digest::blake3(data.as_bytes())
    }

    /// Get summary string
    pub fn summary(&self) -> String {
        if self.is_valid {
            format!("Verification PASSED at level {}", self.level.name())
        } else {
            format!(
                "Verification FAILED at level {} with {} errors",
                self.level.name(),
                self.errors.len()
            )
        }
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
    fn test_verifier_creation() {
        let v1 = Verifier::l1();
        assert_eq!(*v1.level(), ConformanceLevel::L1);

        let v2 = Verifier::l2();
        assert_eq!(*v2.level(), ConformanceLevel::L2);

        let v3 = Verifier::l3();
        assert_eq!(*v3.level(), ConformanceLevel::L3);
    }

    #[test]
    fn test_verification_result() {
        let mut result = FullVerificationResult::new(ConformanceLevel::L1);
        result.bundle_result = Some(BundleVerificationResult::valid());
        result.manifest_result = Some(ManifestVerificationResult::valid());
        result.root_result = Some(RootVerificationResult::valid(P3Digest::zero()));

        result.compute_overall();
        assert!(result.is_valid);
    }

    #[test]
    fn test_verify_bundle_l1() {
        let verifier = Verifier::l1();
        let bundle = create_test_bundle();

        let result = verifier.verify_bundle(&bundle).unwrap();
        assert!(result.is_valid);
        assert!(result.bundle_result.is_some());
        assert!(result.manifest_result.is_some());
        assert!(result.root_result.is_some());
        // L1 doesn't include L2+ verifications
        assert!(result.idempotency_result.is_none());
        assert!(result.gates_result.is_none());
    }

    #[test]
    fn test_verify_bundle_l3() {
        let verifier = Verifier::l3();
        let bundle = create_test_bundle();

        let result = verifier.verify_bundle(&bundle).unwrap();
        assert!(result.is_valid);
        // L3 includes all verifications
        assert!(result.bundle_result.is_some());
        assert!(result.manifest_result.is_some());
        assert!(result.root_result.is_some());
        assert!(result.idempotency_result.is_some());
        assert!(result.gates_result.is_some());
        assert!(result.proof_result.is_some());
        assert!(result.fee_split_result.is_some());
    }

    #[test]
    fn test_quick_verify() {
        let verifier = Verifier::l1();
        let bundle = create_test_bundle();

        assert!(verifier.quick_verify(&bundle));
    }
}
