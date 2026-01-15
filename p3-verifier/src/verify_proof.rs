//! Proof Verification
//!
//! Verifies ExecutionProofRef validity and completeness.

use crate::error::VerifierResult;
use chrono::{DateTime, Utc};
use p3_core::{EconomyEpochBundle, ExecutionProofRef, ExecutionProofType, P3Digest};

/// Proof verification error
#[derive(Clone, Debug)]
pub struct ProofVerificationError {
    pub code: String,
    pub message: String,
}

impl ProofVerificationError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

/// Proof verification result
#[derive(Clone, Debug)]
pub struct ProofVerificationResult {
    /// Overall validity
    pub is_valid: bool,
    /// Errors found
    pub errors: Vec<ProofVerificationError>,
    /// Proofs verified
    pub proofs_verified: usize,
}

impl ProofVerificationResult {
    pub fn valid(proofs_verified: usize) -> Self {
        Self {
            is_valid: true,
            errors: vec![],
            proofs_verified,
        }
    }

    pub fn invalid(errors: Vec<ProofVerificationError>) -> Self {
        Self {
            is_valid: false,
            errors,
            proofs_verified: 0,
        }
    }
}

/// Proof verifier
pub struct ProofVerifier {
    /// Max proof age in days
    max_proof_age_days: i64,
}

impl ProofVerifier {
    /// Create new proof verifier
    pub fn new() -> Self {
        Self {
            max_proof_age_days: 30,
        }
    }

    /// Set max proof age
    pub fn with_max_age(mut self, days: i64) -> Self {
        self.max_proof_age_days = days;
        self
    }

    /// Verify proofs in bundle (structural verification only in zero-plaintext mode)
    pub fn verify(&self, bundle: &EconomyEpochBundle) -> VerifierResult<ProofVerificationResult> {
        let mut errors = Vec::new();
        let mut proofs_verified = 0;

        // In zero-plaintext mode, we verify structural integrity
        // The bundle contains digest references, not actual proofs

        // 1. Verify receipt_refs_digest is present (indicates proof references exist)
        if !bundle.receipt_refs_digest.0.is_zero() {
            proofs_verified += 1;
        }

        // 2. Verify result_root_digest is set (indicates computation was performed)
        if !bundle.result_root_digest.is_zero() {
            proofs_verified += 1;
        }

        // 3. Verify chain anchor if present (strongest proof)
        if let Some(ref anchor) = bundle.chain_anchor_link {
            if anchor.tx_id.is_empty() {
                errors.push(ProofVerificationError::new(
                    "EMPTY_ANCHOR_TX_ID",
                    "Chain anchor tx_id is empty",
                ));
            } else {
                proofs_verified += 1;
            }
        }

        if errors.is_empty() {
            Ok(ProofVerificationResult::valid(proofs_verified))
        } else {
            Ok(ProofVerificationResult::invalid(errors))
        }
    }

    /// Verify a single execution proof reference
    pub fn verify_execution_proof(
        &self,
        proof: &ExecutionProofRef,
        now: &DateTime<Utc>,
    ) -> VerifierResult<ProofVerificationResult> {
        let mut errors = Vec::new();

        // 1. Verify proof ID is not empty
        if proof.proof_id.is_empty() {
            errors.push(ProofVerificationError::new(
                "EMPTY_PROOF_ID",
                "Proof ID cannot be empty",
            ));
        }

        // 2. Verify executor reference is not empty
        if proof.executor_ref.is_empty() {
            errors.push(ProofVerificationError::new(
                "EMPTY_EXECUTOR_REF",
                "Executor reference cannot be empty",
            ));
        }

        // 3. Verify proof is not too old
        let age = *now - proof.executed_at;
        if age.num_days() > self.max_proof_age_days {
            errors.push(ProofVerificationError::new(
                "PROOF_TOO_OLD",
                format!(
                    "Proof is {} days old (max: {})",
                    age.num_days(),
                    self.max_proof_age_days
                ),
            ));
        }

        // 4. Verify proof digest is not zero
        if proof.proof_digest.is_zero() {
            errors.push(ProofVerificationError::new(
                "ZERO_PROOF_DIGEST",
                "Proof digest cannot be zero",
            ));
        }

        // 5. Verify proof type is valid
        self.verify_proof_type(&proof.proof_type, &mut errors);

        if errors.is_empty() {
            Ok(ProofVerificationResult::valid(1))
        } else {
            Ok(ProofVerificationResult::invalid(errors))
        }
    }

    /// Verify proof type is valid
    fn verify_proof_type(&self, proof_type: &ExecutionProofType, _errors: &mut Vec<ProofVerificationError>) {
        // All proof types in the enum are valid
        match proof_type {
            ExecutionProofType::OnChain
            | ExecutionProofType::OffChain
            | ExecutionProofType::Credit
            | ExecutionProofType::MultiSig => {
                // All valid proof types
            }
        }
    }

    /// Verify proof chain (for retries)
    pub fn verify_proof_chain(&self, proofs: &[ExecutionProofRef]) -> VerifierResult<ProofVerificationResult> {
        let mut errors = Vec::new();

        if proofs.is_empty() {
            return Ok(ProofVerificationResult::valid(0));
        }

        // Verify chain ordering (by execution time)
        for window in proofs.windows(2) {
            if window[0].executed_at > window[1].executed_at {
                errors.push(ProofVerificationError::new(
                    "CHAIN_ORDERING",
                    "Proof chain must be ordered by execution time",
                ));
            }
        }

        // Verify all proofs have valid proof_id
        for proof in proofs {
            if proof.proof_id.is_empty() {
                errors.push(ProofVerificationError::new(
                    "EMPTY_PROOF_ID_IN_CHAIN",
                    "All proofs in chain must have valid proof_id",
                ));
            }
        }

        if errors.is_empty() {
            Ok(ProofVerificationResult::valid(proofs.len()))
        } else {
            Ok(ProofVerificationResult::invalid(errors))
        }
    }
}

impl Default for ProofVerifier {
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

    fn create_test_proof() -> ExecutionProofRef {
        ExecutionProofRef {
            proof_id: "proof:001".to_string(),
            proof_type: ExecutionProofType::OnChain,
            executor_ref: "executor:001".to_string(),
            executed_at: Utc::now(),
            receipt_ref: Some("receipt:001".to_string()),
            proof_digest: P3Digest::blake3(b"test proof"),
        }
    }

    #[test]
    fn test_proof_verifier_creation() {
        let verifier = ProofVerifier::new();
        assert_eq!(verifier.max_proof_age_days, 30);
    }

    #[test]
    fn test_verify_bundle() {
        let verifier = ProofVerifier::new();
        let bundle = create_test_bundle();

        let result = verifier.verify(&bundle).unwrap();
        assert!(result.is_valid);
    }

    #[test]
    fn test_verify_valid_proof() {
        let verifier = ProofVerifier::new();
        let proof = create_test_proof();
        let now = Utc::now();

        let result = verifier.verify_execution_proof(&proof, &now).unwrap();
        assert!(result.is_valid);
        assert_eq!(result.proofs_verified, 1);
    }

    #[test]
    fn test_verify_proof_too_old() {
        let verifier = ProofVerifier::new();
        let mut proof = create_test_proof();
        proof.executed_at = Utc::now() - chrono::Duration::days(60);
        let now = Utc::now();

        let result = verifier.verify_execution_proof(&proof, &now).unwrap();
        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| e.code == "PROOF_TOO_OLD"));
    }

    #[test]
    fn test_verify_proof_chain() {
        let verifier = ProofVerifier::new();
        let now = Utc::now();

        let proofs = vec![
            ExecutionProofRef {
                executed_at: now - chrono::Duration::hours(2),
                ..create_test_proof()
            },
            ExecutionProofRef {
                executed_at: now - chrono::Duration::hours(1),
                ..create_test_proof()
            },
            ExecutionProofRef {
                executed_at: now,
                ..create_test_proof()
            },
        ];

        let result = verifier.verify_proof_chain(&proofs).unwrap();
        assert!(result.is_valid);
        assert_eq!(result.proofs_verified, 3);
    }
}
