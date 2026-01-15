//! Bundle Verification Module
//!
//! Chapter 2: Bundle verification for epoch sealing
//!
//! Provides verification for sealed epoch bundles, ensuring:
//! - Manifest digest integrity
//! - Four sets consistency
//! - Version chain validity
//! - Result root verification

use crate::canon::Canonicalizer;
use crate::error::P3Result;
use crate::gates::{GateChecker, GateContext};
use crate::merkle::MerkleTreeBuilder;
use crate::types::*;

/// Bundle verifier
pub struct BundleVerifier {
    /// Canonicalizer
    canon: Canonicalizer,
    /// Gate checker
    gates: GateChecker,
    /// Merkle tree builder
    merkle: MerkleTreeBuilder,
}

impl BundleVerifier {
    /// Create new verifier
    pub fn new() -> Self {
        Self {
            canon: Canonicalizer::v1(),
            gates: GateChecker::new(),
            merkle: MerkleTreeBuilder::for_result_root(),
        }
    }

    /// Verify a sealed epoch bundle
    pub fn verify_bundle(&self, bundle: &SealedBundle) -> P3Result<BundleVerificationResult> {
        let mut result = BundleVerificationResult::new();

        // 1. Verify manifest digest
        let computed_manifest = self.canon.canonicalize_manifest(&bundle.manifest_four_sets)?;
        if computed_manifest != bundle.manifest_digest {
            result.add_error(BundleError::ManifestDigestMismatch {
                expected: bundle.manifest_digest.clone(),
                computed: computed_manifest,
            });
        }

        // 2. Verify each set digest
        self.verify_set_digests(bundle, &mut result)?;

        // 3. Verify result root if present
        if let Some(ref result_root) = bundle.result_root {
            self.verify_result_root(result_root, &bundle.reward_entries, &mut result)?;
        }

        // 4. Verify version chain
        self.verify_version_chain(&bundle.version_info, &mut result)?;

        // 5. Check epoch is properly sealed
        if !bundle.is_sealed {
            result.add_error(BundleError::NotSealed);
        }

        Ok(result)
    }

    /// Verify set digests
    fn verify_set_digests(
        &self,
        bundle: &SealedBundle,
        result: &mut BundleVerificationResult,
    ) -> P3Result<()> {
        let sets = &bundle.manifest_four_sets;

        // Verify knowledge events set
        let computed_knowledge = self
            .canon
            .canonicalize_event_set(&bundle.knowledge_events)?;
        if computed_knowledge != sets.knowledge_events.set_digest {
            result.add_error(BundleError::SetDigestMismatch {
                set_name: "knowledge_events".to_string(),
                expected: sets.knowledge_events.set_digest.0.clone(),
                computed: computed_knowledge.0,
            });
        }

        // Verify court events set
        let computed_court = self.canon.canonicalize_event_set(&bundle.court_events)?;
        if computed_court != sets.court_events.set_digest {
            result.add_error(BundleError::SetDigestMismatch {
                set_name: "court_events".to_string(),
                expected: sets.court_events.set_digest.0.clone(),
                computed: computed_court.0,
            });
        }

        Ok(())
    }

    /// Verify result root matches reward entries
    fn verify_result_root(
        &self,
        expected_root: &P3Digest,
        entries: &[RewardDistributionEntry],
        result: &mut BundleVerificationResult,
    ) -> P3Result<()> {
        let computed = self.merkle.build_result_root(entries)?;

        if computed.root != *expected_root {
            result.add_error(BundleError::ResultRootMismatch {
                expected: expected_root.clone(),
                computed: computed.root,
            });
        }

        Ok(())
    }

    /// Verify version chain
    fn verify_version_chain(
        &self,
        version_info: &BundleVersionInfo,
        result: &mut BundleVerificationResult,
    ) -> P3Result<()> {
        // Version must be valid (not empty string)
        if version_info.version.0.is_empty() {
            result.add_error(BundleError::InvalidVersion);
        }

        // If there's a previous hash, the chain must be valid
        if let Some(ref prev_hash) = version_info.previous_bundle_hash {
            if prev_hash.is_zero() {
                result.add_error(BundleError::InvalidPreviousHash);
            }
        }

        Ok(())
    }

    /// Verify bundle can be used for strong action
    pub fn verify_for_strong_action(
        &self,
        bundle: &SealedBundle,
        action: &StrongEconomicAction,
        context: &GateContext,
        proof: Option<&ExecutionProofRef>,
        verdict_ref: Option<&P3Digest>,
    ) -> P3Result<BundleVerificationResult> {
        let mut result = self.verify_bundle(bundle)?;

        // Check gates for strong action
        let gate_result = self.gates.check_strong_action(context, action, proof, verdict_ref);
        if !gate_result.passed {
            result.add_error(BundleError::GateCheckFailed {
                reason: format!("{:?}", gate_result.error),
            });
        }

        Ok(result)
    }
}

impl Default for BundleVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Sealed epoch bundle
#[derive(Clone, Debug)]
pub struct SealedBundle {
    /// Epoch ID
    pub epoch_id: EpochId,
    /// Manifest four sets
    pub manifest_four_sets: ManifestFourSets,
    /// Computed manifest digest
    pub manifest_digest: P3Digest,
    /// Knowledge events in this epoch
    pub knowledge_events: Vec<EconomyEventRef>,
    /// Court events in this epoch
    pub court_events: Vec<EconomyEventRef>,
    /// Result root (if computed)
    pub result_root: Option<P3Digest>,
    /// Reward distribution entries
    pub reward_entries: Vec<RewardDistributionEntry>,
    /// Version info
    pub version_info: BundleVersionInfo,
    /// Is the bundle sealed?
    pub is_sealed: bool,
}

impl SealedBundle {
    /// Create new bundle builder
    pub fn builder(epoch_id: EpochId) -> SealedBundleBuilder {
        SealedBundleBuilder::new(epoch_id)
    }
}

/// Bundle version info
#[derive(Clone, Debug)]
pub struct BundleVersionInfo {
    /// Canonicalization version
    pub version: CanonVersion,
    /// Previous bundle hash (if not genesis)
    pub previous_bundle_hash: Option<P3Digest>,
    /// Bundle creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl Default for BundleVersionInfo {
    fn default() -> Self {
        Self {
            version: CanonVersion::v1(),
            previous_bundle_hash: None,
            created_at: chrono::Utc::now(),
        }
    }
}

/// Bundle builder
pub struct SealedBundleBuilder {
    epoch_id: EpochId,
    knowledge_events: Vec<EconomyEventRef>,
    court_events: Vec<EconomyEventRef>,
    reward_entries: Vec<RewardDistributionEntry>,
    version_info: BundleVersionInfo,
}

impl SealedBundleBuilder {
    /// Create new builder
    pub fn new(epoch_id: EpochId) -> Self {
        Self {
            epoch_id,
            knowledge_events: Vec::new(),
            court_events: Vec::new(),
            reward_entries: Vec::new(),
            version_info: BundleVersionInfo::default(),
        }
    }

    /// Add knowledge events
    pub fn with_knowledge_events(mut self, events: Vec<EconomyEventRef>) -> Self {
        self.knowledge_events = events;
        self
    }

    /// Add court events
    pub fn with_court_events(mut self, events: Vec<EconomyEventRef>) -> Self {
        self.court_events = events;
        self
    }

    /// Add reward entries
    pub fn with_reward_entries(mut self, entries: Vec<RewardDistributionEntry>) -> Self {
        self.reward_entries = entries;
        self
    }

    /// Set version info
    pub fn with_version_info(mut self, info: BundleVersionInfo) -> Self {
        self.version_info = info;
        self
    }

    /// Build and seal the bundle
    pub fn build(self) -> P3Result<SealedBundle> {
        let canon = Canonicalizer::v1();
        let merkle = MerkleTreeBuilder::for_result_root();

        // Compute set digests
        let knowledge_set_digest = canon.canonicalize_event_set(&self.knowledge_events)?;
        let court_set_digest = canon.canonicalize_event_set(&self.court_events)?;

        // Build manifest four sets
        let manifest_four_sets = ManifestFourSets {
            knowledge_events: EventSet {
                set_digest: knowledge_set_digest,
                refs_digest: RefDigest::empty(),
                object_ids_digest: RefDigest::empty(),
                receipt_refs_digest: RefDigest::empty(),
            },
            court_events: EventSet {
                set_digest: court_set_digest,
                refs_digest: RefDigest::empty(),
                object_ids_digest: RefDigest::empty(),
                receipt_refs_digest: RefDigest::empty(),
            },
            policy_state: EventSet::empty(),
            sampling_audit: EventSet::empty(),
        };

        // Compute manifest digest
        let manifest_digest = canon.canonicalize_manifest(&manifest_four_sets)?;

        // Compute result root
        let result_root = if !self.reward_entries.is_empty() {
            Some(merkle.build_result_root(&self.reward_entries)?.root)
        } else {
            None
        };

        Ok(SealedBundle {
            epoch_id: self.epoch_id,
            manifest_four_sets,
            manifest_digest,
            knowledge_events: self.knowledge_events,
            court_events: self.court_events,
            result_root,
            reward_entries: self.reward_entries,
            version_info: self.version_info,
            is_sealed: true,
        })
    }
}

/// Bundle verification result
#[derive(Clone, Debug)]
pub struct BundleVerificationResult {
    /// Is the bundle valid?
    pub is_valid: bool,
    /// List of errors found
    pub errors: Vec<BundleError>,
    /// Warnings (non-fatal issues)
    pub warnings: Vec<String>,
}

impl BundleVerificationResult {
    /// Create new result
    pub fn new() -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Add an error
    pub fn add_error(&mut self, error: BundleError) {
        self.is_valid = false;
        self.errors.push(error);
    }

    /// Add a warning
    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }

    /// Check if there are any errors
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }
}

impl Default for BundleVerificationResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Bundle verification error
#[derive(Clone, Debug)]
pub enum BundleError {
    /// Manifest digest mismatch
    ManifestDigestMismatch {
        expected: P3Digest,
        computed: P3Digest,
    },
    /// Set digest mismatch
    SetDigestMismatch {
        set_name: String,
        expected: P3Digest,
        computed: P3Digest,
    },
    /// Result root mismatch
    ResultRootMismatch {
        expected: P3Digest,
        computed: P3Digest,
    },
    /// Bundle not sealed
    NotSealed,
    /// Invalid version
    InvalidVersion,
    /// Invalid previous hash
    InvalidPreviousHash,
    /// Gate check failed
    GateCheckFailed { reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal::Decimal;

    fn create_test_event(id: &str) -> EconomyEventRef {
        EconomyEventRef {
            event_type: EventType::Mint,
            event_id: EventId::new(id),
            anchor_ref: AnchorRef::new(1, "receipt:1"),
            object_ids_digest: RefDigest::empty(),
            receipt_refs_digest: RefDigest::empty(),
            status_digest: None,
        }
    }

    fn create_test_entry(recipient: &str, amount: i64) -> RewardDistributionEntry {
        RewardDistributionEntry {
            entry_id: format!("entry:{}", recipient),
            recipient: ActorId::new(recipient),
            pool_id: PoolId::new("pool:reward"),
            amount: RewardPoints(Decimal::new(amount, 0)),
            attribution_ref: None,
            distribution_ref: "dist:1".to_string(),
        }
    }

    #[test]
    fn test_build_empty_bundle() {
        let bundle = SealedBundle::builder(EpochId::new("epoch:1"))
            .build()
            .unwrap();

        assert!(bundle.is_sealed);
        assert_eq!(bundle.knowledge_events.len(), 0);
        assert_eq!(bundle.court_events.len(), 0);
    }

    #[test]
    fn test_build_bundle_with_events() {
        let events = vec![create_test_event("event:1"), create_test_event("event:2")];

        let bundle = SealedBundle::builder(EpochId::new("epoch:1"))
            .with_knowledge_events(events)
            .build()
            .unwrap();

        assert_eq!(bundle.knowledge_events.len(), 2);
    }

    #[test]
    fn test_build_bundle_with_rewards() {
        let entries = vec![
            create_test_entry("alice", 100),
            create_test_entry("bob", 200),
        ];

        let bundle = SealedBundle::builder(EpochId::new("epoch:1"))
            .with_reward_entries(entries)
            .build()
            .unwrap();

        assert!(bundle.result_root.is_some());
        assert_eq!(bundle.reward_entries.len(), 2);
    }

    #[test]
    fn test_verify_valid_bundle() {
        let verifier = BundleVerifier::new();

        let bundle = SealedBundle::builder(EpochId::new("epoch:1"))
            .with_knowledge_events(vec![create_test_event("event:1")])
            .build()
            .unwrap();

        let result = verifier.verify_bundle(&bundle).unwrap();
        assert!(result.is_valid);
        assert!(!result.has_errors());
    }

    #[test]
    fn test_verify_tampered_bundle() {
        let verifier = BundleVerifier::new();

        let mut bundle = SealedBundle::builder(EpochId::new("epoch:1"))
            .with_knowledge_events(vec![create_test_event("event:1")])
            .build()
            .unwrap();

        // Tamper with the manifest digest
        bundle.manifest_digest = P3Digest::zero();

        let result = verifier.verify_bundle(&bundle).unwrap();
        assert!(!result.is_valid);
        assert!(result.has_errors());
    }

    #[test]
    fn test_verify_unsealed_bundle() {
        let verifier = BundleVerifier::new();

        let mut bundle = SealedBundle::builder(EpochId::new("epoch:1"))
            .build()
            .unwrap();

        bundle.is_sealed = false;

        let result = verifier.verify_bundle(&bundle).unwrap();
        assert!(!result.is_valid);
    }
}
