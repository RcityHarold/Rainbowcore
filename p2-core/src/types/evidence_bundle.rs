//! Evidence Bundle Types
//!
//! Evidence payload bundles for judicial discovery.
//! These are the encrypted evidence packages used in dispute resolution.
//!
//! # Hard Invariant
//!
//! **Missing payload_map_commit MUST result in B-level evidence.**
//!
//! Evidence level determination requires VERIFICATION, not just existence checks:
//! - A-level = receipt-backed + payload_map_commit RECONCILED (verified)
//! - B-level = missing receipt OR map_commit OR verification failed

use super::sealed_payload::SealedPayloadRef;
use chrono::{DateTime, Utc};
use l0_core::types::{ActorId, Digest, EvidenceLevel, ReceiptId};
use serde::{Deserialize, Serialize};

/// Evidence Bundle - Encrypted evidence package
///
/// A collection of encrypted payloads submitted as evidence for a case.
/// The bundle contains references to sealed payloads, not the actual data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundle {
    /// Bundle ID
    pub bundle_id: String,

    /// Bundle digest (external reference)
    pub bundle_digest: Digest,

    /// Associated case reference
    pub case_ref: String,

    /// Evidence submitter
    pub submitter: ActorId,

    /// Sealed payload references
    pub payload_refs: Vec<SealedPayloadRef>,

    /// Payload refs digest
    pub payload_refs_digest: Digest,

    /// Evidence type tags
    pub evidence_types: Vec<EvidenceType>,

    /// Access policy version
    pub access_policy_version: String,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Associated P1 receipt (if on-chain)
    pub receipt_id: Option<ReceiptId>,

    /// payload_map_commit reference (if committed)
    pub map_commit_ref: Option<String>,

    /// Bundle status
    pub status: EvidenceBundleStatus,

    /// Submitter notes digest (privacy protected)
    pub notes_digest: Option<Digest>,

    /// Verification state for evidence level determination
    /// MUST be set by verifier before evidence_level() returns A
    #[serde(default)]
    pub verification_state: EvidenceVerificationState,
}

/// Evidence verification state
///
/// This tracks the actual verification results, not just existence.
/// Evidence level determination MUST check these fields.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvidenceVerificationState {
    /// Receipt has been verified against L0
    pub receipt_verified: bool,

    /// Receipt verification timestamp
    pub receipt_verified_at: Option<DateTime<Utc>>,

    /// Receipt verification error (if failed)
    pub receipt_verification_error: Option<String>,

    /// Map commit has been reconciled with P2 payloads
    pub map_commit_reconciled: bool,

    /// Map commit reconciliation timestamp
    pub map_commit_reconciled_at: Option<DateTime<Utc>>,

    /// Map commit reconciliation error (if failed)
    pub map_commit_reconciliation_error: Option<String>,

    /// Digest match confirmed between P1 commit and P2 payloads
    pub digest_verified: bool,

    /// All payloads are accessible in P2
    pub payloads_accessible: bool,

    /// Number of inaccessible payloads (if any)
    pub inaccessible_payload_count: u32,

    /// Last verification timestamp
    pub last_verified_at: Option<DateTime<Utc>>,
}

impl EvidenceBundle {
    /// Create a new evidence bundle
    pub fn new(
        bundle_id: String,
        case_ref: String,
        submitter: ActorId,
        payload_refs: Vec<SealedPayloadRef>,
    ) -> Self {
        let payload_refs_digest = Self::compute_refs_digest(&payload_refs);
        let bundle_digest = Self::compute_bundle_digest(&bundle_id, &case_ref, &payload_refs_digest);

        Self {
            bundle_id,
            bundle_digest,
            case_ref,
            submitter,
            payload_refs,
            payload_refs_digest,
            evidence_types: Vec::new(),
            access_policy_version: "v1".to_string(),
            created_at: Utc::now(),
            receipt_id: None,
            map_commit_ref: None,
            status: EvidenceBundleStatus::Pending,
            notes_digest: None,
            verification_state: EvidenceVerificationState::default(),
        }
    }

    /// Compute payload refs digest
    pub fn compute_refs_digest(refs: &[SealedPayloadRef]) -> Digest {
        let mut data = Vec::new();
        for r in refs {
            data.extend_from_slice(r.checksum.as_bytes());
        }
        Digest::blake3(&data)
    }

    /// Compute bundle digest
    fn compute_bundle_digest(bundle_id: &str, case_ref: &str, refs_digest: &Digest) -> Digest {
        let mut data = Vec::new();
        data.extend_from_slice(bundle_id.as_bytes());
        data.extend_from_slice(b"\0");
        data.extend_from_slice(case_ref.as_bytes());
        data.extend_from_slice(b"\0");
        data.extend_from_slice(refs_digest.as_bytes());
        Digest::blake3(&data)
    }

    /// Verify P1 mapping commitment
    pub fn verify_map_commit(&self, expected_digest: &Digest) -> bool {
        &self.payload_refs_digest == expected_digest
    }

    /// Determine evidence level
    ///
    /// # Hard Invariant
    ///
    /// **A-level requires ALL of the following to be VERIFIED (not just present):**
    /// 1. receipt_id exists AND receipt_verified = true
    /// 2. map_commit_ref exists AND map_commit_reconciled = true
    /// 3. digest_verified = true (P1 commit matches P2 payloads)
    /// 4. payloads_accessible = true
    ///
    /// **Missing ANY of the above results in B-level evidence.**
    pub fn evidence_level(&self) -> EvidenceLevel {
        // Hard invariant: missing map_commit = B-level
        if self.map_commit_ref.is_none() {
            return EvidenceLevel::B;
        }

        // Hard invariant: missing receipt = B-level
        if self.receipt_id.is_none() {
            return EvidenceLevel::B;
        }

        // Verification checks - MUST all pass for A-level
        let vs = &self.verification_state;

        if !vs.receipt_verified {
            return EvidenceLevel::B;
        }

        if !vs.map_commit_reconciled {
            return EvidenceLevel::B;
        }

        if !vs.digest_verified {
            return EvidenceLevel::B;
        }

        if !vs.payloads_accessible {
            return EvidenceLevel::B;
        }

        EvidenceLevel::A
    }

    /// Determine evidence level with detailed breakdown
    ///
    /// Returns the evidence level along with reasons for downgrade if B-level.
    pub fn evidence_level_detailed(&self) -> EvidenceLevelDetails {
        let mut reasons = Vec::new();

        if self.map_commit_ref.is_none() {
            reasons.push(EvidenceLevelDowngradeReason::MissingMapCommit);
        }

        if self.receipt_id.is_none() {
            reasons.push(EvidenceLevelDowngradeReason::MissingReceipt);
        }

        let vs = &self.verification_state;

        if !vs.receipt_verified {
            reasons.push(EvidenceLevelDowngradeReason::ReceiptNotVerified {
                error: vs.receipt_verification_error.clone(),
            });
        }

        if !vs.map_commit_reconciled {
            reasons.push(EvidenceLevelDowngradeReason::MapCommitNotReconciled {
                error: vs.map_commit_reconciliation_error.clone(),
            });
        }

        if !vs.digest_verified {
            reasons.push(EvidenceLevelDowngradeReason::DigestMismatch);
        }

        if !vs.payloads_accessible {
            reasons.push(EvidenceLevelDowngradeReason::PayloadsInaccessible {
                count: vs.inaccessible_payload_count,
            });
        }

        let level = if reasons.is_empty() {
            EvidenceLevel::A
        } else {
            EvidenceLevel::B
        };

        EvidenceLevelDetails {
            level,
            downgrade_reasons: reasons,
            last_verified_at: vs.last_verified_at,
        }
    }

    /// Update verification state after receipt verification
    pub fn set_receipt_verified(&mut self, verified: bool, error: Option<String>) {
        self.verification_state.receipt_verified = verified;
        self.verification_state.receipt_verified_at = Some(Utc::now());
        self.verification_state.receipt_verification_error = error;
        self.verification_state.last_verified_at = Some(Utc::now());
    }

    /// Update verification state after map commit reconciliation
    pub fn set_map_commit_reconciled(&mut self, reconciled: bool, error: Option<String>) {
        self.verification_state.map_commit_reconciled = reconciled;
        self.verification_state.map_commit_reconciled_at = Some(Utc::now());
        self.verification_state.map_commit_reconciliation_error = error;
        self.verification_state.last_verified_at = Some(Utc::now());
    }

    /// Update verification state for digest and payload accessibility
    pub fn set_payload_verification(&mut self, digest_verified: bool, payloads_accessible: bool, inaccessible_count: u32) {
        self.verification_state.digest_verified = digest_verified;
        self.verification_state.payloads_accessible = payloads_accessible;
        self.verification_state.inaccessible_payload_count = inaccessible_count;
        self.verification_state.last_verified_at = Some(Utc::now());
    }

    /// Check if bundle is complete (has all requirements for level A)
    ///
    /// Note: This checks both existence AND verification state.
    pub fn is_complete(&self) -> bool {
        self.evidence_level() == EvidenceLevel::A
    }

    /// Check if bundle has all required references (but may not be verified)
    pub fn has_required_refs(&self) -> bool {
        self.receipt_id.is_some() && self.map_commit_ref.is_some()
    }

    /// Check if verification is needed
    pub fn needs_verification(&self) -> bool {
        self.has_required_refs() && !self.is_complete()
    }

    /// Get total payload size
    pub fn total_size_bytes(&self) -> u64 {
        self.payload_refs.iter().map(|r| r.size_bytes).sum()
    }

    /// Get payload count
    pub fn payload_count(&self) -> usize {
        self.payload_refs.len()
    }

    /// Get evidence availability status considering storage temperature
    pub fn availability(&self) -> EvidenceAvailability {
        EvidenceAvailability::from_bundle(self)
    }

    /// Get temperature impact summary
    pub fn temperature_impact(&self) -> TemperatureImpact {
        TemperatureImpact::from_refs(&self.payload_refs)
    }

    /// Check if evidence is immediately usable (no preheat required)
    pub fn is_immediately_usable(&self) -> bool {
        self.availability().is_immediately_usable()
    }
}

/// Evidence level determination details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceLevelDetails {
    /// Determined evidence level
    pub level: EvidenceLevel,
    /// Reasons for downgrade (empty if A-level)
    pub downgrade_reasons: Vec<EvidenceLevelDowngradeReason>,
    /// Last verification timestamp
    pub last_verified_at: Option<DateTime<Utc>>,
}

/// Reason for evidence level downgrade to B
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvidenceLevelDowngradeReason {
    /// Missing payload_map_commit (HARD INVARIANT)
    MissingMapCommit,
    /// Missing receipt
    MissingReceipt,
    /// Receipt not verified or verification failed
    ReceiptNotVerified { error: Option<String> },
    /// Map commit not reconciled with P2 payloads
    MapCommitNotReconciled { error: Option<String> },
    /// Digest mismatch between P1 and P2
    DigestMismatch,
    /// Some payloads are inaccessible
    PayloadsInaccessible { count: u32 },
    /// Some payloads require preheating (cold storage)
    PayloadsRequirePreheat { count: u32 },
    /// Temperature degradation affects availability
    TemperatureDegraded { cold_count: u32, warm_count: u32 },
}

// ============================================================================
// Storage Temperature and Evidence Level Linkage
// ============================================================================

/// Storage temperature impact on evidence availability
///
/// Per DSN documentation, storage temperature affects evidence availability:
/// - Hot: Immediately available, no impact on evidence level
/// - Warm: Minor latency, acceptable for evidence
/// - Cold: Requires preheat, MAY impact evidence availability for time-sensitive cases
///
/// **RULE**: Cold storage payloads MAY trigger a warning but don't automatically
/// downgrade to B-level. However, if preheat fails or times out, payloads become
/// inaccessible and WILL downgrade to B-level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemperatureImpact {
    /// Hot payload count
    pub hot_count: u32,
    /// Warm payload count
    pub warm_count: u32,
    /// Cold payload count (may need preheat)
    pub cold_count: u32,
    /// Payloads currently being preheated
    pub preheating_count: u32,
    /// Preheat failures
    pub preheat_failures: u32,
    /// Estimated preheat time (seconds) for cold payloads
    pub estimated_preheat_seconds: Option<u32>,
    /// Whether all payloads are immediately accessible
    pub all_immediately_accessible: bool,
}

impl Default for TemperatureImpact {
    fn default() -> Self {
        Self {
            hot_count: 0,
            warm_count: 0,
            cold_count: 0,
            preheating_count: 0,
            preheat_failures: 0,
            estimated_preheat_seconds: None,
            all_immediately_accessible: true,
        }
    }
}

impl TemperatureImpact {
    /// Calculate from sealed payload refs
    pub fn from_refs(refs: &[SealedPayloadRef]) -> Self {
        use super::sealed_payload::StorageTemperature;

        let mut impact = Self::default();

        for r in refs {
            match r.temperature {
                StorageTemperature::Hot => impact.hot_count += 1,
                StorageTemperature::Warm => impact.warm_count += 1,
                StorageTemperature::Cold => {
                    impact.cold_count += 1;
                    impact.all_immediately_accessible = false;
                }
            }
        }

        // Estimate preheat time: ~5 seconds per cold payload (simplified)
        if impact.cold_count > 0 {
            impact.estimated_preheat_seconds = Some(impact.cold_count * 5);
        }

        impact
    }

    /// Check if any payloads need preheating
    pub fn needs_preheat(&self) -> bool {
        self.cold_count > 0
    }

    /// Check if preheat is in progress
    pub fn is_preheating(&self) -> bool {
        self.preheating_count > 0
    }

    /// Check if there are preheat failures
    pub fn has_preheat_failures(&self) -> bool {
        self.preheat_failures > 0
    }

    /// Get summary message
    pub fn summary(&self) -> String {
        if self.all_immediately_accessible {
            format!("All {} payloads immediately accessible (hot/warm)",
                    self.hot_count + self.warm_count)
        } else {
            format!("{} hot, {} warm, {} cold (preheat required)",
                    self.hot_count, self.warm_count, self.cold_count)
        }
    }
}

/// Evidence availability status considering temperature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceAvailability {
    /// Overall availability status
    pub status: AvailabilityStatus,
    /// Temperature impact details
    pub temperature_impact: TemperatureImpact,
    /// Time until fully available (if preheating needed)
    pub time_until_available_seconds: Option<u32>,
    /// Availability degradation reason (if not fully available)
    pub degradation_reason: Option<String>,
}

/// Availability status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityStatus {
    /// Immediately available
    ImmediatelyAvailable,
    /// Available after preheat
    AvailableAfterPreheat,
    /// Preheating in progress
    PreheatingInProgress,
    /// Partially available (some payloads inaccessible)
    PartiallyAvailable,
    /// Unavailable (storage failure or timeout)
    Unavailable,
}

impl EvidenceAvailability {
    /// Calculate availability from evidence bundle
    pub fn from_bundle(bundle: &EvidenceBundle) -> Self {
        let temperature_impact = TemperatureImpact::from_refs(&bundle.payload_refs);

        let status = if !bundle.verification_state.payloads_accessible {
            AvailabilityStatus::Unavailable
        } else if temperature_impact.is_preheating() {
            AvailabilityStatus::PreheatingInProgress
        } else if temperature_impact.needs_preheat() {
            AvailabilityStatus::AvailableAfterPreheat
        } else {
            AvailabilityStatus::ImmediatelyAvailable
        };

        let degradation_reason = match status {
            AvailabilityStatus::AvailableAfterPreheat => {
                Some(format!("{} cold payloads need preheating", temperature_impact.cold_count))
            }
            AvailabilityStatus::PreheatingInProgress => {
                Some(format!("{} payloads currently preheating", temperature_impact.preheating_count))
            }
            AvailabilityStatus::Unavailable => {
                Some(format!("{} payloads inaccessible",
                            bundle.verification_state.inaccessible_payload_count))
            }
            _ => None,
        };

        let preheat_seconds = temperature_impact.estimated_preheat_seconds;
        Self {
            status,
            temperature_impact,
            time_until_available_seconds: preheat_seconds,
            degradation_reason,
        }
    }

    /// Check if evidence is immediately usable for time-sensitive cases
    pub fn is_immediately_usable(&self) -> bool {
        matches!(self.status, AvailabilityStatus::ImmediatelyAvailable)
    }

    /// Check if evidence will be available (even if preheat needed)
    pub fn will_be_available(&self) -> bool {
        !matches!(self.status, AvailabilityStatus::Unavailable)
    }
}

/// Evidence type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceType {
    /// Conversation records
    Conversation,
    /// Transaction records
    Transaction,
    /// Behavior logs
    BehaviorLog,
    /// State snapshots
    StateSnapshot,
    /// Third-party attestation
    ThirdPartyAttestation,
    /// System logs
    SystemLog,
    /// User-generated content
    UserContent,
    /// Contract/Agreement
    Contract,
    /// Other
    Other,
}

// EvidenceLevel is now imported from l0_core::types
// See l0-core/src/types/common.rs for the canonical definition
//
// Hard rule: Missing payload_map_commit MUST be level B

/// Evidence bundle status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceBundleStatus {
    /// Pending submission
    Pending,
    /// Submitted to P2
    Submitted,
    /// Committed to P1 (has receipt)
    Committed,
    /// Verified and complete
    Verified,
    /// Disputed
    Disputed,
    /// Invalidated
    Invalidated,
}

impl Default for EvidenceBundleStatus {
    fn default() -> Self {
        Self::Pending
    }
}

/// Evidence submission request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceSubmission {
    /// Case reference
    pub case_ref: String,
    /// Submitter
    pub submitter: ActorId,
    /// Payload data (to be encrypted and stored)
    pub payloads: Vec<PayloadSubmission>,
    /// Evidence types
    pub evidence_types: Vec<EvidenceType>,
    /// Notes (will be hashed, not stored in plain)
    pub notes: Option<String>,
}

/// Single payload in a submission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadSubmission {
    /// Content type
    pub content_type: String,
    /// Raw data (will be encrypted)
    pub data: Vec<u8>,
    /// Metadata
    pub metadata: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_level_requires_verification() {
        let mut bundle = EvidenceBundle::new(
            "bundle:001".to_string(),
            "case:001".to_string(),
            ActorId::new("actor:submitter"),
            Vec::new(),
        );

        // Without receipt and map_commit, should be level B
        assert_eq!(bundle.evidence_level(), EvidenceLevel::B);
        assert!(!bundle.is_complete());
        assert!(!bundle.has_required_refs());

        // Add receipt only - still B (missing map_commit)
        bundle.receipt_id = Some(ReceiptId("receipt:001".to_string()));
        assert_eq!(bundle.evidence_level(), EvidenceLevel::B);

        // Add map_commit - STILL B because not verified!
        // This is the key change: existence alone is not enough
        bundle.map_commit_ref = Some("pmc:001".to_string());
        assert_eq!(bundle.evidence_level(), EvidenceLevel::B);
        assert!(bundle.has_required_refs());
        assert!(bundle.needs_verification());

        // Set receipt verified - still B (other verifications missing)
        bundle.set_receipt_verified(true, None);
        assert_eq!(bundle.evidence_level(), EvidenceLevel::B);

        // Set map commit reconciled - still B (digest not verified)
        bundle.set_map_commit_reconciled(true, None);
        assert_eq!(bundle.evidence_level(), EvidenceLevel::B);

        // Set payload verification - NOW A level
        bundle.set_payload_verification(true, true, 0);
        assert_eq!(bundle.evidence_level(), EvidenceLevel::A);
        assert!(bundle.is_complete());
    }

    #[test]
    fn test_evidence_level_detailed_breakdown() {
        let mut bundle = EvidenceBundle::new(
            "bundle:001".to_string(),
            "case:001".to_string(),
            ActorId::new("actor:submitter"),
            Vec::new(),
        );

        // Initial state - multiple downgrade reasons
        let details = bundle.evidence_level_detailed();
        assert_eq!(details.level, EvidenceLevel::B);
        assert!(details.downgrade_reasons.len() >= 2); // At least missing refs

        // Add refs but don't verify
        bundle.receipt_id = Some(ReceiptId("receipt:001".to_string()));
        bundle.map_commit_ref = Some("pmc:001".to_string());

        let details = bundle.evidence_level_detailed();
        assert_eq!(details.level, EvidenceLevel::B);
        // Should have verification-related downgrade reasons
        assert!(details.downgrade_reasons.iter().any(|r| {
            matches!(r, EvidenceLevelDowngradeReason::ReceiptNotVerified { .. })
        }));
    }

    #[test]
    fn test_hard_invariant_missing_map_commit() {
        let mut bundle = EvidenceBundle::new(
            "bundle:001".to_string(),
            "case:001".to_string(),
            ActorId::new("actor:submitter"),
            Vec::new(),
        );

        // Even with all verifications passing, missing map_commit = B level
        bundle.receipt_id = Some(ReceiptId("receipt:001".to_string()));
        bundle.set_receipt_verified(true, None);
        bundle.set_map_commit_reconciled(true, None);
        bundle.set_payload_verification(true, true, 0);

        // No map_commit_ref - HARD INVARIANT: must be B
        assert!(bundle.map_commit_ref.is_none());
        assert_eq!(bundle.evidence_level(), EvidenceLevel::B);

        let details = bundle.evidence_level_detailed();
        assert!(details.downgrade_reasons.iter().any(|r| {
            matches!(r, EvidenceLevelDowngradeReason::MissingMapCommit)
        }));
    }

    #[test]
    fn test_verification_failure_downgrades_to_b() {
        let mut bundle = EvidenceBundle::new(
            "bundle:001".to_string(),
            "case:001".to_string(),
            ActorId::new("actor:submitter"),
            Vec::new(),
        );

        bundle.receipt_id = Some(ReceiptId("receipt:001".to_string()));
        bundle.map_commit_ref = Some("pmc:001".to_string());

        // Receipt verification failed
        bundle.set_receipt_verified(false, Some("Invalid signature".to_string()));
        bundle.set_map_commit_reconciled(true, None);
        bundle.set_payload_verification(true, true, 0);

        // Should be B due to receipt verification failure
        assert_eq!(bundle.evidence_level(), EvidenceLevel::B);

        let details = bundle.evidence_level_detailed();
        assert!(details.downgrade_reasons.iter().any(|r| {
            match r {
                EvidenceLevelDowngradeReason::ReceiptNotVerified { error } => {
                    error.as_ref().map(|e| e.contains("Invalid signature")).unwrap_or(false)
                }
                _ => false,
            }
        }));
    }

    #[test]
    fn test_inaccessible_payloads_downgrade() {
        let mut bundle = EvidenceBundle::new(
            "bundle:001".to_string(),
            "case:001".to_string(),
            ActorId::new("actor:submitter"),
            Vec::new(),
        );

        bundle.receipt_id = Some(ReceiptId("receipt:001".to_string()));
        bundle.map_commit_ref = Some("pmc:001".to_string());
        bundle.set_receipt_verified(true, None);
        bundle.set_map_commit_reconciled(true, None);

        // Some payloads inaccessible
        bundle.set_payload_verification(true, false, 3);

        assert_eq!(bundle.evidence_level(), EvidenceLevel::B);

        let details = bundle.evidence_level_detailed();
        assert!(details.downgrade_reasons.iter().any(|r| {
            matches!(r, EvidenceLevelDowngradeReason::PayloadsInaccessible { count: 3 })
        }));
    }

    #[test]
    fn test_evidence_level_properties() {
        assert!(EvidenceLevel::A.supports_strong_verdicts());
        assert!(!EvidenceLevel::B.supports_strong_verdicts());
        assert!(EvidenceLevel::B.upgradeable());
        assert!(!EvidenceLevel::A.upgradeable());
    }

    #[test]
    fn test_evidence_type_serialization() {
        let et = EvidenceType::Conversation;
        let json = serde_json::to_string(&et).unwrap();
        assert_eq!(json, "\"conversation\"");
    }

    #[test]
    fn test_verification_state_default() {
        let state = EvidenceVerificationState::default();
        assert!(!state.receipt_verified);
        assert!(!state.map_commit_reconciled);
        assert!(!state.digest_verified);
        assert!(!state.payloads_accessible);
        assert_eq!(state.inaccessible_payload_count, 0);
    }
}
