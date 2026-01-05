//! Evidence Bundle Types
//!
//! Evidence payload bundles for judicial discovery.
//! These are the encrypted evidence packages used in dispute resolution.

use super::sealed_payload::SealedPayloadRef;
use chrono::{DateTime, Utc};
use l0_core::types::{ActorId, Digest, ReceiptId};
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
    /// A = receipt-backed + payload_map_commit reconciled
    /// B = missing receipt or map_commit
    pub fn evidence_level(&self) -> EvidenceLevel {
        match (&self.receipt_id, &self.map_commit_ref) {
            (Some(_), Some(_)) => EvidenceLevel::A,
            _ => EvidenceLevel::B,
        }
    }

    /// Check if bundle is complete (has all requirements for level A)
    pub fn is_complete(&self) -> bool {
        self.receipt_id.is_some() && self.map_commit_ref.is_some()
    }

    /// Get total payload size
    pub fn total_size_bytes(&self) -> u64 {
        self.payload_refs.iter().map(|r| r.size_bytes).sum()
    }

    /// Get payload count
    pub fn payload_count(&self) -> usize {
        self.payload_refs.len()
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

/// Evidence level
///
/// Hard rule: Missing payload_map_commit MUST be level B
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLevel {
    /// A-level: receipt-backed + payload_map_commit reconciled
    /// Can be used for strong verdicts/clawbacks
    A,
    /// B-level: missing receipt or map_commit
    /// Temporary, needs backfill to upgrade
    B,
}

impl EvidenceLevel {
    /// Check if this level supports strong verdicts
    pub fn supports_strong_verdicts(&self) -> bool {
        matches!(self, EvidenceLevel::A)
    }

    /// Check if this level can be upgraded via backfill
    pub fn upgradeable(&self) -> bool {
        matches!(self, EvidenceLevel::B)
    }
}

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
    fn test_evidence_level() {
        let mut bundle = EvidenceBundle::new(
            "bundle:001".to_string(),
            "case:001".to_string(),
            ActorId::new("actor:submitter"),
            Vec::new(),
        );

        // Without receipt and map_commit, should be level B
        assert_eq!(bundle.evidence_level(), EvidenceLevel::B);
        assert!(!bundle.is_complete());

        // Add receipt only - still B
        bundle.receipt_id = Some(ReceiptId("receipt:001".to_string()));
        assert_eq!(bundle.evidence_level(), EvidenceLevel::B);

        // Add map_commit - now A
        bundle.map_commit_ref = Some("pmc:001".to_string());
        assert_eq!(bundle.evidence_level(), EvidenceLevel::A);
        assert!(bundle.is_complete());
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
}
