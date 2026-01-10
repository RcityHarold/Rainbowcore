//! Non-Platform Verification System
//!
//! This module implements the "非平台化" (Non-Platform) verification principle,
//! which is one of the hard invariants of the DSN layer.
//!
//! # Core Principle
//!
//! Any critical assertion MUST be third-party verifiable. This means:
//! 1. Evidence cannot depend solely on platform-generated proofs
//! 2. All critical data must have external verification anchors
//! 3. Verification can be performed by independent parties without platform assistance
//!
//! # Verification Anchors
//!
//! - **L0 Receipt**: Transaction receipt from L0 consensus layer
//! - **Merkle Proof**: Inclusion proof in a committed merkle tree
//! - **External Timestamp**: Third-party timestamp service attestation
//! - **Witness Signature**: Multi-party witness signatures
//! - **IPFS CID**: Content-addressed storage reference

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use l0_core::types::{Digest, L0Receipt as Receipt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Verification error types
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
pub enum VerificationError {
    #[error("Missing verification anchor: {anchor_type}")]
    MissingAnchor { anchor_type: String },

    #[error("Invalid anchor: {reason}")]
    InvalidAnchor { reason: String },

    #[error("Anchor expired: {anchor_id}")]
    AnchorExpired { anchor_id: String },

    #[error("Insufficient witnesses: required {required}, got {actual}")]
    InsufficientWitnesses { required: usize, actual: usize },

    #[error("Platform-only evidence detected: {details}")]
    PlatformOnlyEvidence { details: String },

    #[error("Verification service unavailable: {service}")]
    ServiceUnavailable { service: String },

    #[error("Merkle proof verification failed: {reason}")]
    MerkleProofFailed { reason: String },

    #[error("Receipt verification failed: {reason}")]
    ReceiptVerificationFailed { reason: String },

    #[error("External timestamp verification failed: {reason}")]
    TimestampVerificationFailed { reason: String },
}

pub type VerificationResult<T> = Result<T, VerificationError>;

/// Types of verification anchors
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnchorType {
    /// L0 consensus receipt
    L0Receipt,
    /// Merkle inclusion proof
    MerkleProof,
    /// External timestamp service
    ExternalTimestamp,
    /// Multi-party witness signatures
    WitnessSignatures,
    /// IPFS content-addressed reference
    IpfsCid,
    /// External notary attestation
    NotaryAttestation,
    /// Blockchain anchor (Ethereum, etc.)
    BlockchainAnchor,
}

impl AnchorType {
    /// Check if this anchor type is platform-independent
    pub fn is_third_party_verifiable(&self) -> bool {
        matches!(
            self,
            AnchorType::ExternalTimestamp
                | AnchorType::WitnessSignatures
                | AnchorType::IpfsCid
                | AnchorType::NotaryAttestation
                | AnchorType::BlockchainAnchor
        )
    }
}

/// Verification anchor - proof that can be verified by third parties
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationAnchor {
    /// Anchor ID
    pub anchor_id: String,
    /// Anchor type
    pub anchor_type: AnchorType,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Expiration (if applicable)
    pub expires_at: Option<DateTime<Utc>>,
    /// Anchor data (type-specific)
    pub anchor_data: AnchorData,
    /// Verification status
    pub verification_status: AnchorVerificationStatus,
    /// Last verified timestamp
    pub last_verified_at: Option<DateTime<Utc>>,
}

impl VerificationAnchor {
    /// Check if anchor is expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() > expires_at
        } else {
            false
        }
    }

    /// Check if anchor is verified
    pub fn is_verified(&self) -> bool {
        matches!(self.verification_status, AnchorVerificationStatus::Verified)
    }
}

/// Anchor data variants
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnchorData {
    /// L0 Receipt anchor
    L0Receipt {
        /// Receipt
        receipt: Receipt,
        /// Block height
        block_height: u64,
        /// Transaction hash
        tx_hash: Digest,
    },
    /// Merkle proof anchor
    MerkleProof {
        /// Root hash
        root_hash: Digest,
        /// Proof path
        proof_path: Vec<MerkleProofNode>,
        /// Leaf index
        leaf_index: u64,
        /// Leaf hash
        leaf_hash: Digest,
    },
    /// External timestamp anchor
    ExternalTimestamp {
        /// Timestamp service name
        service: String,
        /// Timestamp value
        timestamp: DateTime<Utc>,
        /// Service signature
        signature: Vec<u8>,
        /// Certificate chain (for verification)
        certificate_chain: Option<Vec<String>>,
    },
    /// Witness signatures anchor
    WitnessSignatures {
        /// Witness signatures
        signatures: Vec<WitnessSignature>,
        /// Required threshold
        threshold: usize,
        /// Signed data hash
        data_hash: Digest,
    },
    /// IPFS CID anchor
    IpfsCid {
        /// Content ID
        cid: String,
        /// Expected content hash
        content_hash: Digest,
        /// Pin status
        pinned: bool,
    },
    /// Notary attestation anchor
    NotaryAttestation {
        /// Notary ID
        notary_id: String,
        /// Attestation document
        attestation: String,
        /// Notary signature
        signature: Vec<u8>,
        /// Attestation timestamp
        attested_at: DateTime<Utc>,
    },
    /// Blockchain anchor
    BlockchainAnchor {
        /// Chain name (ethereum, etc.)
        chain: String,
        /// Block number
        block_number: u64,
        /// Transaction hash
        tx_hash: String,
        /// Merkle root (if applicable)
        merkle_root: Option<Digest>,
    },
}

/// Merkle proof node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProofNode {
    /// Hash value
    pub hash: Digest,
    /// Position (left or right)
    pub position: MerklePosition,
}

/// Merkle node position
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MerklePosition {
    Left,
    Right,
}

/// Witness signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessSignature {
    /// Witness ID
    pub witness_id: String,
    /// Signature
    pub signature: Vec<u8>,
    /// Signed timestamp
    pub signed_at: DateTime<Utc>,
    /// Public key (for verification)
    pub public_key: Vec<u8>,
}

/// Anchor verification status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnchorVerificationStatus {
    /// Not yet verified
    Pending,
    /// Verification in progress
    Verifying,
    /// Successfully verified
    Verified,
    /// Verification failed
    Failed,
    /// Anchor expired
    Expired,
    /// Verification service unavailable
    ServiceUnavailable,
}

/// Evidence verification requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRequirements {
    /// Required anchor types (at least one must be present)
    pub required_anchor_types: Vec<AnchorType>,
    /// Minimum number of third-party anchors
    pub min_third_party_anchors: usize,
    /// Minimum witness count (for witness signatures)
    pub min_witness_count: usize,
    /// Allow platform-only evidence
    pub allow_platform_only: bool,
    /// Require fresh verification (max age)
    pub max_verification_age_hours: Option<u64>,
}

impl Default for VerificationRequirements {
    fn default() -> Self {
        Self {
            required_anchor_types: vec![AnchorType::L0Receipt, AnchorType::MerkleProof],
            min_third_party_anchors: 1,
            min_witness_count: 2,
            allow_platform_only: false, // Non-platform is default
            max_verification_age_hours: Some(24 * 7), // 1 week
        }
    }
}

/// Verifiable evidence bundle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiableEvidence {
    /// Evidence ID
    pub evidence_id: String,
    /// Evidence hash
    pub evidence_hash: Digest,
    /// Associated anchors
    pub anchors: Vec<VerificationAnchor>,
    /// Verification requirements
    pub requirements: VerificationRequirements,
    /// Overall verification status
    pub verification_status: EvidenceVerificationStatus,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Last verification check
    pub last_checked_at: Option<DateTime<Utc>>,
}

impl VerifiableEvidence {
    /// Create new verifiable evidence
    pub fn new(evidence_id: String, evidence_hash: Digest) -> Self {
        Self {
            evidence_id,
            evidence_hash,
            anchors: Vec::new(),
            requirements: VerificationRequirements::default(),
            verification_status: EvidenceVerificationStatus::Unverified,
            created_at: Utc::now(),
            last_checked_at: None,
        }
    }

    /// Add an anchor
    pub fn add_anchor(&mut self, anchor: VerificationAnchor) {
        self.anchors.push(anchor);
    }

    /// Get third-party anchor count
    pub fn third_party_anchor_count(&self) -> usize {
        self.anchors
            .iter()
            .filter(|a| a.anchor_type.is_third_party_verifiable())
            .count()
    }

    /// Check if evidence is platform-only
    pub fn is_platform_only(&self) -> bool {
        self.third_party_anchor_count() == 0
    }

    /// Get verified anchors
    pub fn verified_anchors(&self) -> Vec<&VerificationAnchor> {
        self.anchors.iter().filter(|a| a.is_verified()).collect()
    }
}

/// Evidence verification status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceVerificationStatus {
    /// Not yet verified
    Unverified,
    /// Verification in progress
    Verifying,
    /// Fully verified (all requirements met)
    FullyVerified,
    /// Partially verified (some anchors verified)
    PartiallyVerified,
    /// Verification failed
    Failed,
    /// Platform-only (no third-party verification)
    PlatformOnly,
}

/// Verification service interface
#[async_trait]
pub trait VerificationService: Send + Sync {
    /// Verify an L0 receipt
    async fn verify_receipt(&self, receipt: &Receipt) -> VerificationResult<bool>;

    /// Verify a merkle proof
    async fn verify_merkle_proof(
        &self,
        root: &Digest,
        proof: &[MerkleProofNode],
        leaf_index: u64,
        leaf_hash: &Digest,
    ) -> VerificationResult<bool>;

    /// Verify external timestamp
    async fn verify_external_timestamp(
        &self,
        service: &str,
        timestamp: DateTime<Utc>,
        signature: &[u8],
    ) -> VerificationResult<bool>;

    /// Verify witness signatures
    async fn verify_witnesses(
        &self,
        signatures: &[WitnessSignature],
        data_hash: &Digest,
        threshold: usize,
    ) -> VerificationResult<bool>;

    /// Verify IPFS CID
    async fn verify_ipfs_cid(&self, cid: &str, expected_hash: &Digest) -> VerificationResult<bool>;

    /// Verify notary attestation
    async fn verify_notary(&self, notary_id: &str, attestation: &str, signature: &[u8]) -> VerificationResult<bool>;

    /// Verify blockchain anchor
    async fn verify_blockchain_anchor(
        &self,
        chain: &str,
        block_number: u64,
        tx_hash: &str,
    ) -> VerificationResult<bool>;
}

/// Non-platform verifier - enforces the non-platform invariant
pub struct NonPlatformVerifier<V: VerificationService> {
    /// Verification service
    verification_service: Arc<V>,
    /// Default requirements
    default_requirements: VerificationRequirements,
    /// Verification cache
    cache: tokio::sync::RwLock<HashMap<String, CachedVerification>>,
    /// Configuration
    config: NonPlatformConfig,
}

/// Cached verification result
#[derive(Debug, Clone)]
struct CachedVerification {
    /// Evidence ID
    evidence_id: String,
    /// Verification result
    status: EvidenceVerificationStatus,
    /// Verified at
    verified_at: DateTime<Utc>,
    /// Cache TTL
    expires_at: DateTime<Utc>,
}

/// Non-platform verifier configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonPlatformConfig {
    /// Enable caching
    pub enable_cache: bool,
    /// Cache TTL (hours)
    pub cache_ttl_hours: u64,
    /// Strict mode (fail on any verification failure)
    pub strict_mode: bool,
    /// Parallel verification
    pub parallel_verification: bool,
    /// Maximum verification timeout (seconds)
    pub verification_timeout_secs: u64,
}

impl Default for NonPlatformConfig {
    fn default() -> Self {
        Self {
            enable_cache: true,
            cache_ttl_hours: 24,
            strict_mode: true,
            parallel_verification: true,
            verification_timeout_secs: 30,
        }
    }
}

impl<V: VerificationService> NonPlatformVerifier<V> {
    /// Create a new verifier
    pub fn new(verification_service: Arc<V>, config: NonPlatformConfig) -> Self {
        Self {
            verification_service,
            default_requirements: VerificationRequirements::default(),
            cache: tokio::sync::RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Verify evidence meets non-platform requirements
    pub async fn verify(&self, evidence: &mut VerifiableEvidence) -> VerificationResult<EvidenceVerificationStatus> {
        // Check cache first
        if self.config.enable_cache {
            if let Some(cached) = self.get_cached(&evidence.evidence_id).await {
                evidence.verification_status = cached.status;
                evidence.last_checked_at = Some(cached.verified_at);
                return Ok(cached.status);
            }
        }

        // Check for platform-only evidence
        if evidence.is_platform_only() && !evidence.requirements.allow_platform_only {
            evidence.verification_status = EvidenceVerificationStatus::PlatformOnly;
            return Err(VerificationError::PlatformOnlyEvidence {
                details: "Evidence has no third-party verification anchors".to_string(),
            });
        }

        // Verify each anchor
        let mut verified_count = 0;
        let mut third_party_verified = 0;

        for anchor in &mut evidence.anchors {
            if anchor.is_expired() {
                anchor.verification_status = AnchorVerificationStatus::Expired;
                continue;
            }

            let result = self.verify_anchor(anchor).await;
            match result {
                Ok(true) => {
                    anchor.verification_status = AnchorVerificationStatus::Verified;
                    anchor.last_verified_at = Some(Utc::now());
                    verified_count += 1;
                    if anchor.anchor_type.is_third_party_verifiable() {
                        third_party_verified += 1;
                    }
                }
                Ok(false) => {
                    anchor.verification_status = AnchorVerificationStatus::Failed;
                    if self.config.strict_mode {
                        evidence.verification_status = EvidenceVerificationStatus::Failed;
                        return Err(VerificationError::InvalidAnchor {
                            reason: format!("Anchor {} verification returned false", anchor.anchor_id),
                        });
                    }
                }
                Err(e) => {
                    anchor.verification_status = AnchorVerificationStatus::Failed;
                    tracing::warn!(anchor_id = %anchor.anchor_id, error = %e, "Anchor verification failed");
                    if self.config.strict_mode {
                        evidence.verification_status = EvidenceVerificationStatus::Failed;
                        return Err(e);
                    }
                }
            }
        }

        // Check requirements
        let status = if third_party_verified >= evidence.requirements.min_third_party_anchors
            && verified_count > 0
        {
            EvidenceVerificationStatus::FullyVerified
        } else if verified_count > 0 {
            EvidenceVerificationStatus::PartiallyVerified
        } else {
            EvidenceVerificationStatus::Failed
        };

        evidence.verification_status = status;
        evidence.last_checked_at = Some(Utc::now());

        // Update cache
        if self.config.enable_cache {
            self.cache_result(&evidence.evidence_id, status).await;
        }

        Ok(status)
    }

    /// Verify a single anchor
    async fn verify_anchor(&self, anchor: &VerificationAnchor) -> VerificationResult<bool> {
        match &anchor.anchor_data {
            AnchorData::L0Receipt { receipt, .. } => {
                self.verification_service.verify_receipt(receipt).await
            }
            AnchorData::MerkleProof {
                root_hash,
                proof_path,
                leaf_index,
                leaf_hash,
            } => {
                self.verification_service
                    .verify_merkle_proof(root_hash, proof_path, *leaf_index, leaf_hash)
                    .await
            }
            AnchorData::ExternalTimestamp {
                service,
                timestamp,
                signature,
                ..
            } => {
                self.verification_service
                    .verify_external_timestamp(service, *timestamp, signature)
                    .await
            }
            AnchorData::WitnessSignatures {
                signatures,
                threshold,
                data_hash,
            } => {
                self.verification_service
                    .verify_witnesses(signatures, data_hash, *threshold)
                    .await
            }
            AnchorData::IpfsCid { cid, content_hash, .. } => {
                self.verification_service.verify_ipfs_cid(cid, content_hash).await
            }
            AnchorData::NotaryAttestation {
                notary_id,
                attestation,
                signature,
                ..
            } => {
                self.verification_service
                    .verify_notary(notary_id, attestation, signature)
                    .await
            }
            AnchorData::BlockchainAnchor {
                chain,
                block_number,
                tx_hash,
                ..
            } => {
                self.verification_service
                    .verify_blockchain_anchor(chain, *block_number, tx_hash)
                    .await
            }
        }
    }

    /// Get cached verification
    async fn get_cached(&self, evidence_id: &str) -> Option<CachedVerification> {
        let cache = self.cache.read().await;
        if let Some(cached) = cache.get(evidence_id) {
            if Utc::now() < cached.expires_at {
                return Some(cached.clone());
            }
        }
        None
    }

    /// Cache verification result
    async fn cache_result(&self, evidence_id: &str, status: EvidenceVerificationStatus) {
        let now = Utc::now();
        let cached = CachedVerification {
            evidence_id: evidence_id.to_string(),
            status,
            verified_at: now,
            expires_at: now + chrono::Duration::hours(self.config.cache_ttl_hours as i64),
        };
        let mut cache = self.cache.write().await;
        cache.insert(evidence_id.to_string(), cached);
    }

    /// Check if evidence meets non-platform requirements without full verification
    pub fn check_requirements(&self, evidence: &VerifiableEvidence) -> RequirementsCheckResult {
        let mut result = RequirementsCheckResult {
            meets_requirements: true,
            issues: Vec::new(),
        };

        // Check third-party anchor count
        let third_party_count = evidence.third_party_anchor_count();
        if third_party_count < evidence.requirements.min_third_party_anchors {
            result.meets_requirements = false;
            result.issues.push(RequirementIssue {
                issue_type: RequirementIssueType::InsufficientThirdPartyAnchors,
                description: format!(
                    "Need {} third-party anchors, have {}",
                    evidence.requirements.min_third_party_anchors, third_party_count
                ),
            });
        }

        // Check for platform-only
        if evidence.is_platform_only() && !evidence.requirements.allow_platform_only {
            result.meets_requirements = false;
            result.issues.push(RequirementIssue {
                issue_type: RequirementIssueType::PlatformOnly,
                description: "Evidence has no third-party verification anchors".to_string(),
            });
        }

        // Check required anchor types
        let anchor_types: std::collections::HashSet<_> =
            evidence.anchors.iter().map(|a| a.anchor_type).collect();
        for required in &evidence.requirements.required_anchor_types {
            if !anchor_types.contains(required) {
                result.issues.push(RequirementIssue {
                    issue_type: RequirementIssueType::MissingRequiredAnchor,
                    description: format!("Missing required anchor type: {:?}", required),
                });
            }
        }

        // Check witness count
        let witness_count: usize = evidence
            .anchors
            .iter()
            .filter_map(|a| {
                if let AnchorData::WitnessSignatures { signatures, .. } = &a.anchor_data {
                    Some(signatures.len())
                } else {
                    None
                }
            })
            .sum();

        if witness_count < evidence.requirements.min_witness_count
            && evidence.requirements.required_anchor_types.contains(&AnchorType::WitnessSignatures)
        {
            result.issues.push(RequirementIssue {
                issue_type: RequirementIssueType::InsufficientWitnesses,
                description: format!(
                    "Need {} witnesses, have {}",
                    evidence.requirements.min_witness_count, witness_count
                ),
            });
        }

        result
    }

    /// Create a verification report
    pub fn generate_report(&self, evidence: &VerifiableEvidence) -> VerificationReport {
        let check_result = self.check_requirements(evidence);

        VerificationReport {
            evidence_id: evidence.evidence_id.clone(),
            evidence_hash: evidence.evidence_hash.clone(),
            status: evidence.verification_status,
            total_anchors: evidence.anchors.len(),
            verified_anchors: evidence.verified_anchors().len(),
            third_party_anchors: evidence.third_party_anchor_count(),
            is_platform_only: evidence.is_platform_only(),
            meets_requirements: check_result.meets_requirements,
            requirement_issues: check_result.issues,
            anchors: evidence
                .anchors
                .iter()
                .map(|a| AnchorSummary {
                    anchor_id: a.anchor_id.clone(),
                    anchor_type: a.anchor_type,
                    is_third_party: a.anchor_type.is_third_party_verifiable(),
                    status: a.verification_status,
                    is_expired: a.is_expired(),
                })
                .collect(),
            generated_at: Utc::now(),
        }
    }
}

/// Requirements check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequirementsCheckResult {
    /// Whether all requirements are met
    pub meets_requirements: bool,
    /// Issues found
    pub issues: Vec<RequirementIssue>,
}

/// Requirement issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequirementIssue {
    /// Issue type
    pub issue_type: RequirementIssueType,
    /// Description
    pub description: String,
}

/// Requirement issue types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum RequirementIssueType {
    /// Not enough third-party anchors
    InsufficientThirdPartyAnchors,
    /// Platform-only evidence
    PlatformOnly,
    /// Missing required anchor type
    MissingRequiredAnchor,
    /// Not enough witnesses
    InsufficientWitnesses,
    /// Anchor expired
    AnchorExpired,
    /// Verification too old
    VerificationStale,
}

/// Verification report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    /// Evidence ID
    pub evidence_id: String,
    /// Evidence hash
    pub evidence_hash: Digest,
    /// Verification status
    pub status: EvidenceVerificationStatus,
    /// Total anchor count
    pub total_anchors: usize,
    /// Verified anchor count
    pub verified_anchors: usize,
    /// Third-party anchor count
    pub third_party_anchors: usize,
    /// Is platform-only
    pub is_platform_only: bool,
    /// Meets requirements
    pub meets_requirements: bool,
    /// Requirement issues
    pub requirement_issues: Vec<RequirementIssue>,
    /// Anchor summaries
    pub anchors: Vec<AnchorSummary>,
    /// Report generation timestamp
    pub generated_at: DateTime<Utc>,
}

/// Anchor summary for report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorSummary {
    /// Anchor ID
    pub anchor_id: String,
    /// Anchor type
    pub anchor_type: AnchorType,
    /// Is third-party verifiable
    pub is_third_party: bool,
    /// Verification status
    pub status: AnchorVerificationStatus,
    /// Is expired
    pub is_expired: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anchor_type_third_party() {
        assert!(!AnchorType::L0Receipt.is_third_party_verifiable());
        assert!(!AnchorType::MerkleProof.is_third_party_verifiable());
        assert!(AnchorType::ExternalTimestamp.is_third_party_verifiable());
        assert!(AnchorType::WitnessSignatures.is_third_party_verifiable());
        assert!(AnchorType::IpfsCid.is_third_party_verifiable());
        assert!(AnchorType::NotaryAttestation.is_third_party_verifiable());
        assert!(AnchorType::BlockchainAnchor.is_third_party_verifiable());
    }

    #[test]
    fn test_verifiable_evidence_new() {
        let evidence = VerifiableEvidence::new(
            "evidence:test".to_string(),
            Digest::zero(),
        );

        assert_eq!(evidence.evidence_id, "evidence:test");
        assert!(evidence.anchors.is_empty());
        assert_eq!(evidence.verification_status, EvidenceVerificationStatus::Unverified);
        assert!(evidence.is_platform_only());
    }

    #[test]
    fn test_verification_requirements_default() {
        let req = VerificationRequirements::default();
        assert_eq!(req.min_third_party_anchors, 1);
        assert_eq!(req.min_witness_count, 2);
        assert!(!req.allow_platform_only);
    }

    #[test]
    fn test_evidence_third_party_count() {
        let mut evidence = VerifiableEvidence::new(
            "evidence:test".to_string(),
            Digest::zero(),
        );

        // Add L0 receipt (not third-party)
        let test_receipt = Receipt {
            receipt_id: l0_core::types::ReceiptId("test-receipt".to_string()),
            scope_type: l0_core::types::ScopeType::BackfillBatch,
            root_kind: l0_core::types::RootKind::BatchRoot,
            root: Digest::zero(),
            time_window_start: Utc::now(),
            time_window_end: Utc::now(),
            batch_sequence_no: Some(1),
            signer_set_version: "v1".to_string(),
            canonicalization_version: "v1".to_string(),
            anchor_policy_version: "v1".to_string(),
            fee_schedule_version: "v1".to_string(),
            fee_receipt_id: "fee-1".to_string(),
            signed_snapshot_ref: "snapshot-1".to_string(),
            created_at: Utc::now(),
            rejected: None,
            reject_reason_code: None,
            observer_reports_digest: None,
        };
        evidence.add_anchor(VerificationAnchor {
            anchor_id: "anchor:1".to_string(),
            anchor_type: AnchorType::L0Receipt,
            created_at: Utc::now(),
            expires_at: None,
            anchor_data: AnchorData::L0Receipt {
                receipt: test_receipt,
                block_height: 100,
                tx_hash: Digest::zero(),
            },
            verification_status: AnchorVerificationStatus::Pending,
            last_verified_at: None,
        });

        assert_eq!(evidence.third_party_anchor_count(), 0);
        assert!(evidence.is_platform_only());

        // Add IPFS anchor (third-party)
        evidence.add_anchor(VerificationAnchor {
            anchor_id: "anchor:2".to_string(),
            anchor_type: AnchorType::IpfsCid,
            created_at: Utc::now(),
            expires_at: None,
            anchor_data: AnchorData::IpfsCid {
                cid: "Qm123".to_string(),
                content_hash: Digest::zero(),
                pinned: true,
            },
            verification_status: AnchorVerificationStatus::Pending,
            last_verified_at: None,
        });

        assert_eq!(evidence.third_party_anchor_count(), 1);
        assert!(!evidence.is_platform_only());
    }

    #[test]
    fn test_non_platform_config_default() {
        let config = NonPlatformConfig::default();
        assert!(config.enable_cache);
        assert_eq!(config.cache_ttl_hours, 24);
        assert!(config.strict_mode);
    }
}
