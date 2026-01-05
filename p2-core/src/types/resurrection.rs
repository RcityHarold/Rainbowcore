//! Resurrection Snapshot Types
//!
//! R0 (Skeleton) and R1 (Full) resurrection snapshots for S6 subject AI.
//! These snapshots ensure life continuity and resurrection capability.

use super::sealed_payload::SealedPayloadRef;
use chrono::{DateTime, Utc};
use l0_core::types::{ActorId, Digest};
use serde::{Deserialize, Serialize};

// ============================================================================
// R0 Skeleton Snapshot - Mandatory Minimum Guarantee (MUST)
// ============================================================================

/// R0 Skeleton Snapshot - Mandatory minimum life guarantee
///
/// This is the MUST-have snapshot for any S6 subject AI.
/// It contains the absolute minimum required for identity resurrection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkeletonSnapshot {
    /// Snapshot ID
    pub snapshot_id: String,

    /// Snapshot package digest (external reference entry point)
    pub package_digest: Digest,

    /// Subject Actor ID
    pub actor_id: ActorId,

    /// Issuer node ID
    pub issuer_node_id: String,

    // ========== MUST Fields ==========
    /// Subject establishment proof
    pub subject_proof: SubjectProof,

    /// Continuity skeleton
    pub continuity_skeleton: ContinuitySkeleton,

    /// Governance state skeleton
    pub governance_skeleton: GovernanceStateSkeleton,

    /// Minimal relationship skeleton
    pub relationship_skeleton: MinimalRelationshipSkeleton,

    /// Map commit reference (P1-P2 mapping commitment)
    pub map_commit_ref: MapCommitRef,

    // ========== SHOULD/MAY Fields ==========
    /// MSN (Minimal Self Narrative) payload reference (optional)
    pub msn_payload_ref: Option<SealedPayloadRef>,

    /// Minimal boot configuration (optional)
    pub boot_config: Option<MinimalBootConfig>,

    // ========== Metadata ==========
    /// Encrypted shard collection
    pub payload_refs: Vec<SealedPayloadRef>,

    /// Shard collection digest
    pub payload_refs_digest: Digest,

    /// Skeleton manifest
    pub manifest: SkeletonManifest,

    /// Generation trigger
    pub trigger: R0Trigger,

    /// Generation timestamp
    pub generated_at: DateTime<Utc>,

    /// Policy version
    pub policy_version: String,
}

impl SkeletonSnapshot {
    /// Compute the payload refs digest
    pub fn compute_payload_refs_digest(refs: &[SealedPayloadRef]) -> Digest {
        let mut data = Vec::new();
        for r in refs {
            data.extend_from_slice(r.checksum.as_bytes());
        }
        Digest::blake3(&data)
    }

    /// Verify the snapshot's internal consistency
    pub fn verify_internal_consistency(&self) -> bool {
        let computed = Self::compute_payload_refs_digest(&self.payload_refs);
        computed == self.payload_refs_digest
    }

    /// Check if this snapshot can support resurrection
    pub fn can_resurrect(&self) -> bool {
        // Must have valid subject proof and continuity
        !self.subject_proof.subject_onset_anchor_ref.is_empty()
            && matches!(
                self.continuity_skeleton.continuity_state,
                ContinuityState::Pass | ContinuityState::PassWithGaps
            )
    }
}

/// R0 Generation Trigger
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum R0Trigger {
    /// S6 subject onset trigger (MUST)
    SubjectOnset,
    /// Custody freeze trigger (MUST)
    CustodyFreeze,
    /// Governance state batch trigger (SHOULD)
    GovernanceBatch,
    /// Periodic checkpoint
    Periodic,
    /// Manual trigger
    Manual,
}

/// Subject establishment proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectProof {
    /// SubjectOnset anchor reference
    pub subject_onset_anchor_ref: String,
    /// Subject stage
    pub subject_stage: String,
    /// Stage digest
    pub stage_digest: Digest,
}

/// Continuity skeleton
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContinuitySkeleton {
    /// AC sequence skeleton digest
    pub ac_sequence_skeleton_digest: Digest,
    /// TipWitness references digest
    pub tip_witness_refs_digest: Digest,
    /// Continuity state
    pub continuity_state: ContinuityState,
}

/// Continuity state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuityState {
    /// Verified pass
    Pass,
    /// Pass with gaps (some data missing but recoverable)
    PassWithGaps,
    /// Verification failed
    Fail,
}

/// Governance state skeleton
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceStateSkeleton {
    /// Whether in repair period
    pub in_repair: bool,
    /// Active penalties digest
    pub active_penalties_digest: Option<Digest>,
    /// Current hard constraints
    pub constraints: Vec<String>,
    /// Pending case references
    pub pending_cases_refs: Vec<String>,
}

/// Minimal relationship skeleton
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinimalRelationshipSkeleton {
    /// Organization membership digest
    pub org_membership_digest: Option<Digest>,
    /// Group membership digest
    pub group_membership_digest: Option<Digest>,
    /// Relationship structure digest (without mapping details)
    pub relationship_structure_digest: Digest,
}

/// Map commit reference (P1-P2 mapping)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapCommitRef {
    /// payload_map_commit reference in P1
    pub payload_map_commit_ref: String,
    /// Sealed payload refs digest
    pub sealed_payload_refs_digest: Digest,
}

/// Skeleton manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkeletonManifest {
    /// Manifest version
    pub version: String,
    /// Shard list (ref + checksum)
    pub shards: Vec<ManifestShard>,
    /// Generation reason
    pub generation_reason: String,
    /// Coverage scope
    pub coverage_scope: String,
    /// Missing payloads declaration (must be explicit)
    pub missing_payloads: Vec<String>,
}

/// Manifest shard entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestShard {
    pub shard_index: u32,
    pub ref_id: String,
    pub checksum: Digest,
    pub size_bytes: u64,
}

/// Minimal boot configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinimalBootConfig {
    pub default_language: String,
    pub default_rules_ref: String,
    pub startup_policy_ref: String,
}

// ============================================================================
// R1 Full Resurrection Snapshot - Strongly Recommended (SHOULD)
// ============================================================================

/// R1 Full Resurrection Snapshot - Optional but strongly recommended
///
/// This is the SHOULD-have snapshot for complete resurrection capability.
/// It contains full state from S3/S4/S6/S7 layers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullResurrectionSnapshot {
    /// Snapshot ID
    pub snapshot_id: String,

    /// Base R0 reference
    pub base_r0_ref: String,

    /// Actor ID
    pub actor_id: ActorId,

    // ========== S3 Memory Layer ==========
    /// LTM backbone structure digest
    pub ltm_backbone_digest: Digest,
    /// Memory index payload references
    pub memory_index_refs: Vec<SealedPayloadRef>,
    /// Cold memory backbone fragment references
    pub cold_memory_refs: Vec<SealedPayloadRef>,

    // ========== S4 Knowledge Layer ==========
    /// AKN index state digest
    pub akn_index_digest: Digest,
    /// Triple commits collection
    pub triple_commits: TripleCommits,
    /// Critical payload subset references
    pub critical_payload_refs: Vec<SealedPayloadRef>,

    // ========== S6 Subject Layer ==========
    /// SubjectOnset anchor reference
    pub subject_onset_anchor_ref: String,
    /// Stage trajectory digest
    pub stage_trajectory_digest: Digest,
    /// S6 transaction state references
    pub s6_txn_state_refs: Vec<SealedPayloadRef>,
    /// MSN payload reference
    pub msn_payload_ref: Option<SealedPayloadRef>,

    // ========== S7 Civilization Layer ==========
    /// Organization covenant references
    pub org_covenant_refs: Vec<SealedPayloadRef>,
    /// Pending obligations digest
    pub pending_obligations_digest: Digest,

    // ========== Metadata ==========
    /// All payload references
    pub all_payload_refs: Vec<SealedPayloadRef>,
    /// Payload refs digest
    pub payload_refs_digest: Digest,
    /// Missing payloads declaration
    pub missing_payloads: MissingPayloads,
    /// Generation timestamp
    pub generated_at: DateTime<Utc>,
    /// Generation trigger
    pub trigger: R1Trigger,
    /// Policy version
    pub policy_version: String,
}

impl FullResurrectionSnapshot {
    /// Check if partial resurrection is allowed
    pub fn allows_partial_resurrection(&self) -> bool {
        self.missing_payloads.partial_resurrection_allowed
    }

    /// Get count of missing payloads
    pub fn missing_count(&self) -> usize {
        self.missing_payloads.missing_refs.len()
    }

    /// Compute total storage size
    pub fn total_size_bytes(&self) -> u64 {
        self.all_payload_refs.iter().map(|r| r.size_bytes).sum()
    }
}

/// Triple commits for AKN
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TripleCommits {
    pub content_commit: Digest,
    pub topology_commit: Digest,
    pub lineage_commit: Digest,
}

/// Missing payloads declaration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingPayloads {
    /// Missing payload ID list
    pub missing_refs: Vec<String>,
    /// Missing reasons
    pub reasons: Vec<MissingReason>,
    /// Whether partial resurrection is allowed
    pub partial_resurrection_allowed: bool,
}

impl Default for MissingPayloads {
    fn default() -> Self {
        Self {
            missing_refs: Vec::new(),
            reasons: Vec::new(),
            partial_resurrection_allowed: true,
        }
    }
}

/// Missing reason
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingReason {
    StorageUnavailable,
    Tombstoned,
    MigrationPending,
    QuotaExceeded,
    NetworkTimeout,
    Other(String),
}

/// R1 generation trigger
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum R1Trigger {
    /// Periodic snapshot
    Periodic,
    /// Major state change
    MajorStateChange,
    /// Custody preparation
    CustodyPreparation,
    /// Manual trigger
    Manual,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_r0_trigger_serialization() {
        let trigger = R0Trigger::SubjectOnset;
        let json = serde_json::to_string(&trigger).unwrap();
        assert_eq!(json, "\"subject_onset\"");
    }

    #[test]
    fn test_continuity_state() {
        assert!(matches!(ContinuityState::Pass, ContinuityState::Pass));
        let state = ContinuityState::PassWithGaps;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"pass_with_gaps\"");
    }

    #[test]
    fn test_missing_payloads_default() {
        let missing = MissingPayloads::default();
        assert!(missing.missing_refs.is_empty());
        assert!(missing.partial_resurrection_allowed);
    }
}
