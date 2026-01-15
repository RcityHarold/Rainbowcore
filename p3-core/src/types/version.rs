//! Version Object Abstraction
//!
//! Chapter 10: Governance Versioning + Error Code Registry
//!
//! Core invariants:
//! - Version cannot rollback (valid_from only moves forward)
//! - Supersedes chain is append-only
//! - Unknown version blocks strong economic actions

use super::common::*;
use super::points::SemanticVersion;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Version object (unified abstraction)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionObject {
    /// Version ID (unique identifier)
    pub version_id: String,
    /// Version type
    pub version_type: VersionType,
    /// Semantic version
    pub semantic_version: SemanticVersion,
    /// Valid from epoch (no rollback)
    pub valid_from: EpochId,
    /// Supersedes (append-only chain)
    pub supersedes: Option<String>,
    /// Issuer reference
    pub issuer_ref: String,
    /// Canonicalization version
    pub canon_version: CanonVersion,
    /// Content digest
    pub content_digest: P3Digest,
    /// Compatibility vector
    pub compatibility: CompatibilityInfo,
    /// Metadata
    pub metadata: VersionMetadata,
}

impl VersionObject {
    /// Check if this version is compatible with another
    pub fn is_compatible_with(&self, other: &VersionObject) -> bool {
        self.semantic_version.major == other.semantic_version.major
            && self.version_type == other.version_type
    }

    /// Check if this version supersedes another
    pub fn supersedes_version(&self, other_id: &str) -> bool {
        self.supersedes.as_deref() == Some(other_id)
    }

    /// Check if version is newer
    pub fn is_newer_than(&self, other: &VersionObject) -> bool {
        self.semantic_version.is_newer_than(&other.semantic_version)
    }
}

/// Version type
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionType {
    /// Weights function version
    Weights,
    /// Pool ratio version
    PoolRatio,
    /// Fee schedule version
    FeeSchedule,
    /// Lineage policy version
    LineagePolicy,
    /// Attribution policy version
    AttributionPolicy,
    /// Clawback policy version
    ClawbackPolicy,
    /// Subsidy policy version
    SubsidyPolicy,
    /// Error code version
    ErrorCode,
    /// Canonicalization version
    Canonicalization,
    /// Event schema version
    EventSchema,
}

impl VersionType {
    /// Get type name
    pub fn name(&self) -> &'static str {
        match self {
            VersionType::Weights => "weights",
            VersionType::PoolRatio => "pool_ratio",
            VersionType::FeeSchedule => "fee_schedule",
            VersionType::LineagePolicy => "lineage_policy",
            VersionType::AttributionPolicy => "attribution_policy",
            VersionType::ClawbackPolicy => "clawback_policy",
            VersionType::SubsidyPolicy => "subsidy_policy",
            VersionType::ErrorCode => "error_code",
            VersionType::Canonicalization => "canonicalization",
            VersionType::EventSchema => "event_schema",
        }
    }
}

/// Compatibility information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompatibilityInfo {
    /// Minimum compatible versions
    pub min_versions: Vec<VersionDependency>,
    /// Maximum compatible versions
    pub max_versions: Vec<VersionDependency>,
    /// Breaking changes
    pub breaking_changes: Vec<BreakingChange>,
}

impl CompatibilityInfo {
    pub fn empty() -> Self {
        Self {
            min_versions: Vec::new(),
            max_versions: Vec::new(),
            breaking_changes: Vec::new(),
        }
    }
}

/// Version dependency
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionDependency {
    pub version_type: VersionType,
    pub version_id: String,
}

/// Breaking change
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BreakingChange {
    pub change_id: String,
    pub description: String,
    pub migration_ref: Option<String>,
}

/// Version metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionMetadata {
    pub created_at: DateTime<Utc>,
    pub description: Option<String>,
    pub changelog_digest: Option<P3Digest>,
    pub approved_by: Vec<String>,
}

impl VersionMetadata {
    pub fn new(created_at: DateTime<Utc>) -> Self {
        Self {
            created_at,
            description: None,
            changelog_digest: None,
            approved_by: Vec::new(),
        }
    }
}

/// Version registry entry
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionRegistryEntry {
    pub version_type: VersionType,
    pub version_id: String,
    pub status: VersionStatus,
    pub valid_from: EpochId,
    pub valid_until: Option<EpochId>,
    pub content_digest: P3Digest,
    pub superseded_by: Option<String>,
}

/// Version status
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionStatus {
    /// Draft (not yet active)
    Draft,
    /// Active (currently in use)
    Active,
    /// Deprecated (still valid but superseded)
    Deprecated,
    /// Retired (no longer valid)
    Retired,
}

/// Version gate check result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionGateResult {
    pub passed: bool,
    pub checked_versions: Vec<VersionCheckItem>,
    pub unknown_versions: Vec<String>,
    pub incompatible_versions: Vec<IncompatibilityInfo>,
}

impl VersionGateResult {
    /// Check if all versions are known
    pub fn all_known(&self) -> bool {
        self.unknown_versions.is_empty()
    }

    /// Check if all versions are compatible
    pub fn all_compatible(&self) -> bool {
        self.incompatible_versions.is_empty()
    }
}

/// Version check item
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionCheckItem {
    pub version_type: VersionType,
    pub version_id: String,
    pub status: VersionCheckStatus,
}

/// Version check status
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionCheckStatus {
    Known,
    Unknown,
    Deprecated,
    Incompatible,
}

/// Incompatibility info
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IncompatibilityInfo {
    pub version_type: VersionType,
    pub expected: String,
    pub actual: String,
    pub reason: String,
}

/// Version transition (for audit)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionTransition {
    pub transition_id: String,
    pub version_type: VersionType,
    pub from_version: String,
    pub to_version: String,
    pub transition_epoch: EpochId,
    pub transition_at: DateTime<Utc>,
    pub approved_by: Vec<String>,
    pub receipt_ref: Option<String>,
}

/// Known version set (for gate checks)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KnownVersionSet {
    pub weights_versions: Vec<String>,
    pub pool_ratio_versions: Vec<String>,
    pub fee_schedule_versions: Vec<String>,
    pub lineage_policy_versions: Vec<String>,
    pub error_code_versions: Vec<String>,
    pub canon_versions: Vec<String>,
}

impl KnownVersionSet {
    /// Check if a version is known
    pub fn is_known(&self, version_type: &VersionType, version_id: &str) -> bool {
        match version_type {
            VersionType::Weights => self.weights_versions.contains(&version_id.to_string()),
            VersionType::PoolRatio => self.pool_ratio_versions.contains(&version_id.to_string()),
            VersionType::FeeSchedule => self.fee_schedule_versions.contains(&version_id.to_string()),
            VersionType::LineagePolicy => self.lineage_policy_versions.contains(&version_id.to_string()),
            VersionType::ErrorCode => self.error_code_versions.contains(&version_id.to_string()),
            VersionType::Canonicalization => self.canon_versions.contains(&version_id.to_string()),
            _ => false,
        }
    }

    /// Create default v1 known set
    pub fn default_v1() -> Self {
        Self {
            weights_versions: vec!["v1".to_string()],
            pool_ratio_versions: vec!["v1".to_string()],
            fee_schedule_versions: vec!["v1".to_string()],
            lineage_policy_versions: vec!["v1".to_string()],
            error_code_versions: vec!["v1".to_string()],
            canon_versions: vec!["v1".to_string()],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_type_name() {
        assert_eq!(VersionType::Weights.name(), "weights");
        assert_eq!(VersionType::PoolRatio.name(), "pool_ratio");
    }

    #[test]
    fn test_known_version_set() {
        let set = KnownVersionSet::default_v1();
        assert!(set.is_known(&VersionType::Weights, "v1"));
        assert!(!set.is_known(&VersionType::Weights, "v2"));
    }

    #[test]
    fn test_version_compatibility() {
        let v1 = VersionObject {
            version_id: "weights_v1".to_string(),
            version_type: VersionType::Weights,
            semantic_version: SemanticVersion::new(1, 0, 0),
            valid_from: EpochId::new("epoch:1"),
            supersedes: None,
            issuer_ref: "issuer1".to_string(),
            canon_version: CanonVersion::v1(),
            content_digest: P3Digest::zero(),
            compatibility: CompatibilityInfo::empty(),
            metadata: VersionMetadata::new(Utc::now()),
        };

        let v1_1 = VersionObject {
            version_id: "weights_v1.1".to_string(),
            version_type: VersionType::Weights,
            semantic_version: SemanticVersion::new(1, 1, 0),
            valid_from: EpochId::new("epoch:2"),
            supersedes: Some("weights_v1".to_string()),
            issuer_ref: "issuer1".to_string(),
            canon_version: CanonVersion::v1(),
            content_digest: P3Digest::zero(),
            compatibility: CompatibilityInfo::empty(),
            metadata: VersionMetadata::new(Utc::now()),
        };

        assert!(v1.is_compatible_with(&v1_1));
        assert!(v1_1.is_newer_than(&v1));
        assert!(v1_1.supersedes_version("weights_v1"));
    }
}
