//! Governance Module
//!
//! Chapter 10: Version Governance System
//!
//! Manages version objects and governance:
//! - VersionObject unified abstraction
//! - Version publishing and revocation
//! - Challenge → Dispute mechanism
//! - UnknownVersion handling

mod version;
mod challenge;
mod registry;

pub use version::*;
pub use challenge::*;
pub use registry::*;

use crate::error::{P3Error, P3Result};
use crate::types::{P3Digest, VersionId};
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use std::collections::HashMap;

/// Version object type
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum VersionObjectType {
    /// Contribution scoring rule
    ContributionRule,
    /// Attribution calculation rule
    AttributionRule,
    /// Threshold configuration
    ThresholdConfig,
    /// Treasury policy
    TreasuryPolicy,
    /// Clearance rule
    ClearanceRule,
    /// Governance rule
    GovernanceRule,
    /// Custom type
    Custom(String),
}

impl VersionObjectType {
    /// Get type name
    pub fn name(&self) -> &str {
        match self {
            VersionObjectType::ContributionRule => "contribution_rule",
            VersionObjectType::AttributionRule => "attribution_rule",
            VersionObjectType::ThresholdConfig => "threshold_config",
            VersionObjectType::TreasuryPolicy => "treasury_policy",
            VersionObjectType::ClearanceRule => "clearance_rule",
            VersionObjectType::GovernanceRule => "governance_rule",
            VersionObjectType::Custom(name) => name,
        }
    }

    /// Get default challenge window hours
    pub fn default_challenge_window_hours(&self) -> i64 {
        match self {
            VersionObjectType::ContributionRule => 72,
            VersionObjectType::AttributionRule => 72,
            VersionObjectType::ThresholdConfig => 48,
            VersionObjectType::TreasuryPolicy => 168, // 1 week
            VersionObjectType::ClearanceRule => 48,
            VersionObjectType::GovernanceRule => 168,
            VersionObjectType::Custom(_) => 72,
        }
    }

    /// Get required quorum for approval
    pub fn required_quorum(&self) -> Decimal {
        match self {
            VersionObjectType::GovernanceRule => Decimal::new(67, 2), // 67%
            VersionObjectType::TreasuryPolicy => Decimal::new(60, 2), // 60%
            _ => Decimal::new(51, 2), // 51%
        }
    }
}

/// Version object status
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VersionStatus {
    /// Draft - not yet published
    Draft,
    /// Proposed - awaiting approval
    Proposed,
    /// Challenge period
    ChallengePeriod,
    /// Active - in use
    Active,
    /// Deprecated - no longer recommended
    Deprecated,
    /// Revoked - explicitly revoked
    Revoked,
    /// Unknown - referenced but not found
    Unknown,
}

impl VersionStatus {
    /// Check if version is usable
    pub fn is_usable(&self) -> bool {
        matches!(self, VersionStatus::Active | VersionStatus::Deprecated)
    }

    /// Check if version can be challenged
    pub fn is_challengeable(&self) -> bool {
        matches!(self, VersionStatus::ChallengePeriod)
    }
}

/// Version object
#[derive(Clone, Debug)]
pub struct VersionObject {
    /// Version ID
    pub version_id: VersionId,
    /// Object type
    pub object_type: VersionObjectType,
    /// Version number (semantic)
    pub version_number: VersionNumber,
    /// Content digest
    pub content_digest: P3Digest,
    /// Previous version (if any)
    pub previous_version: Option<VersionId>,
    /// Status
    pub status: VersionStatus,
    /// Author
    pub author: P3Digest,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Published at
    pub published_at: Option<DateTime<Utc>>,
    /// Challenge window end
    pub challenge_window_end: Option<DateTime<Utc>>,
    /// Activated at
    pub activated_at: Option<DateTime<Utc>>,
    /// Revoked at
    pub revoked_at: Option<DateTime<Utc>>,
    /// Metadata
    pub metadata: HashMap<String, String>,
}

impl VersionObject {
    /// Create new version object
    pub fn new(
        object_type: VersionObjectType,
        version_number: VersionNumber,
        content_digest: P3Digest,
        author: P3Digest,
    ) -> Self {
        let version_id = VersionId::new(format!(
            "ver:{}:{}:{}",
            object_type.name(),
            version_number,
            Utc::now().timestamp_millis()
        ));

        Self {
            version_id,
            object_type,
            version_number,
            content_digest,
            previous_version: None,
            status: VersionStatus::Draft,
            author,
            created_at: Utc::now(),
            published_at: None,
            challenge_window_end: None,
            activated_at: None,
            revoked_at: None,
            metadata: HashMap::new(),
        }
    }

    /// Set previous version
    pub fn with_previous(mut self, previous: VersionId) -> Self {
        self.previous_version = Some(previous);
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Publish version (start challenge period)
    pub fn publish(&mut self) -> P3Result<()> {
        if self.status != VersionStatus::Draft {
            return Err(P3Error::InvalidState {
                reason: format!("Cannot publish version in {:?} status", self.status),
            });
        }

        let now = Utc::now();
        let challenge_hours = self.object_type.default_challenge_window_hours();

        self.status = VersionStatus::ChallengePeriod;
        self.published_at = Some(now);
        self.challenge_window_end = Some(now + chrono::Duration::hours(challenge_hours));

        Ok(())
    }

    /// Activate version (after challenge period)
    pub fn activate(&mut self) -> P3Result<()> {
        if self.status != VersionStatus::ChallengePeriod {
            return Err(P3Error::InvalidState {
                reason: format!("Cannot activate version in {:?} status", self.status),
            });
        }

        // Check challenge window has passed
        if let Some(end) = self.challenge_window_end {
            if Utc::now() < end {
                return Err(P3Error::InvalidState {
                    reason: "Challenge period has not ended".to_string(),
                });
            }
        }

        self.status = VersionStatus::Active;
        self.activated_at = Some(Utc::now());

        Ok(())
    }

    /// Deprecate version
    pub fn deprecate(&mut self) -> P3Result<()> {
        if self.status != VersionStatus::Active {
            return Err(P3Error::InvalidState {
                reason: format!("Cannot deprecate version in {:?} status", self.status),
            });
        }

        self.status = VersionStatus::Deprecated;
        Ok(())
    }

    /// Revoke version
    pub fn revoke(&mut self, reason: impl Into<String>) -> P3Result<()> {
        if !matches!(
            self.status,
            VersionStatus::Active | VersionStatus::Deprecated | VersionStatus::ChallengePeriod
        ) {
            return Err(P3Error::InvalidState {
                reason: format!("Cannot revoke version in {:?} status", self.status),
            });
        }

        self.status = VersionStatus::Revoked;
        self.revoked_at = Some(Utc::now());
        self.metadata.insert("revoke_reason".to_string(), reason.into());

        Ok(())
    }

    /// Check if challenge window is open
    pub fn is_challenge_window_open(&self) -> bool {
        if self.status != VersionStatus::ChallengePeriod {
            return false;
        }

        if let Some(end) = self.challenge_window_end {
            Utc::now() < end
        } else {
            false
        }
    }
}

/// Version number (semantic versioning)
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VersionNumber {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl VersionNumber {
    /// Create new version number
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }

    /// Bump major version
    pub fn bump_major(&self) -> Self {
        Self {
            major: self.major + 1,
            minor: 0,
            patch: 0,
        }
    }

    /// Bump minor version
    pub fn bump_minor(&self) -> Self {
        Self {
            major: self.major,
            minor: self.minor + 1,
            patch: 0,
        }
    }

    /// Bump patch version
    pub fn bump_patch(&self) -> Self {
        Self {
            major: self.major,
            minor: self.minor,
            patch: self.patch + 1,
        }
    }

    /// Check if breaking change (major bump)
    pub fn is_breaking_from(&self, other: &Self) -> bool {
        self.major > other.major
    }
}

impl std::fmt::Display for VersionNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl Default for VersionNumber {
    fn default() -> Self {
        Self::new(1, 0, 0)
    }
}

/// Unknown version reference
#[derive(Clone, Debug)]
pub struct UnknownVersionRef {
    /// Reference ID
    pub ref_id: String,
    /// Version ID that was referenced
    pub version_id: VersionId,
    /// Context where it was referenced
    pub context: String,
    /// First seen
    pub first_seen: DateTime<Utc>,
    /// Reference count
    pub reference_count: u32,
    /// Resolution status
    pub resolution: Option<UnknownVersionResolution>,
}

impl UnknownVersionRef {
    /// Create new unknown version reference
    pub fn new(version_id: VersionId, context: impl Into<String>) -> Self {
        Self {
            ref_id: format!("unknown:{}:{}", version_id.as_str(), Utc::now().timestamp_millis()),
            version_id,
            context: context.into(),
            first_seen: Utc::now(),
            reference_count: 1,
            resolution: None,
        }
    }

    /// Increment reference count
    pub fn increment(&mut self) {
        self.reference_count += 1;
    }

    /// Resolve the unknown version
    pub fn resolve(&mut self, resolution: UnknownVersionResolution) {
        self.resolution = Some(resolution);
    }
}

/// Resolution for unknown version
#[derive(Clone, Debug)]
pub enum UnknownVersionResolution {
    /// Version was found/created
    Found { actual_version_id: VersionId },
    /// Substituted with fallback
    Substituted { fallback_version_id: VersionId },
    /// Ignored with reason
    Ignored { reason: String },
    /// Escalated to governance
    Escalated { dispute_id: String },
}

/// Version transition record
#[derive(Clone, Debug)]
pub struct VersionTransition {
    /// Transition ID
    pub transition_id: String,
    /// From version
    pub from_version: Option<VersionId>,
    /// To version
    pub to_version: VersionId,
    /// Object type
    pub object_type: VersionObjectType,
    /// Transition type
    pub transition_type: TransitionType,
    /// Transition at
    pub transitioned_at: DateTime<Utc>,
    /// Initiated by
    pub initiated_by: P3Digest,
    /// Reason
    pub reason: Option<String>,
}

/// Transition type
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransitionType {
    /// Initial publication
    Initial,
    /// Upgrade to new version
    Upgrade,
    /// Rollback to previous version
    Rollback,
    /// Emergency revocation
    EmergencyRevoke,
    /// Scheduled deprecation
    ScheduledDeprecation,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_number() {
        let v1 = VersionNumber::new(1, 0, 0);
        let v2 = v1.bump_minor();
        let v3 = v2.bump_patch();
        let v4 = v3.bump_major();

        assert_eq!(v1.to_string(), "1.0.0");
        assert_eq!(v2.to_string(), "1.1.0");
        assert_eq!(v3.to_string(), "1.1.1");
        assert_eq!(v4.to_string(), "2.0.0");

        assert!(v4.is_breaking_from(&v1));
        assert!(!v2.is_breaking_from(&v1));
    }

    #[test]
    fn test_version_object_creation() {
        let version = VersionObject::new(
            VersionObjectType::ContributionRule,
            VersionNumber::new(1, 0, 0),
            P3Digest::zero(),
            P3Digest::zero(),
        );

        assert_eq!(version.status, VersionStatus::Draft);
        assert!(version.object_type.name().contains("contribution"));
    }

    #[test]
    fn test_version_lifecycle() {
        let mut version = VersionObject::new(
            VersionObjectType::ThresholdConfig,
            VersionNumber::new(1, 0, 0),
            P3Digest::zero(),
            P3Digest::zero(),
        );

        // Publish
        version.publish().unwrap();
        assert_eq!(version.status, VersionStatus::ChallengePeriod);
        assert!(version.published_at.is_some());
        assert!(version.challenge_window_end.is_some());

        // Cannot activate during challenge period
        assert!(version.activate().is_err());
    }

    #[test]
    fn test_version_object_types() {
        assert_eq!(
            VersionObjectType::GovernanceRule.required_quorum(),
            Decimal::new(67, 2)
        );
        assert_eq!(
            VersionObjectType::ContributionRule.default_challenge_window_hours(),
            72
        );
    }

    #[test]
    fn test_unknown_version_ref() {
        let mut unknown = UnknownVersionRef::new(
            VersionId::new("ver:missing:1.0.0"),
            "attribution_calculation",
        );

        assert_eq!(unknown.reference_count, 1);
        unknown.increment();
        assert_eq!(unknown.reference_count, 2);

        unknown.resolve(UnknownVersionResolution::Substituted {
            fallback_version_id: VersionId::new("ver:fallback:1.0.0"),
        });
        assert!(unknown.resolution.is_some());
    }
}
