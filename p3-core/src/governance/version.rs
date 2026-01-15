//! Version Management
//!
//! Handles version publishing, activation, and revocation.

use super::{
    VersionObject, VersionObjectType, VersionNumber, VersionStatus,
    VersionTransition, TransitionType, UnknownVersionRef, UnknownVersionResolution,
};
use crate::error::{P3Error, P3Result};
use crate::types::{P3Digest, VersionId};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Version manager
pub struct VersionManager {
    /// All versions
    versions: HashMap<String, VersionObject>,
    /// Active version per type
    active_versions: HashMap<VersionObjectType, VersionId>,
    /// Version transitions
    transitions: Vec<VersionTransition>,
    /// Unknown version references
    unknown_refs: HashMap<String, UnknownVersionRef>,
}

impl VersionManager {
    /// Create new manager
    pub fn new() -> Self {
        Self {
            versions: HashMap::new(),
            active_versions: HashMap::new(),
            transitions: Vec::new(),
            unknown_refs: HashMap::new(),
        }
    }

    /// Create version
    pub fn create_version(
        &mut self,
        object_type: VersionObjectType,
        version_number: VersionNumber,
        content_digest: P3Digest,
        author: P3Digest,
    ) -> P3Result<VersionObject> {
        // Check for version conflicts
        let existing: Vec<_> = self
            .versions
            .values()
            .filter(|v| v.object_type == object_type && v.version_number == version_number)
            .collect();

        if !existing.is_empty() {
            return Err(P3Error::InvalidState {
                reason: format!(
                    "Version {} already exists for type {}",
                    version_number,
                    object_type.name()
                ),
            });
        }

        let mut version = VersionObject::new(object_type, version_number, content_digest, author);

        // Set previous version if there's an active one
        if let Some(active_id) = self.active_versions.get(&version.object_type) {
            version.previous_version = Some(active_id.clone());
        }

        self.versions
            .insert(version.version_id.as_str().to_string(), version.clone());

        Ok(version)
    }

    /// Publish version (start challenge period)
    pub fn publish_version(&mut self, version_id: &VersionId) -> P3Result<()> {
        let version = self.get_version_mut(version_id)?;
        version.publish()
    }

    /// Activate version (after challenge period)
    pub fn activate_version(&mut self, version_id: &VersionId, initiator: P3Digest) -> P3Result<()> {
        // Get object type and previous version first
        let (object_type, has_previous) = {
            let version = self.versions.get(version_id.as_str()).ok_or_else(|| {
                P3Error::VersionNotFound {
                    version_id: version_id.as_str().to_string(),
                }
            })?;
            (version.object_type.clone(), version.previous_version.is_some())
        };

        let previous = self.active_versions.get(&object_type).cloned();

        // Now activate the version
        let version = self.versions.get_mut(version_id.as_str()).ok_or_else(|| {
            P3Error::VersionNotFound {
                version_id: version_id.as_str().to_string(),
            }
        })?;
        version.activate()?;

        // Update active version
        self.active_versions.insert(object_type.clone(), version_id.clone());

        // Record transition
        let transition = VersionTransition {
            transition_id: format!("trans:{}:{}", version_id.as_str(), Utc::now().timestamp_millis()),
            from_version: previous,
            to_version: version_id.clone(),
            object_type,
            transition_type: if has_previous {
                TransitionType::Upgrade
            } else {
                TransitionType::Initial
            },
            transitioned_at: Utc::now(),
            initiated_by: initiator,
            reason: None,
        };

        self.transitions.push(transition);
        Ok(())
    }

    /// Deprecate version
    pub fn deprecate_version(&mut self, version_id: &VersionId) -> P3Result<()> {
        let version = self.get_version_mut(version_id)?;
        version.deprecate()
    }

    /// Revoke version
    pub fn revoke_version(
        &mut self,
        version_id: &VersionId,
        reason: impl Into<String>,
        initiator: P3Digest,
    ) -> P3Result<Option<VersionId>> {
        let version = self.get_version_mut(version_id)?;
        let object_type = version.object_type.clone();
        let previous = version.previous_version.clone();

        version.revoke(reason)?;

        // If this was the active version, rollback to previous
        let rollback_to = if self.active_versions.get(&object_type) == Some(version_id) {
            if let Some(prev_id) = &previous {
                self.active_versions.insert(object_type.clone(), prev_id.clone());

                // Record rollback transition
                let transition = VersionTransition {
                    transition_id: format!(
                        "trans:{}:{}",
                        prev_id.as_str(),
                        Utc::now().timestamp_millis()
                    ),
                    from_version: Some(version_id.clone()),
                    to_version: prev_id.clone(),
                    object_type,
                    transition_type: TransitionType::Rollback,
                    transitioned_at: Utc::now(),
                    initiated_by: initiator,
                    reason: Some("Previous version revoked".to_string()),
                };

                self.transitions.push(transition);
                Some(prev_id.clone())
            } else {
                self.active_versions.remove(&object_type);
                None
            }
        } else {
            None
        };

        Ok(rollback_to)
    }

    /// Get version
    pub fn get_version(&self, version_id: &VersionId) -> Option<&VersionObject> {
        self.versions.get(version_id.as_str())
    }

    /// Get version mutable
    fn get_version_mut(&mut self, version_id: &VersionId) -> P3Result<&mut VersionObject> {
        self.versions.get_mut(version_id.as_str()).ok_or_else(|| {
            P3Error::VersionNotFound {
                version_id: version_id.as_str().to_string(),
            }
        })
    }

    /// Get active version for type
    pub fn get_active(&self, object_type: &VersionObjectType) -> Option<&VersionObject> {
        self.active_versions
            .get(object_type)
            .and_then(|id| self.versions.get(id.as_str()))
    }

    /// Get active version ID for type
    pub fn get_active_id(&self, object_type: &VersionObjectType) -> Option<&VersionId> {
        self.active_versions.get(object_type)
    }

    /// Get all versions of a type
    pub fn versions_of_type(&self, object_type: &VersionObjectType) -> Vec<&VersionObject> {
        self.versions
            .values()
            .filter(|v| &v.object_type == object_type)
            .collect()
    }

    /// Get versions in challenge period
    pub fn versions_in_challenge(&self) -> Vec<&VersionObject> {
        self.versions
            .values()
            .filter(|v| v.status == VersionStatus::ChallengePeriod)
            .collect()
    }

    /// Record unknown version reference
    pub fn record_unknown_ref(
        &mut self,
        version_id: VersionId,
        context: impl Into<String>,
    ) -> &UnknownVersionRef {
        let key = version_id.as_str().to_string();

        if let Some(existing) = self.unknown_refs.get_mut(&key) {
            existing.increment();
            return self.unknown_refs.get(&key).unwrap();
        }

        let unknown_ref = UnknownVersionRef::new(version_id, context);
        self.unknown_refs.insert(key.clone(), unknown_ref);
        self.unknown_refs.get(&key).unwrap()
    }

    /// Resolve unknown version reference
    pub fn resolve_unknown_ref(
        &mut self,
        version_id: &VersionId,
        resolution: UnknownVersionResolution,
    ) -> P3Result<()> {
        let key = version_id.as_str();

        let unknown = self.unknown_refs.get_mut(key).ok_or_else(|| P3Error::NotFound {
            entity: "UnknownVersionRef".to_string(),
            id: key.to_string(),
        })?;

        unknown.resolve(resolution);
        Ok(())
    }

    /// Get unknown references
    pub fn unknown_refs(&self) -> Vec<&UnknownVersionRef> {
        self.unknown_refs
            .values()
            .filter(|r| r.resolution.is_none())
            .collect()
    }

    /// Get version history (transitions)
    pub fn transitions(&self) -> &[VersionTransition] {
        &self.transitions
    }

    /// Get transitions for type
    pub fn transitions_for_type(&self, object_type: &VersionObjectType) -> Vec<&VersionTransition> {
        self.transitions
            .iter()
            .filter(|t| &t.object_type == object_type)
            .collect()
    }

    /// Force activate (emergency)
    pub fn force_activate(
        &mut self,
        version_id: &VersionId,
        initiator: P3Digest,
        reason: impl Into<String>,
    ) -> P3Result<()> {
        // Get object type first
        let object_type = {
            let version = self.versions.get(version_id.as_str()).ok_or_else(|| {
                P3Error::VersionNotFound {
                    version_id: version_id.as_str().to_string(),
                }
            })?;
            version.object_type.clone()
        };

        let previous = self.active_versions.get(&object_type).cloned();

        // Now modify the version
        let version = self.versions.get_mut(version_id.as_str()).ok_or_else(|| {
            P3Error::VersionNotFound {
                version_id: version_id.as_str().to_string(),
            }
        })?;
        version.status = VersionStatus::Active;
        version.activated_at = Some(Utc::now());

        self.active_versions.insert(object_type.clone(), version_id.clone());

        // Record emergency transition
        let transition = VersionTransition {
            transition_id: format!(
                "trans:{}:{}",
                version_id.as_str(),
                Utc::now().timestamp_millis()
            ),
            from_version: previous,
            to_version: version_id.clone(),
            object_type,
            transition_type: TransitionType::EmergencyRevoke,
            transitioned_at: Utc::now(),
            initiated_by: initiator,
            reason: Some(reason.into()),
        };

        self.transitions.push(transition);
        Ok(())
    }

    /// Check expiring challenge windows
    pub fn check_challenge_windows(&self, now: &DateTime<Utc>) -> Vec<&VersionObject> {
        self.versions
            .values()
            .filter(|v| {
                v.status == VersionStatus::ChallengePeriod
                    && v.challenge_window_end
                        .map(|end| end <= *now)
                        .unwrap_or(false)
            })
            .collect()
    }

    /// Auto-activate versions with expired challenge windows
    pub fn auto_activate_expired_challenges(
        &mut self,
        now: &DateTime<Utc>,
        system_initiator: P3Digest,
    ) -> Vec<VersionId> {
        let to_activate: Vec<_> = self
            .versions
            .values()
            .filter(|v| {
                v.status == VersionStatus::ChallengePeriod
                    && v.challenge_window_end
                        .map(|end| end <= *now)
                        .unwrap_or(false)
            })
            .map(|v| v.version_id.clone())
            .collect();

        let mut activated = Vec::new();

        for version_id in to_activate {
            if self.activate_version(&version_id, system_initiator.clone()).is_ok() {
                activated.push(version_id);
            }
        }

        activated
    }

    /// Get version count
    pub fn count(&self) -> usize {
        self.versions.len()
    }

    /// Get active version count
    pub fn active_count(&self) -> usize {
        self.active_versions.len()
    }
}

impl Default for VersionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_manager_creation() {
        let manager = VersionManager::new();
        assert_eq!(manager.count(), 0);
    }

    #[test]
    fn test_create_version() {
        let mut manager = VersionManager::new();

        let version = manager
            .create_version(
                VersionObjectType::ContributionRule,
                VersionNumber::new(1, 0, 0),
                P3Digest::zero(),
                P3Digest::zero(),
            )
            .unwrap();

        assert_eq!(version.status, VersionStatus::Draft);
        assert!(manager.get_version(&version.version_id).is_some());
    }

    #[test]
    fn test_publish_and_activate() {
        let mut manager = VersionManager::new();

        let version = manager
            .create_version(
                VersionObjectType::ThresholdConfig,
                VersionNumber::new(1, 0, 0),
                P3Digest::zero(),
                P3Digest::zero(),
            )
            .unwrap();

        manager.publish_version(&version.version_id).unwrap();

        let published = manager.get_version(&version.version_id).unwrap();
        assert_eq!(published.status, VersionStatus::ChallengePeriod);
    }

    #[test]
    fn test_active_version_tracking() {
        let mut manager = VersionManager::new();

        let v1 = manager
            .create_version(
                VersionObjectType::ContributionRule,
                VersionNumber::new(1, 0, 0),
                P3Digest::zero(),
                P3Digest::zero(),
            )
            .unwrap();

        manager.publish_version(&v1.version_id).unwrap();

        // Force activate for testing
        manager
            .force_activate(&v1.version_id, P3Digest::zero(), "Initial setup")
            .unwrap();

        assert!(manager
            .get_active(&VersionObjectType::ContributionRule)
            .is_some());
    }

    #[test]
    fn test_version_upgrade() {
        let mut manager = VersionManager::new();

        // Create and activate v1
        let v1 = manager
            .create_version(
                VersionObjectType::AttributionRule,
                VersionNumber::new(1, 0, 0),
                P3Digest::zero(),
                P3Digest::zero(),
            )
            .unwrap();

        manager
            .force_activate(&v1.version_id, P3Digest::zero(), "Initial")
            .unwrap();

        // Create v2
        let v2 = manager
            .create_version(
                VersionObjectType::AttributionRule,
                VersionNumber::new(2, 0, 0),
                P3Digest::zero(),
                P3Digest::zero(),
            )
            .unwrap();

        // Should have previous version set
        let v2_obj = manager.get_version(&v2.version_id).unwrap();
        assert_eq!(v2_obj.previous_version, Some(v1.version_id.clone()));
    }

    #[test]
    fn test_unknown_version_tracking() {
        let mut manager = VersionManager::new();

        let unknown_id = VersionId::new("ver:missing:1.0.0");

        manager.record_unknown_ref(unknown_id.clone(), "test context");
        manager.record_unknown_ref(unknown_id.clone(), "another context");

        let refs = manager.unknown_refs();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].reference_count, 2);
    }

    #[test]
    fn test_revoke_and_rollback() {
        let mut manager = VersionManager::new();

        // Create and activate v1
        let v1 = manager
            .create_version(
                VersionObjectType::TreasuryPolicy,
                VersionNumber::new(1, 0, 0),
                P3Digest::zero(),
                P3Digest::zero(),
            )
            .unwrap();

        manager
            .force_activate(&v1.version_id, P3Digest::zero(), "Initial")
            .unwrap();

        // Create and activate v2
        let v2 = manager
            .create_version(
                VersionObjectType::TreasuryPolicy,
                VersionNumber::new(2, 0, 0),
                P3Digest::zero(),
                P3Digest::zero(),
            )
            .unwrap();

        manager
            .force_activate(&v2.version_id, P3Digest::zero(), "Upgrade")
            .unwrap();

        // Revoke v2 - should rollback to v1
        let rollback = manager
            .revoke_version(&v2.version_id, "Security issue", P3Digest::zero())
            .unwrap();

        assert_eq!(rollback, Some(v1.version_id.clone()));
        assert_eq!(
            manager.get_active_id(&VersionObjectType::TreasuryPolicy),
            Some(&v1.version_id)
        );
    }

    #[test]
    fn test_transitions_tracking() {
        let mut manager = VersionManager::new();

        let v1 = manager
            .create_version(
                VersionObjectType::GovernanceRule,
                VersionNumber::new(1, 0, 0),
                P3Digest::zero(),
                P3Digest::zero(),
            )
            .unwrap();

        manager
            .force_activate(&v1.version_id, P3Digest::zero(), "Initial")
            .unwrap();

        let transitions = manager.transitions_for_type(&VersionObjectType::GovernanceRule);
        assert!(!transitions.is_empty());
    }
}
