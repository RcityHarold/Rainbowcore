//! Version Registry
//!
//! Central registry for version governance with integrated challenge management.

use super::{
    VersionManager, VersionObject, VersionObjectType, VersionNumber, VersionStatus,
    ChallengeManager, Challenge, ChallengeReason, ChallengeStatus, ChallengeResolution,
    ChallengeAction, Dispute, DisputeVote, DisputeOutcome,
};
use crate::error::{P3Error, P3Result};
use crate::types::{P3Digest, VersionId};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Version registry - unified governance interface
pub struct VersionRegistry {
    /// Version manager
    version_manager: VersionManager,
    /// Challenge manager
    challenge_manager: ChallengeManager,
    /// Registry configuration
    config: RegistryConfig,
    /// Event log
    events: Vec<RegistryEvent>,
}

impl VersionRegistry {
    /// Create new registry
    pub fn new() -> Self {
        Self {
            version_manager: VersionManager::new(),
            challenge_manager: ChallengeManager::new(),
            config: RegistryConfig::default(),
            events: Vec::new(),
        }
    }

    /// With custom config
    pub fn with_config(mut self, config: RegistryConfig) -> Self {
        self.config = config;
        self
    }

    /// Create and register version
    pub fn register_version(
        &mut self,
        object_type: VersionObjectType,
        version_number: VersionNumber,
        content_digest: P3Digest,
        author: P3Digest,
    ) -> P3Result<VersionId> {
        let version = self.version_manager.create_version(
            object_type.clone(),
            version_number.clone(),
            content_digest,
            author.clone(),
        )?;

        let version_id = version.version_id.clone();

        self.log_event(RegistryEvent::VersionCreated {
            version_id: version_id.clone(),
            object_type,
            version_number,
            author,
            timestamp: Utc::now(),
        });

        Ok(version_id)
    }

    /// Publish version for challenge period
    pub fn publish_version(&mut self, version_id: &VersionId) -> P3Result<DateTime<Utc>> {
        self.version_manager.publish_version(version_id)?;

        let version = self.version_manager.get_version(version_id).unwrap();
        let challenge_end = version.challenge_window_end.unwrap();

        self.log_event(RegistryEvent::VersionPublished {
            version_id: version_id.clone(),
            challenge_window_end: challenge_end,
            timestamp: Utc::now(),
        });

        Ok(challenge_end)
    }

    /// Challenge a version during challenge period
    pub fn challenge_version(
        &mut self,
        version_id: &VersionId,
        challenger: P3Digest,
        reason: ChallengeReason,
        evidence_digest: Option<P3Digest>,
    ) -> P3Result<String> {
        // Verify version is challengeable
        let version = self.version_manager.get_version(version_id).ok_or_else(|| {
            P3Error::VersionNotFound {
                version_id: version_id.as_str().to_string(),
            }
        })?;

        if !version.is_challenge_window_open() {
            return Err(P3Error::InvalidState {
                reason: "Challenge window is not open".to_string(),
            });
        }

        let challenge = self.challenge_manager.create_challenge(
            version_id.clone(),
            challenger.clone(),
            reason.clone(),
            evidence_digest,
        )?;

        let challenge_id = challenge.challenge_id.clone();

        self.log_event(RegistryEvent::ChallengeCreated {
            challenge_id: challenge_id.clone(),
            version_id: version_id.clone(),
            challenger,
            reason,
            timestamp: Utc::now(),
        });

        Ok(challenge_id)
    }

    /// Resolve a challenge
    pub fn resolve_challenge(
        &mut self,
        challenge_id: &str,
        resolution: ChallengeResolution,
        resolver: P3Digest,
    ) -> P3Result<()> {
        // If challenge is accepted, may need to revoke version
        if let ChallengeResolution::Accepted { action } = &resolution {
            let challenge = self.challenge_manager.get_challenge(challenge_id).ok_or_else(|| {
                P3Error::NotFound {
                    entity: "Challenge".to_string(),
                    id: challenge_id.to_string(),
                }
            })?;

            if matches!(action, ChallengeAction::Revoke) {
                self.version_manager.revoke_version(
                    &challenge.version_id,
                    "Revoked due to accepted challenge",
                    resolver.clone(),
                )?;
            }
        }

        self.challenge_manager
            .resolve(challenge_id, resolution.clone(), resolver.clone())?;

        self.log_event(RegistryEvent::ChallengeResolved {
            challenge_id: challenge_id.to_string(),
            resolution,
            resolver,
            timestamp: Utc::now(),
        });

        Ok(())
    }

    /// Escalate challenge to dispute
    pub fn escalate_challenge(&mut self, challenge_id: &str, reason: impl Into<String>) -> P3Result<String> {
        let dispute = self
            .challenge_manager
            .escalate_to_dispute(challenge_id, reason)?;

        let dispute_id = dispute.dispute_id.clone();

        self.log_event(RegistryEvent::DisputeCreated {
            dispute_id: dispute_id.clone(),
            challenge_id: challenge_id.to_string(),
            timestamp: Utc::now(),
        });

        Ok(dispute_id)
    }

    /// Vote on dispute
    pub fn vote_on_dispute(
        &mut self,
        dispute_id: &str,
        voter: P3Digest,
        vote: DisputeVote,
        weight: rust_decimal::Decimal,
    ) -> P3Result<()> {
        self.challenge_manager.vote(dispute_id, voter, vote, weight)
    }

    /// Finalize dispute
    pub fn finalize_dispute(&mut self, dispute_id: &str) -> P3Result<DisputeOutcome> {
        let outcome = self.challenge_manager.tally_dispute(dispute_id)?;

        // If challenge upheld, revoke the version
        if outcome == DisputeOutcome::ChallengeUpheld {
            let dispute = self.challenge_manager.get_dispute(dispute_id).unwrap();
            self.version_manager.revoke_version(
                &dispute.version_id,
                "Revoked due to successful dispute",
                P3Digest::zero(), // System action
            )?;
        }

        self.log_event(RegistryEvent::DisputeResolved {
            dispute_id: dispute_id.to_string(),
            outcome: outcome.clone(),
            timestamp: Utc::now(),
        });

        Ok(outcome)
    }

    /// Try to activate version (if challenge period ended)
    pub fn try_activate_version(&mut self, version_id: &VersionId, initiator: P3Digest) -> P3Result<bool> {
        // Check for open challenges
        let challenges = self.challenge_manager.challenges_for_version(version_id);
        let has_open = challenges.iter().any(|c| c.status == ChallengeStatus::Open);

        if has_open {
            return Err(P3Error::InvalidState {
                reason: "Version has open challenges".to_string(),
            });
        }

        self.version_manager.activate_version(version_id, initiator.clone())?;

        self.log_event(RegistryEvent::VersionActivated {
            version_id: version_id.clone(),
            initiator,
            timestamp: Utc::now(),
        });

        Ok(true)
    }

    /// Force activate (emergency, bypasses challenges)
    pub fn emergency_activate(
        &mut self,
        version_id: &VersionId,
        initiator: P3Digest,
        reason: impl Into<String>,
    ) -> P3Result<()> {
        let reason_str = reason.into();
        self.version_manager
            .force_activate(version_id, initiator.clone(), reason_str.clone())?;

        self.log_event(RegistryEvent::EmergencyAction {
            action: "force_activate".to_string(),
            version_id: version_id.clone(),
            initiator,
            reason: reason_str,
            timestamp: Utc::now(),
        });

        Ok(())
    }

    /// Get active version
    pub fn get_active(&self, object_type: &VersionObjectType) -> Option<&VersionObject> {
        self.version_manager.get_active(object_type)
    }

    /// Get version
    pub fn get_version(&self, version_id: &VersionId) -> Option<&VersionObject> {
        self.version_manager.get_version(version_id)
    }

    /// Get or resolve version (handles unknown versions)
    pub fn get_or_resolve(
        &mut self,
        version_id: &VersionId,
        context: impl Into<String>,
    ) -> P3Result<&VersionObject> {
        // Check if version exists first
        let exists = self.version_manager.get_version(version_id).is_some();

        if !exists {
            // Record unknown reference
            self.version_manager
                .record_unknown_ref(version_id.clone(), context);

            return Err(P3Error::VersionNotFound {
                version_id: version_id.as_str().to_string(),
            });
        }

        // Now we can safely return the reference
        Ok(self.version_manager.get_version(version_id).unwrap())
    }

    /// Get fallback version for unknown
    pub fn get_with_fallback(
        &mut self,
        version_id: &VersionId,
        object_type: &VersionObjectType,
        context: impl Into<String>,
    ) -> Option<&VersionObject> {
        // Check if version exists first
        let exists = self.version_manager.get_version(version_id).is_some();

        if exists {
            return self.version_manager.get_version(version_id);
        }

        // Record unknown and try to get active as fallback
        self.version_manager
            .record_unknown_ref(version_id.clone(), context);

        self.version_manager.get_active(object_type)
    }

    /// Get challenge
    pub fn get_challenge(&self, challenge_id: &str) -> Option<&Challenge> {
        self.challenge_manager.get_challenge(challenge_id)
    }

    /// Get dispute
    pub fn get_dispute(&self, dispute_id: &str) -> Option<&Dispute> {
        self.challenge_manager.get_dispute(dispute_id)
    }

    /// Process periodic tasks
    pub fn process_periodic(&mut self, now: &DateTime<Utc>) -> PeriodicResult {
        let mut result = PeriodicResult::default();

        // Auto-activate versions with expired challenge windows (if no open challenges)
        let ready_to_activate: Vec<_> = self
            .version_manager
            .check_challenge_windows(now)
            .into_iter()
            .filter(|v| {
                let challenges = self.challenge_manager.challenges_for_version(&v.version_id);
                !challenges.iter().any(|c| c.status == ChallengeStatus::Open)
            })
            .map(|v| v.version_id.clone())
            .collect();

        for version_id in ready_to_activate {
            if self
                .version_manager
                .activate_version(&version_id, P3Digest::zero())
                .is_ok()
            {
                result.activated_versions.push(version_id);
            }
        }

        // Process expired challenges
        result.expired_challenges = self.challenge_manager.process_expired(now);

        result
    }

    /// Get events
    pub fn events(&self) -> &[RegistryEvent] {
        &self.events
    }

    /// Get events since timestamp
    pub fn events_since(&self, since: &DateTime<Utc>) -> Vec<&RegistryEvent> {
        self.events.iter().filter(|e| e.timestamp() >= since).collect()
    }

    /// Get registry stats
    pub fn stats(&self) -> RegistryStats {
        RegistryStats {
            total_versions: self.version_manager.count(),
            active_versions: self.version_manager.active_count(),
            versions_in_challenge: self.version_manager.versions_in_challenge().len(),
            open_challenges: self.challenge_manager.open_challenge_count(),
            active_disputes: self.challenge_manager.active_dispute_count(),
            unknown_refs: self.version_manager.unknown_refs().len(),
            total_events: self.events.len(),
        }
    }

    /// Log event
    fn log_event(&mut self, event: RegistryEvent) {
        self.events.push(event);

        // Trim if needed
        if self.events.len() > self.config.max_event_history {
            self.events.remove(0);
        }
    }
}

impl Default for VersionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Registry configuration
#[derive(Clone, Debug)]
pub struct RegistryConfig {
    /// Max event history
    pub max_event_history: usize,
    /// Auto-activate on challenge window expiry
    pub auto_activate: bool,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            max_event_history: 1000,
            auto_activate: true,
        }
    }
}

/// Registry event
#[derive(Clone, Debug)]
pub enum RegistryEvent {
    VersionCreated {
        version_id: VersionId,
        object_type: VersionObjectType,
        version_number: VersionNumber,
        author: P3Digest,
        timestamp: DateTime<Utc>,
    },
    VersionPublished {
        version_id: VersionId,
        challenge_window_end: DateTime<Utc>,
        timestamp: DateTime<Utc>,
    },
    VersionActivated {
        version_id: VersionId,
        initiator: P3Digest,
        timestamp: DateTime<Utc>,
    },
    VersionRevoked {
        version_id: VersionId,
        reason: String,
        timestamp: DateTime<Utc>,
    },
    ChallengeCreated {
        challenge_id: String,
        version_id: VersionId,
        challenger: P3Digest,
        reason: ChallengeReason,
        timestamp: DateTime<Utc>,
    },
    ChallengeResolved {
        challenge_id: String,
        resolution: ChallengeResolution,
        resolver: P3Digest,
        timestamp: DateTime<Utc>,
    },
    DisputeCreated {
        dispute_id: String,
        challenge_id: String,
        timestamp: DateTime<Utc>,
    },
    DisputeResolved {
        dispute_id: String,
        outcome: DisputeOutcome,
        timestamp: DateTime<Utc>,
    },
    EmergencyAction {
        action: String,
        version_id: VersionId,
        initiator: P3Digest,
        reason: String,
        timestamp: DateTime<Utc>,
    },
}

impl RegistryEvent {
    /// Get event timestamp
    pub fn timestamp(&self) -> &DateTime<Utc> {
        match self {
            RegistryEvent::VersionCreated { timestamp, .. } => timestamp,
            RegistryEvent::VersionPublished { timestamp, .. } => timestamp,
            RegistryEvent::VersionActivated { timestamp, .. } => timestamp,
            RegistryEvent::VersionRevoked { timestamp, .. } => timestamp,
            RegistryEvent::ChallengeCreated { timestamp, .. } => timestamp,
            RegistryEvent::ChallengeResolved { timestamp, .. } => timestamp,
            RegistryEvent::DisputeCreated { timestamp, .. } => timestamp,
            RegistryEvent::DisputeResolved { timestamp, .. } => timestamp,
            RegistryEvent::EmergencyAction { timestamp, .. } => timestamp,
        }
    }
}

/// Periodic processing result
#[derive(Clone, Debug, Default)]
pub struct PeriodicResult {
    /// Versions auto-activated
    pub activated_versions: Vec<VersionId>,
    /// Challenges expired
    pub expired_challenges: Vec<String>,
}

/// Registry statistics
#[derive(Clone, Debug)]
pub struct RegistryStats {
    /// Total versions
    pub total_versions: usize,
    /// Active versions
    pub active_versions: usize,
    /// Versions in challenge period
    pub versions_in_challenge: usize,
    /// Open challenges
    pub open_challenges: usize,
    /// Active disputes
    pub active_disputes: usize,
    /// Unknown version references
    pub unknown_refs: usize,
    /// Total events
    pub total_events: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal::Decimal;

    #[test]
    fn test_registry_creation() {
        let registry = VersionRegistry::new();
        let stats = registry.stats();
        assert_eq!(stats.total_versions, 0);
    }

    #[test]
    fn test_register_and_publish() {
        let mut registry = VersionRegistry::new();

        let version_id = registry
            .register_version(
                VersionObjectType::ContributionRule,
                VersionNumber::new(1, 0, 0),
                P3Digest::zero(),
                P3Digest::zero(),
            )
            .unwrap();

        let challenge_end = registry.publish_version(&version_id).unwrap();
        assert!(challenge_end > Utc::now());

        let stats = registry.stats();
        assert_eq!(stats.total_versions, 1);
        assert_eq!(stats.versions_in_challenge, 1);
    }

    #[test]
    fn test_challenge_flow() {
        let mut registry = VersionRegistry::new();

        let version_id = registry
            .register_version(
                VersionObjectType::AttributionRule,
                VersionNumber::new(1, 0, 0),
                P3Digest::zero(),
                P3Digest::zero(),
            )
            .unwrap();

        registry.publish_version(&version_id).unwrap();

        let challenge_id = registry
            .challenge_version(
                &version_id,
                P3Digest::zero(),
                ChallengeReason::TechnicalError,
                None,
            )
            .unwrap();

        let stats = registry.stats();
        assert_eq!(stats.open_challenges, 1);

        registry
            .resolve_challenge(
                &challenge_id,
                ChallengeResolution::Rejected {
                    reason: "Invalid claim".to_string(),
                },
                P3Digest::zero(),
            )
            .unwrap();

        let stats = registry.stats();
        assert_eq!(stats.open_challenges, 0);
    }

    #[test]
    fn test_dispute_flow() {
        let mut registry = VersionRegistry::new()
            .with_config(RegistryConfig {
                max_event_history: 100,
                auto_activate: true,
            });

        let version_id = registry
            .register_version(
                VersionObjectType::TreasuryPolicy,
                VersionNumber::new(1, 0, 0),
                P3Digest::zero(),
                P3Digest::zero(),
            )
            .unwrap();

        registry.publish_version(&version_id).unwrap();

        let challenge_id = registry
            .challenge_version(
                &version_id,
                P3Digest::zero(),
                ChallengeReason::Unfairness,
                None,
            )
            .unwrap();

        let dispute_id = registry
            .escalate_challenge(&challenge_id, "Needs community vote")
            .unwrap();

        // Vote
        registry
            .vote_on_dispute(&dispute_id, P3Digest::zero(), DisputeVote::Approve, Decimal::ONE)
            .unwrap();

        let stats = registry.stats();
        assert_eq!(stats.active_disputes, 1);
    }

    #[test]
    fn test_emergency_activate() {
        let mut registry = VersionRegistry::new();

        let version_id = registry
            .register_version(
                VersionObjectType::GovernanceRule,
                VersionNumber::new(1, 0, 0),
                P3Digest::zero(),
                P3Digest::zero(),
            )
            .unwrap();

        registry
            .emergency_activate(&version_id, P3Digest::zero(), "Critical update required")
            .unwrap();

        let version = registry.get_version(&version_id).unwrap();
        assert_eq!(version.status, VersionStatus::Active);
    }

    #[test]
    fn test_fallback_resolution() {
        let mut registry = VersionRegistry::new();

        // Create active version
        let active_id = registry
            .register_version(
                VersionObjectType::ThresholdConfig,
                VersionNumber::new(1, 0, 0),
                P3Digest::zero(),
                P3Digest::zero(),
            )
            .unwrap();

        registry
            .emergency_activate(&active_id, P3Digest::zero(), "Setup")
            .unwrap();

        // Try to get unknown version
        let unknown_id = VersionId::new("ver:unknown:1.0.0");

        let fallback = registry.get_with_fallback(
            &unknown_id,
            &VersionObjectType::ThresholdConfig,
            "test lookup",
        );

        assert!(fallback.is_some());
        assert_eq!(fallback.unwrap().version_id, active_id);

        let stats = registry.stats();
        assert_eq!(stats.unknown_refs, 1);
    }

    #[test]
    fn test_event_logging() {
        let mut registry = VersionRegistry::new();

        registry
            .register_version(
                VersionObjectType::ClearanceRule,
                VersionNumber::new(1, 0, 0),
                P3Digest::zero(),
                P3Digest::zero(),
            )
            .unwrap();

        assert!(!registry.events().is_empty());
        assert!(matches!(
            registry.events()[0],
            RegistryEvent::VersionCreated { .. }
        ));
    }
}
