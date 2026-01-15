//! Challenge and Dispute System
//!
//! Implements challenge → dispute mechanism for version governance.

use crate::error::{P3Error, P3Result};
use crate::types::{P3Digest, VersionId};
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use std::collections::HashMap;

/// Challenge manager
pub struct ChallengeManager {
    /// Active challenges
    challenges: HashMap<String, Challenge>,
    /// Disputes escalated from challenges
    disputes: HashMap<String, Dispute>,
    /// Challenge config
    config: ChallengeConfig,
}

impl ChallengeManager {
    /// Create new manager
    pub fn new() -> Self {
        Self {
            challenges: HashMap::new(),
            disputes: HashMap::new(),
            config: ChallengeConfig::default(),
        }
    }

    /// With custom config
    pub fn with_config(mut self, config: ChallengeConfig) -> Self {
        self.config = config;
        self
    }

    /// Create challenge against version
    pub fn create_challenge(
        &mut self,
        version_id: VersionId,
        challenger: P3Digest,
        reason: ChallengeReason,
        evidence_digest: Option<P3Digest>,
    ) -> P3Result<Challenge> {
        let challenge_id = format!(
            "challenge:{}:{}",
            version_id.as_str(),
            Utc::now().timestamp_millis()
        );

        let now = Utc::now();
        let response_deadline = now + chrono::Duration::hours(self.config.response_window_hours);

        let challenge = Challenge {
            challenge_id: challenge_id.clone(),
            version_id,
            challenger,
            reason,
            evidence_digest,
            status: ChallengeStatus::Open,
            created_at: now,
            response_deadline,
            responses: Vec::new(),
            resolution: None,
            dispute_id: None,
        };

        self.challenges.insert(challenge_id.clone(), challenge.clone());
        Ok(challenge)
    }

    /// Respond to challenge
    pub fn respond(
        &mut self,
        challenge_id: &str,
        responder: P3Digest,
        response_type: ChallengeResponseType,
        content_digest: Option<P3Digest>,
    ) -> P3Result<()> {
        let challenge = self.challenges.get_mut(challenge_id).ok_or_else(|| {
            P3Error::NotFound {
                entity: "Challenge".to_string(),
                id: challenge_id.to_string(),
            }
        })?;

        if challenge.status != ChallengeStatus::Open {
            return Err(P3Error::InvalidState {
                reason: format!("Challenge is in {:?} status", challenge.status),
            });
        }

        let response = ChallengeResponse {
            response_id: format!("resp:{}:{}", challenge_id, Utc::now().timestamp_millis()),
            responder,
            response_type,
            content_digest,
            responded_at: Utc::now(),
        };

        challenge.responses.push(response);
        Ok(())
    }

    /// Resolve challenge
    pub fn resolve(
        &mut self,
        challenge_id: &str,
        resolution: ChallengeResolution,
        resolver: P3Digest,
    ) -> P3Result<()> {
        let challenge = self.challenges.get_mut(challenge_id).ok_or_else(|| {
            P3Error::NotFound {
                entity: "Challenge".to_string(),
                id: challenge_id.to_string(),
            }
        })?;

        if challenge.status != ChallengeStatus::Open
            && challenge.status != ChallengeStatus::UnderReview
        {
            return Err(P3Error::InvalidState {
                reason: format!("Cannot resolve challenge in {:?} status", challenge.status),
            });
        }

        challenge.status = match &resolution {
            ChallengeResolution::Accepted { .. } => ChallengeStatus::Accepted,
            ChallengeResolution::Rejected { .. } => ChallengeStatus::Rejected,
            ChallengeResolution::Escalated { dispute_id } => {
                challenge.dispute_id = Some(dispute_id.clone());
                ChallengeStatus::Escalated
            }
        };

        challenge.resolution = Some(ResolvedChallenge {
            resolution,
            resolved_at: Utc::now(),
            resolver,
        });

        Ok(())
    }

    /// Escalate challenge to dispute
    pub fn escalate_to_dispute(
        &mut self,
        challenge_id: &str,
        escalation_reason: impl Into<String>,
    ) -> P3Result<Dispute> {
        let challenge = self.challenges.get(challenge_id).ok_or_else(|| {
            P3Error::NotFound {
                entity: "Challenge".to_string(),
                id: challenge_id.to_string(),
            }
        })?;

        if challenge.status != ChallengeStatus::Open {
            return Err(P3Error::InvalidState {
                reason: "Can only escalate open challenges".to_string(),
            });
        }

        let dispute_id = format!(
            "dispute:{}:{}",
            challenge.version_id.as_str(),
            Utc::now().timestamp_millis()
        );

        let now = Utc::now();
        let voting_deadline = now + chrono::Duration::hours(self.config.dispute_voting_hours);

        let dispute = Dispute {
            dispute_id: dispute_id.clone(),
            challenge_id: challenge_id.to_string(),
            version_id: challenge.version_id.clone(),
            escalation_reason: escalation_reason.into(),
            status: DisputeStatus::Voting,
            created_at: now,
            voting_deadline,
            votes: Vec::new(),
            resolution: None,
            quorum_required: self.config.dispute_quorum,
        };

        self.disputes.insert(dispute_id.clone(), dispute.clone());

        // Update challenge status
        if let Some(c) = self.challenges.get_mut(challenge_id) {
            c.dispute_id = Some(dispute_id);
            c.status = ChallengeStatus::Escalated;
        }

        Ok(dispute)
    }

    /// Cast vote on dispute
    pub fn vote(
        &mut self,
        dispute_id: &str,
        voter: P3Digest,
        vote: DisputeVote,
        weight: Decimal,
    ) -> P3Result<()> {
        let dispute = self.disputes.get_mut(dispute_id).ok_or_else(|| {
            P3Error::NotFound {
                entity: "Dispute".to_string(),
                id: dispute_id.to_string(),
            }
        })?;

        if dispute.status != DisputeStatus::Voting {
            return Err(P3Error::InvalidState {
                reason: format!("Dispute is in {:?} status", dispute.status),
            });
        }

        // Check if already voted
        if dispute.votes.iter().any(|v| v.voter == voter) {
            return Err(P3Error::InvalidState {
                reason: "Already voted on this dispute".to_string(),
            });
        }

        dispute.votes.push(DisputeVoteRecord {
            voter,
            vote,
            weight,
            voted_at: Utc::now(),
        });

        Ok(())
    }

    /// Tally votes and resolve dispute
    pub fn tally_dispute(&mut self, dispute_id: &str) -> P3Result<DisputeOutcome> {
        let dispute = self.disputes.get_mut(dispute_id).ok_or_else(|| {
            P3Error::NotFound {
                entity: "Dispute".to_string(),
                id: dispute_id.to_string(),
            }
        })?;

        if dispute.status != DisputeStatus::Voting {
            return Err(P3Error::InvalidState {
                reason: "Dispute is not in voting status".to_string(),
            });
        }

        let total_weight: Decimal = dispute.votes.iter().map(|v| v.weight).sum();
        let approve_weight: Decimal = dispute
            .votes
            .iter()
            .filter(|v| v.vote == DisputeVote::Approve)
            .map(|v| v.weight)
            .sum();
        let reject_weight: Decimal = dispute
            .votes
            .iter()
            .filter(|v| v.vote == DisputeVote::Reject)
            .map(|v| v.weight)
            .sum();

        // Check quorum
        if total_weight < dispute.quorum_required {
            dispute.status = DisputeStatus::NoQuorum;
            dispute.resolution = Some(DisputeResolution {
                outcome: DisputeOutcome::NoQuorum,
                resolved_at: Utc::now(),
                total_votes: dispute.votes.len() as u32,
                total_weight,
                approve_weight,
                reject_weight,
            });
            return Ok(DisputeOutcome::NoQuorum);
        }

        // Determine outcome
        let outcome = if approve_weight > reject_weight {
            DisputeOutcome::ChallengeUpheld
        } else if reject_weight > approve_weight {
            DisputeOutcome::ChallengeRejected
        } else {
            DisputeOutcome::Tie
        };

        dispute.status = DisputeStatus::Resolved;
        dispute.resolution = Some(DisputeResolution {
            outcome: outcome.clone(),
            resolved_at: Utc::now(),
            total_votes: dispute.votes.len() as u32,
            total_weight,
            approve_weight,
            reject_weight,
        });

        Ok(outcome)
    }

    /// Get challenge
    pub fn get_challenge(&self, challenge_id: &str) -> Option<&Challenge> {
        self.challenges.get(challenge_id)
    }

    /// Get dispute
    pub fn get_dispute(&self, dispute_id: &str) -> Option<&Dispute> {
        self.disputes.get(dispute_id)
    }

    /// Get challenges for version
    pub fn challenges_for_version(&self, version_id: &VersionId) -> Vec<&Challenge> {
        self.challenges
            .values()
            .filter(|c| &c.version_id == version_id)
            .collect()
    }

    /// Get open challenges count
    pub fn open_challenge_count(&self) -> usize {
        self.challenges
            .values()
            .filter(|c| c.status == ChallengeStatus::Open)
            .count()
    }

    /// Get active disputes count
    pub fn active_dispute_count(&self) -> usize {
        self.disputes
            .values()
            .filter(|d| d.status == DisputeStatus::Voting)
            .count()
    }

    /// Process expired challenges
    pub fn process_expired(&mut self, now: &DateTime<Utc>) -> Vec<String> {
        let mut expired = Vec::new();

        for challenge in self.challenges.values_mut() {
            if challenge.status == ChallengeStatus::Open && *now > challenge.response_deadline {
                // Auto-reject if no responses
                if challenge.responses.is_empty() {
                    challenge.status = ChallengeStatus::Expired;
                    expired.push(challenge.challenge_id.clone());
                }
            }
        }

        expired
    }
}

impl Default for ChallengeManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Challenge configuration
#[derive(Clone, Debug)]
pub struct ChallengeConfig {
    /// Response window in hours
    pub response_window_hours: i64,
    /// Dispute voting period in hours
    pub dispute_voting_hours: i64,
    /// Required quorum for disputes
    pub dispute_quorum: Decimal,
    /// Minimum stake to challenge
    pub min_challenge_stake: Decimal,
}

impl Default for ChallengeConfig {
    fn default() -> Self {
        Self {
            response_window_hours: 48,
            dispute_voting_hours: 72,
            dispute_quorum: Decimal::new(20, 2), // 20%
            min_challenge_stake: Decimal::ZERO,
        }
    }
}

/// Challenge
#[derive(Clone, Debug)]
pub struct Challenge {
    /// Challenge ID
    pub challenge_id: String,
    /// Version being challenged
    pub version_id: VersionId,
    /// Challenger
    pub challenger: P3Digest,
    /// Challenge reason
    pub reason: ChallengeReason,
    /// Evidence digest
    pub evidence_digest: Option<P3Digest>,
    /// Status
    pub status: ChallengeStatus,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Response deadline
    pub response_deadline: DateTime<Utc>,
    /// Responses
    pub responses: Vec<ChallengeResponse>,
    /// Resolution
    pub resolution: Option<ResolvedChallenge>,
    /// Dispute ID (if escalated)
    pub dispute_id: Option<String>,
}

/// Challenge reason
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChallengeReason {
    /// Technical error in version
    TechnicalError,
    /// Unfair or biased rules
    Unfairness,
    /// Security vulnerability
    SecurityVulnerability,
    /// Incompatibility with existing system
    Incompatibility,
    /// Process violation
    ProcessViolation,
    /// Other reason
    Other(String),
}

/// Challenge status
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChallengeStatus {
    /// Open for responses
    Open,
    /// Under review
    UnderReview,
    /// Challenge accepted
    Accepted,
    /// Challenge rejected
    Rejected,
    /// Escalated to dispute
    Escalated,
    /// Expired without resolution
    Expired,
}

/// Challenge response
#[derive(Clone, Debug)]
pub struct ChallengeResponse {
    /// Response ID
    pub response_id: String,
    /// Responder
    pub responder: P3Digest,
    /// Response type
    pub response_type: ChallengeResponseType,
    /// Content digest
    pub content_digest: Option<P3Digest>,
    /// Responded at
    pub responded_at: DateTime<Utc>,
}

/// Challenge response type
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChallengeResponseType {
    /// Accept the challenge
    Accept,
    /// Reject the challenge
    Reject,
    /// Request more information
    RequestInfo,
    /// Propose modification
    ProposeModification,
}

/// Resolved challenge
#[derive(Clone, Debug)]
pub struct ResolvedChallenge {
    /// Resolution
    pub resolution: ChallengeResolution,
    /// Resolved at
    pub resolved_at: DateTime<Utc>,
    /// Resolver
    pub resolver: P3Digest,
}

/// Challenge resolution
#[derive(Clone, Debug)]
pub enum ChallengeResolution {
    /// Challenge accepted - version will be modified/revoked
    Accepted { action: ChallengeAction },
    /// Challenge rejected - version stands
    Rejected { reason: String },
    /// Escalated to governance dispute
    Escalated { dispute_id: String },
}

/// Action taken on accepted challenge
#[derive(Clone, Debug)]
pub enum ChallengeAction {
    /// Revoke the version
    Revoke,
    /// Modify the version
    Modify { new_version_id: VersionId },
    /// Add warning/disclaimer
    AddWarning { warning: String },
}

/// Dispute
#[derive(Clone, Debug)]
pub struct Dispute {
    /// Dispute ID
    pub dispute_id: String,
    /// Original challenge ID
    pub challenge_id: String,
    /// Version being disputed
    pub version_id: VersionId,
    /// Escalation reason
    pub escalation_reason: String,
    /// Status
    pub status: DisputeStatus,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Voting deadline
    pub voting_deadline: DateTime<Utc>,
    /// Votes
    pub votes: Vec<DisputeVoteRecord>,
    /// Resolution
    pub resolution: Option<DisputeResolution>,
    /// Quorum required
    pub quorum_required: Decimal,
}

/// Dispute status
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DisputeStatus {
    /// Voting in progress
    Voting,
    /// Resolved
    Resolved,
    /// No quorum reached
    NoQuorum,
    /// Cancelled
    Cancelled,
}

/// Dispute vote
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DisputeVote {
    /// Approve the challenge (version should be modified/revoked)
    Approve,
    /// Reject the challenge (version stands)
    Reject,
    /// Abstain
    Abstain,
}

/// Dispute vote record
#[derive(Clone, Debug)]
pub struct DisputeVoteRecord {
    /// Voter
    pub voter: P3Digest,
    /// Vote
    pub vote: DisputeVote,
    /// Vote weight
    pub weight: Decimal,
    /// Voted at
    pub voted_at: DateTime<Utc>,
}

/// Dispute resolution
#[derive(Clone, Debug)]
pub struct DisputeResolution {
    /// Outcome
    pub outcome: DisputeOutcome,
    /// Resolved at
    pub resolved_at: DateTime<Utc>,
    /// Total votes
    pub total_votes: u32,
    /// Total weight
    pub total_weight: Decimal,
    /// Approve weight
    pub approve_weight: Decimal,
    /// Reject weight
    pub reject_weight: Decimal,
}

/// Dispute outcome
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DisputeOutcome {
    /// Challenge upheld - version affected
    ChallengeUpheld,
    /// Challenge rejected - version stands
    ChallengeRejected,
    /// Tie - requires further resolution
    Tie,
    /// No quorum reached
    NoQuorum,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_creation() {
        let mut manager = ChallengeManager::new();

        let challenge = manager
            .create_challenge(
                VersionId::new("ver:test:1.0.0"),
                P3Digest::zero(),
                ChallengeReason::TechnicalError,
                None,
            )
            .unwrap();

        assert_eq!(challenge.status, ChallengeStatus::Open);
        assert!(challenge.response_deadline > Utc::now());
    }

    #[test]
    fn test_challenge_response() {
        let mut manager = ChallengeManager::new();

        let challenge = manager
            .create_challenge(
                VersionId::new("ver:test:1.0.0"),
                P3Digest::zero(),
                ChallengeReason::Unfairness,
                None,
            )
            .unwrap();

        manager
            .respond(
                &challenge.challenge_id,
                P3Digest::zero(),
                ChallengeResponseType::Accept,
                None,
            )
            .unwrap();

        let updated = manager.get_challenge(&challenge.challenge_id).unwrap();
        assert_eq!(updated.responses.len(), 1);
    }

    #[test]
    fn test_escalate_to_dispute() {
        let mut manager = ChallengeManager::new();

        let challenge = manager
            .create_challenge(
                VersionId::new("ver:test:1.0.0"),
                P3Digest::zero(),
                ChallengeReason::SecurityVulnerability,
                None,
            )
            .unwrap();

        let dispute = manager
            .escalate_to_dispute(&challenge.challenge_id, "Needs community vote")
            .unwrap();

        assert_eq!(dispute.status, DisputeStatus::Voting);

        let updated = manager.get_challenge(&challenge.challenge_id).unwrap();
        assert_eq!(updated.status, ChallengeStatus::Escalated);
    }

    #[test]
    fn test_dispute_voting() {
        let mut manager = ChallengeManager::new();

        let challenge = manager
            .create_challenge(
                VersionId::new("ver:test:1.0.0"),
                P3Digest::zero(),
                ChallengeReason::ProcessViolation,
                None,
            )
            .unwrap();

        let dispute = manager
            .escalate_to_dispute(&challenge.challenge_id, "Vote required")
            .unwrap();

        // Cast votes
        manager
            .vote(
                &dispute.dispute_id,
                P3Digest::zero(),
                DisputeVote::Approve,
                Decimal::new(30, 2),
            )
            .unwrap();

        let updated = manager.get_dispute(&dispute.dispute_id).unwrap();
        assert_eq!(updated.votes.len(), 1);
    }

    #[test]
    fn test_dispute_tally() {
        let mut manager = ChallengeManager::new()
            .with_config(ChallengeConfig {
                dispute_quorum: Decimal::new(10, 2), // 10%
                ..Default::default()
            });

        let challenge = manager
            .create_challenge(
                VersionId::new("ver:test:1.0.0"),
                P3Digest::zero(),
                ChallengeReason::TechnicalError,
                None,
            )
            .unwrap();

        let dispute = manager
            .escalate_to_dispute(&challenge.challenge_id, "Vote")
            .unwrap();

        // Cast votes (enough for quorum)
        manager
            .vote(
                &dispute.dispute_id,
                P3Digest::zero(),
                DisputeVote::Approve,
                Decimal::new(15, 2),
            )
            .unwrap();

        let outcome = manager.tally_dispute(&dispute.dispute_id).unwrap();
        assert_eq!(outcome, DisputeOutcome::ChallengeUpheld);
    }

    #[test]
    fn test_no_quorum() {
        let mut manager = ChallengeManager::new()
            .with_config(ChallengeConfig {
                dispute_quorum: Decimal::new(50, 2), // 50%
                ..Default::default()
            });

        let challenge = manager
            .create_challenge(
                VersionId::new("ver:test:1.0.0"),
                P3Digest::zero(),
                ChallengeReason::Other("test".to_string()),
                None,
            )
            .unwrap();

        let dispute = manager
            .escalate_to_dispute(&challenge.challenge_id, "Vote")
            .unwrap();

        // Cast small vote
        manager
            .vote(
                &dispute.dispute_id,
                P3Digest::zero(),
                DisputeVote::Approve,
                Decimal::new(10, 2),
            )
            .unwrap();

        let outcome = manager.tally_dispute(&dispute.dispute_id).unwrap();
        assert_eq!(outcome, DisputeOutcome::NoQuorum);
    }
}
