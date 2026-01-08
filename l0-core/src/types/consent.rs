//! Consent and access control types for L0
//!
//! Handles policy-consent ledger entries including consent records,
//! access tickets, and emergency overrides.

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use super::common::Digest;
use super::actor::{ActorId, ReceiptId, SpaceId};

/// Consent type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentType {
    /// Explicit opt-in consent
    Explicit,
    /// Consent implied by action
    Implied,
    /// Consent delegated to another party
    Delegated,
    /// Emergency override (requires justification)
    Emergency,
}

/// Consent status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentStatus {
    Active,
    Revoked,
    Expired,
    Superseded,
}

impl Default for ConsentStatus {
    fn default() -> Self {
        Self::Active
    }
}

/// Consent scope - what the consent covers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentScope {
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub actions: Vec<String>,
    pub constraints_digest: Option<Digest>,
}

/// Consent record - captures agreement to terms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentRecord {
    pub consent_id: String,
    pub consent_type: ConsentType,
    pub grantor: ActorId,
    pub grantee: ActorId,
    pub scope: ConsentScope,
    pub status: ConsentStatus,
    pub terms_digest: Digest,
    pub granted_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_reason_digest: Option<Digest>,
    pub superseded_by: Option<String>,
    pub receipt_id: Option<ReceiptId>,
}

impl ConsentRecord {
    /// Check if consent is currently valid
    pub fn is_valid(&self, at: DateTime<Utc>) -> bool {
        if self.status != ConsentStatus::Active {
            return false;
        }

        if let Some(expires) = self.expires_at {
            if at >= expires {
                return false;
            }
        }

        true
    }
}

/// Access ticket - time-limited access grant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTicket {
    pub ticket_id: String,
    pub consent_ref: String,
    pub holder: ActorId,
    pub target_resource: String,
    pub permissions: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub one_time: bool,
    pub used_at: Option<DateTime<Utc>>,
    pub ticket_digest: Digest,
    pub receipt_id: Option<ReceiptId>,
}

impl AccessTicket {
    /// Check if ticket is valid at a given time
    pub fn is_valid_at(&self, at: DateTime<Utc>) -> bool {
        if self.one_time && self.used_at.is_some() {
            return false;
        }

        at >= self.valid_from && at < self.valid_until
    }

    /// Mark ticket as used
    pub fn mark_used(&mut self, at: DateTime<Utc>) {
        self.used_at = Some(at);
    }
}

/// Emergency override justification type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyJustificationType {
    SafetyRisk,
    SecurityBreach,
    LegalCompliance,
    SystemIntegrity,
    Other,
}

/// Emergency override record - bypasses normal consent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyOverrideRecord {
    pub override_id: String,
    pub justification_type: EmergencyJustificationType,
    pub justification_digest: Digest,
    pub overridden_consent_ref: Option<String>,
    pub authorized_by: ActorId,
    pub executed_by: ActorId,
    pub affected_actors: Vec<ActorId>,
    pub action_taken_digest: Digest,
    pub initiated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub review_deadline: DateTime<Utc>,
    pub reviewed_by: Option<ActorId>,
    pub review_outcome_digest: Option<Digest>,
    pub receipt_id: Option<ReceiptId>,
}

impl EmergencyOverrideRecord {
    /// Check if this override is pending review
    pub fn is_pending_review(&self) -> bool {
        self.review_outcome_digest.is_none()
    }

    /// Check if review is overdue
    pub fn is_review_overdue(&self, at: DateTime<Utc>) -> bool {
        self.is_pending_review() && at > self.review_deadline
    }

    /// Submit a review for this override
    pub fn submit_review(&mut self, reviewer: ActorId, outcome_digest: Digest) -> EmergencyReviewResult {
        if !self.is_pending_review() {
            return EmergencyReviewResult::AlreadyReviewed;
        }

        let now = Utc::now();
        let is_late = now > self.review_deadline;

        self.reviewed_by = Some(reviewer.clone());
        self.review_outcome_digest = Some(outcome_digest);

        if is_late {
            EmergencyReviewResult::ReviewedLate {
                delay: now - self.review_deadline,
            }
        } else {
            EmergencyReviewResult::ReviewedOnTime
        }
    }

    /// Get time remaining until review deadline
    pub fn time_until_deadline(&self) -> chrono::Duration {
        let now = Utc::now();
        if now >= self.review_deadline {
            chrono::Duration::zero()
        } else {
            self.review_deadline - now
        }
    }

    /// Check if override is complete (reviewed)
    pub fn is_complete(&self) -> bool {
        self.review_outcome_digest.is_some()
    }

    /// Calculate urgency level based on deadline proximity
    pub fn urgency_level(&self) -> EmergencyReviewUrgency {
        if self.is_complete() {
            return EmergencyReviewUrgency::None;
        }

        let remaining = self.time_until_deadline();
        if remaining <= chrono::Duration::zero() {
            EmergencyReviewUrgency::Overdue
        } else if remaining <= chrono::Duration::hours(1) {
            EmergencyReviewUrgency::Critical
        } else if remaining <= chrono::Duration::hours(24) {
            EmergencyReviewUrgency::High
        } else if remaining <= chrono::Duration::hours(72) {
            EmergencyReviewUrgency::Medium
        } else {
            EmergencyReviewUrgency::Low
        }
    }
}

/// Result of submitting a review
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyReviewResult {
    /// Review submitted on time
    ReviewedOnTime,
    /// Review submitted late
    ReviewedLate { delay: chrono::Duration },
    /// Override was already reviewed
    AlreadyReviewed,
}

/// Urgency level for pending reviews
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyReviewUrgency {
    /// No review needed (already complete)
    None,
    /// Low urgency (>72 hours remaining)
    Low,
    /// Medium urgency (24-72 hours remaining)
    Medium,
    /// High urgency (1-24 hours remaining)
    High,
    /// Critical urgency (<1 hour remaining)
    Critical,
    /// Overdue (deadline passed)
    Overdue,
}

/// Emergency override review enforcement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyReviewEnforcer {
    /// Maximum time allowed before review is required
    pub max_review_period: chrono::Duration,
    /// Whether to escalate overdue reviews
    pub escalate_overdue: bool,
    /// Escalation threshold (how long after deadline before escalation)
    pub escalation_threshold: chrono::Duration,
    /// Whether to notify affected actors
    pub notify_affected_actors: bool,
}

impl Default for EmergencyReviewEnforcer {
    fn default() -> Self {
        Self {
            max_review_period: chrono::Duration::hours(72),
            escalate_overdue: true,
            escalation_threshold: chrono::Duration::hours(24),
            notify_affected_actors: true,
        }
    }
}

impl EmergencyReviewEnforcer {
    /// Check if an override needs escalation
    pub fn needs_escalation(&self, record: &EmergencyOverrideRecord) -> bool {
        if !self.escalate_overdue {
            return false;
        }

        if record.is_complete() {
            return false;
        }

        let now = Utc::now();
        let escalation_time = record.review_deadline + self.escalation_threshold;
        now > escalation_time
    }

    /// Get list of overrides needing attention
    pub fn check_overrides(&self, overrides: &[EmergencyOverrideRecord]) -> Vec<EmergencyOverrideAlert> {
        let mut alerts = Vec::new();
        let now = Utc::now();

        for record in overrides {
            if record.is_complete() {
                continue;
            }

            let urgency = record.urgency_level();
            if urgency == EmergencyReviewUrgency::None {
                continue;
            }

            alerts.push(EmergencyOverrideAlert {
                override_id: record.override_id.clone(),
                urgency,
                deadline: record.review_deadline,
                overdue_by: if now > record.review_deadline {
                    Some(now - record.review_deadline)
                } else {
                    None
                },
                needs_escalation: self.needs_escalation(record),
                affected_actor_count: record.affected_actors.len(),
                detected_at: now,
            });
        }

        // Sort by urgency (most urgent first)
        alerts.sort_by(|a, b| {
            let a_score = match a.urgency {
                EmergencyReviewUrgency::Overdue => 5,
                EmergencyReviewUrgency::Critical => 4,
                EmergencyReviewUrgency::High => 3,
                EmergencyReviewUrgency::Medium => 2,
                EmergencyReviewUrgency::Low => 1,
                EmergencyReviewUrgency::None => 0,
            };
            let b_score = match b.urgency {
                EmergencyReviewUrgency::Overdue => 5,
                EmergencyReviewUrgency::Critical => 4,
                EmergencyReviewUrgency::High => 3,
                EmergencyReviewUrgency::Medium => 2,
                EmergencyReviewUrgency::Low => 1,
                EmergencyReviewUrgency::None => 0,
            };
            b_score.cmp(&a_score)
        });

        alerts
    }
}

/// Alert for an override needing attention
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyOverrideAlert {
    /// Override ID
    pub override_id: String,
    /// Urgency level
    pub urgency: EmergencyReviewUrgency,
    /// Review deadline
    pub deadline: DateTime<Utc>,
    /// How long overdue (if applicable)
    pub overdue_by: Option<chrono::Duration>,
    /// Whether escalation is needed
    pub needs_escalation: bool,
    /// Number of affected actors
    pub affected_actor_count: usize,
    /// When this alert was generated
    pub detected_at: DateTime<Utc>,
}

/// Delegation record - allows consent transfer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationRecord {
    pub delegation_id: String,
    pub delegator: ActorId,
    pub delegate: ActorId,
    pub scope: ConsentScope,
    pub can_redelegate: bool,
    pub max_depth: u32,
    pub current_depth: u32,
    pub parent_delegation_ref: Option<String>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub receipt_id: Option<ReceiptId>,
}

impl DelegationRecord {
    /// Check if this delegation allows further redelegation
    pub fn can_create_subdelegation(&self) -> bool {
        self.can_redelegate && self.current_depth < self.max_depth
    }
}

/// Covenant status for space-level agreements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CovenantStatus {
    pub covenant_id: String,
    pub space_id: SpaceId,
    pub covenant_digest: Digest,
    pub signatories: Vec<ActorId>,
    pub effective_from: DateTime<Utc>,
    pub status: ConsentStatus,
    pub amendments_digest: Option<Digest>,
    pub receipt_id: Option<ReceiptId>,
}

// ============================================================================
// ConsentChain Validation (ISSUE-016)
// ============================================================================

/// Consent chain for tracking consent lineage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentChain {
    /// Chain ID
    pub chain_id: String,
    /// Root consent ID (first consent in chain)
    pub root_consent_id: String,
    /// Current tip consent ID
    pub tip_consent_id: String,
    /// Number of consents in chain
    pub chain_length: u64,
    /// Chain digest (hash of all consent IDs)
    pub chain_digest: Digest,
    /// Last updated timestamp
    pub updated_at: DateTime<Utc>,
}

/// Consent chain link - represents a consent in the chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentChainLink {
    /// This consent's ID
    pub consent_id: String,
    /// Previous consent ID (None for root)
    pub prev_consent_ref: Option<String>,
    /// Next consent ID (None for tip)
    pub next_consent_ref: Option<String>,
    /// This consent's digest
    pub consent_digest: Digest,
    /// Link position in chain
    pub position: u64,
    /// Timestamp when added to chain
    pub linked_at: DateTime<Utc>,
}

/// ConsentChain validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentChainValidation {
    /// Whether chain is valid
    pub is_valid: bool,
    /// Chain length
    pub chain_length: u64,
    /// Verified link count
    pub verified_links: u64,
    /// Broken links found
    pub broken_links: Vec<ConsentChainBreak>,
    /// Root consent found
    pub has_valid_root: bool,
    /// Tip consent found
    pub has_valid_tip: bool,
    /// Validation timestamp
    pub validated_at: DateTime<Utc>,
}

impl ConsentChainValidation {
    /// Create a valid chain result
    pub fn valid(chain_length: u64) -> Self {
        Self {
            is_valid: true,
            chain_length,
            verified_links: chain_length,
            broken_links: Vec::new(),
            has_valid_root: true,
            has_valid_tip: true,
            validated_at: Utc::now(),
        }
    }

    /// Create an invalid chain result
    pub fn invalid(broken_links: Vec<ConsentChainBreak>) -> Self {
        Self {
            is_valid: false,
            chain_length: 0,
            verified_links: 0,
            broken_links,
            has_valid_root: false,
            has_valid_tip: false,
            validated_at: Utc::now(),
        }
    }
}

/// A break in the consent chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentChainBreak {
    /// Position where break occurred
    pub position: u64,
    /// Expected previous consent ID
    pub expected_prev: Option<String>,
    /// Actual previous consent ID found
    pub actual_prev: Option<String>,
    /// Break type
    pub break_type: ChainBreakType,
    /// Detected at timestamp
    pub detected_at: DateTime<Utc>,
}

/// Type of chain break
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainBreakType {
    /// Missing link (consent not found)
    MissingLink,
    /// Hash mismatch
    HashMismatch,
    /// Forward reference mismatch
    ForwardMismatch,
    /// Backward reference mismatch
    BackwardMismatch,
    /// Circular reference detected
    CircularReference,
    /// Invalid root (has prev_ref but shouldn't)
    InvalidRoot,
    /// Invalid tip (has next_ref but shouldn't)
    InvalidTip,
}

impl ConsentRecord {
    /// Create a chain link from this consent record
    pub fn to_chain_link(&self, position: u64, prev_ref: Option<String>, next_ref: Option<String>) -> ConsentChainLink {
        ConsentChainLink {
            consent_id: self.consent_id.clone(),
            prev_consent_ref: prev_ref,
            next_consent_ref: next_ref,
            consent_digest: self.terms_digest.clone(),
            position,
            linked_at: Utc::now(),
        }
    }

    /// Check if this consent supersedes another
    pub fn supersedes(&self, other: &ConsentRecord) -> bool {
        self.superseded_by.as_ref().map_or(false, |s| s == &other.consent_id)
    }
}

/// Consent chain validator
pub struct ConsentChainValidator {
    /// Maximum chain length to validate
    max_chain_length: u64,
    /// Visited consent IDs (for cycle detection)
    visited: std::collections::HashSet<String>,
}

impl ConsentChainValidator {
    /// Create a new validator
    pub fn new(max_chain_length: u64) -> Self {
        Self {
            max_chain_length,
            visited: std::collections::HashSet::new(),
        }
    }

    /// Validate a chain of consent links
    pub fn validate(&mut self, links: &[ConsentChainLink]) -> ConsentChainValidation {
        if links.is_empty() {
            return ConsentChainValidation::invalid(vec![]);
        }

        let mut broken_links = Vec::new();
        self.visited.clear();

        // Check for valid root
        let root = &links[0];
        if root.prev_consent_ref.is_some() {
            broken_links.push(ConsentChainBreak {
                position: 0,
                expected_prev: None,
                actual_prev: root.prev_consent_ref.clone(),
                break_type: ChainBreakType::InvalidRoot,
                detected_at: Utc::now(),
            });
        }

        // Validate each link
        for i in 0..links.len() {
            let link = &links[i];

            // Check for cycles
            if self.visited.contains(&link.consent_id) {
                broken_links.push(ConsentChainBreak {
                    position: i as u64,
                    expected_prev: None,
                    actual_prev: None,
                    break_type: ChainBreakType::CircularReference,
                    detected_at: Utc::now(),
                });
                break;
            }
            self.visited.insert(link.consent_id.clone());

            // Check chain length
            if i as u64 >= self.max_chain_length {
                break;
            }

            // Validate forward/backward references
            if i > 0 {
                let prev_link = &links[i - 1];
                // Check backward reference
                if link.prev_consent_ref.as_ref() != Some(&prev_link.consent_id) {
                    broken_links.push(ConsentChainBreak {
                        position: i as u64,
                        expected_prev: Some(prev_link.consent_id.clone()),
                        actual_prev: link.prev_consent_ref.clone(),
                        break_type: ChainBreakType::BackwardMismatch,
                        detected_at: Utc::now(),
                    });
                }
                // Check forward reference of previous
                if prev_link.next_consent_ref.as_ref() != Some(&link.consent_id) {
                    broken_links.push(ConsentChainBreak {
                        position: (i - 1) as u64,
                        expected_prev: Some(link.consent_id.clone()),
                        actual_prev: prev_link.next_consent_ref.clone(),
                        break_type: ChainBreakType::ForwardMismatch,
                        detected_at: Utc::now(),
                    });
                }
            }
        }

        // Check valid tip
        let tip = links.last().unwrap();
        let has_valid_tip = tip.next_consent_ref.is_none();
        if !has_valid_tip {
            broken_links.push(ConsentChainBreak {
                position: (links.len() - 1) as u64,
                expected_prev: None,
                actual_prev: tip.next_consent_ref.clone(),
                break_type: ChainBreakType::InvalidTip,
                detected_at: Utc::now(),
            });
        }

        if broken_links.is_empty() {
            ConsentChainValidation::valid(links.len() as u64)
        } else {
            let mut result = ConsentChainValidation::invalid(broken_links);
            result.chain_length = links.len() as u64;
            result.has_valid_root = root.prev_consent_ref.is_none();
            result.has_valid_tip = has_valid_tip;
            result
        }
    }

    /// Reset the validator for reuse
    pub fn reset(&mut self) {
        self.visited.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_consent_validity() {
        let now = Utc::now();
        let consent = ConsentRecord {
            consent_id: "cns:001".to_string(),
            consent_type: ConsentType::Explicit,
            grantor: ActorId::new("actor:1"),
            grantee: ActorId::new("actor:2"),
            scope: ConsentScope {
                resource_type: "data".to_string(),
                resource_id: None,
                actions: vec!["read".to_string()],
                constraints_digest: None,
            },
            status: ConsentStatus::Active,
            terms_digest: Digest::zero(),
            granted_at: now,
            expires_at: Some(now + Duration::hours(24)),
            revoked_at: None,
            revocation_reason_digest: None,
            superseded_by: None,
            receipt_id: None,
        };

        assert!(consent.is_valid(now));
        assert!(!consent.is_valid(now + Duration::hours(25)));
    }

    #[test]
    fn test_access_ticket_one_time() {
        let now = Utc::now();
        let mut ticket = AccessTicket {
            ticket_id: "tkt:001".to_string(),
            consent_ref: "cns:001".to_string(),
            holder: ActorId::new("actor:1"),
            target_resource: "resource:1".to_string(),
            permissions: vec!["access".to_string()],
            issued_at: now,
            valid_from: now,
            valid_until: now + Duration::hours(1),
            one_time: true,
            used_at: None,
            ticket_digest: Digest::zero(),
            receipt_id: None,
        };

        assert!(ticket.is_valid_at(now));
        ticket.mark_used(now);
        assert!(!ticket.is_valid_at(now));
    }
}
