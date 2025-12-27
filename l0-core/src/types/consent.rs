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
