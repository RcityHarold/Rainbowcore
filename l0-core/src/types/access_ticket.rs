//! Forensic Access Ticket - Zero-Plaintext Forensic Access Control
//!
//! Implements ticket-based data access for forensic and audit purposes.
//! Tickets provide time-limited, purpose-bound access to sealed payloads.
//!
//! Note: This extends the basic AccessTicket in consent.rs with forensic capabilities.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use super::common::Digest;
use super::actor::ActorId;

/// Forensic ticket status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForensicTicketStatus {
    /// Ticket is valid and can be used
    Active,
    /// Ticket has been used (single-use tickets)
    Used,
    /// Ticket has expired
    Expired,
    /// Ticket has been revoked
    Revoked,
    /// Ticket is pending approval
    Pending,
}

/// Access purpose - why the access is being requested
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessPurpose {
    /// Legal/regulatory audit
    Audit,
    /// Dispute resolution
    Dispute,
    /// Law enforcement request
    LawEnforcement,
    /// System repair/recovery
    Repair,
    /// Guardian consent override
    GuardianOverride,
    /// Clawback operation
    Clawback,
    /// Data subject access request
    DataSubjectAccess,
    /// Custom purpose with description
    Custom(String),
}

impl AccessPurpose {
    /// Check if this purpose requires multi-party approval
    pub fn requires_multi_approval(&self) -> bool {
        matches!(
            self,
            AccessPurpose::LawEnforcement
                | AccessPurpose::GuardianOverride
                | AccessPurpose::Clawback
        )
    }

    /// Get minimum approval count for this purpose
    pub fn min_approvals(&self) -> u32 {
        match self {
            AccessPurpose::Audit => 1,
            AccessPurpose::Dispute => 2,
            AccessPurpose::LawEnforcement => 3,
            AccessPurpose::Repair => 2,
            AccessPurpose::GuardianOverride => 3,
            AccessPurpose::Clawback => 3,
            AccessPurpose::DataSubjectAccess => 1,
            AccessPurpose::Custom(_) => 2,
        }
    }
}

/// Forensic access ticket - grants time-limited access to sealed data for forensic purposes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicAccessTicket {
    /// Unique ticket identifier
    pub ticket_id: String,
    /// Reference to sealed payload
    pub sealed_payload_ref: String,
    /// Digest of the sealed payload
    pub payload_digest: Digest,
    /// Actor requesting access
    pub requester_id: ActorId,
    /// Purpose of access
    pub purpose: AccessPurpose,
    /// Ticket status
    pub status: ForensicTicketStatus,
    /// When the ticket was created
    pub created_at: DateTime<Utc>,
    /// When the ticket expires
    pub expires_at: DateTime<Utc>,
    /// When the ticket was used (if applicable)
    pub used_at: Option<DateTime<Utc>>,
    /// When the ticket was revoked (if applicable)
    pub revoked_at: Option<DateTime<Utc>>,
    /// Revocation reason
    pub revocation_reason: Option<String>,
    /// Approval signatures (for multi-party approval)
    pub approvals: Vec<TicketApproval>,
    /// Maximum number of uses (None = unlimited within validity)
    pub max_uses: Option<u32>,
    /// Current use count
    pub use_count: u32,
    /// Scope restrictions (what parts of payload can be accessed)
    pub scope: AccessScope,
    /// Audit trail reference
    pub audit_log_ref: Option<String>,
}

impl ForensicAccessTicket {
    /// Check if the ticket is currently valid
    pub fn is_valid(&self) -> bool {
        self.status == ForensicTicketStatus::Active && Utc::now() < self.expires_at
    }

    /// Check if ticket has required approvals
    pub fn has_required_approvals(&self) -> bool {
        self.approvals.len() >= self.purpose.min_approvals() as usize
    }

    /// Mark ticket as used
    pub fn mark_used(&mut self) {
        self.use_count += 1;
        self.used_at = Some(Utc::now());

        // Check if single-use or max uses reached
        if let Some(max) = self.max_uses {
            if self.use_count >= max {
                self.status = ForensicTicketStatus::Used;
            }
        }
    }

    /// Revoke the ticket
    pub fn revoke(&mut self, reason: &str) {
        self.status = ForensicTicketStatus::Revoked;
        self.revoked_at = Some(Utc::now());
        self.revocation_reason = Some(reason.to_string());
    }

    /// Check expiration and update status
    pub fn check_expiration(&mut self) {
        if self.status == ForensicTicketStatus::Active && Utc::now() >= self.expires_at {
            self.status = ForensicTicketStatus::Expired;
        }
    }

    /// Add an approval
    pub fn add_approval(&mut self, approval: TicketApproval) {
        self.approvals.push(approval);

        // If pending and now has enough approvals, activate
        if self.status == ForensicTicketStatus::Pending && self.has_required_approvals() {
            self.status = ForensicTicketStatus::Active;
        }
    }
}

/// Ticket approval from an authorized party
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketApproval {
    /// Approver actor ID
    pub approver_id: ActorId,
    /// Approval timestamp
    pub approved_at: DateTime<Utc>,
    /// Signature over ticket request
    pub signature: String,
    /// Optional approval notes
    pub notes: Option<String>,
}

/// Access scope - restricts what can be accessed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessScope {
    /// Fields that can be accessed (empty = all)
    pub allowed_fields: Vec<String>,
    /// Fields that are explicitly denied
    pub denied_fields: Vec<String>,
    /// Whether to include metadata
    pub include_metadata: bool,
    /// Whether to include history
    pub include_history: bool,
    /// Maximum depth for nested data
    pub max_depth: Option<u32>,
}

impl Default for AccessScope {
    fn default() -> Self {
        Self {
            allowed_fields: Vec::new(),
            denied_fields: Vec::new(),
            include_metadata: true,
            include_history: false,
            max_depth: None,
        }
    }
}

impl AccessScope {
    /// Create a full access scope
    pub fn full() -> Self {
        Self {
            allowed_fields: Vec::new(),
            denied_fields: Vec::new(),
            include_metadata: true,
            include_history: true,
            max_depth: None,
        }
    }

    /// Create a metadata-only scope
    pub fn metadata_only() -> Self {
        Self {
            allowed_fields: Vec::new(),
            denied_fields: Vec::new(),
            include_metadata: true,
            include_history: false,
            max_depth: Some(0),
        }
    }

    /// Check if a field is accessible
    pub fn can_access_field(&self, field: &str) -> bool {
        // If denied, reject
        if self.denied_fields.contains(&field.to_string()) {
            return false;
        }
        // If allowed list is empty, allow all non-denied
        if self.allowed_fields.is_empty() {
            return true;
        }
        // Otherwise, must be in allowed list
        self.allowed_fields.contains(&field.to_string())
    }
}

/// Ticket request - used to request a new access ticket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketRequest {
    /// Requester actor ID
    pub requester_id: ActorId,
    /// Reference to sealed payload
    pub sealed_payload_ref: String,
    /// Purpose of access
    pub purpose: AccessPurpose,
    /// Requested duration
    pub duration: Duration,
    /// Requested scope
    pub scope: AccessScope,
    /// Supporting evidence/justification
    pub justification: String,
    /// Evidence digest (e.g., court order, audit letter)
    pub evidence_digest: Option<Digest>,
    /// Request timestamp
    pub requested_at: DateTime<Utc>,
}

impl TicketRequest {
    /// Create a new ticket request
    pub fn new(
        requester_id: ActorId,
        sealed_payload_ref: String,
        purpose: AccessPurpose,
        justification: String,
    ) -> Self {
        Self {
            requester_id,
            sealed_payload_ref,
            purpose,
            duration: Duration::hours(24), // Default 24 hours
            scope: AccessScope::default(),
            justification,
            evidence_digest: None,
            requested_at: Utc::now(),
        }
    }

    /// Set duration
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = duration;
        self
    }

    /// Set scope
    pub fn with_scope(mut self, scope: AccessScope) -> Self {
        self.scope = scope;
        self
    }

    /// Set evidence
    pub fn with_evidence(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = Some(evidence_digest);
        self
    }
}

/// Ticket verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketVerification {
    /// Whether the ticket is valid
    pub valid: bool,
    /// Ticket status
    pub status: ForensicTicketStatus,
    /// Remaining uses (if limited)
    pub remaining_uses: Option<u32>,
    /// Time until expiration
    pub expires_in_secs: i64,
    /// Validation errors
    pub errors: Vec<String>,
}

impl TicketVerification {
    /// Create a valid verification result
    pub fn valid(ticket: &ForensicAccessTicket) -> Self {
        let remaining = ticket.max_uses.map(|max| max.saturating_sub(ticket.use_count));
        let expires_in = (ticket.expires_at - Utc::now()).num_seconds();

        Self {
            valid: true,
            status: ticket.status,
            remaining_uses: remaining,
            expires_in_secs: expires_in,
            errors: Vec::new(),
        }
    }

    /// Create an invalid verification result
    pub fn invalid(status: ForensicTicketStatus, errors: Vec<String>) -> Self {
        Self {
            valid: false,
            status,
            remaining_uses: None,
            expires_in_secs: 0,
            errors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_purpose_approvals() {
        assert_eq!(AccessPurpose::Audit.min_approvals(), 1);
        assert_eq!(AccessPurpose::LawEnforcement.min_approvals(), 3);
        assert!(AccessPurpose::LawEnforcement.requires_multi_approval());
        assert!(!AccessPurpose::Audit.requires_multi_approval());
    }

    #[test]
    fn test_access_scope() {
        let scope = AccessScope::default();
        assert!(scope.can_access_field("any_field"));

        let restricted = AccessScope {
            allowed_fields: vec!["field1".to_string(), "field2".to_string()],
            denied_fields: vec!["secret".to_string()],
            include_metadata: true,
            include_history: false,
            max_depth: Some(2),
        };

        assert!(restricted.can_access_field("field1"));
        assert!(!restricted.can_access_field("field3"));
        assert!(!restricted.can_access_field("secret"));
    }

    #[test]
    fn test_ticket_expiration() {
        let mut ticket = ForensicAccessTicket {
            ticket_id: "test".to_string(),
            sealed_payload_ref: "ref".to_string(),
            payload_digest: Digest::zero(),
            requester_id: ActorId("actor1".to_string()),
            purpose: AccessPurpose::Audit,
            status: ForensicTicketStatus::Active,
            created_at: Utc::now(),
            expires_at: Utc::now() - Duration::hours(1), // Already expired
            used_at: None,
            revoked_at: None,
            revocation_reason: None,
            approvals: Vec::new(),
            max_uses: None,
            use_count: 0,
            scope: AccessScope::default(),
            audit_log_ref: None,
        };

        ticket.check_expiration();
        assert_eq!(ticket.status, ForensicTicketStatus::Expired);
    }

    #[test]
    fn test_ticket_revocation() {
        let mut ticket = ForensicAccessTicket {
            ticket_id: "test".to_string(),
            sealed_payload_ref: "ref".to_string(),
            payload_digest: Digest::zero(),
            requester_id: ActorId("actor1".to_string()),
            purpose: AccessPurpose::Audit,
            status: ForensicTicketStatus::Active,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(24),
            used_at: None,
            revoked_at: None,
            revocation_reason: None,
            approvals: Vec::new(),
            max_uses: None,
            use_count: 0,
            scope: AccessScope::default(),
            audit_log_ref: None,
        };

        ticket.revoke("No longer needed");
        assert_eq!(ticket.status, ForensicTicketStatus::Revoked);
        assert!(ticket.revoked_at.is_some());
        assert_eq!(ticket.revocation_reason, Some("No longer needed".to_string()));
    }
}
