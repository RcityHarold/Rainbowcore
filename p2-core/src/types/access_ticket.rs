//! Access Ticket Types
//!
//! Ticketed forensic access - the core of P2's minimal disclosure system.
//! All payload access MUST go through a valid access ticket.

use super::selector::PayloadSelector;
use chrono::{DateTime, Utc};
use l0_core::types::{ActorId, Digest, ReceiptId};
use serde::{Deserialize, Serialize};

/// Access Ticket - Ticketed forensic access
///
/// Any access to sealed payloads in P2 MUST be through a valid ticket.
/// Tickets enforce minimal disclosure and generate audit trails.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTicket {
    /// Ticket ID
    pub ticket_id: String,

    /// Associated consent record reference
    pub consent_ref: String,

    /// Ticket holder (authorized accessor)
    pub holder: ActorId,

    /// Ticket issuer (authorizing party)
    pub issuer: ActorId,

    /// Target resource reference
    pub target_resource_ref: String,

    /// Allowed permissions
    pub permissions: Vec<TicketPermission>,

    /// Minimal disclosure selector
    pub selector: PayloadSelector,

    /// Issue timestamp
    pub issued_at: DateTime<Utc>,

    /// Valid from timestamp
    pub valid_from: DateTime<Utc>,

    /// Expiration timestamp
    pub valid_until: DateTime<Utc>,

    /// One-time use flag
    pub one_time: bool,

    /// Maximum use count (if not one-time)
    pub max_uses: Option<u32>,

    /// Current use count
    pub used_count: u32,

    /// Ticket digest
    pub ticket_digest: Digest,

    /// Associated receipt (for high-risk operations)
    pub receipt_id: Option<ReceiptId>,

    /// Ticket status
    pub status: TicketStatus,

    /// Purpose digest (privacy protected)
    pub purpose_digest: Digest,

    /// Delegation chain (if delegated)
    pub delegation_chain: Vec<DelegationEntry>,
}

impl AccessTicket {
    /// Create a new access ticket
    pub fn new(
        ticket_id: String,
        consent_ref: String,
        holder: ActorId,
        issuer: ActorId,
        target_resource_ref: String,
        permissions: Vec<TicketPermission>,
        selector: PayloadSelector,
        valid_until: DateTime<Utc>,
        purpose_digest: Digest,
    ) -> Self {
        let now = Utc::now();
        let ticket_digest = Self::compute_digest(
            &ticket_id,
            &consent_ref,
            &holder,
            &target_resource_ref,
            &now,
        );

        Self {
            ticket_id,
            consent_ref,
            holder,
            issuer,
            target_resource_ref,
            permissions,
            selector,
            issued_at: now,
            valid_from: now,
            valid_until,
            one_time: false,
            max_uses: None,
            used_count: 0,
            ticket_digest,
            receipt_id: None,
            status: TicketStatus::Active,
            purpose_digest,
            delegation_chain: Vec::new(),
        }
    }

    /// Compute ticket digest
    fn compute_digest(
        ticket_id: &str,
        consent_ref: &str,
        holder: &ActorId,
        target: &str,
        issued_at: &DateTime<Utc>,
    ) -> Digest {
        let mut data = Vec::new();
        data.extend_from_slice(ticket_id.as_bytes());
        data.extend_from_slice(consent_ref.as_bytes());
        data.extend_from_slice(holder.0.as_bytes());
        data.extend_from_slice(target.as_bytes());
        data.extend_from_slice(issued_at.to_rfc3339().as_bytes());
        Digest::blake3(&data)
    }

    /// Validate ticket at a given time
    pub fn validate_at(&self, at: DateTime<Utc>) -> TicketValidation {
        // Check status
        if self.status != TicketStatus::Active {
            return TicketValidation::Revoked;
        }

        // Check time window
        if at < self.valid_from {
            return TicketValidation::NotYetValid;
        }
        if at >= self.valid_until {
            return TicketValidation::Expired;
        }

        // Check use limits
        if self.one_time && self.used_count > 0 {
            return TicketValidation::AlreadyUsed;
        }
        if let Some(max) = self.max_uses {
            if self.used_count >= max {
                return TicketValidation::UseLimitExceeded;
            }
        }

        TicketValidation::Valid
    }

    /// Validate ticket now
    pub fn validate(&self) -> TicketValidation {
        self.validate_at(Utc::now())
    }

    /// Check if ticket is currently valid
    pub fn is_valid(&self) -> bool {
        self.validate() == TicketValidation::Valid
    }

    /// Use the ticket (increment counter)
    pub fn use_ticket(&mut self) -> Result<(), TicketError> {
        match self.validate() {
            TicketValidation::Valid => {
                self.used_count += 1;
                Ok(())
            }
            TicketValidation::Expired => Err(TicketError::Expired),
            TicketValidation::AlreadyUsed => Err(TicketError::AlreadyUsed),
            TicketValidation::UseLimitExceeded => Err(TicketError::UseLimitExceeded),
            TicketValidation::NotYetValid => Err(TicketError::NotYetValid),
            TicketValidation::Revoked => Err(TicketError::Revoked),
        }
    }

    /// Revoke the ticket
    pub fn revoke(&mut self, reason: &str) {
        self.status = TicketStatus::Revoked;
        // Note: reason should be stored in audit log, not in ticket
        let _ = reason;
    }

    /// Check if ticket has a specific permission
    pub fn has_permission(&self, permission: TicketPermission) -> bool {
        self.permissions.contains(&permission)
    }

    /// Check if the selector is within the ticket's allowed scope
    pub fn selector_within_scope(&self, requested: &PayloadSelector) -> bool {
        requested.is_subset_of(&self.selector)
    }

    /// Set as one-time use
    pub fn set_one_time(&mut self) {
        self.one_time = true;
        self.max_uses = Some(1);
    }

    /// Set max uses
    pub fn set_max_uses(&mut self, max: u32) {
        self.max_uses = Some(max);
        self.one_time = max == 1;
    }

    /// Get remaining uses
    pub fn remaining_uses(&self) -> Option<u32> {
        self.max_uses.map(|max| max.saturating_sub(self.used_count))
    }
}

/// Ticket permission types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketPermission {
    /// Read (decrypt/expand) permission
    Read,
    /// Export permission (external system transfer)
    Export,
    /// Verify permission (integrity check only)
    Verify,
    /// Audit permission (access audit logs)
    Audit,
    /// Delegate permission (can delegate to others)
    Delegate,
}

/// Ticket status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    /// Active and usable
    Active,
    /// Used (for one-time tickets)
    Used,
    /// Revoked by issuer
    Revoked,
    /// Expired
    Expired,
    /// Suspended pending review
    Suspended,
}

/// Ticket validation result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketValidation {
    Valid,
    NotYetValid,
    Expired,
    AlreadyUsed,
    UseLimitExceeded,
    Revoked,
}

/// Ticket errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum TicketError {
    #[error("Ticket not yet valid")]
    NotYetValid,
    #[error("Ticket expired")]
    Expired,
    #[error("Ticket already used (one-time)")]
    AlreadyUsed,
    #[error("Ticket use limit exceeded")]
    UseLimitExceeded,
    #[error("Ticket revoked")]
    Revoked,
    #[error("Selector out of scope")]
    SelectorOutOfScope,
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    #[error("Invalid ticket: {0}")]
    Invalid(String),
}

/// Delegation entry in the chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationEntry {
    /// Delegator
    pub from: ActorId,
    /// Delegatee
    pub to: ActorId,
    /// Delegation timestamp
    pub delegated_at: DateTime<Utc>,
    /// Delegation signature
    pub signature: String,
}

/// Ticket issuance request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketRequest {
    /// Consent reference
    pub consent_ref: String,
    /// Requested holder
    pub holder: ActorId,
    /// Target resource
    pub target_resource_ref: String,
    /// Requested permissions
    pub permissions: Vec<TicketPermission>,
    /// Requested selector
    pub selector: PayloadSelector,
    /// Requested validity period (seconds)
    pub validity_seconds: u64,
    /// Purpose description (will be hashed)
    pub purpose: String,
    /// One-time flag
    pub one_time: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn create_test_ticket() -> AccessTicket {
        AccessTicket::new(
            "ticket:001".to_string(),
            "consent:001".to_string(),
            ActorId::new("actor:holder"),
            ActorId::new("actor:issuer"),
            "payload:001".to_string(),
            vec![TicketPermission::Read],
            PayloadSelector::span(0, 100),
            Utc::now() + Duration::hours(1),
            Digest::zero(),
        )
    }

    #[test]
    fn test_ticket_creation() {
        let ticket = create_test_ticket();
        assert!(ticket.is_valid());
        assert_eq!(ticket.used_count, 0);
        assert!(!ticket.one_time);
    }

    #[test]
    fn test_ticket_validation() {
        let mut ticket = create_test_ticket();

        // Valid ticket
        assert_eq!(ticket.validate(), TicketValidation::Valid);

        // Use the ticket
        ticket.use_ticket().unwrap();
        assert_eq!(ticket.used_count, 1);

        // Still valid (not one-time)
        assert!(ticket.is_valid());
    }

    #[test]
    fn test_one_time_ticket() {
        let mut ticket = create_test_ticket();
        ticket.set_one_time();

        // First use succeeds
        assert!(ticket.use_ticket().is_ok());

        // Second use fails
        assert!(matches!(ticket.use_ticket(), Err(TicketError::AlreadyUsed)));
    }

    #[test]
    fn test_ticket_expiration() {
        let mut ticket = create_test_ticket();
        ticket.valid_until = Utc::now() - Duration::hours(1);

        assert_eq!(ticket.validate(), TicketValidation::Expired);
        assert!(matches!(ticket.use_ticket(), Err(TicketError::Expired)));
    }

    #[test]
    fn test_ticket_revocation() {
        let mut ticket = create_test_ticket();
        ticket.revoke("test revocation");

        assert_eq!(ticket.status, TicketStatus::Revoked);
        assert_eq!(ticket.validate(), TicketValidation::Revoked);
    }

    #[test]
    fn test_permission_check() {
        let ticket = create_test_ticket();
        assert!(ticket.has_permission(TicketPermission::Read));
        assert!(!ticket.has_permission(TicketPermission::Export));
    }

    #[test]
    fn test_selector_scope() {
        let ticket = create_test_ticket();

        // Subset selector is within scope
        let smaller = PayloadSelector::span(10, 50);
        assert!(ticket.selector_within_scope(&smaller));

        // DigestOnly is always within scope
        let digest = PayloadSelector::digest_only();
        assert!(ticket.selector_within_scope(&digest));

        // Full selector exceeds span scope
        let full = PayloadSelector::full();
        assert!(!ticket.selector_within_scope(&full));
    }

    #[test]
    fn test_max_uses() {
        let mut ticket = create_test_ticket();
        ticket.set_max_uses(3);

        assert_eq!(ticket.remaining_uses(), Some(3));

        ticket.use_ticket().unwrap();
        assert_eq!(ticket.remaining_uses(), Some(2));

        ticket.use_ticket().unwrap();
        ticket.use_ticket().unwrap();

        assert_eq!(ticket.remaining_uses(), Some(0));
        assert!(matches!(ticket.use_ticket(), Err(TicketError::UseLimitExceeded)));
    }
}
