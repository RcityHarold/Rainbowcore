//! Policy-Consent Ledger - Consent records and access control
//!
//! The Policy-Consent Ledger manages:
//! - Consent records between actors
//! - Access tickets and their validity
//! - Delegation chains
//! - Emergency overrides
//! - Covenant status for spaces

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use crate::types::{
    Digest, ReceiptId, ActorId, SpaceId,
    ConsentRecord, ConsentType, ConsentStatus, ConsentScope,
    AccessTicket, DelegationRecord, EmergencyOverrideRecord,
    CovenantStatus,
};
use super::{Ledger, LedgerResult, QueryOptions};

/// Consent verification result
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConsentVerifyResult {
    /// Whether the consent is valid for the requested action
    pub valid: bool,
    /// Reference to the matching consent record
    pub consent_ref: Option<String>,
    /// Primary reason for the verification result
    pub reason: String,
    /// All validation errors encountered (for detailed diagnostics)
    pub errors: Vec<String>,
    /// Whether the consent has expired
    pub expired: bool,
    /// Whether the consent has been revoked
    pub revoked: bool,
    /// If superseded, reference to the new consent
    pub superseded_by: Option<String>,
    /// Whether the requested action is within the consent scope
    pub scope_matches: bool,
    /// Evidence level of the consent (A or B)
    pub evidence_level: crate::types::EvidenceLevel,
}

impl Default for ConsentVerifyResult {
    fn default() -> Self {
        Self {
            valid: false,
            consent_ref: None,
            reason: "No consent found".to_string(),
            errors: Vec::new(),
            expired: false,
            revoked: false,
            superseded_by: None,
            scope_matches: false,
            evidence_level: crate::types::EvidenceLevel::B,
        }
    }
}

impl ConsentVerifyResult {
    /// Create a successful verification result
    pub fn success(consent_ref: String, evidence_level: crate::types::EvidenceLevel) -> Self {
        Self {
            valid: true,
            consent_ref: Some(consent_ref),
            reason: "Consent verified successfully".to_string(),
            errors: Vec::new(),
            expired: false,
            revoked: false,
            superseded_by: None,
            scope_matches: true,
            evidence_level,
        }
    }

    /// Create a failed verification result with a reason
    pub fn failure(reason: impl Into<String>) -> Self {
        Self {
            valid: false,
            reason: reason.into(),
            ..Default::default()
        }
    }

    /// Add an error to the result
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.errors.push(error.into());
        self
    }
}

/// Policy-Consent Ledger trait
#[async_trait]
pub trait ConsentLedger: Ledger {
    /// Grant consent
    async fn grant_consent(
        &self,
        consent_type: ConsentType,
        grantor: &ActorId,
        grantee: &ActorId,
        scope: ConsentScope,
        terms_digest: Digest,
        expires_at: Option<DateTime<Utc>>,
    ) -> LedgerResult<ConsentRecord>;

    /// Revoke consent
    async fn revoke_consent(
        &self,
        consent_id: &str,
        reason_digest: Option<Digest>,
    ) -> LedgerResult<ReceiptId>;

    /// Get consent by ID
    async fn get_consent(&self, consent_id: &str) -> LedgerResult<Option<ConsentRecord>>;

    /// Verify consent between actors
    async fn verify_consent(
        &self,
        grantor: &ActorId,
        grantee: &ActorId,
        action: &str,
        resource_type: &str,
    ) -> LedgerResult<ConsentVerifyResult>;

    /// List consents granted by actor
    async fn list_granted_consents(
        &self,
        grantor: &ActorId,
        status: Option<ConsentStatus>,
        options: QueryOptions,
    ) -> LedgerResult<Vec<ConsentRecord>>;

    /// List consents received by actor
    async fn list_received_consents(
        &self,
        grantee: &ActorId,
        status: Option<ConsentStatus>,
        options: QueryOptions,
    ) -> LedgerResult<Vec<ConsentRecord>>;

    /// Issue access ticket
    async fn issue_ticket(
        &self,
        consent_ref: &str,
        holder: &ActorId,
        target_resource: String,
        permissions: Vec<String>,
        valid_until: DateTime<Utc>,
        one_time: bool,
    ) -> LedgerResult<AccessTicket>;

    /// Validate and consume ticket
    async fn use_ticket(
        &self,
        ticket_id: &str,
    ) -> LedgerResult<bool>;

    /// Get ticket by ID
    async fn get_ticket(&self, ticket_id: &str) -> LedgerResult<Option<AccessTicket>>;

    /// Create delegation
    async fn create_delegation(
        &self,
        delegator: &ActorId,
        delegate: &ActorId,
        scope: ConsentScope,
        can_redelegate: bool,
        max_depth: u32,
        valid_until: Option<DateTime<Utc>>,
    ) -> LedgerResult<DelegationRecord>;

    /// Revoke delegation
    async fn revoke_delegation(&self, delegation_id: &str) -> LedgerResult<ReceiptId>;

    /// Get delegation chain
    async fn get_delegation_chain(
        &self,
        delegation_id: &str,
    ) -> LedgerResult<Vec<DelegationRecord>>;

    /// Record emergency override
    async fn record_emergency_override(
        &self,
        override_record: EmergencyOverrideRecord,
    ) -> LedgerResult<ReceiptId>;

    /// Get emergency overrides pending review
    async fn get_pending_override_reviews(
        &self,
        options: QueryOptions,
    ) -> LedgerResult<Vec<EmergencyOverrideRecord>>;

    /// Create or update covenant
    async fn update_covenant(
        &self,
        space_id: &SpaceId,
        covenant_digest: Digest,
        signatories: Vec<ActorId>,
    ) -> LedgerResult<CovenantStatus>;

    /// Get covenant for space
    async fn get_covenant(&self, space_id: &SpaceId) -> LedgerResult<Option<CovenantStatus>>;
}
