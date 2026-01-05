//! Decrypt Audit Log Types
//!
//! Audit logging for decryption operations and sealed data access.
//! Tracks who accessed what, when, and under what authority.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use super::common::Digest;
use super::actor::ActorId;

/// Type of decryption operation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecryptOperationType {
    /// Standard decryption by authorized accessor
    Standard,
    /// Threshold decryption (multi-party)
    Threshold,
    /// Emergency override decryption
    Emergency,
    /// Guardian-authorized decryption
    Guardian,
    /// Forensic access decryption
    Forensic,
    /// Key rotation re-encryption
    KeyRotation,
}

/// Authorization source for decryption
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecryptAuthorizationSource {
    /// Owner consent receipt
    OwnerConsent,
    /// Guardian consent receipt (GCR)
    GuardianConsent,
    /// Emergency override workflow
    EmergencyOverride,
    /// Forensic access ticket
    ForensicTicket,
    /// Human consent protocol (HCP)
    HumanConsentProtocol,
    /// System automated (key rotation, etc.)
    SystemAutomated,
    /// Court order
    CourtOrder,
}

/// Status of decrypt audit entry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecryptAuditStatus {
    /// Decryption successful
    Success,
    /// Decryption failed
    Failed,
    /// Access denied
    Denied,
    /// Pending approval
    Pending,
    /// Revoked after decryption
    Revoked,
}

/// Decrypt audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptAuditEntry {
    /// Unique entry identifier
    pub entry_id: String,
    /// Sealed payload that was accessed
    pub sealed_payload_ref: String,
    /// Data subject (owner of the data)
    pub data_subject_id: ActorId,
    /// Actor who performed decryption
    pub accessor_id: ActorId,
    /// Type of operation
    pub operation_type: DecryptOperationType,
    /// Authorization source
    pub authorization_source: DecryptAuthorizationSource,
    /// Reference to authorization document
    pub authorization_ref: String,
    /// Operation status
    pub status: DecryptAuditStatus,
    /// Purpose of access
    pub access_purpose: String,
    /// Digest of decrypted data (for verification)
    pub data_digest: Digest,
    /// Epoch when access occurred
    pub access_epoch: u64,
    /// When access was requested
    pub requested_at: DateTime<Utc>,
    /// When access was completed
    pub completed_at: Option<DateTime<Utc>>,
    /// Access location/context
    pub access_context: Option<String>,
    /// IP address or node ID
    pub accessor_location: Option<String>,
    /// Chain of custody entries
    pub custody_chain: Vec<CustodyEntry>,
    /// Threshold participants (if threshold decryption)
    pub threshold_participants: Vec<ThresholdParticipant>,
    /// Expiry for decrypted data access
    pub access_expires_at: Option<DateTime<Utc>>,
}

/// Entry in the chain of custody
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyEntry {
    /// Actor who handled the data
    pub actor_id: ActorId,
    /// Action taken
    pub action: CustodyAction,
    /// When action occurred
    pub timestamp: DateTime<Utc>,
    /// Digital signature
    pub signature: String,
    /// Notes
    pub notes: Option<String>,
}

/// Custody action types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyAction {
    /// Received custody
    Received,
    /// Transferred custody
    Transferred,
    /// Viewed data
    Viewed,
    /// Copied data
    Copied,
    /// Deleted data
    Deleted,
    /// Resealed data
    Resealed,
}

/// Threshold decryption participant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdParticipant {
    /// Participant actor ID
    pub participant_id: ActorId,
    /// Share index
    pub share_index: u32,
    /// When they contributed
    pub contributed_at: DateTime<Utc>,
    /// Signature
    pub signature: String,
}

/// Decrypt audit log summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptAuditSummary {
    /// Total entries
    pub total_entries: u64,
    /// Successful decryptions
    pub successful_decryptions: u64,
    /// Failed decryptions
    pub failed_decryptions: u64,
    /// Denied access attempts
    pub denied_attempts: u64,
    /// By operation type
    pub by_operation_type: Vec<(DecryptOperationType, u64)>,
    /// By authorization source
    pub by_authorization_source: Vec<(DecryptAuthorizationSource, u64)>,
    /// Summary period start
    pub period_start: DateTime<Utc>,
    /// Summary period end
    pub period_end: DateTime<Utc>,
}

/// Audit log retention policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRetentionPolicy {
    /// Retention period for standard access logs (days)
    pub standard_retention_days: u32,
    /// Retention period for emergency access logs (days)
    pub emergency_retention_days: u32,
    /// Retention period for forensic access logs (days)
    pub forensic_retention_days: u32,
    /// Whether to archive before deletion
    pub archive_before_delete: bool,
    /// Minimum signers required to purge
    pub min_signers_for_purge: u32,
}

impl Default for AuditRetentionPolicy {
    fn default() -> Self {
        Self {
            standard_retention_days: 365,      // 1 year
            emergency_retention_days: 365 * 7, // 7 years
            forensic_retention_days: 365 * 10, // 10 years
            archive_before_delete: true,
            min_signers_for_purge: 5,          // Majority of 9
        }
    }
}

impl DecryptAuditEntry {
    /// Check if access is still valid
    pub fn is_access_valid(&self) -> bool {
        if let Some(expires_at) = self.access_expires_at {
            Utc::now() < expires_at && self.status == DecryptAuditStatus::Success
        } else {
            self.status == DecryptAuditStatus::Success
        }
    }

    /// Check if this is an emergency access
    pub fn is_emergency_access(&self) -> bool {
        matches!(
            self.authorization_source,
            DecryptAuthorizationSource::EmergencyOverride
                | DecryptAuthorizationSource::ForensicTicket
                | DecryptAuthorizationSource::CourtOrder
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_retention_policy() {
        let policy = AuditRetentionPolicy::default();
        assert_eq!(policy.standard_retention_days, 365);
        assert_eq!(policy.forensic_retention_days, 365 * 10);
        assert!(policy.archive_before_delete);
    }

    #[test]
    fn test_operation_types() {
        assert_eq!(
            serde_json::to_string(&DecryptOperationType::Threshold).unwrap(),
            "\"threshold\""
        );
    }

    #[test]
    fn test_authorization_sources() {
        assert_eq!(
            serde_json::to_string(&DecryptAuthorizationSource::GuardianConsent).unwrap(),
            "\"guardian_consent\""
        );
    }
}
