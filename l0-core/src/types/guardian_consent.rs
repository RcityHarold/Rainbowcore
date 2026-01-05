//! Guardian Consent Receipt (GCR) and Human Consent Protocol (HCP)
//!
//! Implements emergency override mechanisms with multi-party approval.
//! - GCR: Guardian-authorized consent for minors/incapacitated
//! - HCP: Human-in-the-loop approval for AI actions

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use super::common::Digest;
use super::actor::ActorId;
use super::consent::EmergencyJustificationType;

/// Guardian relationship type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardianType {
    /// Legal guardian (parent, court-appointed)
    Legal,
    /// Medical guardian (healthcare proxy)
    Medical,
    /// Financial guardian (conservator)
    Financial,
    /// Emergency contact
    Emergency,
    /// System administrator
    SystemAdmin,
}

/// HCP approval requirement level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HcpApprovalLevel {
    /// Single human approval required
    Single,
    /// Dual approval (two humans)
    Dual,
    /// Committee approval (3+)
    Committee,
    /// Full board approval (all designated approvers)
    Board,
}

impl HcpApprovalLevel {
    /// Get minimum required approvals
    pub fn min_approvals(&self) -> u32 {
        match self {
            HcpApprovalLevel::Single => 1,
            HcpApprovalLevel::Dual => 2,
            HcpApprovalLevel::Committee => 3,
            HcpApprovalLevel::Board => 5, // Configurable
        }
    }
}

/// GCR Status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GcrStatus {
    /// Pending guardian approval
    Pending,
    /// Approved by guardian
    Approved,
    /// Rejected by guardian
    Rejected,
    /// Expired before decision
    Expired,
    /// Revoked after approval
    Revoked,
    /// Escalated to higher authority
    Escalated,
}

/// Guardian Consent Receipt - consent granted by guardian on behalf of ward
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianConsentReceipt {
    /// Unique GCR identifier
    pub gcr_id: String,
    /// Ward (person being represented)
    pub ward_id: ActorId,
    /// Guardian providing consent
    pub guardian_id: ActorId,
    /// Type of guardianship
    pub guardian_type: GuardianType,
    /// Proof of guardianship (digest of legal document)
    pub guardianship_proof_digest: Digest,
    /// What is being consented to
    pub consent_scope_digest: Digest,
    /// Justification for guardian action
    pub justification: String,
    /// Justification type
    pub justification_type: EmergencyJustificationType,
    /// Status of the GCR
    pub status: GcrStatus,
    /// When the GCR was created
    pub created_at: DateTime<Utc>,
    /// When the GCR expires
    pub expires_at: DateTime<Utc>,
    /// When the GCR was approved/rejected
    pub decided_at: Option<DateTime<Utc>>,
    /// Additional approvers (for multi-guardian scenarios)
    pub additional_approvers: Vec<GuardianApproval>,
    /// Minimum approvers required
    pub min_approvers: u32,
    /// Related emergency override (if applicable)
    pub emergency_override_ref: Option<String>,
    /// Audit trail reference
    pub audit_log_ref: Option<String>,
}

impl GuardianConsentReceipt {
    /// Check if GCR has enough approvals
    pub fn has_required_approvals(&self) -> bool {
        // +1 for the primary guardian
        (self.additional_approvers.len() as u32 + 1) >= self.min_approvers
    }

    /// Check if GCR is valid for use
    pub fn is_valid(&self) -> bool {
        self.status == GcrStatus::Approved && Utc::now() < self.expires_at
    }

    /// Check if GCR can still be approved
    pub fn can_approve(&self) -> bool {
        self.status == GcrStatus::Pending && Utc::now() < self.expires_at
    }
}

/// Guardian approval record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianApproval {
    /// Approving guardian
    pub guardian_id: ActorId,
    /// Guardian type
    pub guardian_type: GuardianType,
    /// Approval timestamp
    pub approved_at: DateTime<Utc>,
    /// Signature
    pub signature: String,
    /// Notes
    pub notes: Option<String>,
}

/// HCP Request - request for human approval of AI action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HcpRequest {
    /// Unique request identifier
    pub request_id: String,
    /// AI actor requesting approval
    pub ai_actor_id: ActorId,
    /// Action being requested (digest)
    pub action_digest: Digest,
    /// Human-readable description
    pub action_description: String,
    /// Why this action needs human approval
    pub reason: String,
    /// Approval level required
    pub approval_level: HcpApprovalLevel,
    /// Request status
    pub status: HcpStatus,
    /// When requested
    pub requested_at: DateTime<Utc>,
    /// When request expires
    pub expires_at: DateTime<Utc>,
    /// Human approvals received
    pub approvals: Vec<HumanApproval>,
    /// Human rejections received
    pub rejections: Vec<HumanRejection>,
    /// When decision was made
    pub decided_at: Option<DateTime<Utc>>,
    /// Escalation chain (if escalated)
    pub escalation_chain: Vec<String>,
}

/// HCP Status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HcpStatus {
    /// Awaiting human approval
    Pending,
    /// Approved by humans
    Approved,
    /// Rejected by humans
    Rejected,
    /// Expired before decision
    Expired,
    /// Escalated to higher authority
    Escalated,
    /// Automatically approved (within pre-approved parameters)
    AutoApproved,
}

impl HcpRequest {
    /// Check if request has enough approvals
    pub fn has_required_approvals(&self) -> bool {
        self.approvals.len() >= self.approval_level.min_approvals() as usize
    }

    /// Check if request has been rejected
    pub fn is_rejected(&self) -> bool {
        // Any rejection blocks approval
        !self.rejections.is_empty()
    }

    /// Update status based on approvals/rejections
    pub fn update_status(&mut self) {
        if Utc::now() >= self.expires_at && self.status == HcpStatus::Pending {
            self.status = HcpStatus::Expired;
        } else if self.is_rejected() && self.status == HcpStatus::Pending {
            self.status = HcpStatus::Rejected;
            self.decided_at = Some(Utc::now());
        } else if self.has_required_approvals() && self.status == HcpStatus::Pending {
            self.status = HcpStatus::Approved;
            self.decided_at = Some(Utc::now());
        }
    }
}

/// Human approval record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanApproval {
    /// Approving human
    pub human_id: ActorId,
    /// Approval timestamp
    pub approved_at: DateTime<Utc>,
    /// Signature
    pub signature: String,
    /// Approval conditions (if any)
    pub conditions: Option<String>,
    /// Verification method used
    pub verification_method: VerificationMethod,
}

/// Human rejection record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanRejection {
    /// Rejecting human
    pub human_id: ActorId,
    /// Rejection timestamp
    pub rejected_at: DateTime<Utc>,
    /// Reason for rejection
    pub reason: String,
    /// Signature
    pub signature: String,
}

/// Verification method for human identity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationMethod {
    /// Password/PIN
    Password,
    /// Biometric (fingerprint, face, etc.)
    Biometric,
    /// Hardware security key
    SecurityKey,
    /// Multi-factor authentication
    Mfa,
    /// In-person verification
    InPerson,
}

/// Emergency override workflow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyOverrideWorkflow {
    /// Workflow identifier
    pub workflow_id: String,
    /// Type of emergency
    pub emergency_type: EmergencyJustificationType,
    /// Initiator
    pub initiated_by: ActorId,
    /// Current stage
    pub stage: OverrideStage,
    /// GCR if guardian consent is required
    pub gcr: Option<GuardianConsentReceipt>,
    /// HCP if human approval is required
    pub hcp: Option<HcpRequest>,
    /// When workflow started
    pub started_at: DateTime<Utc>,
    /// Deadline for completion
    pub deadline: DateTime<Utc>,
    /// Audit trail
    pub audit_entries: Vec<OverrideAuditEntry>,
}

/// Override workflow stage
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverrideStage {
    /// Initial request submitted
    Initiated,
    /// Awaiting guardian consent
    AwaitingGcr,
    /// Awaiting human approval
    AwaitingHcp,
    /// Override approved and executing
    Executing,
    /// Override completed
    Completed,
    /// Override rejected
    Rejected,
    /// Override expired
    Expired,
    /// Under post-action review
    UnderReview,
}

/// Override audit entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverrideAuditEntry {
    /// Entry timestamp
    pub timestamp: DateTime<Utc>,
    /// Actor who performed action
    pub actor_id: ActorId,
    /// Action taken
    pub action: String,
    /// Details
    pub details: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guardian_type() {
        assert_eq!(
            serde_json::to_string(&GuardianType::Legal).unwrap(),
            "\"legal\""
        );
    }

    #[test]
    fn test_hcp_approval_levels() {
        assert_eq!(HcpApprovalLevel::Single.min_approvals(), 1);
        assert_eq!(HcpApprovalLevel::Dual.min_approvals(), 2);
        assert_eq!(HcpApprovalLevel::Committee.min_approvals(), 3);
    }

    #[test]
    fn test_gcr_validity() {
        let gcr = GuardianConsentReceipt {
            gcr_id: "test".to_string(),
            ward_id: ActorId("ward".to_string()),
            guardian_id: ActorId("guardian".to_string()),
            guardian_type: GuardianType::Legal,
            guardianship_proof_digest: Digest::zero(),
            consent_scope_digest: Digest::zero(),
            justification: "Test".to_string(),
            justification_type: EmergencyJustificationType::SafetyRisk,
            status: GcrStatus::Approved,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(24),
            decided_at: Some(Utc::now()),
            additional_approvers: Vec::new(),
            min_approvers: 1,
            emergency_override_ref: None,
            audit_log_ref: None,
        };

        assert!(gcr.is_valid());
        assert!(gcr.has_required_approvals());
    }
}
