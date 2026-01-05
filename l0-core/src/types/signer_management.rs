//! Signer Set Management - Admission and Slashing Policies
//!
//! Manages the 9-node signer set with admission, reputation, and slashing.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use super::common::Digest;
use super::actor::ActorId;

/// Signer status in the set
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerStatus {
    /// Candidate awaiting admission
    Candidate,
    /// Active signer in the set
    Active,
    /// Suspended due to violations
    Suspended,
    /// Demoted from signer to observer
    Demoted,
    /// Removed from the network
    Removed,
    /// Voluntarily exited
    Exited,
}

/// Signer record with reputation tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerRecord {
    /// Signer actor ID
    pub signer_id: ActorId,
    /// Public key for signing
    pub public_key: String,
    /// Current status
    pub status: SignerStatus,
    /// Reputation score (0-1000)
    pub reputation_score: u32,
    /// Total epochs participated
    pub epochs_participated: u64,
    /// Missed signing opportunities
    pub missed_signatures: u64,
    /// Successful signatures
    pub successful_signatures: u64,
    /// Slashing events
    pub slashing_count: u32,
    /// Total amount slashed
    pub total_slashed: u64,
    /// When joined the set
    pub joined_at: DateTime<Utc>,
    /// Last activity timestamp
    pub last_active_at: DateTime<Utc>,
    /// Stake amount (for slashing)
    pub stake_amount: u64,
    /// Locked stake (from slashing)
    pub locked_stake: u64,
}

impl SignerRecord {
    /// Calculate uptime percentage
    pub fn uptime_percentage(&self) -> f64 {
        let total = self.successful_signatures + self.missed_signatures;
        if total == 0 {
            return 100.0;
        }
        (self.successful_signatures as f64 / total as f64) * 100.0
    }

    /// Check if signer meets minimum requirements
    pub fn meets_requirements(&self, policy: &AdmissionPolicy) -> bool {
        self.reputation_score >= policy.min_reputation
            && self.uptime_percentage() >= policy.min_uptime_percentage
            && self.stake_amount >= policy.min_stake
    }
}

/// Admission policy for new signers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionPolicy {
    /// Minimum reputation score required
    pub min_reputation: u32,
    /// Minimum stake required
    pub min_stake: u64,
    /// Minimum uptime percentage
    pub min_uptime_percentage: f64,
    /// Required approval count from existing signers
    pub required_approvals: u32,
    /// Probation period in epochs
    pub probation_epochs: u64,
    /// Maximum candidates in queue
    pub max_candidates: u32,
    /// Minimum time as observer before candidacy
    pub min_observer_time_secs: u64,
}

impl Default for AdmissionPolicy {
    fn default() -> Self {
        Self {
            min_reputation: 500,
            min_stake: 100_000,
            min_uptime_percentage: 95.0,
            required_approvals: 5, // Majority of 9
            probation_epochs: 100,
            max_candidates: 20,
            min_observer_time_secs: 86400 * 7, // 7 days
        }
    }
}

/// Slashing policy for violations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingPolicy {
    /// Percentage slashed for missing signature
    pub miss_signature_slash_bps: u16,
    /// Percentage slashed for double signing
    pub double_sign_slash_bps: u16,
    /// Percentage slashed for downtime
    pub downtime_slash_bps: u16,
    /// Percentage slashed for equivocation
    pub equivocation_slash_bps: u16,
    /// Maximum consecutive misses before suspension
    pub max_consecutive_misses: u32,
    /// Maximum slashing events before demotion
    pub max_slashing_events_before_demotion: u32,
    /// Reputation penalty per miss
    pub reputation_penalty_per_miss: u32,
    /// Cooldown period after slashing (seconds)
    pub slash_cooldown_secs: u64,
    /// Minimum stake after slashing before removal
    pub min_stake_threshold: u64,
}

impl Default for SlashingPolicy {
    fn default() -> Self {
        Self {
            miss_signature_slash_bps: 10,      // 0.1%
            double_sign_slash_bps: 5000,       // 50%
            downtime_slash_bps: 100,           // 1%
            equivocation_slash_bps: 10000,     // 100% (full slash)
            max_consecutive_misses: 10,
            max_slashing_events_before_demotion: 3,  // Demote after 3 slashing events
            reputation_penalty_per_miss: 5,
            slash_cooldown_secs: 3600,         // 1 hour
            min_stake_threshold: 10_000,
        }
    }
}

/// Violation type for slashing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationType {
    /// Missed a required signature
    MissedSignature,
    /// Signed conflicting messages
    DoubleSigning,
    /// Extended downtime
    Downtime,
    /// Equivocation (conflicting votes)
    Equivocation,
    /// Protocol violation
    ProtocolViolation,
}

/// Slashing event record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingEvent {
    /// Event identifier
    pub event_id: String,
    /// Signer being slashed
    pub signer_id: ActorId,
    /// Type of violation
    pub violation_type: ViolationType,
    /// Evidence digest
    pub evidence_digest: Digest,
    /// Amount slashed
    pub amount_slashed: u64,
    /// Reputation penalty applied
    pub reputation_penalty: u32,
    /// New status after slashing
    pub resulting_status: SignerStatus,
    /// When the violation occurred
    pub violation_at: DateTime<Utc>,
    /// When slashing was applied
    pub slashed_at: DateTime<Utc>,
    /// Epoch when violation occurred
    pub epoch: u64,
}

/// Admission request from candidate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionRequest {
    /// Request identifier
    pub request_id: String,
    /// Candidate actor ID
    pub candidate_id: ActorId,
    /// Candidate public key
    pub public_key: String,
    /// Initial stake amount
    pub stake_amount: u64,
    /// Request timestamp
    pub requested_at: DateTime<Utc>,
    /// Request status
    pub status: AdmissionStatus,
    /// Approvals from existing signers
    pub approvals: Vec<SignerApproval>,
    /// Rejections from existing signers
    pub rejections: Vec<SignerRejection>,
    /// When decided
    pub decided_at: Option<DateTime<Utc>>,
}

/// Admission request status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
    Withdrawn,
}

impl AdmissionRequest {
    /// Check if request has enough approvals
    pub fn has_enough_approvals(&self, policy: &AdmissionPolicy) -> bool {
        self.approvals.len() >= policy.required_approvals as usize
    }

    /// Check if request is rejected
    pub fn is_rejected(&self, total_signers: usize) -> bool {
        // Rejected if more than half reject
        self.rejections.len() > total_signers / 2
    }
}

/// Signer approval for admission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerApproval {
    pub signer_id: ActorId,
    pub approved_at: DateTime<Utc>,
    pub signature: String,
}

/// Signer rejection for admission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerRejection {
    pub signer_id: ActorId,
    pub rejected_at: DateTime<Utc>,
    pub reason: String,
    pub signature: String,
}

/// Signer set snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerSetSnapshot {
    /// Snapshot version
    pub version: u64,
    /// Active signers
    pub active_signers: Vec<SignerRecord>,
    /// Suspended signers
    pub suspended_signers: Vec<SignerRecord>,
    /// Candidates
    pub candidates: Vec<AdmissionRequest>,
    /// Current admission policy
    pub admission_policy: AdmissionPolicy,
    /// Current slashing policy
    pub slashing_policy: SlashingPolicy,
    /// Snapshot timestamp
    pub snapshot_at: DateTime<Utc>,
    /// Total stake in the set
    pub total_stake: u64,
}

impl SignerSetSnapshot {
    /// Get signer by ID
    pub fn get_signer(&self, signer_id: &ActorId) -> Option<&SignerRecord> {
        self.active_signers
            .iter()
            .chain(self.suspended_signers.iter())
            .find(|s| &s.signer_id == signer_id)
    }

    /// Check if we have enough active signers
    pub fn has_quorum(&self, threshold: usize) -> bool {
        self.active_signers.len() >= threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policies() {
        let admission = AdmissionPolicy::default();
        assert_eq!(admission.required_approvals, 5);
        assert_eq!(admission.min_reputation, 500);

        let slashing = SlashingPolicy::default();
        assert_eq!(slashing.double_sign_slash_bps, 5000);
    }

    #[test]
    fn test_signer_uptime() {
        let signer = SignerRecord {
            signer_id: ActorId("test".to_string()),
            public_key: "key".to_string(),
            status: SignerStatus::Active,
            reputation_score: 800,
            epochs_participated: 100,
            missed_signatures: 5,
            successful_signatures: 95,
            slashing_count: 0,
            total_slashed: 0,
            joined_at: Utc::now(),
            last_active_at: Utc::now(),
            stake_amount: 100_000,
            locked_stake: 0,
        };

        assert_eq!(signer.uptime_percentage(), 95.0);
    }

    #[test]
    fn test_admission_approvals() {
        let request = AdmissionRequest {
            request_id: "test".to_string(),
            candidate_id: ActorId("candidate".to_string()),
            public_key: "key".to_string(),
            stake_amount: 100_000,
            requested_at: Utc::now(),
            status: AdmissionStatus::Pending,
            approvals: vec![
                SignerApproval {
                    signer_id: ActorId("s1".to_string()),
                    approved_at: Utc::now(),
                    signature: "sig1".to_string(),
                },
                SignerApproval {
                    signer_id: ActorId("s2".to_string()),
                    approved_at: Utc::now(),
                    signature: "sig2".to_string(),
                },
            ],
            rejections: Vec::new(),
            decided_at: None,
        };

        let policy = AdmissionPolicy::default();
        assert!(!request.has_enough_approvals(&policy)); // Needs 5
    }
}
