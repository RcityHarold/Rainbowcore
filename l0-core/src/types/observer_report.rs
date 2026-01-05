//! Observer Report Types
//!
//! Defines reports submitted by observer nodes about network health,
//! signer behavior, and consensus anomalies.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use super::common::Digest;
use super::actor::ActorId;

/// Observer node status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObserverStatus {
    /// Actively monitoring
    Active,
    /// Syncing with network
    Syncing,
    /// Temporarily offline
    Offline,
    /// Suspended for invalid reports
    Suspended,
    /// Removed from observer set
    Removed,
}

/// Type of observation report
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportType {
    /// Network health metrics
    NetworkHealth,
    /// Signer performance report
    SignerPerformance,
    /// Consensus anomaly detected
    ConsensusAnomaly,
    /// Double signing evidence
    DoubleSignEvidence,
    /// Missed signature report
    MissedSignature,
    /// Downtime report
    DowntimeReport,
    /// Block validation report
    BlockValidation,
    /// Tip chain integrity
    TipChainIntegrity,
}

/// Severity level of the report
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportSeverity {
    /// Informational only
    Info,
    /// Low priority issue
    Low,
    /// Medium priority issue
    Medium,
    /// High priority - needs attention
    High,
    /// Critical - immediate action required
    Critical,
}

/// Observer report submission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObserverReport {
    /// Unique report identifier
    pub report_id: String,
    /// Observer who submitted the report
    pub observer_id: ActorId,
    /// Type of report
    pub report_type: ReportType,
    /// Severity level
    pub severity: ReportSeverity,
    /// Subject of the report (e.g., signer ID, epoch)
    pub subject_id: Option<String>,
    /// Report title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Evidence digest (hash of supporting data)
    pub evidence_digest: Option<Digest>,
    /// Epoch when observation was made
    pub observed_epoch: u64,
    /// When the observation was made
    pub observed_at: DateTime<Utc>,
    /// When the report was submitted
    pub submitted_at: DateTime<Utc>,
    /// Report status
    pub status: ReportStatus,
    /// Corroborating observers (other observers who confirmed)
    pub corroborations: Vec<ReportCorroboration>,
    /// Minimum corroborations needed
    pub min_corroborations: u32,
    /// Resolution details
    pub resolution: Option<ReportResolution>,
}

/// Report processing status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    /// Awaiting corroboration
    Pending,
    /// Corroborated by other observers
    Corroborated,
    /// Being investigated
    UnderReview,
    /// Confirmed and action taken
    Confirmed,
    /// Dismissed as invalid
    Dismissed,
    /// Expired before action
    Expired,
}

/// Corroboration from another observer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportCorroboration {
    /// Corroborating observer
    pub observer_id: ActorId,
    /// Their evidence digest
    pub evidence_digest: Option<Digest>,
    /// When they corroborated
    pub corroborated_at: DateTime<Utc>,
    /// Additional notes
    pub notes: Option<String>,
    /// Signature
    pub signature: String,
}

/// Resolution of a report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportResolution {
    /// Who resolved the report
    pub resolved_by: ActorId,
    /// Resolution status
    pub outcome: ResolutionOutcome,
    /// Actions taken
    pub actions_taken: Vec<String>,
    /// When resolved
    pub resolved_at: DateTime<Utc>,
    /// Resolution notes
    pub notes: Option<String>,
}

/// Outcome of report resolution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionOutcome {
    /// Report was valid, action taken
    ActionTaken,
    /// Report was valid, no action needed
    NoActionNeeded,
    /// Report was false positive
    FalsePositive,
    /// Insufficient evidence
    InsufficientEvidence,
    /// Duplicate of another report
    Duplicate,
}

/// Observer node record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObserverRecord {
    /// Observer actor ID
    pub observer_id: ActorId,
    /// Observer public key
    pub public_key: String,
    /// Current status
    pub status: ObserverStatus,
    /// Reputation score (0-1000)
    pub reputation_score: u32,
    /// Total reports submitted
    pub total_reports: u64,
    /// Valid reports (confirmed)
    pub valid_reports: u64,
    /// Invalid reports (dismissed)
    pub invalid_reports: u64,
    /// When registered
    pub registered_at: DateTime<Utc>,
    /// Last report timestamp
    pub last_report_at: Option<DateTime<Utc>>,
    /// Last heartbeat
    pub last_heartbeat_at: DateTime<Utc>,
}

impl ObserverRecord {
    /// Calculate report accuracy percentage
    pub fn accuracy_percentage(&self) -> f64 {
        let total = self.valid_reports + self.invalid_reports;
        if total == 0 {
            return 100.0;
        }
        (self.valid_reports as f64 / total as f64) * 100.0
    }

    /// Check if observer is in good standing
    pub fn is_in_good_standing(&self) -> bool {
        self.status == ObserverStatus::Active
            && self.reputation_score >= 300
            && self.accuracy_percentage() >= 80.0
    }
}

impl ObserverReport {
    /// Check if report has enough corroborations
    pub fn has_enough_corroborations(&self) -> bool {
        self.corroborations.len() >= self.min_corroborations as usize
    }

    /// Check if report is actionable
    pub fn is_actionable(&self) -> bool {
        self.status == ReportStatus::Corroborated
            || (self.status == ReportStatus::Pending
                && self.severity >= ReportSeverity::High)
    }
}

/// Network health snapshot from observers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkHealthSnapshot {
    /// Snapshot ID
    pub snapshot_id: String,
    /// Epoch
    pub epoch: u64,
    /// Active signers count
    pub active_signers: u32,
    /// Active observers count
    pub active_observers: u32,
    /// Average block time (ms)
    pub avg_block_time_ms: u64,
    /// Missed signatures in epoch
    pub missed_signatures: u32,
    /// Double sign attempts detected
    pub double_sign_attempts: u32,
    /// Network connectivity score (0-100)
    pub connectivity_score: u8,
    /// Consensus health score (0-100)
    pub consensus_score: u8,
    /// Timestamp
    pub snapshot_at: DateTime<Utc>,
    /// Contributing observers
    pub contributing_observers: Vec<ActorId>,
}

/// Observer report policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObserverReportPolicy {
    /// Minimum corroborations for low severity
    pub min_corroborations_low: u32,
    /// Minimum corroborations for medium severity
    pub min_corroborations_medium: u32,
    /// Minimum corroborations for high/critical
    pub min_corroborations_high: u32,
    /// Report expiry time in seconds
    pub report_expiry_secs: u64,
    /// Minimum reputation to submit reports
    pub min_reputation: u32,
    /// Reputation penalty for invalid report
    pub invalid_report_penalty: u32,
    /// Reputation reward for valid report
    pub valid_report_reward: u32,
    /// Maximum reports per epoch per observer
    pub max_reports_per_epoch: u32,
}

impl Default for ObserverReportPolicy {
    fn default() -> Self {
        Self {
            min_corroborations_low: 1,
            min_corroborations_medium: 2,
            min_corroborations_high: 3,
            report_expiry_secs: 86400, // 24 hours
            min_reputation: 300,
            invalid_report_penalty: 50,
            valid_report_reward: 10,
            max_reports_per_epoch: 10,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_observer_accuracy() {
        let observer = ObserverRecord {
            observer_id: ActorId("obs1".to_string()),
            public_key: "key".to_string(),
            status: ObserverStatus::Active,
            reputation_score: 500,
            total_reports: 100,
            valid_reports: 90,
            invalid_reports: 10,
            registered_at: Utc::now(),
            last_report_at: Some(Utc::now()),
            last_heartbeat_at: Utc::now(),
        };

        assert_eq!(observer.accuracy_percentage(), 90.0);
        assert!(observer.is_in_good_standing());
    }

    #[test]
    fn test_report_severity_ordering() {
        assert!(ReportSeverity::Critical > ReportSeverity::High);
        assert!(ReportSeverity::High > ReportSeverity::Medium);
        assert!(ReportSeverity::Medium > ReportSeverity::Low);
        assert!(ReportSeverity::Low > ReportSeverity::Info);
    }

    #[test]
    fn test_default_policy() {
        let policy = ObserverReportPolicy::default();
        assert_eq!(policy.min_corroborations_high, 3);
        assert_eq!(policy.min_reputation, 300);
    }
}
