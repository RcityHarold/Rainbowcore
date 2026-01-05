//! Degraded Mode Policy Types
//!
//! Defines policies and states for operating in degraded conditions:
//! - Insufficient signers
//! - Network partition
//! - Consensus failures
//! - Byzantine behavior detected

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use super::actor::ActorId;

/// Current network operational mode
/// Ordered from best (Normal) to worst (Halted)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationalMode {
    /// Normal operation - all systems functional
    Normal,
    /// Warning - approaching degraded conditions
    Warning,
    /// Degraded - reduced functionality
    Degraded,
    /// Emergency - minimal operations only
    Emergency,
    /// Halted - no operations until resolved
    Halted,
    /// Recovery - transitioning back to normal
    Recovery,
}

/// Reason for degraded mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradedReason {
    /// Insufficient active signers
    InsufficientSigners,
    /// Network connectivity issues
    NetworkPartition,
    /// Consensus cannot be reached
    ConsensusFailure,
    /// Byzantine behavior detected
    ByzantineBehavior,
    /// Storage system issues
    StorageFailure,
    /// External anchor unavailable
    AnchorUnavailable,
    /// High latency conditions
    HighLatency,
    /// Resource exhaustion
    ResourceExhaustion,
    /// Scheduled maintenance
    ScheduledMaintenance,
}

/// Severity level of degradation
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradationLevel {
    /// Minor impact, most operations continue
    Minor,
    /// Moderate impact, some operations restricted
    Moderate,
    /// Severe impact, essential operations only
    Severe,
    /// Critical, system halt imminent
    Critical,
}

/// Operation type for access control during degraded mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationType {
    /// Read operations (queries, lookups)
    Read,
    /// Write operations (create, update)
    Write,
    /// Signing operations
    Sign,
    /// Consensus participation
    Consensus,
    /// External anchoring
    Anchor,
    /// Emergency overrides
    Emergency,
    /// Administrative operations
    Admin,
    /// Recovery operations
    Recovery,
}

/// Degraded mode status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegradedModeStatus {
    /// Current operational mode
    pub mode: OperationalMode,
    /// Active degradation reasons
    pub active_reasons: Vec<DegradedReason>,
    /// Overall degradation level
    pub level: DegradationLevel,
    /// When degraded mode started
    pub started_at: Option<DateTime<Utc>>,
    /// Expected resolution time
    pub expected_resolution: Option<DateTime<Utc>>,
    /// Current active signers count
    pub active_signers: u32,
    /// Required signers for normal operation
    pub required_signers: u32,
    /// Network health score (0-100)
    pub network_health: u8,
    /// Consensus success rate (0-100)
    pub consensus_rate: u8,
    /// Last status update
    pub updated_at: DateTime<Utc>,
    /// Status message
    pub status_message: String,
}

impl DegradedModeStatus {
    /// Check if system can perform operation type
    pub fn can_perform(&self, op_type: OperationType, policy: &DegradedModePolicy) -> bool {
        match self.mode {
            OperationalMode::Normal => true,
            OperationalMode::Warning => true,
            OperationalMode::Degraded => {
                policy.degraded_allowed_ops.contains(&op_type)
            }
            OperationalMode::Emergency => {
                policy.emergency_allowed_ops.contains(&op_type)
            }
            OperationalMode::Halted => {
                matches!(op_type, OperationType::Recovery | OperationType::Admin)
            }
            OperationalMode::Recovery => {
                policy.recovery_allowed_ops.contains(&op_type)
            }
        }
    }

    /// Check if mode requires human intervention
    pub fn requires_human_intervention(&self) -> bool {
        matches!(self.mode, OperationalMode::Emergency | OperationalMode::Halted)
            || self.level >= DegradationLevel::Critical
    }
}

/// Policy for degraded mode operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegradedModePolicy {
    /// Minimum signers before warning
    pub min_signers_warning: u32,
    /// Minimum signers before degraded
    pub min_signers_degraded: u32,
    /// Minimum signers before emergency
    pub min_signers_emergency: u32,
    /// Minimum signers before halt
    pub min_signers_halt: u32,
    /// Network health threshold for warning (0-100)
    pub network_health_warning: u8,
    /// Network health threshold for degraded (0-100)
    pub network_health_degraded: u8,
    /// Consensus rate threshold for warning (0-100)
    pub consensus_rate_warning: u8,
    /// Consensus rate threshold for degraded (0-100)
    pub consensus_rate_degraded: u8,
    /// Operations allowed in degraded mode
    pub degraded_allowed_ops: Vec<OperationType>,
    /// Operations allowed in emergency mode
    pub emergency_allowed_ops: Vec<OperationType>,
    /// Operations allowed during recovery
    pub recovery_allowed_ops: Vec<OperationType>,
    /// Auto-recovery enabled
    pub auto_recovery_enabled: bool,
    /// Auto-recovery threshold (consecutive successful epochs)
    pub auto_recovery_threshold: u32,
    /// Alert notification channels
    pub alert_channels: Vec<String>,
}

impl Default for DegradedModePolicy {
    fn default() -> Self {
        Self {
            min_signers_warning: 8,
            min_signers_degraded: 6,
            min_signers_emergency: 4,
            min_signers_halt: 2,
            network_health_warning: 80,
            network_health_degraded: 60,
            consensus_rate_warning: 90,
            consensus_rate_degraded: 70,
            degraded_allowed_ops: vec![
                OperationType::Read,
                OperationType::Emergency,
                OperationType::Admin,
            ],
            emergency_allowed_ops: vec![
                OperationType::Read,
                OperationType::Emergency,
                OperationType::Recovery,
            ],
            recovery_allowed_ops: vec![
                OperationType::Read,
                OperationType::Write,
                OperationType::Recovery,
                OperationType::Admin,
            ],
            auto_recovery_enabled: true,
            auto_recovery_threshold: 10,
            alert_channels: vec!["operators".to_string()],
        }
    }
}

/// Degraded mode event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegradedModeEvent {
    /// Event identifier
    pub event_id: String,
    /// Event type
    pub event_type: DegradedEventType,
    /// Previous mode
    pub previous_mode: OperationalMode,
    /// New mode
    pub new_mode: OperationalMode,
    /// Reasons for the event
    pub reasons: Vec<DegradedReason>,
    /// Degradation level
    pub level: DegradationLevel,
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Epoch when event occurred
    pub epoch: u64,
    /// Triggered by (if manual)
    pub triggered_by: Option<ActorId>,
    /// Event details
    pub details: String,
}

/// Type of degraded mode event
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradedEventType {
    /// Entered degraded mode
    Entered,
    /// Exited degraded mode
    Exited,
    /// Escalated to higher severity
    Escalated,
    /// De-escalated to lower severity
    DeEscalated,
    /// Manual override applied
    ManualOverride,
    /// Auto-recovery triggered
    AutoRecovery,
    /// Alert dispatched
    AlertDispatched,
}

/// Recovery action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryAction {
    /// Action identifier
    pub action_id: String,
    /// Action type
    pub action_type: RecoveryActionType,
    /// Initiated by
    pub initiated_by: ActorId,
    /// Target (e.g., signer ID)
    pub target: Option<String>,
    /// When initiated
    pub initiated_at: DateTime<Utc>,
    /// When completed
    pub completed_at: Option<DateTime<Utc>>,
    /// Action status
    pub status: RecoveryActionStatus,
    /// Result details
    pub result: Option<String>,
}

/// Type of recovery action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryActionType {
    /// Restart a signer node
    RestartNode,
    /// Failover to backup
    Failover,
    /// Reduce threshold temporarily
    ReduceThreshold,
    /// Emergency signer admission
    EmergencyAdmission,
    /// Network reconnection
    NetworkReconnect,
    /// Storage recovery
    StorageRecovery,
    /// Full system restart
    SystemRestart,
    /// Manual intervention complete
    ManualIntervention,
}

/// Status of recovery action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryActionStatus {
    /// Pending execution
    Pending,
    /// Currently executing
    InProgress,
    /// Successfully completed
    Completed,
    /// Failed
    Failed,
    /// Cancelled
    Cancelled,
}

impl DegradedModePolicy {
    /// Determine operational mode from metrics
    pub fn determine_mode(
        &self,
        active_signers: u32,
        network_health: u8,
        consensus_rate: u8,
    ) -> OperationalMode {
        // Check signers first (most critical)
        if active_signers <= self.min_signers_halt {
            return OperationalMode::Halted;
        }
        if active_signers <= self.min_signers_emergency {
            return OperationalMode::Emergency;
        }
        if active_signers <= self.min_signers_degraded {
            return OperationalMode::Degraded;
        }
        if active_signers <= self.min_signers_warning {
            return OperationalMode::Warning;
        }

        // Check network health
        if network_health < self.network_health_degraded {
            return OperationalMode::Degraded;
        }
        if network_health < self.network_health_warning {
            return OperationalMode::Warning;
        }

        // Check consensus rate
        if consensus_rate < self.consensus_rate_degraded {
            return OperationalMode::Degraded;
        }
        if consensus_rate < self.consensus_rate_warning {
            return OperationalMode::Warning;
        }

        OperationalMode::Normal
    }

    /// Determine degradation level
    pub fn determine_level(
        &self,
        active_signers: u32,
        network_health: u8,
    ) -> DegradationLevel {
        if active_signers <= self.min_signers_halt || network_health < 30 {
            DegradationLevel::Critical
        } else if active_signers <= self.min_signers_emergency || network_health < 50 {
            DegradationLevel::Severe
        } else if active_signers <= self.min_signers_degraded || network_health < 70 {
            DegradationLevel::Moderate
        } else {
            DegradationLevel::Minor
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy() {
        let policy = DegradedModePolicy::default();
        assert_eq!(policy.min_signers_degraded, 6);
        assert!(policy.auto_recovery_enabled);
    }

    #[test]
    fn test_mode_determination() {
        let policy = DegradedModePolicy::default();

        assert_eq!(
            policy.determine_mode(9, 100, 100),
            OperationalMode::Normal
        );
        assert_eq!(
            policy.determine_mode(7, 100, 100),
            OperationalMode::Warning
        );
        assert_eq!(
            policy.determine_mode(5, 100, 100),
            OperationalMode::Degraded
        );
        assert_eq!(
            policy.determine_mode(3, 100, 100),
            OperationalMode::Emergency
        );
        assert_eq!(
            policy.determine_mode(2, 100, 100),
            OperationalMode::Halted
        );
    }

    #[test]
    fn test_level_determination() {
        let policy = DegradedModePolicy::default();

        assert_eq!(
            policy.determine_level(9, 100),
            DegradationLevel::Minor
        );
        assert_eq!(
            policy.determine_level(5, 60),
            DegradationLevel::Moderate
        );
        assert_eq!(
            policy.determine_level(3, 40),
            DegradationLevel::Severe
        );
        assert_eq!(
            policy.determine_level(2, 20),
            DegradationLevel::Critical
        );
    }

    #[test]
    fn test_operation_permissions() {
        let policy = DegradedModePolicy::default();
        let status = DegradedModeStatus {
            mode: OperationalMode::Degraded,
            active_reasons: vec![DegradedReason::InsufficientSigners],
            level: DegradationLevel::Moderate,
            started_at: Some(Utc::now()),
            expected_resolution: None,
            active_signers: 5,
            required_signers: 9,
            network_health: 80,
            consensus_rate: 90,
            updated_at: Utc::now(),
            status_message: "Degraded due to insufficient signers".to_string(),
        };

        assert!(status.can_perform(OperationType::Read, &policy));
        assert!(!status.can_perform(OperationType::Write, &policy));
        assert!(status.can_perform(OperationType::Emergency, &policy));
    }
}
