//! Degraded Mode Module
//!
//! Chapter 9: Degraded Mode and Recovery
//!
//! Manages system degradation detection and recovery:
//! - DegradedFlag detection and propagation
//! - Safe mode behavior enforcement
//! - Recovery condition evaluation
//! - Automatic recovery procedures

mod detector;
mod recovery;

pub use detector::*;
pub use recovery::*;

use crate::error::{P3Error, P3Result};
use crate::types::DegradedFlag;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Degraded mode severity
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DegradedSeverity {
    /// Warning only, operations continue
    Warning,
    /// Limited operations
    Limited,
    /// Strong actions blocked
    Restricted,
    /// All non-essential operations blocked
    SafeMode,
    /// System halt
    Critical,
}

impl DegradedSeverity {
    /// Get severity name
    pub fn name(&self) -> &'static str {
        match self {
            DegradedSeverity::Warning => "warning",
            DegradedSeverity::Limited => "limited",
            DegradedSeverity::Restricted => "restricted",
            DegradedSeverity::SafeMode => "safe_mode",
            DegradedSeverity::Critical => "critical",
        }
    }

    /// Check if strong actions are blocked
    pub fn blocks_strong_actions(&self) -> bool {
        matches!(
            self,
            DegradedSeverity::Restricted | DegradedSeverity::SafeMode | DegradedSeverity::Critical
        )
    }

    /// Check if read-only mode
    pub fn is_read_only(&self) -> bool {
        matches!(self, DegradedSeverity::SafeMode | DegradedSeverity::Critical)
    }

    /// Get allowed operations
    pub fn allowed_operations(&self) -> Vec<AllowedOperation> {
        match self {
            DegradedSeverity::Warning => vec![
                AllowedOperation::Read,
                AllowedOperation::Write,
                AllowedOperation::StrongAction,
            ],
            DegradedSeverity::Limited => vec![
                AllowedOperation::Read,
                AllowedOperation::Write,
            ],
            DegradedSeverity::Restricted => vec![
                AllowedOperation::Read,
                AllowedOperation::LimitedWrite,
            ],
            DegradedSeverity::SafeMode => vec![AllowedOperation::Read],
            DegradedSeverity::Critical => vec![],
        }
    }
}

/// Allowed operations in degraded mode
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AllowedOperation {
    /// Read operations
    Read,
    /// Write operations
    Write,
    /// Limited write (essential only)
    LimitedWrite,
    /// Strong economic actions
    StrongAction,
}

/// Extended degraded flag with metadata
#[derive(Clone, Debug)]
pub struct ExtendedDegradedFlag {
    /// Base flag
    pub flag: DegradedFlag,
    /// Severity
    pub severity: DegradedSeverity,
    /// Source of degradation
    pub source: DegradedSource,
    /// First detected
    pub first_detected: DateTime<Utc>,
    /// Last checked
    pub last_checked: DateTime<Utc>,
    /// Check count
    pub check_count: u32,
    /// Recovery attempts
    pub recovery_attempts: u32,
    /// Is acknowledged
    pub acknowledged: bool,
    /// Acknowledger
    pub acknowledged_by: Option<String>,
}

impl ExtendedDegradedFlag {
    /// Create from flag
    pub fn from_flag(flag: DegradedFlag, severity: DegradedSeverity, source: DegradedSource) -> Self {
        let now = Utc::now();
        Self {
            flag,
            severity,
            source,
            first_detected: now,
            last_checked: now,
            check_count: 1,
            recovery_attempts: 0,
            acknowledged: false,
            acknowledged_by: None,
        }
    }

    /// Acknowledge flag
    pub fn acknowledge(&mut self, by: impl Into<String>) {
        self.acknowledged = true;
        self.acknowledged_by = Some(by.into());
    }

    /// Record check
    pub fn record_check(&mut self) {
        self.last_checked = Utc::now();
        self.check_count += 1;
    }

    /// Record recovery attempt
    pub fn record_recovery_attempt(&mut self) {
        self.recovery_attempts += 1;
    }

    /// Get duration since first detected
    pub fn duration(&self, now: &DateTime<Utc>) -> chrono::Duration {
        *now - self.first_detected
    }
}

/// Source of degradation
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DegradedSource {
    /// Internal detection
    Internal,
    /// External notification
    External,
    /// Manual flag
    Manual,
    /// Cascade from dependency
    Cascade,
    /// Scheduled maintenance
    Maintenance,
}

/// Degraded mode status
#[derive(Clone, Debug)]
pub struct DegradedModeStatus {
    /// Active flags
    pub active_flags: Vec<ExtendedDegradedFlag>,
    /// Effective severity (highest of all flags)
    pub effective_severity: DegradedSeverity,
    /// In degraded mode
    pub is_degraded: bool,
    /// Last status change
    pub last_change: DateTime<Utc>,
    /// Status message
    pub message: Option<String>,
}

impl DegradedModeStatus {
    /// Create healthy status
    pub fn healthy() -> Self {
        Self {
            active_flags: Vec::new(),
            effective_severity: DegradedSeverity::Warning,
            is_degraded: false,
            last_change: Utc::now(),
            message: None,
        }
    }

    /// Check if operations of type are allowed
    pub fn is_operation_allowed(&self, operation: &AllowedOperation) -> bool {
        if !self.is_degraded {
            return true;
        }
        self.effective_severity.allowed_operations().contains(operation)
    }
}

/// Recovery condition
#[derive(Clone, Debug)]
pub struct RecoveryCondition {
    /// Condition ID
    pub condition_id: String,
    /// Related flag
    pub flag: DegradedFlag,
    /// Condition type
    pub condition_type: RecoveryConditionType,
    /// Threshold value
    pub threshold: Option<f64>,
    /// Current value
    pub current_value: Option<f64>,
    /// Is met
    pub is_met: bool,
    /// Last evaluated
    pub last_evaluated: DateTime<Utc>,
}

impl RecoveryCondition {
    /// Create new condition
    pub fn new(
        condition_id: impl Into<String>,
        flag: DegradedFlag,
        condition_type: RecoveryConditionType,
    ) -> Self {
        Self {
            condition_id: condition_id.into(),
            flag,
            condition_type,
            threshold: None,
            current_value: None,
            is_met: false,
            last_evaluated: Utc::now(),
        }
    }

    /// Set threshold
    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.threshold = Some(threshold);
        self
    }

    /// Evaluate condition
    pub fn evaluate(&mut self, value: f64) -> bool {
        self.current_value = Some(value);
        self.last_evaluated = Utc::now();

        self.is_met = match &self.condition_type {
            RecoveryConditionType::ValueAbove => {
                self.threshold.map(|t| value > t).unwrap_or(false)
            }
            RecoveryConditionType::ValueBelow => {
                self.threshold.map(|t| value < t).unwrap_or(false)
            }
            RecoveryConditionType::Stable => true, // Would need history
            RecoveryConditionType::ServiceUp => value > 0.0,
            RecoveryConditionType::Manual => false, // Requires manual action
        };

        self.is_met
    }
}

/// Recovery condition type
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryConditionType {
    /// Value above threshold
    ValueAbove,
    /// Value below threshold
    ValueBelow,
    /// Value stable for period
    Stable,
    /// Service is up
    ServiceUp,
    /// Manual confirmation required
    Manual,
}

/// Recovery action
#[derive(Clone, Debug)]
pub struct RecoveryAction {
    /// Action ID
    pub action_id: String,
    /// Flag to recover
    pub flag: DegradedFlag,
    /// Action type
    pub action_type: RecoveryActionType,
    /// Priority
    pub priority: u32,
    /// Status
    pub status: RecoveryActionStatus,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Executed at
    pub executed_at: Option<DateTime<Utc>>,
    /// Result
    pub result: Option<RecoveryResult>,
}

impl RecoveryAction {
    /// Create new action
    pub fn new(
        action_id: impl Into<String>,
        flag: DegradedFlag,
        action_type: RecoveryActionType,
    ) -> Self {
        Self {
            action_id: action_id.into(),
            flag,
            action_type,
            priority: 0,
            status: RecoveryActionStatus::Pending,
            created_at: Utc::now(),
            executed_at: None,
            result: None,
        }
    }

    /// Set priority
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }
}

/// Recovery action type
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryActionType {
    /// Automatic retry
    AutoRetry,
    /// Clear flag
    ClearFlag,
    /// Escalate to operator
    Escalate,
    /// Restart service
    RestartService,
    /// Failover to backup
    Failover,
    /// Manual intervention
    ManualIntervention,
}

/// Recovery action status
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryActionStatus {
    /// Pending
    Pending,
    /// In progress
    InProgress,
    /// Completed
    Completed,
    /// Failed
    Failed,
    /// Skipped
    Skipped,
}

/// Recovery result
#[derive(Clone, Debug)]
pub struct RecoveryResult {
    /// Success
    pub success: bool,
    /// Message
    pub message: String,
    /// New flags (if any)
    pub new_flags: Vec<DegradedFlag>,
    /// Completed at
    pub completed_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_degraded_severity_order() {
        assert!(DegradedSeverity::Critical > DegradedSeverity::SafeMode);
        assert!(DegradedSeverity::SafeMode > DegradedSeverity::Restricted);
        assert!(DegradedSeverity::Restricted > DegradedSeverity::Limited);
        assert!(DegradedSeverity::Limited > DegradedSeverity::Warning);
    }

    #[test]
    fn test_severity_blocks_strong_actions() {
        assert!(!DegradedSeverity::Warning.blocks_strong_actions());
        assert!(!DegradedSeverity::Limited.blocks_strong_actions());
        assert!(DegradedSeverity::Restricted.blocks_strong_actions());
        assert!(DegradedSeverity::SafeMode.blocks_strong_actions());
    }

    #[test]
    fn test_extended_flag() {
        let mut flag = ExtendedDegradedFlag::from_flag(
            DegradedFlag::DsnDown,
            DegradedSeverity::Restricted,
            DegradedSource::Internal,
        );

        assert!(!flag.acknowledged);
        flag.acknowledge("admin");
        assert!(flag.acknowledged);
        assert_eq!(flag.acknowledged_by, Some("admin".to_string()));
    }

    #[test]
    fn test_recovery_condition_evaluate() {
        let mut condition = RecoveryCondition::new(
            "cond:1",
            DegradedFlag::DsnDown,
            RecoveryConditionType::ValueAbove,
        )
        .with_threshold(0.9);

        assert!(!condition.is_met);
        condition.evaluate(0.95);
        assert!(condition.is_met);

        condition.evaluate(0.85);
        assert!(!condition.is_met);
    }

    #[test]
    fn test_degraded_mode_status() {
        let status = DegradedModeStatus::healthy();
        assert!(!status.is_degraded);
        assert!(status.is_operation_allowed(&AllowedOperation::StrongAction));
    }
}
