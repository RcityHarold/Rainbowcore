//! Degraded Mode Detector
//!
//! Detects and manages degraded mode flags.

use super::{
    DegradedSeverity, DegradedSource, DegradedModeStatus, ExtendedDegradedFlag, AllowedOperation,
};
use crate::error::{P3Error, P3Result};
use crate::types::DegradedFlag;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Degraded mode detector
pub struct DegradedModeDetector {
    /// Active flags
    flags: HashMap<String, ExtendedDegradedFlag>,
    /// Detection rules
    rules: Vec<DetectionRule>,
    /// Status history
    status_history: Vec<DegradedModeStatus>,
    /// Max history size
    max_history: usize,
}

impl DegradedModeDetector {
    /// Create new detector
    pub fn new() -> Self {
        Self {
            flags: HashMap::new(),
            rules: Self::default_rules(),
            status_history: Vec::new(),
            max_history: 100,
        }
    }

    /// Set max history size
    pub fn with_max_history(mut self, max: usize) -> Self {
        self.max_history = max;
        self
    }

    /// Add detection rule
    pub fn add_rule(&mut self, rule: DetectionRule) {
        self.rules.push(rule);
    }

    /// Raise degraded flag
    pub fn raise_flag(
        &mut self,
        flag: DegradedFlag,
        severity: DegradedSeverity,
        source: DegradedSource,
    ) -> P3Result<()> {
        let key = flag.name().to_string();

        if self.flags.contains_key(&key) {
            // Update existing flag
            if let Some(existing) = self.flags.get_mut(&key) {
                existing.record_check();
                if severity > existing.severity {
                    existing.severity = severity;
                }
            }
        } else {
            // Add new flag
            let extended = ExtendedDegradedFlag::from_flag(flag, severity, source);
            self.flags.insert(key, extended);
        }

        self.record_status();
        Ok(())
    }

    /// Clear degraded flag
    pub fn clear_flag(&mut self, flag: &DegradedFlag) -> P3Result<bool> {
        let key = flag.name().to_string();
        let removed = self.flags.remove(&key).is_some();

        if removed {
            self.record_status();
        }

        Ok(removed)
    }

    /// Acknowledge flag
    pub fn acknowledge_flag(&mut self, flag: &DegradedFlag, by: impl Into<String>) -> P3Result<()> {
        let key = flag.name().to_string();

        let extended = self.flags.get_mut(&key).ok_or_else(|| P3Error::NotFound {
            entity: "DegradedFlag".to_string(),
            id: key,
        })?;

        extended.acknowledge(by);
        Ok(())
    }

    /// Check if degraded
    pub fn is_degraded(&self) -> bool {
        !self.flags.is_empty()
    }

    /// Get current status
    pub fn status(&self) -> DegradedModeStatus {
        let active_flags: Vec<_> = self.flags.values().cloned().collect();

        let effective_severity = active_flags
            .iter()
            .map(|f| f.severity.clone())
            .max()
            .unwrap_or(DegradedSeverity::Warning);

        DegradedModeStatus {
            active_flags,
            effective_severity,
            is_degraded: self.is_degraded(),
            last_change: Utc::now(),
            message: self.status_message(),
        }
    }

    /// Get flag by type
    pub fn get_flag(&self, flag: &DegradedFlag) -> Option<&ExtendedDegradedFlag> {
        self.flags.get(flag.name())
    }

    /// Check if specific flag is active
    pub fn has_flag(&self, flag: &DegradedFlag) -> bool {
        self.flags.contains_key(flag.name())
    }

    /// Get all active flags
    pub fn active_flags(&self) -> Vec<&ExtendedDegradedFlag> {
        self.flags.values().collect()
    }

    /// Get flags by severity
    pub fn flags_by_severity(&self, severity: &DegradedSeverity) -> Vec<&ExtendedDegradedFlag> {
        self.flags
            .values()
            .filter(|f| &f.severity == severity)
            .collect()
    }

    /// Check operation allowed
    pub fn is_operation_allowed(&self, operation: &AllowedOperation) -> bool {
        self.status().is_operation_allowed(operation)
    }

    /// Check if strong actions blocked
    pub fn are_strong_actions_blocked(&self) -> bool {
        self.flags
            .values()
            .any(|f| f.severity.blocks_strong_actions())
    }

    /// Run detection rules
    pub fn run_detection(&mut self, metrics: &DetectionMetrics) -> Vec<DegradedFlag> {
        let mut new_flags = Vec::new();

        for rule in &self.rules {
            if let Some((flag, severity)) = rule.evaluate(metrics) {
                let key = flag.name().to_string();
                if !self.flags.contains_key(&key) {
                    new_flags.push(flag.clone());
                    let extended = ExtendedDegradedFlag::from_flag(
                        flag,
                        severity,
                        DegradedSource::Internal,
                    );
                    self.flags.insert(key, extended);
                }
            }
        }

        if !new_flags.is_empty() {
            self.record_status();
        }

        new_flags
    }

    /// Get status history
    pub fn history(&self) -> &[DegradedModeStatus] {
        &self.status_history
    }

    /// Record current status to history
    fn record_status(&mut self) {
        let status = self.status();
        self.status_history.push(status);

        // Trim history
        while self.status_history.len() > self.max_history {
            self.status_history.remove(0);
        }
    }

    /// Generate status message
    fn status_message(&self) -> Option<String> {
        if self.flags.is_empty() {
            return None;
        }

        let count = self.flags.len();
        let max_severity = self
            .flags
            .values()
            .map(|f| f.severity.clone())
            .max()
            .unwrap_or(DegradedSeverity::Warning);

        Some(format!(
            "{} degraded flag(s) active, max severity: {}",
            count,
            max_severity.name()
        ))
    }

    /// Default detection rules
    fn default_rules() -> Vec<DetectionRule> {
        vec![
            DetectionRule {
                rule_id: "dsn_health".to_string(),
                description: "DSN health check".to_string(),
                check: DetectionCheck::MetricBelow {
                    metric: "dsn_health".to_string(),
                    threshold: 0.5,
                },
                flag_on_trigger: DegradedFlag::DsnDown,
                severity_on_trigger: DegradedSeverity::Restricted,
            },
            DetectionRule {
                rule_id: "version_drift".to_string(),
                description: "Version drift detection".to_string(),
                check: DetectionCheck::MetricAbove {
                    metric: "version_drift".to_string(),
                    threshold: 0.1,
                },
                flag_on_trigger: DegradedFlag::VersionDrift,
                severity_on_trigger: DegradedSeverity::Limited,
            },
        ]
    }
}

impl Default for DegradedModeDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Detection rule
#[derive(Clone, Debug)]
pub struct DetectionRule {
    /// Rule ID
    pub rule_id: String,
    /// Description
    pub description: String,
    /// Check to perform
    pub check: DetectionCheck,
    /// Flag to raise on trigger
    pub flag_on_trigger: DegradedFlag,
    /// Severity on trigger
    pub severity_on_trigger: DegradedSeverity,
}

impl DetectionRule {
    /// Evaluate rule against metrics
    pub fn evaluate(&self, metrics: &DetectionMetrics) -> Option<(DegradedFlag, DegradedSeverity)> {
        let triggered = match &self.check {
            DetectionCheck::MetricBelow { metric, threshold } => {
                metrics.get(metric).map(|v| *v < *threshold).unwrap_or(false)
            }
            DetectionCheck::MetricAbove { metric, threshold } => {
                metrics.get(metric).map(|v| *v > *threshold).unwrap_or(false)
            }
            DetectionCheck::MetricEquals { metric, value } => {
                metrics.get(metric).map(|v| (*v - *value).abs() < f64::EPSILON).unwrap_or(false)
            }
            DetectionCheck::FlagPresent { flag } => metrics.flags.contains(flag),
        };

        if triggered {
            Some((self.flag_on_trigger.clone(), self.severity_on_trigger.clone()))
        } else {
            None
        }
    }
}

/// Detection check type
#[derive(Clone, Debug)]
pub enum DetectionCheck {
    /// Metric below threshold
    MetricBelow { metric: String, threshold: f64 },
    /// Metric above threshold
    MetricAbove { metric: String, threshold: f64 },
    /// Metric equals value
    MetricEquals { metric: String, value: f64 },
    /// Another flag is present
    FlagPresent { flag: DegradedFlag },
}

/// Detection metrics input
#[derive(Clone, Debug, Default)]
pub struct DetectionMetrics {
    /// Numeric metrics
    pub metrics: HashMap<String, f64>,
    /// Current flags
    pub flags: Vec<DegradedFlag>,
}

impl DetectionMetrics {
    /// Create new metrics
    pub fn new() -> Self {
        Self::default()
    }

    /// Set metric
    pub fn set(&mut self, name: impl Into<String>, value: f64) {
        self.metrics.insert(name.into(), value);
    }

    /// Get metric
    pub fn get(&self, name: &str) -> Option<&f64> {
        self.metrics.get(name)
    }

    /// Add flag
    pub fn add_flag(&mut self, flag: DegradedFlag) {
        self.flags.push(flag);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_creation() {
        let detector = DegradedModeDetector::new();
        assert!(!detector.is_degraded());
    }

    #[test]
    fn test_raise_and_clear_flag() {
        let mut detector = DegradedModeDetector::new();

        detector
            .raise_flag(
                DegradedFlag::DsnDown,
                DegradedSeverity::Restricted,
                DegradedSource::Internal,
            )
            .unwrap();

        assert!(detector.is_degraded());
        assert!(detector.has_flag(&DegradedFlag::DsnDown));

        detector.clear_flag(&DegradedFlag::DsnDown).unwrap();
        assert!(!detector.is_degraded());
    }

    #[test]
    fn test_strong_actions_blocked() {
        let mut detector = DegradedModeDetector::new();

        detector
            .raise_flag(
                DegradedFlag::DsnDown,
                DegradedSeverity::Restricted,
                DegradedSource::Internal,
            )
            .unwrap();

        assert!(detector.are_strong_actions_blocked());

        detector.clear_flag(&DegradedFlag::DsnDown).unwrap();
        assert!(!detector.are_strong_actions_blocked());
    }

    #[test]
    fn test_acknowledge_flag() {
        let mut detector = DegradedModeDetector::new();

        detector
            .raise_flag(
                DegradedFlag::VersionDrift,
                DegradedSeverity::Warning,
                DegradedSource::Internal,
            )
            .unwrap();

        detector
            .acknowledge_flag(&DegradedFlag::VersionDrift, "admin")
            .unwrap();

        let flag = detector.get_flag(&DegradedFlag::VersionDrift).unwrap();
        assert!(flag.acknowledged);
    }

    #[test]
    fn test_run_detection() {
        let mut detector = DegradedModeDetector::new();
        let mut metrics = DetectionMetrics::new();

        // Set DSN health below threshold
        metrics.set("dsn_health", 0.3);

        let new_flags = detector.run_detection(&metrics);
        assert_eq!(new_flags.len(), 1);
        assert!(detector.has_flag(&DegradedFlag::DsnDown));
    }

    #[test]
    fn test_status() {
        let mut detector = DegradedModeDetector::new();

        detector
            .raise_flag(
                DegradedFlag::DsnDown,
                DegradedSeverity::SafeMode,
                DegradedSource::Internal,
            )
            .unwrap();

        let status = detector.status();
        assert!(status.is_degraded);
        assert_eq!(status.effective_severity, DegradedSeverity::SafeMode);
        assert!(!status.is_operation_allowed(&AllowedOperation::StrongAction));
    }

    #[test]
    fn test_status_history() {
        let mut detector = DegradedModeDetector::new().with_max_history(5);

        for _ in 0..10 {
            detector
                .raise_flag(
                    DegradedFlag::DsnDown,
                    DegradedSeverity::Warning,
                    DegradedSource::Internal,
                )
                .unwrap();
        }

        assert!(detector.history().len() <= 5);
    }
}
