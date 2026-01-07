//! Alert System
//!
//! Provides alerting for sampling failures and other critical events.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use super::sampling_report::{FailureDetail, FailureSeverity, HealthStatus, SamplingReport};

/// Alert severity level
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

impl From<FailureSeverity> for AlertSeverity {
    fn from(severity: FailureSeverity) -> Self {
        match severity {
            FailureSeverity::Critical => AlertSeverity::Critical,
            FailureSeverity::High => AlertSeverity::Error,
            FailureSeverity::Medium => AlertSeverity::Warning,
            FailureSeverity::Low => AlertSeverity::Info,
        }
    }
}

impl From<HealthStatus> for AlertSeverity {
    fn from(status: HealthStatus) -> Self {
        match status {
            HealthStatus::Critical => AlertSeverity::Critical,
            HealthStatus::Warning => AlertSeverity::Error,
            HealthStatus::Degraded => AlertSeverity::Warning,
            HealthStatus::Healthy => AlertSeverity::Info,
        }
    }
}

/// Alert type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AlertType {
    /// Integrity check failure
    IntegrityFailure,
    /// Sampling run health degraded
    HealthDegraded,
    /// High failure rate
    HighFailureRate,
    /// Backend connectivity issue
    BackendConnectivity,
    /// Performance degradation
    PerformanceDegraded,
    /// Manual alert
    Manual,
}

/// An alert notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Unique alert ID
    pub alert_id: String,
    /// Alert timestamp
    pub timestamp: DateTime<Utc>,
    /// Alert type
    pub alert_type: AlertType,
    /// Severity level
    pub severity: AlertSeverity,
    /// Alert title
    pub title: String,
    /// Alert message
    pub message: String,
    /// Related payload references
    pub related_refs: Vec<String>,
    /// Metadata
    pub metadata: HashMap<String, String>,
    /// Whether alert has been acknowledged
    pub acknowledged: bool,
    /// Acknowledgement timestamp
    pub acknowledged_at: Option<DateTime<Utc>>,
    /// Acknowledgement user
    pub acknowledged_by: Option<String>,
}

/// Alert handler trait
#[async_trait]
pub trait AlertHandler: Send + Sync {
    /// Handle an alert
    async fn handle(&self, alert: &Alert) -> Result<(), String>;

    /// Handler name for identification
    fn name(&self) -> &str;
}

/// Logging alert handler (default)
pub struct LoggingAlertHandler;

#[async_trait]
impl AlertHandler for LoggingAlertHandler {
    async fn handle(&self, alert: &Alert) -> Result<(), String> {
        match alert.severity {
            AlertSeverity::Critical => {
                error!(
                    alert_id = %alert.alert_id,
                    alert_type = ?alert.alert_type,
                    title = %alert.title,
                    message = %alert.message,
                    "CRITICAL ALERT"
                );
            }
            AlertSeverity::Error => {
                error!(
                    alert_id = %alert.alert_id,
                    alert_type = ?alert.alert_type,
                    title = %alert.title,
                    message = %alert.message,
                    "ERROR ALERT"
                );
            }
            AlertSeverity::Warning => {
                warn!(
                    alert_id = %alert.alert_id,
                    alert_type = ?alert.alert_type,
                    title = %alert.title,
                    message = %alert.message,
                    "WARNING ALERT"
                );
            }
            AlertSeverity::Info => {
                info!(
                    alert_id = %alert.alert_id,
                    alert_type = ?alert.alert_type,
                    title = %alert.title,
                    message = %alert.message,
                    "INFO ALERT"
                );
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "logging"
    }
}

/// Webhook alert handler
pub struct WebhookAlertHandler {
    endpoint: String,
    headers: HashMap<String, String>,
}

impl WebhookAlertHandler {
    pub fn new(endpoint: String) -> Self {
        Self {
            endpoint,
            headers: HashMap::new(),
        }
    }

    pub fn with_header(mut self, key: String, value: String) -> Self {
        self.headers.insert(key, value);
        self
    }
}

#[async_trait]
impl AlertHandler for WebhookAlertHandler {
    async fn handle(&self, alert: &Alert) -> Result<(), String> {
        // In production, this would send an HTTP request
        // For now, just log that we would send
        info!(
            endpoint = %self.endpoint,
            alert_id = %alert.alert_id,
            "Would send webhook alert"
        );
        Ok(())
    }

    fn name(&self) -> &str {
        "webhook"
    }
}

/// Alert configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Minimum severity to trigger alerts
    pub min_severity: AlertSeverity,
    /// Whether to deduplicate similar alerts
    pub deduplicate: bool,
    /// Deduplication window in seconds
    pub dedupe_window_secs: u64,
    /// Maximum alerts per window (rate limiting)
    pub max_alerts_per_window: usize,
    /// Alert window in seconds
    pub alert_window_secs: u64,
    /// Failure rate threshold for alerts
    pub failure_rate_threshold: f64,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            min_severity: AlertSeverity::Warning,
            deduplicate: true,
            dedupe_window_secs: 300,  // 5 minutes
            max_alerts_per_window: 100,
            alert_window_secs: 3600, // 1 hour
            failure_rate_threshold: 0.01, // 1%
        }
    }
}

/// Alert manager service
pub struct AlertManager {
    config: AlertConfig,
    handlers: Vec<Arc<dyn AlertHandler>>,
    /// Recent alerts for deduplication
    recent_alerts: Arc<RwLock<Vec<Alert>>>,
    /// Alert count in current window
    window_count: Arc<RwLock<usize>>,
    /// Window start time
    window_start: Arc<RwLock<DateTime<Utc>>>,
}

impl AlertManager {
    /// Create a new alert manager
    pub fn new(config: AlertConfig) -> Self {
        Self {
            config,
            handlers: vec![Arc::new(LoggingAlertHandler)],
            recent_alerts: Arc::new(RwLock::new(Vec::new())),
            window_count: Arc::new(RwLock::new(0)),
            window_start: Arc::new(RwLock::new(Utc::now())),
        }
    }

    /// Add an alert handler
    pub fn add_handler(&mut self, handler: Arc<dyn AlertHandler>) {
        self.handlers.push(handler);
    }

    /// Create alert from sampling failure
    pub async fn alert_from_failure(&self, failure: &FailureDetail) -> Option<Alert> {
        let severity = AlertSeverity::from(failure.severity);

        if severity < self.config.min_severity {
            return None;
        }

        let alert = Alert {
            alert_id: format!("alert:{}", uuid::Uuid::new_v4()),
            timestamp: Utc::now(),
            alert_type: AlertType::IntegrityFailure,
            severity,
            title: format!("Integrity check failed for {}", failure.ref_id),
            message: format!(
                "{} check failed: {}. Suggested action: {}",
                failure.check_type, failure.error, failure.suggested_action
            ),
            related_refs: vec![failure.ref_id.clone()],
            metadata: {
                let mut m = HashMap::new();
                m.insert("temperature".to_string(), failure.temperature.clone());
                m.insert("check_type".to_string(), failure.check_type.clone());
                m
            },
            acknowledged: false,
            acknowledged_at: None,
            acknowledged_by: None,
        };

        self.send_alert(alert).await
    }

    /// Create alert from sampling report
    pub async fn alert_from_report(&self, report: &SamplingReport) -> Option<Alert> {
        let severity = AlertSeverity::from(report.health_status);

        if severity < self.config.min_severity {
            return None;
        }

        // Check failure rate threshold
        let failure_rate = 1.0 - report.summary.pass_rate;
        if failure_rate < self.config.failure_rate_threshold
            && report.health_status == HealthStatus::Healthy
        {
            return None;
        }

        let alert = Alert {
            alert_id: format!("alert:{}", uuid::Uuid::new_v4()),
            timestamp: Utc::now(),
            alert_type: if failure_rate >= self.config.failure_rate_threshold {
                AlertType::HighFailureRate
            } else {
                AlertType::HealthDegraded
            },
            severity,
            title: format!(
                "Sampling run {} completed with {:?} status",
                report.report_id, report.health_status
            ),
            message: format!(
                "Pass rate: {:.2}%, Failures: {}, Duration: {}s. {}",
                report.summary.pass_rate * 100.0,
                report.summary.checks_failed,
                report.duration_secs,
                report.recommendations.first().unwrap_or(&String::new())
            ),
            related_refs: report.failures.iter().map(|f| f.ref_id.clone()).collect(),
            metadata: {
                let mut m = HashMap::new();
                m.insert("report_id".to_string(), report.report_id.clone());
                m.insert(
                    "pass_rate".to_string(),
                    format!("{:.4}", report.summary.pass_rate),
                );
                m.insert(
                    "failure_count".to_string(),
                    report.summary.checks_failed.to_string(),
                );
                m
            },
            acknowledged: false,
            acknowledged_at: None,
            acknowledged_by: None,
        };

        self.send_alert(alert).await
    }

    /// Send an alert through all handlers
    async fn send_alert(&self, alert: Alert) -> Option<Alert> {
        // Check rate limiting
        if !self.check_rate_limit().await {
            warn!(alert_id = %alert.alert_id, "Alert rate limited");
            return None;
        }

        // Check deduplication
        if self.config.deduplicate && self.is_duplicate(&alert).await {
            info!(alert_id = %alert.alert_id, "Alert deduplicated");
            return None;
        }

        // Send to all handlers
        for handler in &self.handlers {
            if let Err(e) = handler.handle(&alert).await {
                error!(
                    handler = %handler.name(),
                    error = %e,
                    "Alert handler failed"
                );
            }
        }

        // Store in recent alerts
        self.recent_alerts.write().await.push(alert.clone());

        // Increment window count
        *self.window_count.write().await += 1;

        Some(alert)
    }

    /// Check if alert is rate limited
    async fn check_rate_limit(&self) -> bool {
        let now = Utc::now();
        let mut window_start = self.window_start.write().await;
        let mut window_count = self.window_count.write().await;

        // Reset window if expired
        let window_duration = chrono::Duration::seconds(self.config.alert_window_secs as i64);
        if now - *window_start > window_duration {
            *window_start = now;
            *window_count = 0;
        }

        *window_count < self.config.max_alerts_per_window
    }

    /// Check if alert is a duplicate
    async fn is_duplicate(&self, alert: &Alert) -> bool {
        let recent = self.recent_alerts.read().await;
        let cutoff = Utc::now()
            - chrono::Duration::seconds(self.config.dedupe_window_secs as i64);

        recent.iter().any(|a| {
            a.timestamp > cutoff
                && a.alert_type.eq(&alert.alert_type)
                && a.related_refs == alert.related_refs
        })
    }

    /// Get recent alerts
    pub async fn get_recent_alerts(&self, limit: usize) -> Vec<Alert> {
        let recent = self.recent_alerts.read().await;
        recent.iter().rev().take(limit).cloned().collect()
    }

    /// Acknowledge an alert
    pub async fn acknowledge(&self, alert_id: &str, user: &str) -> bool {
        let mut recent = self.recent_alerts.write().await;
        if let Some(alert) = recent.iter_mut().find(|a| a.alert_id == alert_id) {
            alert.acknowledged = true;
            alert.acknowledged_at = Some(Utc::now());
            alert.acknowledged_by = Some(user.to_string());
            true
        } else {
            false
        }
    }

    /// Clear old alerts
    pub async fn cleanup(&self, max_age_secs: u64) {
        let mut recent = self.recent_alerts.write().await;
        let cutoff = Utc::now() - chrono::Duration::seconds(max_age_secs as i64);
        recent.retain(|a| a.timestamp > cutoff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_alert_from_failure() {
        let manager = AlertManager::new(AlertConfig::default());

        let failure = FailureDetail {
            ref_id: "test:001".to_string(),
            temperature: "Hot".to_string(),
            check_type: "ChecksumVerification".to_string(),
            error: "Checksum mismatch".to_string(),
            checked_at: Utc::now(),
            severity: FailureSeverity::Critical,
            suggested_action: "Recover from backup".to_string(),
        };

        let alert = manager.alert_from_failure(&failure).await;
        assert!(alert.is_some());

        let alert = alert.unwrap();
        assert_eq!(alert.severity, AlertSeverity::Critical);
        assert!(alert.related_refs.contains(&"test:001".to_string()));
    }

    #[tokio::test]
    async fn test_deduplication() {
        let config = AlertConfig {
            deduplicate: true,
            dedupe_window_secs: 300,
            ..Default::default()
        };
        let manager = AlertManager::new(config);

        let failure = FailureDetail {
            ref_id: "test:001".to_string(),
            temperature: "Hot".to_string(),
            check_type: "ChecksumVerification".to_string(),
            error: "Checksum mismatch".to_string(),
            checked_at: Utc::now(),
            severity: FailureSeverity::High,
            suggested_action: "Investigate".to_string(),
        };

        // First alert should go through
        let alert1 = manager.alert_from_failure(&failure).await;
        assert!(alert1.is_some());

        // Duplicate should be filtered
        let alert2 = manager.alert_from_failure(&failure).await;
        assert!(alert2.is_none());
    }

    #[tokio::test]
    async fn test_severity_filtering() {
        let config = AlertConfig {
            min_severity: AlertSeverity::Error,
            ..Default::default()
        };
        let manager = AlertManager::new(config);

        let low_severity = FailureDetail {
            ref_id: "test:001".to_string(),
            temperature: "Cold".to_string(),
            check_type: "Accessibility".to_string(),
            error: "Minor issue".to_string(),
            checked_at: Utc::now(),
            severity: FailureSeverity::Low,
            suggested_action: "Monitor".to_string(),
        };

        // Low severity should be filtered
        let alert = manager.alert_from_failure(&low_severity).await;
        assert!(alert.is_none());
    }
}
