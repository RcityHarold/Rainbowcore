//! Compliance Audit Log
//!
//! Records compliance-related events for audit trail.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use super::rules::{RuleCategory, RuleSeverity};

/// Audit event type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    /// Compliance check performed
    ComplianceCheck,
    /// Violation detected
    ViolationDetected,
    /// Violation remediated
    ViolationRemediated,
    /// Rule enabled
    RuleEnabled,
    /// Rule disabled
    RuleDisabled,
    /// Policy changed
    PolicyChanged,
    /// Access granted
    AccessGranted,
    /// Access denied
    AccessDenied,
    /// Data access
    DataAccess,
    /// Data modification
    DataModification,
    /// Data deletion
    DataDeletion,
    /// Configuration change
    ConfigurationChange,
}

/// Compliance audit entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceAuditEntry {
    /// Entry ID
    pub id: String,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Event type
    pub event_type: AuditEventType,
    /// Actor (user/system)
    pub actor: String,
    /// Resource affected
    pub resource: Option<String>,
    /// Rule ID (if applicable)
    pub rule_id: Option<String>,
    /// Rule category
    pub category: Option<RuleCategory>,
    /// Severity
    pub severity: Option<RuleSeverity>,
    /// Event message
    pub message: String,
    /// Event details
    #[serde(default)]
    pub details: HashMap<String, serde_json::Value>,
    /// Source IP
    pub source_ip: Option<String>,
    /// User agent
    pub user_agent: Option<String>,
    /// Session ID
    pub session_id: Option<String>,
    /// Request ID
    pub request_id: Option<String>,
}

impl ComplianceAuditEntry {
    /// Create new audit entry
    pub fn new(event_type: AuditEventType, actor: &str, message: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            event_type,
            actor: actor.to_string(),
            resource: None,
            rule_id: None,
            category: None,
            severity: None,
            message: message.to_string(),
            details: HashMap::new(),
            source_ip: None,
            user_agent: None,
            session_id: None,
            request_id: None,
        }
    }

    /// Set resource
    pub fn with_resource(mut self, resource: &str) -> Self {
        self.resource = Some(resource.to_string());
        self
    }

    /// Set rule info
    pub fn with_rule(mut self, rule_id: &str, category: RuleCategory, severity: RuleSeverity) -> Self {
        self.rule_id = Some(rule_id.to_string());
        self.category = Some(category);
        self.severity = Some(severity);
        self
    }

    /// Add detail
    pub fn with_detail(mut self, key: &str, value: impl Serialize) -> Self {
        if let Ok(v) = serde_json::to_value(value) {
            self.details.insert(key.to_string(), v);
        }
        self
    }

    /// Set source IP
    pub fn with_source_ip(mut self, ip: &str) -> Self {
        self.source_ip = Some(ip.to_string());
        self
    }

    /// Set request ID
    pub fn with_request_id(mut self, id: &str) -> Self {
        self.request_id = Some(id.to_string());
        self
    }

    /// Set session ID
    pub fn with_session_id(mut self, id: &str) -> Self {
        self.session_id = Some(id.to_string());
        self
    }
}

/// Audit log query filter
#[derive(Debug, Clone, Default)]
pub struct AuditLogQuery {
    /// Start time
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    /// End time
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    /// Event types to include
    pub event_types: Option<Vec<AuditEventType>>,
    /// Actor filter
    pub actor: Option<String>,
    /// Resource filter
    pub resource: Option<String>,
    /// Rule ID filter
    pub rule_id: Option<String>,
    /// Category filter
    pub category: Option<RuleCategory>,
    /// Severity filter
    pub severity: Option<RuleSeverity>,
    /// Limit results
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
}

impl AuditLogQuery {
    /// Create new query
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by time range
    pub fn time_range(mut self, start: chrono::DateTime<chrono::Utc>, end: chrono::DateTime<chrono::Utc>) -> Self {
        self.start_time = Some(start);
        self.end_time = Some(end);
        self
    }

    /// Filter by event type
    pub fn event_type(mut self, event_type: AuditEventType) -> Self {
        self.event_types = Some(vec![event_type]);
        self
    }

    /// Filter by actor
    pub fn actor(mut self, actor: &str) -> Self {
        self.actor = Some(actor.to_string());
        self
    }

    /// Filter by resource
    pub fn resource(mut self, resource: &str) -> Self {
        self.resource = Some(resource.to_string());
        self
    }

    /// Limit results
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set offset
    pub fn offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }
}

/// Audit log backend trait
#[async_trait::async_trait]
pub trait AuditLogBackend: Send + Sync {
    /// Write an entry
    async fn write(&self, entry: &ComplianceAuditEntry) -> Result<(), String>;

    /// Query entries
    async fn query(&self, query: &AuditLogQuery) -> Result<Vec<ComplianceAuditEntry>, String>;

    /// Get entry by ID
    async fn get(&self, id: &str) -> Result<Option<ComplianceAuditEntry>, String>;
}

/// In-memory audit log backend
pub struct InMemoryAuditBackend {
    entries: RwLock<Vec<ComplianceAuditEntry>>,
    max_entries: usize,
}

impl InMemoryAuditBackend {
    /// Create new in-memory backend
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
            max_entries,
        }
    }
}

#[async_trait::async_trait]
impl AuditLogBackend for InMemoryAuditBackend {
    async fn write(&self, entry: &ComplianceAuditEntry) -> Result<(), String> {
        let mut entries = self.entries.write().await;

        // Evict old entries if needed
        while entries.len() >= self.max_entries {
            entries.remove(0);
        }

        entries.push(entry.clone());
        Ok(())
    }

    async fn query(&self, query: &AuditLogQuery) -> Result<Vec<ComplianceAuditEntry>, String> {
        let entries = self.entries.read().await;

        let mut results: Vec<_> = entries
            .iter()
            .filter(|e| {
                // Time range filter
                if let Some(start) = query.start_time {
                    if e.timestamp < start {
                        return false;
                    }
                }
                if let Some(end) = query.end_time {
                    if e.timestamp > end {
                        return false;
                    }
                }

                // Event type filter
                if let Some(ref types) = query.event_types {
                    if !types.contains(&e.event_type) {
                        return false;
                    }
                }

                // Actor filter
                if let Some(ref actor) = query.actor {
                    if &e.actor != actor {
                        return false;
                    }
                }

                // Resource filter
                if let Some(ref resource) = query.resource {
                    if e.resource.as_ref() != Some(resource) {
                        return false;
                    }
                }

                // Rule ID filter
                if let Some(ref rule_id) = query.rule_id {
                    if e.rule_id.as_ref() != Some(rule_id) {
                        return false;
                    }
                }

                // Category filter
                if let Some(category) = query.category {
                    if e.category != Some(category) {
                        return false;
                    }
                }

                // Severity filter
                if let Some(severity) = query.severity {
                    if e.severity != Some(severity) {
                        return false;
                    }
                }

                true
            })
            .cloned()
            .collect();

        // Sort by timestamp descending
        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // Apply offset and limit
        let offset = query.offset.unwrap_or(0);
        let limit = query.limit.unwrap_or(usize::MAX);

        Ok(results.into_iter().skip(offset).take(limit).collect())
    }

    async fn get(&self, id: &str) -> Result<Option<ComplianceAuditEntry>, String> {
        let entries = self.entries.read().await;
        Ok(entries.iter().find(|e| e.id == id).cloned())
    }
}

/// Main compliance audit log
pub struct ComplianceAuditLog {
    /// Backend
    backend: Arc<dyn AuditLogBackend>,
    /// Node ID
    node_id: String,
}

impl ComplianceAuditLog {
    /// Create new audit log
    pub fn new(backend: Arc<dyn AuditLogBackend>, node_id: &str) -> Self {
        Self {
            backend,
            node_id: node_id.to_string(),
        }
    }

    /// Create with in-memory backend
    pub fn in_memory(max_entries: usize, node_id: &str) -> Self {
        Self::new(
            Arc::new(InMemoryAuditBackend::new(max_entries)),
            node_id,
        )
    }

    /// Log a compliance check
    pub async fn log_check(
        &self,
        actor: &str,
        resource: Option<&str>,
        passed: bool,
        violations: usize,
    ) -> Result<(), String> {
        let message = if passed {
            "Compliance check passed".to_string()
        } else {
            format!("Compliance check failed with {} violations", violations)
        };

        let mut entry = ComplianceAuditEntry::new(AuditEventType::ComplianceCheck, actor, &message)
            .with_detail("passed", passed)
            .with_detail("violations", violations)
            .with_detail("node_id", &self.node_id);

        if let Some(r) = resource {
            entry = entry.with_resource(r);
        }

        info!(
            actor = actor,
            resource = ?resource,
            passed = passed,
            violations = violations,
            "Compliance check recorded"
        );

        self.backend.write(&entry).await
    }

    /// Log a violation
    pub async fn log_violation(
        &self,
        actor: &str,
        resource: &str,
        rule_id: &str,
        category: RuleCategory,
        severity: RuleSeverity,
        message: &str,
    ) -> Result<(), String> {
        let entry = ComplianceAuditEntry::new(AuditEventType::ViolationDetected, actor, message)
            .with_resource(resource)
            .with_rule(rule_id, category, severity)
            .with_detail("node_id", &self.node_id);

        info!(
            actor = actor,
            resource = resource,
            rule_id = rule_id,
            category = ?category,
            severity = ?severity,
            "Compliance violation recorded"
        );

        self.backend.write(&entry).await
    }

    /// Log data access
    pub async fn log_access(
        &self,
        actor: &str,
        resource: &str,
        operation: &str,
        granted: bool,
    ) -> Result<(), String> {
        let event_type = if granted {
            AuditEventType::AccessGranted
        } else {
            AuditEventType::AccessDenied
        };

        let message = format!("{} access {} for {}", operation, if granted { "granted" } else { "denied" }, resource);

        let entry = ComplianceAuditEntry::new(event_type, actor, &message)
            .with_resource(resource)
            .with_detail("operation", operation)
            .with_detail("granted", granted)
            .with_detail("node_id", &self.node_id);

        self.backend.write(&entry).await
    }

    /// Log data modification
    pub async fn log_modification(
        &self,
        actor: &str,
        resource: &str,
        operation: &str,
        details: HashMap<String, String>,
    ) -> Result<(), String> {
        let message = format!("{} performed {} on {}", actor, operation, resource);

        let mut entry = ComplianceAuditEntry::new(AuditEventType::DataModification, actor, &message)
            .with_resource(resource)
            .with_detail("operation", operation)
            .with_detail("node_id", &self.node_id);

        for (k, v) in details {
            entry = entry.with_detail(&k, v);
        }

        self.backend.write(&entry).await
    }

    /// Log configuration change
    pub async fn log_config_change(
        &self,
        actor: &str,
        config_key: &str,
        old_value: Option<&str>,
        new_value: &str,
    ) -> Result<(), String> {
        let message = format!("Configuration {} changed", config_key);

        let mut entry = ComplianceAuditEntry::new(AuditEventType::ConfigurationChange, actor, &message)
            .with_detail("config_key", config_key)
            .with_detail("new_value", new_value)
            .with_detail("node_id", &self.node_id);

        if let Some(old) = old_value {
            entry = entry.with_detail("old_value", old);
        }

        self.backend.write(&entry).await
    }

    /// Query audit log
    pub async fn query(&self, query: &AuditLogQuery) -> Result<Vec<ComplianceAuditEntry>, String> {
        self.backend.query(query).await
    }

    /// Get entry by ID
    pub async fn get(&self, id: &str) -> Result<Option<ComplianceAuditEntry>, String> {
        self.backend.get(id).await
    }

    /// Get recent entries
    pub async fn recent(&self, limit: usize) -> Result<Vec<ComplianceAuditEntry>, String> {
        self.query(&AuditLogQuery::new().limit(limit)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_audit_log() {
        let log = ComplianceAuditLog::in_memory(100, "test-node");

        log.log_check("user-1", Some("resource-1"), true, 0)
            .await
            .unwrap();

        let entries = log.recent(10).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event_type, AuditEventType::ComplianceCheck);
    }

    #[tokio::test]
    async fn test_audit_query() {
        let log = ComplianceAuditLog::in_memory(100, "test-node");

        log.log_access("user-1", "res-1", "read", true)
            .await
            .unwrap();
        log.log_access("user-2", "res-2", "write", false)
            .await
            .unwrap();

        let query = AuditLogQuery::new()
            .event_type(AuditEventType::AccessDenied);

        let entries = log.query(&query).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].actor, "user-2");
    }

    #[tokio::test]
    async fn test_violation_logging() {
        let log = ComplianceAuditLog::in_memory(100, "test-node");

        log.log_violation(
            "system",
            "resource-123",
            "ENC-001",
            RuleCategory::Encryption,
            RuleSeverity::Critical,
            "Data is not encrypted",
        )
        .await
        .unwrap();

        let query = AuditLogQuery::new().resource("resource-123");
        let entries = log.query(&query).await.unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].rule_id, Some("ENC-001".to_string()));
    }
}
