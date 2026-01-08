//! Invariant Audit Logger
//!
//! Logs all invariant-related operations for accountability and forensics.
//! This is a critical component for non-platform verification - all invariant
//! checks and violations must be logged for third-party auditing.

use chrono::{DateTime, Utc};
use l0_core::types::Digest;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

/// Audit logger errors
#[derive(Debug, Error)]
pub enum AuditLogError {
    /// Failed to write audit entry
    #[error("Failed to write audit entry: {0}")]
    WriteFailed(String),

    /// Log is full
    #[error("Audit log is full (max entries: {0})")]
    LogFull(usize),

    /// Invalid entry
    #[error("Invalid audit entry: {0}")]
    InvalidEntry(String),
}

/// Result type for audit operations
pub type AuditLogResult<T> = Result<T, AuditLogError>;

/// Invariant violation types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantViolationType {
    /// Attempted to overwrite existing data
    OverwriteAttempt,
    /// Plaintext data detected
    PlaintextDetected,
    /// Direct deletion attempted
    DirectDeletionAttempt,
    /// Hash collision (should never happen)
    HashCollision,
    /// Unauthorized access attempt
    UnauthorizedAccess,
    /// Integrity check failed
    IntegrityCheckFailed,
    /// Non-platform verification failed
    NonPlatformVerificationFailed,
    /// Other violation
    Other,
}

impl InvariantViolationType {
    /// Get severity level
    pub fn severity(&self) -> AuditSeverity {
        match self {
            Self::HashCollision => AuditSeverity::Critical,
            Self::PlaintextDetected => AuditSeverity::Critical,
            Self::OverwriteAttempt => AuditSeverity::High,
            Self::DirectDeletionAttempt => AuditSeverity::High,
            Self::UnauthorizedAccess => AuditSeverity::High,
            Self::IntegrityCheckFailed => AuditSeverity::High,
            Self::NonPlatformVerificationFailed => AuditSeverity::Medium,
            Self::Other => AuditSeverity::Low,
        }
    }

    /// Get description
    pub fn description(&self) -> &'static str {
        match self {
            Self::OverwriteAttempt => "Attempted to overwrite existing data (Append-Only violation)",
            Self::PlaintextDetected => "Plaintext data detected (Zero-Plaintext violation)",
            Self::DirectDeletionAttempt => "Direct deletion attempted (Tombstone-Only violation)",
            Self::HashCollision => "CRITICAL: Hash collision detected",
            Self::UnauthorizedAccess => "Unauthorized access attempt",
            Self::IntegrityCheckFailed => "Data integrity check failed",
            Self::NonPlatformVerificationFailed => "Non-platform verification failed",
            Self::Other => "Other invariant violation",
        }
    }
}

/// Audit entry severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSeverity {
    /// Low severity (informational)
    Low,
    /// Medium severity (warning)
    Medium,
    /// High severity (error)
    High,
    /// Critical severity (requires immediate action)
    Critical,
}

/// Invariant audit entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantAuditEntry {
    /// Entry ID
    pub entry_id: String,
    /// Entry type
    pub entry_type: InvariantAuditEntryType,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Severity
    pub severity: AuditSeverity,
    /// Related ref_id (if applicable)
    pub ref_id: Option<String>,
    /// Details
    pub details: String,
    /// Actor (if known)
    pub actor: Option<String>,
    /// Request context
    pub context: Option<String>,
    /// Entry digest (for chain verification)
    pub entry_digest: Digest,
    /// Previous entry digest (for chain)
    pub previous_digest: Option<Digest>,
}

/// Audit entry type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantAuditEntryType {
    /// Invariant violation
    Violation(InvariantViolationType),
    /// Successful operation
    Operation(String),
    /// Invariant check passed
    CheckPassed(String),
    /// System event
    SystemEvent(String),
}

impl InvariantAuditEntry {
    /// Create a violation entry
    pub fn violation(violation_type: InvariantViolationType, details: &str) -> Self {
        let timestamp = Utc::now();
        let entry_id = format!("audit:violation:{}:{}",
            violation_type.description().replace(' ', "_"),
            timestamp.timestamp_millis()
        );

        let entry_data = format!("{}:{}:{}",
            entry_id,
            timestamp.to_rfc3339(),
            details
        );

        Self {
            entry_id,
            entry_type: InvariantAuditEntryType::Violation(violation_type),
            timestamp,
            severity: violation_type.severity(),
            ref_id: None,
            details: details.to_string(),
            actor: None,
            context: None,
            entry_digest: Digest::blake3(entry_data.as_bytes()),
            previous_digest: None,
        }
    }

    /// Create an operation entry
    pub fn operation(operation: &str, ref_id: &str) -> Self {
        let timestamp = Utc::now();
        let entry_id = format!("audit:op:{}:{}", operation, timestamp.timestamp_millis());

        let entry_data = format!("{}:{}:{}:{}", entry_id, timestamp.to_rfc3339(), operation, ref_id);

        Self {
            entry_id,
            entry_type: InvariantAuditEntryType::Operation(operation.to_string()),
            timestamp,
            severity: AuditSeverity::Low,
            ref_id: Some(ref_id.to_string()),
            details: format!("Operation '{}' on {}", operation, ref_id),
            actor: None,
            context: None,
            entry_digest: Digest::blake3(entry_data.as_bytes()),
            previous_digest: None,
        }
    }

    /// Create a check passed entry
    pub fn check_passed(check_name: &str, details: &str) -> Self {
        let timestamp = Utc::now();
        let entry_id = format!("audit:check:{}:{}", check_name, timestamp.timestamp_millis());

        let entry_data = format!("{}:{}:{}", entry_id, timestamp.to_rfc3339(), details);

        Self {
            entry_id,
            entry_type: InvariantAuditEntryType::CheckPassed(check_name.to_string()),
            timestamp,
            severity: AuditSeverity::Low,
            ref_id: None,
            details: details.to_string(),
            actor: None,
            context: None,
            entry_digest: Digest::blake3(entry_data.as_bytes()),
            previous_digest: None,
        }
    }

    /// Create a system event entry
    pub fn system_event(event: &str, details: &str) -> Self {
        let timestamp = Utc::now();
        let entry_id = format!("audit:sys:{}:{}", event, timestamp.timestamp_millis());

        let entry_data = format!("{}:{}:{}", entry_id, timestamp.to_rfc3339(), details);

        Self {
            entry_id,
            entry_type: InvariantAuditEntryType::SystemEvent(event.to_string()),
            timestamp,
            severity: AuditSeverity::Low,
            ref_id: None,
            details: details.to_string(),
            actor: None,
            context: None,
            entry_digest: Digest::blake3(entry_data.as_bytes()),
            previous_digest: None,
        }
    }

    /// Set actor
    pub fn with_actor(mut self, actor: &str) -> Self {
        self.actor = Some(actor.to_string());
        self
    }

    /// Set ref_id
    pub fn with_ref_id(mut self, ref_id: &str) -> Self {
        self.ref_id = Some(ref_id.to_string());
        self
    }

    /// Set context
    pub fn with_context(mut self, context: &str) -> Self {
        self.context = Some(context.to_string());
        self
    }

    /// Is this a violation?
    pub fn is_violation(&self) -> bool {
        matches!(self.entry_type, InvariantAuditEntryType::Violation(_))
    }

    /// Is this critical?
    pub fn is_critical(&self) -> bool {
        self.severity == AuditSeverity::Critical
    }
}

/// Invariant audit logger
pub struct InvariantAuditLogger {
    /// Audit entries (in-memory, limited size)
    entries: Arc<RwLock<VecDeque<InvariantAuditEntry>>>,
    /// Maximum entries to keep in memory
    max_entries: usize,
    /// Last entry digest (for chain)
    last_digest: Arc<RwLock<Option<Digest>>>,
    /// Statistics
    stats: Arc<RwLock<AuditLogStats>>,
}

/// Audit log statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditLogStats {
    /// Total entries logged
    pub total_entries: u64,
    /// Violation entries
    pub violations: u64,
    /// Critical violations
    pub critical_violations: u64,
    /// Operations logged
    pub operations: u64,
}

impl InvariantAuditLogger {
    /// Default maximum entries
    const DEFAULT_MAX_ENTRIES: usize = 10000;

    /// Create a new audit logger
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(VecDeque::new())),
            max_entries: Self::DEFAULT_MAX_ENTRIES,
            last_digest: Arc::new(RwLock::new(None)),
            stats: Arc::new(RwLock::new(AuditLogStats::default())),
        }
    }

    /// Create with custom max entries
    pub fn with_max_entries(max_entries: usize) -> Self {
        Self {
            entries: Arc::new(RwLock::new(VecDeque::new())),
            max_entries,
            last_digest: Arc::new(RwLock::new(None)),
            stats: Arc::new(RwLock::new(AuditLogStats::default())),
        }
    }

    /// Log an audit entry
    pub async fn log(&self, mut entry: InvariantAuditEntry) -> AuditLogResult<()> {
        let mut entries = self.entries.write().await;
        let mut last_digest = self.last_digest.write().await;
        let mut stats = self.stats.write().await;

        // Set previous digest for chain
        entry.previous_digest = last_digest.clone();

        // Update last digest
        *last_digest = Some(entry.entry_digest.clone());

        // Update statistics
        stats.total_entries += 1;
        match &entry.entry_type {
            InvariantAuditEntryType::Violation(v) => {
                stats.violations += 1;
                if v.severity() == AuditSeverity::Critical {
                    stats.critical_violations += 1;
                    // Log critical violations to tracing
                    tracing::error!(
                        "CRITICAL INVARIANT VIOLATION: {:?} - {}",
                        v,
                        entry.details
                    );
                } else {
                    tracing::warn!("Invariant violation: {:?} - {}", v, entry.details);
                }
            }
            InvariantAuditEntryType::Operation(_) => {
                stats.operations += 1;
            }
            _ => {}
        }

        // Remove oldest entry if at capacity
        if entries.len() >= self.max_entries {
            entries.pop_front();
        }

        entries.push_back(entry);
        Ok(())
    }

    /// Get recent entries
    pub async fn get_recent(&self, count: usize) -> Vec<InvariantAuditEntry> {
        let entries = self.entries.read().await;
        entries.iter().rev().take(count).cloned().collect()
    }

    /// Get all violations
    pub async fn get_violations(&self) -> Vec<InvariantAuditEntry> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .filter(|e| e.is_violation())
            .cloned()
            .collect()
    }

    /// Get critical violations
    pub async fn get_critical_violations(&self) -> Vec<InvariantAuditEntry> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .filter(|e| e.is_critical())
            .cloned()
            .collect()
    }

    /// Get entries by ref_id
    pub async fn get_by_ref_id(&self, ref_id: &str) -> Vec<InvariantAuditEntry> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .filter(|e| e.ref_id.as_ref().map(|r| r == ref_id).unwrap_or(false))
            .cloned()
            .collect()
    }

    /// Get statistics
    pub async fn get_stats(&self) -> AuditLogStats {
        self.stats.read().await.clone()
    }

    /// Verify chain integrity
    pub async fn verify_chain(&self) -> bool {
        let entries = self.entries.read().await;

        let mut expected_previous: Option<Digest> = None;

        for entry in entries.iter() {
            if entry.previous_digest != expected_previous {
                return false;
            }
            expected_previous = Some(entry.entry_digest.clone());
        }

        true
    }

    /// Get entry count
    pub async fn entry_count(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Clear all entries (for testing)
    pub async fn clear(&self) {
        let mut entries = self.entries.write().await;
        entries.clear();
        *self.last_digest.write().await = None;
    }

    /// Export entries for external auditing
    pub async fn export(&self) -> Vec<InvariantAuditEntry> {
        self.entries.read().await.iter().cloned().collect()
    }
}

impl Default for InvariantAuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_violation_severity() {
        assert_eq!(InvariantViolationType::HashCollision.severity(), AuditSeverity::Critical);
        assert_eq!(InvariantViolationType::PlaintextDetected.severity(), AuditSeverity::Critical);
        assert_eq!(InvariantViolationType::OverwriteAttempt.severity(), AuditSeverity::High);
    }

    #[test]
    fn test_audit_entry_creation() {
        let entry = InvariantAuditEntry::violation(
            InvariantViolationType::OverwriteAttempt,
            "Attempted to overwrite ref:001"
        );

        assert!(entry.is_violation());
        assert!(!entry.is_critical());
        assert!(entry.entry_id.contains("violation"));
    }

    #[test]
    fn test_critical_entry() {
        let entry = InvariantAuditEntry::violation(
            InvariantViolationType::HashCollision,
            "Critical error"
        );

        assert!(entry.is_violation());
        assert!(entry.is_critical());
    }

    #[tokio::test]
    async fn test_audit_logger() {
        let logger = InvariantAuditLogger::new();

        // Log some entries
        logger.log(InvariantAuditEntry::operation("write", "ref:001")).await.unwrap();
        logger.log(InvariantAuditEntry::violation(
            InvariantViolationType::OverwriteAttempt,
            "Test violation"
        )).await.unwrap();

        let stats = logger.get_stats().await;
        assert_eq!(stats.total_entries, 2);
        assert_eq!(stats.violations, 1);
        assert_eq!(stats.operations, 1);

        // Verify chain
        assert!(logger.verify_chain().await);
    }

    #[tokio::test]
    async fn test_get_violations() {
        let logger = InvariantAuditLogger::new();

        logger.log(InvariantAuditEntry::operation("write", "ref:001")).await.unwrap();
        logger.log(InvariantAuditEntry::violation(
            InvariantViolationType::PlaintextDetected,
            "Plaintext found"
        )).await.unwrap();
        logger.log(InvariantAuditEntry::operation("read", "ref:002")).await.unwrap();

        let violations = logger.get_violations().await;
        assert_eq!(violations.len(), 1);

        let critical = logger.get_critical_violations().await;
        assert_eq!(critical.len(), 1); // PlaintextDetected is critical
    }
}
