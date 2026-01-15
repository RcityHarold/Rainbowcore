//! Pending System Module
//!
//! Chapter 9: Pending System
//!
//! Manages pending items that require resolution:
//! - pending_evidence: Evidence verification pending
//! - pending_execution: Execution pending
//! - pending_budget: Budget approval pending
//! - pending_appeal: Appeal resolution pending
//! - pending_version: Version update pending

mod manager;
mod resolver;

pub use manager::*;
pub use resolver::*;

use crate::error::{P3Error, P3Result};
use crate::types::*;
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use std::collections::HashMap;

/// Pending category
///
/// This extends PendingKind with additional management-specific categories.
///
/// Relationship with PendingKind:
/// - Evidence, Execution, Budget, Appeal, Version: Direct mapping from PendingKind
/// - Manual: Extended category for human intervention (not in core PendingKind)
///
/// Use PendingKind for core type identification, PendingCategory for management operations.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PendingCategory {
    /// Evidence verification pending (maps to PendingKind::Evidence)
    Evidence,
    /// Execution pending (maps to PendingKind::Execution)
    Execution,
    /// Budget approval pending (maps to PendingKind::Budget)
    Budget,
    /// Appeal resolution pending (maps to PendingKind::Appeal)
    Appeal,
    /// Version update pending (maps to PendingKind::Version)
    Version,
    /// Manual intervention pending (management extension, no PendingKind equivalent)
    Manual,
}

impl PendingCategory {
    /// Get category name
    pub fn name(&self) -> &'static str {
        match self {
            PendingCategory::Evidence => "evidence",
            PendingCategory::Execution => "execution",
            PendingCategory::Budget => "budget",
            PendingCategory::Appeal => "appeal",
            PendingCategory::Version => "version",
            PendingCategory::Manual => "manual",
        }
    }

    /// Get default deadline duration
    pub fn default_deadline_hours(&self) -> i64 {
        match self {
            PendingCategory::Evidence => 24,
            PendingCategory::Execution => 1,
            PendingCategory::Budget => 72,
            PendingCategory::Appeal => 168, // 7 days
            PendingCategory::Version => 24,
            PendingCategory::Manual => 168,
        }
    }

    /// Check if auto-expire is enabled
    pub fn auto_expire(&self) -> bool {
        match self {
            PendingCategory::Evidence => true,
            PendingCategory::Execution => true,
            PendingCategory::Budget => false,
            PendingCategory::Appeal => false,
            PendingCategory::Version => true,
            PendingCategory::Manual => false,
        }
    }
}

impl From<PendingKind> for PendingCategory {
    fn from(kind: PendingKind) -> Self {
        match kind {
            PendingKind::Evidence => PendingCategory::Evidence,
            PendingKind::Execution => PendingCategory::Execution,
            PendingKind::Budget => PendingCategory::Budget,
            PendingKind::Appeal => PendingCategory::Appeal,
            PendingKind::Version => PendingCategory::Version,
        }
    }
}

impl PendingCategory {
    /// Try to convert to PendingKind
    ///
    /// Returns None for Manual category which has no PendingKind equivalent.
    pub fn to_pending_kind(&self) -> Option<PendingKind> {
        match self {
            PendingCategory::Evidence => Some(PendingKind::Evidence),
            PendingCategory::Execution => Some(PendingKind::Execution),
            PendingCategory::Budget => Some(PendingKind::Budget),
            PendingCategory::Appeal => Some(PendingKind::Appeal),
            PendingCategory::Version => Some(PendingKind::Version),
            PendingCategory::Manual => None, // No equivalent in PendingKind
        }
    }

    /// Check if this category has a PendingKind equivalent
    pub fn has_pending_kind_equivalent(&self) -> bool {
        !matches!(self, PendingCategory::Manual)
    }

    /// Get all categories that have PendingKind equivalents
    pub fn core_categories() -> Vec<PendingCategory> {
        vec![
            PendingCategory::Evidence,
            PendingCategory::Execution,
            PendingCategory::Budget,
            PendingCategory::Appeal,
            PendingCategory::Version,
        ]
    }

    /// Get all categories including management extensions
    pub fn all_categories() -> Vec<PendingCategory> {
        vec![
            PendingCategory::Evidence,
            PendingCategory::Execution,
            PendingCategory::Budget,
            PendingCategory::Appeal,
            PendingCategory::Version,
            PendingCategory::Manual,
        ]
    }
}

/// Enhanced pending entry with additional metadata
#[derive(Clone, Debug)]
pub struct EnhancedPendingEntry {
    /// Base pending entry
    pub entry: PendingEntry,
    /// Category
    pub category: PendingCategory,
    /// Priority
    pub priority: PendingPriority,
    /// Assignee (if any)
    pub assignee: Option<String>,
    /// Related entries
    pub related_entries: Vec<PendingId>,
    /// Tags
    pub tags: Vec<String>,
    /// Escalation level
    pub escalation_level: u32,
    /// Last updated
    pub last_updated: DateTime<Utc>,
}

impl EnhancedPendingEntry {
    /// Create from base entry
    pub fn from_entry(entry: PendingEntry) -> Self {
        let category = PendingCategory::from(entry.pending_kind.clone());
        Self {
            entry,
            category,
            priority: PendingPriority::Normal,
            assignee: None,
            related_entries: Vec::new(),
            tags: Vec::new(),
            escalation_level: 0,
            last_updated: Utc::now(),
        }
    }

    /// Set priority
    pub fn with_priority(mut self, priority: PendingPriority) -> Self {
        self.priority = priority;
        self
    }

    /// Set assignee
    pub fn with_assignee(mut self, assignee: impl Into<String>) -> Self {
        self.assignee = Some(assignee.into());
        self
    }

    /// Add related entry
    pub fn add_related(&mut self, pending_id: PendingId) {
        self.related_entries.push(pending_id);
    }

    /// Add tag
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        self.tags.push(tag.into());
    }

    /// Escalate
    pub fn escalate(&mut self) {
        self.escalation_level += 1;
        self.last_updated = Utc::now();
    }

    /// Check if expired
    pub fn is_expired(&self, now: &DateTime<Utc>) -> bool {
        self.entry.is_expired(now)
    }

    /// Check if resolved
    pub fn is_resolved(&self) -> bool {
        self.entry.is_resolved()
    }

    /// Get remaining time until deadline
    pub fn time_remaining(&self, now: &DateTime<Utc>) -> Option<chrono::Duration> {
        self.entry.deadline.map(|d| d - *now)
    }
}

/// Pending priority
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PendingPriority {
    /// Low priority
    Low,
    /// Normal priority
    Normal,
    /// High priority
    High,
    /// Critical priority
    Critical,
}

impl PendingPriority {
    /// Get priority weight for sorting
    pub fn weight(&self) -> u32 {
        match self {
            PendingPriority::Low => 1,
            PendingPriority::Normal => 2,
            PendingPriority::High => 3,
            PendingPriority::Critical => 4,
        }
    }
}

/// Pending resolution request
#[derive(Clone, Debug)]
pub struct PendingResolutionRequest {
    /// Pending ID
    pub pending_id: PendingId,
    /// Resolution type
    pub resolution_type: ResolutionType,
    /// Resolution proof
    pub resolution_proof_digest: Option<P3Digest>,
    /// Resolver reference
    pub resolver_ref: String,
    /// Notes
    pub notes: Option<String>,
}

impl PendingResolutionRequest {
    /// Create new request
    pub fn new(
        pending_id: PendingId,
        resolution_type: ResolutionType,
        resolver_ref: impl Into<String>,
    ) -> Self {
        Self {
            pending_id,
            resolution_type,
            resolution_proof_digest: None,
            resolver_ref: resolver_ref.into(),
            notes: None,
        }
    }

    /// Set proof
    pub fn with_proof(mut self, proof: P3Digest) -> Self {
        self.resolution_proof_digest = Some(proof);
        self
    }

    /// Set notes
    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = Some(notes.into());
        self
    }
}

/// Pending queue statistics
#[derive(Clone, Debug)]
pub struct PendingQueueStats {
    /// Total pending
    pub total: usize,
    /// By category
    pub by_category: HashMap<PendingCategory, usize>,
    /// By priority
    pub by_priority: HashMap<PendingPriority, usize>,
    /// Expired count
    pub expired: usize,
    /// Escalated count
    pub escalated: usize,
    /// Average age (seconds)
    pub average_age_secs: f64,
    /// Oldest entry age (seconds)
    pub oldest_age_secs: Option<f64>,
}

/// Recovery sequence for resolving pending items
#[derive(Clone, Debug)]
pub struct RecoverySequence {
    /// Sequence ID
    pub sequence_id: String,
    /// Pending entries to resolve
    pub entries: Vec<PendingId>,
    /// Resolution order
    pub order: RecoveryOrder,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Status
    pub status: RecoveryStatus,
}

impl RecoverySequence {
    /// Create new sequence
    pub fn new(sequence_id: impl Into<String>, entries: Vec<PendingId>, order: RecoveryOrder) -> Self {
        Self {
            sequence_id: sequence_id.into(),
            entries,
            order,
            created_at: Utc::now(),
            status: RecoveryStatus::Pending,
        }
    }

    /// Get next entry to resolve
    pub fn next_entry(&self) -> Option<&PendingId> {
        if self.status != RecoveryStatus::InProgress {
            return None;
        }
        self.entries.first()
    }
}

/// Recovery order
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryOrder {
    /// In order of creation
    Fifo,
    /// By priority
    Priority,
    /// By category (evidence first, then execution, etc.)
    Category,
    /// Custom order
    Custom,
}

/// Recovery status
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryStatus {
    /// Pending start
    Pending,
    /// In progress
    InProgress,
    /// Completed
    Completed,
    /// Paused
    Paused,
    /// Failed
    Failed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pending_category_name() {
        assert_eq!(PendingCategory::Evidence.name(), "evidence");
        assert_eq!(PendingCategory::Budget.name(), "budget");
    }

    #[test]
    fn test_pending_category_deadline() {
        assert_eq!(PendingCategory::Evidence.default_deadline_hours(), 24);
        assert_eq!(PendingCategory::Appeal.default_deadline_hours(), 168);
    }

    #[test]
    fn test_pending_priority_order() {
        assert!(PendingPriority::Critical > PendingPriority::High);
        assert!(PendingPriority::High > PendingPriority::Normal);
        assert!(PendingPriority::Normal > PendingPriority::Low);
    }

    #[test]
    fn test_enhanced_pending_entry() {
        let entry = PendingEntry {
            pending_id: PendingId::new("p1"),
            pending_kind: PendingKind::Evidence,
            bound_epoch_id: EpochId::new("epoch:1"),
            target_ref: "target".to_string(),
            reason_digest: P3Digest::zero(),
            created_at: Utc::now(),
            deadline: Some(Utc::now() + chrono::Duration::hours(24)),
            attempt_chain_id: None,
            resolution: None,
            supersedes_ref: None,
        };

        let enhanced = EnhancedPendingEntry::from_entry(entry)
            .with_priority(PendingPriority::High)
            .with_assignee("admin");

        assert_eq!(enhanced.priority, PendingPriority::High);
        assert_eq!(enhanced.assignee, Some("admin".to_string()));
    }

    #[test]
    fn test_recovery_sequence() {
        let entries = vec![PendingId::new("p1"), PendingId::new("p2")];
        let seq = RecoverySequence::new("seq:1", entries, RecoveryOrder::Fifo);

        assert_eq!(seq.status, RecoveryStatus::Pending);
        assert_eq!(seq.entries.len(), 2);
    }
}
