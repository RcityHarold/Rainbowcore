//! Pending Resolver
//!
//! Handles resolution of pending items in proper order.

use super::*;
use crate::error::{P3Error, P3Result};
use crate::types::*;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Pending resolver
pub struct PendingResolver {
    /// Active recovery sequences
    sequences: HashMap<String, RecoverySequence>,
    /// Resolution handlers by category
    handlers: HashMap<PendingCategory, ResolutionStrategy>,
}

impl PendingResolver {
    /// Create new resolver
    pub fn new() -> Self {
        let mut handlers = HashMap::new();

        // Default handlers
        handlers.insert(PendingCategory::Evidence, ResolutionStrategy::Automatic);
        handlers.insert(PendingCategory::Execution, ResolutionStrategy::Automatic);
        handlers.insert(PendingCategory::Budget, ResolutionStrategy::Manual);
        handlers.insert(PendingCategory::Appeal, ResolutionStrategy::Manual);
        handlers.insert(PendingCategory::Version, ResolutionStrategy::Automatic);
        handlers.insert(PendingCategory::Manual, ResolutionStrategy::Manual);

        Self {
            sequences: HashMap::new(),
            handlers,
        }
    }

    /// Set resolution strategy for category
    pub fn with_strategy(mut self, category: PendingCategory, strategy: ResolutionStrategy) -> Self {
        self.handlers.insert(category, strategy);
        self
    }

    /// Create recovery sequence
    pub fn create_sequence(
        &mut self,
        manager: &PendingManager,
        order: RecoveryOrder,
    ) -> P3Result<RecoverySequence> {
        let entries = self.get_ordered_entries(manager, &order);

        if entries.is_empty() {
            return Err(P3Error::InvalidState {
                reason: "No pending entries to recover".to_string(),
            });
        }

        let sequence_id = format!("seq:{}", Utc::now().timestamp_millis());
        let sequence = RecoverySequence::new(sequence_id.clone(), entries, order);

        self.sequences.insert(sequence_id.clone(), sequence.clone());

        Ok(sequence)
    }

    /// Start recovery sequence
    pub fn start_sequence(&mut self, sequence_id: &str) -> P3Result<()> {
        let sequence = self.sequences.get_mut(sequence_id).ok_or_else(|| {
            P3Error::NotFound {
                entity: "RecoverySequence".to_string(),
                id: sequence_id.to_string(),
            }
        })?;

        if sequence.status != RecoveryStatus::Pending {
            return Err(P3Error::InvalidState {
                reason: format!("Sequence is in {:?} status", sequence.status),
            });
        }

        sequence.status = RecoveryStatus::InProgress;
        Ok(())
    }

    /// Process next entry in sequence
    pub fn process_next(
        &mut self,
        sequence_id: &str,
        manager: &mut PendingManager,
        resolution_type: ResolutionType,
        resolver_ref: impl Into<String>,
    ) -> P3Result<Option<PendingId>> {
        let sequence = self.sequences.get_mut(sequence_id).ok_or_else(|| {
            P3Error::NotFound {
                entity: "RecoverySequence".to_string(),
                id: sequence_id.to_string(),
            }
        })?;

        if sequence.status != RecoveryStatus::InProgress {
            return Err(P3Error::InvalidState {
                reason: format!("Sequence is in {:?} status", sequence.status),
            });
        }

        if sequence.entries.is_empty() {
            sequence.status = RecoveryStatus::Completed;
            return Ok(None);
        }

        let pending_id = sequence.entries.remove(0);

        // Resolve the entry
        let request = PendingResolutionRequest::new(
            pending_id.clone(),
            resolution_type,
            resolver_ref,
        );

        manager.resolve(request)?;

        // Check if sequence is complete
        if sequence.entries.is_empty() {
            sequence.status = RecoveryStatus::Completed;
        }

        Ok(Some(pending_id))
    }

    /// Pause sequence
    pub fn pause_sequence(&mut self, sequence_id: &str) -> P3Result<()> {
        let sequence = self.sequences.get_mut(sequence_id).ok_or_else(|| {
            P3Error::NotFound {
                entity: "RecoverySequence".to_string(),
                id: sequence_id.to_string(),
            }
        })?;

        if sequence.status != RecoveryStatus::InProgress {
            return Err(P3Error::InvalidState {
                reason: "Can only pause in-progress sequence".to_string(),
            });
        }

        sequence.status = RecoveryStatus::Paused;
        Ok(())
    }

    /// Resume sequence
    pub fn resume_sequence(&mut self, sequence_id: &str) -> P3Result<()> {
        let sequence = self.sequences.get_mut(sequence_id).ok_or_else(|| {
            P3Error::NotFound {
                entity: "RecoverySequence".to_string(),
                id: sequence_id.to_string(),
            }
        })?;

        if sequence.status != RecoveryStatus::Paused {
            return Err(P3Error::InvalidState {
                reason: "Can only resume paused sequence".to_string(),
            });
        }

        sequence.status = RecoveryStatus::InProgress;
        Ok(())
    }

    /// Get sequence
    pub fn get_sequence(&self, sequence_id: &str) -> Option<&RecoverySequence> {
        self.sequences.get(sequence_id)
    }

    /// Get resolution strategy for category
    pub fn get_strategy(&self, category: &PendingCategory) -> ResolutionStrategy {
        self.handlers.get(category).cloned().unwrap_or(ResolutionStrategy::Manual)
    }

    /// Check if entry can be auto-resolved
    pub fn can_auto_resolve(&self, entry: &EnhancedPendingEntry) -> bool {
        matches!(
            self.get_strategy(&entry.category),
            ResolutionStrategy::Automatic
        )
    }

    /// Get ordered entries based on order type
    fn get_ordered_entries(
        &self,
        manager: &PendingManager,
        order: &RecoveryOrder,
    ) -> Vec<PendingId> {
        let mut entries: Vec<_> = manager
            .entries
            .values()
            .filter(|e| !e.is_resolved())
            .collect();

        match order {
            RecoveryOrder::Fifo => {
                entries.sort_by_key(|e| e.entry.created_at);
            }
            RecoveryOrder::Priority => {
                entries.sort_by(|a, b| b.priority.cmp(&a.priority));
            }
            RecoveryOrder::Category => {
                entries.sort_by_key(|e| category_order(&e.category));
            }
            RecoveryOrder::Custom => {
                // Keep original order
            }
        }

        entries.into_iter().map(|e| e.entry.pending_id.clone()).collect()
    }

    /// Bulk resolve by category
    pub fn bulk_resolve_category(
        &self,
        manager: &mut PendingManager,
        category: &PendingCategory,
        resolution_type: ResolutionType,
        resolver_ref: impl Into<String>,
    ) -> P3Result<usize> {
        let resolver = resolver_ref.into();
        let entries = manager.get_by_category(category);
        let pending_ids: Vec<_> = entries.iter().map(|e| e.entry.pending_id.clone()).collect();

        let mut count = 0;
        for pending_id in pending_ids {
            let request = PendingResolutionRequest::new(
                pending_id,
                resolution_type.clone(),
                resolver.clone(),
            );
            if manager.resolve(request).is_ok() {
                count += 1;
            }
        }

        Ok(count)
    }
}

impl Default for PendingResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolution strategy
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolutionStrategy {
    /// Automatic resolution
    Automatic,
    /// Manual resolution required
    Manual,
    /// Escalate to governance
    Escalate,
    /// Wait for external event
    WaitForEvent,
}

/// Get category order for sorting
fn category_order(category: &PendingCategory) -> u32 {
    match category {
        PendingCategory::Evidence => 1,
        PendingCategory::Execution => 2,
        PendingCategory::Version => 3,
        PendingCategory::Budget => 4,
        PendingCategory::Appeal => 5,
        PendingCategory::Manual => 6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_manager() -> PendingManager {
        let mut manager = PendingManager::new();

        manager
            .create(
                PendingKind::Evidence,
                EpochId::new("epoch:1"),
                "target:1",
                P3Digest::zero(),
            )
            .unwrap();

        manager
            .create(
                PendingKind::Execution,
                EpochId::new("epoch:1"),
                "target:2",
                P3Digest::zero(),
            )
            .unwrap();

        manager
    }

    #[test]
    fn test_resolver_creation() {
        let resolver = PendingResolver::new();
        assert_eq!(
            resolver.get_strategy(&PendingCategory::Evidence),
            ResolutionStrategy::Automatic
        );
    }

    #[test]
    fn test_create_sequence() {
        let mut resolver = PendingResolver::new();
        let manager = create_test_manager();

        let sequence = resolver.create_sequence(&manager, RecoveryOrder::Fifo).unwrap();

        assert_eq!(sequence.entries.len(), 2);
        assert_eq!(sequence.status, RecoveryStatus::Pending);
    }

    #[test]
    fn test_start_and_process_sequence() {
        let mut resolver = PendingResolver::new();
        let mut manager = create_test_manager();

        let sequence = resolver.create_sequence(&manager, RecoveryOrder::Fifo).unwrap();
        let sequence_id = sequence.sequence_id.clone();

        resolver.start_sequence(&sequence_id).unwrap();

        let result = resolver
            .process_next(&sequence_id, &mut manager, ResolutionType::Resolved, "resolver:1")
            .unwrap();

        assert!(result.is_some());
        assert_eq!(manager.count_unresolved(), 1);
    }

    #[test]
    fn test_pause_and_resume() {
        let mut resolver = PendingResolver::new();
        let manager = create_test_manager();

        let sequence = resolver.create_sequence(&manager, RecoveryOrder::Fifo).unwrap();
        let sequence_id = sequence.sequence_id.clone();

        resolver.start_sequence(&sequence_id).unwrap();
        resolver.pause_sequence(&sequence_id).unwrap();

        let seq = resolver.get_sequence(&sequence_id).unwrap();
        assert_eq!(seq.status, RecoveryStatus::Paused);

        resolver.resume_sequence(&sequence_id).unwrap();

        let seq = resolver.get_sequence(&sequence_id).unwrap();
        assert_eq!(seq.status, RecoveryStatus::InProgress);
    }

    #[test]
    fn test_bulk_resolve() {
        let resolver = PendingResolver::new();
        let mut manager = PendingManager::new();

        // Create multiple evidence entries
        for i in 0..3 {
            manager
                .create(
                    PendingKind::Evidence,
                    EpochId::new("epoch:1"),
                    format!("target:{}", i),
                    P3Digest::zero(),
                )
                .unwrap();
        }

        let count = resolver
            .bulk_resolve_category(
                &mut manager,
                &PendingCategory::Evidence,
                ResolutionType::Resolved,
                "resolver:bulk",
            )
            .unwrap();

        assert_eq!(count, 3);
        assert_eq!(manager.count_unresolved(), 0);
    }

    #[test]
    fn test_can_auto_resolve() {
        let resolver = PendingResolver::new();

        let evidence_entry = EnhancedPendingEntry::from_entry(PendingEntry {
            pending_id: PendingId::new("p1"),
            pending_kind: PendingKind::Evidence,
            bound_epoch_id: EpochId::new("epoch:1"),
            target_ref: "target".to_string(),
            reason_digest: P3Digest::zero(),
            created_at: Utc::now(),
            deadline: None,
            attempt_chain_id: None,
            resolution: None,
            supersedes_ref: None,
        });

        let budget_entry = EnhancedPendingEntry::from_entry(PendingEntry {
            pending_id: PendingId::new("p2"),
            pending_kind: PendingKind::Budget,
            bound_epoch_id: EpochId::new("epoch:1"),
            target_ref: "target".to_string(),
            reason_digest: P3Digest::zero(),
            created_at: Utc::now(),
            deadline: None,
            attempt_chain_id: None,
            resolution: None,
            supersedes_ref: None,
        });

        assert!(resolver.can_auto_resolve(&evidence_entry));
        assert!(!resolver.can_auto_resolve(&budget_entry));
    }
}
