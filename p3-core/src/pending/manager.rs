//! Pending Manager
//!
//! Manages pending entries and their lifecycle.

use super::*;
use crate::error::{P3Error, P3Result};
use crate::types::*;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Pending manager
pub struct PendingManager {
    /// All pending entries
    pub(crate) entries: HashMap<String, EnhancedPendingEntry>,
    /// Entries by category
    by_category: HashMap<PendingCategory, Vec<PendingId>>,
    /// Default deadline hours by category
    deadline_hours: HashMap<PendingCategory, i64>,
    /// Entry counter for unique IDs
    entry_counter: u64,
}

impl PendingManager {
    /// Create new manager
    pub fn new() -> Self {
        let mut deadline_hours = HashMap::new();
        for cat in [
            PendingCategory::Evidence,
            PendingCategory::Execution,
            PendingCategory::Budget,
            PendingCategory::Appeal,
            PendingCategory::Version,
            PendingCategory::Manual,
        ] {
            deadline_hours.insert(cat.clone(), cat.default_deadline_hours());
        }

        Self {
            entries: HashMap::new(),
            by_category: HashMap::new(),
            deadline_hours,
            entry_counter: 0,
        }
    }

    /// Set custom deadline for category
    pub fn with_deadline(mut self, category: PendingCategory, hours: i64) -> Self {
        self.deadline_hours.insert(category, hours);
        self
    }

    /// Create pending entry
    pub fn create(
        &mut self,
        kind: PendingKind,
        epoch_id: EpochId,
        target_ref: impl Into<String>,
        reason_digest: P3Digest,
    ) -> P3Result<PendingId> {
        let now = Utc::now();
        let category = PendingCategory::from(kind.clone());
        let deadline_hours = self.deadline_hours.get(&category).copied().unwrap_or(24);
        let deadline = now + chrono::Duration::hours(deadline_hours);

        self.entry_counter += 1;
        let pending_id = PendingId::new(format!(
            "pending:{}:{}:{}:{}",
            category.name(),
            epoch_id.as_str(),
            now.timestamp_millis(),
            self.entry_counter
        ));

        let entry = PendingEntry {
            pending_id: pending_id.clone(),
            pending_kind: kind,
            bound_epoch_id: epoch_id,
            target_ref: target_ref.into(),
            reason_digest,
            created_at: now,
            deadline: Some(deadline),
            attempt_chain_id: None,
            resolution: None,
            supersedes_ref: None,
        };

        let enhanced = EnhancedPendingEntry::from_entry(entry);

        // Add to category index
        self.by_category
            .entry(category)
            .or_insert_with(Vec::new)
            .push(pending_id.clone());

        self.entries
            .insert(pending_id.as_str().to_string(), enhanced);

        Ok(pending_id)
    }

    /// Get pending entry
    pub fn get(&self, pending_id: &PendingId) -> Option<&EnhancedPendingEntry> {
        self.entries.get(pending_id.as_str())
    }

    /// Get pending entry mutable
    pub fn get_mut(&mut self, pending_id: &PendingId) -> Option<&mut EnhancedPendingEntry> {
        self.entries.get_mut(pending_id.as_str())
    }

    /// Resolve pending entry
    pub fn resolve(&mut self, request: PendingResolutionRequest) -> P3Result<()> {
        let now = Utc::now();

        let entry = self.entries.get_mut(request.pending_id.as_str()).ok_or_else(|| {
            P3Error::NotFound {
                entity: "PendingEntry".to_string(),
                id: request.pending_id.as_str().to_string(),
            }
        })?;

        if entry.is_resolved() {
            return Err(P3Error::InvalidState {
                reason: "Pending entry already resolved".to_string(),
            });
        }

        entry.entry.resolution = Some(PendingResolution {
            resolved_at: now,
            resolution_type: request.resolution_type,
            resolution_proof_digest: request.resolution_proof_digest,
            resolver_ref: request.resolver_ref,
        });

        entry.last_updated = now;

        Ok(())
    }

    /// Escalate pending entry
    pub fn escalate(&mut self, pending_id: &PendingId) -> P3Result<u32> {
        let entry = self.entries.get_mut(pending_id.as_str()).ok_or_else(|| {
            P3Error::NotFound {
                entity: "PendingEntry".to_string(),
                id: pending_id.as_str().to_string(),
            }
        })?;

        if entry.is_resolved() {
            return Err(P3Error::InvalidState {
                reason: "Cannot escalate resolved entry".to_string(),
            });
        }

        entry.escalate();
        Ok(entry.escalation_level)
    }

    /// Set priority
    pub fn set_priority(&mut self, pending_id: &PendingId, priority: PendingPriority) -> P3Result<()> {
        let entry = self.entries.get_mut(pending_id.as_str()).ok_or_else(|| {
            P3Error::NotFound {
                entity: "PendingEntry".to_string(),
                id: pending_id.as_str().to_string(),
            }
        })?;

        entry.priority = priority;
        entry.last_updated = Utc::now();

        Ok(())
    }

    /// Assign to handler
    pub fn assign(&mut self, pending_id: &PendingId, assignee: impl Into<String>) -> P3Result<()> {
        let entry = self.entries.get_mut(pending_id.as_str()).ok_or_else(|| {
            P3Error::NotFound {
                entity: "PendingEntry".to_string(),
                id: pending_id.as_str().to_string(),
            }
        })?;

        entry.assignee = Some(assignee.into());
        entry.last_updated = Utc::now();

        Ok(())
    }

    /// Get entries by category
    pub fn get_by_category(&self, category: &PendingCategory) -> Vec<&EnhancedPendingEntry> {
        self.by_category
            .get(category)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.entries.get(id.as_str()))
                    .filter(|e| !e.is_resolved())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get entries by priority
    pub fn get_by_priority(&self, priority: &PendingPriority) -> Vec<&EnhancedPendingEntry> {
        self.entries
            .values()
            .filter(|e| !e.is_resolved() && &e.priority == priority)
            .collect()
    }

    /// Get expired entries
    pub fn get_expired(&self, now: &DateTime<Utc>) -> Vec<&EnhancedPendingEntry> {
        self.entries
            .values()
            .filter(|e| !e.is_resolved() && e.is_expired(now))
            .collect()
    }

    /// Get escalated entries
    pub fn get_escalated(&self) -> Vec<&EnhancedPendingEntry> {
        self.entries
            .values()
            .filter(|e| !e.is_resolved() && e.escalation_level > 0)
            .collect()
    }

    /// Get unresolved entries ordered by priority
    pub fn get_unresolved_by_priority(&self) -> Vec<&EnhancedPendingEntry> {
        let mut entries: Vec<_> = self.entries.values().filter(|e| !e.is_resolved()).collect();
        entries.sort_by(|a, b| b.priority.cmp(&a.priority));
        entries
    }

    /// Get statistics
    pub fn stats(&self, now: &DateTime<Utc>) -> PendingQueueStats {
        let unresolved: Vec<_> = self.entries.values().filter(|e| !e.is_resolved()).collect();

        let mut by_category = HashMap::new();
        let mut by_priority = HashMap::new();

        for entry in &unresolved {
            *by_category.entry(entry.category.clone()).or_insert(0) += 1;
            *by_priority.entry(entry.priority.clone()).or_insert(0) += 1;
        }

        let expired = unresolved.iter().filter(|e| e.is_expired(now)).count();
        let escalated = unresolved.iter().filter(|e| e.escalation_level > 0).count();

        let ages: Vec<f64> = unresolved
            .iter()
            .map(|e| (*now - e.entry.created_at).num_seconds() as f64)
            .collect();

        let average_age_secs = if ages.is_empty() {
            0.0
        } else {
            ages.iter().sum::<f64>() / ages.len() as f64
        };

        let oldest_age_secs = ages.into_iter().reduce(f64::max);

        PendingQueueStats {
            total: unresolved.len(),
            by_category,
            by_priority,
            expired,
            escalated,
            average_age_secs,
            oldest_age_secs,
        }
    }

    /// Process expired entries (auto-expire if enabled)
    pub fn process_expired(&mut self, now: &DateTime<Utc>) -> Vec<PendingId> {
        let mut expired_ids = Vec::new();

        for entry in self.entries.values_mut() {
            if !entry.is_resolved() && entry.is_expired(now) && entry.category.auto_expire() {
                entry.entry.resolution = Some(PendingResolution {
                    resolved_at: *now,
                    resolution_type: ResolutionType::Expired,
                    resolution_proof_digest: None,
                    resolver_ref: "system:auto_expire".to_string(),
                });
                expired_ids.push(entry.entry.pending_id.clone());
            }
        }

        expired_ids
    }

    /// Count total entries
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Count unresolved entries
    pub fn count_unresolved(&self) -> usize {
        self.entries.values().filter(|e| !e.is_resolved()).count()
    }
}

impl Default for PendingManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pending_manager_creation() {
        let manager = PendingManager::new();
        assert_eq!(manager.count(), 0);
    }

    #[test]
    fn test_create_pending() {
        let mut manager = PendingManager::new();

        let pending_id = manager
            .create(
                PendingKind::Evidence,
                EpochId::new("epoch:1"),
                "target:1",
                P3Digest::zero(),
            )
            .unwrap();

        assert!(manager.get(&pending_id).is_some());
        assert_eq!(manager.count(), 1);
    }

    #[test]
    fn test_resolve_pending() {
        let mut manager = PendingManager::new();

        let pending_id = manager
            .create(
                PendingKind::Execution,
                EpochId::new("epoch:1"),
                "target:1",
                P3Digest::zero(),
            )
            .unwrap();

        let request = PendingResolutionRequest::new(
            pending_id.clone(),
            ResolutionType::Resolved,
            "resolver:1",
        );

        manager.resolve(request).unwrap();

        let entry = manager.get(&pending_id).unwrap();
        assert!(entry.is_resolved());
    }

    #[test]
    fn test_escalate_pending() {
        let mut manager = PendingManager::new();

        let pending_id = manager
            .create(
                PendingKind::Appeal,
                EpochId::new("epoch:1"),
                "target:1",
                P3Digest::zero(),
            )
            .unwrap();

        let level = manager.escalate(&pending_id).unwrap();
        assert_eq!(level, 1);

        let level = manager.escalate(&pending_id).unwrap();
        assert_eq!(level, 2);
    }

    #[test]
    fn test_set_priority() {
        let mut manager = PendingManager::new();

        let pending_id = manager
            .create(
                PendingKind::Budget,
                EpochId::new("epoch:1"),
                "target:1",
                P3Digest::zero(),
            )
            .unwrap();

        manager.set_priority(&pending_id, PendingPriority::Critical).unwrap();

        let entry = manager.get(&pending_id).unwrap();
        assert_eq!(entry.priority, PendingPriority::Critical);
    }

    #[test]
    fn test_get_by_category() {
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
                PendingKind::Evidence,
                EpochId::new("epoch:1"),
                "target:2",
                P3Digest::zero(),
            )
            .unwrap();

        manager
            .create(
                PendingKind::Budget,
                EpochId::new("epoch:1"),
                "target:3",
                P3Digest::zero(),
            )
            .unwrap();

        let evidence = manager.get_by_category(&PendingCategory::Evidence);
        assert_eq!(evidence.len(), 2);

        let budget = manager.get_by_category(&PendingCategory::Budget);
        assert_eq!(budget.len(), 1);
    }

    #[test]
    fn test_stats() {
        let mut manager = PendingManager::new();
        let now = Utc::now();

        manager
            .create(
                PendingKind::Evidence,
                EpochId::new("epoch:1"),
                "target:1",
                P3Digest::zero(),
            )
            .unwrap();

        let stats = manager.stats(&now);
        assert_eq!(stats.total, 1);
        assert_eq!(stats.expired, 0);
    }

    #[test]
    fn test_process_expired() {
        let mut manager = PendingManager::new().with_deadline(PendingCategory::Evidence, 0);

        manager
            .create(
                PendingKind::Evidence,
                EpochId::new("epoch:1"),
                "target:1",
                P3Digest::zero(),
            )
            .unwrap();

        // Wait for expiry
        std::thread::sleep(std::time::Duration::from_millis(10));

        let now = Utc::now();
        let expired = manager.process_expired(&now);

        assert_eq!(expired.len(), 1);
        assert_eq!(manager.count_unresolved(), 0);
    }
}
