//! Legal Hold Management
//!
//! Manages legal holds that prevent data deletion regardless of retention policy.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::error::{StorageError, StorageResult};

/// Legal hold status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegalHoldStatus {
    /// Active hold
    Active,
    /// Released
    Released,
    /// Expired (automatically released after date)
    Expired,
}

/// Legal hold record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegalHold {
    /// Hold ID
    pub hold_id: String,
    /// Case reference (legal case ID)
    pub case_ref: String,
    /// Description/reason
    pub description: String,
    /// Issuing authority
    pub issuing_authority: String,
    /// Contact information
    pub contact_info: Option<String>,
    /// Applied timestamp
    pub applied_at: DateTime<Utc>,
    /// Valid until (None = indefinite)
    pub valid_until: Option<DateTime<Utc>>,
    /// Released timestamp
    pub released_at: Option<DateTime<Utc>>,
    /// Release reason
    pub release_reason: Option<String>,
    /// Status
    pub status: LegalHoldStatus,
    /// Affected payload ref IDs
    pub affected_refs: HashSet<String>,
    /// Audit trail
    pub audit_entries: Vec<LegalHoldAuditEntry>,
}

impl LegalHold {
    /// Create a new legal hold
    pub fn new(
        hold_id: String,
        case_ref: String,
        description: String,
        issuing_authority: String,
        affected_refs: HashSet<String>,
    ) -> Self {
        let now = Utc::now();
        let mut hold = Self {
            hold_id: hold_id.clone(),
            case_ref,
            description,
            issuing_authority,
            contact_info: None,
            applied_at: now,
            valid_until: None,
            released_at: None,
            release_reason: None,
            status: LegalHoldStatus::Active,
            affected_refs,
            audit_entries: Vec::new(),
        };

        hold.add_audit_entry(LegalHoldAuditAction::Applied, "Legal hold applied");

        hold
    }

    /// Check if the hold is currently active
    pub fn is_active(&self) -> bool {
        if self.status != LegalHoldStatus::Active {
            return false;
        }

        // Check expiration
        if let Some(valid_until) = self.valid_until {
            if Utc::now() >= valid_until {
                return false;
            }
        }

        true
    }

    /// Release the legal hold
    pub fn release(&mut self, reason: String) {
        self.status = LegalHoldStatus::Released;
        self.released_at = Some(Utc::now());
        self.release_reason = Some(reason.clone());

        self.add_audit_entry(LegalHoldAuditAction::Released, &reason);
    }

    /// Add a payload to the hold
    pub fn add_payload(&mut self, ref_id: String) {
        if self.affected_refs.insert(ref_id.clone()) {
            self.add_audit_entry(
                LegalHoldAuditAction::PayloadAdded,
                &format!("Added payload: {}", ref_id),
            );
        }
    }

    /// Remove a payload from the hold
    pub fn remove_payload(&mut self, ref_id: &str) {
        if self.affected_refs.remove(ref_id) {
            self.add_audit_entry(
                LegalHoldAuditAction::PayloadRemoved,
                &format!("Removed payload: {}", ref_id),
            );
        }
    }

    /// Extend the hold
    pub fn extend(&mut self, new_valid_until: DateTime<Utc>) {
        self.valid_until = Some(new_valid_until);
        self.add_audit_entry(
            LegalHoldAuditAction::Extended,
            &format!("Extended until: {}", new_valid_until),
        );
    }

    /// Add audit entry
    fn add_audit_entry(&mut self, action: LegalHoldAuditAction, details: &str) {
        self.audit_entries.push(LegalHoldAuditEntry {
            timestamp: Utc::now(),
            action,
            details: details.to_string(),
        });
    }

    /// Get the number of affected payloads
    pub fn payload_count(&self) -> usize {
        self.affected_refs.len()
    }
}

/// Legal hold audit action
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegalHoldAuditAction {
    Applied,
    Released,
    Extended,
    PayloadAdded,
    PayloadRemoved,
    Queried,
}

/// Legal hold audit entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegalHoldAuditEntry {
    pub timestamp: DateTime<Utc>,
    pub action: LegalHoldAuditAction,
    pub details: String,
}

/// Legal hold manager
pub struct LegalHoldManager {
    /// Holds by ID
    holds: RwLock<HashMap<String, LegalHold>>,
    /// Index: ref_id -> hold_ids
    ref_to_holds: RwLock<HashMap<String, HashSet<String>>>,
    /// Index: case_ref -> hold_ids
    case_to_holds: RwLock<HashMap<String, HashSet<String>>>,
}

impl LegalHoldManager {
    /// Create a new legal hold manager
    pub fn new() -> Self {
        Self {
            holds: RwLock::new(HashMap::new()),
            ref_to_holds: RwLock::new(HashMap::new()),
            case_to_holds: RwLock::new(HashMap::new()),
        }
    }

    /// Apply a new legal hold
    pub async fn apply_hold(&self, hold: LegalHold) -> StorageResult<()> {
        let hold_id = hold.hold_id.clone();
        let case_ref = hold.case_ref.clone();
        let affected_refs = hold.affected_refs.clone();

        // Store the hold
        self.holds.write().await.insert(hold_id.clone(), hold);

        // Update indexes
        {
            let mut ref_to_holds = self.ref_to_holds.write().await;
            for ref_id in &affected_refs {
                ref_to_holds
                    .entry(ref_id.clone())
                    .or_insert_with(HashSet::new)
                    .insert(hold_id.clone());
            }
        }

        {
            let mut case_to_holds = self.case_to_holds.write().await;
            case_to_holds
                .entry(case_ref.clone())
                .or_insert_with(HashSet::new)
                .insert(hold_id.clone());
        }

        info!(
            hold_id = %hold_id,
            case_ref = %case_ref,
            payload_count = affected_refs.len(),
            "Legal hold applied"
        );

        Ok(())
    }

    /// Release a legal hold
    pub async fn release_hold(&self, hold_id: &str, reason: String) -> StorageResult<()> {
        let mut holds = self.holds.write().await;
        let hold = holds
            .get_mut(hold_id)
            .ok_or_else(|| StorageError::NotFound(format!("Legal hold not found: {}", hold_id)))?;

        hold.release(reason);

        info!(hold_id = %hold_id, "Legal hold released");

        Ok(())
    }

    /// Check if a payload is under any legal hold
    pub async fn is_under_hold(&self, ref_id: &str) -> StorageResult<bool> {
        let ref_to_holds = self.ref_to_holds.read().await;

        if let Some(hold_ids) = ref_to_holds.get(ref_id) {
            let holds = self.holds.read().await;
            for hold_id in hold_ids {
                if let Some(hold) = holds.get(hold_id) {
                    if hold.is_active() {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    /// Get all active holds for a payload
    pub async fn get_holds_for_payload(&self, ref_id: &str) -> Vec<LegalHold> {
        let ref_to_holds = self.ref_to_holds.read().await;
        let holds = self.holds.read().await;

        let mut result = Vec::new();

        if let Some(hold_ids) = ref_to_holds.get(ref_id) {
            for hold_id in hold_ids {
                if let Some(hold) = holds.get(hold_id) {
                    if hold.is_active() {
                        result.push(hold.clone());
                    }
                }
            }
        }

        result
    }

    /// Get all holds for a case
    pub async fn get_holds_for_case(&self, case_ref: &str) -> Vec<LegalHold> {
        let case_to_holds = self.case_to_holds.read().await;
        let holds = self.holds.read().await;

        let mut result = Vec::new();

        if let Some(hold_ids) = case_to_holds.get(case_ref) {
            for hold_id in hold_ids {
                if let Some(hold) = holds.get(hold_id) {
                    result.push(hold.clone());
                }
            }
        }

        result
    }

    /// Get a specific hold
    pub async fn get_hold(&self, hold_id: &str) -> Option<LegalHold> {
        self.holds.read().await.get(hold_id).cloned()
    }

    /// Add payload to an existing hold
    pub async fn add_payload_to_hold(&self, hold_id: &str, ref_id: &str) -> StorageResult<()> {
        {
            let mut holds = self.holds.write().await;
            let hold = holds.get_mut(hold_id).ok_or_else(|| {
                StorageError::NotFound(format!("Legal hold not found: {}", hold_id))
            })?;

            if !hold.is_active() {
                return Err(StorageError::OperationFailed(
                    "Cannot modify released hold".to_string(),
                ));
            }

            hold.add_payload(ref_id.to_string());
        }

        // Update index
        {
            let mut ref_to_holds = self.ref_to_holds.write().await;
            ref_to_holds
                .entry(ref_id.to_string())
                .or_insert_with(HashSet::new)
                .insert(hold_id.to_string());
        }

        Ok(())
    }

    /// Get statistics
    pub async fn get_stats(&self) -> LegalHoldStats {
        let holds = self.holds.read().await;

        let mut stats = LegalHoldStats::default();
        stats.total_holds = holds.len();

        for hold in holds.values() {
            match hold.status {
                LegalHoldStatus::Active if hold.is_active() => {
                    stats.active_holds += 1;
                    stats.affected_payloads += hold.payload_count();
                }
                LegalHoldStatus::Released => stats.released_holds += 1,
                LegalHoldStatus::Expired => stats.expired_holds += 1,
                _ => stats.expired_holds += 1, // Inactive but not released
            }
        }

        stats
    }
}

impl Default for LegalHoldManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Legal hold statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LegalHoldStats {
    pub total_holds: usize,
    pub active_holds: usize,
    pub released_holds: usize,
    pub expired_holds: usize,
    pub affected_payloads: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_hold() -> LegalHold {
        let mut affected = HashSet::new();
        affected.insert("payload:001".to_string());
        affected.insert("payload:002".to_string());

        LegalHold::new(
            "hold:001".to_string(),
            "case:001".to_string(),
            "Test legal hold".to_string(),
            "Test Authority".to_string(),
            affected,
        )
    }

    #[test]
    fn test_legal_hold_creation() {
        let hold = create_test_hold();

        assert!(hold.is_active());
        assert_eq!(hold.payload_count(), 2);
        assert_eq!(hold.audit_entries.len(), 1);
    }

    #[test]
    fn test_legal_hold_release() {
        let mut hold = create_test_hold();

        hold.release("Case resolved".to_string());

        assert!(!hold.is_active());
        assert_eq!(hold.status, LegalHoldStatus::Released);
        assert!(hold.released_at.is_some());
    }

    #[tokio::test]
    async fn test_legal_hold_manager() {
        let manager = LegalHoldManager::new();

        let hold = create_test_hold();
        manager.apply_hold(hold).await.unwrap();

        // Check if payloads are under hold
        assert!(manager.is_under_hold("payload:001").await.unwrap());
        assert!(manager.is_under_hold("payload:002").await.unwrap());
        assert!(!manager.is_under_hold("payload:999").await.unwrap());

        // Release the hold
        manager
            .release_hold("hold:001", "Case closed".to_string())
            .await
            .unwrap();

        // Payloads should no longer be under hold
        assert!(!manager.is_under_hold("payload:001").await.unwrap());
    }

    #[tokio::test]
    async fn test_get_stats() {
        let manager = LegalHoldManager::new();

        let hold = create_test_hold();
        manager.apply_hold(hold).await.unwrap();

        let stats = manager.get_stats().await;
        assert_eq!(stats.total_holds, 1);
        assert_eq!(stats.active_holds, 1);
        assert_eq!(stats.affected_payloads, 2);
    }
}
