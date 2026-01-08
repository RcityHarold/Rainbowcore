//! Deletion Guard - Tombstone-Only Deletion Invariant
//!
//! Ensures that P2 storage only supports soft deletion via tombstone:
//! - No direct hard deletion of content
//! - All deletions must go through the tombstone process
//! - Tombstone preserves existence proof (metadata)
//! - All deletions are audited
//!
//! This supports the "right to be forgotten" while maintaining
//! accountability through existence proofs.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use l0_core::types::Digest;
use p2_core::types::SealedPayloadStatus;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

use crate::backend::P2StorageBackend;

/// Deletion guard errors
#[derive(Debug, Error)]
pub enum DeletionError {
    /// Direct deletion attempted (not through tombstone)
    #[error("Direct deletion rejected. Use tombstone for ref_id: {0}")]
    DirectDeletionRejected(String),

    /// Payload not found
    #[error("Payload not found: {0}")]
    PayloadNotFound(String),

    /// Already tombstoned
    #[error("Payload already tombstoned: {0}")]
    AlreadyTombstoned(String),

    /// Deletion blocked by legal hold
    #[error("Deletion blocked by legal hold: {hold_id}")]
    LegalHoldBlocked { hold_id: String },

    /// Deletion requires consent
    #[error("Deletion requires consent from: {required_actor}")]
    ConsentRequired { required_actor: String },

    /// Backend error
    #[error("Backend error: {0}")]
    BackendError(String),

    /// Audit logging failed
    #[error("Audit logging failed: {0}")]
    AuditFailed(String),
}

/// Result type for deletion operations
pub type DeletionResult<T> = Result<T, DeletionError>;

/// Deletion request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletionRequest {
    /// Target reference ID
    pub ref_id: String,
    /// Deletion reason
    pub reason: String,
    /// Requestor (actor ID)
    pub requestor: String,
    /// Request timestamp
    pub timestamp: DateTime<Utc>,
}

/// Tombstone record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TombstoneRecord {
    /// Record ID
    pub record_id: String,
    /// Reference ID being tombstoned
    pub ref_id: String,
    /// Original checksum (existence proof)
    pub original_checksum: Digest,
    /// Original size (existence proof)
    pub original_size_bytes: u64,
    /// Tombstone reason
    pub reason: String,
    /// Requestor
    pub requestor: String,
    /// Request timestamp
    pub requested_at: DateTime<Utc>,
    /// Execution timestamp
    pub executed_at: DateTime<Utc>,
    /// Associated consent reference (if right-to-be-forgotten)
    pub consent_ref: Option<String>,
    /// Evidence level impact (tombstone may degrade linked evidence)
    pub evidence_level_impact: Option<String>,
}

impl TombstoneRecord {
    /// Create a new tombstone record
    pub fn new(
        ref_id: String,
        original_checksum: Digest,
        original_size_bytes: u64,
        reason: String,
        requestor: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            record_id: format!("tombstone:{}:{}", ref_id, now.timestamp_millis()),
            ref_id,
            original_checksum,
            original_size_bytes,
            reason,
            requestor,
            requested_at: now,
            executed_at: now,
            consent_ref: None,
            evidence_level_impact: None,
        }
    }

    /// Create existence proof digest
    pub fn existence_proof_digest(&self) -> Digest {
        let data = format!(
            "{}:{}:{}:{}",
            self.ref_id,
            self.original_checksum.to_hex(),
            self.original_size_bytes,
            self.requested_at.to_rfc3339()
        );
        Digest::blake3(data.as_bytes())
    }
}

/// Deletion guard
pub struct DeletionGuard {
    /// Tombstone records
    tombstone_records: Arc<RwLock<HashMap<String, TombstoneRecord>>>,
    /// Legal holds (ref_id -> hold_id)
    legal_holds: Arc<RwLock<HashMap<String, String>>>,
    /// Statistics
    stats: Arc<RwLock<DeletionStats>>,
}

/// Deletion statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeletionStats {
    /// Total deletion requests
    pub total_requests: u64,
    /// Successful tombstones
    pub successful_tombstones: u64,
    /// Rejected deletions
    pub rejected_deletions: u64,
    /// Blocked by legal hold
    pub blocked_by_legal_hold: u64,
    /// Already tombstoned
    pub already_tombstoned: u64,
}

impl DeletionGuard {
    /// Create a new deletion guard
    pub fn new() -> Self {
        Self {
            tombstone_records: Arc::new(RwLock::new(HashMap::new())),
            legal_holds: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(DeletionStats::default())),
        }
    }

    /// Process a deletion request (returns tombstone record if successful)
    pub async fn process_deletion<B: P2StorageBackend>(
        &self,
        backend: &B,
        request: DeletionRequest,
    ) -> DeletionResult<TombstoneRecord> {
        let mut stats = self.stats.write().await;
        stats.total_requests += 1;

        // Check for legal holds
        {
            let holds = self.legal_holds.read().await;
            if let Some(hold_id) = holds.get(&request.ref_id) {
                stats.blocked_by_legal_hold += 1;
                return Err(DeletionError::LegalHoldBlocked {
                    hold_id: hold_id.clone(),
                });
            }
        }

        // Check if already tombstoned
        {
            let records = self.tombstone_records.read().await;
            if records.contains_key(&request.ref_id) {
                stats.already_tombstoned += 1;
                return Err(DeletionError::AlreadyTombstoned(request.ref_id.clone()));
            }
        }

        // Get current metadata for existence proof
        let metadata = backend.get_metadata(&request.ref_id).await.map_err(|e| {
            stats.rejected_deletions += 1;
            DeletionError::BackendError(format!("Failed to get metadata: {}", e))
        })?;

        // Check if already tombstoned at backend level
        if metadata.status == SealedPayloadStatus::Tombstoned {
            stats.already_tombstoned += 1;
            return Err(DeletionError::AlreadyTombstoned(request.ref_id.clone()));
        }

        // Create tombstone record
        let original_checksum = Digest::from_hex(&metadata.checksum).unwrap_or_default();
        let tombstone_record = TombstoneRecord::new(
            request.ref_id.clone(),
            original_checksum,
            metadata.size_bytes,
            request.reason,
            request.requestor,
        );

        // Store tombstone record
        {
            let mut records = self.tombstone_records.write().await;
            records.insert(request.ref_id.clone(), tombstone_record.clone());
        }

        stats.successful_tombstones += 1;

        tracing::info!(
            "Tombstone record created: {} for ref_id {}",
            tombstone_record.record_id,
            tombstone_record.ref_id
        );

        Ok(tombstone_record)
    }

    /// Add a legal hold
    pub async fn add_legal_hold(&self, ref_id: &str, hold_id: &str) {
        let mut holds = self.legal_holds.write().await;
        holds.insert(ref_id.to_string(), hold_id.to_string());
        tracing::info!("Legal hold {} added for ref_id {}", hold_id, ref_id);
    }

    /// Remove a legal hold
    pub async fn remove_legal_hold(&self, ref_id: &str) -> Option<String> {
        let mut holds = self.legal_holds.write().await;
        let removed = holds.remove(ref_id);
        if let Some(ref hold_id) = removed {
            tracing::info!("Legal hold {} removed for ref_id {}", hold_id, ref_id);
        }
        removed
    }

    /// Check if ref_id has a legal hold
    pub async fn has_legal_hold(&self, ref_id: &str) -> bool {
        let holds = self.legal_holds.read().await;
        holds.contains_key(ref_id)
    }

    /// Get tombstone record
    pub async fn get_tombstone_record(&self, ref_id: &str) -> Option<TombstoneRecord> {
        let records = self.tombstone_records.read().await;
        records.get(ref_id).cloned()
    }

    /// Check if ref_id is tombstoned
    pub async fn is_tombstoned(&self, ref_id: &str) -> bool {
        let records = self.tombstone_records.read().await;
        records.contains_key(ref_id)
    }

    /// Get statistics
    pub async fn get_stats(&self) -> DeletionStats {
        self.stats.read().await.clone()
    }

    /// List all tombstone records
    pub async fn list_tombstones(&self) -> Vec<TombstoneRecord> {
        let records = self.tombstone_records.read().await;
        records.values().cloned().collect()
    }

    /// Get tombstone count
    pub async fn tombstone_count(&self) -> usize {
        let records = self.tombstone_records.read().await;
        records.len()
    }
}

impl Default for DeletionGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// Existence proof for tombstoned data
///
/// This proves that data once existed without revealing the content.
/// Used for accountability while respecting right-to-be-forgotten.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExistenceProof {
    /// Reference ID
    pub ref_id: String,
    /// Original content hash
    pub content_hash: Digest,
    /// Original size
    pub size_bytes: u64,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Tombstone timestamp
    pub tombstoned_at: DateTime<Utc>,
    /// Proof digest (covers all fields)
    pub proof_digest: Digest,
}

impl ExistenceProof {
    /// Create from tombstone record
    pub fn from_tombstone(record: &TombstoneRecord, created_at: DateTime<Utc>) -> Self {
        let proof_data = format!(
            "{}:{}:{}:{}:{}",
            record.ref_id,
            record.original_checksum.to_hex(),
            record.original_size_bytes,
            created_at.to_rfc3339(),
            record.executed_at.to_rfc3339()
        );

        Self {
            ref_id: record.ref_id.clone(),
            content_hash: record.original_checksum.clone(),
            size_bytes: record.original_size_bytes,
            created_at,
            tombstoned_at: record.executed_at,
            proof_digest: Digest::blake3(proof_data.as_bytes()),
        }
    }

    /// Verify the proof integrity
    pub fn verify(&self) -> bool {
        let proof_data = format!(
            "{}:{}:{}:{}:{}",
            self.ref_id,
            self.content_hash.to_hex(),
            self.size_bytes,
            self.created_at.to_rfc3339(),
            self.tombstoned_at.to_rfc3339()
        );
        let computed = Digest::blake3(proof_data.as_bytes());
        computed == self.proof_digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tombstone_record() {
        let record = TombstoneRecord::new(
            "ref:001".to_string(),
            Digest::blake3(b"test content"),
            1024,
            "Right to be forgotten".to_string(),
            "actor:user001".to_string(),
        );

        assert!(record.record_id.starts_with("tombstone:ref:001:"));
        assert_eq!(record.ref_id, "ref:001");
        assert_eq!(record.original_size_bytes, 1024);

        // Test existence proof digest
        let proof = record.existence_proof_digest();
        assert!(!proof.to_hex().is_empty());
    }

    #[test]
    fn test_existence_proof() {
        let record = TombstoneRecord::new(
            "ref:002".to_string(),
            Digest::blake3(b"secret data"),
            2048,
            "User request".to_string(),
            "actor:admin".to_string(),
        );

        let created_at = Utc::now() - chrono::Duration::days(30);
        let proof = ExistenceProof::from_tombstone(&record, created_at);

        assert!(proof.verify());
        assert_eq!(proof.ref_id, "ref:002");
        assert_eq!(proof.size_bytes, 2048);
    }

    #[tokio::test]
    async fn test_deletion_guard_legal_hold() {
        let guard = DeletionGuard::new();

        // Add legal hold
        guard.add_legal_hold("ref:003", "hold:case001").await;
        assert!(guard.has_legal_hold("ref:003").await);

        // Remove legal hold
        let removed = guard.remove_legal_hold("ref:003").await;
        assert_eq!(removed, Some("hold:case001".to_string()));
        assert!(!guard.has_legal_hold("ref:003").await);
    }

    #[tokio::test]
    async fn test_deletion_stats() {
        let guard = DeletionGuard::new();
        let stats = guard.get_stats().await;

        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.successful_tombstones, 0);
    }
}
