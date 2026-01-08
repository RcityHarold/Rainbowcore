//! Append-Only Invariant Enforcement
//!
//! Ensures that P2 storage follows the append-only model:
//! - No direct overwrites of existing data
//! - Same content with same hash = idempotent (allowed)
//! - Different content with same ref_id = collision (rejected)
//! - Modifications create new versions, not overwrites

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use l0_core::types::Digest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

use crate::backend::P2StorageBackend;

/// Append-Only enforcement errors
#[derive(Debug, Error)]
pub enum AppendOnlyError {
    /// Attempted to overwrite existing data with different content
    #[error("Overwrite rejected: ref_id '{0}' already exists with different content")]
    OverwriteRejected(String),

    /// Hash collision detected (should be cryptographically impossible)
    #[error("CRITICAL: Hash collision detected for ref_id '{0}'")]
    HashCollision(String),

    /// Backend check failed
    #[error("Backend check failed: {0}")]
    BackendError(String),

    /// Version conflict
    #[error("Version conflict: expected version {expected}, found {found}")]
    VersionConflict { expected: u64, found: u64 },
}

/// Result type for append-only operations
pub type AppendOnlyResult<T> = Result<T, AppendOnlyError>;

/// Write operation descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteOperation {
    /// Target reference ID
    pub ref_id: String,
    /// Hash of the data being written
    pub data_hash: Digest,
    /// Size of the data
    pub size_bytes: u64,
    /// Operation timestamp
    pub timestamp: DateTime<Utc>,
}

/// Append-Only Guard
///
/// Enforces the append-only invariant for all write operations.
pub struct AppendOnlyGuard {
    /// Cache of known ref_ids and their hashes (for quick duplicate detection)
    known_refs: Arc<RwLock<HashMap<String, Digest>>>,
    /// Statistics
    stats: Arc<RwLock<AppendOnlyStats>>,
}

/// Append-only operation statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppendOnlyStats {
    /// Total write attempts
    pub total_writes: u64,
    /// Successful new writes
    pub new_writes: u64,
    /// Idempotent writes (same content)
    pub idempotent_writes: u64,
    /// Rejected overwrites
    pub rejected_overwrites: u64,
    /// Hash collisions (should always be 0)
    pub hash_collisions: u64,
}

impl AppendOnlyGuard {
    /// Create a new append-only guard
    pub fn new() -> Self {
        Self {
            known_refs: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(AppendOnlyStats::default())),
        }
    }

    /// Check if a write operation is allowed
    ///
    /// Returns Ok(()) if the write is allowed (new write or idempotent)
    /// Returns Err if the write would violate append-only invariant
    pub async fn check_write<B: P2StorageBackend>(
        &self,
        backend: &B,
        operation: &WriteOperation,
    ) -> AppendOnlyResult<WriteCheckResult> {
        let mut stats = self.stats.write().await;
        stats.total_writes += 1;

        // First, check the local cache
        {
            let known = self.known_refs.read().await;
            if let Some(existing_hash) = known.get(&operation.ref_id) {
                if *existing_hash == operation.data_hash {
                    stats.idempotent_writes += 1;
                    return Ok(WriteCheckResult::Idempotent);
                } else {
                    stats.rejected_overwrites += 1;
                    return Err(AppendOnlyError::OverwriteRejected(operation.ref_id.clone()));
                }
            }
        }

        // Check the backend
        match backend.exists(&operation.ref_id).await {
            Ok(true) => {
                // Payload exists, need to verify content hash
                match backend.get_metadata(&operation.ref_id).await {
                    Ok(meta) => {
                        let existing_hash = Digest::from_hex(&meta.checksum)
                            .unwrap_or_else(|_| Digest::zero());

                        // Update cache
                        {
                            let mut known = self.known_refs.write().await;
                            known.insert(operation.ref_id.clone(), existing_hash.clone());
                        }

                        if existing_hash == operation.data_hash {
                            stats.idempotent_writes += 1;
                            Ok(WriteCheckResult::Idempotent)
                        } else {
                            stats.rejected_overwrites += 1;
                            // This is a CRITICAL error - different content with same ref_id
                            // With proper content-addressed storage, this means hash collision
                            stats.hash_collisions += 1;
                            Err(AppendOnlyError::HashCollision(operation.ref_id.clone()))
                        }
                    }
                    Err(e) => {
                        Err(AppendOnlyError::BackendError(format!(
                            "Failed to get metadata for {}: {}",
                            operation.ref_id, e
                        )))
                    }
                }
            }
            Ok(false) => {
                // New write
                stats.new_writes += 1;

                // Pre-register in cache to prevent race conditions
                {
                    let mut known = self.known_refs.write().await;
                    known.insert(operation.ref_id.clone(), operation.data_hash.clone());
                }

                Ok(WriteCheckResult::NewWrite)
            }
            Err(e) => {
                Err(AppendOnlyError::BackendError(format!(
                    "Failed to check existence: {}", e
                )))
            }
        }
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> AppendOnlyStats {
        self.stats.read().await.clone()
    }

    /// Clear the cache (for testing or memory management)
    pub async fn clear_cache(&self) {
        self.known_refs.write().await.clear();
    }

    /// Check if append-only invariant is healthy
    pub async fn is_healthy(&self) -> bool {
        let stats = self.stats.read().await;
        // Healthy if no hash collisions ever occurred
        stats.hash_collisions == 0
    }
}

impl Default for AppendOnlyGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a write check
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteCheckResult {
    /// New write (ref_id doesn't exist)
    NewWrite,
    /// Idempotent write (same content already exists)
    Idempotent,
}

impl WriteCheckResult {
    /// Check if this is a new write
    pub fn is_new(&self) -> bool {
        matches!(self, WriteCheckResult::NewWrite)
    }

    /// Check if this is an idempotent write
    pub fn is_idempotent(&self) -> bool {
        matches!(self, WriteCheckResult::Idempotent)
    }
}

/// Version tracking for versioned append-only storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedRef {
    /// Base reference ID
    pub base_ref_id: String,
    /// Current version number
    pub version: u64,
    /// Version history (version -> ref_id)
    pub version_history: Vec<VersionEntry>,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Last modified timestamp
    pub last_modified_at: DateTime<Utc>,
}

/// Version entry in version history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionEntry {
    /// Version number
    pub version: u64,
    /// Actual storage ref_id for this version
    pub ref_id: String,
    /// Content hash
    pub content_hash: Digest,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Creator (actor ID)
    pub created_by: Option<String>,
    /// Reason for new version
    pub reason: Option<String>,
}

impl VersionedRef {
    /// Create a new versioned reference
    pub fn new(base_ref_id: String, initial_ref_id: String, content_hash: Digest) -> Self {
        let now = Utc::now();
        Self {
            base_ref_id,
            version: 1,
            version_history: vec![VersionEntry {
                version: 1,
                ref_id: initial_ref_id,
                content_hash,
                created_at: now,
                created_by: None,
                reason: Some("Initial version".to_string()),
            }],
            created_at: now,
            last_modified_at: now,
        }
    }

    /// Add a new version (append-only)
    pub fn add_version(
        &mut self,
        ref_id: String,
        content_hash: Digest,
        created_by: Option<String>,
        reason: Option<String>,
    ) -> u64 {
        self.version += 1;
        let entry = VersionEntry {
            version: self.version,
            ref_id,
            content_hash,
            created_at: Utc::now(),
            created_by,
            reason,
        };
        self.version_history.push(entry);
        self.last_modified_at = Utc::now();
        self.version
    }

    /// Get the latest version's ref_id
    pub fn latest_ref_id(&self) -> Option<&str> {
        self.version_history.last().map(|e| e.ref_id.as_str())
    }

    /// Get a specific version's ref_id
    pub fn get_version_ref_id(&self, version: u64) -> Option<&str> {
        self.version_history
            .iter()
            .find(|e| e.version == version)
            .map(|e| e.ref_id.as_str())
    }

    /// Get version count
    pub fn version_count(&self) -> usize {
        self.version_history.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_check_result() {
        assert!(WriteCheckResult::NewWrite.is_new());
        assert!(!WriteCheckResult::NewWrite.is_idempotent());
        assert!(WriteCheckResult::Idempotent.is_idempotent());
        assert!(!WriteCheckResult::Idempotent.is_new());
    }

    #[test]
    fn test_versioned_ref() {
        let mut versioned = VersionedRef::new(
            "base:001".to_string(),
            "ref:001:v1".to_string(),
            Digest::zero(),
        );

        assert_eq!(versioned.version, 1);
        assert_eq!(versioned.version_count(), 1);

        let new_version = versioned.add_version(
            "ref:001:v2".to_string(),
            Digest::blake3(b"new content"),
            Some("actor:001".to_string()),
            Some("Content update".to_string()),
        );

        assert_eq!(new_version, 2);
        assert_eq!(versioned.version_count(), 2);
        assert_eq!(versioned.latest_ref_id(), Some("ref:001:v2"));
        assert_eq!(versioned.get_version_ref_id(1), Some("ref:001:v1"));
    }

    #[tokio::test]
    async fn test_append_only_stats() {
        let guard = AppendOnlyGuard::new();
        let stats = guard.get_stats().await;

        assert_eq!(stats.total_writes, 0);
        assert_eq!(stats.new_writes, 0);
        assert_eq!(stats.rejected_overwrites, 0);
        assert!(guard.is_healthy().await);
    }
}
