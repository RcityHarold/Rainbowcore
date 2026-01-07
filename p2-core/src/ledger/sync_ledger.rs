//! Sync State Ledger Implementation
//!
//! Persistent storage for three-phase sync states.
//! Enables recovery of incomplete syncs and status tracking.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::fs;
use tokio::sync::RwLock;

use super::encrypted_storage::{EncryptedStorage, EncryptedStorageConfig};
use crate::error::{P2Error, P2Result};

/// Sync phase enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncPhase {
    /// Phase 1: Plain (local generation)
    Plain,
    /// Phase 2: Encrypted (upload to DSN)
    Encrypted,
    /// Phase 3: Committed (L0 commitment)
    Committed,
    /// Completed successfully
    Completed,
    /// Failed
    Failed,
}

/// Persisted sync state entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStateEntry {
    /// Sync ID
    pub sync_id: String,
    /// Current phase
    pub phase: SyncPhase,
    /// Payload reference ID (if encrypted phase complete)
    pub ref_id: Option<String>,
    /// Commit ID (if committed phase complete)
    pub commit_id: Option<String>,
    /// Receipt ID from L0 (if committed phase complete)
    pub receipt_id: Option<String>,
    /// Committer identifier
    pub committer: String,
    /// Content type
    pub content_type: String,
    /// Local path hint
    pub local_path: Option<String>,
    /// Payload checksum (blake3)
    pub payload_checksum: Option<String>,
    /// Payload size in bytes
    pub payload_size: Option<u64>,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Retry count
    pub retry_count: u32,
    /// Started at timestamp
    pub started_at: DateTime<Utc>,
    /// Completed at timestamp
    pub completed_at: Option<DateTime<Utc>>,
    /// Last updated timestamp
    pub updated_at: DateTime<Utc>,
}

impl SyncStateEntry {
    /// Create a new sync state entry
    pub fn new(sync_id: String, committer: String, content_type: String) -> Self {
        let now = Utc::now();
        Self {
            sync_id,
            phase: SyncPhase::Plain,
            ref_id: None,
            commit_id: None,
            receipt_id: None,
            committer,
            content_type,
            local_path: None,
            payload_checksum: None,
            payload_size: None,
            error: None,
            retry_count: 0,
            started_at: now,
            completed_at: None,
            updated_at: now,
        }
    }

    /// Check if sync is complete
    pub fn is_complete(&self) -> bool {
        matches!(self.phase, SyncPhase::Completed)
    }

    /// Check if sync failed
    pub fn is_failed(&self) -> bool {
        matches!(self.phase, SyncPhase::Failed)
    }

    /// Check if sync can be resumed
    pub fn can_resume(&self) -> bool {
        !self.is_complete() && self.retry_count < 10
    }

    /// Get duration in milliseconds
    pub fn duration_ms(&self) -> Option<i64> {
        self.completed_at
            .map(|end| (end - self.started_at).num_milliseconds())
    }
}

/// Sync State Ledger trait
#[async_trait]
pub trait SyncLedger: Send + Sync {
    /// Create a new sync state
    async fn create(&self, entry: SyncStateEntry) -> P2Result<String>;

    /// Get sync state by ID
    async fn get(&self, sync_id: &str) -> P2Result<Option<SyncStateEntry>>;

    /// Update sync state
    async fn update(&self, entry: SyncStateEntry) -> P2Result<()>;

    /// List incomplete syncs for recovery
    async fn list_incomplete(&self, limit: usize) -> P2Result<Vec<SyncStateEntry>>;

    /// List syncs by committer
    async fn list_by_committer(
        &self,
        committer: &str,
        limit: usize,
    ) -> P2Result<Vec<SyncStateEntry>>;

    /// Delete completed syncs older than given timestamp
    async fn cleanup(&self, older_than: DateTime<Utc>) -> P2Result<u64>;
}

/// Index entry for sync lookup
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncIndexEntry {
    sync_id: String,
    committer: String,
    phase: SyncPhase,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// File-based sync state ledger with encryption at rest
pub struct FileSyncLedger {
    /// Base path for sync storage
    base_path: PathBuf,
    /// Sync states directory
    states_path: PathBuf,
    /// Index path
    index_path: PathBuf,
    /// In-memory index cache
    index_cache: RwLock<HashMap<String, SyncIndexEntry>>,
    /// Encrypted storage handler
    storage: EncryptedStorage,
}

impl FileSyncLedger {
    /// Create a new file-based sync ledger with default encryption
    pub async fn new(base_path: impl Into<PathBuf>) -> P2Result<Self> {
        Self::with_config(base_path, EncryptedStorageConfig::default()).await
    }

    /// Create with custom encryption config
    pub async fn with_config(
        base_path: impl Into<PathBuf>,
        encryption_config: EncryptedStorageConfig,
    ) -> P2Result<Self> {
        let base_path = base_path.into();
        let states_path = base_path.join("states");
        let index_path = base_path.join("index.enc");

        // Create directories
        for path in [&base_path, &states_path] {
            fs::create_dir_all(path).await.map_err(|e| {
                P2Error::Storage(format!("Failed to create directory {:?}: {}", path, e))
            })?;
        }

        let storage = EncryptedStorage::new(encryption_config);

        // Load or create index
        let index_cache = if index_path.exists() {
            let entries: Vec<SyncIndexEntry> = storage
                .read(&index_path, "sync-ledger-index")
                .await
                .unwrap_or_default();
            let mut map = HashMap::new();
            for entry in entries {
                map.insert(entry.sync_id.clone(), entry);
            }
            RwLock::new(map)
        } else {
            RwLock::new(HashMap::new())
        };

        Ok(Self {
            base_path,
            states_path,
            index_path,
            index_cache,
            storage,
        })
    }

    /// Create with encryption disabled (for testing only)
    #[cfg(test)]
    pub async fn unencrypted(base_path: impl Into<PathBuf>) -> P2Result<Self> {
        Self::with_config(base_path, EncryptedStorageConfig::unencrypted()).await
    }

    /// Save the index to disk (encrypted)
    async fn save_index(&self) -> P2Result<()> {
        let entries: Vec<_> = self
            .index_cache
            .read()
            .await
            .values()
            .cloned()
            .collect();

        self.storage
            .write(&self.index_path, &entries, "sync-ledger-index")
            .await
    }

    /// Get the file path for a sync state
    fn state_file_path(&self, sync_id: &str) -> PathBuf {
        self.states_path.join(format!("{}.enc", sync_id))
    }
}

#[async_trait]
impl SyncLedger for FileSyncLedger {
    async fn create(&self, entry: SyncStateEntry) -> P2Result<String> {
        let sync_id = entry.sync_id.clone();

        // Write encrypted state
        let path = self.state_file_path(&sync_id);
        self.storage.write(&path, &entry, &sync_id).await?;

        // Update index
        {
            let mut cache = self.index_cache.write().await;
            cache.insert(
                sync_id.clone(),
                SyncIndexEntry {
                    sync_id: sync_id.clone(),
                    committer: entry.committer.clone(),
                    phase: entry.phase,
                    created_at: entry.started_at,
                    updated_at: entry.updated_at,
                },
            );
        }

        self.save_index().await?;

        Ok(sync_id)
    }

    async fn get(&self, sync_id: &str) -> P2Result<Option<SyncStateEntry>> {
        let path = self.state_file_path(sync_id);
        if !path.exists() {
            return Ok(None);
        }

        let entry: SyncStateEntry = self.storage.read(&path, sync_id).await?;
        Ok(Some(entry))
    }

    async fn update(&self, entry: SyncStateEntry) -> P2Result<()> {
        let sync_id = entry.sync_id.clone();

        // Write encrypted state
        let path = self.state_file_path(&sync_id);
        self.storage.write(&path, &entry, &sync_id).await?;

        // Update index
        {
            let mut cache = self.index_cache.write().await;
            if let Some(index_entry) = cache.get_mut(&sync_id) {
                index_entry.phase = entry.phase;
                index_entry.updated_at = entry.updated_at;
            }
        }

        self.save_index().await?;

        Ok(())
    }

    async fn list_incomplete(&self, limit: usize) -> P2Result<Vec<SyncStateEntry>> {
        let incomplete_ids = {
            let cache = self.index_cache.read().await;

            let mut entries: Vec<_> = cache
                .values()
                .filter(|e| {
                    !matches!(e.phase, SyncPhase::Completed | SyncPhase::Failed)
                })
                .cloned()
                .collect();

            // Sort by updated_at ascending (oldest first for recovery)
            entries.sort_by(|a, b| a.updated_at.cmp(&b.updated_at));
            entries.truncate(limit);
            entries.into_iter().map(|e| e.sync_id).collect::<Vec<_>>()
        };

        let mut results = Vec::new();
        for sync_id in incomplete_ids {
            if let Some(entry) = self.get(&sync_id).await? {
                results.push(entry);
            }
        }

        Ok(results)
    }

    async fn list_by_committer(
        &self,
        committer: &str,
        limit: usize,
    ) -> P2Result<Vec<SyncStateEntry>> {
        let matching_ids = {
            let cache = self.index_cache.read().await;

            let mut entries: Vec<_> = cache
                .values()
                .filter(|e| e.committer == committer)
                .cloned()
                .collect();

            // Sort by created_at descending (most recent first)
            entries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            entries.truncate(limit);
            entries.into_iter().map(|e| e.sync_id).collect::<Vec<_>>()
        };

        let mut results = Vec::new();
        for sync_id in matching_ids {
            if let Some(entry) = self.get(&sync_id).await? {
                results.push(entry);
            }
        }

        Ok(results)
    }

    async fn cleanup(&self, older_than: DateTime<Utc>) -> P2Result<u64> {
        let to_delete = {
            let cache = self.index_cache.read().await;

            cache
                .values()
                .filter(|e| {
                    matches!(e.phase, SyncPhase::Completed) && e.updated_at < older_than
                })
                .map(|e| e.sync_id.clone())
                .collect::<Vec<_>>()
        };

        let mut deleted = 0;
        for sync_id in to_delete {
            let path = self.state_file_path(&sync_id);
            if path.exists() {
                if fs::remove_file(&path).await.is_ok() {
                    deleted += 1;
                }
            }

            let mut cache = self.index_cache.write().await;
            cache.remove(&sync_id);
        }

        self.save_index().await?;

        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_create_and_get() {
        let temp_dir = TempDir::new().unwrap();
        let ledger = FileSyncLedger::unencrypted(temp_dir.path()).await.unwrap();

        let entry = SyncStateEntry::new(
            "sync:test-001".to_string(),
            "committer:alice".to_string(),
            "application/json".to_string(),
        );

        let sync_id = ledger.create(entry).await.unwrap();
        assert_eq!(sync_id, "sync:test-001");

        let retrieved = ledger.get(&sync_id).await.unwrap();
        assert!(retrieved.is_some());

        let entry = retrieved.unwrap();
        assert_eq!(entry.committer, "committer:alice");
        assert_eq!(entry.phase, SyncPhase::Plain);
    }

    #[tokio::test]
    async fn test_update() {
        let temp_dir = TempDir::new().unwrap();
        let ledger = FileSyncLedger::unencrypted(temp_dir.path()).await.unwrap();

        let mut entry = SyncStateEntry::new(
            "sync:test-002".to_string(),
            "committer:bob".to_string(),
            "text/plain".to_string(),
        );
        ledger.create(entry.clone()).await.unwrap();

        // Update phase
        entry.phase = SyncPhase::Encrypted;
        entry.ref_id = Some("ref:abc123".to_string());
        entry.updated_at = Utc::now();
        ledger.update(entry).await.unwrap();

        let retrieved = ledger.get("sync:test-002").await.unwrap().unwrap();
        assert_eq!(retrieved.phase, SyncPhase::Encrypted);
        assert_eq!(retrieved.ref_id, Some("ref:abc123".to_string()));
    }

    #[tokio::test]
    async fn test_list_incomplete() {
        let temp_dir = TempDir::new().unwrap();
        let ledger = FileSyncLedger::unencrypted(temp_dir.path()).await.unwrap();

        // Create one complete and two incomplete
        let mut complete = SyncStateEntry::new(
            "sync:complete".to_string(),
            "committer:alice".to_string(),
            "text/plain".to_string(),
        );
        complete.phase = SyncPhase::Completed;
        ledger.create(complete).await.unwrap();

        let incomplete1 = SyncStateEntry::new(
            "sync:incomplete1".to_string(),
            "committer:alice".to_string(),
            "text/plain".to_string(),
        );
        ledger.create(incomplete1).await.unwrap();

        let mut incomplete2 = SyncStateEntry::new(
            "sync:incomplete2".to_string(),
            "committer:bob".to_string(),
            "text/plain".to_string(),
        );
        incomplete2.phase = SyncPhase::Encrypted;
        ledger.create(incomplete2).await.unwrap();

        let incomplete = ledger.list_incomplete(10).await.unwrap();
        assert_eq!(incomplete.len(), 2);
    }

    #[tokio::test]
    async fn test_list_by_committer() {
        let temp_dir = TempDir::new().unwrap();
        let ledger = FileSyncLedger::unencrypted(temp_dir.path()).await.unwrap();

        for i in 0..3 {
            let entry = SyncStateEntry::new(
                format!("sync:alice-{}", i),
                "committer:alice".to_string(),
                "text/plain".to_string(),
            );
            ledger.create(entry).await.unwrap();
        }

        let entry = SyncStateEntry::new(
            "sync:bob-1".to_string(),
            "committer:bob".to_string(),
            "text/plain".to_string(),
        );
        ledger.create(entry).await.unwrap();

        let alice_syncs = ledger.list_by_committer("committer:alice", 10).await.unwrap();
        assert_eq!(alice_syncs.len(), 3);

        let bob_syncs = ledger.list_by_committer("committer:bob", 10).await.unwrap();
        assert_eq!(bob_syncs.len(), 1);
    }
}
