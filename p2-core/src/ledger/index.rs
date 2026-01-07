//! Ledger Index Module
//!
//! Provides efficient indexing for ledger queries.
//!
//! # Features
//!
//! - **Primary indexes**: Fast lookup by ID
//! - **Secondary indexes**: Query by actor, case, resource, time range
//! - **Composite indexes**: Combined field queries
//! - **Persistence**: Index state survives restarts

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{P2Error, P2Result};

/// Index entry metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexEntry {
    /// Primary key (unique ID)
    pub id: String,
    /// Timestamp for time-based queries
    pub timestamp: DateTime<Utc>,
    /// File path for data retrieval
    pub file_path: PathBuf,
    /// Entry type
    pub entry_type: IndexEntryType,
}

/// Type of indexed entry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IndexEntryType {
    /// R0 skeleton snapshot
    SnapshotR0,
    /// R1 full resurrection snapshot
    SnapshotR1,
    /// Evidence bundle
    EvidenceBundle,
    /// Access ticket
    Ticket,
    /// Decrypt audit log
    AuditDecrypt,
    /// Export audit log
    AuditExport,
    /// Sampling artifact
    AuditSampling,
}

/// Secondary index key types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecondaryKey {
    /// Actor ID index
    ActorId(String),
    /// Case reference index
    CaseRef(String),
    /// Resource/payload reference index
    ResourceRef(String),
    /// Holder (for tickets)
    Holder(String),
    /// Submitter (for evidence)
    Submitter(String),
    /// Batch ID (for sampling)
    BatchId(String),
    /// Status (for filtering)
    Status(String),
}

/// Time-based index using BTreeMap for range queries
#[derive(Debug, Default)]
pub struct TimeIndex {
    /// Entries ordered by timestamp
    entries: BTreeMap<DateTime<Utc>, Vec<String>>,
}

impl TimeIndex {
    /// Create new time index
    pub fn new() -> Self {
        Self::default()
    }

    /// Add entry to time index
    pub fn insert(&mut self, timestamp: DateTime<Utc>, id: String) {
        self.entries.entry(timestamp).or_default().push(id);
    }

    /// Remove entry from time index
    pub fn remove(&mut self, timestamp: DateTime<Utc>, id: &str) {
        if let Some(ids) = self.entries.get_mut(&timestamp) {
            ids.retain(|i| i != id);
            if ids.is_empty() {
                self.entries.remove(&timestamp);
            }
        }
    }

    /// Query entries in time range
    pub fn range(&self, from: DateTime<Utc>, to: DateTime<Utc>) -> Vec<String> {
        self.entries
            .range(from..=to)
            .flat_map(|(_, ids)| ids.iter().cloned())
            .collect()
    }

    /// Get latest N entries
    pub fn latest(&self, limit: usize) -> Vec<String> {
        self.entries
            .iter()
            .rev()
            .flat_map(|(_, ids)| ids.iter().cloned())
            .take(limit)
            .collect()
    }

    /// Get oldest N entries
    pub fn oldest(&self, limit: usize) -> Vec<String> {
        self.entries
            .iter()
            .flat_map(|(_, ids)| ids.iter().cloned())
            .take(limit)
            .collect()
    }
}

/// Secondary index using HashMap
#[derive(Debug, Default)]
pub struct SecondaryIndex {
    /// Key to IDs mapping
    entries: HashMap<SecondaryKey, HashSet<String>>,
}

impl SecondaryIndex {
    /// Create new secondary index
    pub fn new() -> Self {
        Self::default()
    }

    /// Add entry to index
    pub fn insert(&mut self, key: SecondaryKey, id: String) {
        self.entries.entry(key).or_default().insert(id);
    }

    /// Remove entry from index
    pub fn remove(&mut self, key: &SecondaryKey, id: &str) {
        if let Some(ids) = self.entries.get_mut(key) {
            ids.remove(id);
            if ids.is_empty() {
                self.entries.remove(key);
            }
        }
    }

    /// Get all IDs for a key
    pub fn get(&self, key: &SecondaryKey) -> Vec<String> {
        self.entries
            .get(key)
            .map(|ids| ids.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Check if key exists
    pub fn contains_key(&self, key: &SecondaryKey) -> bool {
        self.entries.contains_key(key)
    }

    /// Count entries for a key
    pub fn count(&self, key: &SecondaryKey) -> usize {
        self.entries.get(key).map(|ids| ids.len()).unwrap_or(0)
    }
}

/// Composite index for multi-field queries
#[derive(Debug, Default)]
pub struct CompositeIndex {
    /// (key1, key2) -> IDs
    entries: HashMap<(SecondaryKey, SecondaryKey), HashSet<String>>,
}

impl CompositeIndex {
    /// Create new composite index
    pub fn new() -> Self {
        Self::default()
    }

    /// Add entry to composite index
    pub fn insert(&mut self, key1: SecondaryKey, key2: SecondaryKey, id: String) {
        self.entries.entry((key1, key2)).or_default().insert(id);
    }

    /// Remove entry from composite index
    pub fn remove(&mut self, key1: &SecondaryKey, key2: &SecondaryKey, id: &str) {
        let key = (key1.clone(), key2.clone());
        if let Some(ids) = self.entries.get_mut(&key) {
            ids.remove(id);
            if ids.is_empty() {
                self.entries.remove(&key);
            }
        }
    }

    /// Get all IDs for composite key
    pub fn get(&self, key1: &SecondaryKey, key2: &SecondaryKey) -> Vec<String> {
        let key = (key1.clone(), key2.clone());
        self.entries
            .get(&key)
            .map(|ids| ids.iter().cloned().collect())
            .unwrap_or_default()
    }
}

/// Ledger index manager
pub struct LedgerIndex {
    /// Base path for index files
    base_path: PathBuf,
    /// Primary index (ID -> entry)
    primary: RwLock<HashMap<String, IndexEntry>>,
    /// Secondary indexes
    secondary: RwLock<SecondaryIndex>,
    /// Time-based index
    time_index: RwLock<TimeIndex>,
    /// Composite indexes
    composite: RwLock<CompositeIndex>,
    /// Type-specific indexes
    type_index: RwLock<HashMap<IndexEntryType, HashSet<String>>>,
    /// Dirty flag for persistence
    dirty: RwLock<bool>,
}

impl LedgerIndex {
    /// Create new ledger index
    pub fn new(base_path: PathBuf) -> Self {
        Self {
            base_path,
            primary: RwLock::new(HashMap::new()),
            secondary: RwLock::new(SecondaryIndex::new()),
            time_index: RwLock::new(TimeIndex::new()),
            composite: RwLock::new(CompositeIndex::new()),
            type_index: RwLock::new(HashMap::new()),
            dirty: RwLock::new(false),
        }
    }

    /// Load index from disk
    pub async fn load(&self) -> P2Result<()> {
        let index_file = self.base_path.join("ledger_index.json");

        if !index_file.exists() {
            return Ok(());
        }

        let content = tokio::fs::read_to_string(&index_file).await
            .map_err(|e| P2Error::Storage(format!("Failed to read index: {}", e)))?;

        let state: IndexState = serde_json::from_str(&content)
            .map_err(|e| P2Error::Storage(format!("Failed to parse index: {}", e)))?;

        // Restore primary index
        let mut primary = self.primary.write().await;
        for entry in state.entries {
            primary.insert(entry.id.clone(), entry);
        }

        // Rebuild secondary indexes from primary
        drop(primary);
        self.rebuild_secondary_indexes().await?;

        Ok(())
    }

    /// Save index to disk
    pub async fn save(&self) -> P2Result<()> {
        let mut dirty = self.dirty.write().await;
        if !*dirty {
            return Ok(());
        }

        let primary = self.primary.read().await;
        let entries: Vec<IndexEntry> = primary.values().cloned().collect();

        let state = IndexState {
            version: 1,
            entries,
            updated_at: Utc::now(),
        };

        let content = serde_json::to_string_pretty(&state)
            .map_err(|e| P2Error::Storage(format!("Failed to serialize index: {}", e)))?;

        let index_file = self.base_path.join("ledger_index.json");
        tokio::fs::write(&index_file, content).await
            .map_err(|e| P2Error::Storage(format!("Failed to write index: {}", e)))?;

        *dirty = false;
        Ok(())
    }

    /// Add entry to index
    pub async fn add(
        &self,
        entry: IndexEntry,
        secondary_keys: Vec<SecondaryKey>,
    ) -> P2Result<()> {
        let id = entry.id.clone();
        let timestamp = entry.timestamp;
        let entry_type = entry.entry_type;

        // Primary index
        {
            let mut primary = self.primary.write().await;
            primary.insert(id.clone(), entry);
        }

        // Secondary indexes
        {
            let mut secondary = self.secondary.write().await;
            for key in secondary_keys {
                secondary.insert(key, id.clone());
            }
        }

        // Time index
        {
            let mut time = self.time_index.write().await;
            time.insert(timestamp, id.clone());
        }

        // Type index
        {
            let mut types = self.type_index.write().await;
            types.entry(entry_type).or_default().insert(id);
        }

        *self.dirty.write().await = true;
        Ok(())
    }

    /// Remove entry from index
    pub async fn remove(&self, id: &str) -> P2Result<Option<IndexEntry>> {
        // Remove from primary
        let entry = {
            let mut primary = self.primary.write().await;
            primary.remove(id)
        };

        if let Some(ref entry) = entry {
            // Remove from time index
            {
                let mut time = self.time_index.write().await;
                time.remove(entry.timestamp, id);
            }

            // Remove from type index
            {
                let mut types = self.type_index.write().await;
                if let Some(ids) = types.get_mut(&entry.entry_type) {
                    ids.remove(id);
                }
            }

            *self.dirty.write().await = true;
        }

        Ok(entry)
    }

    /// Get entry by ID
    pub async fn get(&self, id: &str) -> Option<IndexEntry> {
        self.primary.read().await.get(id).cloned()
    }

    /// Query by secondary key
    pub async fn query_by_key(&self, key: &SecondaryKey) -> Vec<IndexEntry> {
        let ids = self.secondary.read().await.get(key);
        let primary = self.primary.read().await;

        ids.into_iter()
            .filter_map(|id| primary.get(&id).cloned())
            .collect()
    }

    /// Query by time range
    pub async fn query_by_time(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Vec<IndexEntry> {
        let ids = self.time_index.read().await.range(from, to);
        let primary = self.primary.read().await;

        ids.into_iter()
            .filter_map(|id| primary.get(&id).cloned())
            .collect()
    }

    /// Query by type
    pub async fn query_by_type(
        &self,
        entry_type: IndexEntryType,
        limit: usize,
    ) -> Vec<IndexEntry> {
        let ids: Vec<String> = {
            let types = self.type_index.read().await;
            types
                .get(&entry_type)
                .map(|ids| ids.iter().take(limit).cloned().collect())
                .unwrap_or_default()
        };

        let primary = self.primary.read().await;
        ids.into_iter()
            .filter_map(|id| primary.get(&id).cloned())
            .collect()
    }

    /// Get latest entries by type
    pub async fn latest_by_type(
        &self,
        entry_type: IndexEntryType,
        limit: usize,
    ) -> Vec<IndexEntry> {
        let type_ids: HashSet<String> = {
            let types = self.type_index.read().await;
            types
                .get(&entry_type)
                .cloned()
                .unwrap_or_default()
        };

        let latest_ids = self.time_index.read().await.latest(limit * 2);
        let primary = self.primary.read().await;

        latest_ids
            .into_iter()
            .filter(|id| type_ids.contains(id))
            .take(limit)
            .filter_map(|id| primary.get(&id).cloned())
            .collect()
    }

    /// Rebuild secondary indexes from primary
    async fn rebuild_secondary_indexes(&self) -> P2Result<()> {
        let primary = self.primary.read().await;
        let mut secondary = self.secondary.write().await;
        let mut time = self.time_index.write().await;
        let mut types = self.type_index.write().await;

        *secondary = SecondaryIndex::new();
        *time = TimeIndex::new();
        *types = HashMap::new();

        for (id, entry) in primary.iter() {
            time.insert(entry.timestamp, id.clone());
            types.entry(entry.entry_type).or_default().insert(id.clone());
        }

        Ok(())
    }

    /// Count entries by type
    pub async fn count_by_type(&self, entry_type: IndexEntryType) -> usize {
        self.type_index
            .read()
            .await
            .get(&entry_type)
            .map(|ids| ids.len())
            .unwrap_or(0)
    }

    /// Get total entry count
    pub async fn total_count(&self) -> usize {
        self.primary.read().await.len()
    }

    /// Get index statistics
    pub async fn stats(&self) -> IndexStats {
        let primary = self.primary.read().await;
        let types = self.type_index.read().await;

        let mut type_counts = HashMap::new();
        for (entry_type, ids) in types.iter() {
            type_counts.insert(*entry_type, ids.len());
        }

        IndexStats {
            total_entries: primary.len(),
            type_counts,
        }
    }
}

/// Serializable index state
#[derive(Debug, Serialize, Deserialize)]
struct IndexState {
    version: u32,
    entries: Vec<IndexEntry>,
    updated_at: DateTime<Utc>,
}

/// Index statistics
#[derive(Debug, Clone)]
pub struct IndexStats {
    /// Total number of entries
    pub total_entries: usize,
    /// Counts by entry type
    pub type_counts: HashMap<IndexEntryType, usize>,
}

/// Index builder for batch operations
pub struct IndexBuilder {
    entries: Vec<(IndexEntry, Vec<SecondaryKey>)>,
}

impl IndexBuilder {
    /// Create new index builder
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add entry to builder
    pub fn add(mut self, entry: IndexEntry, secondary_keys: Vec<SecondaryKey>) -> Self {
        self.entries.push((entry, secondary_keys));
        self
    }

    /// Build and apply to index
    pub async fn apply(self, index: &LedgerIndex) -> P2Result<usize> {
        let count = self.entries.len();
        for (entry, keys) in self.entries {
            index.add(entry, keys).await?;
        }
        Ok(count)
    }
}

impl Default for IndexBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_time_index() {
        let mut index = TimeIndex::new();
        let now = Utc::now();
        let earlier = now - chrono::Duration::hours(1);
        let later = now + chrono::Duration::hours(1);

        index.insert(now, "id1".to_string());
        index.insert(earlier, "id2".to_string());
        index.insert(later, "id3".to_string());

        let range = index.range(earlier, later);
        assert_eq!(range.len(), 3);

        let latest = index.latest(2);
        assert!(latest.contains(&"id3".to_string()));
    }

    #[test]
    fn test_secondary_index() {
        let mut index = SecondaryIndex::new();

        let key1 = SecondaryKey::ActorId("actor1".to_string());
        let key2 = SecondaryKey::CaseRef("case1".to_string());

        index.insert(key1.clone(), "id1".to_string());
        index.insert(key1.clone(), "id2".to_string());
        index.insert(key2.clone(), "id3".to_string());

        assert_eq!(index.get(&key1).len(), 2);
        assert_eq!(index.get(&key2).len(), 1);
        assert_eq!(index.count(&key1), 2);
    }

    #[tokio::test]
    async fn test_ledger_index() {
        let temp_dir = TempDir::new().unwrap();
        let index = LedgerIndex::new(temp_dir.path().to_path_buf());

        let entry = IndexEntry {
            id: "test-001".to_string(),
            timestamp: Utc::now(),
            file_path: PathBuf::from("test.json"),
            entry_type: IndexEntryType::Ticket,
        };

        let keys = vec![
            SecondaryKey::ActorId("actor1".to_string()),
            SecondaryKey::ResourceRef("payload1".to_string()),
        ];

        index.add(entry, keys).await.unwrap();

        let result = index.get("test-001").await;
        assert!(result.is_some());

        let by_actor = index.query_by_key(&SecondaryKey::ActorId("actor1".to_string())).await;
        assert_eq!(by_actor.len(), 1);
    }

    #[tokio::test]
    async fn test_index_persistence() {
        let temp_dir = TempDir::new().unwrap();

        // Create and populate index
        {
            let index = LedgerIndex::new(temp_dir.path().to_path_buf());

            let entry = IndexEntry {
                id: "persist-001".to_string(),
                timestamp: Utc::now(),
                file_path: PathBuf::from("test.json"),
                entry_type: IndexEntryType::EvidenceBundle,
            };

            index.add(entry, vec![]).await.unwrap();
            index.save().await.unwrap();
        }

        // Reload and verify
        {
            let index = LedgerIndex::new(temp_dir.path().to_path_buf());
            index.load().await.unwrap();

            let result = index.get("persist-001").await;
            assert!(result.is_some());
        }
    }
}
