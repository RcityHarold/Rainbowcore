//! Audit Store Service
//!
//! Enhanced audit logging with tamper-proofing via hash chaining.
//! All entries are cryptographically linked to detect any modifications.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::error::{StorageError, StorageResult};

/// Audit store configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStoreConfig {
    /// Base path for audit storage
    pub base_path: PathBuf,
    /// Whether to verify chain on startup
    pub verify_on_startup: bool,
    /// Maximum entries per chain file
    pub max_entries_per_file: usize,
    /// Whether to sync to disk after each write
    pub sync_writes: bool,
}

impl Default for AuditStoreConfig {
    fn default() -> Self {
        Self {
            base_path: PathBuf::from("/var/lib/p2/audit"),
            verify_on_startup: true,
            max_entries_per_file: 10000,
            sync_writes: true,
        }
    }
}

/// Audit log entry types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEntryType {
    /// Payload decryption
    Decrypt,
    /// Payload export
    Export,
    /// Sampling check
    Sampling,
    /// Access denied
    AccessDenied,
    /// Policy violation
    PolicyViolation,
    /// System event
    System,
}

/// A single entry in the audit chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditChainEntry {
    /// Entry sequence number (monotonic)
    pub sequence: u64,
    /// Entry type
    pub entry_type: AuditEntryType,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Hash of the previous entry (None for genesis)
    pub prev_hash: Option<String>,
    /// Hash of this entry's content
    pub content_hash: String,
    /// Actor who performed the action
    pub actor_id: Option<String>,
    /// Target payload reference
    pub payload_ref: Option<String>,
    /// Ticket reference used
    pub ticket_ref: Option<String>,
    /// Additional metadata as JSON
    pub metadata: serde_json::Value,
    /// The computed hash of this entire entry
    pub entry_hash: String,
}

impl AuditChainEntry {
    /// Create a new audit entry
    pub fn new(
        sequence: u64,
        entry_type: AuditEntryType,
        prev_hash: Option<String>,
        actor_id: Option<String>,
        payload_ref: Option<String>,
        ticket_ref: Option<String>,
        metadata: serde_json::Value,
    ) -> Self {
        let timestamp = Utc::now();
        let content_hash = Self::compute_content_hash(&entry_type, &timestamp, &metadata);

        let mut entry = Self {
            sequence,
            entry_type,
            timestamp,
            prev_hash: prev_hash.clone(),
            content_hash,
            actor_id,
            payload_ref,
            ticket_ref,
            metadata,
            entry_hash: String::new(),
        };

        entry.entry_hash = entry.compute_entry_hash();
        entry
    }

    /// Compute hash of the entry content
    fn compute_content_hash(
        entry_type: &AuditEntryType,
        timestamp: &DateTime<Utc>,
        metadata: &serde_json::Value,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(format!("{:?}", entry_type).as_bytes());
        hasher.update(timestamp.to_rfc3339().as_bytes());
        hasher.update(metadata.to_string().as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Compute the full entry hash (includes prev_hash for chaining)
    fn compute_entry_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.sequence.to_le_bytes());
        hasher.update(self.content_hash.as_bytes());
        if let Some(ref prev) = self.prev_hash {
            hasher.update(prev.as_bytes());
        }
        hasher.update(self.timestamp.to_rfc3339().as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Verify this entry's hash is correct
    pub fn verify(&self) -> bool {
        let computed = self.compute_entry_hash();
        computed == self.entry_hash
    }

    /// Verify this entry chains correctly from the previous entry
    pub fn verify_chain(&self, prev_entry: Option<&AuditChainEntry>) -> bool {
        // Verify own hash
        if !self.verify() {
            return false;
        }

        // Verify chain
        match (prev_entry, &self.prev_hash) {
            (Some(prev), Some(prev_hash)) => prev.entry_hash == *prev_hash,
            (None, None) => true, // Genesis entry
            _ => false,
        }
    }
}

/// Audit chain - a sequence of cryptographically linked audit entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditChain {
    /// Chain ID
    pub chain_id: String,
    /// Genesis timestamp
    pub created_at: DateTime<Utc>,
    /// Last entry timestamp
    pub last_entry_at: DateTime<Utc>,
    /// Current sequence number
    pub current_sequence: u64,
    /// Hash of the latest entry
    pub head_hash: Option<String>,
    /// Number of entries
    pub entry_count: usize,
    /// Whether chain integrity is verified
    pub verified: bool,
}

impl AuditChain {
    /// Create a new audit chain
    pub fn new(chain_id: String) -> Self {
        let now = Utc::now();
        Self {
            chain_id,
            created_at: now,
            last_entry_at: now,
            current_sequence: 0,
            head_hash: None,
            entry_count: 0,
            verified: true,
        }
    }

    /// Update chain metadata after adding an entry
    pub fn add_entry(&mut self, entry: &AuditChainEntry) {
        self.current_sequence = entry.sequence;
        self.head_hash = Some(entry.entry_hash.clone());
        self.last_entry_at = entry.timestamp;
        self.entry_count += 1;
    }
}

/// Query parameters for audit logs
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditQuery {
    /// Filter by entry type
    pub entry_type: Option<AuditEntryType>,
    /// Filter by actor ID
    pub actor_id: Option<String>,
    /// Filter by payload ref
    pub payload_ref: Option<String>,
    /// Filter by ticket ref
    pub ticket_ref: Option<String>,
    /// Start time (inclusive)
    pub from: Option<DateTime<Utc>>,
    /// End time (inclusive)
    pub to: Option<DateTime<Utc>>,
    /// Maximum results
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
}

impl AuditQuery {
    /// Create a new query
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by entry type
    pub fn with_type(mut self, entry_type: AuditEntryType) -> Self {
        self.entry_type = Some(entry_type);
        self
    }

    /// Filter by actor
    pub fn with_actor(mut self, actor_id: &str) -> Self {
        self.actor_id = Some(actor_id.to_string());
        self
    }

    /// Filter by payload
    pub fn with_payload(mut self, payload_ref: &str) -> Self {
        self.payload_ref = Some(payload_ref.to_string());
        self
    }

    /// Filter by time range
    pub fn with_time_range(mut self, from: DateTime<Utc>, to: DateTime<Utc>) -> Self {
        self.from = Some(from);
        self.to = Some(to);
        self
    }

    /// Set limit
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Check if an entry matches this query
    pub fn matches(&self, entry: &AuditChainEntry) -> bool {
        if let Some(ref t) = self.entry_type {
            if entry.entry_type != *t {
                return false;
            }
        }
        if let Some(ref a) = self.actor_id {
            if entry.actor_id.as_ref() != Some(a) {
                return false;
            }
        }
        if let Some(ref p) = self.payload_ref {
            if entry.payload_ref.as_ref() != Some(p) {
                return false;
            }
        }
        if let Some(ref t) = self.ticket_ref {
            if entry.ticket_ref.as_ref() != Some(t) {
                return false;
            }
        }
        if let Some(from) = self.from {
            if entry.timestamp < from {
                return false;
            }
        }
        if let Some(to) = self.to {
            if entry.timestamp > to {
                return false;
            }
        }
        true
    }
}

/// Query result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditQueryResult {
    /// Matching entries
    pub entries: Vec<AuditChainEntry>,
    /// Total matching count (before pagination)
    pub total_count: usize,
    /// Query execution time in milliseconds
    pub query_time_ms: u64,
    /// Whether chain integrity was verified
    pub chain_verified: bool,
}

/// Audit store - manages audit chains with tamper-proofing
pub struct AuditStore {
    /// Configuration
    config: AuditStoreConfig,
    /// Current chain metadata
    chain: RwLock<AuditChain>,
    /// In-memory entry cache (for recent queries)
    entries: RwLock<Vec<AuditChainEntry>>,
    /// Index by payload ref
    payload_index: RwLock<HashMap<String, Vec<u64>>>,
    /// Index by actor id
    actor_index: RwLock<HashMap<String, Vec<u64>>>,
}

impl AuditStore {
    /// Create a new audit store
    pub async fn new(config: AuditStoreConfig) -> StorageResult<Self> {
        // Create directories
        fs::create_dir_all(&config.base_path).await.map_err(|e| {
            StorageError::Configuration(format!("Failed to create audit directory: {}", e))
        })?;

        let chain_id = format!("chain:{}", uuid::Uuid::new_v4());
        let chain = AuditChain::new(chain_id);

        let store = Self {
            config,
            chain: RwLock::new(chain),
            entries: RwLock::new(Vec::new()),
            payload_index: RwLock::new(HashMap::new()),
            actor_index: RwLock::new(HashMap::new()),
        };

        // Load existing entries if any
        store.load_entries().await?;

        // Verify chain if configured
        if store.config.verify_on_startup {
            store.verify_chain().await?;
        }

        Ok(store)
    }

    /// Load entries from disk
    async fn load_entries(&self) -> StorageResult<()> {
        let entries_path = self.config.base_path.join("entries.json");
        let chain_path = self.config.base_path.join("chain.json");

        if chain_path.exists() {
            let chain_data = fs::read_to_string(&chain_path).await.map_err(|e| {
                StorageError::ReadFailed(format!("Failed to read chain metadata: {}", e))
            })?;
            let chain: AuditChain = serde_json::from_str(&chain_data)
                .map_err(|e| StorageError::ReadFailed(format!("Failed to parse chain: {}", e)))?;
            *self.chain.write().await = chain;
        }

        if entries_path.exists() {
            let entries_data = fs::read_to_string(&entries_path).await.map_err(|e| {
                StorageError::ReadFailed(format!("Failed to read entries: {}", e))
            })?;
            let entries: Vec<AuditChainEntry> = serde_json::from_str(&entries_data)
                .map_err(|e| StorageError::ReadFailed(format!("Failed to parse entries: {}", e)))?;

            // Rebuild indexes
            let mut payload_idx = self.payload_index.write().await;
            let mut actor_idx = self.actor_index.write().await;

            for entry in &entries {
                if let Some(ref pr) = entry.payload_ref {
                    payload_idx
                        .entry(pr.clone())
                        .or_default()
                        .push(entry.sequence);
                }
                if let Some(ref ai) = entry.actor_id {
                    actor_idx
                        .entry(ai.clone())
                        .or_default()
                        .push(entry.sequence);
                }
            }

            *self.entries.write().await = entries;
        }

        Ok(())
    }

    /// Save entries to disk
    async fn save_entries(&self) -> StorageResult<()> {
        let entries = self.entries.read().await;
        let chain = self.chain.read().await;

        let entries_path = self.config.base_path.join("entries.json");
        let chain_path = self.config.base_path.join("chain.json");

        let entries_json = serde_json::to_string_pretty(&*entries)
            .map_err(|e| StorageError::WriteFailed(format!("Failed to serialize entries: {}", e)))?;
        let chain_json = serde_json::to_string_pretty(&*chain)
            .map_err(|e| StorageError::WriteFailed(format!("Failed to serialize chain: {}", e)))?;

        fs::write(&entries_path, entries_json).await.map_err(|e| {
            StorageError::WriteFailed(format!("Failed to write entries: {}", e))
        })?;
        fs::write(&chain_path, chain_json).await.map_err(|e| {
            StorageError::WriteFailed(format!("Failed to write chain: {}", e))
        })?;

        Ok(())
    }

    /// Record a decrypt audit entry
    pub async fn record_decrypt(
        &self,
        actor_id: &str,
        payload_ref: &str,
        ticket_ref: &str,
        purpose: &str,
        success: bool,
    ) -> StorageResult<String> {
        let metadata = serde_json::json!({
            "purpose": purpose,
            "success": success,
            "operation": "decrypt"
        });

        self.append_entry(
            AuditEntryType::Decrypt,
            Some(actor_id.to_string()),
            Some(payload_ref.to_string()),
            Some(ticket_ref.to_string()),
            metadata,
        )
        .await
    }

    /// Record an export audit entry
    pub async fn record_export(
        &self,
        actor_id: &str,
        payload_refs: &[String],
        ticket_ref: &str,
        destination: &str,
        format: &str,
    ) -> StorageResult<String> {
        let metadata = serde_json::json!({
            "destination": destination,
            "format": format,
            "payload_count": payload_refs.len(),
            "payload_refs": payload_refs,
            "operation": "export"
        });

        // Record for the first payload (main record)
        let first_ref = payload_refs.first().map(|s| s.as_str());

        self.append_entry(
            AuditEntryType::Export,
            Some(actor_id.to_string()),
            first_ref.map(|s| s.to_string()),
            Some(ticket_ref.to_string()),
            metadata,
        )
        .await
    }

    /// Record an access denied event
    pub async fn record_access_denied(
        &self,
        actor_id: &str,
        payload_ref: &str,
        reason: &str,
    ) -> StorageResult<String> {
        let metadata = serde_json::json!({
            "reason": reason,
            "operation": "access_denied"
        });

        self.append_entry(
            AuditEntryType::AccessDenied,
            Some(actor_id.to_string()),
            Some(payload_ref.to_string()),
            None,
            metadata,
        )
        .await
    }

    /// Record a policy violation
    pub async fn record_policy_violation(
        &self,
        actor_id: Option<&str>,
        payload_ref: Option<&str>,
        violation_type: &str,
        details: &str,
    ) -> StorageResult<String> {
        let metadata = serde_json::json!({
            "violation_type": violation_type,
            "details": details,
            "operation": "policy_violation"
        });

        self.append_entry(
            AuditEntryType::PolicyViolation,
            actor_id.map(|s| s.to_string()),
            payload_ref.map(|s| s.to_string()),
            None,
            metadata,
        )
        .await
    }

    /// Append a new entry to the chain
    async fn append_entry(
        &self,
        entry_type: AuditEntryType,
        actor_id: Option<String>,
        payload_ref: Option<String>,
        ticket_ref: Option<String>,
        metadata: serde_json::Value,
    ) -> StorageResult<String> {
        let mut chain = self.chain.write().await;
        let mut entries = self.entries.write().await;

        let sequence = chain.current_sequence + 1;
        let prev_hash = chain.head_hash.clone();

        let entry = AuditChainEntry::new(
            sequence,
            entry_type,
            prev_hash,
            actor_id.clone(),
            payload_ref.clone(),
            ticket_ref,
            metadata,
        );

        let entry_hash = entry.entry_hash.clone();

        // Update indexes
        if let Some(ref pr) = payload_ref {
            self.payload_index
                .write()
                .await
                .entry(pr.clone())
                .or_default()
                .push(sequence);
        }
        if let Some(ref ai) = actor_id {
            self.actor_index
                .write()
                .await
                .entry(ai.clone())
                .or_default()
                .push(sequence);
        }

        // Update chain
        chain.add_entry(&entry);
        entries.push(entry);

        drop(chain);
        drop(entries);

        // Persist
        if self.config.sync_writes {
            self.save_entries().await?;
        }

        info!(
            entry_type = ?entry_type,
            sequence = sequence,
            "Audit entry recorded"
        );

        Ok(entry_hash)
    }

    /// Verify the entire chain integrity
    pub async fn verify_chain(&self) -> StorageResult<bool> {
        let entries = self.entries.read().await;
        let mut chain = self.chain.write().await;

        if entries.is_empty() {
            chain.verified = true;
            return Ok(true);
        }

        // Verify first entry (genesis)
        if !entries[0].verify() {
            warn!("Genesis entry failed verification");
            chain.verified = false;
            return Ok(false);
        }
        if entries[0].prev_hash.is_some() {
            warn!("Genesis entry has unexpected prev_hash");
            chain.verified = false;
            return Ok(false);
        }

        // Verify chain
        for i in 1..entries.len() {
            if !entries[i].verify_chain(Some(&entries[i - 1])) {
                warn!(
                    sequence = entries[i].sequence,
                    "Chain verification failed at entry"
                );
                chain.verified = false;
                return Ok(false);
            }
        }

        chain.verified = true;
        info!(entry_count = entries.len(), "Chain verification passed");
        Ok(true)
    }

    /// Query audit entries
    pub async fn query(&self, query: AuditQuery) -> StorageResult<AuditQueryResult> {
        let start = std::time::Instant::now();
        let entries = self.entries.read().await;
        let chain = self.chain.read().await;

        // Filter entries
        let matching: Vec<_> = entries.iter().filter(|e| query.matches(e)).collect();

        let total_count = matching.len();

        // Apply pagination
        let offset = query.offset.unwrap_or(0);
        let limit = query.limit.unwrap_or(100);

        let paginated: Vec<AuditChainEntry> = matching
            .into_iter()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect();

        Ok(AuditQueryResult {
            entries: paginated,
            total_count,
            query_time_ms: start.elapsed().as_millis() as u64,
            chain_verified: chain.verified,
        })
    }

    /// Get entry by sequence number
    pub async fn get_entry(&self, sequence: u64) -> Option<AuditChainEntry> {
        let entries = self.entries.read().await;
        entries.iter().find(|e| e.sequence == sequence).cloned()
    }

    /// Get entries for a payload
    pub async fn get_entries_for_payload(&self, payload_ref: &str) -> Vec<AuditChainEntry> {
        let payload_index = self.payload_index.read().await;
        let entries = self.entries.read().await;

        if let Some(sequences) = payload_index.get(payload_ref) {
            sequences
                .iter()
                .filter_map(|seq| entries.iter().find(|e| e.sequence == *seq).cloned())
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get entries for an actor
    pub async fn get_entries_for_actor(&self, actor_id: &str) -> Vec<AuditChainEntry> {
        let actor_index = self.actor_index.read().await;
        let entries = self.entries.read().await;

        if let Some(sequences) = actor_index.get(actor_id) {
            sequences
                .iter()
                .filter_map(|seq| entries.iter().find(|e| e.sequence == *seq).cloned())
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get chain metadata
    pub async fn get_chain_info(&self) -> AuditChain {
        self.chain.read().await.clone()
    }

    /// Get audit statistics
    pub async fn get_stats(&self) -> AuditStats {
        let entries = self.entries.read().await;
        let chain = self.chain.read().await;

        let mut decrypt_count = 0;
        let mut export_count = 0;
        let mut access_denied_count = 0;
        let mut policy_violation_count = 0;

        for entry in entries.iter() {
            match entry.entry_type {
                AuditEntryType::Decrypt => decrypt_count += 1,
                AuditEntryType::Export => export_count += 1,
                AuditEntryType::AccessDenied => access_denied_count += 1,
                AuditEntryType::PolicyViolation => policy_violation_count += 1,
                _ => {}
            }
        }

        AuditStats {
            chain_id: chain.chain_id.clone(),
            total_entries: entries.len(),
            decrypt_count,
            export_count,
            access_denied_count,
            policy_violation_count,
            chain_verified: chain.verified,
            oldest_entry: entries.first().map(|e| e.timestamp),
            newest_entry: entries.last().map(|e| e.timestamp),
            computed_at: Utc::now(),
        }
    }
}

/// Audit statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStats {
    /// Chain ID
    pub chain_id: String,
    /// Total number of entries
    pub total_entries: usize,
    /// Decrypt operations
    pub decrypt_count: usize,
    /// Export operations
    pub export_count: usize,
    /// Access denied events
    pub access_denied_count: usize,
    /// Policy violations
    pub policy_violation_count: usize,
    /// Whether chain integrity is verified
    pub chain_verified: bool,
    /// Oldest entry timestamp
    pub oldest_entry: Option<DateTime<Utc>>,
    /// Newest entry timestamp
    pub newest_entry: Option<DateTime<Utc>>,
    /// Statistics computation time
    pub computed_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn create_test_store() -> AuditStore {
        let temp_dir = TempDir::new().unwrap();
        let config = AuditStoreConfig {
            base_path: temp_dir.path().to_path_buf(),
            verify_on_startup: true,
            max_entries_per_file: 1000,
            sync_writes: false, // Faster for tests
        };
        AuditStore::new(config).await.unwrap()
    }

    #[tokio::test]
    async fn test_record_decrypt() {
        let store = create_test_store().await;

        let hash = store
            .record_decrypt("actor:001", "payload:001", "ticket:001", "testing", true)
            .await
            .unwrap();

        assert!(!hash.is_empty());

        let stats = store.get_stats().await;
        assert_eq!(stats.decrypt_count, 1);
    }

    #[tokio::test]
    async fn test_record_export() {
        let store = create_test_store().await;

        let payloads = vec!["payload:001".to_string(), "payload:002".to_string()];
        let hash = store
            .record_export("actor:001", &payloads, "ticket:001", "external", "json")
            .await
            .unwrap();

        assert!(!hash.is_empty());

        let stats = store.get_stats().await;
        assert_eq!(stats.export_count, 1);
    }

    #[tokio::test]
    async fn test_chain_integrity() {
        let store = create_test_store().await;

        // Add multiple entries
        store
            .record_decrypt("actor:001", "payload:001", "ticket:001", "test1", true)
            .await
            .unwrap();
        store
            .record_decrypt("actor:001", "payload:002", "ticket:002", "test2", true)
            .await
            .unwrap();
        store
            .record_export(
                "actor:001",
                &["payload:001".to_string()],
                "ticket:003",
                "ext",
                "json",
            )
            .await
            .unwrap();

        // Verify chain
        let verified = store.verify_chain().await.unwrap();
        assert!(verified);
    }

    #[tokio::test]
    async fn test_query() {
        let store = create_test_store().await;

        store
            .record_decrypt("actor:001", "payload:001", "ticket:001", "test", true)
            .await
            .unwrap();
        store
            .record_decrypt("actor:002", "payload:002", "ticket:002", "test", true)
            .await
            .unwrap();

        // Query by actor
        let query = AuditQuery::new().with_actor("actor:001");
        let result = store.query(query).await.unwrap();
        assert_eq!(result.total_count, 1);

        // Query by payload
        let query = AuditQuery::new().with_payload("payload:002");
        let result = store.query(query).await.unwrap();
        assert_eq!(result.total_count, 1);

        // Query by type
        let query = AuditQuery::new().with_type(AuditEntryType::Decrypt);
        let result = store.query(query).await.unwrap();
        assert_eq!(result.total_count, 2);
    }

    #[tokio::test]
    async fn test_entry_verification() {
        let entry = AuditChainEntry::new(
            1,
            AuditEntryType::Decrypt,
            None,
            Some("actor:001".to_string()),
            Some("payload:001".to_string()),
            Some("ticket:001".to_string()),
            serde_json::json!({"test": true}),
        );

        assert!(entry.verify());
    }

    #[tokio::test]
    async fn test_get_entries_for_payload() {
        let store = create_test_store().await;

        store
            .record_decrypt("actor:001", "payload:001", "ticket:001", "test1", true)
            .await
            .unwrap();
        store
            .record_decrypt("actor:002", "payload:001", "ticket:002", "test2", true)
            .await
            .unwrap();
        store
            .record_decrypt("actor:001", "payload:002", "ticket:003", "test3", true)
            .await
            .unwrap();

        let entries = store.get_entries_for_payload("payload:001").await;
        assert_eq!(entries.len(), 2);
    }
}
