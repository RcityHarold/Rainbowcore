//! Write-Ahead Log (WAL) Module
//!
//! Provides crash recovery and durability guarantees for ledger operations.
//!
//! # Design
//!
//! - All mutations are first written to WAL before applying to main storage
//! - WAL entries are sequentially numbered with LSN (Log Sequence Number)
//! - WAL data is encrypted at rest using envelope encryption
//! - Periodic checkpoints allow WAL truncation
//! - Recovery replays uncommitted entries after crash
//!
//! # Security
//!
//! - WAL entries are encrypted using XChaCha20-Poly1305 via EnvelopeEncryption
//! - Only the `data` field is encrypted (metadata remains readable for recovery)
//! - KEK reference is stored in WalConfig for key management
//!
//! # Usage
//!
//! ```ignore
//! let wal = WriteAheadLog::open("/path/to/wal").await?;
//!
//! // Write entry before mutation
//! let lsn = wal.append(WalEntry::new(Operation::CreateBundle, &data)).await?;
//!
//! // Apply mutation to main storage
//! storage.create_bundle(bundle).await?;
//!
//! // Mark entry as committed
//! wal.commit(lsn).await?;
//! ```

use std::collections::HashMap;
use std::path::PathBuf;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::RwLock;

use crate::crypto::EnvelopeEncryption;
use crate::error::{P2Error, P2Result};

/// Log Sequence Number - monotonically increasing identifier
pub type LSN = u64;

/// WAL operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalOperation {
    /// Create a new entry
    Create,
    /// Update existing entry
    Update,
    /// Delete entry (tombstone)
    Delete,
    /// Checkpoint marker
    Checkpoint,
    /// Transaction begin
    BeginTx,
    /// Transaction commit
    CommitTx,
    /// Transaction rollback
    RollbackTx,
}

/// WAL entry target type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalTarget {
    /// Snapshot ledger
    Snapshot,
    /// Evidence ledger
    Evidence,
    /// Ticket ledger
    Ticket,
    /// Audit ledger
    Audit,
    /// Index
    Index,
}

/// WAL entry status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalEntryStatus {
    /// Entry written but not committed
    Pending,
    /// Entry committed successfully
    Committed,
    /// Entry rolled back
    RolledBack,
    /// Entry is a checkpoint
    Checkpoint,
}

/// A single WAL entry
///
/// # Security
///
/// All WAL entry data is encrypted at rest except for:
/// - Checkpoint entries (contain only LSN, no sensitive data)
/// - Entries created in test mode with encryption disabled
///
/// Production deployments MUST use encrypted WAL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalEntry {
    /// Log Sequence Number
    pub lsn: LSN,
    /// Operation type
    pub operation: WalOperation,
    /// Target ledger type
    pub target: WalTarget,
    /// Entry ID being modified
    pub entry_id: String,
    /// Serialized data (encrypted when encryption is enabled)
    pub data: String,
    /// Whether data is encrypted (must be true in production for non-checkpoint entries)
    #[serde(default)]
    pub encrypted: bool,
    /// Entry status
    pub status: WalEntryStatus,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Optional transaction ID
    pub tx_id: Option<String>,
    /// Checksum for integrity
    pub checksum: String,
}

impl WalEntry {
    /// Create a new WAL entry (unencrypted - will be encrypted when written)
    pub fn new(
        lsn: LSN,
        operation: WalOperation,
        target: WalTarget,
        entry_id: String,
        data: impl Serialize,
    ) -> P2Result<Self> {
        let data_json = serde_json::to_string(&data)
            .map_err(|e| P2Error::Serialization(format!("Failed to serialize WAL data: {}", e)))?;

        let checksum = Self::compute_checksum(lsn, &operation, &target, &entry_id, &data_json, false);

        Ok(Self {
            lsn,
            operation,
            target,
            entry_id,
            data: data_json,
            encrypted: false,
            status: WalEntryStatus::Pending,
            timestamp: Utc::now(),
            tx_id: None,
            checksum,
        })
    }

    /// Create a checkpoint entry (checkpoints are not encrypted)
    pub fn checkpoint(lsn: LSN, last_committed_lsn: LSN) -> Self {
        let data = format!("{{\"last_committed_lsn\":{}}}", last_committed_lsn);
        let checksum = Self::compute_checksum(
            lsn,
            &WalOperation::Checkpoint,
            &WalTarget::Index,
            "checkpoint",
            &data,
            false,
        );

        Self {
            lsn,
            operation: WalOperation::Checkpoint,
            target: WalTarget::Index,
            entry_id: "checkpoint".to_string(),
            data,
            encrypted: false,
            status: WalEntryStatus::Checkpoint,
            timestamp: Utc::now(),
            tx_id: None,
            checksum,
        }
    }

    /// Compute checksum for entry
    fn compute_checksum(
        lsn: LSN,
        operation: &WalOperation,
        target: &WalTarget,
        entry_id: &str,
        data: &str,
        encrypted: bool,
    ) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(lsn.to_le_bytes());
        hasher.update(format!("{:?}", operation).as_bytes());
        hasher.update(format!("{:?}", target).as_bytes());
        hasher.update(entry_id.as_bytes());
        hasher.update(data.as_bytes());
        hasher.update(&[encrypted as u8]);
        hex::encode(hasher.finalize())
    }

    /// Verify entry integrity
    pub fn verify(&self) -> bool {
        let expected = Self::compute_checksum(
            self.lsn,
            &self.operation,
            &self.target,
            &self.entry_id,
            &self.data,
            self.encrypted,
        );
        self.checksum == expected
    }

    /// Mark as committed
    pub fn commit(&mut self) {
        self.status = WalEntryStatus::Committed;
    }

    /// Mark as rolled back
    pub fn rollback(&mut self) {
        self.status = WalEntryStatus::RolledBack;
    }

    /// Deserialize the data
    pub fn deserialize_data<T: for<'de> Deserialize<'de>>(&self) -> P2Result<T> {
        serde_json::from_str(&self.data)
            .map_err(|e| P2Error::Serialization(format!("Failed to deserialize WAL data: {}", e)))
    }
}

/// Write-Ahead Log manager
pub struct WriteAheadLog {
    /// Base path for WAL files
    base_path: PathBuf,
    /// Current WAL file
    current_file: RwLock<Option<File>>,
    /// Next LSN to assign
    next_lsn: RwLock<LSN>,
    /// Last committed LSN
    last_committed_lsn: RwLock<LSN>,
    /// Last checkpoint LSN
    last_checkpoint_lsn: RwLock<LSN>,
    /// Pending entries (not yet committed) - stored decrypted in memory
    pending: RwLock<HashMap<LSN, WalEntry>>,
    /// Configuration
    config: WalConfig,
    /// Encryption handler (None = no encryption)
    encryption: Option<EnvelopeEncryption>,
}

/// WAL configuration
///
/// # Security
///
/// Encryption is mandatory for production use. The `kek_ref` field should
/// always be `Some(...)` in production deployments to ensure zero-plaintext
/// compliance. The only exception is test configurations created via
/// `WalConfig::unencrypted()` which is only available in test builds.
#[derive(Debug, Clone)]
pub struct WalConfig {
    /// Maximum WAL file size before rotation (bytes)
    pub max_file_size: u64,
    /// Checkpoint interval (number of entries)
    pub checkpoint_interval: u64,
    /// Sync mode
    pub sync_mode: SyncMode,
    /// Retain at least this many checkpoints
    pub retain_checkpoints: usize,
    /// KEK reference for encrypting WAL data.
    /// SECURITY: Must be Some(...) in production. None only allowed in tests.
    pub kek_ref: Option<String>,
}

/// Sync mode for WAL writes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    /// Sync after every write (safest, slowest)
    Always,
    /// Sync at checkpoint only
    Checkpoint,
    /// No explicit sync (fastest, relies on OS)
    None,
}

impl Default for WalConfig {
    fn default() -> Self {
        Self {
            max_file_size: 64 * 1024 * 1024, // 64 MB
            checkpoint_interval: 1000,
            sync_mode: SyncMode::Checkpoint,
            retain_checkpoints: 3,
            kek_ref: Some("wal-kek-v1".to_string()), // Default: encryption enabled
        }
    }
}

impl WalConfig {
    /// Create config with encryption disabled (for testing only)
    ///
    /// # Security Warning
    ///
    /// This method is ONLY available in test builds. Using an unencrypted WAL
    /// in production violates zero-plaintext compliance requirements.
    #[cfg(test)]
    pub fn unencrypted() -> Self {
        Self {
            kek_ref: None,
            ..Default::default()
        }
    }

    /// Create config with specific KEK reference
    pub fn with_kek(kek_ref: impl Into<String>) -> Self {
        Self {
            kek_ref: Some(kek_ref.into()),
            ..Default::default()
        }
    }

    /// Validate configuration for production use
    ///
    /// Returns an error if encryption is not properly configured.
    pub fn validate_production(&self) -> crate::error::P2Result<()> {
        if self.kek_ref.is_none() {
            return Err(crate::error::P2Error::Validation(
                "WAL encryption is mandatory in production. Configure kek_ref.".to_string()
            ));
        }
        Ok(())
    }
}

impl WriteAheadLog {
    /// Open or create a WAL at the given path
    pub async fn open(base_path: impl Into<PathBuf>) -> P2Result<Self> {
        Self::open_with_config(base_path, WalConfig::default()).await
    }

    /// Open with custom configuration
    pub async fn open_with_config(base_path: impl Into<PathBuf>, config: WalConfig) -> P2Result<Self> {
        let base_path = base_path.into();

        // Create directory if needed
        tokio::fs::create_dir_all(&base_path).await
            .map_err(|e| P2Error::Storage(format!("Failed to create WAL directory: {}", e)))?;

        // Initialize encryption if KEK is configured
        // Note: In production, use open_with_key_store() for secure key management
        #[allow(deprecated)]
        let encryption = config.kek_ref.as_ref().map(|kek_ref| {
            EnvelopeEncryption::new_insecure(kek_ref.clone())
        });

        let wal = Self {
            base_path,
            current_file: RwLock::new(None),
            next_lsn: RwLock::new(1),
            last_committed_lsn: RwLock::new(0),
            last_checkpoint_lsn: RwLock::new(0),
            pending: RwLock::new(HashMap::new()),
            config,
            encryption,
        };

        // Recovery: scan existing WAL files
        wal.recover().await?;

        Ok(wal)
    }

    /// Append an entry to the WAL
    pub async fn append(&self, mut entry: WalEntry) -> P2Result<LSN> {
        let lsn = {
            let mut next = self.next_lsn.write().await;
            let lsn = *next;
            entry.lsn = lsn;
            *next += 1;
            lsn
        };

        // Store the unencrypted entry in pending (for in-memory access)
        let pending_entry = entry.clone();

        // Encrypt data if encryption is enabled (skip for checkpoints)
        if let Some(ref enc) = self.encryption {
            if entry.operation != WalOperation::Checkpoint {
                let sealed = enc.seal(entry.data.as_bytes(), Some(entry.entry_id.as_bytes()))?;
                let sealed_json = serde_json::to_string(&sealed)
                    .map_err(|e| P2Error::Serialization(format!("Failed to serialize sealed envelope: {}", e)))?;
                entry.data = sealed_json;
                entry.encrypted = true;
            }
        }

        // Recompute checksum with correct LSN and encryption state
        entry.checksum = WalEntry::compute_checksum(
            entry.lsn,
            &entry.operation,
            &entry.target,
            &entry.entry_id,
            &entry.data,
            entry.encrypted,
        );

        // Write encrypted entry to file
        self.write_entry(&entry).await?;

        // Store unencrypted entry in pending
        self.pending.write().await.insert(lsn, pending_entry);

        Ok(lsn)
    }

    /// Commit an entry
    pub async fn commit(&self, lsn: LSN) -> P2Result<()> {
        let mut pending = self.pending.write().await;

        if let Some(entry) = pending.get_mut(&lsn) {
            entry.commit();

            // Write commit marker
            let mut commit_entry = entry.clone();
            commit_entry.operation = WalOperation::CommitTx;
            drop(pending);

            self.write_entry(&commit_entry).await?;

            // Update last committed
            let mut last = self.last_committed_lsn.write().await;
            if lsn > *last {
                *last = lsn;
            }

            // Remove from pending
            self.pending.write().await.remove(&lsn);

            // Check if checkpoint needed
            self.maybe_checkpoint().await?;
        }

        Ok(())
    }

    /// Rollback an entry
    pub async fn rollback(&self, lsn: LSN) -> P2Result<()> {
        let mut pending = self.pending.write().await;

        if let Some(entry) = pending.get_mut(&lsn) {
            entry.rollback();

            // Write rollback marker
            let mut rb_entry = entry.clone();
            rb_entry.operation = WalOperation::RollbackTx;
            drop(pending);

            self.write_entry(&rb_entry).await?;

            // Remove from pending
            self.pending.write().await.remove(&lsn);
        }

        Ok(())
    }

    /// Create a checkpoint
    pub async fn checkpoint(&self) -> P2Result<LSN> {
        let last_committed = *self.last_committed_lsn.read().await;
        let lsn = {
            let mut next = self.next_lsn.write().await;
            let lsn = *next;
            *next += 1;
            lsn
        };

        let entry = WalEntry::checkpoint(lsn, last_committed);
        self.write_entry(&entry).await?;

        // Sync if configured
        if matches!(self.config.sync_mode, SyncMode::Checkpoint | SyncMode::Always) {
            self.sync().await?;
        }

        *self.last_checkpoint_lsn.write().await = lsn;

        Ok(lsn)
    }

    /// Recover from WAL files
    async fn recover(&self) -> P2Result<RecoveryResult> {
        let mut result = RecoveryResult::default();

        let wal_file = self.base_path.join("wal.log");
        if !wal_file.exists() {
            return Ok(result);
        }

        let file = File::open(&wal_file).await
            .map_err(|e| P2Error::Storage(format!("Failed to open WAL: {}", e)))?;

        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        let mut max_lsn: LSN = 0;
        let mut last_checkpoint: LSN = 0;
        let mut pending_entries: HashMap<LSN, WalEntry> = HashMap::new();
        let mut committed: std::collections::HashSet<LSN> = std::collections::HashSet::new();
        let mut rolled_back: std::collections::HashSet<LSN> = std::collections::HashSet::new();

        while let Some(line) = lines.next_line().await
            .map_err(|e| P2Error::Storage(format!("Failed to read WAL line: {}", e)))?
        {
            if line.is_empty() {
                continue;
            }

            let mut entry: WalEntry = serde_json::from_str(&line)
                .map_err(|e| P2Error::Serialization(format!("Failed to parse WAL entry: {}", e)))?;

            if !entry.verify() {
                result.corrupted_entries += 1;
                continue;
            }

            // Decrypt entry data if encrypted
            if entry.encrypted {
                if let Some(ref enc) = self.encryption {
                    use crate::crypto::SealedEnvelope;
                    let sealed: SealedEnvelope = serde_json::from_str(&entry.data)
                        .map_err(|e| P2Error::Serialization(format!("Failed to parse sealed envelope: {}", e)))?;
                    let plaintext = enc.unseal_with_aad(&sealed, entry.entry_id.as_bytes())?;
                    entry.data = String::from_utf8(plaintext)
                        .map_err(|e| P2Error::Serialization(format!("Failed to decode decrypted data: {}", e)))?;
                    entry.encrypted = false;
                } else {
                    // Encrypted entry but no encryption configured - skip with warning
                    result.corrupted_entries += 1;
                    continue;
                }
            }

            max_lsn = max_lsn.max(entry.lsn);

            match entry.operation {
                WalOperation::Checkpoint => {
                    last_checkpoint = entry.lsn;
                    result.checkpoints_found += 1;
                }
                WalOperation::CommitTx => {
                    committed.insert(entry.lsn);
                    result.committed_count += 1;
                }
                WalOperation::RollbackTx => {
                    rolled_back.insert(entry.lsn);
                    result.rolledback_count += 1;
                }
                _ => {
                    pending_entries.insert(entry.lsn, entry);
                }
            }
        }

        // Filter out committed and rolled back entries
        pending_entries.retain(|lsn, _| !committed.contains(lsn) && !rolled_back.contains(lsn));
        result.pending_count = pending_entries.len();

        // Update state
        *self.next_lsn.write().await = max_lsn + 1;
        *self.last_checkpoint_lsn.write().await = last_checkpoint;
        *self.pending.write().await = pending_entries;

        // Find last committed LSN
        if let Some(max_committed) = committed.iter().max() {
            *self.last_committed_lsn.write().await = *max_committed;
        }

        Ok(result)
    }

    /// Get pending entries for replay
    pub async fn pending_entries(&self) -> Vec<WalEntry> {
        self.pending.read().await.values().cloned().collect()
    }

    /// Sync WAL to disk
    async fn sync(&self) -> P2Result<()> {
        if let Some(ref file) = *self.current_file.read().await {
            file.sync_all().await
                .map_err(|e| P2Error::Storage(format!("Failed to sync WAL: {}", e)))?;
        }
        Ok(())
    }

    /// Write entry to WAL file
    async fn write_entry(&self, entry: &WalEntry) -> P2Result<()> {
        let line = serde_json::to_string(entry)
            .map_err(|e| P2Error::Serialization(format!("Failed to serialize WAL entry: {}", e)))?;

        let mut file_guard = self.current_file.write().await;

        // Open file if not already open
        if file_guard.is_none() {
            let wal_file = self.base_path.join("wal.log");
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&wal_file)
                .await
                .map_err(|e| P2Error::Storage(format!("Failed to open WAL file: {}", e)))?;
            *file_guard = Some(file);
        }

        if let Some(ref mut file) = *file_guard {
            file.write_all(line.as_bytes()).await
                .map_err(|e| P2Error::Storage(format!("Failed to write WAL entry: {}", e)))?;
            file.write_all(b"\n").await
                .map_err(|e| P2Error::Storage(format!("Failed to write WAL newline: {}", e)))?;

            if self.config.sync_mode == SyncMode::Always {
                file.sync_all().await
                    .map_err(|e| P2Error::Storage(format!("Failed to sync WAL: {}", e)))?;
            }
        }

        Ok(())
    }

    /// Maybe create a checkpoint based on config
    async fn maybe_checkpoint(&self) -> P2Result<()> {
        let last_committed = *self.last_committed_lsn.read().await;
        let last_checkpoint = *self.last_checkpoint_lsn.read().await;

        if last_committed - last_checkpoint >= self.config.checkpoint_interval {
            self.checkpoint().await?;
        }

        Ok(())
    }

    /// Get current LSN
    pub async fn current_lsn(&self) -> LSN {
        *self.next_lsn.read().await - 1
    }

    /// Get last committed LSN
    pub async fn last_committed(&self) -> LSN {
        *self.last_committed_lsn.read().await
    }

    /// Get pending count
    pub async fn pending_count(&self) -> usize {
        self.pending.read().await.len()
    }

    /// Get WAL statistics
    pub async fn stats(&self) -> WalStats {
        WalStats {
            current_lsn: self.current_lsn().await,
            last_committed_lsn: self.last_committed().await,
            last_checkpoint_lsn: *self.last_checkpoint_lsn.read().await,
            pending_count: self.pending_count().await,
        }
    }
}

/// Recovery result
#[derive(Debug, Default)]
pub struct RecoveryResult {
    /// Number of checkpoints found
    pub checkpoints_found: usize,
    /// Number of committed entries
    pub committed_count: usize,
    /// Number of rolled back entries
    pub rolledback_count: usize,
    /// Number of pending (uncommitted) entries
    pub pending_count: usize,
    /// Number of corrupted entries
    pub corrupted_entries: usize,
}

/// WAL statistics
#[derive(Debug, Clone)]
pub struct WalStats {
    /// Current LSN
    pub current_lsn: LSN,
    /// Last committed LSN
    pub last_committed_lsn: LSN,
    /// Last checkpoint LSN
    pub last_checkpoint_lsn: LSN,
    /// Number of pending entries
    pub pending_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_wal_basic() {
        let temp_dir = TempDir::new().unwrap();
        let wal = WriteAheadLog::open(temp_dir.path()).await.unwrap();

        let entry = WalEntry::new(
            0,
            WalOperation::Create,
            WalTarget::Ticket,
            "ticket:001".to_string(),
            serde_json::json!({"holder": "actor:001"}),
        ).unwrap();

        let lsn = wal.append(entry).await.unwrap();
        assert_eq!(lsn, 1);

        assert_eq!(wal.pending_count().await, 1);

        wal.commit(lsn).await.unwrap();
        assert_eq!(wal.pending_count().await, 0);
        assert_eq!(wal.last_committed().await, 1);
    }

    #[tokio::test]
    async fn test_wal_rollback() {
        let temp_dir = TempDir::new().unwrap();
        let wal = WriteAheadLog::open(temp_dir.path()).await.unwrap();

        let entry = WalEntry::new(
            0,
            WalOperation::Create,
            WalTarget::Evidence,
            "bundle:001".to_string(),
            serde_json::json!({"case": "case:001"}),
        ).unwrap();

        let lsn = wal.append(entry).await.unwrap();
        wal.rollback(lsn).await.unwrap();

        assert_eq!(wal.pending_count().await, 0);
        assert_eq!(wal.last_committed().await, 0);
    }

    #[tokio::test]
    async fn test_wal_checkpoint() {
        let temp_dir = TempDir::new().unwrap();
        let config = WalConfig {
            checkpoint_interval: 3,
            ..Default::default()
        };
        let wal = WriteAheadLog::open_with_config(temp_dir.path(), config).await.unwrap();

        // Create and commit 3 entries
        for i in 0..3 {
            let entry = WalEntry::new(
                0,
                WalOperation::Create,
                WalTarget::Snapshot,
                format!("snap:{}", i),
                serde_json::json!({"idx": i}),
            ).unwrap();

            let lsn = wal.append(entry).await.unwrap();
            wal.commit(lsn).await.unwrap();
        }

        // Should have created a checkpoint
        let stats = wal.stats().await;
        assert!(stats.last_checkpoint_lsn > 0);
    }

    #[tokio::test]
    async fn test_wal_recovery() {
        let temp_dir = TempDir::new().unwrap();

        // First session: write entries
        {
            let wal = WriteAheadLog::open(temp_dir.path()).await.unwrap();

            let entry1 = WalEntry::new(
                0,
                WalOperation::Create,
                WalTarget::Ticket,
                "ticket:001".to_string(),
                serde_json::json!({"test": 1}),
            ).unwrap();

            let lsn1 = wal.append(entry1).await.unwrap();
            wal.commit(lsn1).await.unwrap();

            // This one is not committed - should be pending after recovery
            let entry2 = WalEntry::new(
                0,
                WalOperation::Create,
                WalTarget::Ticket,
                "ticket:002".to_string(),
                serde_json::json!({"test": 2}),
            ).unwrap();

            wal.append(entry2).await.unwrap();
        }

        // Second session: recover
        {
            let wal = WriteAheadLog::open(temp_dir.path()).await.unwrap();

            assert_eq!(wal.last_committed().await, 1);
            assert_eq!(wal.pending_count().await, 1);

            let pending = wal.pending_entries().await;
            assert_eq!(pending.len(), 1);
            assert_eq!(pending[0].entry_id, "ticket:002");
        }
    }

    #[test]
    fn test_entry_checksum() {
        let entry = WalEntry::new(
            1,
            WalOperation::Create,
            WalTarget::Evidence,
            "bundle:001".to_string(),
            serde_json::json!({"test": true}),
        ).unwrap();

        assert!(entry.verify());

        // Tampered entry should fail
        let mut tampered = entry.clone();
        tampered.entry_id = "bundle:002".to_string();
        assert!(!tampered.verify());
    }
}
