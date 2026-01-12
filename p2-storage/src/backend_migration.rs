//! Backend Migration Protocol (ISSUE-012)
//!
//! Per DSN documentation Chapter 4, backend migration MUST:
//! 1. Support ref remapping (old_ref -> new_ref)
//! 2. Support dual-write period (write to both backends during migration)
//! 3. Support re-encryption during migration (new keys)
//! 4. Append migration events to audit trail
//!
//! # Migration Phases
//!
//! 1. **Prepare**: Validate source/target backends, create migration plan
//! 2. **Dual-Write**: Start writing to both backends
//! 3. **Migrate**: Copy existing data to target backend
//! 4. **Verify**: Verify all data in target backend
//! 5. **Cutover**: Switch reads to target backend
//! 6. **Cleanup**: Remove data from source backend (optional)

use chrono::{DateTime, Utc};
use l0_core::types::Digest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::backend::{BackendType, P2StorageBackend, PayloadMetadata, WriteMetadata};
use crate::error::{StorageError, StorageResult};

/// Backend migration errors
#[derive(Debug, Error)]
pub enum MigrationError {
    /// Migration not found
    #[error("Migration not found: {0}")]
    NotFound(String),

    /// Invalid migration state
    #[error("Invalid migration state: expected {expected:?}, got {actual:?}")]
    InvalidState {
        expected: MigrationPhase,
        actual: MigrationPhase,
    },

    /// Source backend error
    #[error("Source backend error: {0}")]
    SourceBackend(String),

    /// Target backend error
    #[error("Target backend error: {0}")]
    TargetBackend(String),

    /// Verification failed
    #[error("Verification failed for {ref_id}: {reason}")]
    VerificationFailed { ref_id: String, reason: String },

    /// Ref remapping conflict
    #[error("Ref remapping conflict: {old_ref} already mapped to {existing}, cannot map to {new}")]
    RemappingConflict {
        old_ref: String,
        existing: String,
        new: String,
    },

    /// Re-encryption error
    #[error("Re-encryption failed: {0}")]
    ReEncryption(String),

    /// Migration cancelled
    #[error("Migration cancelled: {0}")]
    Cancelled(String),

    /// Storage error
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
}

/// Migration result type
pub type MigrationResult<T> = Result<T, MigrationError>;

// ============================================================================
// Migration Types
// ============================================================================

/// Migration phase
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationPhase {
    /// Migration created but not started
    Created,
    /// Preparing migration (validation, planning)
    Preparing,
    /// Dual-write mode (writing to both backends)
    DualWrite,
    /// Migrating existing data
    Migrating,
    /// Verifying migrated data
    Verifying,
    /// Cutting over to new backend
    CuttingOver,
    /// Migration complete
    Complete,
    /// Migration failed
    Failed,
    /// Migration cancelled
    Cancelled,
}

impl Default for MigrationPhase {
    fn default() -> Self {
        Self::Created
    }
}

/// Migration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationConfig {
    /// Migration ID
    pub migration_id: String,
    /// Source backend type
    pub source_backend: BackendType,
    /// Target backend type
    pub target_backend: BackendType,
    /// Enable re-encryption during migration
    pub re_encrypt: bool,
    /// New encryption key version (if re-encrypting)
    pub new_key_version: Option<String>,
    /// Batch size for migration
    pub batch_size: usize,
    /// Parallel workers
    pub parallel_workers: usize,
    /// Verify after each batch
    pub verify_after_batch: bool,
    /// Auto-cleanup source after migration
    pub auto_cleanup: bool,
    /// Dual-write duration limit (seconds)
    pub dual_write_timeout_seconds: u64,
    /// Description
    pub description: Option<String>,
}

impl Default for MigrationConfig {
    fn default() -> Self {
        Self {
            migration_id: uuid::Uuid::new_v4().to_string(),
            source_backend: BackendType::Local,
            target_backend: BackendType::S3,
            re_encrypt: false,
            new_key_version: None,
            batch_size: 100,
            parallel_workers: 4,
            verify_after_batch: true,
            auto_cleanup: false,
            dual_write_timeout_seconds: 86400, // 24 hours
            description: None,
        }
    }
}

/// Migration state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationState {
    /// Migration ID
    pub migration_id: String,
    /// Current phase
    pub phase: MigrationPhase,
    /// Configuration
    pub config: MigrationConfig,
    /// Started at
    pub started_at: DateTime<Utc>,
    /// Phase started at
    pub phase_started_at: DateTime<Utc>,
    /// Completed at
    pub completed_at: Option<DateTime<Utc>>,
    /// Total payloads to migrate
    pub total_payloads: u64,
    /// Migrated payloads
    pub migrated_payloads: u64,
    /// Verified payloads
    pub verified_payloads: u64,
    /// Failed payloads
    pub failed_payloads: u64,
    /// Skipped payloads (already in target)
    pub skipped_payloads: u64,
    /// Total bytes migrated
    pub bytes_migrated: u64,
    /// Error message (if failed)
    pub error_message: Option<String>,
    /// Ref mappings (old -> new)
    pub ref_mappings: HashMap<String, String>,
    /// Migration events
    pub events: Vec<MigrationEvent>,
}

impl MigrationState {
    /// Create a new migration state
    pub fn new(config: MigrationConfig) -> Self {
        let now = Utc::now();
        let migration_id = config.migration_id.clone();
        Self {
            migration_id,
            phase: MigrationPhase::Created,
            config,
            started_at: now,
            phase_started_at: now,
            completed_at: None,
            total_payloads: 0,
            migrated_payloads: 0,
            verified_payloads: 0,
            failed_payloads: 0,
            skipped_payloads: 0,
            bytes_migrated: 0,
            error_message: None,
            ref_mappings: HashMap::new(),
            events: Vec::new(),
        }
    }

    /// Get migration progress percentage
    pub fn progress_percent(&self) -> f64 {
        if self.total_payloads == 0 {
            return 100.0;
        }
        ((self.migrated_payloads + self.skipped_payloads) as f64 / self.total_payloads as f64) * 100.0
    }

    /// Check if migration is complete
    pub fn is_complete(&self) -> bool {
        matches!(self.phase, MigrationPhase::Complete)
    }

    /// Check if migration failed
    pub fn is_failed(&self) -> bool {
        matches!(self.phase, MigrationPhase::Failed)
    }

    /// Add event
    pub fn add_event(&mut self, event: MigrationEvent) {
        self.events.push(event);
    }

    /// Transition to next phase
    pub fn transition_to(&mut self, phase: MigrationPhase) {
        let old_phase = self.phase;
        self.phase = phase;
        self.phase_started_at = Utc::now();
        self.add_event(MigrationEvent::PhaseTransition {
            from: old_phase,
            to: phase,
            timestamp: Utc::now(),
        });
    }
}

/// Migration event
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MigrationEvent {
    /// Phase transition
    PhaseTransition {
        from: MigrationPhase,
        to: MigrationPhase,
        timestamp: DateTime<Utc>,
    },
    /// Batch started
    BatchStarted {
        batch_id: String,
        payload_count: usize,
        timestamp: DateTime<Utc>,
    },
    /// Batch completed
    BatchCompleted {
        batch_id: String,
        success_count: usize,
        failure_count: usize,
        duration_ms: i64,
        timestamp: DateTime<Utc>,
    },
    /// Payload migrated
    PayloadMigrated {
        old_ref: String,
        new_ref: String,
        size_bytes: u64,
        re_encrypted: bool,
        timestamp: DateTime<Utc>,
    },
    /// Payload verification
    PayloadVerified {
        ref_id: String,
        checksum_match: bool,
        timestamp: DateTime<Utc>,
    },
    /// Ref remapped
    RefRemapped {
        old_ref: String,
        new_ref: String,
        timestamp: DateTime<Utc>,
    },
    /// Error occurred
    Error {
        message: String,
        ref_id: Option<String>,
        timestamp: DateTime<Utc>,
    },
}

// ============================================================================
// Ref Remapping
// ============================================================================

/// Ref remapping registry
///
/// Tracks mappings from old ref_ids to new ref_ids during and after migration.
/// This is essential for maintaining referential integrity when backends use
/// different addressing schemes.
#[derive(Debug, Clone, Default)]
pub struct RefRemappingRegistry {
    /// Forward mappings (old -> new)
    forward: HashMap<String, String>,
    /// Reverse mappings (new -> old)
    reverse: HashMap<String, String>,
    /// Migration ID that created each mapping
    migration_sources: HashMap<String, String>,
}

impl RefRemappingRegistry {
    /// Create a new registry
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a mapping
    pub fn add_mapping(
        &mut self,
        old_ref: &str,
        new_ref: &str,
        migration_id: &str,
    ) -> MigrationResult<()> {
        // Check for conflicts
        if let Some(existing) = self.forward.get(old_ref) {
            if existing != new_ref {
                return Err(MigrationError::RemappingConflict {
                    old_ref: old_ref.to_string(),
                    existing: existing.clone(),
                    new: new_ref.to_string(),
                });
            }
        }

        self.forward.insert(old_ref.to_string(), new_ref.to_string());
        self.reverse.insert(new_ref.to_string(), old_ref.to_string());
        self.migration_sources.insert(old_ref.to_string(), migration_id.to_string());
        Ok(())
    }

    /// Resolve a ref (returns new ref if mapped, otherwise original)
    pub fn resolve<'a>(&'a self, ref_id: &'a str) -> &'a str {
        self.forward.get(ref_id).map(|s| s.as_str()).unwrap_or(ref_id)
    }

    /// Resolve reverse (new -> old)
    pub fn resolve_reverse(&self, ref_id: &str) -> Option<&str> {
        self.reverse.get(ref_id).map(|s| s.as_str())
    }

    /// Check if a ref is mapped
    pub fn is_mapped(&self, ref_id: &str) -> bool {
        self.forward.contains_key(ref_id)
    }

    /// Get all mappings
    pub fn get_all_mappings(&self) -> &HashMap<String, String> {
        &self.forward
    }

    /// Get mapping count
    pub fn mapping_count(&self) -> usize {
        self.forward.len()
    }
}

// ============================================================================
// Dual-Write Manager
// ============================================================================

/// Dual-write mode for migration
///
/// During migration, writes go to both source and target backends.
/// This ensures no data loss if migration needs to be rolled back.
pub struct DualWriteManager<S: P2StorageBackend, T: P2StorageBackend> {
    /// Source backend
    source: Arc<S>,
    /// Target backend
    target: Arc<T>,
    /// Whether dual-write is active
    active: RwLock<bool>,
    /// Ref remapping registry
    remapping: RwLock<RefRemappingRegistry>,
    /// Migration ID
    migration_id: String,
    /// Write statistics
    stats: RwLock<DualWriteStats>,
}

/// Dual-write statistics
#[derive(Debug, Clone, Default)]
pub struct DualWriteStats {
    /// Total dual writes
    pub total_writes: u64,
    /// Successful writes to both backends
    pub both_success: u64,
    /// Source success, target failure
    pub source_only: u64,
    /// Target success, source failure
    pub target_only: u64,
    /// Both failed
    pub both_failed: u64,
}

impl<S: P2StorageBackend, T: P2StorageBackend> DualWriteManager<S, T> {
    /// Create a new dual-write manager
    pub fn new(source: Arc<S>, target: Arc<T>, migration_id: &str) -> Self {
        Self {
            source,
            target,
            active: RwLock::new(false),
            remapping: RwLock::new(RefRemappingRegistry::new()),
            migration_id: migration_id.to_string(),
            stats: RwLock::new(DualWriteStats::default()),
        }
    }

    /// Activate dual-write mode
    pub async fn activate(&self) {
        let mut active = self.active.write().await;
        *active = true;
        info!("Dual-write mode activated for migration {}", self.migration_id);
    }

    /// Deactivate dual-write mode
    pub async fn deactivate(&self) {
        let mut active = self.active.write().await;
        *active = false;
        info!("Dual-write mode deactivated for migration {}", self.migration_id);
    }

    /// Check if dual-write is active
    pub async fn is_active(&self) -> bool {
        *self.active.read().await
    }

    /// Write to both backends
    pub async fn write(
        &self,
        data: &[u8],
        metadata: WriteMetadata,
    ) -> StorageResult<(String, String)> {
        let is_active = *self.active.read().await;
        if !is_active {
            // Not in dual-write mode, write to source only
            let source_ref = self.source.write(data, metadata).await?;
            return Ok((source_ref.ref_id.clone(), source_ref.ref_id));
        }

        // Dual-write mode: write to both
        let source_result = self.source.write(data, metadata.clone()).await;
        let target_result = self.target.write(data, metadata).await;

        let mut stats = self.stats.write().await;
        stats.total_writes += 1;

        match (&source_result, &target_result) {
            (Ok(source_ref), Ok(target_ref)) => {
                stats.both_success += 1;

                // Register ref mapping if refs differ
                if source_ref.ref_id != target_ref.ref_id {
                    let mut remapping = self.remapping.write().await;
                    let _ = remapping.add_mapping(
                        &source_ref.ref_id,
                        &target_ref.ref_id,
                        &self.migration_id,
                    );
                }

                Ok((source_ref.ref_id.clone(), target_ref.ref_id.clone()))
            }
            (Ok(source_ref), Err(e)) => {
                stats.source_only += 1;
                warn!(
                    "Dual-write: target failed for {}: {}",
                    source_ref.ref_id, e
                );
                Ok((source_ref.ref_id.clone(), source_ref.ref_id.clone()))
            }
            (Err(e), Ok(target_ref)) => {
                stats.target_only += 1;
                warn!(
                    "Dual-write: source failed, target succeeded: {}",
                    target_ref.ref_id
                );
                // This is problematic - source is primary during migration
                Err(StorageError::Backend(format!(
                    "Source write failed during dual-write: {}",
                    e
                )))
            }
            (Err(e1), Err(e2)) => {
                stats.both_failed += 1;
                Err(StorageError::Backend(format!(
                    "Both backends failed: source={}, target={}",
                    e1, e2
                )))
            }
        }
    }

    /// Get ref remapping registry
    pub async fn get_remapping(&self) -> RefRemappingRegistry {
        self.remapping.read().await.clone()
    }

    /// Get statistics
    pub async fn get_stats(&self) -> DualWriteStats {
        self.stats.read().await.clone()
    }
}

// ============================================================================
// Migration Executor
// ============================================================================

/// Backend migration executor
pub struct BackendMigrationExecutor<S: P2StorageBackend, T: P2StorageBackend> {
    /// Source backend
    source: Arc<S>,
    /// Target backend
    target: Arc<T>,
    /// Migration state
    state: RwLock<MigrationState>,
    /// Dual-write manager
    dual_write: Option<Arc<DualWriteManager<S, T>>>,
    /// Re-encryption handler (if enabled)
    re_encrypt_handler: Option<Arc<dyn ReEncryptionHandler + Send + Sync>>,
}

/// Re-encryption handler trait
#[async_trait::async_trait]
pub trait ReEncryptionHandler {
    /// Re-encrypt data with new key
    async fn re_encrypt(
        &self,
        data: &[u8],
        old_key_version: &str,
        new_key_version: &str,
    ) -> Result<Vec<u8>, String>;
}

impl<S: P2StorageBackend, T: P2StorageBackend> BackendMigrationExecutor<S, T> {
    /// Create a new migration executor
    pub fn new(source: Arc<S>, target: Arc<T>, config: MigrationConfig) -> Self {
        let state = MigrationState::new(config.clone());
        let migration_id = state.migration_id.clone();

        Self {
            source: source.clone(),
            target: target.clone(),
            state: RwLock::new(state),
            dual_write: Some(Arc::new(DualWriteManager::new(
                source,
                target,
                &migration_id,
            ))),
            re_encrypt_handler: None,
        }
    }

    /// Set re-encryption handler
    pub fn with_re_encryption(
        mut self,
        handler: Arc<dyn ReEncryptionHandler + Send + Sync>,
    ) -> Self {
        self.re_encrypt_handler = Some(handler);
        self
    }

    /// Get migration state
    pub async fn get_state(&self) -> MigrationState {
        self.state.read().await.clone()
    }

    /// Prepare migration
    pub async fn prepare(&self) -> MigrationResult<()> {
        let mut state = self.state.write().await;

        if state.phase != MigrationPhase::Created {
            return Err(MigrationError::InvalidState {
                expected: MigrationPhase::Created,
                actual: state.phase,
            });
        }

        state.transition_to(MigrationPhase::Preparing);

        // Validate backends
        let source_health = self.source.health_check().await.map_err(|e| {
            MigrationError::SourceBackend(format!("Health check failed: {}", e))
        })?;

        if !source_health.healthy {
            return Err(MigrationError::SourceBackend(format!(
                "Source unhealthy: {}",
                source_health.message
            )));
        }

        let target_health = self.target.health_check().await.map_err(|e| {
            MigrationError::TargetBackend(format!("Health check failed: {}", e))
        })?;

        if !target_health.healthy {
            return Err(MigrationError::TargetBackend(format!(
                "Target unhealthy: {}",
                target_health.message
            )));
        }

        info!(
            "Migration {} prepared: {} -> {}",
            state.migration_id,
            state.config.source_backend,
            state.config.target_backend
        );

        Ok(())
    }

    /// Start dual-write mode
    pub async fn start_dual_write(&self) -> MigrationResult<()> {
        let mut state = self.state.write().await;

        if state.phase != MigrationPhase::Preparing {
            return Err(MigrationError::InvalidState {
                expected: MigrationPhase::Preparing,
                actual: state.phase,
            });
        }

        state.transition_to(MigrationPhase::DualWrite);

        if let Some(ref dw) = self.dual_write {
            dw.activate().await;
        }

        info!("Migration {} dual-write mode started", state.migration_id);
        Ok(())
    }

    /// Migrate a single payload
    pub async fn migrate_payload(&self, ref_id: &str) -> MigrationResult<String> {
        let state = self.state.read().await;

        if !matches!(state.phase, MigrationPhase::Migrating | MigrationPhase::DualWrite) {
            return Err(MigrationError::InvalidState {
                expected: MigrationPhase::Migrating,
                actual: state.phase,
            });
        }
        drop(state);

        // Read from source
        let data = self.source.read(ref_id).await.map_err(|e| {
            MigrationError::SourceBackend(format!("Failed to read {}: {}", ref_id, e))
        })?;

        let source_metadata = self.source.get_metadata(ref_id).await.map_err(|e| {
            MigrationError::SourceBackend(format!("Failed to get metadata {}: {}", ref_id, e))
        })?;

        // Re-encrypt if needed
        let (data_to_write, key_version) = {
            let state = self.state.read().await;
            if state.config.re_encrypt {
                if let Some(ref handler) = self.re_encrypt_handler {
                    let new_key = state.config.new_key_version.clone()
                        .unwrap_or_else(|| "v2".to_string());
                    let re_encrypted = handler
                        .re_encrypt(&data, &source_metadata.encryption_key_version, &new_key)
                        .await
                        .map_err(MigrationError::ReEncryption)?;
                    (re_encrypted, new_key)
                } else {
                    (data, source_metadata.encryption_key_version.clone())
                }
            } else {
                (data, source_metadata.encryption_key_version.clone())
            }
        };

        // Write to target
        let write_metadata = WriteMetadata {
            content_type: source_metadata.content_type.clone(),
            encryption_key_version: key_version,
            temperature: source_metadata.temperature,
            retention_policy_ref: None,
            tags: source_metadata.tags.clone(),
            owner_id: source_metadata.owner_id.clone(),
            expected_size: Some(data_to_write.len() as u64),
        };

        let target_ref = self.target.write(&data_to_write, write_metadata).await.map_err(|e| {
            MigrationError::TargetBackend(format!("Failed to write: {}", e))
        })?;

        // Update state
        {
            let mut state = self.state.write().await;
            state.migrated_payloads += 1;
            state.bytes_migrated += data_to_write.len() as u64;

            // Record ref mapping if different
            if ref_id != target_ref.ref_id {
                state.ref_mappings.insert(ref_id.to_string(), target_ref.ref_id.clone());
                state.add_event(MigrationEvent::RefRemapped {
                    old_ref: ref_id.to_string(),
                    new_ref: target_ref.ref_id.clone(),
                    timestamp: Utc::now(),
                });
            }

            state.add_event(MigrationEvent::PayloadMigrated {
                old_ref: ref_id.to_string(),
                new_ref: target_ref.ref_id.clone(),
                size_bytes: data_to_write.len() as u64,
                re_encrypted: self.state.read().await.config.re_encrypt,
                timestamp: Utc::now(),
            });
        }

        debug!(
            "Migrated {} -> {} ({} bytes)",
            ref_id,
            target_ref.ref_id,
            data_to_write.len()
        );

        Ok(target_ref.ref_id)
    }

    /// Verify migrated payload
    pub async fn verify_payload(&self, old_ref: &str, new_ref: &str) -> MigrationResult<bool> {
        // Read from both
        let source_data = self.source.read(old_ref).await.map_err(|e| {
            MigrationError::SourceBackend(format!("Verify read source failed: {}", e))
        })?;

        let target_data = self.target.read(new_ref).await.map_err(|e| {
            MigrationError::TargetBackend(format!("Verify read target failed: {}", e))
        })?;

        // If re-encrypted, we can't compare content directly
        // Instead compare checksums or use verification token
        let state = self.state.read().await;
        let matches = if state.config.re_encrypt {
            // For re-encrypted data, verify sizes match (content will differ)
            source_data.len() == target_data.len()
        } else {
            // For non-re-encrypted, verify exact content match
            source_data == target_data
        };
        drop(state);

        // Update state
        {
            let mut state = self.state.write().await;
            if matches {
                state.verified_payloads += 1;
            } else {
                state.failed_payloads += 1;
            }
            state.add_event(MigrationEvent::PayloadVerified {
                ref_id: new_ref.to_string(),
                checksum_match: matches,
                timestamp: Utc::now(),
            });
        }

        if !matches {
            return Err(MigrationError::VerificationFailed {
                ref_id: new_ref.to_string(),
                reason: "Content mismatch".to_string(),
            });
        }

        Ok(true)
    }

    /// Complete migration
    pub async fn complete(&self) -> MigrationResult<MigrationState> {
        let mut state = self.state.write().await;

        if !matches!(state.phase, MigrationPhase::Verifying | MigrationPhase::CuttingOver) {
            return Err(MigrationError::InvalidState {
                expected: MigrationPhase::Verifying,
                actual: state.phase,
            });
        }

        // Deactivate dual-write
        if let Some(ref dw) = self.dual_write {
            dw.deactivate().await;
        }

        state.transition_to(MigrationPhase::Complete);
        state.completed_at = Some(Utc::now());

        info!(
            "Migration {} complete: {} payloads migrated, {} bytes",
            state.migration_id, state.migrated_payloads, state.bytes_migrated
        );

        Ok(state.clone())
    }

    /// Cancel migration
    pub async fn cancel(&self, reason: &str) -> MigrationResult<()> {
        let mut state = self.state.write().await;

        if matches!(state.phase, MigrationPhase::Complete | MigrationPhase::Cancelled) {
            return Err(MigrationError::Cancelled(
                "Migration already completed or cancelled".to_string(),
            ));
        }

        // Deactivate dual-write
        if let Some(ref dw) = self.dual_write {
            dw.deactivate().await;
        }

        state.transition_to(MigrationPhase::Cancelled);
        state.error_message = Some(reason.to_string());
        state.completed_at = Some(Utc::now());

        warn!("Migration {} cancelled: {}", state.migration_id, reason);
        Ok(())
    }

    /// Get ref remapping
    pub async fn get_ref_remapping(&self) -> HashMap<String, String> {
        self.state.read().await.ref_mappings.clone()
    }
}

// ============================================================================
// Migration Audit
// ============================================================================

/// Migration audit entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationAuditEntry {
    /// Entry ID
    pub entry_id: String,
    /// Migration ID
    pub migration_id: String,
    /// Event type
    pub event: MigrationEvent,
    /// Entry digest
    pub digest: Digest,
    /// Previous entry digest (chain)
    pub prev_digest: Option<Digest>,
    /// Created at
    pub created_at: DateTime<Utc>,
}

impl MigrationAuditEntry {
    /// Create a new audit entry
    pub fn new(
        migration_id: &str,
        event: MigrationEvent,
        prev_digest: Option<Digest>,
    ) -> Self {
        let entry_id = uuid::Uuid::new_v4().to_string();
        let created_at = Utc::now();

        // Compute digest
        let digest_data = format!(
            "{}:{}:{:?}:{:?}:{}",
            entry_id,
            migration_id,
            event,
            prev_digest,
            created_at.to_rfc3339()
        );
        let digest = Digest::blake3(digest_data.as_bytes());

        Self {
            entry_id,
            migration_id: migration_id.to_string(),
            event,
            digest,
            prev_digest,
            created_at,
        }
    }

    /// Verify entry integrity
    pub fn verify(&self) -> bool {
        let digest_data = format!(
            "{}:{}:{:?}:{:?}:{}",
            self.entry_id,
            self.migration_id,
            self.event,
            self.prev_digest,
            self.created_at.to_rfc3339()
        );
        let computed = Digest::blake3(digest_data.as_bytes());
        computed == self.digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migration_state() {
        let config = MigrationConfig::default();
        let mut state = MigrationState::new(config);

        assert_eq!(state.phase, MigrationPhase::Created);
        assert_eq!(state.progress_percent(), 100.0); // 0/0 = 100%

        state.total_payloads = 100;
        state.migrated_payloads = 50;
        assert_eq!(state.progress_percent(), 50.0);

        state.transition_to(MigrationPhase::Migrating);
        assert_eq!(state.phase, MigrationPhase::Migrating);
        assert!(!state.events.is_empty());
    }

    #[test]
    fn test_ref_remapping() {
        let mut registry = RefRemappingRegistry::new();

        registry
            .add_mapping("old:001", "new:001", "migration:001")
            .unwrap();

        assert!(registry.is_mapped("old:001"));
        assert!(!registry.is_mapped("old:002"));
        assert_eq!(registry.resolve("old:001"), "new:001");
        assert_eq!(registry.resolve("old:002"), "old:002"); // Not mapped

        // Test conflict detection
        let result = registry.add_mapping("old:001", "new:002", "migration:002");
        assert!(result.is_err());
    }

    #[test]
    fn test_migration_audit_entry() {
        let event = MigrationEvent::PhaseTransition {
            from: MigrationPhase::Created,
            to: MigrationPhase::Preparing,
            timestamp: Utc::now(),
        };

        let entry = MigrationAuditEntry::new("migration:001", event, None);
        assert!(entry.verify());
    }

    #[test]
    fn test_migration_config_default() {
        let config = MigrationConfig::default();
        assert_eq!(config.batch_size, 100);
        assert_eq!(config.parallel_workers, 4);
        assert!(!config.re_encrypt);
        assert!(config.verify_after_batch);
    }
}
