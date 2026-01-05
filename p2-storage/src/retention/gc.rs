//! Retention Garbage Collector
//!
//! Automatically cleans up expired payloads based on retention policies.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, Duration as TokioDuration};
use tracing::{debug, error, info, warn};

use super::checker::{RetentionAction, RetentionChecker, RetentionCheckResult};
use super::legal_hold::LegalHoldManager;
use crate::error::{StorageError, StorageResult};

/// Garbage collection mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GCMode {
    /// Dry run - report what would be deleted without actual deletion
    DryRun,
    /// Tombstone only - mark as deleted but retain data
    TombstoneOnly,
    /// Full deletion - actually remove data
    FullDeletion,
}

/// GC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GCConfig {
    /// GC mode
    pub mode: GCMode,
    /// Scan interval in seconds
    pub scan_interval_secs: u64,
    /// Maximum deletions per scan
    pub max_deletions_per_scan: usize,
    /// Grace period before deletion (days)
    pub grace_period_days: u32,
    /// Whether to require confirmation for sensitive data
    pub require_confirmation_for_sensitive: bool,
    /// Batch size for processing
    pub batch_size: usize,
    /// Enable automatic scanning
    pub auto_scan_enabled: bool,
}

impl Default for GCConfig {
    fn default() -> Self {
        Self {
            mode: GCMode::TombstoneOnly,
            scan_interval_secs: 3600, // 1 hour
            max_deletions_per_scan: 1000,
            grace_period_days: 30,
            require_confirmation_for_sensitive: true,
            batch_size: 100,
            auto_scan_enabled: true,
        }
    }
}

/// GC operation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GCResult {
    /// Scan timestamp
    pub scanned_at: DateTime<Utc>,
    /// Number of payloads scanned
    pub payloads_scanned: usize,
    /// Number of payloads marked for deletion
    pub marked_for_deletion: usize,
    /// Number of payloads tombstoned
    pub tombstoned: usize,
    /// Number of payloads permanently deleted
    pub deleted: usize,
    /// Number skipped due to legal hold
    pub skipped_legal_hold: usize,
    /// Number skipped due to grace period
    pub skipped_grace_period: usize,
    /// Errors encountered
    pub errors: Vec<String>,
    /// Duration of scan in milliseconds
    pub duration_ms: u64,
}

impl Default for GCResult {
    fn default() -> Self {
        Self {
            scanned_at: Utc::now(),
            payloads_scanned: 0,
            marked_for_deletion: 0,
            tombstoned: 0,
            deleted: 0,
            skipped_legal_hold: 0,
            skipped_grace_period: 0,
            errors: Vec::new(),
            duration_ms: 0,
        }
    }
}

/// Tombstone record for deleted payloads
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tombstone {
    /// Payload reference ID
    pub ref_id: String,
    /// Tombstone timestamp
    pub tombstoned_at: DateTime<Utc>,
    /// Reason for deletion
    pub reason: String,
    /// Original expiration date
    pub original_expiration: Option<DateTime<Utc>>,
    /// Scheduled permanent deletion date
    pub permanent_deletion_at: DateTime<Utc>,
    /// Whether permanently deleted
    pub permanently_deleted: bool,
    /// Permanent deletion timestamp
    pub deleted_at: Option<DateTime<Utc>>,
}

impl Tombstone {
    /// Create a new tombstone
    pub fn new(
        ref_id: String,
        reason: String,
        original_expiration: Option<DateTime<Utc>>,
        grace_period_days: u32,
    ) -> Self {
        let now = Utc::now();
        Self {
            ref_id,
            tombstoned_at: now,
            reason,
            original_expiration,
            permanent_deletion_at: now + Duration::days(grace_period_days as i64),
            permanently_deleted: false,
            deleted_at: None,
        }
    }

    /// Check if ready for permanent deletion
    pub fn ready_for_permanent_deletion(&self) -> bool {
        !self.permanently_deleted && Utc::now() >= self.permanent_deletion_at
    }

    /// Mark as permanently deleted
    pub fn mark_deleted(&mut self) {
        self.permanently_deleted = true;
        self.deleted_at = Some(Utc::now());
    }
}

/// Deletion callback trait for actual data removal
#[async_trait::async_trait]
pub trait DeletionHandler: Send + Sync {
    /// Called when a payload should be tombstoned
    async fn tombstone(&self, ref_id: &str, reason: &str) -> StorageResult<()>;

    /// Called when a payload should be permanently deleted
    async fn delete(&self, ref_id: &str) -> StorageResult<()>;

    /// Check if a ref_id still exists
    async fn exists(&self, ref_id: &str) -> StorageResult<bool>;
}

/// No-op deletion handler for testing
pub struct NoOpDeletionHandler;

#[async_trait::async_trait]
impl DeletionHandler for NoOpDeletionHandler {
    async fn tombstone(&self, ref_id: &str, reason: &str) -> StorageResult<()> {
        debug!(ref_id = %ref_id, reason = %reason, "NoOp tombstone");
        Ok(())
    }

    async fn delete(&self, ref_id: &str) -> StorageResult<()> {
        debug!(ref_id = %ref_id, "NoOp delete");
        Ok(())
    }

    async fn exists(&self, _ref_id: &str) -> StorageResult<bool> {
        Ok(true)
    }
}

/// GC control commands
#[derive(Debug)]
pub enum GCCommand {
    /// Run a scan now
    ScanNow,
    /// Pause automatic scanning
    Pause,
    /// Resume automatic scanning
    Resume,
    /// Stop the GC task
    Stop,
}

/// Retention Garbage Collector
pub struct RetentionGC {
    /// Configuration
    config: Arc<RwLock<GCConfig>>,
    /// Retention checker
    checker: Arc<RetentionChecker>,
    /// Legal hold manager
    legal_hold_manager: Arc<LegalHoldManager>,
    /// Deletion handler
    deletion_handler: Arc<dyn DeletionHandler>,
    /// Tombstones
    tombstones: RwLock<Vec<Tombstone>>,
    /// Pending deletions (ref_ids awaiting confirmation)
    pending_deletions: RwLock<HashSet<String>>,
    /// GC statistics
    last_result: RwLock<Option<GCResult>>,
    /// Total deletions since start
    total_deletions: RwLock<usize>,
    /// Command sender
    command_tx: Option<mpsc::Sender<GCCommand>>,
}

impl RetentionGC {
    /// Create a new GC instance
    pub fn new(
        config: GCConfig,
        checker: Arc<RetentionChecker>,
        legal_hold_manager: Arc<LegalHoldManager>,
        deletion_handler: Arc<dyn DeletionHandler>,
    ) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            checker,
            legal_hold_manager,
            deletion_handler,
            tombstones: RwLock::new(Vec::new()),
            pending_deletions: RwLock::new(HashSet::new()),
            last_result: RwLock::new(None),
            total_deletions: RwLock::new(0),
            command_tx: None,
        }
    }

    /// Run a single GC scan
    pub async fn scan(&self) -> GCResult {
        let start = std::time::Instant::now();
        let config = self.config.read().await.clone();
        let mut result = GCResult::default();

        info!("Starting GC scan in {:?} mode", config.mode);

        // Get all items needing action
        let check_results = self.checker.scan_all().await;
        result.payloads_scanned = check_results.len();

        let mut processed = 0;

        for check_result in check_results {
            if processed >= config.max_deletions_per_scan {
                debug!("Reached max deletions per scan limit");
                break;
            }

            match self.process_item(&check_result, &config, &mut result).await {
                Ok(true) => processed += 1,
                Ok(false) => {}
                Err(e) => {
                    result.errors.push(format!(
                        "Error processing {}: {}",
                        check_result.ref_id, e
                    ));
                }
            }
        }

        // Process tombstones ready for permanent deletion
        if config.mode == GCMode::FullDeletion {
            self.process_tombstones(&config, &mut result).await;
        }

        result.duration_ms = start.elapsed().as_millis() as u64;

        info!(
            scanned = result.payloads_scanned,
            tombstoned = result.tombstoned,
            deleted = result.deleted,
            skipped_hold = result.skipped_legal_hold,
            duration_ms = result.duration_ms,
            "GC scan complete"
        );

        // Store result
        *self.last_result.write().await = Some(result.clone());

        result
    }

    /// Process a single item
    async fn process_item(
        &self,
        check_result: &RetentionCheckResult,
        config: &GCConfig,
        result: &mut GCResult,
    ) -> StorageResult<bool> {
        let ref_id = &check_result.ref_id;

        // Skip if under legal hold
        if check_result.under_legal_hold {
            result.skipped_legal_hold += 1;
            return Ok(false);
        }

        // Only process items marked for deletion
        if check_result.action != RetentionAction::Delete {
            return Ok(false);
        }

        result.marked_for_deletion += 1;

        match config.mode {
            GCMode::DryRun => {
                debug!(ref_id = %ref_id, "Dry run: would delete");
                Ok(true)
            }
            GCMode::TombstoneOnly => {
                self.tombstone_payload(ref_id, check_result, config, result)
                    .await
            }
            GCMode::FullDeletion => {
                // First tombstone, then check if ready for deletion
                let tombstone = self.get_tombstone(ref_id).await;
                if let Some(t) = tombstone {
                    if t.ready_for_permanent_deletion() {
                        self.delete_payload(ref_id, result).await
                    } else {
                        result.skipped_grace_period += 1;
                        Ok(false)
                    }
                } else {
                    // Create tombstone first
                    self.tombstone_payload(ref_id, check_result, config, result)
                        .await
                }
            }
        }
    }

    /// Tombstone a payload
    async fn tombstone_payload(
        &self,
        ref_id: &str,
        check_result: &RetentionCheckResult,
        config: &GCConfig,
        result: &mut GCResult,
    ) -> StorageResult<bool> {
        let reason = format!(
            "Retention policy expired. Status: {:?}",
            check_result.status
        );

        // Create tombstone record
        let tombstone = Tombstone::new(
            ref_id.to_string(),
            reason.clone(),
            check_result.days_until_expiration.map(|d| {
                Utc::now() + Duration::days(d)
            }),
            config.grace_period_days,
        );

        // Call deletion handler
        self.deletion_handler.tombstone(ref_id, &reason).await?;

        // Store tombstone
        self.tombstones.write().await.push(tombstone);

        result.tombstoned += 1;

        info!(ref_id = %ref_id, "Payload tombstoned");
        Ok(true)
    }

    /// Permanently delete a payload
    async fn delete_payload(&self, ref_id: &str, result: &mut GCResult) -> StorageResult<bool> {
        // Call deletion handler
        self.deletion_handler.delete(ref_id).await?;

        // Update tombstone
        let mut tombstones = self.tombstones.write().await;
        if let Some(t) = tombstones.iter_mut().find(|t| t.ref_id == ref_id) {
            t.mark_deleted();
        }

        result.deleted += 1;
        *self.total_deletions.write().await += 1;

        info!(ref_id = %ref_id, "Payload permanently deleted");
        Ok(true)
    }

    /// Process tombstones ready for permanent deletion
    async fn process_tombstones(&self, config: &GCConfig, result: &mut GCResult) {
        let tombstones = self.tombstones.read().await;
        let ready: Vec<_> = tombstones
            .iter()
            .filter(|t| t.ready_for_permanent_deletion())
            .take(config.batch_size)
            .map(|t| t.ref_id.clone())
            .collect();
        drop(tombstones);

        for ref_id in ready {
            // Double-check legal hold before permanent deletion
            if let Ok(under_hold) = self.legal_hold_manager.is_under_hold(&ref_id).await {
                if under_hold {
                    warn!(ref_id = %ref_id, "Skipping permanent deletion - under legal hold");
                    result.skipped_legal_hold += 1;
                    continue;
                }
            }

            if let Err(e) = self.delete_payload(&ref_id, result).await {
                result
                    .errors
                    .push(format!("Failed to delete {}: {}", ref_id, e));
            }
        }
    }

    /// Get a tombstone by ref_id
    async fn get_tombstone(&self, ref_id: &str) -> Option<Tombstone> {
        self.tombstones
            .read()
            .await
            .iter()
            .find(|t| t.ref_id == ref_id)
            .cloned()
    }

    /// Get all tombstones
    pub async fn get_tombstones(&self) -> Vec<Tombstone> {
        self.tombstones.read().await.clone()
    }

    /// Get tombstones ready for permanent deletion
    pub async fn get_ready_for_deletion(&self) -> Vec<Tombstone> {
        self.tombstones
            .read()
            .await
            .iter()
            .filter(|t| t.ready_for_permanent_deletion())
            .cloned()
            .collect()
    }

    /// Get last scan result
    pub async fn get_last_result(&self) -> Option<GCResult> {
        self.last_result.read().await.clone()
    }

    /// Get total deletions since start
    pub async fn get_total_deletions(&self) -> usize {
        *self.total_deletions.read().await
    }

    /// Update configuration
    pub async fn update_config(&self, config: GCConfig) {
        *self.config.write().await = config;
    }

    /// Get current configuration
    pub async fn get_config(&self) -> GCConfig {
        self.config.read().await.clone()
    }

    /// Cancel a pending tombstone (recover data)
    pub async fn cancel_tombstone(&self, ref_id: &str) -> StorageResult<bool> {
        let mut tombstones = self.tombstones.write().await;
        let original_len = tombstones.len();

        tombstones.retain(|t| t.ref_id != ref_id || t.permanently_deleted);

        if tombstones.len() < original_len {
            info!(ref_id = %ref_id, "Tombstone cancelled - data recovered");
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Get GC statistics
    pub async fn get_stats(&self) -> GCStats {
        let tombstones = self.tombstones.read().await;
        let config = self.config.read().await;
        let last_result = self.last_result.read().await;
        let total_deletions = *self.total_deletions.read().await;

        let pending_tombstones = tombstones
            .iter()
            .filter(|t| !t.permanently_deleted)
            .count();
        let ready_for_deletion = tombstones
            .iter()
            .filter(|t| t.ready_for_permanent_deletion())
            .count();

        GCStats {
            mode: config.mode,
            total_tombstones: tombstones.len(),
            pending_tombstones,
            ready_for_deletion,
            total_permanent_deletions: total_deletions,
            last_scan_at: last_result.as_ref().map(|r| r.scanned_at),
            auto_scan_enabled: config.auto_scan_enabled,
        }
    }

    /// Start background GC task
    pub async fn start_background_task(gc: Arc<Self>) -> mpsc::Sender<GCCommand> {
        let (tx, mut rx) = mpsc::channel::<GCCommand>(10);

        let gc_clone = gc.clone();
        tokio::spawn(async move {
            let mut paused = false;

            loop {
                let config = gc_clone.config.read().await;
                let scan_interval = TokioDuration::from_secs(config.scan_interval_secs);
                let auto_enabled = config.auto_scan_enabled;
                drop(config);

                tokio::select! {
                    cmd = rx.recv() => {
                        match cmd {
                            Some(GCCommand::ScanNow) => {
                                gc_clone.scan().await;
                            }
                            Some(GCCommand::Pause) => {
                                paused = true;
                                info!("GC paused");
                            }
                            Some(GCCommand::Resume) => {
                                paused = false;
                                info!("GC resumed");
                            }
                            Some(GCCommand::Stop) | None => {
                                info!("GC stopping");
                                break;
                            }
                        }
                    }
                    _ = tokio::time::sleep(scan_interval), if auto_enabled && !paused => {
                        gc_clone.scan().await;
                    }
                }
            }
        });

        tx
    }
}

/// GC statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GCStats {
    /// Current GC mode
    pub mode: GCMode,
    /// Total tombstones (including deleted)
    pub total_tombstones: usize,
    /// Pending tombstones (not yet permanently deleted)
    pub pending_tombstones: usize,
    /// Ready for permanent deletion
    pub ready_for_deletion: usize,
    /// Total permanent deletions
    pub total_permanent_deletions: usize,
    /// Last scan timestamp
    pub last_scan_at: Option<DateTime<Utc>>,
    /// Whether auto-scan is enabled
    pub auto_scan_enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retention::policy::RetentionPolicyConfig;

    async fn create_test_gc() -> RetentionGC {
        let config = GCConfig {
            mode: GCMode::DryRun,
            ..Default::default()
        };
        let policy_config = RetentionPolicyConfig::default();
        let legal_manager = Arc::new(LegalHoldManager::new());
        let checker = Arc::new(RetentionChecker::new(policy_config, legal_manager.clone()));
        let deletion_handler = Arc::new(NoOpDeletionHandler);

        RetentionGC::new(config, checker, legal_manager, deletion_handler)
    }

    #[tokio::test]
    async fn test_gc_creation() {
        let gc = create_test_gc().await;
        let stats = gc.get_stats().await;

        assert_eq!(stats.mode, GCMode::DryRun);
        assert_eq!(stats.total_tombstones, 0);
    }

    #[tokio::test]
    async fn test_empty_scan() {
        let gc = create_test_gc().await;
        let result = gc.scan().await;

        assert_eq!(result.payloads_scanned, 0);
        assert_eq!(result.tombstoned, 0);
        assert_eq!(result.deleted, 0);
    }

    #[tokio::test]
    async fn test_tombstone_creation() {
        let tombstone = Tombstone::new(
            "payload:001".to_string(),
            "Expired".to_string(),
            Some(Utc::now() - Duration::days(1)),
            30,
        );

        assert!(!tombstone.permanently_deleted);
        assert!(!tombstone.ready_for_permanent_deletion());
    }

    #[tokio::test]
    async fn test_config_update() {
        let gc = create_test_gc().await;

        let mut new_config = gc.get_config().await;
        new_config.mode = GCMode::TombstoneOnly;
        gc.update_config(new_config).await;

        let config = gc.get_config().await;
        assert_eq!(config.mode, GCMode::TombstoneOnly);
    }

    #[test]
    fn test_tombstone_ready_for_deletion() {
        let mut tombstone = Tombstone::new(
            "payload:001".to_string(),
            "Test".to_string(),
            None,
            0, // 0 days grace period
        );

        // Should be ready immediately with 0 grace period
        // Note: There might be a small time difference, so we set it to past
        tombstone.permanent_deletion_at = Utc::now() - Duration::seconds(1);
        assert!(tombstone.ready_for_permanent_deletion());

        tombstone.mark_deleted();
        assert!(!tombstone.ready_for_permanent_deletion());
        assert!(tombstone.permanently_deleted);
    }
}
