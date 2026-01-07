//! Temperature Policy Executor
//!
//! Executes temperature migration policies by scanning storage and
//! migrating payloads between temperature tiers.

use chrono::{DateTime, Utc};
use p2_core::types::StorageTemperature;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::policy::{MigrationContext, TemperaturePolicy, TemperaturePolicyConfig};
use crate::backend::{P2StorageBackend, PayloadMetadata};
use crate::error::{StorageError, StorageResult};

/// Temperature policy executor
pub struct TemperaturePolicyExecutor<B: P2StorageBackend> {
    /// Storage backend
    backend: Arc<B>,
    /// Policy
    policy: TemperaturePolicy,
    /// In-progress migrations
    in_progress: RwLock<HashMap<String, MigrationStatus>>,
    /// Access history tracker
    access_tracker: RwLock<AccessTracker>,
    /// Executor ID
    executor_id: String,
    /// Cached storage utilization percentage
    cached_utilization: RwLock<CachedUtilization>,
}

/// Cached storage utilization with timestamp
struct CachedUtilization {
    /// Utilization percentage (0-100)
    percent: u8,
    /// When this was last computed
    last_computed: DateTime<Utc>,
}

impl Default for CachedUtilization {
    fn default() -> Self {
        Self {
            percent: 50, // Default fallback
            last_computed: DateTime::UNIX_EPOCH.into(),
        }
    }
}

impl<B: P2StorageBackend> TemperaturePolicyExecutor<B> {
    /// Create a new executor with default policy
    pub fn new(backend: Arc<B>) -> Self {
        Self::with_policy(backend, TemperaturePolicyConfig::default())
    }

    /// Create with custom policy
    pub fn with_policy(backend: Arc<B>, config: TemperaturePolicyConfig) -> Self {
        Self {
            backend,
            policy: TemperaturePolicy::new(config),
            in_progress: RwLock::new(HashMap::new()),
            access_tracker: RwLock::new(AccessTracker::new()),
            executor_id: uuid::Uuid::new_v4().to_string(),
            cached_utilization: RwLock::new(CachedUtilization::default()),
        }
    }

    /// Get current storage utilization percentage
    /// Caches the result for 5 minutes to avoid excessive health checks
    async fn get_storage_utilization(&self) -> u8 {
        const CACHE_DURATION_SECS: i64 = 300; // 5 minutes

        // Check cache first
        {
            let cached = self.cached_utilization.read().await;
            let age = Utc::now() - cached.last_computed;
            if age.num_seconds() < CACHE_DURATION_SECS {
                return cached.percent;
            }
        }

        // Compute fresh utilization from health check
        let utilization = match self.backend.health_check().await {
            Ok(status) => {
                match (status.used_bytes, status.available_bytes) {
                    (Some(used), Some(available)) if used + available > 0 => {
                        let total = used + available;
                        ((used as f64 / total as f64) * 100.0) as u8
                    }
                    _ => {
                        debug!("Backend health check missing storage metrics, using default");
                        50 // Default fallback
                    }
                }
            }
            Err(e) => {
                warn!("Failed to get storage utilization: {}", e);
                50 // Default fallback on error
            }
        };

        // Update cache
        {
            let mut cached = self.cached_utilization.write().await;
            cached.percent = utilization;
            cached.last_computed = Utc::now();
        }

        utilization
    }

    /// Get the policy config
    pub fn policy_config(&self) -> &TemperaturePolicyConfig {
        self.policy.config()
    }

    /// Record an access for temperature tracking
    pub async fn record_access(&self, ref_id: &str) {
        let mut tracker = self.access_tracker.write().await;
        tracker.record(ref_id);
    }

    /// Scan and identify migration candidates
    pub async fn scan_for_candidates(
        &self,
        payloads: &[PayloadMetadata],
    ) -> StorageResult<Vec<MigrationCandidate>> {
        let tracker = self.access_tracker.read().await;
        let mut candidates = Vec::new();

        // Get actual storage utilization
        let storage_utilization = self.get_storage_utilization().await;

        for metadata in payloads {
            // Build migration context
            let context = MigrationContext {
                ref_id: metadata.ref_id.clone(),
                current_temp: metadata.temperature,
                created_at: metadata.created_at,
                last_accessed_at: metadata.last_accessed_at,
                size_bytes: metadata.size_bytes,
                access_history: tracker.get_history(&metadata.ref_id),
                explicit_request: false,
                storage_utilization_percent: storage_utilization,
                tags: metadata.tags.clone(),
            };

            // Evaluate policy
            if let Some(target_temp) = self.policy.evaluate(&context) {
                candidates.push(MigrationCandidate {
                    ref_id: metadata.ref_id.clone(),
                    current_temp: metadata.temperature,
                    target_temp,
                    size_bytes: metadata.size_bytes,
                    created_at: metadata.created_at,
                    reason: format!(
                        "Policy '{}' triggered migration",
                        self.policy.config().name
                    ),
                });
            }
        }

        debug!(
            "Scan complete: {} candidates from {} payloads",
            candidates.len(),
            payloads.len()
        );

        Ok(candidates)
    }

    /// Execute migrations for a batch of candidates
    pub async fn execute_batch(&self, candidates: Vec<MigrationCandidate>) -> MigrationBatch {
        let batch_id = uuid::Uuid::new_v4().to_string();
        let max_batch = self.policy.config().max_batch_size;
        let to_process: Vec<_> = candidates.into_iter().take(max_batch).collect();
        let total = to_process.len();

        info!(
            "Starting migration batch {}: {} payloads",
            batch_id, total
        );

        let mut results = Vec::new();
        let mut success_count = 0;
        let mut failure_count = 0;

        for candidate in to_process {
            // Mark as in-progress
            {
                let mut in_progress = self.in_progress.write().await;
                in_progress.insert(
                    candidate.ref_id.clone(),
                    MigrationStatus::InProgress {
                        started_at: Utc::now(),
                        target_temp: candidate.target_temp,
                    },
                );
            }

            // Execute migration
            let result = self
                .migrate_single(&candidate.ref_id, candidate.target_temp)
                .await;

            // Update status
            {
                let mut in_progress = self.in_progress.write().await;
                match &result {
                    Ok(_) => {
                        in_progress.remove(&candidate.ref_id);
                        success_count += 1;
                    }
                    Err(e) => {
                        in_progress.insert(
                            candidate.ref_id.clone(),
                            MigrationStatus::Failed {
                                error: e.to_string(),
                                failed_at: Utc::now(),
                            },
                        );
                        failure_count += 1;
                    }
                }
            }

            results.push(MigrationResult {
                ref_id: candidate.ref_id,
                from_temp: candidate.current_temp,
                to_temp: candidate.target_temp,
                success: result.is_ok(),
                error: result.err().map(|e| e.to_string()),
                completed_at: Utc::now(),
            });
        }

        info!(
            "Migration batch {} complete: {}/{} succeeded",
            batch_id, success_count, total
        );

        MigrationBatch {
            batch_id,
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
            total_count: total,
            success_count,
            failure_count,
            results,
        }
    }

    /// Migrate a single payload
    async fn migrate_single(
        &self,
        ref_id: &str,
        target_temp: StorageTemperature,
    ) -> StorageResult<()> {
        debug!("Migrating {} to {:?}", ref_id, target_temp);

        self.backend
            .migrate_temperature(ref_id, target_temp)
            .await?;

        Ok(())
    }

    /// Get migration status for a payload
    pub async fn get_status(&self, ref_id: &str) -> Option<MigrationStatus> {
        let in_progress = self.in_progress.read().await;
        in_progress.get(ref_id).cloned()
    }

    /// Get all in-progress migrations
    pub async fn get_in_progress(&self) -> Vec<(String, MigrationStatus)> {
        let in_progress = self.in_progress.read().await;
        in_progress
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Request explicit migration for a payload
    pub async fn request_migration(
        &self,
        ref_id: &str,
        target_temp: StorageTemperature,
    ) -> StorageResult<MigrationResult> {
        // Get current metadata
        let metadata = self.backend.get_metadata(ref_id).await?;

        if metadata.temperature == target_temp {
            return Ok(MigrationResult {
                ref_id: ref_id.to_string(),
                from_temp: metadata.temperature,
                to_temp: target_temp,
                success: true,
                error: None,
                completed_at: Utc::now(),
            });
        }

        // Execute migration
        let result = self.migrate_single(ref_id, target_temp).await;

        Ok(MigrationResult {
            ref_id: ref_id.to_string(),
            from_temp: metadata.temperature,
            to_temp: target_temp,
            success: result.is_ok(),
            error: result.err().map(|e| e.to_string()),
            completed_at: Utc::now(),
        })
    }

    /// Get progress summary
    pub async fn get_progress(&self) -> MigrationProgress {
        let in_progress = self.in_progress.read().await;
        let in_progress_count = in_progress
            .values()
            .filter(|s| matches!(s, MigrationStatus::InProgress { .. }))
            .count();
        let failed_count = in_progress
            .values()
            .filter(|s| matches!(s, MigrationStatus::Failed { .. }))
            .count();

        MigrationProgress {
            executor_id: self.executor_id.clone(),
            in_progress_count,
            failed_count,
            policy_name: self.policy.config().name.clone(),
            policy_enabled: self.policy.config().enabled,
        }
    }

    /// Clear failed migrations from tracking
    pub async fn clear_failed(&self) {
        let mut in_progress = self.in_progress.write().await;
        in_progress.retain(|_, status| !matches!(status, MigrationStatus::Failed { .. }));
    }
}

/// Migration candidate
#[derive(Debug, Clone)]
pub struct MigrationCandidate {
    /// Payload reference ID
    pub ref_id: String,
    /// Current temperature
    pub current_temp: StorageTemperature,
    /// Target temperature
    pub target_temp: StorageTemperature,
    /// Payload size
    pub size_bytes: u64,
    /// Creation time
    pub created_at: DateTime<Utc>,
    /// Reason for migration
    pub reason: String,
}

/// Migration status
#[derive(Debug, Clone)]
pub enum MigrationStatus {
    /// Migration in progress
    InProgress {
        started_at: DateTime<Utc>,
        target_temp: StorageTemperature,
    },
    /// Migration failed
    Failed {
        error: String,
        failed_at: DateTime<Utc>,
    },
}

/// Migration result
#[derive(Debug, Clone)]
pub struct MigrationResult {
    /// Payload reference ID
    pub ref_id: String,
    /// Original temperature
    pub from_temp: StorageTemperature,
    /// Target temperature
    pub to_temp: StorageTemperature,
    /// Whether migration succeeded
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Completion timestamp
    pub completed_at: DateTime<Utc>,
}

/// Migration batch result
#[derive(Debug, Clone)]
pub struct MigrationBatch {
    /// Batch ID
    pub batch_id: String,
    /// Start time
    pub started_at: DateTime<Utc>,
    /// Completion time
    pub completed_at: Option<DateTime<Utc>>,
    /// Total payloads in batch
    pub total_count: usize,
    /// Successful migrations
    pub success_count: usize,
    /// Failed migrations
    pub failure_count: usize,
    /// Individual results
    pub results: Vec<MigrationResult>,
}

impl MigrationBatch {
    /// Get success rate as percentage
    pub fn success_rate(&self) -> f64 {
        if self.total_count == 0 {
            100.0
        } else {
            (self.success_count as f64 / self.total_count as f64) * 100.0
        }
    }

    /// Get duration in milliseconds
    pub fn duration_ms(&self) -> Option<i64> {
        self.completed_at
            .map(|end| (end - self.started_at).num_milliseconds())
    }
}

/// Migration progress summary
#[derive(Debug, Clone)]
pub struct MigrationProgress {
    /// Executor ID
    pub executor_id: String,
    /// Number of migrations in progress
    pub in_progress_count: usize,
    /// Number of failed migrations
    pub failed_count: usize,
    /// Active policy name
    pub policy_name: String,
    /// Whether policy is enabled
    pub policy_enabled: bool,
}

/// Access tracker for temperature decisions
struct AccessTracker {
    /// Access history per payload (ref_id -> (timestamp, count))
    history: HashMap<String, Vec<(DateTime<Utc>, u32)>>,
    /// Max history entries per payload
    max_entries: usize,
}

impl AccessTracker {
    fn new() -> Self {
        Self {
            history: HashMap::new(),
            max_entries: 365, // Keep ~1 year of daily data
        }
    }

    fn record(&mut self, ref_id: &str) {
        let today = Utc::now().date_naive();
        let entry = self.history.entry(ref_id.to_string()).or_default();

        // Check if we have an entry for today
        if let Some(last) = entry.last_mut() {
            if last.0.date_naive() == today {
                last.1 += 1;
                return;
            }
        }

        // Add new entry for today
        entry.push((Utc::now(), 1));

        // Trim if needed
        if entry.len() > self.max_entries {
            entry.remove(0);
        }
    }

    fn get_history(&self, ref_id: &str) -> Vec<(DateTime<Utc>, u32)> {
        self.history.get(ref_id).cloned().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migration_batch_success_rate() {
        let batch = MigrationBatch {
            batch_id: "test".to_string(),
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
            total_count: 10,
            success_count: 8,
            failure_count: 2,
            results: vec![],
        };

        assert!((batch.success_rate() - 80.0).abs() < 0.01);
    }

    #[test]
    fn test_access_tracker() {
        let mut tracker = AccessTracker::new();

        tracker.record("payload:001");
        tracker.record("payload:001");
        tracker.record("payload:002");

        let history1 = tracker.get_history("payload:001");
        let history2 = tracker.get_history("payload:002");

        assert_eq!(history1.len(), 1);
        assert_eq!(history1[0].1, 2); // 2 accesses today
        assert_eq!(history2.len(), 1);
        assert_eq!(history2[0].1, 1);
    }
}
