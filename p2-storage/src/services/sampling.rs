//! Sampling Scheduler
//!
//! Orchestrates periodic sampling runs for data integrity verification.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

use crate::backend::P2StorageBackend;
use crate::error::StorageError;

use super::alerting::{AlertConfig, AlertManager};
use super::integrity_check::{IntegrityCheckResult, IntegrityCheckType, IntegrityChecker, IntegrityCheckerConfig};
use super::sampler::{PayloadSampleInfo, PayloadSampler, SamplingStrategy, SelectedSample, TemperatureTier};
use super::sampling_report::{SamplingReport, SamplingReportBuilder};

/// Sampling scheduler configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingSchedulerConfig {
    /// Whether scheduler is enabled
    pub enabled: bool,
    /// Interval between sampling runs in seconds
    pub interval_secs: u64,
    /// Sampling strategy
    pub strategy: SamplingStrategy,
    /// Integrity check configuration
    pub integrity_config: IntegrityCheckerConfig,
    /// Alert configuration
    pub alert_config: AlertConfig,
    /// Whether to run on startup
    pub run_on_startup: bool,
    /// Maximum run duration in seconds
    pub max_run_duration_secs: u64,
}

impl Default for SamplingSchedulerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 86400, // Daily
            strategy: SamplingStrategy::default(),
            integrity_config: IntegrityCheckerConfig::default(),
            alert_config: AlertConfig::default(),
            run_on_startup: false,
            max_run_duration_secs: 3600, // 1 hour max
        }
    }
}

/// Sampling run status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SamplingRunStatus {
    /// Not running
    Idle,
    /// Currently running
    Running,
    /// Completed successfully
    Completed,
    /// Failed
    Failed,
    /// Cancelled
    Cancelled,
}

/// Sampling scheduler state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingSchedulerState {
    /// Current status
    pub status: SamplingRunStatus,
    /// Last run start time
    pub last_run_started: Option<DateTime<Utc>>,
    /// Last run end time
    pub last_run_ended: Option<DateTime<Utc>>,
    /// Last run report ID
    pub last_report_id: Option<String>,
    /// Next scheduled run
    pub next_run: Option<DateTime<Utc>>,
    /// Total runs completed
    pub total_runs: u64,
    /// Total samples verified
    pub total_samples_verified: u64,
    /// Total failures detected
    pub total_failures_detected: u64,
}

impl Default for SamplingSchedulerState {
    fn default() -> Self {
        Self {
            status: SamplingRunStatus::Idle,
            last_run_started: None,
            last_run_ended: None,
            last_report_id: None,
            next_run: None,
            total_runs: 0,
            total_samples_verified: 0,
            total_failures_detected: 0,
        }
    }
}

/// Payload metadata provider trait
#[async_trait::async_trait]
pub trait PayloadMetadataProvider: Send + Sync {
    /// Get all payload metadata for sampling
    async fn get_all_payloads(&self) -> Result<Vec<PayloadSampleInfo>, StorageError>;

    /// Get expected checksum for a payload
    async fn get_expected_checksum(&self, ref_id: &str) -> Result<Option<String>, StorageError>;

    /// Update last verified timestamp
    async fn update_last_verified(&self, ref_id: &str, timestamp: DateTime<Utc>) -> Result<(), StorageError>;
}

/// Sampling scheduler
pub struct SamplingScheduler<B: P2StorageBackend, P: PayloadMetadataProvider> {
    config: Arc<RwLock<SamplingSchedulerConfig>>,
    backend: Arc<B>,
    metadata_provider: Arc<P>,
    state: Arc<RwLock<SamplingSchedulerState>>,
    sampler: Arc<RwLock<PayloadSampler>>,
    alert_manager: Arc<AlertManager>,
    /// Recent reports
    reports: Arc<RwLock<Vec<SamplingReport>>>,
    /// Shutdown signal
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl<B: P2StorageBackend + Send + Sync + 'static, P: PayloadMetadataProvider + 'static>
    SamplingScheduler<B, P>
{
    /// Create a new sampling scheduler
    pub fn new(
        config: SamplingSchedulerConfig,
        backend: Arc<B>,
        metadata_provider: Arc<P>,
    ) -> Self {
        let sampler = PayloadSampler::new(config.strategy.clone());
        let alert_manager = AlertManager::new(config.alert_config.clone());

        Self {
            config: Arc::new(RwLock::new(config)),
            backend,
            metadata_provider,
            state: Arc::new(RwLock::new(SamplingSchedulerState::default())),
            sampler: Arc::new(RwLock::new(sampler)),
            alert_manager: Arc::new(alert_manager),
            reports: Arc::new(RwLock::new(Vec::new())),
            shutdown_tx: None,
        }
    }

    /// Start the scheduler background task
    pub async fn start(&mut self) {
        let config = self.config.read().await;
        if !config.enabled {
            info!("Sampling scheduler is disabled");
            return;
        }

        let (tx, mut rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(tx);

        let scheduler = self.clone_inner();
        let interval_secs = config.interval_secs;
        let run_on_startup = config.run_on_startup;

        drop(config);

        tokio::spawn(async move {
            if run_on_startup {
                info!("Running sampling on startup");
                if let Err(e) = scheduler.run_sampling().await {
                    error!(error = %e, "Startup sampling failed");
                }
            }

            let mut interval = interval(Duration::from_secs(interval_secs));
            interval.tick().await; // Skip first immediate tick if we ran on startup

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        info!("Starting scheduled sampling run");
                        if let Err(e) = scheduler.run_sampling().await {
                            error!(error = %e, "Scheduled sampling failed");
                        }
                    }
                    _ = rx.recv() => {
                        info!("Sampling scheduler shutting down");
                        break;
                    }
                }
            }
        });

        info!("Sampling scheduler started");
    }

    /// Stop the scheduler
    pub async fn stop(&self) {
        if let Some(tx) = &self.shutdown_tx {
            let _ = tx.send(()).await;
        }
    }

    /// Clone inner references for spawned task
    fn clone_inner(&self) -> SamplingSchedulerInner<B, P> {
        SamplingSchedulerInner {
            config: self.config.clone(),
            backend: self.backend.clone(),
            metadata_provider: self.metadata_provider.clone(),
            state: self.state.clone(),
            sampler: self.sampler.clone(),
            alert_manager: self.alert_manager.clone(),
            reports: self.reports.clone(),
        }
    }

    /// Run a sampling verification manually
    pub async fn run_sampling(&self) -> Result<SamplingReport, StorageError> {
        self.clone_inner().run_sampling().await
    }

    /// Get current state
    pub async fn get_state(&self) -> SamplingSchedulerState {
        self.state.read().await.clone()
    }

    /// Get recent reports
    pub async fn get_reports(&self, limit: usize) -> Vec<SamplingReport> {
        let reports = self.reports.read().await;
        reports.iter().rev().take(limit).cloned().collect()
    }

    /// Get a specific report
    pub async fn get_report(&self, report_id: &str) -> Option<SamplingReport> {
        let reports = self.reports.read().await;
        reports.iter().find(|r| r.report_id == report_id).cloned()
    }

    /// Update configuration
    pub async fn update_config(&self, config: SamplingSchedulerConfig) {
        let mut current = self.config.write().await;
        *current = config.clone();

        // Update sampler strategy
        let mut sampler = self.sampler.write().await;
        sampler.set_strategy(config.strategy);
    }
}

/// Inner scheduler for spawned task
struct SamplingSchedulerInner<B: P2StorageBackend, P: PayloadMetadataProvider> {
    config: Arc<RwLock<SamplingSchedulerConfig>>,
    backend: Arc<B>,
    metadata_provider: Arc<P>,
    state: Arc<RwLock<SamplingSchedulerState>>,
    sampler: Arc<RwLock<PayloadSampler>>,
    alert_manager: Arc<AlertManager>,
    reports: Arc<RwLock<Vec<SamplingReport>>>,
}

impl<B: P2StorageBackend + Send + Sync + 'static, P: PayloadMetadataProvider + 'static>
    SamplingSchedulerInner<B, P>
{
    async fn run_sampling(&self) -> Result<SamplingReport, StorageError> {
        let run_start = Utc::now();
        let report_id = format!("sampling:{}", uuid::Uuid::new_v4());

        // Update state to running
        {
            let mut state = self.state.write().await;
            state.status = SamplingRunStatus::Running;
            state.last_run_started = Some(run_start);
        }

        info!(report_id = %report_id, "Starting sampling run");

        // Get all payload metadata
        let population = match self.metadata_provider.get_all_payloads().await {
            Ok(p) => p,
            Err(e) => {
                self.mark_failed().await;
                return Err(e);
            }
        };

        let population_size = population.len();
        info!(population_size = population_size, "Retrieved payload population");

        // Select samples
        let samples = {
            let mut sampler = self.sampler.write().await;
            sampler.reset();
            sampler.select_samples(&population)
        };

        info!(sample_count = samples.len(), "Selected samples for verification");

        // Run integrity checks
        let config = self.config.read().await;
        let checker = IntegrityChecker::new(config.integrity_config.clone(), self.backend.clone());
        drop(config);

        let results = self.run_checks(&checker, &samples).await;

        // Build report
        let report = SamplingReportBuilder::new(report_id.clone(), population_size)
            .started_at(run_start)
            .with_samples(samples)
            .with_results(results)
            .build();

        // Send alerts for failures
        for failure in &report.failures {
            self.alert_manager.alert_from_failure(failure).await;
        }

        // Send summary alert if health degraded
        if report.health_status != super::sampling_report::HealthStatus::Healthy {
            self.alert_manager.alert_from_report(&report).await;
        }

        // Store report
        self.reports.write().await.push(report.clone());

        // Update state
        {
            let mut state = self.state.write().await;
            state.status = SamplingRunStatus::Completed;
            state.last_run_ended = Some(Utc::now());
            state.last_report_id = Some(report_id);
            state.total_runs += 1;
            state.total_samples_verified += report.summary.checks_completed as u64;
            state.total_failures_detected += report.summary.checks_failed as u64;

            let interval = self.config.read().await.interval_secs;
            state.next_run = Some(Utc::now() + chrono::Duration::seconds(interval as i64));
        }

        // Update last verified timestamps
        for failure in &report.failures {
            if failure.ref_id.is_empty() {
                continue;
            }
        }

        info!(
            report_id = %report.report_id,
            pass_rate = %format!("{:.2}%", report.summary.pass_rate * 100.0),
            failures = report.summary.checks_failed,
            "Sampling run completed"
        );

        Ok(report)
    }

    async fn run_checks(
        &self,
        checker: &IntegrityChecker<B>,
        samples: &[SelectedSample],
    ) -> Vec<IntegrityCheckResult> {
        let mut results = Vec::with_capacity(samples.len());

        // Prepare check items with checksums
        let mut items = Vec::new();
        for sample in samples {
            let checksum = self
                .metadata_provider
                .get_expected_checksum(&sample.ref_id)
                .await
                .ok()
                .flatten();
            items.push((sample.ref_id.clone(), checksum));
        }

        // Run batch checks
        let batch_results = checker
            .check_batch(items, IntegrityCheckType::ChecksumVerification)
            .await;

        results.extend(batch_results);

        // Update last verified for successful checks
        for result in &results {
            if result.passed {
                let _ = self
                    .metadata_provider
                    .update_last_verified(&result.ref_id, result.checked_at)
                    .await;
            }
        }

        results
    }

    async fn mark_failed(&self) {
        let mut state = self.state.write().await;
        state.status = SamplingRunStatus::Failed;
        state.last_run_ended = Some(Utc::now());
    }
}

/// In-memory payload metadata provider for testing
pub struct InMemoryMetadataProvider {
    payloads: RwLock<Vec<PayloadSampleInfo>>,
    checksums: RwLock<std::collections::HashMap<String, String>>,
}

impl InMemoryMetadataProvider {
    pub fn new() -> Self {
        Self {
            payloads: RwLock::new(Vec::new()),
            checksums: RwLock::new(std::collections::HashMap::new()),
        }
    }

    pub async fn add_payload(&self, info: PayloadSampleInfo, checksum: Option<String>) {
        self.payloads.write().await.push(info.clone());
        if let Some(cs) = checksum {
            self.checksums.write().await.insert(info.ref_id, cs);
        }
    }
}

impl Default for InMemoryMetadataProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl PayloadMetadataProvider for InMemoryMetadataProvider {
    async fn get_all_payloads(&self) -> Result<Vec<PayloadSampleInfo>, StorageError> {
        Ok(self.payloads.read().await.clone())
    }

    async fn get_expected_checksum(&self, ref_id: &str) -> Result<Option<String>, StorageError> {
        Ok(self.checksums.read().await.get(ref_id).cloned())
    }

    async fn update_last_verified(
        &self,
        ref_id: &str,
        timestamp: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        let mut payloads = self.payloads.write().await;
        if let Some(p) = payloads.iter_mut().find(|p| p.ref_id == ref_id) {
            p.last_verified = Some(timestamp);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_metadata_provider() {
        let provider = InMemoryMetadataProvider::new();

        provider
            .add_payload(
                PayloadSampleInfo {
                    ref_id: "test:001".to_string(),
                    temperature: TemperatureTier::Hot,
                    last_accessed: Utc::now(),
                    last_verified: None,
                    size_bytes: 1024,
                    sample_count: 0,
                },
                Some("checksum123".to_string()),
            )
            .await;

        let payloads = provider.get_all_payloads().await.unwrap();
        assert_eq!(payloads.len(), 1);

        let checksum = provider.get_expected_checksum("test:001").await.unwrap();
        assert_eq!(checksum, Some("checksum123".to_string()));
    }

    #[test]
    fn test_sampling_scheduler_config() {
        let config = SamplingSchedulerConfig::default();
        assert!(config.enabled);
        assert_eq!(config.interval_secs, 86400); // Daily
    }

    #[test]
    fn test_sampling_scheduler_state() {
        let state = SamplingSchedulerState::default();
        assert_eq!(state.status, SamplingRunStatus::Idle);
        assert_eq!(state.total_runs, 0);
    }
}
