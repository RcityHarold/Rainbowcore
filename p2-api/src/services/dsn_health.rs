//! DSN Health Monitor Service (ISSUE-015)
//!
//! Background service that monitors DSN (L0/P1) health and automatically
//! triggers degraded mode when unavailability is detected.
//!
//! # Features
//!
//! - Periodic health checks against L0 endpoint
//! - Automatic degraded mode entry on consecutive failures
//! - Automatic recovery initiation when health is restored
//! - Configurable check intervals and failure thresholds

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use bridge::L0CommitClient;
use p2_core::DegradedModeManager;

/// Configuration for DSN health monitoring
#[derive(Debug, Clone)]
pub struct DsnHealthConfig {
    /// Interval between health checks
    pub check_interval: Duration,
    /// Number of consecutive failures before entering degraded mode
    pub failure_threshold: u32,
    /// Number of consecutive successes before attempting recovery
    pub recovery_threshold: u32,
    /// Timeout for each health check
    pub check_timeout: Duration,
    /// Whether to enable automatic recovery
    pub auto_recovery: bool,
}

impl Default for DsnHealthConfig {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(30),
            failure_threshold: 3,
            recovery_threshold: 2,
            check_timeout: Duration::from_secs(10),
            auto_recovery: true,
        }
    }
}

impl DsnHealthConfig {
    /// Create config for aggressive monitoring (shorter intervals)
    pub fn aggressive() -> Self {
        Self {
            check_interval: Duration::from_secs(10),
            failure_threshold: 2,
            recovery_threshold: 1,
            check_timeout: Duration::from_secs(5),
            auto_recovery: true,
        }
    }

    /// Create config for relaxed monitoring (longer intervals)
    pub fn relaxed() -> Self {
        Self {
            check_interval: Duration::from_secs(60),
            failure_threshold: 5,
            recovery_threshold: 3,
            check_timeout: Duration::from_secs(15),
            auto_recovery: true,
        }
    }
}

/// DSN Health Monitor
///
/// Runs in the background and monitors DSN health, automatically
/// managing degraded mode transitions.
pub struct DsnHealthMonitor {
    /// L0 client for health checks
    l0_client: Arc<dyn L0CommitClient>,
    /// Degraded mode manager
    degraded_mode: Arc<DegradedModeManager>,
    /// Configuration
    config: DsnHealthConfig,
    /// Shutdown signal sender
    shutdown_tx: watch::Sender<bool>,
    /// Shutdown signal receiver
    shutdown_rx: watch::Receiver<bool>,
}

impl DsnHealthMonitor {
    /// Create a new health monitor
    pub fn new(
        l0_client: Arc<dyn L0CommitClient>,
        degraded_mode: Arc<DegradedModeManager>,
        config: DsnHealthConfig,
    ) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            l0_client,
            degraded_mode,
            config,
            shutdown_tx,
            shutdown_rx,
        }
    }

    /// Create with default configuration
    pub fn with_defaults(
        l0_client: Arc<dyn L0CommitClient>,
        degraded_mode: Arc<DegradedModeManager>,
    ) -> Self {
        Self::new(l0_client, degraded_mode, DsnHealthConfig::default())
    }

    /// Start the health monitor in a background task
    ///
    /// Returns a handle that can be used to stop the monitor.
    pub fn start(self) -> DsnHealthHandle {
        let shutdown_tx = self.shutdown_tx.clone();
        let config = self.config.clone();

        let handle = tokio::spawn(async move {
            self.run_monitor_loop().await;
        });

        DsnHealthHandle {
            shutdown_tx,
            task_handle: handle,
            config,
        }
    }

    /// Run the monitoring loop
    async fn run_monitor_loop(self) {
        let mut check_interval = interval(self.config.check_interval);
        let mut shutdown_rx = self.shutdown_rx.clone();
        let mut consecutive_failures: u32 = 0;
        let mut consecutive_successes: u32 = 0;
        let mut in_degraded_mode = false;

        info!(
            check_interval_secs = self.config.check_interval.as_secs(),
            failure_threshold = self.config.failure_threshold,
            "DSN health monitor started"
        );

        loop {
            tokio::select! {
                _ = check_interval.tick() => {
                    let healthy = self.perform_health_check().await;

                    // Record the health check result
                    self.degraded_mode.record_health_check(healthy).await;

                    if healthy {
                        consecutive_failures = 0;
                        consecutive_successes += 1;

                        debug!(
                            consecutive_successes = consecutive_successes,
                            "DSN health check passed"
                        );

                        // Check if we should attempt recovery
                        if in_degraded_mode
                            && self.config.auto_recovery
                            && consecutive_successes >= self.config.recovery_threshold
                        {
                            info!(
                                consecutive_successes = consecutive_successes,
                                "DSN healthy, initiating recovery"
                            );
                            if let Err(e) = self.attempt_recovery().await {
                                warn!(error = %e, "Recovery attempt failed");
                            } else {
                                in_degraded_mode = false;
                                consecutive_successes = 0;
                            }
                        }
                    } else {
                        consecutive_successes = 0;
                        consecutive_failures += 1;

                        warn!(
                            consecutive_failures = consecutive_failures,
                            threshold = self.config.failure_threshold,
                            "DSN health check failed"
                        );

                        // Check if we should enter degraded mode
                        if !in_degraded_mode
                            && consecutive_failures >= self.config.failure_threshold
                        {
                            error!(
                                consecutive_failures = consecutive_failures,
                                "Entering degraded mode due to DSN unavailability"
                            );
                            if let Err(e) = self.degraded_mode
                                .enter_unavailable_mode("Health check failures exceeded threshold")
                                .await
                            {
                                error!(error = %e, "Failed to enter degraded mode");
                            } else {
                                in_degraded_mode = true;
                            }
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("DSN health monitor shutting down");
                        break;
                    }
                }
            }
        }
    }

    /// Perform a single health check
    async fn perform_health_check(&self) -> bool {
        // Use tokio timeout to bound the health check
        let result = tokio::time::timeout(
            self.config.check_timeout,
            self.l0_client.health_check(),
        )
        .await;

        match result {
            Ok(Ok(health_status)) => {
                // L0HealthStatus has an `available` field
                health_status.available
            }
            Ok(Err(e)) => {
                debug!(error = %e, "L0 health check returned error");
                false
            }
            Err(_) => {
                debug!("L0 health check timed out");
                false
            }
        }
    }

    /// Attempt to recover from degraded mode
    async fn attempt_recovery(&self) -> Result<(), p2_core::DegradedModeError> {
        // Start recovery process
        self.degraded_mode.start_recovery().await?;

        // TODO: Replay queued operations here
        // For now, just complete recovery
        // In a full implementation, we would:
        // 1. Get queued operations from TicketReplayQueue
        // 2. Replay each operation
        // 3. Mark operations as replayed or failed
        // 4. Complete recovery only if all critical operations succeeded

        self.degraded_mode.complete_recovery().await?;

        info!("Recovery completed successfully");
        Ok(())
    }
}

/// Handle for controlling the health monitor
pub struct DsnHealthHandle {
    shutdown_tx: watch::Sender<bool>,
    task_handle: tokio::task::JoinHandle<()>,
    config: DsnHealthConfig,
}

impl DsnHealthHandle {
    /// Stop the health monitor
    pub async fn stop(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.task_handle.await;
        info!("DSN health monitor stopped");
    }

    /// Check if the monitor is still running
    pub fn is_running(&self) -> bool {
        !self.task_handle.is_finished()
    }

    /// Get the configuration
    pub fn config(&self) -> &DsnHealthConfig {
        &self.config
    }
}

/// Extension trait for AppState to easily start health monitoring
#[async_trait::async_trait]
pub trait DsnHealthExt {
    /// Start DSN health monitoring with default configuration
    fn start_dsn_health_monitor(&self) -> DsnHealthHandle;

    /// Start DSN health monitoring with custom configuration
    fn start_dsn_health_monitor_with_config(&self, config: DsnHealthConfig) -> DsnHealthHandle;
}

#[async_trait::async_trait]
impl DsnHealthExt for crate::state::AppState {
    fn start_dsn_health_monitor(&self) -> DsnHealthHandle {
        let monitor = DsnHealthMonitor::with_defaults(
            self.l0_client.clone(),
            self.degraded_mode.clone(),
        );
        monitor.start()
    }

    fn start_dsn_health_monitor_with_config(&self, config: DsnHealthConfig) -> DsnHealthHandle {
        let monitor = DsnHealthMonitor::new(
            self.l0_client.clone(),
            self.degraded_mode.clone(),
            config,
        );
        monitor.start()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DsnHealthConfig::default();
        assert_eq!(config.check_interval.as_secs(), 30);
        assert_eq!(config.failure_threshold, 3);
        assert_eq!(config.recovery_threshold, 2);
        assert!(config.auto_recovery);
    }

    #[test]
    fn test_aggressive_config() {
        let config = DsnHealthConfig::aggressive();
        assert_eq!(config.check_interval.as_secs(), 10);
        assert_eq!(config.failure_threshold, 2);
    }

    #[test]
    fn test_relaxed_config() {
        let config = DsnHealthConfig::relaxed();
        assert_eq!(config.check_interval.as_secs(), 60);
        assert_eq!(config.failure_threshold, 5);
    }
}
