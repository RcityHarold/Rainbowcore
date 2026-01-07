//! Backend Health Monitor
//!
//! Monitors health status of storage backends.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use tracing::{debug, info, warn};

use crate::backend::{BackendType, HealthStatus, P2StorageBackend};

/// Health monitor configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthMonitorConfig {
    /// Health check interval in seconds
    pub check_interval_secs: u64,
    /// Timeout for health checks in milliseconds
    pub check_timeout_ms: u64,
    /// Number of consecutive failures to mark unhealthy
    pub failure_threshold: u32,
    /// Number of consecutive successes to mark healthy
    pub recovery_threshold: u32,
    /// Enable active health checks
    pub active_checks: bool,
}

impl Default for HealthMonitorConfig {
    fn default() -> Self {
        Self {
            check_interval_secs: 30,
            check_timeout_ms: 5000,
            failure_threshold: 3,
            recovery_threshold: 2,
            active_checks: true,
        }
    }
}

/// Backend health state
#[derive(Debug, Clone)]
pub struct BackendHealth {
    /// Backend type
    pub backend_type: BackendType,
    /// Is currently healthy
    pub healthy: bool,
    /// Consecutive failure count
    pub failure_count: u32,
    /// Consecutive success count
    pub success_count: u32,
    /// Last health check timestamp
    pub last_check: Option<DateTime<Utc>>,
    /// Last health check result
    pub last_status: Option<HealthStatus>,
    /// Last error message
    pub last_error: Option<String>,
    /// Time when backend became unhealthy
    pub unhealthy_since: Option<DateTime<Utc>>,
    /// Average response time in milliseconds
    pub avg_response_time_ms: f64,
    /// Total checks performed
    pub total_checks: u64,
}

impl BackendHealth {
    /// Create a new health state
    pub fn new(backend_type: BackendType) -> Self {
        Self {
            backend_type,
            healthy: true, // Assume healthy initially
            failure_count: 0,
            success_count: 0,
            last_check: None,
            last_status: None,
            last_error: None,
            unhealthy_since: None,
            avg_response_time_ms: 0.0,
            total_checks: 0,
        }
    }

    /// Record a successful health check
    pub fn record_success(&mut self, status: HealthStatus, response_time_ms: u64) {
        self.success_count += 1;
        self.failure_count = 0;
        self.last_check = Some(Utc::now());
        self.last_status = Some(status);
        self.last_error = None;
        self.total_checks += 1;

        // Update average response time
        let n = self.total_checks as f64;
        self.avg_response_time_ms =
            (self.avg_response_time_ms * (n - 1.0) + response_time_ms as f64) / n;

        // Possibly mark as healthy
        if !self.healthy && self.success_count >= 2 {
            // recovery threshold
            self.healthy = true;
            self.unhealthy_since = None;
            info!(
                backend = ?self.backend_type,
                "Backend recovered and marked healthy"
            );
        }
    }

    /// Record a failed health check
    pub fn record_failure(&mut self, error: &str) {
        self.failure_count += 1;
        self.success_count = 0;
        self.last_check = Some(Utc::now());
        self.last_error = Some(error.to_string());
        self.total_checks += 1;

        // Possibly mark as unhealthy
        if self.healthy && self.failure_count >= 3 {
            // failure threshold
            self.healthy = false;
            self.unhealthy_since = Some(Utc::now());
            warn!(
                backend = ?self.backend_type,
                failures = self.failure_count,
                error = %error,
                "Backend marked unhealthy"
            );
        }
    }
}

/// Health check result
#[derive(Debug, Clone)]
pub struct HealthCheckResult {
    /// Backend type
    pub backend_type: BackendType,
    /// Check timestamp
    pub timestamp: DateTime<Utc>,
    /// Is healthy
    pub healthy: bool,
    /// Health status
    pub status: Option<HealthStatus>,
    /// Response time in milliseconds
    pub response_time_ms: u64,
    /// Error message if unhealthy
    pub error: Option<String>,
}

/// Health monitor
pub struct HealthMonitor {
    config: HealthMonitorConfig,
    /// Registered backends
    backends: RwLock<HashMap<BackendType, Arc<dyn P2StorageBackend + Send + Sync>>>,
    /// Health states
    health_states: RwLock<HashMap<BackendType, BackendHealth>>,
    /// Manual health overrides
    overrides: RwLock<HashMap<BackendType, bool>>,
    /// Is running
    running: AtomicBool,
}

impl HealthMonitor {
    /// Create a new health monitor
    pub fn new(config: HealthMonitorConfig) -> Self {
        Self {
            config,
            backends: RwLock::new(HashMap::new()),
            health_states: RwLock::new(HashMap::new()),
            overrides: RwLock::new(HashMap::new()),
            running: AtomicBool::new(false),
        }
    }

    /// Create with default configuration
    pub fn default_monitor() -> Arc<Self> {
        Arc::new(Self::new(HealthMonitorConfig::default()))
    }

    /// Register a backend for monitoring
    pub async fn register(
        &self,
        backend_type: BackendType,
        backend: Arc<dyn P2StorageBackend + Send + Sync>,
    ) {
        let mut backends = self.backends.write().await;
        backends.insert(backend_type, backend);

        let mut states = self.health_states.write().await;
        states.insert(backend_type, BackendHealth::new(backend_type));

        info!(backend = ?backend_type, "Registered backend for health monitoring");
    }

    /// Unregister a backend
    pub async fn unregister(&self, backend_type: BackendType) {
        let mut backends = self.backends.write().await;
        backends.remove(&backend_type);

        let mut states = self.health_states.write().await;
        states.remove(&backend_type);

        info!(backend = ?backend_type, "Unregistered backend from health monitoring");
    }

    /// Check if a backend is healthy
    pub fn is_healthy(&self, backend_type: BackendType) -> bool {
        // Check manual override first
        if let Some(override_val) = self.overrides.try_read().ok().and_then(|o| o.get(&backend_type).copied()) {
            return override_val;
        }

        // Check health state
        self.health_states
            .try_read()
            .ok()
            .and_then(|states| states.get(&backend_type).map(|h| h.healthy))
            .unwrap_or(true) // Assume healthy if unknown
    }

    /// Set manual health override
    pub async fn set_override(&self, backend_type: BackendType, healthy: bool) {
        let mut overrides = self.overrides.write().await;
        overrides.insert(backend_type, healthy);

        info!(
            backend = ?backend_type,
            healthy = healthy,
            "Set health override"
        );
    }

    /// Clear manual health override
    pub async fn clear_override(&self, backend_type: BackendType) {
        let mut overrides = self.overrides.write().await;
        overrides.remove(&backend_type);

        info!(backend = ?backend_type, "Cleared health override");
    }

    /// Perform a single health check
    pub async fn check_backend(&self, backend_type: BackendType) -> Option<HealthCheckResult> {
        let backends = self.backends.read().await;
        let backend = backends.get(&backend_type)?;

        let start = std::time::Instant::now();
        let result = tokio::time::timeout(
            Duration::from_millis(self.config.check_timeout_ms),
            backend.health_check(),
        )
        .await;

        let response_time_ms = start.elapsed().as_millis() as u64;

        let check_result = match result {
            Ok(Ok(status)) => {
                let healthy = status.is_healthy();
                let mut states = self.health_states.write().await;
                if let Some(state) = states.get_mut(&backend_type) {
                    if healthy {
                        state.record_success(status.clone(), response_time_ms);
                    } else {
                        state.record_failure(status.message());
                    }
                }

                HealthCheckResult {
                    backend_type,
                    timestamp: Utc::now(),
                    healthy,
                    status: Some(status),
                    response_time_ms,
                    error: None,
                }
            }
            Ok(Err(e)) => {
                let error_msg = e.to_string();
                let mut states = self.health_states.write().await;
                if let Some(state) = states.get_mut(&backend_type) {
                    state.record_failure(&error_msg);
                }

                HealthCheckResult {
                    backend_type,
                    timestamp: Utc::now(),
                    healthy: false,
                    status: None,
                    response_time_ms,
                    error: Some(error_msg),
                }
            }
            Err(_) => {
                let error_msg = "Health check timed out".to_string();
                let mut states = self.health_states.write().await;
                if let Some(state) = states.get_mut(&backend_type) {
                    state.record_failure(&error_msg);
                }

                HealthCheckResult {
                    backend_type,
                    timestamp: Utc::now(),
                    healthy: false,
                    status: None,
                    response_time_ms,
                    error: Some(error_msg),
                }
            }
        };

        debug!(
            backend = ?backend_type,
            healthy = check_result.healthy,
            response_time_ms = response_time_ms,
            "Health check completed"
        );

        Some(check_result)
    }

    /// Check all registered backends
    pub async fn check_all(&self) -> Vec<HealthCheckResult> {
        let backend_types: Vec<_> = {
            let backends = self.backends.read().await;
            backends.keys().copied().collect()
        };

        let mut results = Vec::new();
        for backend_type in backend_types {
            if let Some(result) = self.check_backend(backend_type).await {
                results.push(result);
            }
        }

        results
    }

    /// Start background health monitoring
    pub async fn start(self: Arc<Self>) {
        if !self.config.active_checks {
            return;
        }

        if self.running.swap(true, Ordering::SeqCst) {
            return; // Already running
        }

        let monitor = self.clone();
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(monitor.config.check_interval_secs));

            while monitor.running.load(Ordering::SeqCst) {
                ticker.tick().await;
                monitor.check_all().await;
            }
        });

        info!(
            interval_secs = self.config.check_interval_secs,
            "Started health monitoring"
        );
    }

    /// Stop background health monitoring
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        info!("Stopped health monitoring");
    }

    /// Get health state for a backend
    pub async fn get_health(&self, backend_type: BackendType) -> Option<BackendHealth> {
        let states = self.health_states.read().await;
        states.get(&backend_type).cloned()
    }

    /// Get all health states
    pub async fn get_all_health(&self) -> HashMap<BackendType, BackendHealth> {
        let states = self.health_states.read().await;
        states.clone()
    }

    /// Get health summary
    pub async fn get_summary(&self) -> HealthSummary {
        let states = self.health_states.read().await;

        let total = states.len();
        let healthy = states.values().filter(|h| h.healthy).count();
        let unhealthy = total - healthy;

        let avg_response_time = if total > 0 {
            states.values().map(|h| h.avg_response_time_ms).sum::<f64>() / total as f64
        } else {
            0.0
        };

        HealthSummary {
            total_backends: total,
            healthy_backends: healthy,
            unhealthy_backends: unhealthy,
            avg_response_time_ms: avg_response_time,
            backends: states
                .iter()
                .map(|(bt, h)| {
                    (
                        *bt,
                        BackendHealthSummary {
                            healthy: h.healthy,
                            last_check: h.last_check,
                            avg_response_time_ms: h.avg_response_time_ms,
                        },
                    )
                })
                .collect(),
        }
    }
}

/// Health summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthSummary {
    /// Total registered backends
    pub total_backends: usize,
    /// Number of healthy backends
    pub healthy_backends: usize,
    /// Number of unhealthy backends
    pub unhealthy_backends: usize,
    /// Average response time across all backends
    pub avg_response_time_ms: f64,
    /// Per-backend summary
    pub backends: HashMap<BackendType, BackendHealthSummary>,
}

/// Backend health summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendHealthSummary {
    /// Is healthy
    pub healthy: bool,
    /// Last check timestamp
    pub last_check: Option<DateTime<Utc>>,
    /// Average response time
    pub avg_response_time_ms: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_health_new() {
        let health = BackendHealth::new(BackendType::Local);
        assert!(health.healthy);
        assert_eq!(health.failure_count, 0);
        assert_eq!(health.success_count, 0);
    }

    #[test]
    fn test_health_record_success() {
        let mut health = BackendHealth::new(BackendType::Local);
        health.record_success(HealthStatus::healthy(), 10);

        assert_eq!(health.success_count, 1);
        assert_eq!(health.failure_count, 0);
        assert!(health.last_check.is_some());
    }

    #[test]
    fn test_health_record_failure() {
        let mut health = BackendHealth::new(BackendType::Local);

        // Need 3 consecutive failures to mark unhealthy
        health.record_failure("error 1");
        assert!(health.healthy);

        health.record_failure("error 2");
        assert!(health.healthy);

        health.record_failure("error 3");
        assert!(!health.healthy);
        assert!(health.unhealthy_since.is_some());
    }

    #[test]
    fn test_monitor_config_default() {
        let config = HealthMonitorConfig::default();
        assert_eq!(config.check_interval_secs, 30);
        assert!(config.active_checks);
    }
}
