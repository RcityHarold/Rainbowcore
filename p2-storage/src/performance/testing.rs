//! Performance and Fault Testing Framework
//!
//! Provides infrastructure for real-world testing of:
//! - T-14: Three-phase sync latency < 2s (p99)
//! - T-15: Concurrent connections >= 1000
//! - T-19: Network partition - data not lost
//! - T-20: Key unavailability - read fails but data protected

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, error, info, warn};

// ============================================================================
// Performance Test Harness (ISSUE-028)
// ============================================================================

/// Performance test configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceTestConfig {
    /// Test name
    pub name: String,
    /// Target latency (for latency tests) in milliseconds
    pub target_latency_ms: Option<u64>,
    /// Target throughput (operations per second)
    pub target_ops_per_sec: Option<u64>,
    /// Target concurrent connections
    pub target_concurrent: Option<usize>,
    /// Test duration in seconds
    pub duration_secs: u64,
    /// Warmup duration in seconds
    pub warmup_secs: u64,
    /// Number of worker tasks
    pub workers: usize,
    /// Operations per worker
    pub ops_per_worker: u64,
    /// Payload size range (min, max)
    pub payload_size_range: (u64, u64),
    /// Enable detailed metrics
    pub detailed_metrics: bool,
}

impl Default for PerformanceTestConfig {
    fn default() -> Self {
        Self {
            name: "performance_test".to_string(),
            target_latency_ms: Some(2000), // 2s for three-phase sync
            target_ops_per_sec: None,
            target_concurrent: Some(1000),
            duration_secs: 60,
            warmup_secs: 10,
            workers: 100,
            ops_per_worker: 100,
            payload_size_range: (1024, 1024 * 1024), // 1KB to 1MB
            detailed_metrics: true,
        }
    }
}

/// Three-phase sync test configuration
impl PerformanceTestConfig {
    /// Create config for three-phase sync latency test (T-14)
    pub fn three_phase_sync_test() -> Self {
        Self {
            name: "T-14: Three-Phase Sync Latency".to_string(),
            target_latency_ms: Some(2000), // < 2s p99
            target_ops_per_sec: None,
            target_concurrent: None,
            duration_secs: 300, // 5 minutes
            warmup_secs: 30,
            workers: 50,
            ops_per_worker: 200,
            payload_size_range: (1024, 100 * 1024), // 1KB to 100KB
            detailed_metrics: true,
        }
    }

    /// Create config for concurrent connection test (T-15)
    pub fn concurrent_connection_test() -> Self {
        Self {
            name: "T-15: Concurrent Connections".to_string(),
            target_latency_ms: None,
            target_ops_per_sec: None,
            target_concurrent: Some(1000), // >= 1000 concurrent
            duration_secs: 60,
            warmup_secs: 10,
            workers: 1000,
            ops_per_worker: 10,
            payload_size_range: (1024, 10 * 1024), // 1KB to 10KB
            detailed_metrics: true,
        }
    }
}

/// Performance test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceTestResult {
    /// Test configuration
    pub config: PerformanceTestConfig,
    /// Test start time
    pub started_at: DateTime<Utc>,
    /// Test end time
    pub ended_at: DateTime<Utc>,
    /// Total operations completed
    pub total_ops: u64,
    /// Successful operations
    pub successful_ops: u64,
    /// Failed operations
    pub failed_ops: u64,
    /// Latency percentiles (p50, p90, p95, p99)
    pub latency_percentiles: LatencyPercentiles,
    /// Maximum concurrent connections achieved
    pub max_concurrent: usize,
    /// Average throughput (ops/sec)
    pub avg_throughput: f64,
    /// Test passed
    pub passed: bool,
    /// Pass/fail reasons
    pub reasons: Vec<String>,
    /// Detailed error breakdown
    pub error_breakdown: HashMap<String, u64>,
}

/// Latency percentiles
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LatencyPercentiles {
    pub p50_ms: f64,
    pub p90_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
    pub min_ms: f64,
    pub mean_ms: f64,
}

impl LatencyPercentiles {
    /// Calculate percentiles from samples (in milliseconds)
    pub fn from_samples(samples: &[f64]) -> Self {
        if samples.is_empty() {
            return Self::default();
        }

        let mut sorted = samples.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let len = sorted.len();
        let min_ms = sorted[0];
        let max_ms = sorted[len - 1];
        let mean_ms = samples.iter().sum::<f64>() / len as f64;

        let percentile = |p: f64| -> f64 {
            let idx = ((p / 100.0) * (len - 1) as f64).round() as usize;
            sorted[idx.min(len - 1)]
        };

        Self {
            p50_ms: percentile(50.0),
            p90_ms: percentile(90.0),
            p95_ms: percentile(95.0),
            p99_ms: percentile(99.0),
            max_ms,
            min_ms,
            mean_ms,
        }
    }
}

/// Performance test harness
pub struct PerformanceTestHarness {
    /// Active concurrent connections
    active_connections: AtomicU64,
    /// Maximum concurrent connections seen
    max_connections: AtomicU64,
    /// Latency samples (in ms)
    latency_samples: RwLock<Vec<f64>>,
    /// Error counts by type
    error_counts: RwLock<HashMap<String, u64>>,
    /// Test running flag
    running: AtomicBool,
    /// Connection semaphore for limiting concurrency
    connection_limit: Option<Semaphore>,
}

impl PerformanceTestHarness {
    /// Create a new test harness
    pub fn new(max_concurrent: Option<usize>) -> Self {
        Self {
            active_connections: AtomicU64::new(0),
            max_connections: AtomicU64::new(0),
            latency_samples: RwLock::new(Vec::with_capacity(100000)),
            error_counts: RwLock::new(HashMap::new()),
            running: AtomicBool::new(false),
            connection_limit: max_concurrent.map(Semaphore::new),
        }
    }

    /// Start a connection (for tracking concurrency)
    pub fn start_connection(&self) -> Option<ConnectionGuard> {
        if !self.running.load(Ordering::Relaxed) {
            return None;
        }

        let current = self.active_connections.fetch_add(1, Ordering::SeqCst) + 1;

        // Update max if needed
        loop {
            let max = self.max_connections.load(Ordering::Relaxed);
            if current <= max {
                break;
            }
            if self.max_connections.compare_exchange(
                max, current as u64, Ordering::SeqCst, Ordering::Relaxed
            ).is_ok() {
                break;
            }
        }

        Some(ConnectionGuard {
            harness: self,
        })
    }

    /// Record a latency sample
    pub async fn record_latency(&self, latency_ms: f64) {
        let mut samples = self.latency_samples.write().await;
        samples.push(latency_ms);
    }

    /// Record an error
    pub async fn record_error(&self, error_type: &str) {
        let mut errors = self.error_counts.write().await;
        *errors.entry(error_type.to_string()).or_insert(0) += 1;
    }

    /// Get current metrics
    pub async fn get_current_metrics(&self) -> CurrentMetrics {
        let samples = self.latency_samples.read().await;
        let errors = self.error_counts.read().await;

        CurrentMetrics {
            active_connections: self.active_connections.load(Ordering::Relaxed) as usize,
            max_connections: self.max_connections.load(Ordering::Relaxed) as usize,
            total_samples: samples.len(),
            total_errors: errors.values().sum(),
        }
    }

    /// Run a performance test
    pub async fn run_test<F, Fut>(
        &self,
        config: PerformanceTestConfig,
        operation: F,
    ) -> PerformanceTestResult
    where
        F: Fn(usize) -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = Result<Duration, String>> + Send,
    {
        self.running.store(true, Ordering::SeqCst);
        let started_at = Utc::now();

        info!(test = %config.name, "Starting performance test");

        // Warmup phase
        if config.warmup_secs > 0 {
            info!(warmup_secs = config.warmup_secs, "Starting warmup");
            tokio::time::sleep(Duration::from_secs(config.warmup_secs)).await;
        }

        // Clear any warmup data
        self.latency_samples.write().await.clear();
        self.error_counts.write().await.clear();
        self.max_connections.store(0, Ordering::SeqCst);

        // Spawn workers
        let mut handles = Vec::new();
        let operation = Arc::new(operation);
        let harness = Arc::new(self);

        for worker_id in 0..config.workers {
            let op = operation.clone();
            let h = harness.clone();
            let ops = config.ops_per_worker;

            handles.push(tokio::spawn(async move {
                let mut successful = 0u64;
                let mut failed = 0u64;

                for i in 0..ops {
                    let _guard = h.start_connection();

                    let start = Instant::now();
                    match op(worker_id * ops as usize + i as usize).await {
                        Ok(duration) => {
                            h.record_latency(duration.as_secs_f64() * 1000.0).await;
                            successful += 1;
                        }
                        Err(e) => {
                            h.record_error(&e).await;
                            failed += 1;
                        }
                    }
                }

                (successful, failed)
            }));
        }

        // Wait for all workers
        let mut total_successful = 0u64;
        let mut total_failed = 0u64;

        for handle in handles {
            match handle.await {
                Ok((s, f)) => {
                    total_successful += s;
                    total_failed += f;
                }
                Err(e) => {
                    error!(error = %e, "Worker task failed");
                    total_failed += config.ops_per_worker;
                }
            }
        }

        self.running.store(false, Ordering::SeqCst);
        let ended_at = Utc::now();

        // Calculate results
        let samples = self.latency_samples.read().await;
        let errors = self.error_counts.read().await;
        let latency_percentiles = LatencyPercentiles::from_samples(&samples);

        let duration_secs = (ended_at - started_at).num_seconds().max(1) as f64;
        let total_ops = total_successful + total_failed;
        let avg_throughput = total_ops as f64 / duration_secs;
        let max_concurrent = self.max_connections.load(Ordering::Relaxed) as usize;

        // Determine pass/fail
        let mut passed = true;
        let mut reasons = Vec::new();

        if let Some(target) = config.target_latency_ms {
            if latency_percentiles.p99_ms > target as f64 {
                passed = false;
                reasons.push(format!(
                    "p99 latency {:.2}ms exceeds target {}ms",
                    latency_percentiles.p99_ms, target
                ));
            } else {
                reasons.push(format!(
                    "p99 latency {:.2}ms meets target {}ms",
                    latency_percentiles.p99_ms, target
                ));
            }
        }

        if let Some(target) = config.target_concurrent {
            if max_concurrent < target {
                passed = false;
                reasons.push(format!(
                    "max concurrent {} below target {}",
                    max_concurrent, target
                ));
            } else {
                reasons.push(format!(
                    "max concurrent {} meets target {}",
                    max_concurrent, target
                ));
            }
        }

        if let Some(target) = config.target_ops_per_sec {
            if avg_throughput < target as f64 {
                passed = false;
                reasons.push(format!(
                    "throughput {:.2} ops/s below target {}",
                    avg_throughput, target
                ));
            } else {
                reasons.push(format!(
                    "throughput {:.2} ops/s meets target {}",
                    avg_throughput, target
                ));
            }
        }

        info!(
            test = %config.name,
            passed = passed,
            p99_ms = latency_percentiles.p99_ms,
            max_concurrent = max_concurrent,
            throughput = avg_throughput,
            "Performance test completed"
        );

        PerformanceTestResult {
            config,
            started_at,
            ended_at,
            total_ops,
            successful_ops: total_successful,
            failed_ops: total_failed,
            latency_percentiles,
            max_concurrent,
            avg_throughput,
            passed,
            reasons,
            error_breakdown: errors.clone(),
        }
    }
}

/// Guard for tracking active connections
pub struct ConnectionGuard<'a> {
    harness: &'a PerformanceTestHarness,
}

impl Drop for ConnectionGuard<'_> {
    fn drop(&mut self) {
        self.harness.active_connections.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Current test metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentMetrics {
    pub active_connections: usize,
    pub max_connections: usize,
    pub total_samples: usize,
    pub total_errors: u64,
}

// ============================================================================
// Fault Testing Framework (ISSUE-029)
// ============================================================================

/// Fault injection type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultType {
    /// Network partition (node unreachable)
    NetworkPartition,
    /// Network latency injection
    NetworkLatency,
    /// Packet loss
    PacketLoss,
    /// Key/encryption unavailable
    KeyUnavailable,
    /// Storage backend failure
    StorageFailure,
    /// Memory pressure
    MemoryPressure,
    /// CPU throttling
    CpuThrottle,
    /// Disk full
    DiskFull,
}

/// Fault injection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultConfig {
    /// Fault type to inject
    pub fault_type: FaultType,
    /// Duration of fault in seconds
    pub duration_secs: u64,
    /// Fault intensity (0.0 - 1.0)
    pub intensity: f64,
    /// Target nodes (empty = all nodes)
    pub target_nodes: Vec<String>,
    /// Affected percentage of operations (0.0 - 1.0)
    pub affected_ratio: f64,
}

impl Default for FaultConfig {
    fn default() -> Self {
        Self {
            fault_type: FaultType::NetworkPartition,
            duration_secs: 30,
            intensity: 1.0,
            target_nodes: Vec::new(),
            affected_ratio: 1.0,
        }
    }
}

impl FaultConfig {
    /// Create network partition test config (T-19)
    pub fn network_partition_test() -> Self {
        Self {
            fault_type: FaultType::NetworkPartition,
            duration_secs: 60,
            intensity: 1.0,
            target_nodes: Vec::new(),
            affected_ratio: 0.5, // Partition half the nodes
        }
    }

    /// Create key unavailability test config (T-20)
    pub fn key_unavailable_test() -> Self {
        Self {
            fault_type: FaultType::KeyUnavailable,
            duration_secs: 30,
            intensity: 1.0,
            target_nodes: Vec::new(),
            affected_ratio: 1.0,
        }
    }
}

/// Fault test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultTestResult {
    /// Test ID
    pub test_id: String,
    /// Fault configuration
    pub config: FaultConfig,
    /// Test start time
    pub started_at: DateTime<Utc>,
    /// Test end time
    pub ended_at: DateTime<Utc>,
    /// Data integrity check passed
    pub data_integrity_ok: bool,
    /// Operations before fault
    pub ops_before_fault: u64,
    /// Operations during fault
    pub ops_during_fault: OperationStats,
    /// Operations after recovery
    pub ops_after_recovery: u64,
    /// Recovery time in seconds
    pub recovery_time_secs: f64,
    /// Test passed (meets requirements)
    pub passed: bool,
    /// Test notes/observations
    pub notes: Vec<String>,
}

/// Operation statistics during fault
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OperationStats {
    /// Total attempted
    pub attempted: u64,
    /// Successful
    pub successful: u64,
    /// Failed as expected (graceful degradation)
    pub failed_expected: u64,
    /// Failed unexpectedly
    pub failed_unexpected: u64,
    /// Data loss detected
    pub data_loss: u64,
}

/// Fault injector for testing
pub struct FaultInjector {
    /// Active faults
    active_faults: RwLock<HashMap<String, ActiveFault>>,
    /// Fault history
    fault_history: RwLock<Vec<FaultRecord>>,
    /// Running flag
    running: AtomicBool,
}

/// Active fault state
#[derive(Debug, Clone)]
pub struct ActiveFault {
    /// Fault ID
    pub fault_id: String,
    /// Configuration
    pub config: FaultConfig,
    /// Started at
    pub started_at: DateTime<Utc>,
    /// Scheduled end
    pub scheduled_end: DateTime<Utc>,
}

/// Fault record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultRecord {
    /// Fault ID
    pub fault_id: String,
    /// Configuration
    pub config: FaultConfig,
    /// Started at
    pub started_at: DateTime<Utc>,
    /// Ended at
    pub ended_at: DateTime<Utc>,
    /// Impact summary
    pub impact: String,
}

impl FaultInjector {
    /// Create a new fault injector
    pub fn new() -> Self {
        Self {
            active_faults: RwLock::new(HashMap::new()),
            fault_history: RwLock::new(Vec::new()),
            running: AtomicBool::new(true),
        }
    }

    /// Inject a fault
    pub async fn inject_fault(&self, config: FaultConfig) -> String {
        let fault_id = format!("fault:{}:{}",
            config.fault_type as u8,
            Utc::now().timestamp_micros()
        );

        let active_fault = ActiveFault {
            fault_id: fault_id.clone(),
            config: config.clone(),
            started_at: Utc::now(),
            scheduled_end: Utc::now() + chrono::Duration::seconds(config.duration_secs as i64),
        };

        self.active_faults.write().await.insert(fault_id.clone(), active_fault);

        info!(
            fault_id = %fault_id,
            fault_type = ?config.fault_type,
            duration_secs = config.duration_secs,
            "Fault injected"
        );

        fault_id
    }

    /// Remove a fault
    pub async fn remove_fault(&self, fault_id: &str) -> bool {
        if let Some(fault) = self.active_faults.write().await.remove(fault_id) {
            let record = FaultRecord {
                fault_id: fault.fault_id,
                config: fault.config,
                started_at: fault.started_at,
                ended_at: Utc::now(),
                impact: "Removed manually".to_string(),
            };
            self.fault_history.write().await.push(record);

            info!(fault_id = %fault_id, "Fault removed");
            true
        } else {
            false
        }
    }

    /// Check if a fault should affect an operation
    pub async fn should_fail(&self, fault_type: FaultType, node_id: Option<&str>) -> bool {
        let faults = self.active_faults.read().await;

        for fault in faults.values() {
            if fault.config.fault_type != fault_type {
                continue;
            }

            // Check if fault is still active
            if Utc::now() > fault.scheduled_end {
                continue;
            }

            // Check target nodes
            if !fault.config.target_nodes.is_empty() {
                if let Some(node) = node_id {
                    if !fault.config.target_nodes.contains(&node.to_string()) {
                        continue;
                    }
                }
            }

            // Check affected ratio
            if fault.config.affected_ratio < 1.0 {
                let random: f64 = rand_value();
                if random > fault.config.affected_ratio {
                    continue;
                }
            }

            return true;
        }

        false
    }

    /// Get active faults
    pub async fn get_active_faults(&self) -> Vec<ActiveFault> {
        self.active_faults.read().await.values().cloned().collect()
    }

    /// Get fault history
    pub async fn get_history(&self, limit: usize) -> Vec<FaultRecord> {
        let history = self.fault_history.read().await;
        history.iter().rev().take(limit).cloned().collect()
    }

    /// Clean up expired faults
    pub async fn cleanup_expired(&self) {
        let now = Utc::now();
        let mut faults = self.active_faults.write().await;
        let mut history = self.fault_history.write().await;

        let expired: Vec<_> = faults.iter()
            .filter(|(_, f)| now > f.scheduled_end)
            .map(|(k, _)| k.clone())
            .collect();

        for fault_id in expired {
            if let Some(fault) = faults.remove(&fault_id) {
                let record = FaultRecord {
                    fault_id: fault.fault_id,
                    config: fault.config,
                    started_at: fault.started_at,
                    ended_at: Utc::now(),
                    impact: "Expired".to_string(),
                };
                history.push(record);
                info!(fault_id = %fault_id, "Fault expired and removed");
            }
        }
    }
}

impl Default for FaultInjector {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a pseudo-random value between 0.0 and 1.0
fn rand_value() -> f64 {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    let nanos = duration.subsec_nanos() as f64;
    nanos / 1_000_000_000.0
}

/// Fault test harness
pub struct FaultTestHarness {
    /// Fault injector
    pub injector: FaultInjector,
    /// Data integrity checker
    data_checksums: RwLock<HashMap<String, String>>,
    /// Operation stats during fault
    fault_stats: RwLock<OperationStats>,
}

impl FaultTestHarness {
    /// Create a new fault test harness
    pub fn new() -> Self {
        Self {
            injector: FaultInjector::new(),
            data_checksums: RwLock::new(HashMap::new()),
            fault_stats: RwLock::new(OperationStats::default()),
        }
    }

    /// Register data for integrity checking
    pub async fn register_data(&self, key: &str, checksum: &str) {
        self.data_checksums.write().await.insert(key.to_string(), checksum.to_string());
    }

    /// Verify data integrity after fault
    pub async fn verify_integrity<F, Fut>(&self, get_checksum: F) -> DataIntegrityResult
    where
        F: Fn(String) -> Fut,
        Fut: std::future::Future<Output = Option<String>>,
    {
        let checksums = self.data_checksums.read().await;
        let mut verified = 0;
        let mut corrupted = 0;
        let mut missing = 0;
        let mut corrupted_keys = Vec::new();
        let mut missing_keys = Vec::new();

        for (key, expected) in checksums.iter() {
            match get_checksum(key.clone()).await {
                Some(actual) if actual == *expected => verified += 1,
                Some(_) => {
                    corrupted += 1;
                    corrupted_keys.push(key.clone());
                }
                None => {
                    missing += 1;
                    missing_keys.push(key.clone());
                }
            }
        }

        DataIntegrityResult {
            total_keys: checksums.len(),
            verified,
            corrupted,
            missing,
            corrupted_keys,
            missing_keys,
            integrity_ok: corrupted == 0 && missing == 0,
        }
    }

    /// Record fault operation result
    pub async fn record_operation(&self, success: bool, expected_failure: bool, data_loss: bool) {
        let mut stats = self.fault_stats.write().await;
        stats.attempted += 1;

        if success {
            stats.successful += 1;
        } else if expected_failure {
            stats.failed_expected += 1;
        } else {
            stats.failed_unexpected += 1;
        }

        if data_loss {
            stats.data_loss += 1;
        }
    }

    /// Get fault operation stats
    pub async fn get_stats(&self) -> OperationStats {
        self.fault_stats.read().await.clone()
    }

    /// Reset stats
    pub async fn reset_stats(&self) {
        *self.fault_stats.write().await = OperationStats::default();
    }
}

impl Default for FaultTestHarness {
    fn default() -> Self {
        Self::new()
    }
}

/// Data integrity verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataIntegrityResult {
    /// Total keys checked
    pub total_keys: usize,
    /// Successfully verified
    pub verified: usize,
    /// Corrupted (checksum mismatch)
    pub corrupted: usize,
    /// Missing (not found)
    pub missing: usize,
    /// Corrupted keys
    pub corrupted_keys: Vec<String>,
    /// Missing keys
    pub missing_keys: Vec<String>,
    /// Overall integrity OK
    pub integrity_ok: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latency_percentiles() {
        let samples: Vec<f64> = (0..100).map(|i| i as f64).collect();
        let percentiles = LatencyPercentiles::from_samples(&samples);

        assert_eq!(percentiles.min_ms, 0.0);
        assert_eq!(percentiles.max_ms, 99.0);
        assert!(percentiles.p50_ms >= 49.0 && percentiles.p50_ms <= 50.0);
        assert!(percentiles.p99_ms >= 98.0 && percentiles.p99_ms <= 99.0);
    }

    #[test]
    fn test_fault_config() {
        let config = FaultConfig::network_partition_test();
        assert_eq!(config.fault_type, FaultType::NetworkPartition);
        assert_eq!(config.duration_secs, 60);

        let config = FaultConfig::key_unavailable_test();
        assert_eq!(config.fault_type, FaultType::KeyUnavailable);
    }

    #[tokio::test]
    async fn test_fault_injector() {
        let injector = FaultInjector::new();

        let fault_id = injector.inject_fault(FaultConfig {
            fault_type: FaultType::NetworkPartition,
            duration_secs: 10,
            intensity: 1.0,
            target_nodes: Vec::new(),
            affected_ratio: 1.0,
        }).await;

        assert!(injector.should_fail(FaultType::NetworkPartition, None).await);
        assert!(!injector.should_fail(FaultType::KeyUnavailable, None).await);

        injector.remove_fault(&fault_id).await;
        assert!(!injector.should_fail(FaultType::NetworkPartition, None).await);
    }

    #[tokio::test]
    async fn test_performance_test_config() {
        let config = PerformanceTestConfig::three_phase_sync_test();
        assert_eq!(config.target_latency_ms, Some(2000));

        let config = PerformanceTestConfig::concurrent_connection_test();
        assert_eq!(config.target_concurrent, Some(1000));
    }
}
