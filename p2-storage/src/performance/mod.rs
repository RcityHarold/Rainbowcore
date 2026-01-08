//! Performance Testing and Validation Module
//!
//! Implements acceptance criteria tracking for:
//! - ISSUE-021: Write latency < 10ms (p99)
//! - ISSUE-022: Preheat latency < 5s (Cold->Hot)
//! - ISSUE-023: Daily sampling 0.1% of payloads
//! - ISSUE-024: Replication delay < 100ms sync, < 1min async
//!
//! Also provides testing infrastructure for:
//! - ISSUE-028: Performance testing (T-14, T-15)
//! - ISSUE-029: Fault testing (T-19, T-20)

pub mod testing;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Performance metrics collector
#[derive(Debug)]
pub struct PerformanceCollector {
    /// Write latency samples (microseconds)
    write_latencies: RwLock<VecDeque<u64>>,
    /// Read latency samples (microseconds)
    read_latencies: RwLock<VecDeque<u64>>,
    /// Preheat latency samples (milliseconds)
    preheat_latencies: RwLock<VecDeque<u64>>,
    /// Sync replication latency samples (milliseconds)
    sync_repl_latencies: RwLock<VecDeque<u64>>,
    /// Async replication latency samples (milliseconds)
    async_repl_latencies: RwLock<VecDeque<u64>>,
    /// Maximum samples to keep
    max_samples: usize,
    /// Total operations counters
    total_writes: AtomicU64,
    total_reads: AtomicU64,
    total_preheats: AtomicU64,
}

impl PerformanceCollector {
    /// Create a new collector with default sample size
    pub fn new() -> Self {
        Self::with_max_samples(10000)
    }

    /// Create a new collector with custom sample size
    pub fn with_max_samples(max_samples: usize) -> Self {
        Self {
            write_latencies: RwLock::new(VecDeque::with_capacity(max_samples)),
            read_latencies: RwLock::new(VecDeque::with_capacity(max_samples)),
            preheat_latencies: RwLock::new(VecDeque::with_capacity(max_samples)),
            sync_repl_latencies: RwLock::new(VecDeque::with_capacity(max_samples)),
            async_repl_latencies: RwLock::new(VecDeque::with_capacity(max_samples)),
            max_samples,
            total_writes: AtomicU64::new(0),
            total_reads: AtomicU64::new(0),
            total_preheats: AtomicU64::new(0),
        }
    }

    /// Record a write latency (in microseconds)
    pub async fn record_write_latency(&self, latency_us: u64) {
        let mut latencies = self.write_latencies.write().await;
        if latencies.len() >= self.max_samples {
            latencies.pop_front();
        }
        latencies.push_back(latency_us);
        self.total_writes.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a read latency (in microseconds)
    pub async fn record_read_latency(&self, latency_us: u64) {
        let mut latencies = self.read_latencies.write().await;
        if latencies.len() >= self.max_samples {
            latencies.pop_front();
        }
        latencies.push_back(latency_us);
        self.total_reads.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a preheat latency (in milliseconds)
    pub async fn record_preheat_latency(&self, latency_ms: u64) {
        let mut latencies = self.preheat_latencies.write().await;
        if latencies.len() >= self.max_samples {
            latencies.pop_front();
        }
        latencies.push_back(latency_ms);
        self.total_preheats.fetch_add(1, Ordering::Relaxed);
    }

    /// Record sync replication latency (in milliseconds)
    pub async fn record_sync_repl_latency(&self, latency_ms: u64) {
        let mut latencies = self.sync_repl_latencies.write().await;
        if latencies.len() >= self.max_samples {
            latencies.pop_front();
        }
        latencies.push_back(latency_ms);
    }

    /// Record async replication latency (in milliseconds)
    pub async fn record_async_repl_latency(&self, latency_ms: u64) {
        let mut latencies = self.async_repl_latencies.write().await;
        if latencies.len() >= self.max_samples {
            latencies.pop_front();
        }
        latencies.push_back(latency_ms);
    }

    /// Calculate percentile from samples
    fn percentile(samples: &[u64], p: f64) -> Option<u64> {
        if samples.is_empty() {
            return None;
        }
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        let idx = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
        Some(sorted[idx.min(sorted.len() - 1)])
    }

    /// Get write latency statistics
    pub async fn get_write_stats(&self) -> LatencyStats {
        let latencies = self.write_latencies.read().await;
        let samples: Vec<u64> = latencies.iter().copied().collect();
        LatencyStats::from_samples(&samples, "write_latency_us")
    }

    /// Get read latency statistics
    pub async fn get_read_stats(&self) -> LatencyStats {
        let latencies = self.read_latencies.read().await;
        let samples: Vec<u64> = latencies.iter().copied().collect();
        LatencyStats::from_samples(&samples, "read_latency_us")
    }

    /// Get preheat latency statistics
    pub async fn get_preheat_stats(&self) -> LatencyStats {
        let latencies = self.preheat_latencies.read().await;
        let samples: Vec<u64> = latencies.iter().copied().collect();
        LatencyStats::from_samples(&samples, "preheat_latency_ms")
    }

    /// Get sync replication latency statistics
    pub async fn get_sync_repl_stats(&self) -> LatencyStats {
        let latencies = self.sync_repl_latencies.read().await;
        let samples: Vec<u64> = latencies.iter().copied().collect();
        LatencyStats::from_samples(&samples, "sync_repl_latency_ms")
    }

    /// Get async replication latency statistics
    pub async fn get_async_repl_stats(&self) -> LatencyStats {
        let latencies = self.async_repl_latencies.read().await;
        let samples: Vec<u64> = latencies.iter().copied().collect();
        LatencyStats::from_samples(&samples, "async_repl_latency_ms")
    }

    /// Generate acceptance criteria report
    pub async fn generate_acceptance_report(&self) -> AcceptanceReport {
        let write_stats = self.get_write_stats().await;
        let preheat_stats = self.get_preheat_stats().await;
        let sync_repl_stats = self.get_sync_repl_stats().await;
        let async_repl_stats = self.get_async_repl_stats().await;

        // ISSUE-021: Write latency < 10ms (p99) = 10000us
        let write_latency_pass = write_stats.p99.map(|p99| p99 < 10000).unwrap_or(false);

        // ISSUE-022: Preheat latency < 5s = 5000ms
        let preheat_latency_pass = preheat_stats.p99.map(|p99| p99 < 5000).unwrap_or(false);

        // ISSUE-024: Sync replication < 100ms
        let sync_repl_pass = sync_repl_stats.p99.map(|p99| p99 < 100).unwrap_or(false);

        // ISSUE-024: Async replication < 60000ms (1 min)
        let async_repl_pass = async_repl_stats.p99.map(|p99| p99 < 60000).unwrap_or(false);

        AcceptanceReport {
            generated_at: Utc::now(),
            criteria: vec![
                AcceptanceCriterion {
                    id: "ISSUE-021".to_string(),
                    name: "Write Latency".to_string(),
                    target: "< 10ms (p99)".to_string(),
                    actual: write_stats.p99.map(|v| format!("{}us", v)).unwrap_or("N/A".to_string()),
                    passed: write_latency_pass,
                    sample_count: write_stats.sample_count,
                },
                AcceptanceCriterion {
                    id: "ISSUE-022".to_string(),
                    name: "Preheat Latency (Cold->Hot)".to_string(),
                    target: "< 5s (p99)".to_string(),
                    actual: preheat_stats.p99.map(|v| format!("{}ms", v)).unwrap_or("N/A".to_string()),
                    passed: preheat_latency_pass,
                    sample_count: preheat_stats.sample_count,
                },
                AcceptanceCriterion {
                    id: "ISSUE-024a".to_string(),
                    name: "Sync Replication Latency".to_string(),
                    target: "< 100ms (p99)".to_string(),
                    actual: sync_repl_stats.p99.map(|v| format!("{}ms", v)).unwrap_or("N/A".to_string()),
                    passed: sync_repl_pass,
                    sample_count: sync_repl_stats.sample_count,
                },
                AcceptanceCriterion {
                    id: "ISSUE-024b".to_string(),
                    name: "Async Replication Latency".to_string(),
                    target: "< 1min (p99)".to_string(),
                    actual: async_repl_stats.p99.map(|v| format!("{}ms", v)).unwrap_or("N/A".to_string()),
                    passed: async_repl_pass,
                    sample_count: async_repl_stats.sample_count,
                },
            ],
            total_writes: self.total_writes.load(Ordering::Relaxed),
            total_reads: self.total_reads.load(Ordering::Relaxed),
            total_preheats: self.total_preheats.load(Ordering::Relaxed),
        }
    }
}

impl Default for PerformanceCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Latency statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyStats {
    /// Metric name
    pub name: String,
    /// Sample count
    pub sample_count: usize,
    /// Minimum value
    pub min: Option<u64>,
    /// Maximum value
    pub max: Option<u64>,
    /// Mean value
    pub mean: Option<f64>,
    /// Median (p50)
    pub p50: Option<u64>,
    /// 90th percentile
    pub p90: Option<u64>,
    /// 95th percentile
    pub p95: Option<u64>,
    /// 99th percentile
    pub p99: Option<u64>,
}

impl LatencyStats {
    /// Create stats from samples
    pub fn from_samples(samples: &[u64], name: &str) -> Self {
        if samples.is_empty() {
            return Self {
                name: name.to_string(),
                sample_count: 0,
                min: None,
                max: None,
                mean: None,
                p50: None,
                p90: None,
                p95: None,
                p99: None,
            };
        }

        let min = samples.iter().min().copied();
        let max = samples.iter().max().copied();
        let sum: u64 = samples.iter().sum();
        let mean = Some(sum as f64 / samples.len() as f64);

        Self {
            name: name.to_string(),
            sample_count: samples.len(),
            min,
            max,
            mean,
            p50: PerformanceCollector::percentile(samples, 50.0),
            p90: PerformanceCollector::percentile(samples, 90.0),
            p95: PerformanceCollector::percentile(samples, 95.0),
            p99: PerformanceCollector::percentile(samples, 99.0),
        }
    }
}

/// Acceptance criterion result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptanceCriterion {
    /// Issue ID
    pub id: String,
    /// Criterion name
    pub name: String,
    /// Target value
    pub target: String,
    /// Actual measured value
    pub actual: String,
    /// Whether criterion passed
    pub passed: bool,
    /// Number of samples used
    pub sample_count: usize,
}

/// Acceptance criteria report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptanceReport {
    /// Report generation time
    pub generated_at: DateTime<Utc>,
    /// All criteria results
    pub criteria: Vec<AcceptanceCriterion>,
    /// Total write operations
    pub total_writes: u64,
    /// Total read operations
    pub total_reads: u64,
    /// Total preheat operations
    pub total_preheats: u64,
}

impl AcceptanceReport {
    /// Check if all criteria passed
    pub fn all_passed(&self) -> bool {
        self.criteria.iter().all(|c| c.passed || c.sample_count == 0)
    }

    /// Get passed criteria count
    pub fn passed_count(&self) -> usize {
        self.criteria.iter().filter(|c| c.passed).count()
    }

    /// Get failed criteria count
    pub fn failed_count(&self) -> usize {
        self.criteria.iter().filter(|c| !c.passed && c.sample_count > 0).count()
    }

    /// Get criteria with insufficient samples
    pub fn insufficient_samples_count(&self) -> usize {
        self.criteria.iter().filter(|c| c.sample_count == 0).count()
    }
}

// ============================================================================
// Sampling Automation (ISSUE-023)
// ============================================================================

/// Daily sampling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailySamplingConfig {
    /// Sampling rate (0.001 = 0.1%)
    pub sampling_rate: f64,
    /// Minimum samples per day
    pub min_samples: u64,
    /// Maximum samples per day
    pub max_samples: u64,
    /// Enable automatic alerting
    pub auto_alert: bool,
    /// Alert threshold (failure rate)
    pub alert_threshold: f64,
}

impl Default for DailySamplingConfig {
    fn default() -> Self {
        Self {
            sampling_rate: 0.001, // 0.1%
            min_samples: 100,
            max_samples: 100000,
            auto_alert: true,
            alert_threshold: 0.01, // 1% failure rate triggers alert
        }
    }
}

/// Daily sampling result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailySamplingResult {
    /// Date of sampling
    pub date: DateTime<Utc>,
    /// Total payloads in storage
    pub total_payloads: u64,
    /// Payloads sampled
    pub sampled_count: u64,
    /// Actual sampling rate achieved
    pub actual_rate: f64,
    /// Checksum verification passed
    pub checksum_passed: u64,
    /// Checksum verification failed
    pub checksum_failed: u64,
    /// Reachability check passed
    pub reachable_passed: u64,
    /// Reachability check failed
    pub reachable_failed: u64,
    /// Overall pass rate
    pub pass_rate: f64,
    /// Alerts triggered
    pub alerts_triggered: Vec<String>,
}

impl DailySamplingResult {
    /// Check if sampling meets acceptance criteria
    pub fn meets_criteria(&self, config: &DailySamplingConfig) -> bool {
        // Must sample at least 0.1% of payloads
        self.actual_rate >= config.sampling_rate * 0.9 // Allow 10% tolerance
            && self.pass_rate >= (1.0 - config.alert_threshold)
    }
}

/// Daily sampler
pub struct DailySampler {
    config: DailySamplingConfig,
    last_run: RwLock<Option<DateTime<Utc>>>,
    results: RwLock<Vec<DailySamplingResult>>,
}

impl DailySampler {
    /// Create a new daily sampler
    pub fn new(config: DailySamplingConfig) -> Self {
        Self {
            config,
            last_run: RwLock::new(None),
            results: RwLock::new(Vec::new()),
        }
    }

    /// Calculate samples needed for a given payload count
    pub fn calculate_sample_count(&self, total_payloads: u64) -> u64 {
        let target = (total_payloads as f64 * self.config.sampling_rate).ceil() as u64;
        target.max(self.config.min_samples).min(self.config.max_samples)
    }

    /// Record a sampling result
    pub async fn record_result(&self, result: DailySamplingResult) {
        let mut results = self.results.write().await;
        results.push(result);

        // Keep only last 30 days
        if results.len() > 30 {
            results.remove(0);
        }

        *self.last_run.write().await = Some(Utc::now());
    }

    /// Get last run time
    pub async fn last_run_time(&self) -> Option<DateTime<Utc>> {
        *self.last_run.read().await
    }

    /// Check if daily sampling is due
    pub async fn is_due(&self) -> bool {
        match *self.last_run.read().await {
            None => true,
            Some(last) => Utc::now() - last >= Duration::hours(24),
        }
    }

    /// Get recent results
    pub async fn get_recent_results(&self, days: usize) -> Vec<DailySamplingResult> {
        let results = self.results.read().await;
        results.iter().rev().take(days).cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_performance_collector() {
        let collector = PerformanceCollector::new();

        // Record some write latencies
        for i in 0..100 {
            collector.record_write_latency(i * 100).await;
        }

        let stats = collector.get_write_stats().await;
        assert_eq!(stats.sample_count, 100);
        assert!(stats.min.is_some());
        assert!(stats.max.is_some());
        assert!(stats.p99.is_some());
    }

    #[tokio::test]
    async fn test_acceptance_report() {
        let collector = PerformanceCollector::new();

        // Record fast writes (should pass)
        for _ in 0..100 {
            collector.record_write_latency(1000).await; // 1ms = 1000us
        }

        let report = collector.generate_acceptance_report().await;
        assert!(report.criteria.iter().find(|c| c.id == "ISSUE-021").unwrap().passed);
    }

    #[test]
    fn test_daily_sampling_config() {
        let config = DailySamplingConfig::default();
        assert_eq!(config.sampling_rate, 0.001);

        let sampler = DailySampler::new(config);
        let count = sampler.calculate_sample_count(1_000_000);
        assert_eq!(count, 1000); // 0.1% of 1M
    }
}
