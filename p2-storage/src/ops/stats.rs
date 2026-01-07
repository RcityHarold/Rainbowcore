//! Storage Statistics API
//!
//! Provides statistics collection and reporting for storage operations.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Storage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    /// Total objects stored
    pub total_objects: u64,
    /// Total bytes stored
    pub total_bytes: u64,
    /// Objects by temperature tier
    pub objects_by_tier: HashMap<String, u64>,
    /// Bytes by temperature tier
    pub bytes_by_tier: HashMap<String, u64>,
    /// Oldest object timestamp
    pub oldest_object: Option<chrono::DateTime<chrono::Utc>>,
    /// Newest object timestamp
    pub newest_object: Option<chrono::DateTime<chrono::Utc>>,
}

impl Default for StorageStats {
    fn default() -> Self {
        Self {
            total_objects: 0,
            total_bytes: 0,
            objects_by_tier: HashMap::new(),
            bytes_by_tier: HashMap::new(),
            oldest_object: None,
            newest_object: None,
        }
    }
}

/// Operation statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationStats {
    /// Total read operations
    pub reads: u64,
    /// Total write operations
    pub writes: u64,
    /// Total delete operations
    pub deletes: u64,
    /// Total bytes read
    pub bytes_read: u64,
    /// Total bytes written
    pub bytes_written: u64,
    /// Read errors
    pub read_errors: u64,
    /// Write errors
    pub write_errors: u64,
    /// Delete errors
    pub delete_errors: u64,
}

impl Default for OperationStats {
    fn default() -> Self {
        Self {
            reads: 0,
            writes: 0,
            deletes: 0,
            bytes_read: 0,
            bytes_written: 0,
            read_errors: 0,
            write_errors: 0,
            delete_errors: 0,
        }
    }
}

/// Backend-specific statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendStats {
    /// Backend name
    pub name: String,
    /// Backend type
    pub backend_type: String,
    /// Is healthy
    pub healthy: bool,
    /// Storage statistics
    pub storage: StorageStats,
    /// Operation statistics
    pub operations: OperationStats,
    /// Backend-specific metadata
    pub metadata: HashMap<String, String>,
}

impl BackendStats {
    /// Create new backend stats
    pub fn new(name: &str, backend_type: &str) -> Self {
        Self {
            name: name.to_string(),
            backend_type: backend_type.to_string(),
            healthy: true,
            storage: StorageStats::default(),
            operations: OperationStats::default(),
            metadata: HashMap::new(),
        }
    }
}

/// Performance statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceStats {
    /// Average read latency in milliseconds
    pub avg_read_latency_ms: f64,
    /// Average write latency in milliseconds
    pub avg_write_latency_ms: f64,
    /// P50 read latency
    pub p50_read_latency_ms: f64,
    /// P95 read latency
    pub p95_read_latency_ms: f64,
    /// P99 read latency
    pub p99_read_latency_ms: f64,
    /// P50 write latency
    pub p50_write_latency_ms: f64,
    /// P95 write latency
    pub p95_write_latency_ms: f64,
    /// P99 write latency
    pub p99_write_latency_ms: f64,
}

impl Default for PerformanceStats {
    fn default() -> Self {
        Self {
            avg_read_latency_ms: 0.0,
            avg_write_latency_ms: 0.0,
            p50_read_latency_ms: 0.0,
            p95_read_latency_ms: 0.0,
            p99_read_latency_ms: 0.0,
            p50_write_latency_ms: 0.0,
            p95_write_latency_ms: 0.0,
            p99_write_latency_ms: 0.0,
        }
    }
}

/// Throughput statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThroughputStats {
    /// Current reads per second
    pub reads_per_sec: f64,
    /// Current writes per second
    pub writes_per_sec: f64,
    /// Bytes read per second
    pub read_bytes_per_sec: f64,
    /// Bytes written per second
    pub write_bytes_per_sec: f64,
    /// Peak reads per second
    pub peak_reads_per_sec: f64,
    /// Peak writes per second
    pub peak_writes_per_sec: f64,
}

impl Default for ThroughputStats {
    fn default() -> Self {
        Self {
            reads_per_sec: 0.0,
            writes_per_sec: 0.0,
            read_bytes_per_sec: 0.0,
            write_bytes_per_sec: 0.0,
            peak_reads_per_sec: 0.0,
            peak_writes_per_sec: 0.0,
        }
    }
}

/// Statistics response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsResponse {
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Collection period in seconds
    pub period_secs: u64,
    /// Overall storage stats
    pub storage: StorageStats,
    /// Overall operation stats
    pub operations: OperationStats,
    /// Performance stats
    pub performance: PerformanceStats,
    /// Throughput stats
    pub throughput: ThroughputStats,
    /// Per-backend stats
    pub backends: Vec<BackendStats>,
}

/// Atomic counter for thread-safe statistics
#[derive(Debug)]
pub struct AtomicStats {
    reads: AtomicU64,
    writes: AtomicU64,
    deletes: AtomicU64,
    bytes_read: AtomicU64,
    bytes_written: AtomicU64,
    read_errors: AtomicU64,
    write_errors: AtomicU64,
    delete_errors: AtomicU64,
}

impl Default for AtomicStats {
    fn default() -> Self {
        Self {
            reads: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            deletes: AtomicU64::new(0),
            bytes_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            read_errors: AtomicU64::new(0),
            write_errors: AtomicU64::new(0),
            delete_errors: AtomicU64::new(0),
        }
    }
}

impl AtomicStats {
    /// Record a read operation
    pub fn record_read(&self, bytes: u64) {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.bytes_read.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record a write operation
    pub fn record_write(&self, bytes: u64) {
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.bytes_written.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record a delete operation
    pub fn record_delete(&self) {
        self.deletes.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a read error
    pub fn record_read_error(&self) {
        self.read_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a write error
    pub fn record_write_error(&self) {
        self.write_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a delete error
    pub fn record_delete_error(&self) {
        self.delete_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Get current stats
    pub fn get(&self) -> OperationStats {
        OperationStats {
            reads: self.reads.load(Ordering::Relaxed),
            writes: self.writes.load(Ordering::Relaxed),
            deletes: self.deletes.load(Ordering::Relaxed),
            bytes_read: self.bytes_read.load(Ordering::Relaxed),
            bytes_written: self.bytes_written.load(Ordering::Relaxed),
            read_errors: self.read_errors.load(Ordering::Relaxed),
            write_errors: self.write_errors.load(Ordering::Relaxed),
            delete_errors: self.delete_errors.load(Ordering::Relaxed),
        }
    }

    /// Reset all counters
    pub fn reset(&self) {
        self.reads.store(0, Ordering::Relaxed);
        self.writes.store(0, Ordering::Relaxed);
        self.deletes.store(0, Ordering::Relaxed);
        self.bytes_read.store(0, Ordering::Relaxed);
        self.bytes_written.store(0, Ordering::Relaxed);
        self.read_errors.store(0, Ordering::Relaxed);
        self.write_errors.store(0, Ordering::Relaxed);
        self.delete_errors.store(0, Ordering::Relaxed);
    }
}

/// Latency tracker for computing percentiles
#[derive(Debug)]
pub struct LatencyTracker {
    /// Ring buffer of latencies
    samples: RwLock<Vec<f64>>,
    /// Max samples to keep
    max_samples: usize,
}

impl LatencyTracker {
    /// Create new latency tracker
    pub fn new(max_samples: usize) -> Self {
        Self {
            samples: RwLock::new(Vec::with_capacity(max_samples)),
            max_samples,
        }
    }

    /// Record a latency sample
    pub async fn record(&self, latency: Duration) {
        let latency_ms = latency.as_secs_f64() * 1000.0;
        let mut samples = self.samples.write().await;

        if samples.len() >= self.max_samples {
            samples.remove(0);
        }
        samples.push(latency_ms);
    }

    /// Calculate percentile (0-100)
    pub async fn percentile(&self, p: f64) -> f64 {
        let samples = self.samples.read().await;
        if samples.is_empty() {
            return 0.0;
        }

        let mut sorted: Vec<f64> = samples.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let index = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
        sorted.get(index).copied().unwrap_or(0.0)
    }

    /// Calculate average
    pub async fn average(&self) -> f64 {
        let samples = self.samples.read().await;
        if samples.is_empty() {
            return 0.0;
        }

        samples.iter().sum::<f64>() / samples.len() as f64
    }
}

/// Statistics collector
pub struct StatsCollector {
    /// Atomic operation counters
    operations: Arc<AtomicStats>,
    /// Read latency tracker
    read_latency: Arc<LatencyTracker>,
    /// Write latency tracker
    write_latency: Arc<LatencyTracker>,
    /// Collection start time
    start_time: Instant,
    /// Previous snapshot for rate calculation
    previous_snapshot: RwLock<Option<(OperationStats, Instant)>>,
    /// Storage stats provider
    storage_stats_provider: RwLock<Option<Arc<dyn StorageStatsProvider>>>,
    /// Backend stats providers
    backend_providers: RwLock<Vec<Arc<dyn BackendStatsProvider>>>,
}

/// Trait for providing storage statistics
#[async_trait::async_trait]
pub trait StorageStatsProvider: Send + Sync {
    /// Get current storage statistics
    async fn get_storage_stats(&self) -> StorageStats;
}

/// Trait for providing backend statistics
#[async_trait::async_trait]
pub trait BackendStatsProvider: Send + Sync {
    /// Get backend statistics
    async fn get_backend_stats(&self) -> BackendStats;
}

impl StatsCollector {
    /// Create new stats collector
    pub fn new() -> Self {
        Self {
            operations: Arc::new(AtomicStats::default()),
            read_latency: Arc::new(LatencyTracker::new(10000)),
            write_latency: Arc::new(LatencyTracker::new(10000)),
            start_time: Instant::now(),
            previous_snapshot: RwLock::new(None),
            storage_stats_provider: RwLock::new(None),
            backend_providers: RwLock::new(Vec::new()),
        }
    }

    /// Get atomic stats reference for recording
    pub fn operations(&self) -> Arc<AtomicStats> {
        self.operations.clone()
    }

    /// Record read latency
    pub async fn record_read_latency(&self, latency: Duration) {
        self.read_latency.record(latency).await;
    }

    /// Record write latency
    pub async fn record_write_latency(&self, latency: Duration) {
        self.write_latency.record(latency).await;
    }

    /// Set storage stats provider
    pub async fn set_storage_provider(&self, provider: Arc<dyn StorageStatsProvider>) {
        *self.storage_stats_provider.write().await = Some(provider);
    }

    /// Register backend provider
    pub async fn register_backend(&self, provider: Arc<dyn BackendStatsProvider>) {
        self.backend_providers.write().await.push(provider);
    }

    /// Collect all statistics
    pub async fn collect(&self) -> StatsResponse {
        let now = Instant::now();
        let current_ops = self.operations.get();

        // Calculate throughput
        let throughput = {
            let mut prev = self.previous_snapshot.write().await;
            let throughput = if let Some((prev_ops, prev_time)) = prev.as_ref() {
                let elapsed = now.duration_since(*prev_time).as_secs_f64();
                if elapsed > 0.0 {
                    ThroughputStats {
                        reads_per_sec: (current_ops.reads - prev_ops.reads) as f64 / elapsed,
                        writes_per_sec: (current_ops.writes - prev_ops.writes) as f64 / elapsed,
                        read_bytes_per_sec: (current_ops.bytes_read - prev_ops.bytes_read) as f64
                            / elapsed,
                        write_bytes_per_sec: (current_ops.bytes_written - prev_ops.bytes_written)
                            as f64
                            / elapsed,
                        peak_reads_per_sec: 0.0, // Would need historical tracking
                        peak_writes_per_sec: 0.0,
                    }
                } else {
                    ThroughputStats::default()
                }
            } else {
                ThroughputStats::default()
            };

            *prev = Some((current_ops.clone(), now));
            throughput
        };

        // Get performance stats
        let performance = PerformanceStats {
            avg_read_latency_ms: self.read_latency.average().await,
            avg_write_latency_ms: self.write_latency.average().await,
            p50_read_latency_ms: self.read_latency.percentile(50.0).await,
            p95_read_latency_ms: self.read_latency.percentile(95.0).await,
            p99_read_latency_ms: self.read_latency.percentile(99.0).await,
            p50_write_latency_ms: self.write_latency.percentile(50.0).await,
            p95_write_latency_ms: self.write_latency.percentile(95.0).await,
            p99_write_latency_ms: self.write_latency.percentile(99.0).await,
        };

        // Get storage stats
        let storage = if let Some(provider) = self.storage_stats_provider.read().await.as_ref() {
            provider.get_storage_stats().await
        } else {
            StorageStats::default()
        };

        // Get backend stats
        let mut backends = Vec::new();
        for provider in self.backend_providers.read().await.iter() {
            backends.push(provider.get_backend_stats().await);
        }

        StatsResponse {
            timestamp: chrono::Utc::now(),
            period_secs: self.start_time.elapsed().as_secs(),
            storage,
            operations: current_ops,
            performance,
            throughput,
            backends,
        }
    }

    /// Reset all statistics
    pub async fn reset(&self) {
        self.operations.reset();
        *self.previous_snapshot.write().await = None;
    }
}

impl Default for StatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atomic_stats() {
        let stats = AtomicStats::default();

        stats.record_read(100);
        stats.record_write(200);
        stats.record_delete();

        let current = stats.get();
        assert_eq!(current.reads, 1);
        assert_eq!(current.writes, 1);
        assert_eq!(current.deletes, 1);
        assert_eq!(current.bytes_read, 100);
        assert_eq!(current.bytes_written, 200);
    }

    #[tokio::test]
    async fn test_latency_tracker() {
        let tracker = LatencyTracker::new(100);

        tracker.record(Duration::from_millis(10)).await;
        tracker.record(Duration::from_millis(20)).await;
        tracker.record(Duration::from_millis(30)).await;

        let avg = tracker.average().await;
        assert!((avg - 20.0).abs() < 0.1);

        let p50 = tracker.percentile(50.0).await;
        assert!((p50 - 20.0).abs() < 0.1);
    }

    #[tokio::test]
    async fn test_stats_collector() {
        let collector = StatsCollector::new();

        collector.operations().record_read(100);
        collector.operations().record_write(200);
        collector.record_read_latency(Duration::from_millis(10)).await;

        let stats = collector.collect().await;
        assert_eq!(stats.operations.reads, 1);
        assert_eq!(stats.operations.writes, 1);
    }
}
