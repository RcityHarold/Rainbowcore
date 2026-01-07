//! Metrics Collection
//!
//! Provides Prometheus-compatible metrics for monitoring the storage layer.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Metrics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Whether metrics are enabled
    pub enabled: bool,
    /// Metrics prefix (e.g., "p2_storage")
    pub prefix: String,
    /// Global labels applied to all metrics
    pub global_labels: HashMap<String, String>,
    /// Histogram buckets for latency metrics
    pub latency_buckets: Vec<f64>,
    /// Histogram buckets for size metrics
    pub size_buckets: Vec<f64>,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            prefix: "p2_storage".to_string(),
            global_labels: HashMap::new(),
            latency_buckets: vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ],
            size_buckets: vec![
                1024.0,
                10240.0,
                102400.0,
                1048576.0,
                10485760.0,
                104857600.0,
                1073741824.0,
            ],
        }
    }
}

/// Counter metric (only increases)
#[derive(Debug)]
pub struct Counter {
    name: String,
    help: String,
    value: AtomicU64,
    labels: HashMap<String, String>,
}

impl Counter {
    /// Create a new counter
    pub fn new(name: &str, help: &str) -> Self {
        Self {
            name: name.to_string(),
            help: help.to_string(),
            value: AtomicU64::new(0),
            labels: HashMap::new(),
        }
    }

    /// Create with labels
    pub fn with_labels(name: &str, help: &str, labels: HashMap<String, String>) -> Self {
        Self {
            name: name.to_string(),
            help: help.to_string(),
            value: AtomicU64::new(0),
            labels,
        }
    }

    /// Increment by 1
    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment by n
    pub fn inc_by(&self, n: u64) {
        self.value.fetch_add(n, Ordering::Relaxed);
    }

    /// Get current value
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    /// Get name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get help text
    pub fn help(&self) -> &str {
        &self.help
    }

    /// Get labels
    pub fn labels(&self) -> &HashMap<String, String> {
        &self.labels
    }
}

/// Gauge metric (can increase or decrease)
#[derive(Debug)]
pub struct Gauge {
    name: String,
    help: String,
    value: AtomicI64,
    labels: HashMap<String, String>,
}

impl Gauge {
    /// Create a new gauge
    pub fn new(name: &str, help: &str) -> Self {
        Self {
            name: name.to_string(),
            help: help.to_string(),
            value: AtomicI64::new(0),
            labels: HashMap::new(),
        }
    }

    /// Create with labels
    pub fn with_labels(name: &str, help: &str, labels: HashMap<String, String>) -> Self {
        Self {
            name: name.to_string(),
            help: help.to_string(),
            value: AtomicI64::new(0),
            labels,
        }
    }

    /// Set value
    pub fn set(&self, value: i64) {
        self.value.store(value, Ordering::Relaxed);
    }

    /// Increment by 1
    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement by 1
    pub fn dec(&self) {
        self.value.fetch_sub(1, Ordering::Relaxed);
    }

    /// Increment by n
    pub fn add(&self, n: i64) {
        self.value.fetch_add(n, Ordering::Relaxed);
    }

    /// Get current value
    pub fn get(&self) -> i64 {
        self.value.load(Ordering::Relaxed)
    }

    /// Get name
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Histogram metric for distributions
#[derive(Debug)]
pub struct Histogram {
    name: String,
    help: String,
    buckets: Vec<f64>,
    bucket_counts: Vec<AtomicU64>,
    sum: AtomicU64,
    count: AtomicU64,
    labels: HashMap<String, String>,
}

impl Histogram {
    /// Create a new histogram
    pub fn new(name: &str, help: &str, buckets: Vec<f64>) -> Self {
        let bucket_counts = buckets.iter().map(|_| AtomicU64::new(0)).collect();
        Self {
            name: name.to_string(),
            help: help.to_string(),
            buckets,
            bucket_counts,
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
            labels: HashMap::new(),
        }
    }

    /// Observe a value
    pub fn observe(&self, value: f64) {
        // Find bucket and increment
        for (i, bucket) in self.buckets.iter().enumerate() {
            if value <= *bucket {
                self.bucket_counts[i].fetch_add(1, Ordering::Relaxed);
            }
        }

        // Update sum and count (storing as bits)
        let bits = value.to_bits();
        self.sum.fetch_add(bits, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get count
    pub fn get_count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Get name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get buckets
    pub fn buckets(&self) -> &[f64] {
        &self.buckets
    }

    /// Get bucket counts
    pub fn bucket_counts(&self) -> Vec<u64> {
        self.bucket_counts
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .collect()
    }
}

/// Metrics registry
pub struct MetricsRegistry {
    config: MetricsConfig,
    counters: RwLock<HashMap<String, Arc<Counter>>>,
    gauges: RwLock<HashMap<String, Arc<Gauge>>>,
    histograms: RwLock<HashMap<String, Arc<Histogram>>>,
}

impl MetricsRegistry {
    /// Create a new registry
    pub fn new(config: MetricsConfig) -> Self {
        Self {
            config,
            counters: RwLock::new(HashMap::new()),
            gauges: RwLock::new(HashMap::new()),
            histograms: RwLock::new(HashMap::new()),
        }
    }

    /// Register a counter
    pub async fn register_counter(&self, name: &str, help: &str) -> Arc<Counter> {
        let full_name = format!("{}_{}", self.config.prefix, name);
        let counter = Arc::new(Counter::new(&full_name, help));

        let mut counters = self.counters.write().await;
        counters.insert(full_name.clone(), counter.clone());
        counter
    }

    /// Register a gauge
    pub async fn register_gauge(&self, name: &str, help: &str) -> Arc<Gauge> {
        let full_name = format!("{}_{}", self.config.prefix, name);
        let gauge = Arc::new(Gauge::new(&full_name, help));

        let mut gauges = self.gauges.write().await;
        gauges.insert(full_name.clone(), gauge.clone());
        gauge
    }

    /// Register a histogram
    pub async fn register_histogram(
        &self,
        name: &str,
        help: &str,
        buckets: Option<Vec<f64>>,
    ) -> Arc<Histogram> {
        let full_name = format!("{}_{}", self.config.prefix, name);
        let buckets = buckets.unwrap_or_else(|| self.config.latency_buckets.clone());
        let histogram = Arc::new(Histogram::new(&full_name, help, buckets));

        let mut histograms = self.histograms.write().await;
        histograms.insert(full_name.clone(), histogram.clone());
        histogram
    }

    /// Export metrics in Prometheus format
    pub async fn export_prometheus(&self) -> String {
        let mut output = String::new();

        // Export counters
        for counter in self.counters.read().await.values() {
            output.push_str(&format!("# HELP {} {}\n", counter.name(), counter.help()));
            output.push_str(&format!("# TYPE {} counter\n", counter.name()));
            output.push_str(&format!("{} {}\n", counter.name(), counter.get()));
        }

        // Export gauges
        for gauge in self.gauges.read().await.values() {
            output.push_str(&format!("# HELP {} {}\n", gauge.name(), gauge.help));
            output.push_str(&format!("# TYPE {} gauge\n", gauge.name()));
            output.push_str(&format!("{} {}\n", gauge.name(), gauge.get()));
        }

        // Export histograms
        for histogram in self.histograms.read().await.values() {
            output.push_str(&format!("# HELP {} {}\n", histogram.name(), histogram.help));
            output.push_str(&format!("# TYPE {} histogram\n", histogram.name()));

            let counts = histogram.bucket_counts();
            for (i, bucket) in histogram.buckets().iter().enumerate() {
                output.push_str(&format!(
                    "{}_bucket{{le=\"{}\"}} {}\n",
                    histogram.name(),
                    bucket,
                    counts[i]
                ));
            }
            output.push_str(&format!(
                "{}_bucket{{le=\"+Inf\"}} {}\n",
                histogram.name(),
                histogram.get_count()
            ));
            output.push_str(&format!("{}_count {}\n", histogram.name(), histogram.get_count()));
        }

        output
    }
}

/// Pre-defined storage metrics
pub struct StorageMetrics {
    pub writes_total: Arc<Counter>,
    pub reads_total: Arc<Counter>,
    pub bytes_written: Arc<Counter>,
    pub bytes_read: Arc<Counter>,
    pub write_errors: Arc<Counter>,
    pub read_errors: Arc<Counter>,
    pub write_latency: Arc<Histogram>,
    pub read_latency: Arc<Histogram>,
    pub active_operations: Arc<Gauge>,
    pub storage_size_bytes: Arc<Gauge>,
}

impl StorageMetrics {
    pub async fn new(registry: &MetricsRegistry) -> Self {
        Self {
            writes_total: registry
                .register_counter("writes_total", "Total number of write operations")
                .await,
            reads_total: registry
                .register_counter("reads_total", "Total number of read operations")
                .await,
            bytes_written: registry
                .register_counter("bytes_written_total", "Total bytes written")
                .await,
            bytes_read: registry
                .register_counter("bytes_read_total", "Total bytes read")
                .await,
            write_errors: registry
                .register_counter("write_errors_total", "Total write errors")
                .await,
            read_errors: registry
                .register_counter("read_errors_total", "Total read errors")
                .await,
            write_latency: registry
                .register_histogram("write_latency_seconds", "Write operation latency", None)
                .await,
            read_latency: registry
                .register_histogram("read_latency_seconds", "Read operation latency", None)
                .await,
            active_operations: registry
                .register_gauge("active_operations", "Currently active operations")
                .await,
            storage_size_bytes: registry
                .register_gauge("storage_size_bytes", "Total storage size in bytes")
                .await,
        }
    }
}

/// Pre-defined replication metrics
pub struct ReplicationMetrics {
    pub replications_total: Arc<Counter>,
    pub replication_errors: Arc<Counter>,
    pub bytes_replicated: Arc<Counter>,
    pub replication_latency: Arc<Histogram>,
    pub replication_lag_ms: Arc<Gauge>,
    pub pending_replications: Arc<Gauge>,
    pub healthy_nodes: Arc<Gauge>,
}

impl ReplicationMetrics {
    pub async fn new(registry: &MetricsRegistry) -> Self {
        Self {
            replications_total: registry
                .register_counter("replications_total", "Total replication operations")
                .await,
            replication_errors: registry
                .register_counter("replication_errors_total", "Total replication errors")
                .await,
            bytes_replicated: registry
                .register_counter("bytes_replicated_total", "Total bytes replicated")
                .await,
            replication_latency: registry
                .register_histogram(
                    "replication_latency_seconds",
                    "Replication operation latency",
                    None,
                )
                .await,
            replication_lag_ms: registry
                .register_gauge("replication_lag_ms", "Current replication lag in milliseconds")
                .await,
            pending_replications: registry
                .register_gauge("pending_replications", "Number of pending replication tasks")
                .await,
            healthy_nodes: registry
                .register_gauge("healthy_nodes", "Number of healthy replica nodes")
                .await,
        }
    }
}

/// Pre-defined sampling metrics
pub struct SamplingMetrics {
    pub samples_total: Arc<Counter>,
    pub samples_passed: Arc<Counter>,
    pub samples_failed: Arc<Counter>,
    pub sample_latency: Arc<Histogram>,
    pub last_sample_time: Arc<Gauge>,
}

impl SamplingMetrics {
    pub async fn new(registry: &MetricsRegistry) -> Self {
        Self {
            samples_total: registry
                .register_counter("samples_total", "Total integrity samples checked")
                .await,
            samples_passed: registry
                .register_counter("samples_passed_total", "Samples that passed integrity check")
                .await,
            samples_failed: registry
                .register_counter("samples_failed_total", "Samples that failed integrity check")
                .await,
            sample_latency: registry
                .register_histogram("sample_latency_seconds", "Sample check latency", None)
                .await,
            last_sample_time: registry
                .register_gauge("last_sample_timestamp", "Unix timestamp of last sample run")
                .await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter() {
        let counter = Counter::new("test_counter", "Test counter");
        assert_eq!(counter.get(), 0);

        counter.inc();
        assert_eq!(counter.get(), 1);

        counter.inc_by(5);
        assert_eq!(counter.get(), 6);
    }

    #[test]
    fn test_gauge() {
        let gauge = Gauge::new("test_gauge", "Test gauge");
        assert_eq!(gauge.get(), 0);

        gauge.set(100);
        assert_eq!(gauge.get(), 100);

        gauge.inc();
        assert_eq!(gauge.get(), 101);

        gauge.dec();
        assert_eq!(gauge.get(), 100);
    }

    #[test]
    fn test_histogram() {
        let histogram = Histogram::new(
            "test_histogram",
            "Test histogram",
            vec![0.1, 0.5, 1.0, 5.0],
        );

        histogram.observe(0.05);
        histogram.observe(0.3);
        histogram.observe(2.0);

        assert_eq!(histogram.get_count(), 3);
    }

    #[tokio::test]
    async fn test_registry() {
        let config = MetricsConfig::default();
        let registry = MetricsRegistry::new(config);

        let counter = registry
            .register_counter("test_ops", "Test operations")
            .await;
        counter.inc();

        let output = registry.export_prometheus().await;
        assert!(output.contains("p2_storage_test_ops"));
    }
}
