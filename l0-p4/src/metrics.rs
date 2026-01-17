//! P4 Metrics Module
//!
//! Provides comprehensive metrics for the P4 Chain Anchor Layer.
//!
//! # Metrics Categories
//!
//! - **Counters**: Cumulative counts (total inputs, successful anchors, etc.)
//! - **Gauges**: Current values (queue size, budget remaining, etc.)
//! - **Histograms**: Distribution of values (processing latency, confirmation time)
//!
//! # Usage
//!
//! ```rust,ignore
//! use l0_p4::metrics::{P4Metrics, MetricsSnapshot};
//!
//! let metrics = P4Metrics::new();
//!
//! // Record metrics
//! metrics.input_submitted(AnchorPriority::Must);
//! metrics.anchor_confirmed(AnchorPriority::Must, Duration::from_secs(600));
//!
//! // Get snapshot
//! let snapshot = metrics.snapshot().await;
//! println!("Total inputs: {}", snapshot.total_inputs);
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::types::{AnchorPriority, Timestamp};

/// P4 Metrics collector
pub struct P4Metrics {
    /// Counter metrics
    counters: Arc<Counters>,
    /// Gauge metrics
    gauges: Arc<RwLock<Gauges>>,
    /// Histogram metrics
    histograms: Arc<RwLock<Histograms>>,
    /// Metrics start time
    start_time: Timestamp,
}

/// Counter metrics (monotonically increasing)
#[derive(Default)]
struct Counters {
    /// Total inputs submitted
    total_inputs: AtomicU64,
    /// Inputs by priority
    inputs_must: AtomicU64,
    inputs_should: AtomicU64,
    inputs_may: AtomicU64,

    /// Successful anchors
    successful_anchors: AtomicU64,
    successful_must: AtomicU64,
    successful_should: AtomicU64,
    successful_may: AtomicU64,

    /// Failed anchors
    failed_anchors: AtomicU64,
    failed_must: AtomicU64,
    failed_should: AtomicU64,
    failed_may: AtomicU64,

    /// Dropped anchors (due to expiry or cap)
    dropped_anchors: AtomicU64,
    dropped_must: AtomicU64,
    dropped_should: AtomicU64,
    dropped_may: AtomicU64,

    /// Retry attempts
    retry_attempts: AtomicU64,

    /// Degradation events
    degradation_events: AtomicU64,
    recovery_events: AtomicU64,

    /// Budget operations
    budget_reserves: AtomicU64,
    budget_commits: AtomicU64,
    budget_releases: AtomicU64,
    budget_exhaustion_events: AtomicU64,

    /// RPC calls
    rpc_calls_total: AtomicU64,
    rpc_calls_failed: AtomicU64,

    /// Verification events
    verification_passed: AtomicU64,
    verification_failed: AtomicU64,
    fake_endorsements_detected: AtomicU64,
}

/// Gauge metrics (point-in-time values)
#[derive(Default, Clone)]
struct Gauges {
    /// Current queue sizes
    queue_must: u64,
    queue_should: u64,
    queue_may: u64,

    /// Budget gauges
    budget_remaining: u64,
    budget_reserved: u64,
    budget_spent_today: u64,

    /// Active degradation signals
    active_degradations: u64,

    /// Processing state
    inputs_pending: u64,
    jobs_in_progress: u64,
    links_awaiting_confirmation: u64,

    /// Bitcoin network state
    mempool_size: u64,
    fee_rate_sat_per_vb: u64,
    current_block_height: u64,
}

/// Histogram bucket configuration
#[derive(Clone)]
struct HistogramBuckets {
    /// Bucket boundaries (upper limits)
    boundaries: Vec<f64>,
    /// Count in each bucket
    counts: Vec<u64>,
    /// Sum of all observed values
    sum: f64,
    /// Total count
    count: u64,
}

impl HistogramBuckets {
    fn new(boundaries: Vec<f64>) -> Self {
        let num_buckets = boundaries.len() + 1; // +1 for infinity bucket
        Self {
            boundaries,
            counts: vec![0; num_buckets],
            sum: 0.0,
            count: 0,
        }
    }

    fn observe(&mut self, value: f64) {
        self.sum += value;
        self.count += 1;

        // Find the bucket
        for (i, boundary) in self.boundaries.iter().enumerate() {
            if value <= *boundary {
                self.counts[i] += 1;
                return;
            }
        }
        // Falls into infinity bucket
        *self.counts.last_mut().unwrap() += 1;
    }

    fn percentile(&self, p: f64) -> f64 {
        if self.count == 0 {
            return 0.0;
        }

        let target = (self.count as f64 * p / 100.0).ceil() as u64;
        let mut cumulative = 0u64;

        for (i, count) in self.counts.iter().enumerate() {
            cumulative += count;
            if cumulative >= target {
                if i < self.boundaries.len() {
                    return self.boundaries[i];
                }
                // Return last boundary for infinity bucket
                return *self.boundaries.last().unwrap_or(&0.0);
            }
        }

        *self.boundaries.last().unwrap_or(&0.0)
    }

    fn mean(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.sum / self.count as f64
        }
    }
}

/// Histogram metrics
#[derive(Default)]
struct Histograms {
    /// Processing latency (input to link) in seconds
    processing_latency: Option<HistogramBuckets>,
    /// Confirmation time in seconds
    confirmation_time: Option<HistogramBuckets>,
    /// Queue wait time in seconds
    queue_wait_time: Option<HistogramBuckets>,
    /// Transaction fee in satoshis
    transaction_fees: Option<HistogramBuckets>,
    /// RPC call duration in milliseconds
    rpc_duration_ms: Option<HistogramBuckets>,
}

impl Default for P4Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl P4Metrics {
    /// Create new metrics collector
    pub fn new() -> Self {
        // Initialize histograms with appropriate buckets
        let histograms = Histograms {
            processing_latency: Some(HistogramBuckets::new(vec![
                10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0, 3600.0,
            ])),
            confirmation_time: Some(HistogramBuckets::new(vec![
                60.0, 300.0, 600.0, 1800.0, 3600.0, 7200.0, 14400.0,
            ])),
            queue_wait_time: Some(HistogramBuckets::new(vec![
                1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0,
            ])),
            transaction_fees: Some(HistogramBuckets::new(vec![
                1000.0, 2000.0, 5000.0, 10000.0, 20000.0, 50000.0, 100000.0,
            ])),
            rpc_duration_ms: Some(HistogramBuckets::new(vec![
                10.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0,
            ])),
        };

        Self {
            counters: Arc::new(Counters::default()),
            gauges: Arc::new(RwLock::new(Gauges::default())),
            histograms: Arc::new(RwLock::new(histograms)),
            start_time: Timestamp::now(),
        }
    }

    // ========== Counter Methods ==========

    /// Record input submission
    pub fn input_submitted(&self, priority: AnchorPriority) {
        self.counters.total_inputs.fetch_add(1, Ordering::Relaxed);
        match priority {
            AnchorPriority::Must => self.counters.inputs_must.fetch_add(1, Ordering::Relaxed),
            AnchorPriority::Should => self.counters.inputs_should.fetch_add(1, Ordering::Relaxed),
            AnchorPriority::May => self.counters.inputs_may.fetch_add(1, Ordering::Relaxed),
        };
    }

    /// Record successful anchor
    pub fn anchor_successful(&self, priority: AnchorPriority) {
        self.counters.successful_anchors.fetch_add(1, Ordering::Relaxed);
        match priority {
            AnchorPriority::Must => self.counters.successful_must.fetch_add(1, Ordering::Relaxed),
            AnchorPriority::Should => self.counters.successful_should.fetch_add(1, Ordering::Relaxed),
            AnchorPriority::May => self.counters.successful_may.fetch_add(1, Ordering::Relaxed),
        };
    }

    /// Record failed anchor
    pub fn anchor_failed(&self, priority: AnchorPriority) {
        self.counters.failed_anchors.fetch_add(1, Ordering::Relaxed);
        match priority {
            AnchorPriority::Must => self.counters.failed_must.fetch_add(1, Ordering::Relaxed),
            AnchorPriority::Should => self.counters.failed_should.fetch_add(1, Ordering::Relaxed),
            AnchorPriority::May => self.counters.failed_may.fetch_add(1, Ordering::Relaxed),
        };
    }

    /// Record dropped anchor
    pub fn anchor_dropped(&self, priority: AnchorPriority) {
        self.counters.dropped_anchors.fetch_add(1, Ordering::Relaxed);
        match priority {
            AnchorPriority::Must => self.counters.dropped_must.fetch_add(1, Ordering::Relaxed),
            AnchorPriority::Should => self.counters.dropped_should.fetch_add(1, Ordering::Relaxed),
            AnchorPriority::May => self.counters.dropped_may.fetch_add(1, Ordering::Relaxed),
        };
    }

    /// Record retry attempt
    pub fn retry_attempted(&self) {
        self.counters.retry_attempts.fetch_add(1, Ordering::Relaxed);
    }

    /// Record degradation event
    pub fn degradation_entered(&self) {
        self.counters.degradation_events.fetch_add(1, Ordering::Relaxed);
    }

    /// Record recovery event
    pub fn recovery_completed(&self) {
        self.counters.recovery_events.fetch_add(1, Ordering::Relaxed);
    }

    /// Record budget reserve
    pub fn budget_reserved(&self) {
        self.counters.budget_reserves.fetch_add(1, Ordering::Relaxed);
    }

    /// Record budget commit
    pub fn budget_committed(&self) {
        self.counters.budget_commits.fetch_add(1, Ordering::Relaxed);
    }

    /// Record budget release
    pub fn budget_released(&self) {
        self.counters.budget_releases.fetch_add(1, Ordering::Relaxed);
    }

    /// Record budget exhaustion
    pub fn budget_exhausted(&self) {
        self.counters.budget_exhaustion_events.fetch_add(1, Ordering::Relaxed);
    }

    /// Record RPC call
    pub fn rpc_call(&self, success: bool) {
        self.counters.rpc_calls_total.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.counters.rpc_calls_failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record verification result
    pub fn verification_completed(&self, passed: bool) {
        if passed {
            self.counters.verification_passed.fetch_add(1, Ordering::Relaxed);
        } else {
            self.counters.verification_failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record fake endorsement detection
    pub fn fake_endorsement_detected(&self) {
        self.counters.fake_endorsements_detected.fetch_add(1, Ordering::Relaxed);
    }

    // ========== Gauge Methods ==========

    /// Update queue sizes
    pub async fn set_queue_sizes(&self, must: u64, should: u64, may: u64) {
        let mut gauges = self.gauges.write().await;
        gauges.queue_must = must;
        gauges.queue_should = should;
        gauges.queue_may = may;
    }

    /// Update budget gauges
    pub async fn set_budget_state(&self, remaining: u64, reserved: u64, spent_today: u64) {
        let mut gauges = self.gauges.write().await;
        gauges.budget_remaining = remaining;
        gauges.budget_reserved = reserved;
        gauges.budget_spent_today = spent_today;
    }

    /// Update active degradations count
    pub async fn set_active_degradations(&self, count: u64) {
        let mut gauges = self.gauges.write().await;
        gauges.active_degradations = count;
    }

    /// Update processing state gauges
    pub async fn set_processing_state(
        &self,
        pending: u64,
        in_progress: u64,
        awaiting_confirmation: u64,
    ) {
        let mut gauges = self.gauges.write().await;
        gauges.inputs_pending = pending;
        gauges.jobs_in_progress = in_progress;
        gauges.links_awaiting_confirmation = awaiting_confirmation;
    }

    /// Update Bitcoin network state
    pub async fn set_bitcoin_state(&self, mempool_size: u64, fee_rate: u64, block_height: u64) {
        let mut gauges = self.gauges.write().await;
        gauges.mempool_size = mempool_size;
        gauges.fee_rate_sat_per_vb = fee_rate;
        gauges.current_block_height = block_height;
    }

    // ========== Histogram Methods ==========

    /// Record processing latency
    pub async fn observe_processing_latency(&self, duration: Duration) {
        let mut histograms = self.histograms.write().await;
        if let Some(ref mut h) = histograms.processing_latency {
            h.observe(duration.as_secs_f64());
        }
    }

    /// Record confirmation time
    pub async fn observe_confirmation_time(&self, duration: Duration) {
        let mut histograms = self.histograms.write().await;
        if let Some(ref mut h) = histograms.confirmation_time {
            h.observe(duration.as_secs_f64());
        }
    }

    /// Record queue wait time
    pub async fn observe_queue_wait_time(&self, duration: Duration) {
        let mut histograms = self.histograms.write().await;
        if let Some(ref mut h) = histograms.queue_wait_time {
            h.observe(duration.as_secs_f64());
        }
    }

    /// Record transaction fee
    pub async fn observe_transaction_fee(&self, fee_satoshis: u64) {
        let mut histograms = self.histograms.write().await;
        if let Some(ref mut h) = histograms.transaction_fees {
            h.observe(fee_satoshis as f64);
        }
    }

    /// Record RPC duration
    pub async fn observe_rpc_duration(&self, duration: Duration) {
        let mut histograms = self.histograms.write().await;
        if let Some(ref mut h) = histograms.rpc_duration_ms {
            h.observe(duration.as_millis() as f64);
        }
    }

    // ========== Snapshot Methods ==========

    /// Get a snapshot of all metrics
    pub async fn snapshot(&self) -> MetricsSnapshot {
        let gauges = self.gauges.read().await.clone();
        let histograms = self.histograms.read().await;

        MetricsSnapshot {
            // Counters
            total_inputs: self.counters.total_inputs.load(Ordering::Relaxed),
            inputs_by_priority: PriorityMetrics {
                must: self.counters.inputs_must.load(Ordering::Relaxed),
                should: self.counters.inputs_should.load(Ordering::Relaxed),
                may: self.counters.inputs_may.load(Ordering::Relaxed),
            },
            successful_anchors: self.counters.successful_anchors.load(Ordering::Relaxed),
            successful_by_priority: PriorityMetrics {
                must: self.counters.successful_must.load(Ordering::Relaxed),
                should: self.counters.successful_should.load(Ordering::Relaxed),
                may: self.counters.successful_may.load(Ordering::Relaxed),
            },
            failed_anchors: self.counters.failed_anchors.load(Ordering::Relaxed),
            failed_by_priority: PriorityMetrics {
                must: self.counters.failed_must.load(Ordering::Relaxed),
                should: self.counters.failed_should.load(Ordering::Relaxed),
                may: self.counters.failed_may.load(Ordering::Relaxed),
            },
            dropped_anchors: self.counters.dropped_anchors.load(Ordering::Relaxed),
            retry_attempts: self.counters.retry_attempts.load(Ordering::Relaxed),
            degradation_events: self.counters.degradation_events.load(Ordering::Relaxed),
            recovery_events: self.counters.recovery_events.load(Ordering::Relaxed),
            budget_reserves: self.counters.budget_reserves.load(Ordering::Relaxed),
            budget_commits: self.counters.budget_commits.load(Ordering::Relaxed),
            budget_exhaustion_events: self.counters.budget_exhaustion_events.load(Ordering::Relaxed),
            rpc_calls_total: self.counters.rpc_calls_total.load(Ordering::Relaxed),
            rpc_calls_failed: self.counters.rpc_calls_failed.load(Ordering::Relaxed),
            verification_passed: self.counters.verification_passed.load(Ordering::Relaxed),
            verification_failed: self.counters.verification_failed.load(Ordering::Relaxed),
            fake_endorsements_detected: self.counters.fake_endorsements_detected.load(Ordering::Relaxed),

            // Gauges
            queue_sizes: PriorityMetrics {
                must: gauges.queue_must,
                should: gauges.queue_should,
                may: gauges.queue_may,
            },
            budget_remaining: gauges.budget_remaining,
            budget_reserved: gauges.budget_reserved,
            budget_spent_today: gauges.budget_spent_today,
            active_degradations: gauges.active_degradations,
            inputs_pending: gauges.inputs_pending,
            jobs_in_progress: gauges.jobs_in_progress,
            links_awaiting_confirmation: gauges.links_awaiting_confirmation,
            mempool_size: gauges.mempool_size,
            fee_rate_sat_per_vb: gauges.fee_rate_sat_per_vb,
            current_block_height: gauges.current_block_height,

            // Histogram summaries
            processing_latency: histograms.processing_latency.as_ref().map(|h| HistogramSummary {
                count: h.count,
                sum: h.sum,
                mean: h.mean(),
                p50: h.percentile(50.0),
                p95: h.percentile(95.0),
                p99: h.percentile(99.0),
            }),
            confirmation_time: histograms.confirmation_time.as_ref().map(|h| HistogramSummary {
                count: h.count,
                sum: h.sum,
                mean: h.mean(),
                p50: h.percentile(50.0),
                p95: h.percentile(95.0),
                p99: h.percentile(99.0),
            }),
            rpc_duration_ms: histograms.rpc_duration_ms.as_ref().map(|h| HistogramSummary {
                count: h.count,
                sum: h.sum,
                mean: h.mean(),
                p50: h.percentile(50.0),
                p95: h.percentile(95.0),
                p99: h.percentile(99.0),
            }),

            // Meta
            uptime_secs: {
                let now = Timestamp::now().as_millis();
                let start = self.start_time.as_millis();
                (now.saturating_sub(start)) / 1000
            },
            snapshot_timestamp: Timestamp::now(),
        }
    }

    /// Export metrics in Prometheus format
    pub async fn prometheus_export(&self) -> String {
        let snapshot = self.snapshot().await;
        let mut output = String::new();

        // Helper macro for metrics
        macro_rules! metric {
            ($name:expr, $help:expr, $type:expr, $value:expr) => {
                output.push_str(&format!(
                    "# HELP {} {}\n# TYPE {} {}\n{} {}\n",
                    $name, $help, $name, $type, $name, $value
                ));
            };
            ($name:expr, $help:expr, $type:expr, $value:expr, $labels:expr) => {
                output.push_str(&format!(
                    "# HELP {} {}\n# TYPE {} {}\n{}{{{}}} {}\n",
                    $name, $help, $name, $type, $name, $labels, $value
                ));
            };
        }

        // Counters
        metric!(
            "p4_inputs_total",
            "Total inputs submitted",
            "counter",
            snapshot.total_inputs
        );
        output.push_str(&format!(
            "p4_inputs_total{{priority=\"must\"}} {}\n",
            snapshot.inputs_by_priority.must
        ));
        output.push_str(&format!(
            "p4_inputs_total{{priority=\"should\"}} {}\n",
            snapshot.inputs_by_priority.should
        ));
        output.push_str(&format!(
            "p4_inputs_total{{priority=\"may\"}} {}\n",
            snapshot.inputs_by_priority.may
        ));

        metric!(
            "p4_anchors_successful_total",
            "Total successful anchors",
            "counter",
            snapshot.successful_anchors
        );
        metric!(
            "p4_anchors_failed_total",
            "Total failed anchors",
            "counter",
            snapshot.failed_anchors
        );
        metric!(
            "p4_anchors_dropped_total",
            "Total dropped anchors",
            "counter",
            snapshot.dropped_anchors
        );
        metric!(
            "p4_retry_attempts_total",
            "Total retry attempts",
            "counter",
            snapshot.retry_attempts
        );
        metric!(
            "p4_degradation_events_total",
            "Total degradation events",
            "counter",
            snapshot.degradation_events
        );
        metric!(
            "p4_recovery_events_total",
            "Total recovery events",
            "counter",
            snapshot.recovery_events
        );
        metric!(
            "p4_rpc_calls_total",
            "Total RPC calls",
            "counter",
            snapshot.rpc_calls_total
        );
        metric!(
            "p4_rpc_calls_failed_total",
            "Total failed RPC calls",
            "counter",
            snapshot.rpc_calls_failed
        );

        // Gauges
        metric!(
            "p4_queue_size",
            "Current queue size",
            "gauge",
            snapshot.queue_sizes.must + snapshot.queue_sizes.should + snapshot.queue_sizes.may
        );
        output.push_str(&format!(
            "p4_queue_size{{priority=\"must\"}} {}\n",
            snapshot.queue_sizes.must
        ));
        output.push_str(&format!(
            "p4_queue_size{{priority=\"should\"}} {}\n",
            snapshot.queue_sizes.should
        ));
        output.push_str(&format!(
            "p4_queue_size{{priority=\"may\"}} {}\n",
            snapshot.queue_sizes.may
        ));

        metric!(
            "p4_budget_remaining_satoshis",
            "Remaining budget in satoshis",
            "gauge",
            snapshot.budget_remaining
        );
        metric!(
            "p4_budget_reserved_satoshis",
            "Reserved budget in satoshis",
            "gauge",
            snapshot.budget_reserved
        );
        metric!(
            "p4_budget_spent_today_satoshis",
            "Budget spent today in satoshis",
            "gauge",
            snapshot.budget_spent_today
        );
        metric!(
            "p4_active_degradations",
            "Number of active degradation signals",
            "gauge",
            snapshot.active_degradations
        );
        metric!(
            "p4_inputs_pending",
            "Number of inputs pending processing",
            "gauge",
            snapshot.inputs_pending
        );
        metric!(
            "p4_jobs_in_progress",
            "Number of jobs in progress",
            "gauge",
            snapshot.jobs_in_progress
        );
        metric!(
            "p4_links_awaiting_confirmation",
            "Number of links awaiting confirmation",
            "gauge",
            snapshot.links_awaiting_confirmation
        );
        metric!(
            "p4_bitcoin_mempool_size",
            "Bitcoin mempool size",
            "gauge",
            snapshot.mempool_size
        );
        metric!(
            "p4_bitcoin_fee_rate",
            "Bitcoin fee rate in sat/vB",
            "gauge",
            snapshot.fee_rate_sat_per_vb
        );
        metric!(
            "p4_bitcoin_block_height",
            "Current Bitcoin block height",
            "gauge",
            snapshot.current_block_height
        );
        metric!(
            "p4_uptime_seconds",
            "Uptime in seconds",
            "gauge",
            snapshot.uptime_secs
        );

        // Histogram summaries
        if let Some(ref h) = snapshot.processing_latency {
            output.push_str(&format!(
                "# HELP p4_processing_latency_seconds Processing latency histogram\n\
                 # TYPE p4_processing_latency_seconds histogram\n\
                 p4_processing_latency_seconds_count {}\n\
                 p4_processing_latency_seconds_sum {}\n",
                h.count, h.sum
            ));
        }

        if let Some(ref h) = snapshot.confirmation_time {
            output.push_str(&format!(
                "# HELP p4_confirmation_time_seconds Confirmation time histogram\n\
                 # TYPE p4_confirmation_time_seconds histogram\n\
                 p4_confirmation_time_seconds_count {}\n\
                 p4_confirmation_time_seconds_sum {}\n",
                h.count, h.sum
            ));
        }

        output
    }

    /// Reset all metrics (for testing)
    #[cfg(test)]
    pub async fn reset(&self) {
        self.counters.total_inputs.store(0, Ordering::Relaxed);
        self.counters.inputs_must.store(0, Ordering::Relaxed);
        self.counters.inputs_should.store(0, Ordering::Relaxed);
        self.counters.inputs_may.store(0, Ordering::Relaxed);
        self.counters.successful_anchors.store(0, Ordering::Relaxed);
        self.counters.failed_anchors.store(0, Ordering::Relaxed);
        *self.gauges.write().await = Gauges::default();
    }
}

/// Metrics by priority level
#[derive(Debug, Clone, Default)]
pub struct PriorityMetrics {
    pub must: u64,
    pub should: u64,
    pub may: u64,
}

impl PriorityMetrics {
    pub fn total(&self) -> u64 {
        self.must + self.should + self.may
    }
}

/// Histogram summary statistics
#[derive(Debug, Clone)]
pub struct HistogramSummary {
    pub count: u64,
    pub sum: f64,
    pub mean: f64,
    pub p50: f64,
    pub p95: f64,
    pub p99: f64,
}

/// Complete metrics snapshot
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    // Counters
    pub total_inputs: u64,
    pub inputs_by_priority: PriorityMetrics,
    pub successful_anchors: u64,
    pub successful_by_priority: PriorityMetrics,
    pub failed_anchors: u64,
    pub failed_by_priority: PriorityMetrics,
    pub dropped_anchors: u64,
    pub retry_attempts: u64,
    pub degradation_events: u64,
    pub recovery_events: u64,
    pub budget_reserves: u64,
    pub budget_commits: u64,
    pub budget_exhaustion_events: u64,
    pub rpc_calls_total: u64,
    pub rpc_calls_failed: u64,
    pub verification_passed: u64,
    pub verification_failed: u64,
    pub fake_endorsements_detected: u64,

    // Gauges
    pub queue_sizes: PriorityMetrics,
    pub budget_remaining: u64,
    pub budget_reserved: u64,
    pub budget_spent_today: u64,
    pub active_degradations: u64,
    pub inputs_pending: u64,
    pub jobs_in_progress: u64,
    pub links_awaiting_confirmation: u64,
    pub mempool_size: u64,
    pub fee_rate_sat_per_vb: u64,
    pub current_block_height: u64,

    // Histogram summaries
    pub processing_latency: Option<HistogramSummary>,
    pub confirmation_time: Option<HistogramSummary>,
    pub rpc_duration_ms: Option<HistogramSummary>,

    // Meta
    pub uptime_secs: u64,
    pub snapshot_timestamp: Timestamp,
}

impl MetricsSnapshot {
    /// Calculate success rate as a percentage
    pub fn success_rate(&self) -> f64 {
        let total = self.successful_anchors + self.failed_anchors;
        if total == 0 {
            100.0
        } else {
            (self.successful_anchors as f64 / total as f64) * 100.0
        }
    }

    /// Calculate RPC success rate as a percentage
    pub fn rpc_success_rate(&self) -> f64 {
        if self.rpc_calls_total == 0 {
            100.0
        } else {
            let successful = self.rpc_calls_total - self.rpc_calls_failed;
            (successful as f64 / self.rpc_calls_total as f64) * 100.0
        }
    }

    /// Get total queue size
    pub fn total_queue_size(&self) -> u64 {
        self.queue_sizes.total()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_counter_metrics() {
        let metrics = P4Metrics::new();

        metrics.input_submitted(AnchorPriority::Must);
        metrics.input_submitted(AnchorPriority::Should);
        metrics.input_submitted(AnchorPriority::May);
        metrics.input_submitted(AnchorPriority::Must);

        let snapshot = metrics.snapshot().await;
        assert_eq!(snapshot.total_inputs, 4);
        assert_eq!(snapshot.inputs_by_priority.must, 2);
        assert_eq!(snapshot.inputs_by_priority.should, 1);
        assert_eq!(snapshot.inputs_by_priority.may, 1);
    }

    #[tokio::test]
    async fn test_gauge_metrics() {
        let metrics = P4Metrics::new();

        metrics.set_queue_sizes(10, 20, 30).await;
        metrics.set_budget_state(50000, 10000, 5000).await;

        let snapshot = metrics.snapshot().await;
        assert_eq!(snapshot.queue_sizes.must, 10);
        assert_eq!(snapshot.queue_sizes.should, 20);
        assert_eq!(snapshot.queue_sizes.may, 30);
        assert_eq!(snapshot.budget_remaining, 50000);
        assert_eq!(snapshot.budget_reserved, 10000);
    }

    #[tokio::test]
    async fn test_histogram_metrics() {
        let metrics = P4Metrics::new();

        // Observe some processing latencies
        metrics.observe_processing_latency(Duration::from_secs(5)).await;
        metrics.observe_processing_latency(Duration::from_secs(15)).await;
        metrics.observe_processing_latency(Duration::from_secs(45)).await;
        metrics.observe_processing_latency(Duration::from_secs(90)).await;

        let snapshot = metrics.snapshot().await;
        let h = snapshot.processing_latency.unwrap();
        assert_eq!(h.count, 4);
        assert!((h.mean - 38.75).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_success_rate() {
        let metrics = P4Metrics::new();

        metrics.anchor_successful(AnchorPriority::Must);
        metrics.anchor_successful(AnchorPriority::Must);
        metrics.anchor_successful(AnchorPriority::Should);
        metrics.anchor_failed(AnchorPriority::May);

        let snapshot = metrics.snapshot().await;
        assert!((snapshot.success_rate() - 75.0).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_prometheus_export() {
        let metrics = P4Metrics::new();

        metrics.input_submitted(AnchorPriority::Must);
        metrics.set_queue_sizes(5, 10, 15).await;

        let output = metrics.prometheus_export().await;
        assert!(output.contains("p4_inputs_total"));
        assert!(output.contains("p4_queue_size"));
    }

    #[test]
    fn test_priority_metrics_total() {
        let pm = PriorityMetrics {
            must: 10,
            should: 20,
            may: 30,
        };
        assert_eq!(pm.total(), 60);
    }
}
