//! Telemetry Module
//!
//! Provides unified observability for the P2 storage layer including:
//! - Structured logging
//! - Metrics (Prometheus-compatible)
//! - Distributed tracing (OpenTelemetry-compatible)

pub mod logging;
pub mod metrics;
pub mod tracing_config;

pub use logging::{LogConfig, LogFormat, LogLevel, init_logging};
pub use metrics::{
    MetricsConfig, MetricsRegistry, Counter, Gauge, Histogram,
    StorageMetrics, ReplicationMetrics, SamplingMetrics,
};
pub use tracing_config::{TracingConfig, TraceContext, init_tracing, create_span};
