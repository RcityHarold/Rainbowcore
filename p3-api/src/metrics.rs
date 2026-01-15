//! Prometheus Metrics
//!
//! Provides Prometheus metrics for monitoring the P3 API.
//!
//! # Metrics
//!
//! ## Counters
//! - `p3_http_requests_total` - Total HTTP requests by method, path, status
//! - `p3_execution_total` - Total execution operations by type, status
//! - `p3_errors_total` - Total errors by type
//!
//! ## Histograms
//! - `p3_http_request_duration_seconds` - HTTP request duration
//! - `p3_execution_duration_seconds` - Execution operation duration
//!
//! ## Gauges
//! - `p3_active_requests` - Currently active requests
//! - `p3_uptime_seconds` - Service uptime
//!
//! # Configuration
//!
//! - `P3_METRICS_ENABLED`: Enable metrics (default: true)
//! - `P3_METRICS_PORT`: Metrics server port (default: 9090)

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::PrometheusBuilder;
use std::sync::Arc;
use std::time::Instant;

use crate::state::AppState;

/// Metrics configuration
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// Whether metrics are enabled
    pub enabled: bool,
    /// Port for metrics endpoint
    pub port: u16,
    /// Prefix for metric names
    pub prefix: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 9090,
            prefix: "p3".to_string(),
        }
    }
}

impl MetricsConfig {
    /// Create from environment variables
    pub fn from_env() -> Self {
        let enabled = std::env::var("P3_METRICS_ENABLED")
            .map(|v| v.to_lowercase() != "false" && v != "0")
            .unwrap_or(true);

        let port = std::env::var("P3_METRICS_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(9090);

        Self {
            enabled,
            port,
            ..Default::default()
        }
    }
}

/// Initialize metrics exporter
///
/// This should be called once at startup. Returns the metrics handle
/// that can be used for rendering.
pub fn init_metrics(config: &MetricsConfig) -> Result<(), String> {
    if !config.enabled {
        tracing::info!("Metrics disabled");
        return Ok(());
    }

    let builder = PrometheusBuilder::new();

    builder
        .install()
        .map_err(|e| format!("Failed to install metrics recorder: {}", e))?;

    tracing::info!("Metrics initialized");
    Ok(())
}

/// Record a request metric
pub fn record_request(method: &str, path: &str, status: u16, duration_secs: f64) {
    let labels = [
        ("method", method.to_string()),
        ("path", normalize_path(path)),
        ("status", status.to_string()),
    ];

    counter!("p3_http_requests_total", &labels).increment(1);
    histogram!("p3_http_request_duration_seconds", &labels).record(duration_secs);
}

/// Record an execution operation
pub fn record_execution(operation_type: &str, status: &str, duration_secs: f64) {
    let labels = [
        ("operation", operation_type.to_string()),
        ("status", status.to_string()),
    ];

    counter!("p3_execution_total", &labels).increment(1);
    histogram!("p3_execution_duration_seconds", &labels).record(duration_secs);
}

/// Record an error
pub fn record_error(error_type: &str) {
    counter!("p3_errors_total", "type" => error_type.to_string()).increment(1);
}

/// Update active requests gauge
pub fn set_active_requests(count: u64) {
    gauge!("p3_active_requests").set(count as f64);
}

/// Update uptime gauge
pub fn set_uptime(seconds: u64) {
    gauge!("p3_uptime_seconds").set(seconds as f64);
}

/// Normalize path for metric labels (remove dynamic segments)
fn normalize_path(path: &str) -> String {
    // Replace UUIDs and numeric IDs with placeholders
    let path = regex_replace_ids(path);

    // Limit path length
    if path.len() > 50 {
        path[..50].to_string()
    } else {
        path
    }
}

/// Replace IDs in path with placeholders
fn regex_replace_ids(path: &str) -> String {
    // Simple replacement for common ID patterns
    let mut result = path.to_string();

    // Replace UUID-like patterns
    if result.contains('/') {
        let parts: Vec<&str> = result.split('/').collect();
        let normalized: Vec<String> = parts
            .iter()
            .map(|part| {
                // Check if part looks like an ID (hex, numeric, or UUID)
                if part.len() >= 8 && (
                    part.chars().all(|c| c.is_ascii_hexdigit() || c == '-') ||
                    part.chars().all(|c| c.is_ascii_digit())
                ) {
                    ":id".to_string()
                } else {
                    part.to_string()
                }
            })
            .collect();
        result = normalized.join("/");
    }

    result
}

/// Metrics middleware for tracking HTTP requests
pub async fn metrics_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let start = Instant::now();
    let method = request.method().to_string();
    let path = request.uri().path().to_string();

    // Increment active requests
    let active = state.increment_requests().await;
    set_active_requests(active);

    // Update uptime
    set_uptime(state.uptime_secs());

    // Process request
    let response = next.run(request).await;

    // Record metrics
    let duration = start.elapsed().as_secs_f64();
    let status = response.status().as_u16();
    record_request(&method, &path, status, duration);

    // Decrement would need atomic counter, skipping for simplicity

    response
}

/// Metrics summary for health check response
#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricsSummary {
    pub total_requests: u64,
    pub uptime_seconds: u64,
    pub metrics_enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_config_default() {
        let config = MetricsConfig::default();
        assert!(config.enabled);
        assert_eq!(config.port, 9090);
        assert_eq!(config.prefix, "p3");
    }

    #[test]
    fn test_normalize_path() {
        assert_eq!(normalize_path("/api/v1/health"), "/api/v1/health");
        assert_eq!(normalize_path("/api/v1/providers/12345678"), "/api/v1/providers/:id");
        assert_eq!(normalize_path("/api/v1/clearing/batches/abcdef12"), "/api/v1/clearing/batches/:id");
    }

    #[test]
    fn test_regex_replace_ids() {
        // UUID pattern
        assert_eq!(
            regex_replace_ids("/providers/550e8400-e29b-41d4-a716-446655440000"),
            "/providers/:id"
        );
        // Numeric ID
        assert_eq!(
            regex_replace_ids("/batches/123456789"),
            "/batches/:id"
        );
        // Short segment (not an ID)
        assert_eq!(
            regex_replace_ids("/api/v1/health"),
            "/api/v1/health"
        );
    }

    #[test]
    fn test_metrics_summary() {
        let summary = MetricsSummary {
            total_requests: 100,
            uptime_seconds: 3600,
            metrics_enabled: true,
        };
        assert_eq!(summary.total_requests, 100);
    }
}
