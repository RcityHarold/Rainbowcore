//! Distributed Tracing Configuration
//!
//! Provides OpenTelemetry-compatible distributed tracing configuration.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{span, Level, Span};

/// Tracing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    /// Whether tracing is enabled
    pub enabled: bool,
    /// Service name
    pub service_name: String,
    /// Service version
    pub service_version: String,
    /// Environment (e.g., "production", "staging")
    pub environment: String,
    /// Sampling rate (0.0 to 1.0)
    pub sampling_rate: f64,
    /// OTLP endpoint for trace export
    pub otlp_endpoint: Option<String>,
    /// Additional resource attributes
    pub resource_attributes: HashMap<String, String>,
    /// Propagation format
    pub propagation_format: PropagationFormat,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            service_name: "p2-storage".to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            environment: "development".to_string(),
            sampling_rate: 1.0,
            otlp_endpoint: None,
            resource_attributes: HashMap::new(),
            propagation_format: PropagationFormat::W3C,
        }
    }
}

impl TracingConfig {
    /// Create production configuration
    pub fn production() -> Self {
        Self {
            enabled: true,
            service_name: "p2-storage".to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            environment: "production".to_string(),
            sampling_rate: 0.1, // 10% sampling in production
            otlp_endpoint: None,
            resource_attributes: HashMap::new(),
            propagation_format: PropagationFormat::W3C,
        }
    }

    /// Set OTLP endpoint
    pub fn with_otlp_endpoint(mut self, endpoint: &str) -> Self {
        self.otlp_endpoint = Some(endpoint.to_string());
        self
    }

    /// Set sampling rate
    pub fn with_sampling_rate(mut self, rate: f64) -> Self {
        self.sampling_rate = rate.clamp(0.0, 1.0);
        self
    }

    /// Add resource attribute
    pub fn with_resource(mut self, key: &str, value: &str) -> Self {
        self.resource_attributes
            .insert(key.to_string(), value.to_string());
        self
    }
}

/// Trace propagation format
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PropagationFormat {
    /// W3C Trace Context
    W3C,
    /// Jaeger format
    Jaeger,
    /// B3 (Zipkin) format
    B3,
}

impl Default for PropagationFormat {
    fn default() -> Self {
        Self::W3C
    }
}

/// Initialize tracing
pub fn init_tracing(config: &TracingConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !config.enabled {
        return Ok(());
    }

    // Basic tracing setup - in production would integrate with OpenTelemetry
    // For now, just ensure tracing subscriber is set up
    tracing::info!(
        service = %config.service_name,
        version = %config.service_version,
        environment = %config.environment,
        "Tracing initialized"
    );

    Ok(())
}

/// Create a new span for an operation
pub fn create_span(name: &str, operation: &str) -> Span {
    span!(
        Level::INFO,
        "operation",
        name = %name,
        operation = %operation,
        otel.kind = "internal"
    )
}

/// Trace context for propagation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceContext {
    /// Trace ID (128-bit hex)
    pub trace_id: String,
    /// Span ID (64-bit hex)
    pub span_id: String,
    /// Trace flags
    pub trace_flags: u8,
    /// Parent span ID (optional)
    pub parent_span_id: Option<String>,
    /// Trace state (vendor-specific data)
    pub trace_state: HashMap<String, String>,
}

impl TraceContext {
    /// Generate new trace context
    pub fn new() -> Self {
        Self {
            trace_id: generate_trace_id(),
            span_id: generate_span_id(),
            trace_flags: 1, // Sampled
            parent_span_id: None,
            trace_state: HashMap::new(),
        }
    }

    /// Create child span context
    pub fn create_child(&self) -> Self {
        Self {
            trace_id: self.trace_id.clone(),
            span_id: generate_span_id(),
            trace_flags: self.trace_flags,
            parent_span_id: Some(self.span_id.clone()),
            trace_state: self.trace_state.clone(),
        }
    }

    /// Parse W3C traceparent header
    pub fn from_traceparent(header: &str) -> Option<Self> {
        let parts: Vec<&str> = header.split('-').collect();
        if parts.len() < 4 {
            return None;
        }

        Some(Self {
            trace_id: parts[1].to_string(),
            span_id: parts[2].to_string(),
            trace_flags: u8::from_str_radix(parts[3], 16).unwrap_or(0),
            parent_span_id: None,
            trace_state: HashMap::new(),
        })
    }

    /// Format as W3C traceparent header
    pub fn to_traceparent(&self) -> String {
        format!(
            "00-{}-{}-{:02x}",
            self.trace_id, self.span_id, self.trace_flags
        )
    }

    /// Check if sampled
    pub fn is_sampled(&self) -> bool {
        self.trace_flags & 0x01 != 0
    }
}

impl Default for TraceContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate random trace ID (128-bit hex)
fn generate_trace_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let random: u64 = rand::random();

    format!("{:016x}{:016x}", timestamp, random)
}

/// Generate random span ID (64-bit hex)
fn generate_span_id() -> String {
    let random: u64 = rand::random();
    format!("{:016x}", random)
}

/// Span decorator for adding common attributes
pub struct SpanDecorator {
    span: Span,
}

impl SpanDecorator {
    pub fn new(span: Span) -> Self {
        Self { span }
    }

    /// Add ref_id attribute
    pub fn with_ref_id(self, ref_id: &str) -> Self {
        self.span.record("ref_id", ref_id);
        self
    }

    /// Add operation attribute
    pub fn with_operation(self, operation: &str) -> Self {
        self.span.record("operation", operation);
        self
    }

    /// Add size attribute
    pub fn with_size(self, size: u64) -> Self {
        self.span.record("size_bytes", size);
        self
    }

    /// Get the decorated span
    pub fn span(self) -> Span {
        self.span
    }
}

/// Instrumentation helpers
#[macro_export]
macro_rules! trace_operation {
    ($name:expr, $op:expr, $($field:tt)*) => {
        tracing::info_span!(
            "operation",
            name = $name,
            operation = $op,
            $($field)*
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_context_new() {
        let ctx = TraceContext::new();
        assert_eq!(ctx.trace_id.len(), 32);
        assert_eq!(ctx.span_id.len(), 16);
        assert!(ctx.is_sampled());
    }

    #[test]
    fn test_trace_context_child() {
        let parent = TraceContext::new();
        let child = parent.create_child();

        assert_eq!(parent.trace_id, child.trace_id);
        assert_ne!(parent.span_id, child.span_id);
        assert_eq!(child.parent_span_id, Some(parent.span_id));
    }

    #[test]
    fn test_traceparent_roundtrip() {
        let ctx = TraceContext::new();
        let header = ctx.to_traceparent();
        let parsed = TraceContext::from_traceparent(&header).unwrap();

        assert_eq!(ctx.trace_id, parsed.trace_id);
        assert_eq!(ctx.span_id, parsed.span_id);
    }

    #[test]
    fn test_tracing_config() {
        let config = TracingConfig::default();
        assert!(config.enabled);
        assert_eq!(config.sampling_rate, 1.0);

        let prod_config = TracingConfig::production();
        assert_eq!(prod_config.environment, "production");
        assert_eq!(prod_config.sampling_rate, 0.1);
    }
}
