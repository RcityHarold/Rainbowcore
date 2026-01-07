//! Health Check API
//!
//! Provides health check endpoints for monitoring and load balancing.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Health status enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// Service is healthy
    Healthy,
    /// Service is degraded but operational
    Degraded,
    /// Service is unhealthy
    Unhealthy,
    /// Health status is unknown
    Unknown,
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self::Unknown
    }
}

impl HealthStatus {
    /// Check if status indicates service is operational
    pub fn is_operational(&self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded)
    }

    /// Get HTTP status code for this health status
    pub fn http_status_code(&self) -> u16 {
        match self {
            Self::Healthy => 200,
            Self::Degraded => 200,
            Self::Unhealthy => 503,
            Self::Unknown => 503,
        }
    }
}

/// Health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    /// Component name
    pub component: String,
    /// Health status
    pub status: HealthStatus,
    /// Optional message
    pub message: Option<String>,
    /// Check duration in milliseconds
    pub duration_ms: u64,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Additional details
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub details: HashMap<String, String>,
}

impl HealthCheckResult {
    /// Create a healthy result
    pub fn healthy(component: &str, duration: Duration) -> Self {
        Self {
            component: component.to_string(),
            status: HealthStatus::Healthy,
            message: None,
            duration_ms: duration.as_millis() as u64,
            timestamp: chrono::Utc::now(),
            details: HashMap::new(),
        }
    }

    /// Create an unhealthy result
    pub fn unhealthy(component: &str, message: &str, duration: Duration) -> Self {
        Self {
            component: component.to_string(),
            status: HealthStatus::Unhealthy,
            message: Some(message.to_string()),
            duration_ms: duration.as_millis() as u64,
            timestamp: chrono::Utc::now(),
            details: HashMap::new(),
        }
    }

    /// Create a degraded result
    pub fn degraded(component: &str, message: &str, duration: Duration) -> Self {
        Self {
            component: component.to_string(),
            status: HealthStatus::Degraded,
            message: Some(message.to_string()),
            duration_ms: duration.as_millis() as u64,
            timestamp: chrono::Utc::now(),
            details: HashMap::new(),
        }
    }

    /// Add a detail to the result
    pub fn with_detail(mut self, key: &str, value: &str) -> Self {
        self.details.insert(key.to_string(), value.to_string());
        self
    }
}

/// Health check trait
#[async_trait::async_trait]
pub trait HealthCheck: Send + Sync {
    /// Get component name
    fn name(&self) -> &str;

    /// Perform health check
    async fn check(&self) -> HealthCheckResult;

    /// Is this check critical?
    fn is_critical(&self) -> bool {
        true
    }
}

/// Health response for API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Overall status
    pub status: HealthStatus,
    /// Service version
    pub version: String,
    /// Uptime in seconds
    pub uptime_secs: u64,
    /// Individual component checks
    pub checks: Vec<HealthCheckResult>,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl HealthResponse {
    /// Create new health response
    pub fn new(checks: Vec<HealthCheckResult>, uptime: Duration) -> Self {
        // Determine overall status based on checks
        let status = Self::aggregate_status(&checks);

        Self {
            status,
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs: uptime.as_secs(),
            checks,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Aggregate status from multiple checks
    fn aggregate_status(checks: &[HealthCheckResult]) -> HealthStatus {
        let has_unhealthy = checks.iter().any(|c| c.status == HealthStatus::Unhealthy);
        let has_degraded = checks.iter().any(|c| c.status == HealthStatus::Degraded);
        let has_unknown = checks.iter().any(|c| c.status == HealthStatus::Unknown);

        if has_unhealthy {
            HealthStatus::Unhealthy
        } else if has_degraded || has_unknown {
            HealthStatus::Degraded
        } else if checks.is_empty() {
            HealthStatus::Unknown
        } else {
            HealthStatus::Healthy
        }
    }
}

/// Health endpoint manager
pub struct HealthEndpoint {
    /// Registered health checks
    checks: RwLock<Vec<Arc<dyn HealthCheck>>>,
    /// Service start time
    start_time: Instant,
    /// Cache duration
    cache_duration: Duration,
    /// Cached response
    cached_response: RwLock<Option<(HealthResponse, Instant)>>,
}

impl HealthEndpoint {
    /// Create new health endpoint
    pub fn new() -> Self {
        Self {
            checks: RwLock::new(Vec::new()),
            start_time: Instant::now(),
            cache_duration: Duration::from_secs(5),
            cached_response: RwLock::new(None),
        }
    }

    /// Create with custom cache duration
    pub fn with_cache_duration(mut self, duration: Duration) -> Self {
        self.cache_duration = duration;
        self
    }

    /// Register a health check
    pub async fn register(&self, check: Arc<dyn HealthCheck>) {
        let name = check.name().to_string();
        self.checks.write().await.push(check);
        debug!(check = %name, "Registered health check");
    }

    /// Perform all health checks
    pub async fn check(&self) -> HealthResponse {
        // Check cache first
        {
            let cache = self.cached_response.read().await;
            if let Some((response, cached_at)) = cache.as_ref() {
                if cached_at.elapsed() < self.cache_duration {
                    return response.clone();
                }
            }
        }

        // Perform checks
        let checks = self.checks.read().await;
        let mut results = Vec::with_capacity(checks.len());

        for check in checks.iter() {
            let result = check.check().await;
            if result.status != HealthStatus::Healthy {
                warn!(
                    component = result.component,
                    status = ?result.status,
                    message = ?result.message,
                    "Health check not healthy"
                );
            }
            results.push(result);
        }

        let uptime = self.start_time.elapsed();
        let response = HealthResponse::new(results, uptime);

        // Update cache
        {
            let mut cache = self.cached_response.write().await;
            *cache = Some((response.clone(), Instant::now()));
        }

        response
    }

    /// Quick liveness check (no detailed checks)
    pub fn liveness(&self) -> HealthStatus {
        HealthStatus::Healthy
    }

    /// Readiness check (checks critical components)
    pub async fn readiness(&self) -> HealthStatus {
        let checks = self.checks.read().await;

        for check in checks.iter() {
            if check.is_critical() {
                let result = check.check().await;
                if !result.status.is_operational() {
                    return HealthStatus::Unhealthy;
                }
            }
        }

        HealthStatus::Healthy
    }

    /// Get uptime
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }
}

impl Default for HealthEndpoint {
    fn default() -> Self {
        Self::new()
    }
}

/// System-wide health aggregator
pub struct SystemHealth {
    /// Local endpoint health
    endpoint: HealthEndpoint,
    /// Node ID
    node_id: String,
    /// Environment
    environment: String,
}

impl SystemHealth {
    /// Create new system health
    pub fn new(node_id: &str, environment: &str) -> Self {
        Self {
            endpoint: HealthEndpoint::new(),
            node_id: node_id.to_string(),
            environment: environment.to_string(),
        }
    }

    /// Get the health endpoint
    pub fn endpoint(&self) -> &HealthEndpoint {
        &self.endpoint
    }

    /// Register a health check
    pub async fn register(&self, check: Arc<dyn HealthCheck>) {
        self.endpoint.register(check).await;
    }

    /// Get full health response with system info
    pub async fn full_check(&self) -> SystemHealthResponse {
        let health = self.endpoint.check().await;

        SystemHealthResponse {
            node_id: self.node_id.clone(),
            environment: self.environment.clone(),
            health,
        }
    }
}

/// System health response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealthResponse {
    /// Node identifier
    pub node_id: String,
    /// Environment (dev, staging, prod)
    pub environment: String,
    /// Health details
    pub health: HealthResponse,
}

/// Storage backend health check
pub struct StorageHealthCheck {
    /// Backend name
    name: String,
    /// Check function
    check_fn: Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>> + Send + Sync>,
}

impl StorageHealthCheck {
    /// Create new storage health check
    pub fn new<F, Fut>(name: &str, check_fn: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<(), String>> + Send + 'static,
    {
        Self {
            name: name.to_string(),
            check_fn: Arc::new(move || Box::pin(check_fn())),
        }
    }
}

#[async_trait::async_trait]
impl HealthCheck for StorageHealthCheck {
    fn name(&self) -> &str {
        &self.name
    }

    async fn check(&self) -> HealthCheckResult {
        let start = Instant::now();
        let result = (self.check_fn)().await;
        let duration = start.elapsed();

        match result {
            Ok(()) => HealthCheckResult::healthy(&self.name, duration),
            Err(e) => HealthCheckResult::unhealthy(&self.name, &e, duration),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status() {
        assert!(HealthStatus::Healthy.is_operational());
        assert!(HealthStatus::Degraded.is_operational());
        assert!(!HealthStatus::Unhealthy.is_operational());
        assert!(!HealthStatus::Unknown.is_operational());
    }

    #[test]
    fn test_health_check_result() {
        let result = HealthCheckResult::healthy("test", Duration::from_millis(10));
        assert_eq!(result.status, HealthStatus::Healthy);
        assert_eq!(result.component, "test");

        let result = HealthCheckResult::unhealthy("test", "error", Duration::from_millis(10));
        assert_eq!(result.status, HealthStatus::Unhealthy);
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let endpoint = HealthEndpoint::new();
        let response = endpoint.check().await;

        // No checks registered, should be unknown
        assert_eq!(response.status, HealthStatus::Unknown);
    }

    #[test]
    fn test_aggregate_status() {
        let healthy = HealthCheckResult::healthy("a", Duration::ZERO);
        let degraded = HealthCheckResult::degraded("b", "msg", Duration::ZERO);
        let unhealthy = HealthCheckResult::unhealthy("c", "err", Duration::ZERO);

        // All healthy
        let status = HealthResponse::aggregate_status(&[healthy.clone()]);
        assert_eq!(status, HealthStatus::Healthy);

        // Has degraded
        let status = HealthResponse::aggregate_status(&[healthy.clone(), degraded]);
        assert_eq!(status, HealthStatus::Degraded);

        // Has unhealthy
        let status = HealthResponse::aggregate_status(&[healthy, unhealthy]);
        assert_eq!(status, HealthStatus::Unhealthy);
    }
}
