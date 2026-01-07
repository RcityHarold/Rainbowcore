//! Multi-Backend Router
//!
//! Routes storage operations to appropriate backends based on configuration.

use async_trait::async_trait;
use p2_core::types::{SealedPayloadRef, StorageTemperature};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::backend::{
    BackendCapabilities, BackendType, HealthStatus, IntegrityResult, P2StorageBackend,
    PayloadMetadata, WriteMetadata,
};
use crate::error::{StorageError, StorageResult};
use crate::failover::FailoverManager;
use crate::health_monitor::HealthMonitor;
use crate::routing_policy::{RoutingDecision, RoutingPolicy};

/// Backend router configuration
#[derive(Debug, Clone)]
pub struct RouterConfig {
    /// Default backend for writes
    pub default_backend: BackendType,
    /// Enable automatic failover
    pub enable_failover: bool,
    /// Enable read-through caching
    pub enable_read_through: bool,
    /// Retry count on failure
    pub retry_count: u32,
    /// Timeout for operations in milliseconds
    pub operation_timeout_ms: u64,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            default_backend: BackendType::Local,
            enable_failover: true,
            enable_read_through: true,
            retry_count: 3,
            operation_timeout_ms: 30_000,
        }
    }
}

/// Backend registration entry
struct BackendEntry {
    backend: Arc<dyn P2StorageBackend + Send + Sync>,
    priority: u8,
    enabled: bool,
}

/// Multi-backend router
pub struct BackendRouter {
    config: RouterConfig,
    /// Registered backends by type
    backends: RwLock<HashMap<BackendType, BackendEntry>>,
    /// Routing policy
    routing_policy: Arc<dyn RoutingPolicy + Send + Sync>,
    /// Failover manager
    failover_manager: Arc<FailoverManager>,
    /// Health monitor
    health_monitor: Arc<HealthMonitor>,
    /// Payload location map (ref_id -> backend types)
    location_map: RwLock<HashMap<String, Vec<BackendType>>>,
}

impl BackendRouter {
    /// Create a new backend router
    pub fn new(
        config: RouterConfig,
        routing_policy: Arc<dyn RoutingPolicy + Send + Sync>,
        failover_manager: Arc<FailoverManager>,
        health_monitor: Arc<HealthMonitor>,
    ) -> Self {
        Self {
            config,
            backends: RwLock::new(HashMap::new()),
            routing_policy,
            failover_manager,
            health_monitor,
            location_map: RwLock::new(HashMap::new()),
        }
    }

    /// Register a backend
    pub async fn register_backend(
        &self,
        backend_type: BackendType,
        backend: Arc<dyn P2StorageBackend + Send + Sync>,
        priority: u8,
    ) {
        let mut backends = self.backends.write().await;
        backends.insert(
            backend_type,
            BackendEntry {
                backend,
                priority,
                enabled: true,
            },
        );

        info!(
            backend = ?backend_type,
            priority = priority,
            "Registered storage backend"
        );
    }

    /// Unregister a backend
    pub async fn unregister_backend(&self, backend_type: BackendType) {
        let mut backends = self.backends.write().await;
        backends.remove(&backend_type);

        info!(backend = ?backend_type, "Unregistered storage backend");
    }

    /// Enable/disable a backend
    pub async fn set_backend_enabled(&self, backend_type: BackendType, enabled: bool) {
        let mut backends = self.backends.write().await;
        if let Some(entry) = backends.get_mut(&backend_type) {
            entry.enabled = enabled;
            info!(
                backend = ?backend_type,
                enabled = enabled,
                "Backend enabled state changed"
            );
        }
    }

    /// Get backend by type
    async fn get_backend(
        &self,
        backend_type: BackendType,
    ) -> Option<Arc<dyn P2StorageBackend + Send + Sync>> {
        let backends = self.backends.read().await;
        backends
            .get(&backend_type)
            .filter(|e| e.enabled)
            .map(|e| e.backend.clone())
    }

    /// Get all healthy backends sorted by priority
    async fn get_healthy_backends(&self) -> Vec<(BackendType, Arc<dyn P2StorageBackend + Send + Sync>)> {
        let backends = self.backends.read().await;
        let mut result: Vec<_> = backends
            .iter()
            .filter(|(_, e)| e.enabled)
            .filter(|(bt, _)| self.health_monitor.is_healthy(**bt))
            .map(|(bt, e)| (*bt, e.backend.clone(), e.priority))
            .collect();

        // Sort by priority (higher first)
        result.sort_by(|a, b| b.2.cmp(&a.2));
        result.into_iter().map(|(bt, b, _)| (bt, b)).collect()
    }

    /// Select backend for write operation
    async fn select_write_backend(
        &self,
        metadata: &WriteMetadata,
    ) -> StorageResult<(BackendType, Arc<dyn P2StorageBackend + Send + Sync>)> {
        // Get routing decision from policy
        let decision = self.routing_policy.decide_write(metadata).await;

        match decision {
            RoutingDecision::Route(backend_type) => {
                if let Some(backend) = self.get_backend(backend_type).await {
                    if self.health_monitor.is_healthy(backend_type) {
                        return Ok((backend_type, backend));
                    }
                }

                // Try failover
                if self.config.enable_failover {
                    self.failover_write_backend(metadata).await
                } else {
                    Err(StorageError::Unavailable(format!(
                        "Primary backend {:?} unavailable",
                        backend_type
                    )))
                }
            }
            RoutingDecision::Failover(alternatives) => {
                for backend_type in alternatives {
                    if let Some(backend) = self.get_backend(backend_type).await {
                        if self.health_monitor.is_healthy(backend_type) {
                            return Ok((backend_type, backend));
                        }
                    }
                }
                Err(StorageError::Unavailable(
                    "No healthy backends available".to_string(),
                ))
            }
            RoutingDecision::Reject(reason) => {
                Err(StorageError::OperationFailed(reason))
            }
        }
    }

    /// Failover to alternative backend for write
    async fn failover_write_backend(
        &self,
        metadata: &WriteMetadata,
    ) -> StorageResult<(BackendType, Arc<dyn P2StorageBackend + Send + Sync>)> {
        let failover_order = self
            .failover_manager
            .get_failover_order(self.config.default_backend)
            .await;

        for backend_type in failover_order {
            if let Some(backend) = self.get_backend(backend_type).await {
                if self.health_monitor.is_healthy(backend_type) {
                    warn!(
                        from = ?self.config.default_backend,
                        to = ?backend_type,
                        "Failover for write operation"
                    );
                    return Ok((backend_type, backend));
                }
            }
        }

        Err(StorageError::Unavailable(
            "All backends unavailable for write".to_string(),
        ))
    }

    /// Select backend for read operation
    async fn select_read_backend(
        &self,
        ref_id: &str,
    ) -> StorageResult<(BackendType, Arc<dyn P2StorageBackend + Send + Sync>)> {
        // Check location map for known locations
        let locations = self.location_map.read().await;
        if let Some(backend_types) = locations.get(ref_id) {
            for backend_type in backend_types {
                if let Some(backend) = self.get_backend(*backend_type).await {
                    if self.health_monitor.is_healthy(*backend_type) {
                        return Ok((*backend_type, backend));
                    }
                }
            }
        }
        drop(locations);

        // Try all healthy backends
        let healthy_backends = self.get_healthy_backends().await;
        for (backend_type, backend) in healthy_backends {
            // Check if payload exists in this backend
            if backend.exists(ref_id).await? {
                // Update location map
                self.location_map
                    .write()
                    .await
                    .entry(ref_id.to_string())
                    .or_default()
                    .push(backend_type);
                return Ok((backend_type, backend));
            }
        }

        Err(StorageError::NotFound(ref_id.to_string()))
    }

    /// Record payload location
    async fn record_location(&self, ref_id: &str, backend_type: BackendType) {
        let mut locations = self.location_map.write().await;
        locations
            .entry(ref_id.to_string())
            .or_default()
            .push(backend_type);
    }

    /// Get backend statistics
    pub async fn get_stats(&self) -> RouterStats {
        let backends = self.backends.read().await;
        let locations = self.location_map.read().await;

        let mut backend_stats = HashMap::new();
        for (bt, entry) in backends.iter() {
            backend_stats.insert(
                *bt,
                BackendStats {
                    enabled: entry.enabled,
                    priority: entry.priority,
                    healthy: self.health_monitor.is_healthy(*bt),
                },
            );
        }

        RouterStats {
            total_backends: backends.len(),
            healthy_backends: backend_stats.values().filter(|s| s.healthy).count(),
            tracked_payloads: locations.len(),
            backend_stats,
        }
    }
}

#[async_trait]
impl P2StorageBackend for BackendRouter {
    async fn write(&self, data: &[u8], metadata: WriteMetadata) -> StorageResult<SealedPayloadRef> {
        let (backend_type, backend) = self.select_write_backend(&metadata).await?;

        let mut last_error = None;
        for attempt in 0..=self.config.retry_count {
            match backend.write(data, metadata.clone()).await {
                Ok(payload_ref) => {
                    self.record_location(&payload_ref.ref_id, backend_type).await;
                    debug!(
                        ref_id = %payload_ref.ref_id,
                        backend = ?backend_type,
                        attempt = attempt,
                        "Write succeeded"
                    );
                    return Ok(payload_ref);
                }
                Err(e) => {
                    warn!(
                        backend = ?backend_type,
                        attempt = attempt,
                        error = %e,
                        "Write attempt failed"
                    );
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            StorageError::WriteFailed("All write attempts failed".to_string())
        }))
    }

    async fn read(&self, ref_id: &str) -> StorageResult<Vec<u8>> {
        let (backend_type, backend) = self.select_read_backend(ref_id).await?;

        match backend.read(ref_id).await {
            Ok(data) => {
                debug!(
                    ref_id = %ref_id,
                    backend = ?backend_type,
                    "Read succeeded"
                );
                Ok(data)
            }
            Err(e) => {
                // Try failover
                if self.config.enable_failover {
                    let healthy_backends = self.get_healthy_backends().await;
                    for (bt, b) in healthy_backends {
                        if bt != backend_type {
                            if let Ok(data) = b.read(ref_id).await {
                                self.record_location(ref_id, bt).await;
                                return Ok(data);
                            }
                        }
                    }
                }
                Err(e)
            }
        }
    }

    async fn exists(&self, ref_id: &str) -> StorageResult<bool> {
        // Check location map first
        let locations = self.location_map.read().await;
        if locations.contains_key(ref_id) {
            return Ok(true);
        }
        drop(locations);

        // Check all backends
        let healthy_backends = self.get_healthy_backends().await;
        for (_, backend) in healthy_backends {
            if backend.exists(ref_id).await? {
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn get_metadata(&self, ref_id: &str) -> StorageResult<PayloadMetadata> {
        let (_, backend) = self.select_read_backend(ref_id).await?;
        backend.get_metadata(ref_id).await
    }

    async fn tombstone(&self, ref_id: &str) -> StorageResult<()> {
        // Tombstone in all backends that have this payload
        let locations = self.location_map.read().await;
        if let Some(backend_types) = locations.get(ref_id) {
            for backend_type in backend_types {
                if let Some(backend) = self.get_backend(*backend_type).await {
                    backend.tombstone(ref_id).await?;
                }
            }
        }
        Ok(())
    }

    async fn migrate_temperature(
        &self,
        ref_id: &str,
        target_temp: StorageTemperature,
    ) -> StorageResult<SealedPayloadRef> {
        let (_, backend) = self.select_read_backend(ref_id).await?;
        backend.migrate_temperature(ref_id, target_temp).await
    }

    async fn verify_integrity(&self, ref_id: &str) -> StorageResult<IntegrityResult> {
        let (_, backend) = self.select_read_backend(ref_id).await?;
        backend.verify_integrity(ref_id).await
    }

    fn backend_type(&self) -> BackendType {
        BackendType::Router
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            supports_temperature: true,
            supports_streaming: true,
            supports_atomic_write: false, // Depends on underlying backends
            content_addressed: false,
            max_payload_size: None, // Unlimited
            durability_nines: 9,    // Depends on configuration
        }
    }

    async fn health_check(&self) -> StorageResult<HealthStatus> {
        let healthy_count = self
            .get_healthy_backends()
            .await
            .len();

        let total = self.backends.read().await.len();

        if healthy_count == 0 {
            Ok(HealthStatus::unhealthy("No healthy backends"))
        } else if healthy_count < total {
            Ok(HealthStatus::degraded(&format!(
                "{}/{} backends healthy",
                healthy_count, total
            )))
        } else {
            Ok(HealthStatus::healthy())
        }
    }
}

/// Router statistics
#[derive(Debug, Clone)]
pub struct RouterStats {
    /// Total registered backends
    pub total_backends: usize,
    /// Number of healthy backends
    pub healthy_backends: usize,
    /// Number of tracked payloads
    pub tracked_payloads: usize,
    /// Per-backend statistics
    pub backend_stats: HashMap<BackendType, BackendStats>,
}

/// Per-backend statistics
#[derive(Debug, Clone)]
pub struct BackendStats {
    /// Whether backend is enabled
    pub enabled: bool,
    /// Backend priority
    pub priority: u8,
    /// Whether backend is healthy
    pub healthy: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_config_default() {
        let config = RouterConfig::default();
        assert_eq!(config.default_backend, BackendType::Local);
        assert!(config.enable_failover);
        assert_eq!(config.retry_count, 3);
    }
}
