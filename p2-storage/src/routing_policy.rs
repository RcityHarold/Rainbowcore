//! Backend Routing Policy
//!
//! Defines strategies for selecting storage backends.

use async_trait::async_trait;
use p2_core::types::StorageTemperature;
use serde::{Deserialize, Serialize};

use crate::backend::{BackendType, WriteMetadata};

/// Routing decision from policy
#[derive(Debug, Clone)]
pub enum RoutingDecision {
    /// Route to specific backend
    Route(BackendType),
    /// Failover to alternatives in order
    Failover(Vec<BackendType>),
    /// Reject the operation
    Reject(String),
}

/// Routing policy trait
#[async_trait]
pub trait RoutingPolicy {
    /// Decide which backend to use for write operation
    async fn decide_write(&self, metadata: &WriteMetadata) -> RoutingDecision;

    /// Decide which backend to use for read operation
    async fn decide_read(&self, ref_id: &str) -> RoutingDecision;

    /// Get policy name
    fn name(&self) -> &'static str;
}

/// Temperature-based routing policy
///
/// Routes based on storage temperature:
/// - Hot: Local/fast storage
/// - Warm: Distributed storage
/// - Cold: Archive storage (IPFS/S3 Glacier)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemperatureBasedPolicy {
    /// Backend for hot data
    pub hot_backend: BackendType,
    /// Backend for warm data
    pub warm_backend: BackendType,
    /// Backend for cold data
    pub cold_backend: BackendType,
}

impl Default for TemperatureBasedPolicy {
    fn default() -> Self {
        Self {
            hot_backend: BackendType::Local,
            warm_backend: BackendType::Ipfs,
            cold_backend: BackendType::S3,
        }
    }
}

#[async_trait]
impl RoutingPolicy for TemperatureBasedPolicy {
    async fn decide_write(&self, metadata: &WriteMetadata) -> RoutingDecision {
        let backend = match metadata.temperature {
            StorageTemperature::Hot => self.hot_backend,
            StorageTemperature::Warm => self.warm_backend,
            StorageTemperature::Cold => self.cold_backend,
        };
        RoutingDecision::Route(backend)
    }

    async fn decide_read(&self, _ref_id: &str) -> RoutingDecision {
        // For reads, try hot first, then warm, then cold
        RoutingDecision::Failover(vec![
            self.hot_backend,
            self.warm_backend,
            self.cold_backend,
        ])
    }

    fn name(&self) -> &'static str {
        "temperature_based"
    }
}

/// Round-robin routing policy
///
/// Distributes writes evenly across backends.
pub struct RoundRobinPolicy {
    backends: Vec<BackendType>,
    counter: std::sync::atomic::AtomicUsize,
}

impl RoundRobinPolicy {
    /// Create a new round-robin policy
    pub fn new(backends: Vec<BackendType>) -> Self {
        Self {
            backends,
            counter: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl RoutingPolicy for RoundRobinPolicy {
    async fn decide_write(&self, _metadata: &WriteMetadata) -> RoutingDecision {
        if self.backends.is_empty() {
            return RoutingDecision::Reject("No backends configured".to_string());
        }

        let index = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % self.backends.len();

        RoutingDecision::Route(self.backends[index])
    }

    async fn decide_read(&self, _ref_id: &str) -> RoutingDecision {
        if self.backends.is_empty() {
            return RoutingDecision::Reject("No backends configured".to_string());
        }
        RoutingDecision::Failover(self.backends.clone())
    }

    fn name(&self) -> &'static str {
        "round_robin"
    }
}

/// Primary-backup routing policy
///
/// Always routes to primary backend, fails over to backup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrimaryBackupPolicy {
    /// Primary backend
    pub primary: BackendType,
    /// Backup backends in order
    pub backups: Vec<BackendType>,
}

impl Default for PrimaryBackupPolicy {
    fn default() -> Self {
        Self {
            primary: BackendType::Local,
            backups: vec![BackendType::Ipfs],
        }
    }
}

#[async_trait]
impl RoutingPolicy for PrimaryBackupPolicy {
    async fn decide_write(&self, _metadata: &WriteMetadata) -> RoutingDecision {
        RoutingDecision::Route(self.primary)
    }

    async fn decide_read(&self, _ref_id: &str) -> RoutingDecision {
        let mut order = vec![self.primary];
        order.extend(self.backups.clone());
        RoutingDecision::Failover(order)
    }

    fn name(&self) -> &'static str {
        "primary_backup"
    }
}

/// Content-type based routing policy
///
/// Routes based on content type.
#[derive(Debug, Clone, Default)]
pub struct ContentTypePolicy {
    /// Mapping from content type pattern to backend
    pub rules: Vec<ContentTypeRule>,
    /// Default backend if no rule matches
    pub default_backend: BackendType,
}

/// Content type routing rule
#[derive(Debug, Clone)]
pub struct ContentTypeRule {
    /// Content type pattern (prefix match)
    pub pattern: String,
    /// Target backend
    pub backend: BackendType,
}

impl ContentTypePolicy {
    /// Create a new content-type policy
    pub fn new(default_backend: BackendType) -> Self {
        Self {
            rules: Vec::new(),
            default_backend,
        }
    }

    /// Add a routing rule
    pub fn add_rule(&mut self, pattern: &str, backend: BackendType) {
        self.rules.push(ContentTypeRule {
            pattern: pattern.to_string(),
            backend,
        });
    }
}

#[async_trait]
impl RoutingPolicy for ContentTypePolicy {
    async fn decide_write(&self, metadata: &WriteMetadata) -> RoutingDecision {
        for rule in &self.rules {
            if metadata.content_type.starts_with(&rule.pattern) {
                return RoutingDecision::Route(rule.backend);
            }
        }
        RoutingDecision::Route(self.default_backend)
    }

    async fn decide_read(&self, _ref_id: &str) -> RoutingDecision {
        // Collect all unique backends
        let mut backends: Vec<BackendType> = self.rules.iter().map(|r| r.backend).collect();
        backends.push(self.default_backend);
        backends.dedup();
        RoutingDecision::Failover(backends)
    }

    fn name(&self) -> &'static str {
        "content_type"
    }
}

/// Size-based routing policy
///
/// Routes based on payload size.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SizeBasedPolicy {
    /// Small payload threshold (bytes)
    pub small_threshold: u64,
    /// Large payload threshold (bytes)
    pub large_threshold: u64,
    /// Backend for small payloads
    pub small_backend: BackendType,
    /// Backend for medium payloads
    pub medium_backend: BackendType,
    /// Backend for large payloads
    pub large_backend: BackendType,
}

impl Default for SizeBasedPolicy {
    fn default() -> Self {
        Self {
            small_threshold: 1024 * 1024,       // 1MB
            large_threshold: 100 * 1024 * 1024, // 100MB
            small_backend: BackendType::Local,
            medium_backend: BackendType::Local,
            large_backend: BackendType::S3,
        }
    }
}

#[async_trait]
impl RoutingPolicy for SizeBasedPolicy {
    async fn decide_write(&self, metadata: &WriteMetadata) -> RoutingDecision {
        let backend = if let Some(size) = metadata.expected_size {
            if size < self.small_threshold {
                self.small_backend
            } else if size < self.large_threshold {
                self.medium_backend
            } else {
                self.large_backend
            }
        } else {
            // Default to medium backend if size unknown
            self.medium_backend
        };
        RoutingDecision::Route(backend)
    }

    async fn decide_read(&self, _ref_id: &str) -> RoutingDecision {
        RoutingDecision::Failover(vec![
            self.small_backend,
            self.medium_backend,
            self.large_backend,
        ])
    }

    fn name(&self) -> &'static str {
        "size_based"
    }
}

/// Composite routing policy
///
/// Combines multiple policies with priority.
pub struct CompositePolicy {
    policies: Vec<(Box<dyn RoutingPolicy + Send + Sync>, u8)>,
}

impl CompositePolicy {
    /// Create a new composite policy
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    /// Add a policy with priority (higher = more priority)
    pub fn add_policy(&mut self, policy: Box<dyn RoutingPolicy + Send + Sync>, priority: u8) {
        self.policies.push((policy, priority));
        self.policies.sort_by(|a, b| b.1.cmp(&a.1));
    }
}

impl Default for CompositePolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RoutingPolicy for CompositePolicy {
    async fn decide_write(&self, metadata: &WriteMetadata) -> RoutingDecision {
        for (policy, _) in &self.policies {
            let decision = policy.decide_write(metadata).await;
            match &decision {
                RoutingDecision::Reject(_) => continue,
                _ => return decision,
            }
        }
        RoutingDecision::Reject("No policy provided a routing decision".to_string())
    }

    async fn decide_read(&self, ref_id: &str) -> RoutingDecision {
        let mut all_backends = Vec::new();
        for (policy, _) in &self.policies {
            if let RoutingDecision::Failover(backends) = policy.decide_read(ref_id).await {
                all_backends.extend(backends);
            }
        }
        all_backends.dedup();

        if all_backends.is_empty() {
            RoutingDecision::Reject("No backends available".to_string())
        } else {
            RoutingDecision::Failover(all_backends)
        }
    }

    fn name(&self) -> &'static str {
        "composite"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_temperature_based_policy() {
        let policy = TemperatureBasedPolicy::default();

        let hot_meta = WriteMetadata {
            temperature: StorageTemperature::Hot,
            ..Default::default()
        };
        let decision = policy.decide_write(&hot_meta).await;
        assert!(matches!(decision, RoutingDecision::Route(BackendType::Local)));

        let cold_meta = WriteMetadata {
            temperature: StorageTemperature::Cold,
            ..Default::default()
        };
        let decision = policy.decide_write(&cold_meta).await;
        assert!(matches!(decision, RoutingDecision::Route(BackendType::S3)));
    }

    #[tokio::test]
    async fn test_primary_backup_policy() {
        let policy = PrimaryBackupPolicy::default();

        let meta = WriteMetadata::default();
        let decision = policy.decide_write(&meta).await;
        assert!(matches!(decision, RoutingDecision::Route(BackendType::Local)));
    }

    #[tokio::test]
    async fn test_round_robin_policy() {
        let policy = RoundRobinPolicy::new(vec![BackendType::Local, BackendType::Ipfs]);
        let meta = WriteMetadata::default();

        // Should alternate between Local and IPFS
        let d1 = policy.decide_write(&meta).await;
        let d2 = policy.decide_write(&meta).await;
        let d3 = policy.decide_write(&meta).await;

        assert!(matches!(d1, RoutingDecision::Route(BackendType::Local)));
        assert!(matches!(d2, RoutingDecision::Route(BackendType::Ipfs)));
        assert!(matches!(d3, RoutingDecision::Route(BackendType::Local)));
    }
}
