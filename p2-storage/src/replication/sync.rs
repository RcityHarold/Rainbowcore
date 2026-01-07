//! Synchronous Replication
//!
//! Implements synchronous replication where writes wait for all replicas
//! to confirm before returning success.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::error::{StorageError, StorageResult};

use super::config::{ConsistencyLevel, ReplicationConfig, ReplicaNodeConfig};

/// Sync replication result for a single node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeReplicationResult {
    /// Node ID
    pub node_id: String,
    /// Whether replication succeeded
    pub success: bool,
    /// Replication duration in milliseconds
    pub duration_ms: u64,
    /// Error message if failed
    pub error: Option<String>,
    /// Timestamp of completion
    pub completed_at: DateTime<Utc>,
}

/// Sync replication result for a write operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncReplicationResult {
    /// Payload reference ID
    pub ref_id: String,
    /// Total nodes attempted
    pub nodes_attempted: usize,
    /// Successful replications
    pub nodes_succeeded: usize,
    /// Failed replications
    pub nodes_failed: usize,
    /// Per-node results
    pub node_results: Vec<NodeReplicationResult>,
    /// Whether overall replication met consistency requirements
    pub consistency_met: bool,
    /// Total duration in milliseconds
    pub total_duration_ms: u64,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Replica client trait for communicating with replica nodes
#[async_trait]
pub trait ReplicaClient: Send + Sync {
    /// Write data to a replica node
    async fn write(&self, node: &ReplicaNodeConfig, ref_id: &str, data: &[u8]) -> StorageResult<()>;

    /// Read data from a replica node
    async fn read(&self, node: &ReplicaNodeConfig, ref_id: &str) -> StorageResult<Vec<u8>>;

    /// Check if data exists on a replica node
    async fn exists(&self, node: &ReplicaNodeConfig, ref_id: &str) -> StorageResult<bool>;

    /// Delete data from a replica node
    async fn delete(&self, node: &ReplicaNodeConfig, ref_id: &str) -> StorageResult<()>;

    /// Health check a replica node
    async fn health_check(&self, node: &ReplicaNodeConfig) -> StorageResult<bool>;
}

/// Synchronous replicator
pub struct SyncReplicator<C: ReplicaClient> {
    config: Arc<RwLock<ReplicationConfig>>,
    client: Arc<C>,
    /// Node health status
    node_health: Arc<RwLock<HashMap<String, NodeHealthStatus>>>,
}

/// Node health status
#[derive(Debug, Clone)]
pub struct NodeHealthStatus {
    pub healthy: bool,
    pub last_check: DateTime<Utc>,
    pub consecutive_failures: u32,
    pub latency_ms: Option<u64>,
}

impl Default for NodeHealthStatus {
    fn default() -> Self {
        Self {
            healthy: true,
            last_check: Utc::now(),
            consecutive_failures: 0,
            latency_ms: None,
        }
    }
}

impl<C: ReplicaClient + 'static> SyncReplicator<C> {
    /// Create a new synchronous replicator
    pub fn new(config: ReplicationConfig, client: Arc<C>) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            client,
            node_health: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Replicate data synchronously to required number of nodes
    pub async fn replicate(
        &self,
        ref_id: &str,
        data: &[u8],
        required_replicas: usize,
    ) -> StorageResult<SyncReplicationResult> {
        let start = std::time::Instant::now();
        let config = self.config.read().await;

        // Get healthy nodes
        let nodes = self.get_healthy_nodes(&config).await;
        let nodes_to_use = nodes.into_iter().take(required_replicas).collect::<Vec<_>>();

        if nodes_to_use.len() < required_replicas {
            warn!(
                ref_id = %ref_id,
                required = required_replicas,
                available = nodes_to_use.len(),
                "Insufficient healthy nodes for replication"
            );
        }

        let consistency_level = config.write_consistency;
        drop(config);

        // Replicate to all nodes in parallel
        let mut handles = Vec::new();
        for node in &nodes_to_use {
            let client = self.client.clone();
            let node_config = node.clone();
            let ref_id = ref_id.to_string();
            let data = data.to_vec();

            handles.push(tokio::spawn(async move {
                let node_start = std::time::Instant::now();
                let result = client.write(&node_config, &ref_id, &data).await;
                let duration_ms = node_start.elapsed().as_millis() as u64;

                NodeReplicationResult {
                    node_id: node_config.node_id.clone(),
                    success: result.is_ok(),
                    duration_ms,
                    error: result.err().map(|e| e.to_string()),
                    completed_at: Utc::now(),
                }
            }));
        }

        // Wait for all to complete
        let mut node_results = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(result) => node_results.push(result),
                Err(e) => {
                    error!(error = %e, "Replication task failed");
                }
            }
        }

        // Update node health
        self.update_node_health(&node_results).await;

        // Calculate results
        let nodes_succeeded = node_results.iter().filter(|r| r.success).count();
        let nodes_failed = node_results.len() - nodes_succeeded;

        // Check consistency requirements
        let consistency_met = match consistency_level {
            ConsistencyLevel::All => nodes_succeeded == nodes_to_use.len() && nodes_succeeded >= required_replicas,
            ConsistencyLevel::Quorum => nodes_succeeded >= (required_replicas / 2 + 1),
            ConsistencyLevel::One => nodes_succeeded >= 1,
            ConsistencyLevel::Local => true,
        };

        let result = SyncReplicationResult {
            ref_id: ref_id.to_string(),
            nodes_attempted: node_results.len(),
            nodes_succeeded,
            nodes_failed,
            node_results,
            consistency_met,
            total_duration_ms: start.elapsed().as_millis() as u64,
            timestamp: Utc::now(),
        };

        if consistency_met {
            info!(
                ref_id = %ref_id,
                succeeded = nodes_succeeded,
                failed = nodes_failed,
                duration_ms = result.total_duration_ms,
                "Sync replication completed"
            );
            Ok(result)
        } else {
            error!(
                ref_id = %ref_id,
                succeeded = nodes_succeeded,
                required = required_replicas,
                "Sync replication failed to meet consistency"
            );
            Err(StorageError::ReplicationFailed(format!(
                "Failed to meet consistency: {} of {} required replicas succeeded",
                nodes_succeeded, required_replicas
            )))
        }
    }

    /// Read from replicas with consistency level
    pub async fn read_consistent(
        &self,
        ref_id: &str,
        consistency: ConsistencyLevel,
    ) -> StorageResult<Vec<u8>> {
        let config = self.config.read().await;
        let nodes = self.get_healthy_nodes(&config).await;
        drop(config);

        match consistency {
            ConsistencyLevel::One | ConsistencyLevel::Local => {
                // Read from first available node
                for node in &nodes {
                    match self.client.read(node, ref_id).await {
                        Ok(data) => return Ok(data),
                        Err(e) => {
                            debug!(
                                node_id = %node.node_id,
                                error = %e,
                                "Failed to read from node, trying next"
                            );
                        }
                    }
                }
                Err(StorageError::NotFound(ref_id.to_string()))
            }
            ConsistencyLevel::Quorum | ConsistencyLevel::All => {
                // Read from multiple nodes and verify consistency
                let required = match consistency {
                    ConsistencyLevel::Quorum => nodes.len() / 2 + 1,
                    ConsistencyLevel::All => nodes.len(),
                    _ => 1,
                };

                let mut reads = Vec::new();
                let mut handles = Vec::new();

                for node in nodes.iter().take(required) {
                    let client = self.client.clone();
                    let node_config = node.clone();
                    let ref_id = ref_id.to_string();

                    handles.push(tokio::spawn(async move {
                        client.read(&node_config, &ref_id).await
                    }));
                }

                for handle in handles {
                    if let Ok(Ok(data)) = handle.await {
                        reads.push(data);
                    }
                }

                if reads.len() < required {
                    return Err(StorageError::NotFound(ref_id.to_string()));
                }

                // Verify all reads are consistent (simple check: all equal)
                let first = &reads[0];
                if reads.iter().all(|d| d == first) {
                    Ok(first.clone())
                } else {
                    Err(StorageError::ConsistencyError(format!(
                        "Inconsistent reads from {} replicas",
                        reads.len()
                    )))
                }
            }
        }
    }

    /// Get healthy nodes sorted by priority
    async fn get_healthy_nodes(&self, config: &ReplicationConfig) -> Vec<ReplicaNodeConfig> {
        let health = self.node_health.read().await;
        let mut nodes: Vec<_> = config
            .active_nodes()
            .into_iter()
            .filter(|n| {
                health
                    .get(&n.node_id)
                    .map(|h| h.healthy)
                    .unwrap_or(true)
            })
            .cloned()
            .collect();

        nodes.sort_by(|a, b| b.priority.cmp(&a.priority));
        nodes
    }

    /// Update node health based on replication results
    async fn update_node_health(&self, results: &[NodeReplicationResult]) {
        let mut health = self.node_health.write().await;

        for result in results {
            let status = health
                .entry(result.node_id.clone())
                .or_insert_with(NodeHealthStatus::default);

            if result.success {
                status.healthy = true;
                status.consecutive_failures = 0;
                status.latency_ms = Some(result.duration_ms);
            } else {
                status.consecutive_failures += 1;
                if status.consecutive_failures >= 3 {
                    status.healthy = false;
                    warn!(
                        node_id = %result.node_id,
                        failures = status.consecutive_failures,
                        "Marking node as unhealthy"
                    );
                }
            }
            status.last_check = Utc::now();
        }
    }

    /// Run health checks on all nodes
    pub async fn run_health_checks(&self) {
        let config = self.config.read().await;
        let nodes: Vec<_> = config.nodes.values().cloned().collect();
        drop(config);

        for node in nodes {
            let start = std::time::Instant::now();
            let result = self.client.health_check(&node).await;
            let latency = start.elapsed().as_millis() as u64;

            let mut health = self.node_health.write().await;
            let status = health
                .entry(node.node_id.clone())
                .or_insert_with(NodeHealthStatus::default);

            match result {
                Ok(true) => {
                    status.healthy = true;
                    status.consecutive_failures = 0;
                    status.latency_ms = Some(latency);
                }
                Ok(false) | Err(_) => {
                    status.consecutive_failures += 1;
                    if status.consecutive_failures >= 3 {
                        status.healthy = false;
                    }
                }
            }
            status.last_check = Utc::now();
        }
    }

    /// Get current node health status
    pub async fn get_node_health(&self) -> HashMap<String, NodeHealthStatus> {
        self.node_health.read().await.clone()
    }
}

/// Mock replica client for testing
pub struct MockReplicaClient {
    data: RwLock<HashMap<String, HashMap<String, Vec<u8>>>>,
}

impl MockReplicaClient {
    pub fn new() -> Self {
        Self {
            data: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for MockReplicaClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ReplicaClient for MockReplicaClient {
    async fn write(&self, node: &ReplicaNodeConfig, ref_id: &str, data: &[u8]) -> StorageResult<()> {
        let mut store = self.data.write().await;
        let node_data = store.entry(node.node_id.clone()).or_default();
        node_data.insert(ref_id.to_string(), data.to_vec());
        Ok(())
    }

    async fn read(&self, node: &ReplicaNodeConfig, ref_id: &str) -> StorageResult<Vec<u8>> {
        let store = self.data.read().await;
        store
            .get(&node.node_id)
            .and_then(|n| n.get(ref_id).cloned())
            .ok_or_else(|| StorageError::NotFound(ref_id.to_string()))
    }

    async fn exists(&self, node: &ReplicaNodeConfig, ref_id: &str) -> StorageResult<bool> {
        let store = self.data.read().await;
        Ok(store
            .get(&node.node_id)
            .map(|n| n.contains_key(ref_id))
            .unwrap_or(false))
    }

    async fn delete(&self, node: &ReplicaNodeConfig, ref_id: &str) -> StorageResult<()> {
        let mut store = self.data.write().await;
        if let Some(node_data) = store.get_mut(&node.node_id) {
            node_data.remove(ref_id);
        }
        Ok(())
    }

    async fn health_check(&self, _node: &ReplicaNodeConfig) -> StorageResult<bool> {
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sync_replication() {
        let client = Arc::new(MockReplicaClient::new());
        let mut config = ReplicationConfig::synchronous();

        config.add_node(ReplicaNodeConfig {
            node_id: "node1".to_string(),
            priority: 100,
            enabled: true,
            ..Default::default()
        });

        config.add_node(ReplicaNodeConfig {
            node_id: "node2".to_string(),
            priority: 100,
            enabled: true,
            ..Default::default()
        });

        let replicator = SyncReplicator::new(config, client);

        let result = replicator
            .replicate("test:001", b"test data", 2)
            .await
            .unwrap();

        assert!(result.consistency_met);
        assert_eq!(result.nodes_succeeded, 2);
    }

    #[tokio::test]
    async fn test_consistent_read() {
        let client = Arc::new(MockReplicaClient::new());
        let mut config = ReplicationConfig::default();

        let node = ReplicaNodeConfig {
            node_id: "node1".to_string(),
            priority: 100,
            enabled: true,
            ..Default::default()
        };
        config.add_node(node.clone());

        // Pre-populate data
        client.write(&node, "test:001", b"test data").await.unwrap();

        let replicator = SyncReplicator::new(config, client);
        let data = replicator
            .read_consistent("test:001", ConsistencyLevel::One)
            .await
            .unwrap();

        assert_eq!(data, b"test data");
    }
}
