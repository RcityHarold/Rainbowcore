//! Replication Manager
//!
//! Coordinates all replication activities across the storage layer.

use chrono::{DateTime, Utc};
use p2_core::types::StorageTemperature;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::error::{StorageError, StorageResult};

use super::async_repl::AsyncReplicator;
use super::config::{ConsistencyLevel, ReplicationConfig, ReplicationMode};
use super::consistency::{BatchConsistencyResult, ConsistencyCheckConfig, ConsistencyChecker};
use super::sync::{ReplicaClient, SyncReplicator, SyncReplicationResult};

/// Replication manager state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationManagerState {
    /// Whether replication is enabled
    pub enabled: bool,
    /// Current replication mode
    pub mode: ReplicationMode,
    /// Total writes replicated
    pub total_writes: u64,
    /// Total bytes replicated
    pub total_bytes: u64,
    /// Sync replication count
    pub sync_replications: u64,
    /// Async replication count
    pub async_replications: u64,
    /// Failed replications
    pub failed_replications: u64,
    /// Last replication timestamp
    pub last_replication: Option<DateTime<Utc>>,
    /// State timestamp
    pub timestamp: DateTime<Utc>,
}

impl Default for ReplicationManagerState {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: ReplicationMode::default(),
            total_writes: 0,
            total_bytes: 0,
            sync_replications: 0,
            async_replications: 0,
            failed_replications: 0,
            last_replication: None,
            timestamp: Utc::now(),
        }
    }
}

/// Replication write options
#[derive(Debug, Clone)]
pub struct ReplicationWriteOptions {
    /// Override replication mode
    pub mode: Option<ReplicationMode>,
    /// Override consistency level
    pub consistency: Option<ConsistencyLevel>,
    /// Override replication factor
    pub replication_factor: Option<usize>,
    /// Storage temperature (affects default replication factor)
    pub temperature: StorageTemperature,
    /// Priority for async replication
    pub priority: u8,
}

impl Default for ReplicationWriteOptions {
    fn default() -> Self {
        Self {
            mode: None,
            consistency: None,
            replication_factor: None,
            temperature: StorageTemperature::Hot,
            priority: 100,
        }
    }
}

/// Replication manager
pub struct ReplicationManager<C: ReplicaClient> {
    config: Arc<RwLock<ReplicationConfig>>,
    sync_replicator: Arc<SyncReplicator<C>>,
    async_replicator: Arc<RwLock<AsyncReplicator<C>>>,
    consistency_checker: Arc<ConsistencyChecker<C>>,
    state: Arc<RwLock<ReplicationManagerState>>,
}

impl<C: ReplicaClient + 'static> ReplicationManager<C> {
    /// Create a new replication manager
    pub fn new(config: ReplicationConfig, client: Arc<C>) -> Self {
        let config = Arc::new(RwLock::new(config.clone()));

        let sync_replicator = Arc::new(SyncReplicator::new(
            config.try_read().unwrap().clone(),
            client.clone(),
        ));

        let async_replicator = Arc::new(RwLock::new(AsyncReplicator::new(
            config.try_read().unwrap().clone(),
            client.clone(),
        )));

        let consistency_checker = Arc::new(ConsistencyChecker::new(
            ConsistencyCheckConfig::default(),
            config.clone(),
            client.clone(),
        ));

        Self {
            config,
            sync_replicator,
            async_replicator,
            consistency_checker,
            state: Arc::new(RwLock::new(ReplicationManagerState::default())),
        }
    }

    /// Start the replication manager
    pub async fn start(&self) -> StorageResult<()> {
        let config = self.config.read().await;
        if !config.enabled {
            info!("Replication manager is disabled");
            return Ok(());
        }
        drop(config);

        // Start async replicator
        self.async_replicator.write().await.start().await;

        info!("Replication manager started");
        Ok(())
    }

    /// Stop the replication manager
    pub async fn stop(&self) -> StorageResult<()> {
        self.async_replicator.read().await.stop().await;
        info!("Replication manager stopped");
        Ok(())
    }

    /// Replicate a payload according to configuration
    pub async fn replicate(
        &self,
        ref_id: &str,
        data: &[u8],
        options: ReplicationWriteOptions,
    ) -> StorageResult<()> {
        let config = self.config.read().await;

        if !config.enabled {
            return Ok(());
        }

        let mode = options.mode.unwrap_or(config.mode);
        let replication_factor = options
            .replication_factor
            .unwrap_or_else(|| config.required_replicas(options.temperature));

        let target_nodes: Vec<_> = config
            .active_nodes()
            .into_iter()
            .take(replication_factor)
            .map(|n| n.node_id.clone())
            .collect();

        drop(config);

        if target_nodes.is_empty() {
            warn!(ref_id = %ref_id, "No target nodes for replication");
            return Ok(());
        }

        match mode {
            ReplicationMode::Synchronous => {
                self.replicate_sync(ref_id, data, replication_factor).await?;
            }
            ReplicationMode::Asynchronous => {
                self.replicate_async(ref_id, data, target_nodes).await?;
            }
            ReplicationMode::SemiSynchronous => {
                // Wait for at least one replica, then async the rest
                if target_nodes.len() > 1 {
                    self.replicate_sync(ref_id, data, 1).await?;
                    let remaining: Vec<_> = target_nodes.into_iter().skip(1).collect();
                    self.replicate_async(ref_id, data, remaining).await?;
                } else {
                    self.replicate_sync(ref_id, data, 1).await?;
                }
            }
        }

        // Update state
        let mut state = self.state.write().await;
        state.total_writes += 1;
        state.total_bytes += data.len() as u64;
        state.last_replication = Some(Utc::now());

        Ok(())
    }

    /// Perform synchronous replication
    async fn replicate_sync(
        &self,
        ref_id: &str,
        data: &[u8],
        required: usize,
    ) -> StorageResult<SyncReplicationResult> {
        let result = self.sync_replicator.replicate(ref_id, data, required).await?;

        let mut state = self.state.write().await;
        state.sync_replications += 1;
        if !result.consistency_met {
            state.failed_replications += 1;
        }

        Ok(result)
    }

    /// Perform asynchronous replication
    async fn replicate_async(
        &self,
        ref_id: &str,
        data: &[u8],
        target_nodes: Vec<String>,
    ) -> StorageResult<()> {
        self.async_replicator
            .read()
            .await
            .enqueue(ref_id, data.to_vec(), target_nodes)
            .await?;

        let mut state = self.state.write().await;
        state.async_replications += 1;

        Ok(())
    }

    /// Delete from all replicas
    pub async fn delete(&self, ref_id: &str) -> StorageResult<()> {
        let config = self.config.read().await;

        if !config.enabled {
            return Ok(());
        }

        let target_nodes: Vec<_> = config
            .active_nodes()
            .into_iter()
            .map(|n| n.node_id.clone())
            .collect();

        drop(config);

        self.async_replicator
            .read()
            .await
            .enqueue_delete(ref_id, target_nodes)
            .await
    }

    /// Read from replicas with consistency
    pub async fn read(
        &self,
        ref_id: &str,
        consistency: Option<ConsistencyLevel>,
    ) -> StorageResult<Vec<u8>> {
        let config = self.config.read().await;
        let consistency = consistency.unwrap_or(config.read_consistency);
        drop(config);

        self.sync_replicator.read_consistent(ref_id, consistency).await
    }

    /// Check consistency of a payload
    pub async fn check_consistency(
        &self,
        ref_id: &str,
    ) -> StorageResult<super::consistency::ConsistencyCheckResult> {
        self.consistency_checker.check_payload(ref_id).await
    }

    /// Check consistency of multiple payloads
    pub async fn check_batch_consistency(
        &self,
        ref_ids: &[String],
    ) -> StorageResult<BatchConsistencyResult> {
        self.consistency_checker.check_batch(ref_ids).await
    }

    /// Run health checks on all nodes
    pub async fn health_check(&self) {
        self.sync_replicator.run_health_checks().await;
    }

    /// Get current state
    pub async fn get_state(&self) -> ReplicationManagerState {
        self.state.read().await.clone()
    }

    /// Get node health status
    pub async fn get_node_health(
        &self,
    ) -> std::collections::HashMap<String, super::sync::NodeHealthStatus> {
        self.sync_replicator.get_node_health().await
    }

    /// Get async replication queue status
    pub async fn get_queue_status(&self) -> super::async_repl::QueueStatus {
        self.async_replicator.read().await.get_status().await
    }

    /// Check if replication lag is acceptable
    pub async fn is_lag_acceptable(&self) -> bool {
        self.async_replicator.read().await.is_lag_acceptable().await
    }

    /// Update configuration
    pub async fn update_config(&self, config: ReplicationConfig) {
        let mut current = self.config.write().await;
        *current = config.clone();

        let mut state = self.state.write().await;
        state.enabled = config.enabled;
        state.mode = config.mode;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::config::ReplicaNodeConfig;
    use super::super::sync::MockReplicaClient;

    #[tokio::test]
    async fn test_replication_manager_sync() {
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

        let manager = ReplicationManager::new(config, client);

        let options = ReplicationWriteOptions {
            mode: Some(ReplicationMode::Synchronous),
            replication_factor: Some(2),
            ..Default::default()
        };

        manager
            .replicate("test:001", b"test data", options)
            .await
            .unwrap();

        let state = manager.get_state().await;
        assert_eq!(state.total_writes, 1);
        assert_eq!(state.sync_replications, 1);
    }

    #[tokio::test]
    async fn test_replication_manager_state() {
        let client = Arc::new(MockReplicaClient::new());
        let config = ReplicationConfig::default();

        let manager = ReplicationManager::new(config, client);
        let state = manager.get_state().await;

        assert!(state.enabled);
        assert_eq!(state.total_writes, 0);
    }
}
