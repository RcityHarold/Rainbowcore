//! Replication Configuration
//!
//! Configuration for data replication across storage backends.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use p2_core::types::StorageTemperature;

/// Replication mode
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReplicationMode {
    /// Synchronous replication - wait for all replicas before confirming write
    Synchronous,
    /// Asynchronous replication - confirm write after primary, replicate in background
    Asynchronous,
    /// Semi-synchronous - wait for at least one replica
    SemiSynchronous,
}

impl Default for ReplicationMode {
    fn default() -> Self {
        Self::Asynchronous
    }
}

/// Replication factor configuration by temperature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationFactorConfig {
    /// Replication factor for hot data (frequently accessed)
    pub hot: u8,
    /// Replication factor for warm data (moderately accessed)
    pub warm: u8,
    /// Replication factor for cold data (rarely accessed)
    pub cold: u8,
}

impl Default for ReplicationFactorConfig {
    fn default() -> Self {
        Self {
            hot: 3,  // 3 replicas for hot data
            warm: 2, // 2 replicas for warm data
            cold: 1, // 1 replica for cold data (+ archive)
        }
    }
}

impl ReplicationFactorConfig {
    /// Get replication factor for a temperature tier
    pub fn factor_for(&self, temperature: StorageTemperature) -> u8 {
        match temperature {
            StorageTemperature::Hot => self.hot,
            StorageTemperature::Warm => self.warm,
            StorageTemperature::Cold => self.cold,
        }
    }
}

/// Replica node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicaNodeConfig {
    /// Unique node identifier
    pub node_id: String,
    /// Node endpoint URL
    pub endpoint: String,
    /// Node region/datacenter
    pub region: String,
    /// Node priority (higher = preferred)
    pub priority: u8,
    /// Whether node is enabled
    pub enabled: bool,
    /// Maximum concurrent replication operations
    pub max_concurrent: usize,
    /// Health check interval in seconds
    pub health_check_interval_secs: u64,
}

impl Default for ReplicaNodeConfig {
    fn default() -> Self {
        Self {
            node_id: String::new(),
            endpoint: String::new(),
            region: "default".to_string(),
            priority: 100,
            enabled: true,
            max_concurrent: 10,
            health_check_interval_secs: 30,
        }
    }
}

/// Consistency level for reads
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConsistencyLevel {
    /// Read from any available replica
    One,
    /// Read from majority of replicas
    Quorum,
    /// Read from all replicas
    All,
    /// Read from local replica only
    Local,
}

impl Default for ConsistencyLevel {
    fn default() -> Self {
        Self::One
    }
}

/// Replication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationConfig {
    /// Whether replication is enabled
    pub enabled: bool,
    /// Default replication mode
    pub mode: ReplicationMode,
    /// Replication factors by temperature
    pub factors: ReplicationFactorConfig,
    /// Read consistency level
    pub read_consistency: ConsistencyLevel,
    /// Write consistency level
    pub write_consistency: ConsistencyLevel,
    /// Replica nodes
    pub nodes: HashMap<String, ReplicaNodeConfig>,
    /// Maximum replication lag in milliseconds
    pub max_lag_ms: u64,
    /// Retry configuration
    pub retry_config: RetryConfig,
    /// Async replication configuration
    pub async_config: AsyncReplicationConfig,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: ReplicationMode::default(),
            factors: ReplicationFactorConfig::default(),
            read_consistency: ConsistencyLevel::default(),
            write_consistency: ConsistencyLevel::One,
            nodes: HashMap::new(),
            max_lag_ms: 60000, // 1 minute
            retry_config: RetryConfig::default(),
            async_config: AsyncReplicationConfig::default(),
        }
    }
}

impl ReplicationConfig {
    /// Create configuration with synchronous replication
    pub fn synchronous() -> Self {
        Self {
            mode: ReplicationMode::Synchronous,
            write_consistency: ConsistencyLevel::All,
            ..Default::default()
        }
    }

    /// Create configuration with asynchronous replication
    pub fn asynchronous() -> Self {
        Self {
            mode: ReplicationMode::Asynchronous,
            write_consistency: ConsistencyLevel::One,
            ..Default::default()
        }
    }

    /// Add a replica node
    pub fn add_node(&mut self, node: ReplicaNodeConfig) {
        self.nodes.insert(node.node_id.clone(), node);
    }

    /// Get active nodes sorted by priority
    pub fn active_nodes(&self) -> Vec<&ReplicaNodeConfig> {
        let mut nodes: Vec<_> = self.nodes.values().filter(|n| n.enabled).collect();
        nodes.sort_by(|a, b| b.priority.cmp(&a.priority));
        nodes
    }

    /// Get number of required replicas for a temperature
    pub fn required_replicas(&self, temperature: StorageTemperature) -> usize {
        self.factors.factor_for(temperature) as usize
    }
}

/// Retry configuration for replication operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum retry attempts
    pub max_attempts: u32,
    /// Initial backoff in milliseconds
    pub initial_backoff_ms: u64,
    /// Maximum backoff in milliseconds
    pub max_backoff_ms: u64,
    /// Backoff multiplier
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff_ms: 100,
            max_backoff_ms: 10000,
            backoff_multiplier: 2.0,
        }
    }
}

impl RetryConfig {
    /// Calculate backoff for a given attempt
    pub fn backoff_ms(&self, attempt: u32) -> u64 {
        let backoff = (self.initial_backoff_ms as f64) * self.backoff_multiplier.powi(attempt as i32);
        (backoff as u64).min(self.max_backoff_ms)
    }
}

/// Async replication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsyncReplicationConfig {
    /// Queue size for pending replications
    pub queue_size: usize,
    /// Batch size for replication operations
    pub batch_size: usize,
    /// Flush interval in milliseconds
    pub flush_interval_ms: u64,
    /// Maximum lag before blocking writes
    pub block_on_lag: bool,
    /// Worker thread count
    pub worker_count: usize,
}

impl Default for AsyncReplicationConfig {
    fn default() -> Self {
        Self {
            queue_size: 10000,
            batch_size: 100,
            flush_interval_ms: 100,
            block_on_lag: false,
            worker_count: 4,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replication_factor_config() {
        let config = ReplicationFactorConfig::default();
        assert_eq!(config.factor_for(StorageTemperature::Hot), 3);
        assert_eq!(config.factor_for(StorageTemperature::Warm), 2);
        assert_eq!(config.factor_for(StorageTemperature::Cold), 1);
    }

    #[test]
    fn test_retry_backoff() {
        let config = RetryConfig::default();
        assert_eq!(config.backoff_ms(0), 100);
        assert_eq!(config.backoff_ms(1), 200);
        assert_eq!(config.backoff_ms(2), 400);
    }

    #[test]
    fn test_active_nodes() {
        let mut config = ReplicationConfig::default();

        config.add_node(ReplicaNodeConfig {
            node_id: "node1".to_string(),
            priority: 100,
            enabled: true,
            ..Default::default()
        });

        config.add_node(ReplicaNodeConfig {
            node_id: "node2".to_string(),
            priority: 200,
            enabled: true,
            ..Default::default()
        });

        config.add_node(ReplicaNodeConfig {
            node_id: "node3".to_string(),
            priority: 150,
            enabled: false,
            ..Default::default()
        });

        let active = config.active_nodes();
        assert_eq!(active.len(), 2);
        assert_eq!(active[0].node_id, "node2"); // Highest priority first
        assert_eq!(active[1].node_id, "node1");
    }
}
