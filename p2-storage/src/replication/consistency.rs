//! Consistency Checking
//!
//! Verifies data consistency across replicas and handles repair.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::error::{StorageError, StorageResult};

use super::config::{ReplicationConfig, ReplicaNodeConfig};
use super::sync::ReplicaClient;

/// Consistency check result for a single payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyCheckResult {
    /// Payload reference ID
    pub ref_id: String,
    /// Check timestamp
    pub checked_at: DateTime<Utc>,
    /// Whether all replicas are consistent
    pub consistent: bool,
    /// Number of replicas checked
    pub replicas_checked: usize,
    /// Number of replicas with matching data
    pub replicas_matching: usize,
    /// Per-replica status
    pub replica_status: Vec<ReplicaStatus>,
    /// Majority checksum (if consensus exists)
    pub majority_checksum: Option<String>,
    /// Repair action taken
    pub repair_action: Option<RepairAction>,
    /// Check duration in milliseconds
    pub duration_ms: u64,
}

/// Status of a single replica
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicaStatus {
    /// Node ID
    pub node_id: String,
    /// Whether data exists
    pub exists: bool,
    /// Checksum if data exists
    pub checksum: Option<String>,
    /// Size in bytes
    pub size_bytes: Option<u64>,
    /// Whether matches majority
    pub matches_majority: bool,
    /// Error if check failed
    pub error: Option<String>,
}

/// Repair action taken
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RepairAction {
    /// No repair needed
    None,
    /// Repaired from majority
    RepairedFromMajority { from_node: String, to_nodes: Vec<String> },
    /// Could not repair - manual intervention needed
    ManualRequired { reason: String },
    /// Repair in progress
    InProgress,
}

/// Consistency check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyCheckConfig {
    /// Whether to auto-repair inconsistencies
    pub auto_repair: bool,
    /// Minimum replicas for majority consensus
    pub min_majority: usize,
    /// Check timeout in seconds
    pub timeout_secs: u64,
    /// Parallel check limit
    pub parallel_limit: usize,
}

impl Default for ConsistencyCheckConfig {
    fn default() -> Self {
        Self {
            auto_repair: true,
            min_majority: 2,
            timeout_secs: 30,
            parallel_limit: 10,
        }
    }
}

/// Batch consistency check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchConsistencyResult {
    /// Check timestamp
    pub checked_at: DateTime<Utc>,
    /// Total items checked
    pub total_checked: usize,
    /// Consistent items
    pub consistent: usize,
    /// Inconsistent items
    pub inconsistent: usize,
    /// Missing items (not found on any replica)
    pub missing: usize,
    /// Repaired items
    pub repaired: usize,
    /// Items requiring manual intervention
    pub manual_required: usize,
    /// Individual results
    pub results: Vec<ConsistencyCheckResult>,
    /// Total duration in milliseconds
    pub total_duration_ms: u64,
}

/// Consistency checker
pub struct ConsistencyChecker<C: ReplicaClient> {
    config: ConsistencyCheckConfig,
    replication_config: Arc<RwLock<ReplicationConfig>>,
    client: Arc<C>,
}

impl<C: ReplicaClient + 'static> ConsistencyChecker<C> {
    /// Create a new consistency checker
    pub fn new(
        config: ConsistencyCheckConfig,
        replication_config: Arc<RwLock<ReplicationConfig>>,
        client: Arc<C>,
    ) -> Self {
        Self {
            config,
            replication_config,
            client,
        }
    }

    /// Check consistency of a single payload across replicas
    pub async fn check_payload(&self, ref_id: &str) -> StorageResult<ConsistencyCheckResult> {
        let start = std::time::Instant::now();
        let repl_config = self.replication_config.read().await;
        let nodes: Vec<_> = repl_config.active_nodes().into_iter().cloned().collect();
        drop(repl_config);

        if nodes.is_empty() {
            return Err(StorageError::OperationFailed("No active replica nodes".to_string()));
        }

        // Check all replicas in parallel
        let mut handles = Vec::new();
        for node in &nodes {
            let client = self.client.clone();
            let node_config = node.clone();
            let ref_id = ref_id.to_string();

            handles.push(tokio::spawn(async move {
                let result = tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    client.read(&node_config, &ref_id),
                )
                .await;

                match result {
                    Ok(Ok(data)) => {
                        let checksum = compute_checksum(&data);
                        ReplicaStatus {
                            node_id: node_config.node_id,
                            exists: true,
                            checksum: Some(checksum),
                            size_bytes: Some(data.len() as u64),
                            matches_majority: false, // Will be set later
                            error: None,
                        }
                    }
                    Ok(Err(StorageError::NotFound(_))) => ReplicaStatus {
                        node_id: node_config.node_id,
                        exists: false,
                        checksum: None,
                        size_bytes: None,
                        matches_majority: false,
                        error: None,
                    },
                    Ok(Err(e)) => ReplicaStatus {
                        node_id: node_config.node_id,
                        exists: false,
                        checksum: None,
                        size_bytes: None,
                        matches_majority: false,
                        error: Some(e.to_string()),
                    },
                    Err(_) => ReplicaStatus {
                        node_id: node_config.node_id,
                        exists: false,
                        checksum: None,
                        size_bytes: None,
                        matches_majority: false,
                        error: Some("Timeout".to_string()),
                    },
                }
            }));
        }

        // Collect results
        let mut replica_status = Vec::new();
        for handle in handles {
            if let Ok(status) = handle.await {
                replica_status.push(status);
            }
        }

        // Find majority checksum
        let (majority_checksum, checksum_counts) = find_majority_checksum(&replica_status);

        // Update matches_majority
        for status in &mut replica_status {
            if let Some(ref cs) = status.checksum {
                if Some(cs.as_str()) == majority_checksum.as_deref() {
                    status.matches_majority = true;
                }
            }
        }

        let replicas_matching = replica_status.iter().filter(|s| s.matches_majority).count();
        let consistent = replicas_matching == replica_status.iter().filter(|s| s.exists).count()
            && replicas_matching > 0;

        // Auto-repair if needed
        let repair_action = if !consistent && self.config.auto_repair {
            self.attempt_repair(ref_id, &replica_status, &majority_checksum, &nodes)
                .await
        } else {
            RepairAction::None
        };

        Ok(ConsistencyCheckResult {
            ref_id: ref_id.to_string(),
            checked_at: Utc::now(),
            consistent,
            replicas_checked: replica_status.len(),
            replicas_matching,
            replica_status,
            majority_checksum,
            repair_action: Some(repair_action),
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    /// Attempt to repair inconsistent replicas
    async fn attempt_repair(
        &self,
        ref_id: &str,
        statuses: &[ReplicaStatus],
        majority_checksum: &Option<String>,
        nodes: &[ReplicaNodeConfig],
    ) -> RepairAction {
        // Find source node with majority data
        let source = statuses.iter().find(|s| s.matches_majority && s.exists);
        let source = match source {
            Some(s) => s,
            None => {
                return RepairAction::ManualRequired {
                    reason: "No majority replica found".to_string(),
                };
            }
        };

        // Find nodes needing repair
        let repair_targets: Vec<_> = statuses
            .iter()
            .filter(|s| !s.matches_majority || !s.exists)
            .map(|s| s.node_id.clone())
            .collect();

        if repair_targets.is_empty() {
            return RepairAction::None;
        }

        // Get source node config
        let source_node = match nodes.iter().find(|n| n.node_id == source.node_id) {
            Some(n) => n,
            None => {
                return RepairAction::ManualRequired {
                    reason: "Source node config not found".to_string(),
                };
            }
        };

        // Read data from source
        let data = match self.client.read(source_node, ref_id).await {
            Ok(d) => d,
            Err(e) => {
                return RepairAction::ManualRequired {
                    reason: format!("Failed to read from source: {}", e),
                };
            }
        };

        // Write to repair targets
        let mut repaired_nodes = Vec::new();
        for target_id in &repair_targets {
            if let Some(target_node) = nodes.iter().find(|n| &n.node_id == target_id) {
                match self.client.write(target_node, ref_id, &data).await {
                    Ok(_) => {
                        info!(
                            ref_id = %ref_id,
                            from = %source.node_id,
                            to = %target_id,
                            "Repaired replica"
                        );
                        repaired_nodes.push(target_id.clone());
                    }
                    Err(e) => {
                        warn!(
                            ref_id = %ref_id,
                            target = %target_id,
                            error = %e,
                            "Failed to repair replica"
                        );
                    }
                }
            }
        }

        if repaired_nodes.is_empty() {
            RepairAction::ManualRequired {
                reason: "All repair attempts failed".to_string(),
            }
        } else if repaired_nodes.len() == repair_targets.len() {
            RepairAction::RepairedFromMajority {
                from_node: source.node_id.clone(),
                to_nodes: repaired_nodes,
            }
        } else {
            RepairAction::ManualRequired {
                reason: format!(
                    "Partial repair: {} of {} targets repaired",
                    repaired_nodes.len(),
                    repair_targets.len()
                ),
            }
        }
    }

    /// Check consistency of multiple payloads
    pub async fn check_batch(&self, ref_ids: &[String]) -> StorageResult<BatchConsistencyResult> {
        let start = std::time::Instant::now();
        use futures::stream::{self, StreamExt};

        let results: Vec<ConsistencyCheckResult> = stream::iter(ref_ids)
            .map(|ref_id| {
                let checker = self;
                async move { checker.check_payload(ref_id).await }
            })
            .buffer_unordered(self.config.parallel_limit)
            .filter_map(|r| async { r.ok() })
            .collect()
            .await;

        let consistent = results.iter().filter(|r| r.consistent).count();
        let inconsistent = results.iter().filter(|r| !r.consistent && r.replicas_checked > 0).count();
        let missing = results.iter().filter(|r| r.replicas_checked == 0).count();
        let repaired = results
            .iter()
            .filter(|r| matches!(r.repair_action, Some(RepairAction::RepairedFromMajority { .. })))
            .count();
        let manual_required = results
            .iter()
            .filter(|r| matches!(r.repair_action, Some(RepairAction::ManualRequired { .. })))
            .count();

        Ok(BatchConsistencyResult {
            checked_at: Utc::now(),
            total_checked: results.len(),
            consistent,
            inconsistent,
            missing,
            repaired,
            manual_required,
            results,
            total_duration_ms: start.elapsed().as_millis() as u64,
        })
    }
}

/// Compute SHA-256 checksum of data
fn compute_checksum(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Find the majority checksum from replica statuses
fn find_majority_checksum(statuses: &[ReplicaStatus]) -> (Option<String>, HashMap<String, usize>) {
    let mut counts: HashMap<String, usize> = HashMap::new();

    for status in statuses {
        if let Some(ref checksum) = status.checksum {
            *counts.entry(checksum.clone()).or_insert(0) += 1;
        }
    }

    let majority = counts
        .iter()
        .max_by_key(|(_, count)| *count)
        .map(|(checksum, _)| checksum.clone());

    (majority, counts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::sync::MockReplicaClient;

    #[tokio::test]
    async fn test_consistency_check_all_consistent() {
        let client = Arc::new(MockReplicaClient::new());
        let mut config = ReplicationConfig::default();

        let node1 = ReplicaNodeConfig {
            node_id: "node1".to_string(),
            priority: 100,
            enabled: true,
            ..Default::default()
        };
        let node2 = ReplicaNodeConfig {
            node_id: "node2".to_string(),
            priority: 100,
            enabled: true,
            ..Default::default()
        };

        config.add_node(node1.clone());
        config.add_node(node2.clone());

        // Write same data to both nodes
        client.write(&node1, "test:001", b"test data").await.unwrap();
        client.write(&node2, "test:001", b"test data").await.unwrap();

        let checker = ConsistencyChecker::new(
            ConsistencyCheckConfig::default(),
            Arc::new(RwLock::new(config)),
            client,
        );

        let result = checker.check_payload("test:001").await.unwrap();

        assert!(result.consistent);
        assert_eq!(result.replicas_matching, 2);
    }

    #[tokio::test]
    async fn test_find_majority_checksum() {
        let statuses = vec![
            ReplicaStatus {
                node_id: "node1".to_string(),
                exists: true,
                checksum: Some("abc123".to_string()),
                size_bytes: Some(100),
                matches_majority: false,
                error: None,
            },
            ReplicaStatus {
                node_id: "node2".to_string(),
                exists: true,
                checksum: Some("abc123".to_string()),
                size_bytes: Some(100),
                matches_majority: false,
                error: None,
            },
            ReplicaStatus {
                node_id: "node3".to_string(),
                exists: true,
                checksum: Some("def456".to_string()),
                size_bytes: Some(100),
                matches_majority: false,
                error: None,
            },
        ];

        let (majority, counts) = find_majority_checksum(&statuses);
        assert_eq!(majority, Some("abc123".to_string()));
        assert_eq!(*counts.get("abc123").unwrap(), 2);
        assert_eq!(*counts.get("def456").unwrap(), 1);
    }
}
