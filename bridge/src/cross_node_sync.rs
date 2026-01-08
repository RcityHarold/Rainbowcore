//! Cross-Node Payload Synchronization (ISSUE-025)
//!
//! Implements the ability to fetch missing payloads from other nodes
//! during backfill operations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Node discovery result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Node ID
    pub node_id: String,
    /// Node endpoint URL
    pub endpoint: String,
    /// Node type
    pub node_type: NodeType,
    /// Last seen timestamp
    pub last_seen: DateTime<Utc>,
    /// Availability score (0.0 - 1.0)
    pub availability_score: f64,
    /// Latency in milliseconds
    pub latency_ms: Option<u64>,
    /// Supported payload types
    pub supported_types: Vec<String>,
    /// Current load (0.0 - 1.0)
    pub current_load: f64,
}

/// Node type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeType {
    /// Full storage node
    Storage,
    /// Relay node (caches but doesn't persist)
    Relay,
    /// Archive node (cold storage specialist)
    Archive,
    /// Gateway node
    Gateway,
}

/// Payload sync request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadSyncRequest {
    /// Request ID
    pub request_id: String,
    /// Requesting node ID
    pub requester_id: String,
    /// Payload references to fetch
    pub payload_refs: Vec<String>,
    /// Priority level
    pub priority: SyncPriority,
    /// Reason for sync
    pub reason: SyncReason,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Deadline for completion
    pub deadline: Option<DateTime<Utc>>,
}

/// Sync priority
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncPriority {
    /// Critical - needed for active operations
    Critical,
    /// High - backfill in progress
    High,
    /// Normal - routine sync
    Normal,
    /// Low - background optimization
    Low,
}

/// Reason for sync request
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncReason {
    /// Backfill operation
    Backfill,
    /// Replication factor recovery
    ReplicationRecovery,
    /// Temperature tier migration
    TierMigration,
    /// Manual repair request
    ManualRepair,
    /// Consistency check recovery
    ConsistencyRecovery,
}

/// Payload sync response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadSyncResponse {
    /// Request ID this responds to
    pub request_id: String,
    /// Responding node ID
    pub responder_id: String,
    /// Successfully synced payload refs
    pub synced: Vec<String>,
    /// Failed payload refs with reasons
    pub failed: Vec<SyncFailure>,
    /// Not found payload refs
    pub not_found: Vec<String>,
    /// Bytes transferred
    pub bytes_transferred: u64,
    /// Duration in milliseconds
    pub duration_ms: u64,
}

/// Sync failure details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncFailure {
    /// Payload ref
    pub payload_ref: String,
    /// Failure reason
    pub reason: SyncFailureReason,
    /// Error message
    pub message: String,
}

/// Sync failure reason
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncFailureReason {
    /// Network error
    NetworkError,
    /// Checksum mismatch
    ChecksumMismatch,
    /// Timeout
    Timeout,
    /// Access denied
    AccessDenied,
    /// Storage error on receiver
    StorageError,
    /// Rate limited
    RateLimited,
}

/// Cross-node sync coordinator
pub struct CrossNodeSyncCoordinator {
    /// Local node ID
    local_node_id: String,
    /// Known nodes
    known_nodes: RwLock<HashMap<String, NodeInfo>>,
    /// Active sync requests
    active_requests: RwLock<HashMap<String, PayloadSyncRequest>>,
    /// Completed syncs (recent)
    completed_syncs: RwLock<Vec<PayloadSyncResponse>>,
    /// Configuration
    config: CrossNodeSyncConfig,
}

/// Configuration for cross-node sync
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossNodeSyncConfig {
    /// Maximum concurrent sync requests
    pub max_concurrent_requests: usize,
    /// Default timeout for sync operations (ms)
    pub default_timeout_ms: u64,
    /// Maximum payload size to sync (bytes)
    pub max_payload_size: u64,
    /// Retry count for failed syncs
    pub max_retries: u32,
    /// Minimum availability score to consider a node
    pub min_availability_score: f64,
    /// Enable checksum verification
    pub verify_checksum: bool,
}

impl Default for CrossNodeSyncConfig {
    fn default() -> Self {
        Self {
            max_concurrent_requests: 10,
            default_timeout_ms: 30000,
            max_payload_size: 100 * 1024 * 1024, // 100MB
            max_retries: 3,
            min_availability_score: 0.8,
            verify_checksum: true,
        }
    }
}

impl CrossNodeSyncCoordinator {
    /// Create a new coordinator
    pub fn new(local_node_id: String, config: CrossNodeSyncConfig) -> Self {
        Self {
            local_node_id,
            known_nodes: RwLock::new(HashMap::new()),
            active_requests: RwLock::new(HashMap::new()),
            completed_syncs: RwLock::new(Vec::new()),
            config,
        }
    }

    /// Register a known node
    pub async fn register_node(&self, node: NodeInfo) {
        let mut nodes = self.known_nodes.write().await;
        nodes.insert(node.node_id.clone(), node);
    }

    /// Unregister a node
    pub async fn unregister_node(&self, node_id: &str) {
        let mut nodes = self.known_nodes.write().await;
        nodes.remove(node_id);
    }

    /// Update node info
    pub async fn update_node(&self, node_id: &str, update: NodeInfoUpdate) {
        let mut nodes = self.known_nodes.write().await;
        if let Some(node) = nodes.get_mut(node_id) {
            if let Some(score) = update.availability_score {
                node.availability_score = score;
            }
            if let Some(latency) = update.latency_ms {
                node.latency_ms = Some(latency);
            }
            if let Some(load) = update.current_load {
                node.current_load = load;
            }
            node.last_seen = Utc::now();
        }
    }

    /// Find best nodes for a payload
    pub async fn find_nodes_for_payload(&self, payload_ref: &str) -> Vec<NodeInfo> {
        let nodes = self.known_nodes.read().await;
        let mut candidates: Vec<NodeInfo> = nodes
            .values()
            .filter(|n| {
                n.availability_score >= self.config.min_availability_score
                    && n.node_id != self.local_node_id
            })
            .cloned()
            .collect();

        // Sort by: availability score (desc), latency (asc), load (asc)
        candidates.sort_by(|a, b| {
            let score_cmp = b.availability_score.partial_cmp(&a.availability_score).unwrap();
            if score_cmp != std::cmp::Ordering::Equal {
                return score_cmp;
            }
            let lat_a = a.latency_ms.unwrap_or(u64::MAX);
            let lat_b = b.latency_ms.unwrap_or(u64::MAX);
            let lat_cmp = lat_a.cmp(&lat_b);
            if lat_cmp != std::cmp::Ordering::Equal {
                return lat_cmp;
            }
            a.current_load.partial_cmp(&b.current_load).unwrap()
        });

        candidates
    }

    /// Create a sync request
    pub async fn create_sync_request(
        &self,
        payload_refs: Vec<String>,
        priority: SyncPriority,
        reason: SyncReason,
    ) -> PayloadSyncRequest {
        let request = PayloadSyncRequest {
            request_id: format!("sync:{}:{}", self.local_node_id, Utc::now().timestamp_micros()),
            requester_id: self.local_node_id.clone(),
            payload_refs,
            priority,
            reason,
            created_at: Utc::now(),
            deadline: match priority {
                SyncPriority::Critical => Some(Utc::now() + chrono::Duration::minutes(5)),
                SyncPriority::High => Some(Utc::now() + chrono::Duration::minutes(30)),
                SyncPriority::Normal => Some(Utc::now() + chrono::Duration::hours(2)),
                SyncPriority::Low => None,
            },
        };

        let mut active = self.active_requests.write().await;
        active.insert(request.request_id.clone(), request.clone());

        request
    }

    /// Record a completed sync
    pub async fn record_sync_response(&self, response: PayloadSyncResponse) {
        // Remove from active
        let mut active = self.active_requests.write().await;
        active.remove(&response.request_id);

        // Add to completed (keep last 1000)
        let mut completed = self.completed_syncs.write().await;
        completed.push(response);
        if completed.len() > 1000 {
            completed.remove(0);
        }
    }

    /// Get sync statistics
    pub async fn get_stats(&self) -> SyncStats {
        let active = self.active_requests.read().await;
        let completed = self.completed_syncs.read().await;
        let nodes = self.known_nodes.read().await;

        let total_synced: u64 = completed.iter().map(|r| r.synced.len() as u64).sum();
        let total_failed: u64 = completed.iter().map(|r| r.failed.len() as u64).sum();
        let total_bytes: u64 = completed.iter().map(|r| r.bytes_transferred).sum();
        let avg_duration: f64 = if completed.is_empty() {
            0.0
        } else {
            completed.iter().map(|r| r.duration_ms as f64).sum::<f64>() / completed.len() as f64
        };

        SyncStats {
            active_requests: active.len(),
            known_nodes: nodes.len(),
            available_nodes: nodes.values().filter(|n| n.availability_score >= self.config.min_availability_score).count(),
            total_payloads_synced: total_synced,
            total_payloads_failed: total_failed,
            total_bytes_transferred: total_bytes,
            average_sync_duration_ms: avg_duration,
            success_rate: if total_synced + total_failed > 0 {
                total_synced as f64 / (total_synced + total_failed) as f64
            } else {
                1.0
            },
        }
    }
}

/// Node info update
#[derive(Debug, Clone, Default)]
pub struct NodeInfoUpdate {
    pub availability_score: Option<f64>,
    pub latency_ms: Option<u64>,
    pub current_load: Option<f64>,
}

/// Sync statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStats {
    /// Number of active sync requests
    pub active_requests: usize,
    /// Total known nodes
    pub known_nodes: usize,
    /// Available nodes (above threshold)
    pub available_nodes: usize,
    /// Total payloads successfully synced
    pub total_payloads_synced: u64,
    /// Total payloads failed to sync
    pub total_payloads_failed: u64,
    /// Total bytes transferred
    pub total_bytes_transferred: u64,
    /// Average sync duration (ms)
    pub average_sync_duration_ms: f64,
    /// Success rate
    pub success_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_coordinator_creation() {
        let coord = CrossNodeSyncCoordinator::new(
            "node:local".to_string(),
            CrossNodeSyncConfig::default(),
        );

        let stats = coord.get_stats().await;
        assert_eq!(stats.active_requests, 0);
        assert_eq!(stats.known_nodes, 0);
    }

    #[tokio::test]
    async fn test_node_registration() {
        let coord = CrossNodeSyncCoordinator::new(
            "node:local".to_string(),
            CrossNodeSyncConfig::default(),
        );

        coord.register_node(NodeInfo {
            node_id: "node:remote1".to_string(),
            endpoint: "https://remote1.example.com".to_string(),
            node_type: NodeType::Storage,
            last_seen: Utc::now(),
            availability_score: 0.95,
            latency_ms: Some(50),
            supported_types: vec!["evidence".to_string()],
            current_load: 0.3,
        }).await;

        let stats = coord.get_stats().await;
        assert_eq!(stats.known_nodes, 1);
        assert_eq!(stats.available_nodes, 1);
    }

    #[tokio::test]
    async fn test_sync_request_creation() {
        let coord = CrossNodeSyncCoordinator::new(
            "node:local".to_string(),
            CrossNodeSyncConfig::default(),
        );

        let request = coord.create_sync_request(
            vec!["payload:001".to_string(), "payload:002".to_string()],
            SyncPriority::High,
            SyncReason::Backfill,
        ).await;

        assert_eq!(request.payload_refs.len(), 2);
        assert!(request.deadline.is_some());

        let stats = coord.get_stats().await;
        assert_eq!(stats.active_requests, 1);
    }
}
