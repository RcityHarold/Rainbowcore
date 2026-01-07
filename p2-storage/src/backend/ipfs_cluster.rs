//! IPFS Cluster Support
//!
//! Provides distributed pinning across IPFS Cluster nodes.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::error::{StorageError, StorageResult};

/// IPFS Cluster configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    /// Cluster API endpoint
    pub api_endpoint: String,
    /// Authentication token
    pub auth_token: Option<String>,
    /// Connection timeout in seconds
    pub timeout_secs: u64,
    /// Default replication factor (min)
    pub replication_factor_min: i32,
    /// Default replication factor (max)
    pub replication_factor_max: i32,
    /// Pin expiry (None = never)
    pub pin_expiry_secs: Option<u64>,
    /// Cluster name
    pub cluster_name: String,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            api_endpoint: "http://127.0.0.1:9094".to_string(),
            auth_token: None,
            timeout_secs: 60,
            replication_factor_min: -1, // All peers
            replication_factor_max: -1, // All peers
            pin_expiry_secs: None,
            cluster_name: "default".to_string(),
        }
    }
}

/// Cluster peer status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterPeer {
    /// Peer ID
    pub id: String,
    /// Peer addresses
    pub addresses: Vec<String>,
    /// Cluster peer name
    pub peername: Option<String>,
    /// Is available
    pub available: bool,
    /// Last seen timestamp
    pub last_seen: Option<DateTime<Utc>>,
    /// IPFS peer ID
    pub ipfs_peer_id: Option<String>,
}

/// Cluster pin status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClusterPinStatus {
    /// Pin is queued
    Queued,
    /// Pinning in progress
    Pinning,
    /// Successfully pinned
    Pinned,
    /// Pin error
    Error,
    /// Unpinning in progress
    Unpinning,
    /// Not pinned
    Unpinned,
    /// Remote pin
    Remote,
}

impl Default for ClusterPinStatus {
    fn default() -> Self {
        Self::Unpinned
    }
}

/// Cluster pin info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterPinInfo {
    /// CID
    pub cid: String,
    /// Pin name
    pub name: Option<String>,
    /// Replication factor min
    pub replication_factor_min: i32,
    /// Replication factor max
    pub replication_factor_max: i32,
    /// Allocations (peer IDs)
    pub allocations: Vec<String>,
    /// Pin status per peer
    pub peer_status: HashMap<String, ClusterPinStatus>,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Metadata
    pub metadata: HashMap<String, String>,
}

/// Cluster pin request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterPinRequest {
    /// CID to pin
    pub cid: String,
    /// Pin name
    pub name: Option<String>,
    /// Replication factor min (-1 = all)
    pub replication_factor_min: Option<i32>,
    /// Replication factor max (-1 = all)
    pub replication_factor_max: Option<i32>,
    /// Specific peers to pin to
    pub allocations: Option<Vec<String>>,
    /// User metadata
    pub metadata: HashMap<String, String>,
    /// Pin expiry
    pub expire_at: Option<DateTime<Utc>>,
}

impl ClusterPinRequest {
    /// Create a new pin request
    pub fn new(cid: &str) -> Self {
        Self {
            cid: cid.to_string(),
            name: None,
            replication_factor_min: None,
            replication_factor_max: None,
            allocations: None,
            metadata: HashMap::new(),
            expire_at: None,
        }
    }

    /// Set pin name
    pub fn with_name(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }

    /// Set replication factor
    pub fn with_replication(mut self, min: i32, max: i32) -> Self {
        self.replication_factor_min = Some(min);
        self.replication_factor_max = Some(max);
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }
}

/// Cluster client trait
#[async_trait]
pub trait ClusterClient: Send + Sync {
    /// Get cluster peers
    async fn get_peers(&self) -> StorageResult<Vec<ClusterPeer>>;

    /// Pin content to cluster
    async fn pin(&self, request: ClusterPinRequest) -> StorageResult<ClusterPinInfo>;

    /// Unpin content from cluster
    async fn unpin(&self, cid: &str) -> StorageResult<()>;

    /// Get pin status
    async fn get_pin_status(&self, cid: &str) -> StorageResult<ClusterPinInfo>;

    /// List all pins
    async fn list_pins(&self) -> StorageResult<Vec<ClusterPinInfo>>;

    /// Get cluster health
    async fn health(&self) -> StorageResult<ClusterHealth>;
}

/// Cluster health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterHealth {
    /// Cluster is healthy
    pub healthy: bool,
    /// Total peers
    pub total_peers: usize,
    /// Available peers
    pub available_peers: usize,
    /// Cluster version
    pub version: Option<String>,
    /// Check timestamp
    pub checked_at: DateTime<Utc>,
}

/// HTTP IPFS Cluster client
pub struct HttpClusterClient {
    config: ClusterConfig,
    client: reqwest::Client,
}

impl HttpClusterClient {
    /// Create a new cluster client
    pub fn new(config: ClusterConfig) -> StorageResult<Self> {
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(token) = &config.auth_token {
            headers.insert(
                reqwest::header::AUTHORIZATION,
                format!("Basic {}", token).parse().unwrap(),
            );
        }

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .default_headers(headers)
            .build()
            .map_err(|e| StorageError::Configuration(format!("HTTP client error: {}", e)))?;

        Ok(Self { config, client })
    }

    /// Build URL for API endpoint
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.config.api_endpoint, path)
    }
}

#[async_trait]
impl ClusterClient for HttpClusterClient {
    async fn get_peers(&self) -> StorageResult<Vec<ClusterPeer>> {
        let response = self
            .client
            .get(&self.url("/peers"))
            .send()
            .await
            .map_err(|e| StorageError::Unavailable(format!("Cluster request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(StorageError::Unavailable("Cluster peers request failed".to_string()));
        }

        // Parse response - cluster returns array of peer objects
        let peers: Vec<serde_json::Value> = response
            .json()
            .await
            .map_err(|e| StorageError::Backend(format!("Failed to parse peers: {}", e)))?;

        let result = peers
            .into_iter()
            .map(|p| ClusterPeer {
                id: p["id"].as_str().unwrap_or_default().to_string(),
                addresses: p["addresses"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                    .unwrap_or_default(),
                peername: p["peername"].as_str().map(String::from),
                available: !p["error"].as_str().map(|s| !s.is_empty()).unwrap_or(false),
                last_seen: None,
                ipfs_peer_id: p["ipfs"]["id"].as_str().map(String::from),
            })
            .collect();

        Ok(result)
    }

    async fn pin(&self, request: ClusterPinRequest) -> StorageResult<ClusterPinInfo> {
        let mut url = format!("{}/pins/ipfs/{}", self.config.api_endpoint, request.cid);

        // Add query parameters
        let mut params = vec![];
        if let Some(name) = &request.name {
            params.push(format!("name={}", urlencoding::encode(name)));
        }
        if let Some(min) = request.replication_factor_min {
            params.push(format!("replication-min={}", min));
        }
        if let Some(max) = request.replication_factor_max {
            params.push(format!("replication-max={}", max));
        }
        if !params.is_empty() {
            url = format!("{}?{}", url, params.join("&"));
        }

        let response = self
            .client
            .post(&url)
            .send()
            .await
            .map_err(|e| StorageError::OperationFailed(format!("Cluster pin failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(StorageError::OperationFailed(format!(
                "Cluster pin failed: {} - {}",
                status, body
            )));
        }

        let pin_info: serde_json::Value = response
            .json()
            .await
            .map_err(|e| StorageError::Backend(format!("Failed to parse pin response: {}", e)))?;

        Ok(ClusterPinInfo {
            cid: request.cid,
            name: request.name,
            replication_factor_min: request.replication_factor_min.unwrap_or(-1),
            replication_factor_max: request.replication_factor_max.unwrap_or(-1),
            allocations: pin_info["allocations"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            peer_status: HashMap::new(),
            created_at: Utc::now(),
            metadata: request.metadata,
        })
    }

    async fn unpin(&self, cid: &str) -> StorageResult<()> {
        let url = format!("{}/pins/ipfs/{}", self.config.api_endpoint, cid);

        let response = self
            .client
            .delete(&url)
            .send()
            .await
            .map_err(|e| StorageError::OperationFailed(format!("Cluster unpin failed: {}", e)))?;

        if !response.status().is_success() {
            // 404 is OK - already unpinned
            if response.status() != reqwest::StatusCode::NOT_FOUND {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                return Err(StorageError::OperationFailed(format!(
                    "Cluster unpin failed: {} - {}",
                    status, body
                )));
            }
        }

        Ok(())
    }

    async fn get_pin_status(&self, cid: &str) -> StorageResult<ClusterPinInfo> {
        let url = format!("{}/pins/ipfs/{}", self.config.api_endpoint, cid);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| StorageError::ReadFailed(format!("Cluster status request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(StorageError::NotFound(cid.to_string()));
        }

        let pin_info: serde_json::Value = response
            .json()
            .await
            .map_err(|e| StorageError::Backend(format!("Failed to parse status: {}", e)))?;

        // Parse peer map
        let mut peer_status = HashMap::new();
        if let Some(peer_map) = pin_info["peer_map"].as_object() {
            for (peer_id, status) in peer_map {
                let status_str = status["status"].as_str().unwrap_or("unknown");
                let pin_status = match status_str {
                    "pinned" => ClusterPinStatus::Pinned,
                    "pinning" => ClusterPinStatus::Pinning,
                    "pin_queued" => ClusterPinStatus::Queued,
                    "pin_error" => ClusterPinStatus::Error,
                    "unpinning" => ClusterPinStatus::Unpinning,
                    "remote" => ClusterPinStatus::Remote,
                    _ => ClusterPinStatus::Unpinned,
                };
                peer_status.insert(peer_id.clone(), pin_status);
            }
        }

        Ok(ClusterPinInfo {
            cid: cid.to_string(),
            name: pin_info["name"].as_str().map(String::from),
            replication_factor_min: pin_info["replication_factor_min"].as_i64().unwrap_or(-1) as i32,
            replication_factor_max: pin_info["replication_factor_max"].as_i64().unwrap_or(-1) as i32,
            allocations: pin_info["allocations"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            peer_status,
            created_at: Utc::now(),
            metadata: HashMap::new(),
        })
    }

    async fn list_pins(&self) -> StorageResult<Vec<ClusterPinInfo>> {
        let url = format!("{}/allocations", self.config.api_endpoint);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| StorageError::ReadFailed(format!("Cluster list request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(StorageError::Backend("Failed to list pins".to_string()));
        }

        let pins: Vec<serde_json::Value> = response
            .json()
            .await
            .map_err(|e| StorageError::Backend(format!("Failed to parse pins: {}", e)))?;

        let result = pins
            .into_iter()
            .map(|p| ClusterPinInfo {
                cid: p["cid"]["/"].as_str().unwrap_or_default().to_string(),
                name: p["name"].as_str().map(String::from),
                replication_factor_min: p["replication_factor_min"].as_i64().unwrap_or(-1) as i32,
                replication_factor_max: p["replication_factor_max"].as_i64().unwrap_or(-1) as i32,
                allocations: p["allocations"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                    .unwrap_or_default(),
                peer_status: HashMap::new(),
                created_at: Utc::now(),
                metadata: HashMap::new(),
            })
            .collect();

        Ok(result)
    }

    async fn health(&self) -> StorageResult<ClusterHealth> {
        let peers = self.get_peers().await?;

        let total = peers.len();
        let available = peers.iter().filter(|p| p.available).count();

        Ok(ClusterHealth {
            healthy: available > 0 && available >= (total / 2 + 1),
            total_peers: total,
            available_peers: available,
            version: None,
            checked_at: Utc::now(),
        })
    }
}

/// Mock cluster client for testing
pub struct MockClusterClient {
    pins: Arc<RwLock<HashMap<String, ClusterPinInfo>>>,
    peers: Arc<RwLock<Vec<ClusterPeer>>>,
}

impl MockClusterClient {
    pub fn new() -> Self {
        let mut peers = Vec::new();
        peers.push(ClusterPeer {
            id: "peer1".to_string(),
            addresses: vec!["/ip4/127.0.0.1/tcp/9096".to_string()],
            peername: Some("node1".to_string()),
            available: true,
            last_seen: Some(Utc::now()),
            ipfs_peer_id: Some("Qm123".to_string()),
        });

        Self {
            pins: Arc::new(RwLock::new(HashMap::new())),
            peers: Arc::new(RwLock::new(peers)),
        }
    }
}

impl Default for MockClusterClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ClusterClient for MockClusterClient {
    async fn get_peers(&self) -> StorageResult<Vec<ClusterPeer>> {
        Ok(self.peers.read().await.clone())
    }

    async fn pin(&self, request: ClusterPinRequest) -> StorageResult<ClusterPinInfo> {
        let info = ClusterPinInfo {
            cid: request.cid.clone(),
            name: request.name,
            replication_factor_min: request.replication_factor_min.unwrap_or(-1),
            replication_factor_max: request.replication_factor_max.unwrap_or(-1),
            allocations: vec!["peer1".to_string()],
            peer_status: {
                let mut m = HashMap::new();
                m.insert("peer1".to_string(), ClusterPinStatus::Pinned);
                m
            },
            created_at: Utc::now(),
            metadata: request.metadata,
        };

        self.pins.write().await.insert(request.cid, info.clone());
        Ok(info)
    }

    async fn unpin(&self, cid: &str) -> StorageResult<()> {
        self.pins.write().await.remove(cid);
        Ok(())
    }

    async fn get_pin_status(&self, cid: &str) -> StorageResult<ClusterPinInfo> {
        self.pins
            .read()
            .await
            .get(cid)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(cid.to_string()))
    }

    async fn list_pins(&self) -> StorageResult<Vec<ClusterPinInfo>> {
        Ok(self.pins.read().await.values().cloned().collect())
    }

    async fn health(&self) -> StorageResult<ClusterHealth> {
        let peers = self.peers.read().await;
        Ok(ClusterHealth {
            healthy: true,
            total_peers: peers.len(),
            available_peers: peers.iter().filter(|p| p.available).count(),
            version: Some("mock".to_string()),
            checked_at: Utc::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_cluster_client() {
        let client = MockClusterClient::new();

        // Get peers
        let peers = client.get_peers().await.unwrap();
        assert_eq!(peers.len(), 1);

        // Pin content
        let request = ClusterPinRequest::new("Qm123")
            .with_name("test")
            .with_replication(2, 3);
        let pin_info = client.pin(request).await.unwrap();
        assert_eq!(pin_info.cid, "Qm123");

        // Get status
        let status = client.get_pin_status("Qm123").await.unwrap();
        assert_eq!(status.name, Some("test".to_string()));

        // List pins
        let pins = client.list_pins().await.unwrap();
        assert_eq!(pins.len(), 1);

        // Unpin
        client.unpin("Qm123").await.unwrap();
        let pins = client.list_pins().await.unwrap();
        assert_eq!(pins.len(), 0);
    }

    #[tokio::test]
    async fn test_cluster_health() {
        let client = MockClusterClient::new();
        let health = client.health().await.unwrap();
        assert!(health.healthy);
    }
}
