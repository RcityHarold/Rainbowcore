//! L0 Node Connection Management
//!
//! Manages connections to other L0 nodes in the network.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::NetworkResult;
use crate::message::{L0Message, NodeId, NodeInfo, NodeRole};

/// Node connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not connected
    Disconnected,
    /// Connecting
    Connecting,
    /// Connected and healthy
    Connected,
    /// Connection failed
    Failed,
}

/// Peer node information
#[derive(Debug, Clone)]
pub struct PeerNode {
    /// Node ID
    pub node_id: NodeId,
    /// Node role
    pub role: NodeRole,
    /// Public key (hex)
    pub pubkey: String,
    /// Network address
    pub address: String,
    /// Connection state
    pub state: ConnectionState,
    /// Last successful ping
    pub last_ping: Option<DateTime<Utc>>,
    /// Last seen activity
    pub last_seen: DateTime<Utc>,
    /// Consecutive failures
    pub failure_count: u32,
    /// Is this a signer node?
    pub is_signer: bool,
}

impl PeerNode {
    /// Create a new peer node
    pub fn new(node_id: NodeId, role: NodeRole, pubkey: String, address: String) -> Self {
        let is_signer = matches!(role, NodeRole::CertifiedSigner | NodeRole::ObserverSigner);
        Self {
            node_id,
            role,
            pubkey,
            address,
            state: ConnectionState::Disconnected,
            last_ping: None,
            last_seen: Utc::now(),
            failure_count: 0,
            is_signer,
        }
    }

    /// Check if the node is online
    pub fn is_online(&self) -> bool {
        self.state == ConnectionState::Connected
    }

    /// Convert to NodeInfo for network messages
    pub fn to_info(&self) -> NodeInfo {
        NodeInfo {
            node_id: self.node_id.clone(),
            role: self.role,
            pubkey: self.pubkey.clone(),
            address: self.address.clone(),
            last_seen: self.last_seen,
            is_online: self.is_online(),
        }
    }
}

/// Transport trait for sending messages
#[async_trait]
pub trait Transport: Send + Sync {
    /// Send a message to a specific node
    async fn send(&self, to: &NodeId, message: &L0Message) -> NetworkResult<()>;

    /// Broadcast a message to all connected nodes
    async fn broadcast(&self, message: &L0Message) -> NetworkResult<Vec<NodeId>>;

    /// Connect to a node
    async fn connect(&self, address: &str) -> NetworkResult<NodeId>;

    /// Disconnect from a node
    async fn disconnect(&self, node_id: &NodeId) -> NetworkResult<()>;
}

/// Node manager for tracking peer nodes
pub struct NodeManager {
    /// Our node ID
    pub node_id: NodeId,
    /// Our node role
    pub role: NodeRole,
    /// Our public key
    pub pubkey: String,
    /// Known peer nodes
    peers: Arc<RwLock<HashMap<NodeId, PeerNode>>>,
    /// Certified signer nodes (for quick lookup)
    signers: Arc<RwLock<Vec<NodeId>>>,
    /// Maximum peers to track
    max_peers: usize,
}

impl NodeManager {
    /// Create a new node manager
    pub fn new(node_id: NodeId, role: NodeRole, pubkey: String) -> Self {
        Self {
            node_id,
            role,
            pubkey,
            peers: Arc::new(RwLock::new(HashMap::new())),
            signers: Arc::new(RwLock::new(Vec::new())),
            max_peers: 100,
        }
    }

    /// Add or update a peer node
    pub async fn upsert_peer(&self, peer: PeerNode) {
        let is_signer = peer.is_signer;
        let node_id = peer.node_id.clone();

        let mut peers = self.peers.write().await;
        if peers.len() >= self.max_peers && !peers.contains_key(&node_id) {
            // Remove oldest disconnected peer
            let oldest = peers
                .iter()
                .filter(|(_, p)| p.state == ConnectionState::Disconnected)
                .min_by_key(|(_, p)| p.last_seen)
                .map(|(id, _)| id.clone());
            if let Some(old_id) = oldest {
                peers.remove(&old_id);
            }
        }
        peers.insert(node_id.clone(), peer);

        if is_signer {
            let mut signers = self.signers.write().await;
            if !signers.contains(&node_id) {
                signers.push(node_id);
            }
        }
    }

    /// Remove a peer node
    pub async fn remove_peer(&self, node_id: &NodeId) {
        let mut peers = self.peers.write().await;
        peers.remove(node_id);

        let mut signers = self.signers.write().await;
        signers.retain(|id| id != node_id);
    }

    /// Get a peer by ID
    pub async fn get_peer(&self, node_id: &NodeId) -> Option<PeerNode> {
        let peers = self.peers.read().await;
        peers.get(node_id).cloned()
    }

    /// Get all connected peers
    pub async fn connected_peers(&self) -> Vec<PeerNode> {
        let peers = self.peers.read().await;
        peers
            .values()
            .filter(|p| p.is_online())
            .cloned()
            .collect()
    }

    /// Get all certified signer nodes
    pub async fn signer_nodes(&self) -> Vec<PeerNode> {
        let peers = self.peers.read().await;
        peers
            .values()
            .filter(|p| p.role == NodeRole::CertifiedSigner)
            .cloned()
            .collect()
    }

    /// Get connected signer count
    pub async fn connected_signer_count(&self) -> usize {
        let peers = self.peers.read().await;
        peers
            .values()
            .filter(|p| p.role == NodeRole::CertifiedSigner && p.is_online())
            .count()
    }

    /// Update peer connection state
    pub async fn update_peer_state(&self, node_id: &NodeId, state: ConnectionState) {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(node_id) {
            peer.state = state;
            if state == ConnectionState::Connected {
                peer.failure_count = 0;
                peer.last_seen = Utc::now();
            } else if state == ConnectionState::Failed {
                peer.failure_count += 1;
            }
        }
    }

    /// Record a successful ping
    pub async fn record_ping(&self, node_id: &NodeId) {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(node_id) {
            peer.last_ping = Some(Utc::now());
            peer.last_seen = Utc::now();
        }
    }

    /// Get all node infos for network messages
    pub async fn all_node_infos(&self) -> Vec<NodeInfo> {
        let peers = self.peers.read().await;
        peers.values().map(|p| p.to_info()).collect()
    }

    /// Check if we have enough signers connected for threshold
    pub async fn has_threshold_signers(&self, threshold: usize) -> bool {
        self.connected_signer_count().await >= threshold
    }
}

/// In-memory transport for testing
pub struct MemoryTransport {
    /// Node manager
    node_manager: Arc<NodeManager>,
    /// Message queue per node
    queues: Arc<RwLock<HashMap<NodeId, Vec<L0Message>>>>,
}

impl MemoryTransport {
    /// Create a new memory transport
    pub fn new(node_manager: Arc<NodeManager>) -> Self {
        Self {
            node_manager,
            queues: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get pending messages for a node
    pub async fn get_messages(&self, node_id: &NodeId) -> Vec<L0Message> {
        let mut queues = self.queues.write().await;
        queues.remove(node_id).unwrap_or_default()
    }
}

#[async_trait]
impl Transport for MemoryTransport {
    async fn send(&self, to: &NodeId, message: &L0Message) -> NetworkResult<()> {
        let mut queues = self.queues.write().await;
        queues
            .entry(to.clone())
            .or_insert_with(Vec::new)
            .push(message.clone());
        Ok(())
    }

    async fn broadcast(&self, message: &L0Message) -> NetworkResult<Vec<NodeId>> {
        let peers = self.node_manager.connected_peers().await;
        let mut sent_to = Vec::new();

        let mut queues = self.queues.write().await;
        for peer in peers {
            queues
                .entry(peer.node_id.clone())
                .or_insert_with(Vec::new)
                .push(message.clone());
            sent_to.push(peer.node_id);
        }

        Ok(sent_to)
    }

    async fn connect(&self, address: &str) -> NetworkResult<NodeId> {
        // In memory transport, we just extract node_id from address
        let node_id = address.to_string();
        self.node_manager
            .update_peer_state(&node_id, ConnectionState::Connected)
            .await;
        Ok(node_id)
    }

    async fn disconnect(&self, node_id: &NodeId) -> NetworkResult<()> {
        self.node_manager
            .update_peer_state(node_id, ConnectionState::Disconnected)
            .await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_node_manager() {
        let manager = NodeManager::new(
            "node_0".to_string(),
            NodeRole::CertifiedSigner,
            "pubkey_0".to_string(),
        );

        // Add some peers
        for i in 1..5 {
            let peer = PeerNode::new(
                format!("node_{}", i),
                if i <= 2 {
                    NodeRole::CertifiedSigner
                } else {
                    NodeRole::ReadVerify
                },
                format!("pubkey_{}", i),
                format!("127.0.0.1:800{}", i),
            );
            manager.upsert_peer(peer).await;
        }

        // Check signer count
        let signers = manager.signer_nodes().await;
        assert_eq!(signers.len(), 2);

        // Update state
        manager
            .update_peer_state(&"node_1".to_string(), ConnectionState::Connected)
            .await;
        assert_eq!(manager.connected_signer_count().await, 1);
    }

    #[tokio::test]
    async fn test_memory_transport() {
        let manager = Arc::new(NodeManager::new(
            "node_0".to_string(),
            NodeRole::CertifiedSigner,
            "pubkey_0".to_string(),
        ));

        // Add a connected peer
        let mut peer = PeerNode::new(
            "node_1".to_string(),
            NodeRole::CertifiedSigner,
            "pubkey_1".to_string(),
            "127.0.0.1:8001".to_string(),
        );
        peer.state = ConnectionState::Connected;
        manager.upsert_peer(peer).await;

        let transport = MemoryTransport::new(manager);

        // Send a message
        let msg = L0Message::broadcast(
            "node_0".to_string(),
            crate::message::MessagePayload::Ping(crate::message::PingPayload { nonce: 1 }),
        );
        let sent = transport.broadcast(&msg).await.unwrap();
        assert_eq!(sent.len(), 1);

        // Get the message
        let messages = transport.get_messages(&"node_1".to_string()).await;
        assert_eq!(messages.len(), 1);
    }
}
