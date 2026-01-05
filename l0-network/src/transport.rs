//! TCP Transport Implementation
//!
//! Provides actual P2P communication over TCP with:
//! - Connection pool management
//! - Message serialization/deserialization
//! - Automatic reconnection with backoff
//! - Heartbeat/ping mechanism

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, timeout};

use crate::error::{NetworkError, NetworkResult};
use crate::message::{L0Message, MessagePayload, NodeId, PingPayload};
use crate::node::{ConnectionState, NodeManager, PeerNode, Transport};

/// Configuration for TCP transport
#[derive(Debug, Clone)]
pub struct TcpTransportConfig {
    /// Address to bind to for incoming connections
    pub bind_address: String,
    /// Connection timeout in milliseconds
    pub connect_timeout_ms: u64,
    /// Read timeout in milliseconds
    pub read_timeout_ms: u64,
    /// Write timeout in milliseconds
    pub write_timeout_ms: u64,
    /// Ping interval in seconds
    pub ping_interval_secs: u64,
    /// Maximum reconnection attempts
    pub max_reconnect_attempts: u32,
    /// Base reconnection delay in milliseconds
    pub reconnect_delay_ms: u64,
    /// Maximum message size in bytes
    pub max_message_size: usize,
}

impl Default for TcpTransportConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:9000".to_string(),
            connect_timeout_ms: 5000,
            read_timeout_ms: 30000,
            write_timeout_ms: 10000,
            ping_interval_secs: 30,
            max_reconnect_attempts: 5,
            reconnect_delay_ms: 1000,
            max_message_size: 16 * 1024 * 1024, // 16MB
        }
    }
}

/// Connection to a peer (reserved for future connection pooling enhancements)
#[allow(dead_code)]
struct PeerConnection {
    stream: TcpStream,
    node_id: NodeId,
    address: String,
}

/// TCP Transport for P2P communication
pub struct TcpTransport {
    /// Configuration
    config: TcpTransportConfig,
    /// Node manager
    node_manager: Arc<NodeManager>,
    /// Active connections (node_id -> connection)
    connections: Arc<RwLock<HashMap<NodeId, Arc<RwLock<TcpStream>>>>>,
    /// Message receiver channel
    message_rx: Arc<RwLock<Option<mpsc::Receiver<(NodeId, L0Message)>>>>,
    /// Message sender channel (for incoming messages)
    message_tx: mpsc::Sender<(NodeId, L0Message)>,
    /// Shutdown signal
    shutdown: Arc<RwLock<bool>>,
}

impl TcpTransport {
    /// Create a new TCP transport
    pub fn new(node_manager: Arc<NodeManager>, config: TcpTransportConfig) -> Self {
        let (tx, rx) = mpsc::channel(1000);
        Self {
            config,
            node_manager,
            connections: Arc::new(RwLock::new(HashMap::new())),
            message_rx: Arc::new(RwLock::new(Some(rx))),
            message_tx: tx,
            shutdown: Arc::new(RwLock::new(false)),
        }
    }

    /// Start the transport (listener and ping tasks)
    pub async fn start(&self) -> NetworkResult<()> {
        // Start listener
        let listener = TcpListener::bind(&self.config.bind_address)
            .await
            .map_err(|e| NetworkError::Connection(format!("Failed to bind: {}", e)))?;

        let connections = self.connections.clone();
        let node_manager = self.node_manager.clone();
        let message_tx = self.message_tx.clone();
        let config = self.config.clone();
        let shutdown = self.shutdown.clone();

        // Spawn listener task
        tokio::spawn(async move {
            loop {
                if *shutdown.read().await {
                    break;
                }

                match listener.accept().await {
                    Ok((stream, addr)) => {
                        let connections = connections.clone();
                        let node_manager = node_manager.clone();
                        let message_tx = message_tx.clone();
                        let config = config.clone();

                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_connection(
                                stream,
                                addr.to_string(),
                                connections,
                                node_manager,
                                message_tx,
                                config,
                            )
                            .await
                            {
                                eprintln!("Connection error from {}: {}", addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("Accept error: {}", e);
                    }
                }
            }
        });

        // Spawn ping task
        let connections = self.connections.clone();
        let node_manager = self.node_manager.clone();
        let ping_interval = self.config.ping_interval_secs;
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(ping_interval));
            loop {
                interval.tick().await;
                if *shutdown.read().await {
                    break;
                }

                // Ping all connected nodes
                let conns = connections.read().await;
                for (node_id, _) in conns.iter() {
                    node_manager.record_ping(node_id).await;
                }
            }
        });

        Ok(())
    }

    /// Handle an incoming connection
    async fn handle_connection(
        mut stream: TcpStream,
        _address: String,
        connections: Arc<RwLock<HashMap<NodeId, Arc<RwLock<TcpStream>>>>>,
        node_manager: Arc<NodeManager>,
        message_tx: mpsc::Sender<(NodeId, L0Message)>,
        config: TcpTransportConfig,
    ) -> NetworkResult<()> {
        // Read handshake message to get node_id
        let handshake = Self::read_message(&mut stream, &config).await?;
        let node_id = handshake.from.clone();

        // Store connection
        let stream = Arc::new(RwLock::new(stream));
        connections
            .write()
            .await
            .insert(node_id.clone(), stream.clone());

        // Update node manager
        node_manager
            .update_peer_state(&node_id, ConnectionState::Connected)
            .await;

        // Read messages in a loop
        loop {
            let mut stream_guard = stream.write().await;
            match Self::read_message(&mut *stream_guard, &config).await {
                Ok(message) => {
                    drop(stream_guard);
                    if message_tx.send((node_id.clone(), message)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    drop(stream_guard);
                    eprintln!("Read error from {}: {}", node_id, e);
                    break;
                }
            }
        }

        // Cleanup
        connections.write().await.remove(&node_id);
        node_manager
            .update_peer_state(&node_id, ConnectionState::Disconnected)
            .await;

        Ok(())
    }

    /// Read a message from a stream
    async fn read_message(stream: &mut TcpStream, config: &TcpTransportConfig) -> NetworkResult<L0Message> {
        // Read length prefix (4 bytes)
        let mut len_buf = [0u8; 4];
        timeout(
            Duration::from_millis(config.read_timeout_ms),
            stream.read_exact(&mut len_buf),
        )
        .await
        .map_err(|_| NetworkError::Timeout("Read timeout".to_string()))?
        .map_err(|e| NetworkError::Connection(format!("Read error: {}", e)))?;

        let len = u32::from_be_bytes(len_buf) as usize;
        if len > config.max_message_size {
            return Err(NetworkError::InvalidMessage(format!(
                "Message too large: {} > {}",
                len, config.max_message_size
            )));
        }

        // Read message body
        let mut buf = vec![0u8; len];
        timeout(
            Duration::from_millis(config.read_timeout_ms),
            stream.read_exact(&mut buf),
        )
        .await
        .map_err(|_| NetworkError::Timeout("Read timeout".to_string()))?
        .map_err(|e| NetworkError::Connection(format!("Read error: {}", e)))?;

        // Deserialize
        serde_json::from_slice(&buf)
            .map_err(|e| NetworkError::InvalidMessage(format!("Deserialize error: {}", e)))
    }

    /// Write a message to a stream
    async fn write_message(
        stream: &mut TcpStream,
        message: &L0Message,
        config: &TcpTransportConfig,
    ) -> NetworkResult<()> {
        let data = serde_json::to_vec(message)
            .map_err(|e| NetworkError::InvalidMessage(format!("Serialize error: {}", e)))?;

        if data.len() > config.max_message_size {
            return Err(NetworkError::InvalidMessage(format!(
                "Message too large: {} > {}",
                data.len(),
                config.max_message_size
            )));
        }

        // Write length prefix
        let len = (data.len() as u32).to_be_bytes();
        timeout(
            Duration::from_millis(config.write_timeout_ms),
            stream.write_all(&len),
        )
        .await
        .map_err(|_| NetworkError::Timeout("Write timeout".to_string()))?
        .map_err(|e| NetworkError::Connection(format!("Write error: {}", e)))?;

        // Write message body
        timeout(
            Duration::from_millis(config.write_timeout_ms),
            stream.write_all(&data),
        )
        .await
        .map_err(|_| NetworkError::Timeout("Write timeout".to_string()))?
        .map_err(|e| NetworkError::Connection(format!("Write error: {}", e)))?;

        Ok(())
    }

    /// Connect to a peer with retry logic
    async fn connect_with_retry(&self, address: &str) -> NetworkResult<TcpStream> {
        let mut attempts = 0;
        let mut delay = self.config.reconnect_delay_ms;

        loop {
            match timeout(
                Duration::from_millis(self.config.connect_timeout_ms),
                TcpStream::connect(address),
            )
            .await
            {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(e)) => {
                    attempts += 1;
                    if attempts >= self.config.max_reconnect_attempts {
                        return Err(NetworkError::Connection(format!(
                            "Failed to connect after {} attempts: {}",
                            attempts, e
                        )));
                    }
                }
                Err(_) => {
                    attempts += 1;
                    if attempts >= self.config.max_reconnect_attempts {
                        return Err(NetworkError::Timeout(format!(
                            "Connection timeout after {} attempts",
                            attempts
                        )));
                    }
                }
            }

            // Exponential backoff
            tokio::time::sleep(Duration::from_millis(delay)).await;
            delay = (delay * 2).min(30000); // Cap at 30 seconds
        }
    }

    /// Take the message receiver (can only be called once)
    pub async fn take_message_receiver(&self) -> Option<mpsc::Receiver<(NodeId, L0Message)>> {
        self.message_rx.write().await.take()
    }

    /// Shutdown the transport
    pub async fn shutdown(&self) {
        *self.shutdown.write().await = true;

        // Close all connections
        let mut conns = self.connections.write().await;
        conns.clear();
    }
}

#[async_trait]
impl Transport for TcpTransport {
    async fn send(&self, to: &NodeId, message: &L0Message) -> NetworkResult<()> {
        let conns = self.connections.read().await;
        let stream = conns
            .get(to)
            .ok_or_else(|| NetworkError::NotConnected(to.clone()))?;

        let mut stream_guard = stream.write().await;
        Self::write_message(&mut *stream_guard, message, &self.config).await
    }

    async fn broadcast(&self, message: &L0Message) -> NetworkResult<Vec<NodeId>> {
        let conns = self.connections.read().await;
        let mut sent_to = Vec::new();

        for (node_id, stream) in conns.iter() {
            let mut stream_guard = stream.write().await;
            if Self::write_message(&mut *stream_guard, message, &self.config)
                .await
                .is_ok()
            {
                sent_to.push(node_id.clone());
            }
        }

        Ok(sent_to)
    }

    async fn connect(&self, address: &str) -> NetworkResult<NodeId> {
        let mut stream = self.connect_with_retry(address).await?;

        // Send handshake
        let handshake = L0Message::broadcast(
            self.node_manager.node_id.clone(),
            MessagePayload::Ping(PingPayload { nonce: 0 }),
        );
        Self::write_message(&mut stream, &handshake, &self.config).await?;

        // Read response to get node_id
        let response = Self::read_message(&mut stream, &self.config).await?;
        let node_id = response.from.clone();

        // Store connection
        self.connections
            .write()
            .await
            .insert(node_id.clone(), Arc::new(RwLock::new(stream)));

        // Update node manager
        self.node_manager
            .update_peer_state(&node_id, ConnectionState::Connected)
            .await;

        Ok(node_id)
    }

    async fn disconnect(&self, node_id: &NodeId) -> NetworkResult<()> {
        self.connections.write().await.remove(node_id);
        self.node_manager
            .update_peer_state(node_id, ConnectionState::Disconnected)
            .await;
        Ok(())
    }
}

/// Node discovery service
pub struct NodeDiscovery {
    /// Node manager
    node_manager: Arc<NodeManager>,
    /// Transport
    transport: Arc<dyn Transport>,
    /// Bootstrap nodes
    bootstrap_nodes: Vec<String>,
    /// Discovery interval in seconds
    pub discovery_interval_secs: u64,
}

impl NodeDiscovery {
    /// Create a new node discovery service
    pub fn new(
        node_manager: Arc<NodeManager>,
        transport: Arc<dyn Transport>,
        bootstrap_nodes: Vec<String>,
    ) -> Self {
        Self {
            node_manager,
            transport,
            bootstrap_nodes,
            discovery_interval_secs: 60,
        }
    }

    /// Start the discovery service
    pub async fn start(&self) -> NetworkResult<()> {
        // Connect to bootstrap nodes
        for addr in &self.bootstrap_nodes {
            match self.transport.connect(addr).await {
                Ok(node_id) => {
                    println!("Connected to bootstrap node: {} at {}", node_id, addr);
                }
                Err(e) => {
                    eprintln!("Failed to connect to bootstrap node {}: {}", addr, e);
                }
            }
        }

        // Request node list from connected peers
        self.discover_peers().await?;

        Ok(())
    }

    /// Discover peers from connected nodes
    async fn discover_peers(&self) -> NetworkResult<()> {
        let message = L0Message::broadcast(
            self.node_manager.node_id.clone(),
            MessagePayload::RequestNodes,
        );

        self.transport.broadcast(&message).await?;
        Ok(())
    }

    /// Handle a node list response
    pub async fn handle_node_list(&self, nodes: Vec<crate::message::NodeInfo>) {
        for node_info in nodes {
            if node_info.node_id == self.node_manager.node_id {
                continue; // Skip ourselves
            }

            let address = node_info.address.clone();
            let node_id = node_info.node_id.clone();

            let peer = PeerNode::new(
                node_info.node_id,
                node_info.role,
                node_info.pubkey,
                address.clone(),
            );

            self.node_manager.upsert_peer(peer).await;

            // Try to connect if not already connected
            if !node_info.is_online {
                if let Err(e) = self.transport.connect(&address).await {
                    eprintln!(
                        "Failed to connect to discovered node {}: {}",
                        node_id, e
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::NodeRole;
    use crate::node::MemoryTransport;

    #[tokio::test]
    async fn test_tcp_transport_config_default() {
        let config = TcpTransportConfig::default();
        assert_eq!(config.bind_address, "0.0.0.0:9000");
        assert_eq!(config.ping_interval_secs, 30);
        assert_eq!(config.max_reconnect_attempts, 5);
    }

    #[tokio::test]
    async fn test_tcp_transport_config_custom() {
        let config = TcpTransportConfig {
            bind_address: "127.0.0.1:9001".to_string(),
            connect_timeout_ms: 10000,
            read_timeout_ms: 60000,
            write_timeout_ms: 20000,
            ping_interval_secs: 60,
            max_reconnect_attempts: 10,
            reconnect_delay_ms: 2000,
            max_message_size: 32 * 1024 * 1024,
        };
        assert_eq!(config.bind_address, "127.0.0.1:9001");
        assert_eq!(config.connect_timeout_ms, 10000);
        assert_eq!(config.max_message_size, 32 * 1024 * 1024);
    }

    #[tokio::test]
    async fn test_tcp_transport_creation() {
        let node_manager = Arc::new(NodeManager::new(
            "node_0".to_string(),
            NodeRole::CertifiedSigner,
            "pubkey_0".to_string(),
        ));
        let config = TcpTransportConfig::default();
        let transport = TcpTransport::new(node_manager, config);

        // Check we can take the message receiver
        let receiver = transport.take_message_receiver().await;
        assert!(receiver.is_some());

        // Second take should return None
        let receiver2 = transport.take_message_receiver().await;
        assert!(receiver2.is_none());
    }

    #[tokio::test]
    async fn test_node_discovery_creation() {
        let node_manager = Arc::new(NodeManager::new(
            "node_0".to_string(),
            NodeRole::CertifiedSigner,
            "pubkey_0".to_string(),
        ));
        let transport = Arc::new(MemoryTransport::new(node_manager.clone()));
        let bootstrap_nodes = vec!["127.0.0.1:9000".to_string(), "127.0.0.1:9001".to_string()];

        let discovery = NodeDiscovery::new(node_manager, transport, bootstrap_nodes);
        assert_eq!(discovery.discovery_interval_secs, 60);
    }

    #[tokio::test]
    async fn test_node_discovery_handle_node_list() {
        let node_manager = Arc::new(NodeManager::new(
            "node_0".to_string(),
            NodeRole::CertifiedSigner,
            "pubkey_0".to_string(),
        ));
        let transport = Arc::new(MemoryTransport::new(node_manager.clone()));
        let discovery = NodeDiscovery::new(node_manager.clone(), transport, vec![]);

        // Handle a node list response
        let nodes = vec![
            crate::message::NodeInfo {
                node_id: "node_1".to_string(),
                role: NodeRole::CertifiedSigner,
                pubkey: "pubkey_1".to_string(),
                address: "127.0.0.1:9001".to_string(),
                last_seen: chrono::Utc::now(),
                is_online: false,
            },
            crate::message::NodeInfo {
                node_id: "node_2".to_string(),
                role: NodeRole::ReadVerify,
                pubkey: "pubkey_2".to_string(),
                address: "127.0.0.1:9002".to_string(),
                last_seen: chrono::Utc::now(),
                is_online: false,
            },
        ];

        discovery.handle_node_list(nodes).await;

        // Verify nodes were added
        let peer1 = node_manager.get_peer(&"node_1".to_string()).await;
        assert!(peer1.is_some());
        assert_eq!(peer1.unwrap().role, NodeRole::CertifiedSigner);

        let peer2 = node_manager.get_peer(&"node_2".to_string()).await;
        assert!(peer2.is_some());
        assert_eq!(peer2.unwrap().role, NodeRole::ReadVerify);
    }

    #[tokio::test]
    async fn test_node_discovery_skip_self() {
        let node_manager = Arc::new(NodeManager::new(
            "node_0".to_string(),
            NodeRole::CertifiedSigner,
            "pubkey_0".to_string(),
        ));
        let transport = Arc::new(MemoryTransport::new(node_manager.clone()));
        let discovery = NodeDiscovery::new(node_manager.clone(), transport, vec![]);

        // Try to add ourselves
        let nodes = vec![crate::message::NodeInfo {
            node_id: "node_0".to_string(), // Same as our node
            role: NodeRole::CertifiedSigner,
            pubkey: "pubkey_0".to_string(),
            address: "127.0.0.1:9000".to_string(),
            last_seen: chrono::Utc::now(),
            is_online: true,
        }];

        discovery.handle_node_list(nodes).await;

        // Should not have added ourselves to peers
        let peer = node_manager.get_peer(&"node_0".to_string()).await;
        assert!(peer.is_none());
    }
}
