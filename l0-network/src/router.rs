//! Message Router
//!
//! Routes incoming messages to appropriate handlers and manages
//! message forwarding for multi-hop communication.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

use crate::error::NetworkResult;
use crate::message::{L0Message, MessagePayload, NodeId, PongPayload};
use crate::node::{NodeManager, Transport};

/// Message handler trait
#[async_trait]
pub trait MessageHandler: Send + Sync {
    /// Handle an incoming message
    async fn handle(&self, from: NodeId, message: L0Message) -> NetworkResult<Option<L0Message>>;
}

/// Router configuration
#[derive(Debug, Clone)]
pub struct RouterConfig {
    /// Maximum hops for message forwarding
    pub max_hops: u8,
    /// Enable message forwarding
    pub enable_forwarding: bool,
    /// Message queue size
    pub queue_size: usize,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            max_hops: 3,
            enable_forwarding: true,
            queue_size: 1000,
        }
    }
}

/// Message router for handling incoming messages
pub struct MessageRouter {
    /// Configuration
    config: RouterConfig,
    /// Node manager
    node_manager: Arc<NodeManager>,
    /// Transport for sending responses
    transport: Arc<dyn Transport>,
    /// Registered message handlers
    handlers: Arc<RwLock<HashMap<String, Arc<dyn MessageHandler>>>>,
    /// Pending responses (for request-response patterns)
    pending_responses: Arc<RwLock<HashMap<String, mpsc::Sender<L0Message>>>>,
}

impl MessageRouter {
    /// Create a new message router
    pub fn new(
        node_manager: Arc<NodeManager>,
        transport: Arc<dyn Transport>,
        config: RouterConfig,
    ) -> Self {
        Self {
            config,
            node_manager,
            transport,
            handlers: Arc::new(RwLock::new(HashMap::new())),
            pending_responses: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a message handler
    pub async fn register_handler(&self, message_type: &str, handler: Arc<dyn MessageHandler>) {
        let mut handlers = self.handlers.write().await;
        handlers.insert(message_type.to_string(), handler);
    }

    /// Route an incoming message
    pub async fn route(&self, from: NodeId, message: L0Message) -> NetworkResult<()> {
        // Check for pending response
        if let Some(tx) = self.check_pending_response(&message).await {
            let _ = tx.send(message).await;
            return Ok(());
        }

        // Handle message based on payload type
        let response = match &message.payload {
            MessagePayload::Ping(ping) => {
                // Respond with pong
                Some(L0Message::direct(
                    self.node_manager.node_id.clone(),
                    from.clone(),
                    MessagePayload::Pong(PongPayload {
                        nonce: ping.nonce,
                        node_role: None,
                        signer_set_version: None,
                    }),
                ))
            }
            MessagePayload::Pong(_) => {
                // Record successful ping
                self.node_manager.record_ping(&from).await;
                None
            }
            MessagePayload::RequestNodes => {
                // Respond with node list
                let nodes = self.node_manager.all_node_infos().await;
                Some(L0Message::direct(
                    self.node_manager.node_id.clone(),
                    from.clone(),
                    MessagePayload::NodeList(nodes),
                ))
            }
            MessagePayload::NodeList(nodes) => {
                // Update our node list
                for node_info in nodes {
                    if node_info.node_id != self.node_manager.node_id {
                        let peer = crate::node::PeerNode::new(
                            node_info.node_id.clone(),
                            node_info.role,
                            node_info.pubkey.clone(),
                            node_info.address.clone(),
                        );
                        self.node_manager.upsert_peer(peer).await;
                    }
                }
                None
            }
            _ => {
                // Try registered handlers
                let message_type = message.payload.message_type();
                let handlers = self.handlers.read().await;
                if let Some(handler) = handlers.get(&message_type) {
                    handler.handle(from.clone(), message.clone()).await?
                } else {
                    // Forward if enabled and not at hop limit
                    if self.config.enable_forwarding && message.hop_count < self.config.max_hops {
                        if let Some(to) = &message.to {
                            if to != &self.node_manager.node_id {
                                self.forward_message(message.clone()).await?;
                            }
                        }
                    }
                    None
                }
            }
        };

        // Send response if any
        if let Some(resp) = response {
            self.transport.send(&from, &resp).await?;
        }

        Ok(())
    }

    /// Forward a message to its destination
    async fn forward_message(&self, mut message: L0Message) -> NetworkResult<()> {
        message.hop_count += 1;

        if let Some(to) = &message.to {
            // Try direct send first
            if self.transport.send(to, &message).await.is_ok() {
                return Ok(());
            }

            // Find a connected peer that might be closer
            let peers = self.node_manager.connected_peers().await;
            for peer in peers {
                if &peer.node_id != to && peer.node_id != message.from {
                    if self.transport.send(&peer.node_id, &message).await.is_ok() {
                        return Ok(());
                    }
                }
            }
        }

        Ok(())
    }

    /// Check for pending response
    async fn check_pending_response(&self, message: &L0Message) -> Option<mpsc::Sender<L0Message>> {
        let pending = self.pending_responses.read().await;
        pending.get(&message.message_id).cloned()
    }

    /// Send a request and wait for response
    pub async fn request(
        &self,
        to: &NodeId,
        payload: MessagePayload,
        timeout_ms: u64,
    ) -> NetworkResult<L0Message> {
        let message = L0Message::direct(self.node_manager.node_id.clone(), to.clone(), payload);

        // Create response channel
        let (tx, mut rx) = mpsc::channel(1);
        self.pending_responses
            .write()
            .await
            .insert(message.message_id.clone(), tx);

        // Send request
        self.transport.send(to, &message).await?;

        // Wait for response
        let response = tokio::time::timeout(
            std::time::Duration::from_millis(timeout_ms),
            rx.recv(),
        )
        .await
        .map_err(|_| crate::error::NetworkError::Timeout("Request timeout".to_string()))?
        .ok_or_else(|| crate::error::NetworkError::Connection("Channel closed".to_string()))?;

        // Cleanup
        self.pending_responses
            .write()
            .await
            .remove(&message.message_id);

        Ok(response)
    }

    /// Start the router message processing loop
    pub async fn run(&self, mut message_rx: mpsc::Receiver<(NodeId, L0Message)>) {
        while let Some((from, message)) = message_rx.recv().await {
            if let Err(e) = self.route(from.clone(), message).await {
                eprintln!("Error routing message from {}: {}", from, e);
            }
        }
    }
}

/// Signing message handler
pub struct SigningMessageHandler {
    /// Signing session manager
    signing_tx: mpsc::Sender<(NodeId, L0Message)>,
}

impl SigningMessageHandler {
    /// Create a new signing message handler
    pub fn new(signing_tx: mpsc::Sender<(NodeId, L0Message)>) -> Self {
        Self { signing_tx }
    }
}

#[async_trait]
impl MessageHandler for SigningMessageHandler {
    async fn handle(&self, from: NodeId, message: L0Message) -> NetworkResult<Option<L0Message>> {
        // Forward to signing service
        let _ = self.signing_tx.send((from, message)).await;
        Ok(None)
    }
}

/// Commitment message handler
pub struct CommitmentMessageHandler {
    /// Commitment processing channel
    commitment_tx: mpsc::Sender<(NodeId, L0Message)>,
}

impl CommitmentMessageHandler {
    /// Create a new commitment message handler
    pub fn new(commitment_tx: mpsc::Sender<(NodeId, L0Message)>) -> Self {
        Self { commitment_tx }
    }
}

#[async_trait]
impl MessageHandler for CommitmentMessageHandler {
    async fn handle(&self, from: NodeId, message: L0Message) -> NetworkResult<Option<L0Message>> {
        // Forward to commitment service
        let _ = self.commitment_tx.send((from, message)).await;
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{NodeRole, PingPayload};
    use crate::node::MemoryTransport;

    #[tokio::test]
    async fn test_router_config_default() {
        let config = RouterConfig::default();
        assert_eq!(config.max_hops, 3);
        assert!(config.enable_forwarding);
    }

    #[tokio::test]
    async fn test_router_config_custom() {
        let config = RouterConfig {
            max_hops: 5,
            enable_forwarding: false,
            queue_size: 500,
        };
        assert_eq!(config.max_hops, 5);
        assert!(!config.enable_forwarding);
        assert_eq!(config.queue_size, 500);
    }

    #[tokio::test]
    async fn test_router_creation() {
        let manager = Arc::new(NodeManager::new(
            "node_0".to_string(),
            NodeRole::CertifiedSigner,
            "pubkey_0".to_string(),
        ));
        let transport = Arc::new(MemoryTransport::new(manager.clone()));
        let config = RouterConfig::default();
        let _router = MessageRouter::new(manager, transport, config);
    }

    #[tokio::test]
    async fn test_router_register_handler() {
        let manager = Arc::new(NodeManager::new(
            "node_0".to_string(),
            NodeRole::CertifiedSigner,
            "pubkey_0".to_string(),
        ));
        let transport = Arc::new(MemoryTransport::new(manager.clone()));
        let config = RouterConfig::default();
        let router = MessageRouter::new(manager, transport, config);

        // Create a dummy handler
        let (tx, _rx) = tokio::sync::mpsc::channel(10);
        let handler = Arc::new(SigningMessageHandler::new(tx));
        router.register_handler("SignRequest", handler).await;
    }

    #[tokio::test]
    async fn test_router_ping_response() {
        let manager = Arc::new(NodeManager::new(
            "node_0".to_string(),
            NodeRole::CertifiedSigner,
            "pubkey_0".to_string(),
        ));
        let transport = Arc::new(MemoryTransport::new(manager.clone()));
        let config = RouterConfig::default();
        let router = MessageRouter::new(manager.clone(), transport.clone(), config);

        // Add peer
        let peer = crate::node::PeerNode::new(
            "node_1".to_string(),
            NodeRole::CertifiedSigner,
            "pubkey_1".to_string(),
            "127.0.0.1:8001".to_string(),
        );
        manager.upsert_peer(peer).await;

        // Route a ping message
        let msg = L0Message::direct(
            "node_1".to_string(),
            "node_0".to_string(),
            MessagePayload::Ping(PingPayload { nonce: 12345 }),
        );

        let result = router.route("node_1".to_string(), msg).await;
        assert!(result.is_ok());

        // Check that a pong was sent back
        let messages = transport.get_messages(&"node_1".to_string()).await;
        assert_eq!(messages.len(), 1);
        assert!(matches!(messages[0].payload, MessagePayload::Pong(_)));
    }

    #[tokio::test]
    async fn test_router_pong_records_ping() {
        let manager = Arc::new(NodeManager::new(
            "node_0".to_string(),
            NodeRole::CertifiedSigner,
            "pubkey_0".to_string(),
        ));

        // Add peer first
        let mut peer = crate::node::PeerNode::new(
            "node_1".to_string(),
            NodeRole::CertifiedSigner,
            "pubkey_1".to_string(),
            "127.0.0.1:8001".to_string(),
        );
        peer.state = crate::node::ConnectionState::Connected;
        manager.upsert_peer(peer).await;

        let transport = Arc::new(MemoryTransport::new(manager.clone()));
        let config = RouterConfig::default();
        let router = MessageRouter::new(manager.clone(), transport, config);

        // Route a pong message
        let msg = L0Message::direct(
            "node_1".to_string(),
            "node_0".to_string(),
            MessagePayload::Pong(crate::message::PongPayload {
                nonce: 12345,
                node_role: None,
                signer_set_version: None,
            }),
        );

        let result = router.route("node_1".to_string(), msg).await;
        assert!(result.is_ok());

        // Check that ping was recorded
        let peer = manager.get_peer(&"node_1".to_string()).await.unwrap();
        assert!(peer.last_ping.is_some());
    }

    #[tokio::test]
    async fn test_router_request_nodes() {
        let manager = Arc::new(NodeManager::new(
            "node_0".to_string(),
            NodeRole::CertifiedSigner,
            "pubkey_0".to_string(),
        ));

        // Add some peers
        for i in 1..4 {
            let peer = crate::node::PeerNode::new(
                format!("node_{}", i),
                NodeRole::CertifiedSigner,
                format!("pubkey_{}", i),
                format!("127.0.0.1:800{}", i),
            );
            manager.upsert_peer(peer).await;
        }

        let transport = Arc::new(MemoryTransport::new(manager.clone()));
        let config = RouterConfig::default();
        let router = MessageRouter::new(manager.clone(), transport.clone(), config);

        // Route a request nodes message
        let msg = L0Message::direct(
            "node_1".to_string(),
            "node_0".to_string(),
            MessagePayload::RequestNodes,
        );

        let result = router.route("node_1".to_string(), msg).await;
        assert!(result.is_ok());

        // Check that node list was sent back
        let messages = transport.get_messages(&"node_1".to_string()).await;
        assert_eq!(messages.len(), 1);
        assert!(matches!(messages[0].payload, MessagePayload::NodeList(_)));
    }

    #[tokio::test]
    async fn test_signing_message_handler() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = SigningMessageHandler::new(tx);

        let msg = L0Message::broadcast(
            "node_0".to_string(),
            MessagePayload::Ping(PingPayload { nonce: 1 }),
        );

        let result = handler.handle("node_1".to_string(), msg.clone()).await;
        assert!(result.is_ok());

        // Check that message was forwarded
        let received = rx.try_recv();
        assert!(received.is_ok());
        let (from, received_msg) = received.unwrap();
        assert_eq!(from, "node_1");
        assert_eq!(received_msg.message_id, msg.message_id);
    }

    #[tokio::test]
    async fn test_commitment_message_handler() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = CommitmentMessageHandler::new(tx);

        let msg = L0Message::broadcast(
            "node_0".to_string(),
            MessagePayload::Ping(PingPayload { nonce: 1 }),
        );

        let result = handler.handle("node_1".to_string(), msg.clone()).await;
        assert!(result.is_ok());

        // Check that message was forwarded
        let received = rx.try_recv();
        assert!(received.is_ok());
    }
}
