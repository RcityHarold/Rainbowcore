//! Connected Node Admission Logic
//!
//! This module implements the admission control for DSN connected nodes.
//! It manages node registration, trust scoring, and access control.
//!
//! # Key Concepts
//!
//! 1. **Node Registration**: Nodes must register with valid credentials
//! 2. **Trust Score**: Nodes accumulate trust based on behavior
//! 3. **Admission Control**: Only trusted nodes can participate
//! 4. **Health Monitoring**: Continuous monitoring for node health
//! 5. **Eviction**: Misbehaving nodes are removed from the network
//!
//! # Node Types
//!
//! - **Storage Node**: Stores encrypted payloads
//! - **Relay Node**: Routes traffic between nodes
//! - **Validator Node**: Validates operations
//! - **Gateway Node**: External API gateway

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use l0_core::types::{ActorId, Digest};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Node admission error types
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
pub enum AdmissionError {
    #[error("Node not registered: {node_id}")]
    NodeNotRegistered { node_id: String },

    #[error("Invalid credentials: {reason}")]
    InvalidCredentials { reason: String },

    #[error("Trust score too low: {score} < {required}")]
    InsufficientTrust { score: f64, required: f64 },

    #[error("Node banned: {reason}")]
    NodeBanned { reason: String },

    #[error("Capacity exceeded: {current}/{max}")]
    CapacityExceeded { current: usize, max: usize },

    #[error("Node type not allowed: {node_type:?}")]
    NodeTypeNotAllowed { node_type: NodeType },

    #[error("Region not allowed: {region}")]
    RegionNotAllowed { region: String },

    #[error("Health check failed: {reason}")]
    HealthCheckFailed { reason: String },

    #[error("Registration expired: {node_id}")]
    RegistrationExpired { node_id: String },

    #[error("Duplicate registration: {node_id}")]
    DuplicateRegistration { node_id: String },

    #[error("Rate limit exceeded: {node_id}")]
    RateLimitExceeded { node_id: String },
}

pub type AdmissionResult<T> = Result<T, AdmissionError>;

/// Node types in the DSN network
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeType {
    /// Stores encrypted payloads
    Storage,
    /// Routes traffic
    Relay,
    /// Validates operations
    Validator,
    /// External API gateway
    Gateway,
    /// Lightweight client
    Light,
}

impl NodeType {
    /// Get required minimum trust score for this node type
    pub fn min_trust_score(&self) -> f64 {
        match self {
            NodeType::Storage => 0.7,
            NodeType::Validator => 0.9,
            NodeType::Relay => 0.6,
            NodeType::Gateway => 0.8,
            NodeType::Light => 0.3,
        }
    }

    /// Check if this node type can store data
    pub fn can_store(&self) -> bool {
        matches!(self, NodeType::Storage | NodeType::Validator)
    }

    /// Check if this node type can validate
    pub fn can_validate(&self) -> bool {
        matches!(self, NodeType::Validator)
    }
}

/// Node registration status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistrationStatus {
    /// Pending approval
    Pending,
    /// Active and approved
    Active,
    /// Suspended temporarily
    Suspended,
    /// Banned permanently
    Banned,
    /// Registration expired
    Expired,
    /// Node gracefully departed
    Departed,
}

/// Connected node information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectedNode {
    /// Unique node identifier
    pub node_id: String,
    /// Node type
    pub node_type: NodeType,
    /// Node public key
    pub public_key: Vec<u8>,
    /// Registration status
    pub status: RegistrationStatus,
    /// Trust score (0.0 - 1.0)
    pub trust_score: TrustScore,
    /// Network address
    pub address: NodeAddress,
    /// Registration timestamp
    pub registered_at: DateTime<Utc>,
    /// Last activity timestamp
    pub last_active_at: DateTime<Utc>,
    /// Registration expiry
    pub expires_at: DateTime<Utc>,
    /// Node capabilities
    pub capabilities: NodeCapabilities,
    /// Metadata
    pub metadata: HashMap<String, String>,
}

impl ConnectedNode {
    /// Create a new connected node
    pub fn new(
        node_id: String,
        node_type: NodeType,
        public_key: Vec<u8>,
        address: NodeAddress,
    ) -> Self {
        let now = Utc::now();
        Self {
            node_id,
            node_type,
            public_key,
            status: RegistrationStatus::Pending,
            trust_score: TrustScore::initial(),
            address,
            registered_at: now,
            last_active_at: now,
            expires_at: now + Duration::days(365), // 1 year registration
            capabilities: NodeCapabilities::default_for(node_type),
            metadata: HashMap::new(),
        }
    }

    /// Check if node is active
    pub fn is_active(&self) -> bool {
        self.status == RegistrationStatus::Active && Utc::now() < self.expires_at
    }

    /// Check if node can participate
    pub fn can_participate(&self) -> bool {
        self.is_active() && self.trust_score.value >= self.node_type.min_trust_score()
    }

    /// Update last activity
    pub fn touch(&mut self) {
        self.last_active_at = Utc::now();
    }
}

/// Node network address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeAddress {
    /// IP address
    pub ip: IpAddr,
    /// Port
    pub port: u16,
    /// Protocol (TCP/UDP/QUIC)
    pub protocol: NetworkProtocol,
    /// Region/zone
    pub region: Option<String>,
    /// DNS name (if available)
    pub dns_name: Option<String>,
}

/// Network protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Quic,
    WebSocket,
}

/// Node capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCapabilities {
    /// Storage capacity (bytes)
    pub storage_capacity: Option<u64>,
    /// Bandwidth (bytes/sec)
    pub bandwidth: Option<u64>,
    /// Supported encryption formats
    pub encryption_formats: Vec<String>,
    /// Can serve reads
    pub can_read: bool,
    /// Can accept writes
    pub can_write: bool,
    /// Can relay traffic
    pub can_relay: bool,
    /// Max concurrent connections
    pub max_connections: usize,
}

impl NodeCapabilities {
    /// Default capabilities for a node type
    pub fn default_for(node_type: NodeType) -> Self {
        match node_type {
            NodeType::Storage => Self {
                storage_capacity: Some(1024 * 1024 * 1024 * 100), // 100 GB
                bandwidth: Some(1024 * 1024 * 100), // 100 MB/s
                encryption_formats: vec!["AES-256-GCM".to_string(), "ChaCha20-Poly1305".to_string()],
                can_read: true,
                can_write: true,
                can_relay: false,
                max_connections: 1000,
            },
            NodeType::Relay => Self {
                storage_capacity: None,
                bandwidth: Some(1024 * 1024 * 500), // 500 MB/s
                encryption_formats: vec![],
                can_read: false,
                can_write: false,
                can_relay: true,
                max_connections: 10000,
            },
            NodeType::Validator => Self {
                storage_capacity: Some(1024 * 1024 * 1024 * 10), // 10 GB
                bandwidth: Some(1024 * 1024 * 50), // 50 MB/s
                encryption_formats: vec!["AES-256-GCM".to_string()],
                can_read: true,
                can_write: true,
                can_relay: false,
                max_connections: 500,
            },
            NodeType::Gateway => Self {
                storage_capacity: None,
                bandwidth: Some(1024 * 1024 * 200), // 200 MB/s
                encryption_formats: vec![],
                can_read: true,
                can_write: true,
                can_relay: true,
                max_connections: 5000,
            },
            NodeType::Light => Self {
                storage_capacity: None,
                bandwidth: Some(1024 * 1024 * 10), // 10 MB/s
                encryption_formats: vec![],
                can_read: true,
                can_write: false,
                can_relay: false,
                max_connections: 10,
            },
        }
    }
}

/// Trust score for a node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustScore {
    /// Current trust value (0.0 - 1.0)
    pub value: f64,
    /// Score history
    pub history: Vec<TrustEvent>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
    /// Decay rate (per day)
    pub decay_rate: f64,
}

impl TrustScore {
    /// Initial trust score for new nodes
    pub fn initial() -> Self {
        Self {
            value: 0.5, // Start at neutral
            history: Vec::new(),
            updated_at: Utc::now(),
            decay_rate: 0.01, // 1% decay per day
        }
    }

    /// Apply a trust event
    pub fn apply_event(&mut self, event: TrustEvent) {
        let delta = event.impact;
        self.value = (self.value + delta).clamp(0.0, 1.0);
        self.history.push(event);
        self.updated_at = Utc::now();

        // Keep only recent history
        if self.history.len() > 100 {
            self.history.drain(0..50);
        }
    }

    /// Apply time decay
    pub fn apply_decay(&mut self) {
        let now = Utc::now();
        let days_elapsed = (now - self.updated_at).num_hours() as f64 / 24.0;
        if days_elapsed > 0.0 {
            let decay = self.decay_rate * days_elapsed;
            // Decay towards neutral (0.5)
            if self.value > 0.5 {
                self.value = (self.value - decay).max(0.5);
            } else if self.value < 0.5 {
                self.value = (self.value + decay).min(0.5);
            }
            self.updated_at = now;
        }
    }
}

/// Trust-affecting event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEvent {
    /// Event type
    pub event_type: TrustEventType,
    /// Impact on trust score
    pub impact: f64,
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Additional details
    pub details: Option<String>,
}

/// Types of trust-affecting events
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TrustEventType {
    /// Successful operation
    SuccessfulOperation,
    /// Failed operation
    FailedOperation,
    /// Health check passed
    HealthCheckPassed,
    /// Health check failed
    HealthCheckFailed,
    /// Data corruption detected
    DataCorruption,
    /// Availability issue
    AvailabilityIssue,
    /// Latency issue
    LatencyIssue,
    /// Security violation
    SecurityViolation,
    /// Positive audit result
    PositiveAudit,
    /// Negative audit result
    NegativeAudit,
    /// Vouched by trusted node
    Vouched,
    /// Manual adjustment
    ManualAdjustment,
}

impl TrustEventType {
    /// Get default impact for this event type
    pub fn default_impact(&self) -> f64 {
        match self {
            TrustEventType::SuccessfulOperation => 0.001,
            TrustEventType::FailedOperation => -0.01,
            TrustEventType::HealthCheckPassed => 0.005,
            TrustEventType::HealthCheckFailed => -0.02,
            TrustEventType::DataCorruption => -0.2,
            TrustEventType::AvailabilityIssue => -0.05,
            TrustEventType::LatencyIssue => -0.01,
            TrustEventType::SecurityViolation => -0.5,
            TrustEventType::PositiveAudit => 0.05,
            TrustEventType::NegativeAudit => -0.1,
            TrustEventType::Vouched => 0.02,
            TrustEventType::ManualAdjustment => 0.0, // Varies
        }
    }
}

/// Node registration request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationRequest {
    /// Requested node type
    pub node_type: NodeType,
    /// Node public key
    pub public_key: Vec<u8>,
    /// Network address
    pub address: NodeAddress,
    /// Capabilities
    pub capabilities: NodeCapabilities,
    /// Proof of ownership (signed challenge)
    pub ownership_proof: Vec<u8>,
    /// Referrer node (optional, for vouching)
    pub referrer_node_id: Option<String>,
    /// Metadata
    pub metadata: HashMap<String, String>,
}

/// Admission policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionPolicy {
    /// Maximum nodes per type
    pub max_nodes: HashMap<NodeType, usize>,
    /// Minimum trust score for admission
    pub min_trust_score: f64,
    /// Allowed regions
    pub allowed_regions: Option<Vec<String>>,
    /// Blocked regions
    pub blocked_regions: Vec<String>,
    /// Require referrer for registration
    pub require_referrer: bool,
    /// Auto-approve registrations
    pub auto_approve: bool,
    /// Health check interval (seconds)
    pub health_check_interval_secs: u64,
    /// Inactivity timeout (hours)
    pub inactivity_timeout_hours: u64,
    /// Ban threshold (trust score below this = ban)
    pub ban_threshold: f64,
}

impl Default for AdmissionPolicy {
    fn default() -> Self {
        let mut max_nodes = HashMap::new();
        max_nodes.insert(NodeType::Storage, 1000);
        max_nodes.insert(NodeType::Relay, 100);
        max_nodes.insert(NodeType::Validator, 50);
        max_nodes.insert(NodeType::Gateway, 20);
        max_nodes.insert(NodeType::Light, 10000);

        Self {
            max_nodes,
            min_trust_score: 0.3,
            allowed_regions: None,
            blocked_regions: Vec::new(),
            require_referrer: false,
            auto_approve: true,
            health_check_interval_secs: 60,
            inactivity_timeout_hours: 24,
            ban_threshold: 0.1,
        }
    }
}

/// Health check interface
#[async_trait]
pub trait NodeHealthChecker: Send + Sync {
    /// Check node health
    async fn check_health(&self, node: &ConnectedNode) -> HealthCheckResult;
}

/// Health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    /// Check passed
    pub healthy: bool,
    /// Response latency (ms)
    pub latency_ms: Option<u64>,
    /// Error message (if unhealthy)
    pub error: Option<String>,
    /// Check timestamp
    pub checked_at: DateTime<Utc>,
    /// Additional metrics
    pub metrics: HashMap<String, f64>,
}

/// Node admission controller
pub struct NodeAdmissionController<H: NodeHealthChecker> {
    /// Registered nodes
    nodes: RwLock<HashMap<String, ConnectedNode>>,
    /// Admission policy
    policy: RwLock<AdmissionPolicy>,
    /// Health checker
    health_checker: Arc<H>,
    /// Pending registrations
    pending: RwLock<HashMap<String, RegistrationRequest>>,
    /// Banned nodes
    banned: RwLock<HashMap<String, BanRecord>>,
}

/// Ban record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanRecord {
    /// Node ID
    pub node_id: String,
    /// Ban reason
    pub reason: String,
    /// Banned at
    pub banned_at: DateTime<Utc>,
    /// Ban expiry (None = permanent)
    pub expires_at: Option<DateTime<Utc>>,
    /// Banning authority
    pub banned_by: String,
}

impl<H: NodeHealthChecker> NodeAdmissionController<H> {
    /// Create a new admission controller
    pub fn new(health_checker: Arc<H>, policy: AdmissionPolicy) -> Self {
        Self {
            nodes: RwLock::new(HashMap::new()),
            policy: RwLock::new(policy),
            health_checker,
            pending: RwLock::new(HashMap::new()),
            banned: RwLock::new(HashMap::new()),
        }
    }

    /// Submit a registration request
    pub async fn submit_registration(&self, request: RegistrationRequest) -> AdmissionResult<String> {
        let node_id = format!("node:{}", Uuid::new_v4());

        // Check if already registered
        let nodes = self.nodes.read().await;
        for existing in nodes.values() {
            if existing.public_key == request.public_key {
                return Err(AdmissionError::DuplicateRegistration {
                    node_id: existing.node_id.clone(),
                });
            }
        }
        drop(nodes);

        // Check if banned
        let banned = self.banned.read().await;
        for ban in banned.values() {
            // Check by public key hash
            let pk_hash = Digest::blake3(&request.public_key);
            if ban.node_id == pk_hash.to_hex() {
                if let Some(expires) = ban.expires_at {
                    if Utc::now() < expires {
                        return Err(AdmissionError::NodeBanned {
                            reason: ban.reason.clone(),
                        });
                    }
                } else {
                    return Err(AdmissionError::NodeBanned {
                        reason: ban.reason.clone(),
                    });
                }
            }
        }
        drop(banned);

        // Check capacity
        let policy = self.policy.read().await;
        let nodes = self.nodes.read().await;
        let node_count = nodes
            .values()
            .filter(|n| n.node_type == request.node_type && n.is_active())
            .count();

        if let Some(&max) = policy.max_nodes.get(&request.node_type) {
            if node_count >= max {
                return Err(AdmissionError::CapacityExceeded {
                    current: node_count,
                    max,
                });
            }
        }

        // Check region
        if let Some(ref region) = request.address.region {
            if policy.blocked_regions.contains(region) {
                return Err(AdmissionError::RegionNotAllowed {
                    region: region.clone(),
                });
            }
            if let Some(ref allowed) = policy.allowed_regions {
                if !allowed.contains(region) {
                    return Err(AdmissionError::RegionNotAllowed {
                        region: region.clone(),
                    });
                }
            }
        }

        // Check referrer requirement
        if policy.require_referrer && request.referrer_node_id.is_none() {
            return Err(AdmissionError::InvalidCredentials {
                reason: "Referrer required for registration".to_string(),
            });
        }
        drop(nodes);

        // Auto-approve or queue for manual approval
        if policy.auto_approve {
            drop(policy);
            self.approve_registration(&node_id, request).await?;
        } else {
            drop(policy);
            let mut pending = self.pending.write().await;
            pending.insert(node_id.clone(), request);
        }

        Ok(node_id)
    }

    /// Approve a pending registration
    pub async fn approve_registration(
        &self,
        node_id: &str,
        request: RegistrationRequest,
    ) -> AdmissionResult<ConnectedNode> {
        let mut node = ConnectedNode::new(
            node_id.to_string(),
            request.node_type,
            request.public_key,
            request.address,
        );
        node.capabilities = request.capabilities;
        node.metadata = request.metadata;
        node.status = RegistrationStatus::Active;

        // Apply referrer vouch
        if let Some(ref referrer_id) = request.referrer_node_id {
            let nodes = self.nodes.read().await;
            if let Some(referrer) = nodes.get(referrer_id) {
                if referrer.trust_score.value >= 0.7 {
                    node.trust_score.apply_event(TrustEvent {
                        event_type: TrustEventType::Vouched,
                        impact: 0.1,
                        timestamp: Utc::now(),
                        details: Some(format!("Vouched by {}", referrer_id)),
                    });
                }
            }
        }

        let mut nodes = self.nodes.write().await;
        nodes.insert(node_id.to_string(), node.clone());

        // Remove from pending
        let mut pending = self.pending.write().await;
        pending.remove(node_id);

        tracing::info!(node_id = %node_id, node_type = ?node.node_type, "Node registered and approved");
        Ok(node)
    }

    /// Check if a node can perform an operation
    pub async fn check_admission(&self, node_id: &str) -> AdmissionResult<&'static str> {
        let nodes = self.nodes.read().await;
        let node = nodes.get(node_id).ok_or_else(|| AdmissionError::NodeNotRegistered {
            node_id: node_id.to_string(),
        })?;

        // Check status
        match node.status {
            RegistrationStatus::Pending => {
                return Err(AdmissionError::InvalidCredentials {
                    reason: "Registration pending approval".to_string(),
                });
            }
            RegistrationStatus::Suspended => {
                return Err(AdmissionError::NodeBanned {
                    reason: "Node suspended".to_string(),
                });
            }
            RegistrationStatus::Banned => {
                return Err(AdmissionError::NodeBanned {
                    reason: "Node banned".to_string(),
                });
            }
            RegistrationStatus::Expired => {
                return Err(AdmissionError::RegistrationExpired {
                    node_id: node_id.to_string(),
                });
            }
            RegistrationStatus::Departed => {
                return Err(AdmissionError::NodeNotRegistered {
                    node_id: node_id.to_string(),
                });
            }
            RegistrationStatus::Active => {}
        }

        // Check expiry
        if Utc::now() > node.expires_at {
            return Err(AdmissionError::RegistrationExpired {
                node_id: node_id.to_string(),
            });
        }

        // Check trust score
        let policy = self.policy.read().await;
        if node.trust_score.value < policy.min_trust_score {
            return Err(AdmissionError::InsufficientTrust {
                score: node.trust_score.value,
                required: policy.min_trust_score,
            });
        }

        if node.trust_score.value < node.node_type.min_trust_score() {
            return Err(AdmissionError::InsufficientTrust {
                score: node.trust_score.value,
                required: node.node_type.min_trust_score(),
            });
        }

        Ok("admitted")
    }

    /// Record a trust event for a node
    pub async fn record_trust_event(&self, node_id: &str, event: TrustEvent) -> AdmissionResult<()> {
        let mut nodes = self.nodes.write().await;
        let node = nodes.get_mut(node_id).ok_or_else(|| AdmissionError::NodeNotRegistered {
            node_id: node_id.to_string(),
        })?;

        node.trust_score.apply_event(event);

        // Check for auto-ban
        let policy = self.policy.read().await;
        if node.trust_score.value < policy.ban_threshold {
            node.status = RegistrationStatus::Banned;
            tracing::warn!(node_id = %node_id, trust_score = %node.trust_score.value, "Node auto-banned due to low trust score");
        }

        Ok(())
    }

    /// Run health check on a node
    pub async fn run_health_check(&self, node_id: &str) -> AdmissionResult<HealthCheckResult> {
        let nodes = self.nodes.read().await;
        let node = nodes.get(node_id).ok_or_else(|| AdmissionError::NodeNotRegistered {
            node_id: node_id.to_string(),
        })?;

        let result = self.health_checker.check_health(node).await;
        drop(nodes);

        // Record trust event based on result
        let event = TrustEvent {
            event_type: if result.healthy {
                TrustEventType::HealthCheckPassed
            } else {
                TrustEventType::HealthCheckFailed
            },
            impact: if result.healthy {
                TrustEventType::HealthCheckPassed.default_impact()
            } else {
                TrustEventType::HealthCheckFailed.default_impact()
            },
            timestamp: Utc::now(),
            details: result.error.clone(),
        };
        self.record_trust_event(node_id, event).await?;

        // Update last activity
        let mut nodes = self.nodes.write().await;
        if let Some(node) = nodes.get_mut(node_id) {
            node.touch();
        }

        Ok(result)
    }

    /// Ban a node
    pub async fn ban_node(&self, node_id: &str, reason: &str, duration: Option<Duration>) -> AdmissionResult<()> {
        let mut nodes = self.nodes.write().await;
        let node = nodes.get_mut(node_id).ok_or_else(|| AdmissionError::NodeNotRegistered {
            node_id: node_id.to_string(),
        })?;

        node.status = RegistrationStatus::Banned;
        drop(nodes);

        let ban = BanRecord {
            node_id: node_id.to_string(),
            reason: reason.to_string(),
            banned_at: Utc::now(),
            expires_at: duration.map(|d| Utc::now() + d),
            banned_by: "system".to_string(),
        };

        let mut banned = self.banned.write().await;
        banned.insert(node_id.to_string(), ban);

        tracing::warn!(node_id = %node_id, reason = %reason, "Node banned");
        Ok(())
    }

    /// Gracefully remove a node
    pub async fn depart_node(&self, node_id: &str) -> AdmissionResult<()> {
        let mut nodes = self.nodes.write().await;
        let node = nodes.get_mut(node_id).ok_or_else(|| AdmissionError::NodeNotRegistered {
            node_id: node_id.to_string(),
        })?;

        node.status = RegistrationStatus::Departed;
        tracing::info!(node_id = %node_id, "Node departed gracefully");
        Ok(())
    }

    /// Get all active nodes
    pub async fn get_active_nodes(&self) -> Vec<ConnectedNode> {
        let nodes = self.nodes.read().await;
        nodes.values().filter(|n| n.is_active()).cloned().collect()
    }

    /// Get nodes by type
    pub async fn get_nodes_by_type(&self, node_type: NodeType) -> Vec<ConnectedNode> {
        let nodes = self.nodes.read().await;
        nodes
            .values()
            .filter(|n| n.node_type == node_type && n.is_active())
            .cloned()
            .collect()
    }

    /// Get node statistics
    pub async fn get_stats(&self) -> NodeStats {
        let nodes = self.nodes.read().await;
        let pending = self.pending.read().await;
        let banned = self.banned.read().await;

        let mut by_type = HashMap::new();
        let mut total_active = 0;
        let mut total_trust = 0.0;

        for node in nodes.values() {
            if node.is_active() {
                total_active += 1;
                total_trust += node.trust_score.value;
                *by_type.entry(node.node_type).or_insert(0) += 1;
            }
        }

        NodeStats {
            total_registered: nodes.len(),
            total_active,
            total_pending: pending.len(),
            total_banned: banned.len(),
            by_type,
            average_trust_score: if total_active > 0 {
                total_trust / total_active as f64
            } else {
                0.0
            },
            collected_at: Utc::now(),
        }
    }

    /// Update admission policy
    pub async fn update_policy(&self, policy: AdmissionPolicy) {
        let mut current = self.policy.write().await;
        *current = policy;
    }

    /// Clean up expired and inactive nodes
    pub async fn cleanup_inactive(&self) -> usize {
        let policy = self.policy.read().await;
        let timeout = Duration::hours(policy.inactivity_timeout_hours as i64);
        let now = Utc::now();
        drop(policy);

        let mut nodes = self.nodes.write().await;
        let mut removed = 0;

        for node in nodes.values_mut() {
            // Mark expired registrations
            if node.status == RegistrationStatus::Active && now > node.expires_at {
                node.status = RegistrationStatus::Expired;
                removed += 1;
            }

            // Mark inactive nodes
            if node.status == RegistrationStatus::Active && now - node.last_active_at > timeout {
                node.status = RegistrationStatus::Suspended;
                removed += 1;
            }
        }

        removed
    }
}

/// Node statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStats {
    /// Total registered nodes
    pub total_registered: usize,
    /// Total active nodes
    pub total_active: usize,
    /// Total pending registrations
    pub total_pending: usize,
    /// Total banned nodes
    pub total_banned: usize,
    /// Nodes by type
    pub by_type: HashMap<NodeType, usize>,
    /// Average trust score
    pub average_trust_score: f64,
    /// Stats collection timestamp
    pub collected_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_node_type_trust_requirements() {
        assert!(NodeType::Validator.min_trust_score() > NodeType::Light.min_trust_score());
        assert!(NodeType::Storage.can_store());
        assert!(NodeType::Validator.can_validate());
        assert!(!NodeType::Relay.can_store());
    }

    #[test]
    fn test_trust_score_initial() {
        let score = TrustScore::initial();
        assert_eq!(score.value, 0.5);
        assert!(score.history.is_empty());
    }

    #[test]
    fn test_trust_score_apply_event() {
        let mut score = TrustScore::initial();
        score.apply_event(TrustEvent {
            event_type: TrustEventType::SuccessfulOperation,
            impact: 0.1,
            timestamp: Utc::now(),
            details: None,
        });
        assert!(score.value > 0.5);

        score.apply_event(TrustEvent {
            event_type: TrustEventType::SecurityViolation,
            impact: -0.5,
            timestamp: Utc::now(),
            details: None,
        });
        assert!(score.value < 0.5);
    }

    #[test]
    fn test_connected_node_new() {
        let address = NodeAddress {
            ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port: 8080,
            protocol: NetworkProtocol::Tcp,
            region: Some("us-east".to_string()),
            dns_name: None,
        };

        let node = ConnectedNode::new(
            "node:test".to_string(),
            NodeType::Storage,
            vec![1, 2, 3],
            address,
        );

        assert_eq!(node.node_id, "node:test");
        assert_eq!(node.node_type, NodeType::Storage);
        assert_eq!(node.status, RegistrationStatus::Pending);
    }

    #[test]
    fn test_node_capabilities_default() {
        let storage_caps = NodeCapabilities::default_for(NodeType::Storage);
        assert!(storage_caps.can_read);
        assert!(storage_caps.can_write);
        assert!(storage_caps.storage_capacity.is_some());

        let relay_caps = NodeCapabilities::default_for(NodeType::Relay);
        assert!(relay_caps.can_relay);
        assert!(!relay_caps.can_write);
    }

    #[test]
    fn test_admission_policy_default() {
        let policy = AdmissionPolicy::default();
        assert!(policy.auto_approve);
        assert_eq!(policy.min_trust_score, 0.3);
        assert!(policy.max_nodes.get(&NodeType::Storage).is_some());
    }
}
