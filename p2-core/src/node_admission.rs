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
//! # Connected Node Hard Requirements (硬门槛)
//!
//! Per DSN documentation Chapter 2, Connected Nodes MUST meet two requirements:
//!
//! 1. **P1 Connection**: Node must be connected to P1 (L0) receipt chain
//! 2. **R0 Skeleton Package**: Node must have a valid R0 skeleton package
//!    - R0 contains minimal state required for life resurrection
//!    - Verified via SnapshotMapCommit or payload_map_commit reconciliation
//!
//! **HARD RULE**: Nodes lacking R0 are "local-only" - they cannot:
//! - Participate in cross-node reconciliation
//! - Be recognized by other connected nodes
//! - Share or receive payload mappings
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

    // ==== R0 Skeleton Package Errors (HARD REQUIREMENTS) ====

    /// Node lacks R0 skeleton package - HARD REQUIREMENT VIOLATION
    #[error("Missing R0 skeleton package (node is local-only): {node_id}")]
    MissingR0Skeleton { node_id: String },

    /// R0 skeleton package verification failed
    #[error("R0 skeleton verification failed: {reason}")]
    R0VerificationFailed { reason: String },

    /// P1 connection not established - HARD REQUIREMENT VIOLATION
    #[error("P1 connection not established (node is local-only): {node_id}")]
    MissingP1Connection { node_id: String },

    /// SnapshotMapCommit reconciliation failed
    #[error("SnapshotMapCommit reconciliation failed: {reason}")]
    SnapshotReconciliationFailed { reason: String },

    /// Node is local-only (lacks required connections)
    #[error("Node is local-only and cannot participate in cross-node operations: {node_id}")]
    LocalOnlyNode { node_id: String },
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

/// R0 Skeleton Package Status
///
/// Tracks the status of the node's R0 skeleton package.
/// R0 is REQUIRED for connected node status (not local-only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R0SkeletonStatus {
    /// R0 skeleton package exists
    pub has_r0: bool,
    /// R0 skeleton digest (for verification)
    pub r0_digest: Option<Digest>,
    /// R0 creation timestamp
    pub created_at: Option<DateTime<Utc>>,
    /// R0 last verified timestamp
    pub last_verified_at: Option<DateTime<Utc>>,
    /// R0 verification result
    pub verified: bool,
    /// R0 verification error (if any)
    pub verification_error: Option<String>,
    /// Associated SnapshotMapCommit reference
    pub snapshot_map_commit_ref: Option<String>,
}

impl Default for R0SkeletonStatus {
    fn default() -> Self {
        Self {
            has_r0: false,
            r0_digest: None,
            created_at: None,
            last_verified_at: None,
            verified: false,
            verification_error: None,
            snapshot_map_commit_ref: None,
        }
    }
}

impl R0SkeletonStatus {
    /// Check if R0 is valid and verified
    pub fn is_valid(&self) -> bool {
        self.has_r0 && self.verified && self.r0_digest.is_some()
    }

    /// Create a verified R0 status
    pub fn verified_with_digest(digest: Digest, snapshot_ref: String) -> Self {
        Self {
            has_r0: true,
            r0_digest: Some(digest),
            created_at: Some(Utc::now()),
            last_verified_at: Some(Utc::now()),
            verified: true,
            verification_error: None,
            snapshot_map_commit_ref: Some(snapshot_ref),
        }
    }

    /// Mark verification failed
    pub fn mark_verification_failed(&mut self, reason: &str) {
        self.verified = false;
        self.verification_error = Some(reason.to_string());
        self.last_verified_at = Some(Utc::now());
    }
}

/// P1 (L0) Connection Status
///
/// Tracks the node's connection to the P1/L0 receipt chain.
/// P1 connection is REQUIRED for connected node status (not local-only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P1ConnectionStatus {
    /// P1 connection established
    pub connected: bool,
    /// P1 node endpoint
    pub endpoint: Option<String>,
    /// Last successful receipt sync
    pub last_sync_at: Option<DateTime<Utc>>,
    /// Last receipt ID received
    pub last_receipt_id: Option<String>,
    /// Connection health
    pub healthy: bool,
    /// Connection error (if any)
    pub error: Option<String>,
}

impl Default for P1ConnectionStatus {
    fn default() -> Self {
        Self {
            connected: false,
            endpoint: None,
            last_sync_at: None,
            last_receipt_id: None,
            healthy: false,
            error: None,
        }
    }
}

impl P1ConnectionStatus {
    /// Check if P1 connection is valid
    pub fn is_valid(&self) -> bool {
        self.connected && self.healthy
    }

    /// Create a connected status
    pub fn connected_to(endpoint: &str) -> Self {
        Self {
            connected: true,
            endpoint: Some(endpoint.to_string()),
            last_sync_at: Some(Utc::now()),
            last_receipt_id: None,
            healthy: true,
            error: None,
        }
    }

    /// Mark connection failed
    pub fn mark_disconnected(&mut self, reason: &str) {
        self.connected = false;
        self.healthy = false;
        self.error = Some(reason.to_string());
    }
}

/// Node connectivity classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeConnectivity {
    /// Fully connected: has P1 + R0 - can participate in all operations
    FullyConnected,
    /// Local-only: missing P1 or R0 - cannot participate in cross-node operations
    LocalOnly,
    /// Degraded: has connections but they are unhealthy
    Degraded,
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

    // ==== Hard Requirements for Connected Node Status ====

    /// R0 Skeleton Package status (REQUIRED for connected status)
    pub r0_status: R0SkeletonStatus,
    /// P1 (L0) Connection status (REQUIRED for connected status)
    pub p1_status: P1ConnectionStatus,
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
            r0_status: R0SkeletonStatus::default(),
            p1_status: P1ConnectionStatus::default(),
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

    // ==== Connected Node Hard Requirements Checks ====

    /// Get node connectivity classification
    ///
    /// Returns the connectivity status based on P1 and R0 requirements.
    pub fn connectivity(&self) -> NodeConnectivity {
        let has_r0 = self.r0_status.is_valid();
        let has_p1 = self.p1_status.is_valid();

        if has_r0 && has_p1 {
            NodeConnectivity::FullyConnected
        } else if self.r0_status.has_r0 || self.p1_status.connected {
            // Has partial connections but they're not all valid
            NodeConnectivity::Degraded
        } else {
            NodeConnectivity::LocalOnly
        }
    }

    /// Check if node is fully connected (has P1 + R0)
    ///
    /// **HARD REQUIREMENT**: Only fully connected nodes can participate
    /// in cross-node operations like reconciliation and sharing.
    pub fn is_fully_connected(&self) -> bool {
        self.connectivity() == NodeConnectivity::FullyConnected
    }

    /// Check if node is local-only (missing P1 or R0)
    ///
    /// Local-only nodes:
    /// - Cannot participate in cross-node reconciliation
    /// - Are not recognized by other connected nodes
    /// - Cannot share or receive payload mappings
    pub fn is_local_only(&self) -> bool {
        !self.r0_status.is_valid() || !self.p1_status.is_valid()
    }

    /// Check if node can participate in cross-node operations
    ///
    /// Requires:
    /// 1. Node is active
    /// 2. Trust score meets requirements
    /// 3. Node is fully connected (has P1 + R0)
    pub fn can_participate_cross_node(&self) -> bool {
        self.can_participate() && self.is_fully_connected()
    }

    /// Get detailed reason why node cannot participate in cross-node operations
    pub fn cross_node_participation_blocked_reason(&self) -> Option<String> {
        if !self.is_active() {
            return Some("Node is not active".to_string());
        }
        if self.trust_score.value < self.node_type.min_trust_score() {
            return Some(format!(
                "Trust score {} is below required {}",
                self.trust_score.value,
                self.node_type.min_trust_score()
            ));
        }
        if !self.r0_status.is_valid() {
            if !self.r0_status.has_r0 {
                return Some("Missing R0 skeleton package".to_string());
            }
            if !self.r0_status.verified {
                return Some(format!(
                    "R0 skeleton verification failed: {}",
                    self.r0_status.verification_error.as_deref().unwrap_or("unknown")
                ));
            }
        }
        if !self.p1_status.is_valid() {
            if !self.p1_status.connected {
                return Some("P1 connection not established".to_string());
            }
            if !self.p1_status.healthy {
                return Some(format!(
                    "P1 connection unhealthy: {}",
                    self.p1_status.error.as_deref().unwrap_or("unknown")
                ));
            }
        }
        None
    }

    /// Set R0 skeleton status
    pub fn set_r0_status(&mut self, status: R0SkeletonStatus) {
        self.r0_status = status;
    }

    /// Set P1 connection status
    pub fn set_p1_status(&mut self, status: P1ConnectionStatus) {
        self.p1_status = status;
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

    /// Check if a node can perform cross-node operations
    ///
    /// **HARD REQUIREMENTS** (per DSN documentation Chapter 2):
    ///
    /// 1. Node must pass basic admission check
    /// 2. Node must have valid R0 skeleton package
    /// 3. Node must have valid P1 (L0) connection
    ///
    /// Nodes failing these requirements are "local-only" and CANNOT:
    /// - Participate in cross-node reconciliation
    /// - Be recognized by other connected nodes
    /// - Share or receive payload mappings
    pub async fn check_cross_node_admission(&self, node_id: &str) -> AdmissionResult<NodeConnectivity> {
        // First, run basic admission check
        self.check_admission(node_id).await?;

        let nodes = self.nodes.read().await;
        let node = nodes.get(node_id).ok_or_else(|| AdmissionError::NodeNotRegistered {
            node_id: node_id.to_string(),
        })?;

        // Check R0 skeleton package (HARD REQUIREMENT)
        if !node.r0_status.has_r0 {
            return Err(AdmissionError::MissingR0Skeleton {
                node_id: node_id.to_string(),
            });
        }

        if !node.r0_status.verified {
            return Err(AdmissionError::R0VerificationFailed {
                reason: node.r0_status.verification_error.clone()
                    .unwrap_or_else(|| "R0 skeleton not verified".to_string()),
            });
        }

        // Check P1 connection (HARD REQUIREMENT)
        if !node.p1_status.connected {
            return Err(AdmissionError::MissingP1Connection {
                node_id: node_id.to_string(),
            });
        }

        if !node.p1_status.healthy {
            return Err(AdmissionError::MissingP1Connection {
                node_id: node_id.to_string(),
            });
        }

        // All checks passed - node is fully connected
        Ok(NodeConnectivity::FullyConnected)
    }

    /// Check if node is local-only (cannot participate in cross-node operations)
    pub async fn is_node_local_only(&self, node_id: &str) -> AdmissionResult<bool> {
        let nodes = self.nodes.read().await;
        let node = nodes.get(node_id).ok_or_else(|| AdmissionError::NodeNotRegistered {
            node_id: node_id.to_string(),
        })?;

        Ok(node.is_local_only())
    }

    /// Set R0 skeleton status for a node
    pub async fn set_r0_status(&self, node_id: &str, status: R0SkeletonStatus) -> AdmissionResult<()> {
        let mut nodes = self.nodes.write().await;
        let node = nodes.get_mut(node_id).ok_or_else(|| AdmissionError::NodeNotRegistered {
            node_id: node_id.to_string(),
        })?;

        node.set_r0_status(status);

        tracing::info!(
            node_id = %node_id,
            has_r0 = %node.r0_status.has_r0,
            verified = %node.r0_status.verified,
            "Updated R0 skeleton status"
        );

        Ok(())
    }

    /// Set P1 connection status for a node
    pub async fn set_p1_status(&self, node_id: &str, status: P1ConnectionStatus) -> AdmissionResult<()> {
        let mut nodes = self.nodes.write().await;
        let node = nodes.get_mut(node_id).ok_or_else(|| AdmissionError::NodeNotRegistered {
            node_id: node_id.to_string(),
        })?;

        node.set_p1_status(status);

        tracing::info!(
            node_id = %node_id,
            connected = %node.p1_status.connected,
            healthy = %node.p1_status.healthy,
            "Updated P1 connection status"
        );

        Ok(())
    }

    /// Get all fully connected nodes (have both P1 and R0)
    pub async fn get_fully_connected_nodes(&self) -> Vec<ConnectedNode> {
        let nodes = self.nodes.read().await;
        nodes
            .values()
            .filter(|n| n.is_active() && n.is_fully_connected())
            .cloned()
            .collect()
    }

    /// Get all local-only nodes (missing P1 or R0)
    pub async fn get_local_only_nodes(&self) -> Vec<ConnectedNode> {
        let nodes = self.nodes.read().await;
        nodes
            .values()
            .filter(|n| n.is_active() && n.is_local_only())
            .cloned()
            .collect()
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

    /// Get a node by ID
    pub async fn get_node(&self, node_id: &str) -> Option<ConnectedNode> {
        let nodes = self.nodes.read().await;
        nodes.get(node_id).cloned()
    }

    /// Get current policy
    pub async fn get_policy(&self) -> AdmissionPolicy {
        let policy = self.policy.read().await;
        policy.clone()
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

// ============================================================================
// Default Health Checker Implementations
// ============================================================================

/// Simple ping-based health checker
///
/// This is a basic implementation that checks node health via HTTP ping.
/// For production, consider implementing more sophisticated health checks.
pub struct HttpNodeHealthChecker {
    /// HTTP client
    client: reqwest::Client,
    /// Timeout for health checks
    timeout: std::time::Duration,
}

impl HttpNodeHealthChecker {
    /// Create a new HTTP health checker
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            timeout: std::time::Duration::from_secs(5),
        }
    }

    /// Create with custom timeout
    pub fn with_timeout(timeout: std::time::Duration) -> Self {
        Self {
            client: reqwest::Client::new(),
            timeout,
        }
    }
}

impl Default for HttpNodeHealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NodeHealthChecker for HttpNodeHealthChecker {
    async fn check_health(&self, node: &ConnectedNode) -> HealthCheckResult {
        let url = format!(
            "http://{}:{}/health",
            node.address.ip, node.address.port
        );

        let start = std::time::Instant::now();

        match self.client
            .get(&url)
            .timeout(self.timeout)
            .send()
            .await
        {
            Ok(response) => {
                let latency = start.elapsed().as_millis() as u64;
                let healthy = response.status().is_success();

                HealthCheckResult {
                    healthy,
                    latency_ms: Some(latency),
                    error: if healthy { None } else {
                        Some(format!("Unhealthy status: {}", response.status()))
                    },
                    checked_at: Utc::now(),
                    metrics: HashMap::new(),
                }
            }
            Err(e) => {
                HealthCheckResult {
                    healthy: false,
                    latency_ms: None,
                    error: Some(format!("Connection failed: {}", e)),
                    checked_at: Utc::now(),
                    metrics: HashMap::new(),
                }
            }
        }
    }
}

/// Mock health checker for testing
///
/// Always returns healthy status. Use only in tests.
pub struct MockNodeHealthChecker {
    /// Whether to simulate failures
    fail_mode: std::sync::atomic::AtomicBool,
}

impl MockNodeHealthChecker {
    /// Create a new mock health checker
    pub fn new() -> Self {
        Self {
            fail_mode: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Enable failure mode for testing
    pub fn set_fail_mode(&self, fail: bool) {
        self.fail_mode.store(fail, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Default for MockNodeHealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NodeHealthChecker for MockNodeHealthChecker {
    async fn check_health(&self, _node: &ConnectedNode) -> HealthCheckResult {
        let fail = self.fail_mode.load(std::sync::atomic::Ordering::SeqCst);

        HealthCheckResult {
            healthy: !fail,
            latency_ms: Some(1),
            error: if fail { Some("Mock failure mode".to_string()) } else { None },
            checked_at: Utc::now(),
            metrics: HashMap::new(),
        }
    }
}

/// Type alias for admission controller with HTTP health checker
pub type HttpNodeAdmissionController = NodeAdmissionController<HttpNodeHealthChecker>;

/// Type alias for admission controller with mock health checker
pub type MockNodeAdmissionController = NodeAdmissionController<MockNodeHealthChecker>;

impl HttpNodeAdmissionController {
    /// Create a new admission controller with HTTP health checker
    pub fn new_with_http_checker(policy: AdmissionPolicy) -> Self {
        let health_checker = Arc::new(HttpNodeHealthChecker::new());
        NodeAdmissionController::new(health_checker, policy)
    }
}

impl MockNodeAdmissionController {
    /// Create a new admission controller with mock health checker (TESTING ONLY)
    pub fn new_for_testing() -> Self {
        let health_checker = Arc::new(MockNodeHealthChecker::new());
        NodeAdmissionController::new(health_checker, AdmissionPolicy::default())
    }
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
