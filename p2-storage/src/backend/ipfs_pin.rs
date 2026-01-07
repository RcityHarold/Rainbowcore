//! IPFS Pinning Strategies
//!
//! Manages IPFS content pinning with priority-based strategies.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::ipfs::IpfsConfig;

/// Pin priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PinPriority {
    /// Critical - never unpin
    Critical = 4,
    /// High priority - last to unpin
    High = 3,
    /// Medium priority
    Medium = 2,
    /// Low priority - first to unpin
    Low = 1,
    /// No priority - can be unpinned anytime
    None = 0,
}

impl Default for PinPriority {
    fn default() -> Self {
        Self::Medium
    }
}

/// Pin status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PinStatus {
    /// Content is pinned
    Pinned,
    /// Content is being pinned
    Pinning,
    /// Content is not pinned
    Unpinned,
    /// Pin failed
    Failed,
}

/// Pin record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinRecord {
    /// IPFS CID
    pub cid: String,
    /// Pin status
    pub status: PinStatus,
    /// Pin priority
    pub priority: PinPriority,
    /// Size in bytes
    pub size_bytes: Option<u64>,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Last verified timestamp
    pub last_verified: Option<DateTime<Utc>>,
    /// Pin service (local, cluster, remote)
    pub pin_service: String,
    /// Replication count
    pub replication: u8,
    /// Associated metadata
    pub metadata: HashMap<String, String>,
}

impl PinRecord {
    /// Create a new pin record
    pub fn new(cid: &str, priority: PinPriority) -> Self {
        Self {
            cid: cid.to_string(),
            status: PinStatus::Unpinned,
            priority,
            size_bytes: None,
            created_at: Utc::now(),
            last_verified: None,
            pin_service: "local".to_string(),
            replication: 1,
            metadata: HashMap::new(),
        }
    }

    /// Mark as pinned
    pub fn mark_pinned(&mut self) {
        self.status = PinStatus::Pinned;
        self.last_verified = Some(Utc::now());
    }

    /// Mark as unpinned
    pub fn mark_unpinned(&mut self) {
        self.status = PinStatus::Unpinned;
    }
}

/// Pinning strategy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PinStrategy {
    /// Pin everything
    PinAll,
    /// Pin by priority threshold
    PriorityThreshold { min_priority: PinPriority },
    /// Pin with size limit (LRU eviction)
    SizeLimit { max_bytes: u64 },
    /// Pin by temperature (Hot always, Warm sometimes, Cold rarely)
    TemperatureBased,
    /// Custom strategy
    Custom,
}

impl Default for PinStrategy {
    fn default() -> Self {
        Self::PinAll
    }
}

/// Pin manager configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinManagerConfig {
    /// Pinning strategy
    pub strategy: PinStrategy,
    /// Maximum total pinned size (bytes)
    pub max_pinned_bytes: Option<u64>,
    /// Default replication factor
    pub default_replication: u8,
    /// Verification interval in seconds
    pub verify_interval_secs: u64,
    /// Enable remote pinning services
    pub enable_remote_pinning: bool,
    /// Remote pinning services
    pub remote_services: Vec<RemotePinService>,
}

impl Default for PinManagerConfig {
    fn default() -> Self {
        Self {
            strategy: PinStrategy::PinAll,
            max_pinned_bytes: None,
            default_replication: 1,
            verify_interval_secs: 3600, // 1 hour
            enable_remote_pinning: false,
            remote_services: Vec::new(),
        }
    }
}

/// Remote pinning service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemotePinService {
    /// Service name
    pub name: String,
    /// API endpoint
    pub endpoint: String,
    /// API key
    pub api_key: String,
    /// Service type (pinata, web3.storage, etc.)
    pub service_type: String,
}

/// Pin manager
pub struct PinManager {
    config: IpfsConfig,
    pin_config: RwLock<PinManagerConfig>,
    /// Pin records by CID
    records: RwLock<HashMap<String, PinRecord>>,
    /// Total pinned size
    total_pinned_bytes: RwLock<u64>,
}

impl PinManager {
    /// Create a new pin manager
    pub fn new(config: IpfsConfig) -> Self {
        Self {
            config,
            pin_config: RwLock::new(PinManagerConfig::default()),
            records: RwLock::new(HashMap::new()),
            total_pinned_bytes: RwLock::new(0),
        }
    }

    /// Configure pin manager
    pub async fn configure(&self, config: PinManagerConfig) {
        *self.pin_config.write().await = config;
    }

    /// Register a CID for pinning
    pub async fn register(&self, cid: &str, priority: PinPriority, size: Option<u64>) {
        let mut record = PinRecord::new(cid, priority);
        record.size_bytes = size;

        self.records.write().await.insert(cid.to_string(), record);

        debug!(cid = %cid, priority = ?priority, "Registered CID for pinning");
    }

    /// Set priority for a CID
    pub async fn set_priority(&self, cid: &str, priority: PinPriority) {
        let mut records = self.records.write().await;
        if let Some(record) = records.get_mut(cid) {
            record.priority = priority;
            debug!(cid = %cid, priority = ?priority, "Updated pin priority");
        } else {
            // Create new record
            let record = PinRecord::new(cid, priority);
            records.insert(cid.to_string(), record);
        }
    }

    /// Mark CID as pinned
    pub async fn mark_pinned(&self, cid: &str, size: u64) {
        let mut records = self.records.write().await;
        if let Some(record) = records.get_mut(cid) {
            record.mark_pinned();
            record.size_bytes = Some(size);

            // Update total size
            *self.total_pinned_bytes.write().await += size;
        }
    }

    /// Mark CID as unpinned
    pub async fn mark_unpinned(&self, cid: &str) {
        let mut records = self.records.write().await;
        if let Some(record) = records.get_mut(cid) {
            if let Some(size) = record.size_bytes {
                let mut total = self.total_pinned_bytes.write().await;
                *total = total.saturating_sub(size);
            }
            record.mark_unpinned();
        }
    }

    /// Get pin status
    pub async fn get_status(&self, cid: &str) -> Option<PinStatus> {
        self.records.read().await.get(cid).map(|r| r.status)
    }

    /// Get all pin records
    pub async fn get_all_records(&self) -> Vec<PinRecord> {
        self.records.read().await.values().cloned().collect()
    }

    /// Get records by priority
    pub async fn get_by_priority(&self, priority: PinPriority) -> Vec<PinRecord> {
        self.records
            .read()
            .await
            .values()
            .filter(|r| r.priority == priority)
            .cloned()
            .collect()
    }

    /// Get candidates for unpinning (lowest priority first)
    pub async fn get_unpin_candidates(&self, max_count: usize) -> Vec<String> {
        let records = self.records.read().await;
        let mut pinned: Vec<_> = records
            .values()
            .filter(|r| r.status == PinStatus::Pinned && r.priority < PinPriority::Critical)
            .collect();

        // Sort by priority (ascending) and then by last_verified (oldest first)
        pinned.sort_by(|a, b| {
            a.priority
                .cmp(&b.priority)
                .then_with(|| a.last_verified.cmp(&b.last_verified))
        });

        pinned
            .into_iter()
            .take(max_count)
            .map(|r| r.cid.clone())
            .collect()
    }

    /// Check if should pin based on strategy
    pub async fn should_pin(&self, cid: &str, priority: PinPriority, size: u64) -> bool {
        let config = self.pin_config.read().await;

        match &config.strategy {
            PinStrategy::PinAll => true,
            PinStrategy::PriorityThreshold { min_priority } => priority >= *min_priority,
            PinStrategy::SizeLimit { max_bytes } => {
                let total = *self.total_pinned_bytes.read().await;
                total + size <= *max_bytes
            }
            PinStrategy::TemperatureBased => {
                // Hot (High) always, Warm (Medium) usually, Cold (Low) sometimes
                match priority {
                    PinPriority::Critical | PinPriority::High => true,
                    PinPriority::Medium => true,
                    PinPriority::Low => {
                        // Check if we have space
                        if let Some(max) = config.max_pinned_bytes {
                            let total = *self.total_pinned_bytes.read().await;
                            total + size <= max
                        } else {
                            true
                        }
                    }
                    PinPriority::None => false,
                }
            }
            PinStrategy::Custom => true, // Delegate to external logic
        }
    }

    /// Get total pinned size
    pub async fn total_pinned_size(&self) -> u64 {
        *self.total_pinned_bytes.read().await
    }

    /// Get pin statistics
    pub async fn get_stats(&self) -> PinStats {
        let records = self.records.read().await;

        let total = records.len();
        let pinned = records.values().filter(|r| r.status == PinStatus::Pinned).count();
        let unpinned = records.values().filter(|r| r.status == PinStatus::Unpinned).count();
        let failed = records.values().filter(|r| r.status == PinStatus::Failed).count();

        let total_size = *self.total_pinned_bytes.read().await;

        let by_priority: HashMap<String, usize> = vec![
            ("critical".to_string(), records.values().filter(|r| r.priority == PinPriority::Critical).count()),
            ("high".to_string(), records.values().filter(|r| r.priority == PinPriority::High).count()),
            ("medium".to_string(), records.values().filter(|r| r.priority == PinPriority::Medium).count()),
            ("low".to_string(), records.values().filter(|r| r.priority == PinPriority::Low).count()),
        ].into_iter().collect();

        PinStats {
            total_records: total,
            pinned_count: pinned,
            unpinned_count: unpinned,
            failed_count: failed,
            total_pinned_bytes: total_size,
            by_priority,
            computed_at: Utc::now(),
        }
    }
}

/// Pin statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinStats {
    /// Total pin records
    pub total_records: usize,
    /// Pinned count
    pub pinned_count: usize,
    /// Unpinned count
    pub unpinned_count: usize,
    /// Failed count
    pub failed_count: usize,
    /// Total pinned bytes
    pub total_pinned_bytes: u64,
    /// Count by priority
    pub by_priority: HashMap<String, usize>,
    /// Stats timestamp
    pub computed_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pin_manager() {
        let config = IpfsConfig::default();
        let manager = PinManager::new(config);

        manager.register("Qm123", PinPriority::High, Some(1024)).await;
        manager.mark_pinned("Qm123", 1024).await;

        let status = manager.get_status("Qm123").await;
        assert_eq!(status, Some(PinStatus::Pinned));

        assert_eq!(manager.total_pinned_size().await, 1024);
    }

    #[tokio::test]
    async fn test_priority_ordering() {
        let config = IpfsConfig::default();
        let manager = PinManager::new(config);

        manager.register("low", PinPriority::Low, Some(100)).await;
        manager.mark_pinned("low", 100).await;

        manager.register("high", PinPriority::High, Some(100)).await;
        manager.mark_pinned("high", 100).await;

        let candidates = manager.get_unpin_candidates(10).await;
        assert_eq!(candidates.first(), Some(&"low".to_string()));
    }

    #[tokio::test]
    async fn test_pin_strategy() {
        let config = IpfsConfig::default();
        let manager = PinManager::new(config);

        manager.configure(PinManagerConfig {
            strategy: PinStrategy::PriorityThreshold {
                min_priority: PinPriority::Medium,
            },
            ..Default::default()
        }).await;

        assert!(manager.should_pin("cid1", PinPriority::High, 1000).await);
        assert!(!manager.should_pin("cid2", PinPriority::Low, 1000).await);
    }
}
