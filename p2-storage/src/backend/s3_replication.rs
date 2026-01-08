//! S3 Cross-Region Replication (CRR)
//!
//! Implements cross-region replication for P2 payloads stored in S3.
//! Supports both AWS S3 native CRR configuration and manual replication
//! for S3-compatible services.
//!
//! # Features
//!
//! - Multi-region replication configuration
//! - Replication rule management
//! - Replication status tracking
//! - Manual replication for non-AWS S3 services
//! - Replication metrics and monitoring

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn, error};

use crate::error::{StorageError, StorageResult};
use super::s3::{S3Backend, S3Config, S3StorageClass};

/// Cross-region replication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossRegionReplicationConfig {
    /// Source bucket configuration
    pub source: ReplicationEndpoint,
    /// Destination bucket configurations (can replicate to multiple regions)
    pub destinations: Vec<ReplicationEndpoint>,
    /// Replication rules
    pub rules: Vec<ReplicationRule>,
    /// Enable real-time replication (vs batch)
    pub real_time: bool,
    /// Batch replication interval in seconds (if not real-time)
    pub batch_interval_secs: u64,
    /// Maximum concurrent replication operations
    pub max_concurrent_ops: usize,
    /// Retry configuration
    pub retry_config: ReplicationRetryConfig,
    /// Enable replication metrics
    pub enable_metrics: bool,
}

impl Default for CrossRegionReplicationConfig {
    fn default() -> Self {
        Self {
            source: ReplicationEndpoint::default(),
            destinations: Vec::new(),
            rules: vec![ReplicationRule::default()],
            real_time: true,
            batch_interval_secs: 300, // 5 minutes
            max_concurrent_ops: 10,
            retry_config: ReplicationRetryConfig::default(),
            enable_metrics: true,
        }
    }
}

/// Replication endpoint (source or destination)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationEndpoint {
    /// Region identifier
    pub region: String,
    /// Bucket name
    pub bucket: String,
    /// S3 endpoint URL (for S3-compatible services)
    pub endpoint: Option<String>,
    /// Access key (if different from source)
    pub access_key_id: Option<String>,
    /// Secret key (if different from source)
    pub secret_access_key: Option<String>,
    /// Key prefix filter
    pub key_prefix: Option<String>,
    /// Storage class for replicated objects
    pub storage_class: Option<S3StorageClass>,
}

impl Default for ReplicationEndpoint {
    fn default() -> Self {
        Self {
            region: "us-east-1".to_string(),
            bucket: "p2-storage".to_string(),
            endpoint: None,
            access_key_id: None,
            secret_access_key: None,
            key_prefix: None,
            storage_class: None,
        }
    }
}

/// Replication rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationRule {
    /// Rule ID
    pub id: String,
    /// Rule status
    pub status: ReplicationRuleStatus,
    /// Priority (lower number = higher priority)
    pub priority: u32,
    /// Filter for objects to replicate
    pub filter: ReplicationFilter,
    /// Destination configuration
    pub destination: ReplicationDestination,
    /// Delete marker replication
    pub delete_marker_replication: DeleteMarkerReplication,
    /// Existing object replication (for newly added rules)
    pub existing_object_replication: ExistingObjectReplication,
}

impl Default for ReplicationRule {
    fn default() -> Self {
        Self {
            id: "default-rule".to_string(),
            status: ReplicationRuleStatus::Enabled,
            priority: 1,
            filter: ReplicationFilter::default(),
            destination: ReplicationDestination::default(),
            delete_marker_replication: DeleteMarkerReplication::Enabled,
            existing_object_replication: ExistingObjectReplication::Disabled,
        }
    }
}

/// Replication rule status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicationRuleStatus {
    Enabled,
    Disabled,
}

/// Replication filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationFilter {
    /// Key prefix to match
    pub prefix: Option<String>,
    /// Tags to match (all must match)
    pub tags: HashMap<String, String>,
    /// Minimum object size (bytes)
    pub min_size: Option<u64>,
    /// Maximum object size (bytes)
    pub max_size: Option<u64>,
}

impl Default for ReplicationFilter {
    fn default() -> Self {
        Self {
            prefix: Some("payloads/".to_string()),
            tags: HashMap::new(),
            min_size: None,
            max_size: None,
        }
    }
}

impl ReplicationFilter {
    /// Check if an object matches this filter
    pub fn matches(&self, key: &str, size: u64, tags: &HashMap<String, String>) -> bool {
        // Check prefix
        if let Some(prefix) = &self.prefix {
            if !key.starts_with(prefix) {
                return false;
            }
        }

        // Check size bounds
        if let Some(min) = self.min_size {
            if size < min {
                return false;
            }
        }
        if let Some(max) = self.max_size {
            if size > max {
                return false;
            }
        }

        // Check tags (all must match)
        for (key, value) in &self.tags {
            match tags.get(key) {
                Some(v) if v == value => continue,
                _ => return false,
            }
        }

        true
    }
}

/// Replication destination configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationDestination {
    /// Destination bucket ARN or name
    pub bucket: String,
    /// Destination region
    pub region: String,
    /// Storage class for replicated objects
    pub storage_class: Option<S3StorageClass>,
    /// Encryption configuration
    pub encryption: Option<ReplicationEncryption>,
    /// Access control translation
    pub access_control_translation: Option<AccessControlTranslation>,
    /// Replication time control
    pub replication_time: Option<ReplicationTimeControl>,
    /// Metrics configuration
    pub metrics: Option<ReplicationMetricsConfig>,
}

impl Default for ReplicationDestination {
    fn default() -> Self {
        Self {
            bucket: "p2-storage-replica".to_string(),
            region: "us-west-2".to_string(),
            storage_class: Some(S3StorageClass::Standard),
            encryption: None,
            access_control_translation: None,
            replication_time: Some(ReplicationTimeControl::default()),
            metrics: Some(ReplicationMetricsConfig::default()),
        }
    }
}

/// Replication encryption configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationEncryption {
    /// KMS key ID for destination encryption
    pub kms_key_id: Option<String>,
}

/// Access control translation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlTranslation {
    /// Owner override
    pub owner: OwnerOverride,
}

/// Owner override option
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerOverride {
    /// Destination bucket owner
    Destination,
}

/// Replication Time Control (RTC)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationTimeControl {
    /// Enable RTC
    pub enabled: bool,
    /// Target replication time in minutes
    pub time_minutes: u32,
}

impl Default for ReplicationTimeControl {
    fn default() -> Self {
        Self {
            enabled: true,
            time_minutes: 15, // 15-minute SLA
        }
    }
}

/// Replication metrics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationMetricsConfig {
    /// Enable metrics
    pub enabled: bool,
    /// Emit events for failed replications
    pub event_threshold_minutes: u32,
}

impl Default for ReplicationMetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            event_threshold_minutes: 15,
        }
    }
}

/// Delete marker replication
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeleteMarkerReplication {
    Enabled,
    Disabled,
}

/// Existing object replication
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExistingObjectReplication {
    Enabled,
    Disabled,
}

/// Retry configuration for replication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationRetryConfig {
    /// Maximum retry attempts
    pub max_retries: u32,
    /// Initial backoff in milliseconds
    pub initial_backoff_ms: u64,
    /// Maximum backoff in milliseconds
    pub max_backoff_ms: u64,
    /// Backoff multiplier
    pub backoff_multiplier: f64,
}

impl Default for ReplicationRetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 5,
            initial_backoff_ms: 1000,
            max_backoff_ms: 60000,
            backoff_multiplier: 2.0,
        }
    }
}

/// Replication status for an object
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectReplicationStatus {
    /// Pending replication
    Pending,
    /// Replication in progress
    InProgress,
    /// Successfully replicated
    Completed,
    /// Replication failed
    Failed,
    /// Object is a replica (not source)
    Replica,
}

/// Replication record for tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationRecord {
    /// Source object key
    pub source_key: String,
    /// Source region
    pub source_region: String,
    /// Destination bucket
    pub destination_bucket: String,
    /// Destination region
    pub destination_region: String,
    /// Destination key
    pub destination_key: String,
    /// Replication status
    pub status: ObjectReplicationStatus,
    /// Object size in bytes
    pub size_bytes: u64,
    /// Replication start time
    pub started_at: DateTime<Utc>,
    /// Replication completion time
    pub completed_at: Option<DateTime<Utc>>,
    /// Retry count
    pub retry_count: u32,
    /// Error message (if failed)
    pub error_message: Option<String>,
    /// Replication rule ID that triggered this
    pub rule_id: String,
}

impl ReplicationRecord {
    /// Create a new pending replication record
    pub fn new(
        source_key: String,
        source_region: String,
        destination_bucket: String,
        destination_region: String,
        size_bytes: u64,
        rule_id: String,
    ) -> Self {
        Self {
            source_key: source_key.clone(),
            source_region,
            destination_bucket,
            destination_region,
            destination_key: source_key,
            status: ObjectReplicationStatus::Pending,
            size_bytes,
            started_at: Utc::now(),
            completed_at: None,
            retry_count: 0,
            error_message: None,
            rule_id,
        }
    }

    /// Mark as in progress
    pub fn start(&mut self) {
        self.status = ObjectReplicationStatus::InProgress;
    }

    /// Mark as completed
    pub fn complete(&mut self) {
        self.status = ObjectReplicationStatus::Completed;
        self.completed_at = Some(Utc::now());
    }

    /// Mark as failed
    pub fn fail(&mut self, error: String) {
        self.status = ObjectReplicationStatus::Failed;
        self.error_message = Some(error);
        self.retry_count += 1;
    }

    /// Get replication duration in milliseconds
    pub fn duration_ms(&self) -> Option<u64> {
        self.completed_at.map(|c| {
            (c - self.started_at).num_milliseconds().max(0) as u64
        })
    }
}

/// Cross-region replication manager
pub struct CrossRegionReplicator {
    /// Configuration
    config: CrossRegionReplicationConfig,
    /// Source S3 client
    source_client: reqwest::Client,
    /// Destination S3 clients (region -> client)
    destination_clients: HashMap<String, reqwest::Client>,
    /// Pending replications
    pending: Arc<RwLock<Vec<ReplicationRecord>>>,
    /// Completed replications (recent)
    completed: Arc<RwLock<Vec<ReplicationRecord>>>,
    /// Failed replications
    failed: Arc<RwLock<Vec<ReplicationRecord>>>,
    /// Replication statistics
    stats: Arc<RwLock<ReplicationStats>>,
}

/// Replication statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReplicationStats {
    /// Total objects replicated
    pub total_replicated: u64,
    /// Total bytes replicated
    pub total_bytes_replicated: u64,
    /// Total failed replications
    pub total_failed: u64,
    /// Currently pending replications
    pub pending_count: usize,
    /// Average replication time (ms)
    pub avg_replication_time_ms: f64,
    /// Last replication timestamp
    pub last_replication_at: Option<DateTime<Utc>>,
    /// Replication by destination region
    pub by_region: HashMap<String, RegionReplicationStats>,
}

/// Per-region replication statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegionReplicationStats {
    /// Objects replicated to this region
    pub objects_replicated: u64,
    /// Bytes replicated to this region
    pub bytes_replicated: u64,
    /// Failed replications to this region
    pub failed_count: u64,
    /// Average replication time to this region (ms)
    pub avg_time_ms: f64,
}

impl CrossRegionReplicator {
    /// Create a new replicator
    pub async fn new(config: CrossRegionReplicationConfig) -> StorageResult<Self> {
        let source_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .map_err(|e| StorageError::Configuration(format!("HTTP client error: {}", e)))?;

        let mut destination_clients = HashMap::new();
        for dest in &config.destinations {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(300))
                .build()
                .map_err(|e| StorageError::Configuration(format!("HTTP client error: {}", e)))?;
            destination_clients.insert(dest.region.clone(), client);
        }

        info!(
            source_region = %config.source.region,
            destination_count = config.destinations.len(),
            rule_count = config.rules.len(),
            "Cross-region replicator initialized"
        );

        Ok(Self {
            config,
            source_client,
            destination_clients,
            pending: Arc::new(RwLock::new(Vec::new())),
            completed: Arc::new(RwLock::new(Vec::new())),
            failed: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(ReplicationStats::default())),
        })
    }

    /// Queue an object for replication
    pub async fn queue_replication(
        &self,
        key: &str,
        size_bytes: u64,
        tags: &HashMap<String, String>,
    ) -> StorageResult<Vec<String>> {
        let mut queued_records = Vec::new();

        for rule in &self.config.rules {
            if rule.status != ReplicationRuleStatus::Enabled {
                continue;
            }

            if !rule.filter.matches(key, size_bytes, tags) {
                continue;
            }

            // Find destination endpoint
            let dest = self.config.destinations
                .iter()
                .find(|d| d.region == rule.destination.region);

            if let Some(dest) = dest {
                let record = ReplicationRecord::new(
                    key.to_string(),
                    self.config.source.region.clone(),
                    dest.bucket.clone(),
                    dest.region.clone(),
                    size_bytes,
                    rule.id.clone(),
                );

                let record_id = format!("{}:{}:{}",
                    record.source_key,
                    record.destination_region,
                    record.started_at.timestamp_micros()
                );

                self.pending.write().await.push(record);
                queued_records.push(record_id);

                debug!(
                    key = %key,
                    dest_region = %dest.region,
                    rule_id = %rule.id,
                    "Queued object for replication"
                );
            }
        }

        // Update pending count
        let pending_count = self.pending.read().await.len();
        self.stats.write().await.pending_count = pending_count;

        Ok(queued_records)
    }

    /// Execute pending replications
    pub async fn execute_pending(&self) -> StorageResult<ReplicationBatchResult> {
        let mut pending = self.pending.write().await;
        let to_process: Vec<_> = pending.drain(..).collect();
        drop(pending);

        let total = to_process.len();
        let mut succeeded = 0;
        let mut failed = 0;
        let mut total_bytes = 0u64;

        for mut record in to_process {
            record.start();

            match self.replicate_object(&record).await {
                Ok(bytes) => {
                    record.complete();
                    total_bytes += bytes;
                    succeeded += 1;

                    // Update stats
                    let mut stats = self.stats.write().await;
                    stats.total_replicated += 1;
                    stats.total_bytes_replicated += bytes;
                    stats.last_replication_at = Some(Utc::now());

                    // Update per-region stats
                    let region_stats = stats.by_region
                        .entry(record.destination_region.clone())
                        .or_insert_with(RegionReplicationStats::default);
                    region_stats.objects_replicated += 1;
                    region_stats.bytes_replicated += bytes;

                    // Add to completed
                    let mut completed = self.completed.write().await;
                    completed.push(record);
                    if completed.len() > 10000 {
                        completed.remove(0);
                    }
                }
                Err(e) => {
                    record.fail(e.to_string());
                    failed += 1;

                    // Check if should retry
                    if record.retry_count < self.config.retry_config.max_retries {
                        self.pending.write().await.push(record.clone());
                    } else {
                        // Update failed stats
                        let mut stats = self.stats.write().await;
                        stats.total_failed += 1;

                        let region_stats = stats.by_region
                            .entry(record.destination_region.clone())
                            .or_insert_with(RegionReplicationStats::default);
                        region_stats.failed_count += 1;

                        self.failed.write().await.push(record);
                    }
                }
            }
        }

        // Update pending count
        let pending_count = self.pending.read().await.len();
        self.stats.write().await.pending_count = pending_count;

        Ok(ReplicationBatchResult {
            total,
            succeeded,
            failed,
            total_bytes,
            pending_remaining: pending_count,
        })
    }

    /// Replicate a single object
    async fn replicate_object(&self, record: &ReplicationRecord) -> StorageResult<u64> {
        // Build source URL
        let source_url = self.build_source_url(&record.source_key);

        // Read from source
        let response = self.source_client
            .get(&source_url)
            .send()
            .await
            .map_err(|e| StorageError::ReadFailed(format!("Source read failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(StorageError::ReadFailed(format!(
                "Source read failed: {}",
                response.status()
            )));
        }

        let data = response.bytes().await
            .map_err(|e| StorageError::ReadFailed(format!("Failed to read source data: {}", e)))?;

        let size = data.len() as u64;

        // Build destination URL
        let dest_url = self.build_destination_url(
            &record.destination_region,
            &record.destination_bucket,
            &record.destination_key,
        );

        // Get destination client
        let client = self.destination_clients.get(&record.destination_region)
            .ok_or_else(|| StorageError::Configuration(format!(
                "No client for region: {}",
                record.destination_region
            )))?;

        // Write to destination
        let dest_storage_class = self.config.destinations
            .iter()
            .find(|d| d.region == record.destination_region)
            .and_then(|d| d.storage_class)
            .unwrap_or(S3StorageClass::Standard);

        let response = client
            .put(&dest_url)
            .body(data.to_vec())
            .header("Content-Type", "application/octet-stream")
            .header("x-amz-storage-class", dest_storage_class.as_aws_str())
            .header("x-amz-meta-replicated-from", &self.config.source.region)
            .header("x-amz-meta-replication-rule", &record.rule_id)
            .send()
            .await
            .map_err(|e| StorageError::WriteFailed(format!("Destination write failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(StorageError::WriteFailed(format!(
                "Destination write failed: {}",
                response.status()
            )));
        }

        info!(
            source_key = %record.source_key,
            dest_region = %record.destination_region,
            size = size,
            "Object replicated successfully"
        );

        Ok(size)
    }

    /// Build source object URL
    fn build_source_url(&self, key: &str) -> String {
        if let Some(endpoint) = &self.config.source.endpoint {
            format!("{}/{}/{}", endpoint, self.config.source.bucket, key)
        } else {
            format!(
                "https://s3.{}.amazonaws.com/{}/{}",
                self.config.source.region,
                self.config.source.bucket,
                key
            )
        }
    }

    /// Build destination object URL
    fn build_destination_url(&self, region: &str, bucket: &str, key: &str) -> String {
        let dest = self.config.destinations.iter().find(|d| d.region == region);

        if let Some(dest) = dest {
            if let Some(endpoint) = &dest.endpoint {
                return format!("{}/{}/{}", endpoint, bucket, key);
            }
        }

        format!("https://s3.{}.amazonaws.com/{}/{}", region, bucket, key)
    }

    /// Get replication statistics
    pub async fn get_stats(&self) -> ReplicationStats {
        self.stats.read().await.clone()
    }

    /// Get pending replications
    pub async fn get_pending(&self) -> Vec<ReplicationRecord> {
        self.pending.read().await.clone()
    }

    /// Get recent completed replications
    pub async fn get_completed(&self, limit: usize) -> Vec<ReplicationRecord> {
        let completed = self.completed.read().await;
        completed.iter().rev().take(limit).cloned().collect()
    }

    /// Get failed replications
    pub async fn get_failed(&self) -> Vec<ReplicationRecord> {
        self.failed.read().await.clone()
    }

    /// Retry failed replications
    pub async fn retry_failed(&self) -> StorageResult<usize> {
        let mut failed = self.failed.write().await;
        let to_retry: Vec<_> = failed.drain(..).collect();
        let count = to_retry.len();

        let mut pending = self.pending.write().await;
        for mut record in to_retry {
            record.status = ObjectReplicationStatus::Pending;
            record.retry_count = 0;
            record.error_message = None;
            pending.push(record);
        }

        info!(count = count, "Queued failed replications for retry");

        Ok(count)
    }

    /// Check replication status for an object
    pub async fn check_status(&self, key: &str) -> Option<ObjectReplicationStatus> {
        // Check pending
        if self.pending.read().await.iter().any(|r| r.source_key == key) {
            return Some(ObjectReplicationStatus::Pending);
        }

        // Check completed
        if self.completed.read().await.iter().any(|r| r.source_key == key) {
            return Some(ObjectReplicationStatus::Completed);
        }

        // Check failed
        if self.failed.read().await.iter().any(|r| r.source_key == key) {
            return Some(ObjectReplicationStatus::Failed);
        }

        None
    }

    /// Verify replication for an object
    pub async fn verify_replication(&self, key: &str) -> StorageResult<ReplicationVerification> {
        let source_url = self.build_source_url(key);
        let source_response = self.source_client.head(&source_url).send().await
            .map_err(|e| StorageError::OperationFailed(format!("Source check failed: {}", e)))?;

        let source_exists = source_response.status().is_success();
        let source_etag = source_response.headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_matches('"').to_string());

        let mut destination_status = HashMap::new();

        for dest in &self.config.destinations {
            let dest_url = self.build_destination_url(&dest.region, &dest.bucket, key);
            let client = self.destination_clients.get(&dest.region);

            let status = if let Some(client) = client {
                match client.head(&dest_url).send().await {
                    Ok(response) => {
                        let exists = response.status().is_success();
                        let dest_etag = response.headers()
                            .get("etag")
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.trim_matches('"').to_string());

                        DestinationVerification {
                            region: dest.region.clone(),
                            exists,
                            etag_match: source_etag == dest_etag,
                            etag: dest_etag,
                        }
                    }
                    Err(_) => DestinationVerification {
                        region: dest.region.clone(),
                        exists: false,
                        etag_match: false,
                        etag: None,
                    },
                }
            } else {
                DestinationVerification {
                    region: dest.region.clone(),
                    exists: false,
                    etag_match: false,
                    etag: None,
                }
            };

            destination_status.insert(dest.region.clone(), status);
        }

        let all_replicated = destination_status.values().all(|v| v.exists && v.etag_match);

        Ok(ReplicationVerification {
            key: key.to_string(),
            source_exists,
            source_etag,
            destination_status,
            fully_replicated: all_replicated,
            verified_at: Utc::now(),
        })
    }
}

/// Replication batch result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationBatchResult {
    /// Total objects processed
    pub total: usize,
    /// Successfully replicated
    pub succeeded: usize,
    /// Failed to replicate
    pub failed: usize,
    /// Total bytes transferred
    pub total_bytes: u64,
    /// Remaining pending
    pub pending_remaining: usize,
}

/// Replication verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationVerification {
    /// Object key
    pub key: String,
    /// Source exists
    pub source_exists: bool,
    /// Source ETag
    pub source_etag: Option<String>,
    /// Destination verification status
    pub destination_status: HashMap<String, DestinationVerification>,
    /// All destinations have matching copies
    pub fully_replicated: bool,
    /// Verification timestamp
    pub verified_at: DateTime<Utc>,
}

/// Destination verification status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestinationVerification {
    /// Region
    pub region: String,
    /// Object exists at destination
    pub exists: bool,
    /// ETag matches source
    pub etag_match: bool,
    /// Destination ETag
    pub etag: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replication_filter_prefix() {
        let filter = ReplicationFilter {
            prefix: Some("payloads/".to_string()),
            ..Default::default()
        };

        assert!(filter.matches("payloads/abc123", 1000, &HashMap::new()));
        assert!(!filter.matches("other/abc123", 1000, &HashMap::new()));
    }

    #[test]
    fn test_replication_filter_size() {
        let filter = ReplicationFilter {
            prefix: None,
            min_size: Some(100),
            max_size: Some(1000),
            ..Default::default()
        };

        assert!(filter.matches("key", 500, &HashMap::new()));
        assert!(!filter.matches("key", 50, &HashMap::new()));
        assert!(!filter.matches("key", 2000, &HashMap::new()));
    }

    #[test]
    fn test_replication_record() {
        let mut record = ReplicationRecord::new(
            "payloads/test".to_string(),
            "us-east-1".to_string(),
            "bucket-replica".to_string(),
            "us-west-2".to_string(),
            1000,
            "rule-1".to_string(),
        );

        assert_eq!(record.status, ObjectReplicationStatus::Pending);

        record.start();
        assert_eq!(record.status, ObjectReplicationStatus::InProgress);

        record.complete();
        assert_eq!(record.status, ObjectReplicationStatus::Completed);
        assert!(record.completed_at.is_some());
    }

    #[test]
    fn test_replication_config_default() {
        let config = CrossRegionReplicationConfig::default();
        assert!(config.real_time);
        assert_eq!(config.max_concurrent_ops, 10);
    }
}
