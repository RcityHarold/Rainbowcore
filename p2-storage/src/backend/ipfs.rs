//! IPFS Storage Backend
//!
//! Content-addressed distributed storage using IPFS.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use l0_core::types::Digest as L0Digest;
use p2_core::types::{SealedPayloadRef, SealedPayloadStatus, StorageTemperature};
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::error::{StorageError, StorageResult};

use super::traits::{
    BackendCapabilities, BackendType, HealthStatus, IntegrityResult, P2StorageBackend,
    PayloadMetadata, WriteMetadata,
};
use super::ipfs_pin::{PinManager, PinPriority, PinStatus};

/// IPFS backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpfsConfig {
    /// IPFS API endpoint
    pub api_endpoint: String,
    /// Gateway endpoint for reads
    pub gateway_endpoint: Option<String>,
    /// Connection timeout in seconds
    pub timeout_secs: u64,
    /// Whether to pin content automatically
    pub auto_pin: bool,
    /// Pin replication factor
    pub pin_replication: u8,
    /// Use local node
    pub use_local_node: bool,
    /// MFS (Mutable File System) path prefix
    pub mfs_prefix: String,
}

impl Default for IpfsConfig {
    fn default() -> Self {
        Self {
            api_endpoint: "http://127.0.0.1:5001".to_string(),
            gateway_endpoint: Some("http://127.0.0.1:8080".to_string()),
            timeout_secs: 30,
            auto_pin: true,
            pin_replication: 1,
            use_local_node: true,
            mfs_prefix: "/p2-storage".to_string(),
        }
    }
}

impl IpfsConfig {
    /// Create config for local IPFS node
    pub fn local() -> Self {
        Self::default()
    }

    /// Create config for remote IPFS node
    pub fn remote(api_endpoint: &str) -> Self {
        Self {
            api_endpoint: api_endpoint.to_string(),
            use_local_node: false,
            ..Default::default()
        }
    }

    /// Create config for Infura IPFS
    pub fn infura(project_id: &str, project_secret: &str) -> Self {
        Self {
            api_endpoint: format!(
                "https://{}:{}@ipfs.infura.io:5001",
                project_id, project_secret
            ),
            gateway_endpoint: Some("https://ipfs.infura.io".to_string()),
            use_local_node: false,
            ..Default::default()
        }
    }
}

/// CID to ref_id mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CidMapping {
    /// IPFS CID (Content Identifier)
    pub cid: String,
    /// P2 reference ID
    pub ref_id: String,
    /// CID version
    pub cid_version: u8,
    /// Size in bytes
    pub size_bytes: u64,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
}

/// IPFS add response
#[derive(Debug, Clone, Deserialize)]
struct IpfsAddResponse {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Hash")]
    hash: String,
    #[serde(rename = "Size")]
    size: String,
}

/// IPFS cat response is raw bytes
///
/// IPFS pin response
#[derive(Debug, Clone, Deserialize)]
struct IpfsPinResponse {
    #[serde(rename = "Pins")]
    pins: Vec<String>,
}

/// IPFS Storage Backend
pub struct IpfsBackend {
    config: IpfsConfig,
    /// HTTP client for IPFS API
    client: reqwest::Client,
    /// CID to ref_id mappings
    mappings: Arc<RwLock<HashMap<String, CidMapping>>>,
    /// Ref_id to CID reverse mappings
    reverse_mappings: Arc<RwLock<HashMap<String, String>>>,
    /// Metadata storage
    metadata_store: Arc<RwLock<HashMap<String, PayloadMetadata>>>,
    /// Pin manager
    pin_manager: Arc<PinManager>,
}

impl IpfsBackend {
    /// Create a new IPFS backend
    pub async fn new(config: IpfsConfig) -> StorageResult<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|e| StorageError::Configuration(format!("HTTP client error: {}", e)))?;

        let pin_manager = Arc::new(PinManager::new(config.clone()));

        let backend = Self {
            config,
            client,
            mappings: Arc::new(RwLock::new(HashMap::new())),
            reverse_mappings: Arc::new(RwLock::new(HashMap::new())),
            metadata_store: Arc::new(RwLock::new(HashMap::new())),
            pin_manager,
        };

        // Verify connection
        backend.verify_connection().await?;

        info!(
            endpoint = %backend.config.api_endpoint,
            "IPFS backend initialized"
        );

        Ok(backend)
    }

    /// Verify IPFS connection
    async fn verify_connection(&self) -> StorageResult<()> {
        let url = format!("{}/api/v0/id", self.config.api_endpoint);

        self.client
            .post(&url)
            .send()
            .await
            .map_err(|e| StorageError::Unavailable(format!("IPFS connection failed: {}", e)))?
            .error_for_status()
            .map_err(|e| StorageError::Unavailable(format!("IPFS API error: {}", e)))?;

        Ok(())
    }

    /// Add content to IPFS
    async fn ipfs_add(&self, data: &[u8]) -> StorageResult<IpfsAddResponse> {
        let url = format!(
            "{}/api/v0/add?pin={}&cid-version=1",
            self.config.api_endpoint, self.config.auto_pin
        );

        let part = reqwest::multipart::Part::bytes(data.to_vec())
            .file_name("data");
        let form = reqwest::multipart::Form::new().part("file", part);

        let response = self
            .client
            .post(&url)
            .multipart(form)
            .send()
            .await
            .map_err(|e| StorageError::WriteFailed(format!("IPFS add failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(StorageError::WriteFailed(format!(
                "IPFS add failed: {} - {}",
                status, body
            )));
        }

        response
            .json::<IpfsAddResponse>()
            .await
            .map_err(|e| StorageError::WriteFailed(format!("Failed to parse IPFS response: {}", e)))
    }

    /// Get content from IPFS
    async fn ipfs_cat(&self, cid: &str) -> StorageResult<Vec<u8>> {
        // Try gateway first for better performance
        if let Some(gateway) = &self.config.gateway_endpoint {
            let url = format!("{}/ipfs/{}", gateway, cid);
            if let Ok(response) = self.client.get(&url).send().await {
                if response.status().is_success() {
                    if let Ok(bytes) = response.bytes().await {
                        return Ok(bytes.to_vec());
                    }
                }
            }
        }

        // Fall back to API
        let url = format!("{}/api/v0/cat?arg={}", self.config.api_endpoint, cid);

        let response = self
            .client
            .post(&url)
            .send()
            .await
            .map_err(|e| StorageError::ReadFailed(format!("IPFS cat failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(StorageError::NotFound(cid.to_string()));
        }

        response
            .bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| StorageError::ReadFailed(format!("Failed to read IPFS content: {}", e)))
    }

    /// Pin content on IPFS
    async fn ipfs_pin(&self, cid: &str) -> StorageResult<()> {
        let url = format!("{}/api/v0/pin/add?arg={}", self.config.api_endpoint, cid);

        let response = self
            .client
            .post(&url)
            .send()
            .await
            .map_err(|e| StorageError::OperationFailed(format!("IPFS pin failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(StorageError::OperationFailed(format!(
                "IPFS pin failed: {} - {}",
                status, body
            )));
        }

        Ok(())
    }

    /// Unpin content on IPFS
    async fn ipfs_unpin(&self, cid: &str) -> StorageResult<()> {
        let url = format!("{}/api/v0/pin/rm?arg={}", self.config.api_endpoint, cid);

        let response = self
            .client
            .post(&url)
            .send()
            .await
            .map_err(|e| StorageError::OperationFailed(format!("IPFS unpin failed: {}", e)))?;

        // Ignore errors for unpin (might not be pinned)
        if !response.status().is_success() {
            debug!(cid = %cid, "Content was not pinned");
        }

        Ok(())
    }

    /// Generate ref_id from content
    fn generate_ref_id(&self, data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(Utc::now().timestamp().to_le_bytes());
        format!("ipfs:{}", hex::encode(&hasher.finalize()[..16]))
    }

    /// Store CID mapping
    async fn store_mapping(&self, ref_id: &str, cid: &str, size: u64) {
        let mapping = CidMapping {
            cid: cid.to_string(),
            ref_id: ref_id.to_string(),
            cid_version: 1,
            size_bytes: size,
            created_at: Utc::now(),
        };

        self.mappings.write().await.insert(cid.to_string(), mapping);
        self.reverse_mappings
            .write()
            .await
            .insert(ref_id.to_string(), cid.to_string());
    }

    /// Get CID for ref_id
    async fn get_cid(&self, ref_id: &str) -> Option<String> {
        self.reverse_mappings.read().await.get(ref_id).cloned()
    }

    /// Get pin manager
    pub fn pin_manager(&self) -> Arc<PinManager> {
        self.pin_manager.clone()
    }
}

#[async_trait]
impl P2StorageBackend for IpfsBackend {
    async fn write(&self, data: &[u8], metadata: WriteMetadata) -> StorageResult<SealedPayloadRef> {
        let start = std::time::Instant::now();

        // Add to IPFS
        let add_response = self.ipfs_add(data).await?;
        let cid = add_response.hash;
        let size: u64 = add_response.size.parse().unwrap_or(data.len() as u64);

        // Generate ref_id and store mapping
        let ref_id = self.generate_ref_id(data);
        self.store_mapping(&ref_id, &cid, size).await;

        // Compute checksum
        let mut hasher = Sha256::new();
        hasher.update(data);
        let checksum_bytes = hasher.finalize();
        let checksum = hex::encode(&checksum_bytes);

        // Compute checksum as L0Digest (convert GenericArray to fixed array)
        let checksum_arr: [u8; 32] = checksum_bytes.into();
        let checksum_digest = L0Digest::new(checksum_arr);

        // Compute encryption_meta_digest using consistent format
        let encryption_meta_str = format!(
            "encryption:v1:key_version={}",
            metadata.encryption_key_version
        );
        let encryption_meta_digest = L0Digest::blake3(encryption_meta_str.as_bytes());

        // Store metadata
        let payload_metadata = PayloadMetadata {
            ref_id: ref_id.clone(),
            content_type: metadata.content_type.clone(),
            size_bytes: size,
            checksum: checksum.clone(),
            temperature: metadata.temperature,
            status: SealedPayloadStatus::Active,
            created_at: Utc::now(),
            last_accessed_at: None,
            encryption_key_version: metadata.encryption_key_version,
            owner_id: metadata.owner_id,
            tags: metadata.tags,
            encryption_meta_digest: Some(encryption_meta_digest.to_hex()),
        };
        self.metadata_store
            .write()
            .await
            .insert(ref_id.clone(), payload_metadata);

        // Update pin priority based on temperature
        let priority = match metadata.temperature {
            StorageTemperature::Hot => PinPriority::High,
            StorageTemperature::Warm => PinPriority::Medium,
            StorageTemperature::Cold => PinPriority::Low,
        };
        self.pin_manager.set_priority(&cid, priority).await;

        let duration = start.elapsed();
        info!(
            ref_id = %ref_id,
            cid = %cid,
            size = size,
            duration_ms = duration.as_millis(),
            "Wrote payload to IPFS"
        );

        // Create SealedPayloadRef using constructor
        let mut payload_ref = SealedPayloadRef::new(
            ref_id,
            checksum_digest,
            encryption_meta_digest,
            size,
        );
        payload_ref.set_temperature(metadata.temperature);
        payload_ref.content_type = Some(metadata.content_type);

        Ok(payload_ref)
    }

    async fn read(&self, ref_id: &str) -> StorageResult<Vec<u8>> {
        let cid = self
            .get_cid(ref_id)
            .await
            .ok_or_else(|| StorageError::NotFound(ref_id.to_string()))?;

        let data = self.ipfs_cat(&cid).await?;

        // Update last accessed
        if let Some(meta) = self.metadata_store.write().await.get_mut(ref_id) {
            meta.last_accessed_at = Some(Utc::now());
        }

        debug!(ref_id = %ref_id, cid = %cid, size = data.len(), "Read payload from IPFS");

        Ok(data)
    }

    async fn exists(&self, ref_id: &str) -> StorageResult<bool> {
        Ok(self.get_cid(ref_id).await.is_some())
    }

    async fn get_metadata(&self, ref_id: &str) -> StorageResult<PayloadMetadata> {
        self.metadata_store
            .read()
            .await
            .get(ref_id)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(ref_id.to_string()))
    }

    async fn tombstone(&self, ref_id: &str) -> StorageResult<()> {
        let cid = self
            .get_cid(ref_id)
            .await
            .ok_or_else(|| StorageError::NotFound(ref_id.to_string()))?;

        // Unpin the content (allows garbage collection)
        self.ipfs_unpin(&cid).await?;

        // Update status
        if let Some(meta) = self.metadata_store.write().await.get_mut(ref_id) {
            meta.status = SealedPayloadStatus::Tombstoned;
        }

        info!(ref_id = %ref_id, cid = %cid, "Tombstoned IPFS payload");

        Ok(())
    }

    async fn migrate_temperature(
        &self,
        ref_id: &str,
        target_temp: StorageTemperature,
    ) -> StorageResult<SealedPayloadRef> {
        let cid = self
            .get_cid(ref_id)
            .await
            .ok_or_else(|| StorageError::NotFound(ref_id.to_string()))?;

        // Update pin priority based on temperature
        let priority = match target_temp {
            StorageTemperature::Hot => PinPriority::High,
            StorageTemperature::Warm => PinPriority::Medium,
            StorageTemperature::Cold => PinPriority::Low,
        };
        self.pin_manager.set_priority(&cid, priority).await;

        // Update metadata
        let mut metadata_store = self.metadata_store.write().await;
        let meta = metadata_store
            .get_mut(ref_id)
            .ok_or_else(|| StorageError::NotFound(ref_id.to_string()))?;

        meta.temperature = target_temp;

        info!(
            ref_id = %ref_id,
            target_temp = ?target_temp,
            "Migrated IPFS payload temperature"
        );

        // Parse checksum from hex string to L0Digest
        let checksum_digest = L0Digest::from_hex(&meta.checksum)
            .map_err(|e| StorageError::OperationFailed(format!("Invalid checksum: {}", e)))?;

        // Compute encryption_meta_digest from encryption metadata
        let encryption_meta_digest = L0Digest::blake3(
            format!("enc:{}:{}", meta.encryption_key_version, target_temp.latency_description())
                .as_bytes()
        );

        let mut payload_ref = SealedPayloadRef::new(
            ref_id.to_string(),
            checksum_digest,
            encryption_meta_digest,
            meta.size_bytes,
        );
        payload_ref.set_temperature(target_temp);
        payload_ref.content_type = Some(meta.content_type.clone());

        Ok(payload_ref)
    }

    async fn verify_integrity(&self, ref_id: &str) -> StorageResult<IntegrityResult> {
        let meta = self.get_metadata(ref_id).await?;
        let data = self.read(ref_id).await?;

        let mut hasher = Sha256::new();
        hasher.update(&data);
        let actual_checksum = hex::encode(hasher.finalize());

        if actual_checksum == meta.checksum {
            Ok(IntegrityResult::pass(actual_checksum))
        } else {
            Ok(IntegrityResult::fail(meta.checksum, actual_checksum))
        }
    }

    fn backend_type(&self) -> BackendType {
        BackendType::Ipfs
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            supports_temperature: true,
            supports_streaming: true,
            supports_atomic_write: true,
            content_addressed: true,
            max_payload_size: Some(1024 * 1024 * 1024), // 1GB
            durability_nines: 11, // Very high with proper pinning
        }
    }

    async fn health_check(&self) -> StorageResult<HealthStatus> {
        match self.verify_connection().await {
            Ok(_) => Ok(HealthStatus::healthy()),
            Err(e) => Ok(HealthStatus::unhealthy(&e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipfs_config() {
        let config = IpfsConfig::default();
        assert!(config.auto_pin);
        assert!(config.use_local_node);
    }

    #[test]
    fn test_ipfs_config_remote() {
        let config = IpfsConfig::remote("http://ipfs.example.com:5001");
        assert!(!config.use_local_node);
        assert_eq!(config.api_endpoint, "http://ipfs.example.com:5001");
    }

    #[test]
    fn test_backend_capabilities() {
        let caps = BackendCapabilities {
            content_addressed: true,
            ..Default::default()
        };
        assert!(caps.content_addressed);
    }
}
