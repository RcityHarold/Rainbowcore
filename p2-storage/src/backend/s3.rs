//! S3-Compatible Storage Backend
//!
//! Object storage backend supporting AWS S3, MinIO, and other S3-compatible services.
//!
//! # Important Security Note
//!
//! This implementation uses a simplified HTTP client without AWS Signature v4 signing.
//! It works well with:
//! - MinIO (with access key/secret in URL or environment)
//! - LocalStack
//! - Other S3-compatible services that support simple authentication
//!
//! For production AWS S3 usage with proper IAM authentication, consider:
//! 1. Using the `aws-sdk-s3` crate directly
//! 2. Running behind a proxy that handles signing
//! 3. Using pre-signed URLs

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use p2_core::types::{SealedPayloadRef, SealedPayloadStatus, StorageTemperature};
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use l0_core::types::Digest as L0Digest;

use crate::error::{StorageError, StorageResult};

use super::traits::{
    BackendCapabilities, BackendType, HealthStatus, IntegrityResult, P2StorageBackend,
    PayloadMetadata, WriteMetadata,
};

/// S3 Storage Class for temperature mapping
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum S3StorageClass {
    /// Standard - frequently accessed data
    Standard,
    /// Standard-IA - infrequently accessed data
    StandardIa,
    /// One Zone-IA - infrequently accessed, single AZ
    OneZoneIa,
    /// Intelligent-Tiering - automatic cost optimization
    IntelligentTiering,
    /// Glacier Instant Retrieval
    GlacierIr,
    /// Glacier Flexible Retrieval
    Glacier,
    /// Glacier Deep Archive
    GlacierDeepArchive,
}

impl S3StorageClass {
    /// Get AWS storage class string
    pub fn as_aws_str(&self) -> &'static str {
        match self {
            Self::Standard => "STANDARD",
            Self::StandardIa => "STANDARD_IA",
            Self::OneZoneIa => "ONEZONE_IA",
            Self::IntelligentTiering => "INTELLIGENT_TIERING",
            Self::GlacierIr => "GLACIER_IR",
            Self::Glacier => "GLACIER",
            Self::GlacierDeepArchive => "DEEP_ARCHIVE",
        }
    }

    /// Map from storage temperature
    pub fn from_temperature(temp: StorageTemperature) -> Self {
        match temp {
            StorageTemperature::Hot => Self::Standard,
            StorageTemperature::Warm => Self::StandardIa,
            StorageTemperature::Cold => Self::GlacierIr,
        }
    }

    /// Map to storage temperature
    pub fn to_temperature(&self) -> StorageTemperature {
        match self {
            Self::Standard | Self::IntelligentTiering => StorageTemperature::Hot,
            Self::StandardIa | Self::OneZoneIa => StorageTemperature::Warm,
            Self::GlacierIr | Self::Glacier | Self::GlacierDeepArchive => StorageTemperature::Cold,
        }
    }
}

impl Default for S3StorageClass {
    fn default() -> Self {
        Self::Standard
    }
}

/// S3 backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Config {
    /// S3 endpoint URL (for MinIO or other S3-compatible services)
    pub endpoint: Option<String>,
    /// AWS region
    pub region: String,
    /// Bucket name
    pub bucket: String,
    /// Key prefix for all objects
    pub key_prefix: String,
    /// Access key ID
    pub access_key_id: Option<String>,
    /// Secret access key
    pub secret_access_key: Option<String>,
    /// Use path-style addressing (required for MinIO)
    pub path_style: bool,
    /// Server-side encryption type
    pub server_side_encryption: Option<ServerSideEncryption>,
    /// Enable versioning
    pub enable_versioning: bool,
    /// Default storage class
    pub default_storage_class: S3StorageClass,
    /// Connection timeout in seconds
    pub timeout_secs: u64,
    /// Enable multipart upload for large files
    pub multipart_threshold_bytes: u64,
    /// Part size for multipart uploads
    pub multipart_part_size_bytes: u64,
}

impl Default for S3Config {
    fn default() -> Self {
        Self {
            endpoint: None,
            region: "us-east-1".to_string(),
            bucket: "p2-storage".to_string(),
            key_prefix: "payloads/".to_string(),
            access_key_id: None,
            secret_access_key: None,
            path_style: false,
            server_side_encryption: Some(ServerSideEncryption::Aes256),
            enable_versioning: true,
            default_storage_class: S3StorageClass::Standard,
            timeout_secs: 30,
            multipart_threshold_bytes: 100 * 1024 * 1024, // 100MB
            multipart_part_size_bytes: 10 * 1024 * 1024,  // 10MB
        }
    }
}

impl S3Config {
    /// Create config for AWS S3
    pub fn aws(region: &str, bucket: &str) -> Self {
        Self {
            region: region.to_string(),
            bucket: bucket.to_string(),
            ..Default::default()
        }
    }

    /// Create config for MinIO
    pub fn minio(endpoint: &str, bucket: &str) -> Self {
        Self {
            endpoint: Some(endpoint.to_string()),
            region: "us-east-1".to_string(), // MinIO uses this as default
            bucket: bucket.to_string(),
            path_style: true,
            server_side_encryption: None,
            ..Default::default()
        }
    }

    /// Create config with credentials
    pub fn with_credentials(mut self, access_key: &str, secret_key: &str) -> Self {
        self.access_key_id = Some(access_key.to_string());
        self.secret_access_key = Some(secret_key.to_string());
        self
    }
}

/// Server-side encryption options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerSideEncryption {
    /// AES-256 encryption (SSE-S3)
    Aes256,
    /// AWS KMS encryption (SSE-KMS)
    AwsKms { key_id: String },
    /// Customer-provided key (SSE-C)
    CustomerKey { algorithm: String },
}

/// S3 object metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3ObjectMeta {
    /// S3 key
    pub key: String,
    /// ETag (MD5 hash or multipart)
    pub etag: String,
    /// Content length
    pub content_length: u64,
    /// Storage class
    pub storage_class: S3StorageClass,
    /// Last modified
    pub last_modified: DateTime<Utc>,
    /// Version ID (if versioning enabled)
    pub version_id: Option<String>,
    /// Custom metadata
    pub metadata: HashMap<String, String>,
}

/// S3 Storage Backend
pub struct S3Backend {
    config: S3Config,
    /// HTTP client for S3 API
    client: reqwest::Client,
    /// Metadata cache
    metadata_cache: Arc<RwLock<HashMap<String, PayloadMetadata>>>,
    /// Key to ref_id mapping
    key_mapping: Arc<RwLock<HashMap<String, String>>>,
}

impl S3Backend {
    /// Create a new S3 backend
    pub async fn new(config: S3Config) -> StorageResult<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|e| StorageError::Configuration(format!("HTTP client error: {}", e)))?;

        let backend = Self {
            config,
            client,
            metadata_cache: Arc::new(RwLock::new(HashMap::new())),
            key_mapping: Arc::new(RwLock::new(HashMap::new())),
        };

        info!(
            bucket = %backend.config.bucket,
            region = %backend.config.region,
            "S3 backend initialized"
        );

        Ok(backend)
    }

    /// Generate S3 key from ref_id
    fn generate_key(&self, ref_id: &str) -> String {
        format!("{}{}", self.config.key_prefix, ref_id)
    }

    /// Generate ref_id from data
    fn generate_ref_id(&self, data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(Utc::now().timestamp().to_le_bytes());
        format!("s3:{}", hex::encode(&hasher.finalize()[..16]))
    }

    /// Get the S3 endpoint URL
    fn get_endpoint(&self) -> String {
        if let Some(endpoint) = &self.config.endpoint {
            endpoint.clone()
        } else {
            format!("https://s3.{}.amazonaws.com", self.config.region)
        }
    }

    /// Build URL for S3 object
    fn build_url(&self, key: &str) -> String {
        let endpoint = self.get_endpoint();
        if self.config.path_style {
            format!("{}/{}/{}", endpoint, self.config.bucket, key)
        } else {
            format!(
                "{}.{}/{}",
                self.config.bucket,
                endpoint.trim_start_matches("https://").trim_start_matches("http://"),
                key
            )
        }
    }

    /// Put object to S3-compatible storage
    ///
    /// # Note
    /// This uses a simplified HTTP PUT without AWS Signature v4 signing.
    /// Works with MinIO, LocalStack, and services that support basic auth.
    /// For AWS S3 with IAM, use `aws-sdk-s3` or pre-signed URLs.
    async fn put_object(
        &self,
        key: &str,
        data: &[u8],
        storage_class: S3StorageClass,
        content_type: &str,
    ) -> StorageResult<S3ObjectMeta> {
        let url = self.build_url(key);

        // Note: This is a simplified implementation suitable for MinIO/LocalStack.
        // For AWS S3 with proper IAM authentication, use aws-sdk-s3 or implement
        // AWS Signature v4 signing.
        let mut request = self.client.put(&url).body(data.to_vec());

        request = request.header("Content-Type", content_type);
        request = request.header("x-amz-storage-class", storage_class.as_aws_str());

        if let Some(sse) = &self.config.server_side_encryption {
            match sse {
                ServerSideEncryption::Aes256 => {
                    request = request.header("x-amz-server-side-encryption", "AES256");
                }
                ServerSideEncryption::AwsKms { key_id } => {
                    request = request.header("x-amz-server-side-encryption", "aws:kms");
                    request = request.header("x-amz-server-side-encryption-aws-kms-key-id", key_id);
                }
                ServerSideEncryption::CustomerKey { algorithm } => {
                    request = request.header("x-amz-server-side-encryption-customer-algorithm", algorithm);
                }
            }
        }

        let response = request
            .send()
            .await
            .map_err(|e| StorageError::WriteFailed(format!("S3 PUT failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(StorageError::WriteFailed(format!(
                "S3 PUT failed: {} - {}",
                status, body
            )));
        }

        let etag = response
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .trim_matches('"')
            .to_string();

        let version_id = response
            .headers()
            .get("x-amz-version-id")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        Ok(S3ObjectMeta {
            key: key.to_string(),
            etag,
            content_length: data.len() as u64,
            storage_class,
            last_modified: Utc::now(),
            version_id,
            metadata: HashMap::new(),
        })
    }

    /// Get object from S3 (simplified)
    async fn get_object(&self, key: &str) -> StorageResult<Vec<u8>> {
        let url = self.build_url(key);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| StorageError::ReadFailed(format!("S3 GET failed: {}", e)))?;

        if response.status().as_u16() == 404 {
            return Err(StorageError::NotFound(key.to_string()));
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(StorageError::ReadFailed(format!(
                "S3 GET failed: {} - {}",
                status, body
            )));
        }

        response
            .bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| StorageError::ReadFailed(format!("Failed to read S3 response: {}", e)))
    }

    /// Check if object exists
    async fn head_object(&self, key: &str) -> StorageResult<bool> {
        let url = self.build_url(key);

        let response = self
            .client
            .head(&url)
            .send()
            .await
            .map_err(|e| StorageError::OperationFailed(format!("S3 HEAD failed: {}", e)))?;

        Ok(response.status().is_success())
    }

    /// Delete object (for tombstone)
    async fn delete_object(&self, key: &str) -> StorageResult<()> {
        let url = self.build_url(key);

        let response = self
            .client
            .delete(&url)
            .send()
            .await
            .map_err(|e| StorageError::OperationFailed(format!("S3 DELETE failed: {}", e)))?;

        if !response.status().is_success() && response.status().as_u16() != 404 {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(StorageError::OperationFailed(format!(
                "S3 DELETE failed: {} - {}",
                status, body
            )));
        }

        Ok(())
    }

    /// Copy object with new storage class (for temperature migration)
    async fn copy_object(
        &self,
        source_key: &str,
        dest_key: &str,
        storage_class: S3StorageClass,
    ) -> StorageResult<()> {
        let url = self.build_url(dest_key);
        let copy_source = format!("{}/{}", self.config.bucket, source_key);

        let response = self
            .client
            .put(&url)
            .header("x-amz-copy-source", &copy_source)
            .header("x-amz-storage-class", storage_class.as_aws_str())
            .header("x-amz-metadata-directive", "COPY")
            .send()
            .await
            .map_err(|e| StorageError::OperationFailed(format!("S3 COPY failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(StorageError::OperationFailed(format!(
                "S3 COPY failed: {} - {}",
                status, body
            )));
        }

        Ok(())
    }

    /// Get storage class for a key
    pub fn get_storage_class_for_temperature(&self, temp: StorageTemperature) -> S3StorageClass {
        S3StorageClass::from_temperature(temp)
    }
}

#[async_trait]
impl P2StorageBackend for S3Backend {
    async fn write(&self, data: &[u8], metadata: WriteMetadata) -> StorageResult<SealedPayloadRef> {
        let start = std::time::Instant::now();

        // Generate ref_id and key
        let ref_id = self.generate_ref_id(data);
        let key = self.generate_key(&ref_id);

        // Determine storage class from temperature
        let storage_class = S3StorageClass::from_temperature(metadata.temperature);

        // Put object to S3
        let s3_meta = self
            .put_object(&key, data, storage_class, &metadata.content_type)
            .await?;

        // Compute checksum
        let mut hasher = Sha256::new();
        hasher.update(data);
        let checksum_bytes = hasher.finalize();
        let checksum = hex::encode(&checksum_bytes);
        let checksum_arr: [u8; 32] = checksum_bytes.into();
        let checksum_digest = L0Digest::new(checksum_arr);

        // Compute encryption metadata digest from key version
        let encryption_meta_str = format!(
            "encryption:v1:key_version={}",
            metadata.encryption_key_version
        );
        let encryption_meta_digest = L0Digest::blake3(encryption_meta_str.as_bytes());

        // Store metadata
        let payload_metadata = PayloadMetadata {
            ref_id: ref_id.clone(),
            content_type: metadata.content_type.clone(),
            size_bytes: data.len() as u64,
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

        self.metadata_cache
            .write()
            .await
            .insert(ref_id.clone(), payload_metadata);

        self.key_mapping
            .write()
            .await
            .insert(ref_id.clone(), key.clone());

        let duration = start.elapsed();
        info!(
            ref_id = %ref_id,
            key = %key,
            size = data.len(),
            storage_class = ?storage_class,
            duration_ms = duration.as_millis(),
            "Wrote payload to S3"
        );

        // Create SealedPayloadRef
        let mut payload_ref = SealedPayloadRef::new(
            ref_id,
            checksum_digest,
            encryption_meta_digest,
            data.len() as u64,
        );
        payload_ref.set_temperature(metadata.temperature);
        payload_ref.content_type = Some(metadata.content_type);

        Ok(payload_ref)
    }

    async fn read(&self, ref_id: &str) -> StorageResult<Vec<u8>> {
        let key = self.generate_key(ref_id);

        let data = self.get_object(&key).await?;

        // Update last accessed
        if let Some(meta) = self.metadata_cache.write().await.get_mut(ref_id) {
            meta.last_accessed_at = Some(Utc::now());
        }

        debug!(
            ref_id = %ref_id,
            key = %key,
            size = data.len(),
            "Read payload from S3"
        );

        Ok(data)
    }

    async fn exists(&self, ref_id: &str) -> StorageResult<bool> {
        let key = self.generate_key(ref_id);
        self.head_object(&key).await
    }

    async fn get_metadata(&self, ref_id: &str) -> StorageResult<PayloadMetadata> {
        self.metadata_cache
            .read()
            .await
            .get(ref_id)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(ref_id.to_string()))
    }

    async fn tombstone(&self, ref_id: &str) -> StorageResult<()> {
        let key = self.generate_key(ref_id);

        // In S3, we can either delete or add a delete marker (with versioning)
        // For P2, we mark as tombstoned but keep for audit
        if let Some(meta) = self.metadata_cache.write().await.get_mut(ref_id) {
            meta.status = SealedPayloadStatus::Tombstoned;
        }

        // Optionally delete the actual object
        // self.delete_object(&key).await?;

        info!(ref_id = %ref_id, key = %key, "Tombstoned S3 payload");

        Ok(())
    }

    async fn migrate_temperature(
        &self,
        ref_id: &str,
        target_temp: StorageTemperature,
    ) -> StorageResult<SealedPayloadRef> {
        let key = self.generate_key(ref_id);
        let target_class = S3StorageClass::from_temperature(target_temp);

        // Copy object to same location with new storage class
        self.copy_object(&key, &key, target_class).await?;

        // Update metadata
        let mut metadata_cache = self.metadata_cache.write().await;
        let meta = metadata_cache
            .get_mut(ref_id)
            .ok_or_else(|| StorageError::NotFound(ref_id.to_string()))?;

        meta.temperature = target_temp;

        info!(
            ref_id = %ref_id,
            target_temp = ?target_temp,
            storage_class = ?target_class,
            "Migrated S3 payload temperature"
        );

        // Create SealedPayloadRef
        let checksum_digest = L0Digest::from_hex(&meta.checksum)
            .map_err(|e| StorageError::OperationFailed(format!("Invalid checksum: {}", e)))?;

        // Get or compute encryption metadata digest
        let encryption_meta_digest = L0Digest::from_hex(&meta.get_encryption_meta_digest())
            .map_err(|e| StorageError::OperationFailed(format!("Invalid encryption meta digest: {}", e)))?;

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
        BackendType::S3
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            supports_temperature: true,
            supports_streaming: true,
            supports_atomic_write: true,
            content_addressed: false,
            max_payload_size: Some(5 * 1024 * 1024 * 1024 * 1024), // 5TB per object
            durability_nines: 11, // S3 provides 11 nines durability
        }
    }

    async fn health_check(&self) -> StorageResult<HealthStatus> {
        // Try to list bucket or head bucket
        let endpoint = self.get_endpoint();
        let url = if self.config.path_style {
            format!("{}/{}", endpoint, self.config.bucket)
        } else {
            format!(
                "{}.{}",
                self.config.bucket,
                endpoint.trim_start_matches("https://").trim_start_matches("http://")
            )
        };

        match self.client.head(&url).send().await {
            Ok(response) if response.status().is_success() => Ok(HealthStatus::healthy()),
            Ok(response) => Ok(HealthStatus::unhealthy(&format!(
                "S3 returned status {}",
                response.status()
            ))),
            Err(e) => Ok(HealthStatus::unhealthy(&format!("S3 connection failed: {}", e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_s3_config_default() {
        let config = S3Config::default();
        assert_eq!(config.region, "us-east-1");
        assert!(!config.path_style);
    }

    #[test]
    fn test_s3_config_minio() {
        let config = S3Config::minio("http://localhost:9000", "test-bucket");
        assert!(config.path_style);
        assert_eq!(config.endpoint, Some("http://localhost:9000".to_string()));
    }

    #[test]
    fn test_storage_class_mapping() {
        assert_eq!(
            S3StorageClass::from_temperature(StorageTemperature::Hot),
            S3StorageClass::Standard
        );
        assert_eq!(
            S3StorageClass::from_temperature(StorageTemperature::Warm),
            S3StorageClass::StandardIa
        );
        assert_eq!(
            S3StorageClass::from_temperature(StorageTemperature::Cold),
            S3StorageClass::GlacierIr
        );
    }

    #[test]
    fn test_storage_class_to_temperature() {
        assert_eq!(
            S3StorageClass::Standard.to_temperature(),
            StorageTemperature::Hot
        );
        assert_eq!(
            S3StorageClass::Glacier.to_temperature(),
            StorageTemperature::Cold
        );
    }
}
