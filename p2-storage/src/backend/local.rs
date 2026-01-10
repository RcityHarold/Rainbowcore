//! Local Filesystem Storage Backend
//!
//! Implements P2StorageBackend using the local filesystem.
//! Suitable for development, testing, and single-node deployments.

use async_trait::async_trait;
use chrono::Utc;
use l0_core::types::Digest;
use p2_core::types::{SealedPayloadRef, SealedPayloadStatus, StorageTemperature};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};

use super::traits::{
    BackendCapabilities, BackendType, HealthStatus, IntegrityResult, P2StorageBackend,
    PayloadMetadata, WriteMetadata,
};
use crate::error::{StorageError, StorageResult};

/// Local filesystem storage backend
pub struct LocalStorageBackend {
    /// Base directory for storage
    base_path: PathBuf,
    /// Hot storage subdirectory
    hot_path: PathBuf,
    /// Warm storage subdirectory
    warm_path: PathBuf,
    /// Cold storage subdirectory
    cold_path: PathBuf,
    /// Metadata subdirectory
    meta_path: PathBuf,
}

impl LocalStorageBackend {
    /// Create a new local storage backend
    pub async fn new(base_path: impl AsRef<Path>) -> StorageResult<Self> {
        let base_path = base_path.as_ref().to_path_buf();
        let hot_path = base_path.join("hot");
        let warm_path = base_path.join("warm");
        let cold_path = base_path.join("cold");
        let meta_path = base_path.join("meta");

        // Create directories
        for path in [&base_path, &hot_path, &warm_path, &cold_path, &meta_path] {
            fs::create_dir_all(path).await.map_err(|e| {
                StorageError::Backend(format!("Failed to create directory {:?}: {}", path, e))
            })?;
        }

        info!("Initialized local storage backend at {:?}", base_path);

        Ok(Self {
            base_path,
            hot_path,
            warm_path,
            cold_path,
            meta_path,
        })
    }

    /// Get the storage path for a temperature tier
    fn get_temp_path(&self, temp: StorageTemperature) -> &PathBuf {
        match temp {
            StorageTemperature::Hot => &self.hot_path,
            StorageTemperature::Warm => &self.warm_path,
            StorageTemperature::Cold => &self.cold_path,
        }
    }

    /// Get the data file path for a reference
    fn get_data_path(&self, ref_id: &str, temp: StorageTemperature) -> PathBuf {
        self.get_temp_path(temp).join(format!("{}.dat", ref_id))
    }

    /// Get the metadata file path for a reference
    fn get_meta_path(&self, ref_id: &str) -> PathBuf {
        self.meta_path.join(format!("{}.json", ref_id))
    }

    /// Generate a unique reference ID
    fn generate_ref_id(&self, checksum: &Digest) -> String {
        format!("local:{}", &checksum.to_hex()[..32])
    }

    /// Save metadata to file
    async fn save_metadata(&self, ref_id: &str, meta: &PayloadMetadata) -> StorageResult<()> {
        let path = self.get_meta_path(ref_id);
        let json = serde_json::to_string_pretty(meta).map_err(|e| {
            StorageError::Backend(format!("Failed to serialize metadata: {}", e))
        })?;

        fs::write(&path, json).await.map_err(|e| {
            StorageError::Backend(format!("Failed to write metadata: {}", e))
        })?;

        Ok(())
    }

    /// Load metadata from file
    async fn load_metadata(&self, ref_id: &str) -> StorageResult<PayloadMetadata> {
        let path = self.get_meta_path(ref_id);

        if !path.exists() {
            return Err(StorageError::NotFound(ref_id.to_string()));
        }

        let json = fs::read_to_string(&path).await.map_err(|e| {
            StorageError::Backend(format!("Failed to read metadata: {}", e))
        })?;

        serde_json::from_str(&json).map_err(|e| {
            StorageError::Backend(format!("Failed to parse metadata: {}", e))
        })
    }

    /// Find which temperature tier contains a payload
    async fn find_payload_temp(&self, ref_id: &str) -> StorageResult<StorageTemperature> {
        for temp in [StorageTemperature::Hot, StorageTemperature::Warm, StorageTemperature::Cold] {
            let path = self.get_data_path(ref_id, temp);
            if path.exists() {
                return Ok(temp);
            }
        }
        Err(StorageError::NotFound(ref_id.to_string()))
    }
}

#[async_trait]
impl P2StorageBackend for LocalStorageBackend {
    async fn write(&self, data: &[u8], metadata: WriteMetadata) -> StorageResult<SealedPayloadRef> {
        // Compute checksum
        let checksum = Digest::blake3(data);
        let ref_id = self.generate_ref_id(&checksum);

        debug!("Writing payload {} ({} bytes)", ref_id, data.len());

        // APPEND-ONLY INVARIANT: Check if payload already exists
        // With content-addressed storage, same ref_id means same content
        let data_path = self.get_data_path(&ref_id, metadata.temperature);
        if data_path.exists() {
            // Payload already exists - verify checksum matches (idempotent write)
            let existing_data = fs::read(&data_path).await.map_err(|e| {
                StorageError::ReadFailed(format!("Failed to read existing file: {}", e))
            })?;
            let existing_checksum = Digest::blake3(&existing_data);
            if existing_checksum == checksum {
                debug!("Payload {} already exists with matching checksum, returning existing", ref_id);
                // Return the existing reference (idempotent)
                if let Ok(existing_meta) = self.load_metadata(&ref_id).await {
                    let encryption_meta_digest = Digest::blake3(
                        format!("enc:{}:{}", existing_meta.encryption_key_version, existing_meta.temperature.latency_description())
                            .as_bytes()
                    );
                    return Ok(SealedPayloadRef::new(
                        ref_id,
                        checksum,
                        encryption_meta_digest,
                        data.len() as u64,
                    ));
                }
            } else {
                // Different content with same ref_id - this should never happen with proper hashing
                return Err(StorageError::WriteFailed(
                    format!("CRITICAL: Hash collision detected for ref_id {}", ref_id)
                ));
            }
        }

        // Create parent directory if needed
        if let Some(parent) = data_path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                StorageError::WriteFailed(format!("Failed to create directory: {}", e))
            })?;
        }

        // Write data file (new file only - checked above)
        let mut file = fs::File::create(&data_path).await.map_err(|e| {
            StorageError::WriteFailed(format!("Failed to create file: {}", e))
        })?;
        file.write_all(data).await.map_err(|e| {
            StorageError::WriteFailed(format!("Failed to write data: {}", e))
        })?;
        file.sync_all().await.map_err(|e| {
            StorageError::WriteFailed(format!("Failed to sync file: {}", e))
        })?;

        // Create and save metadata
        let now = Utc::now();

        // Compute encryption metadata digest using consistent format
        let encryption_meta_str = format!(
            "encryption:v1:key_version={}",
            metadata.encryption_key_version
        );
        let encryption_meta_digest = Digest::blake3(encryption_meta_str.as_bytes());

        let payload_meta = PayloadMetadata {
            ref_id: ref_id.clone(),
            content_type: metadata.content_type,
            size_bytes: data.len() as u64,
            checksum: checksum.to_hex(),
            temperature: metadata.temperature,
            status: SealedPayloadStatus::Active,
            created_at: now,
            last_accessed_at: None,
            encryption_key_version: metadata.encryption_key_version,
            owner_id: metadata.owner_id,
            tags: metadata.tags,
            encryption_meta_digest: Some(encryption_meta_digest.to_hex()),
        };
        self.save_metadata(&ref_id, &payload_meta).await?;

        // Create SealedPayloadRef (use the same digest computed above)

        let payload_ref = SealedPayloadRef {
            ref_id: ref_id.clone(),
            checksum,
            encryption_meta_digest,
            access_policy_version: "v1".to_string(),
            format_version: p2_core::types::PayloadFormatVersion::current(),
            size_bytes: data.len() as u64,
            status: SealedPayloadStatus::Active,
            temperature: metadata.temperature,
            created_at: now,
            last_accessed_at: None,
            content_type: Some(payload_meta.content_type.clone()),
            retention_policy_ref: metadata.retention_policy_ref,
        };

        info!("Stored payload {} ({} bytes, {:?})", ref_id, data.len(), metadata.temperature);
        Ok(payload_ref)
    }

    async fn read(&self, ref_id: &str) -> StorageResult<Vec<u8>> {
        debug!("Reading payload {}", ref_id);

        // Find the temperature tier
        let temp = self.find_payload_temp(ref_id).await?;
        let data_path = self.get_data_path(ref_id, temp);

        // Read data
        let data = fs::read(&data_path).await.map_err(|e| {
            StorageError::ReadFailed(format!("Failed to read file: {}", e))
        })?;

        // Update last accessed time
        let mut meta = self.load_metadata(ref_id).await?;
        meta.last_accessed_at = Some(Utc::now());
        self.save_metadata(ref_id, &meta).await?;

        debug!("Read {} bytes from {}", data.len(), ref_id);
        Ok(data)
    }

    async fn exists(&self, ref_id: &str) -> StorageResult<bool> {
        let meta_path = self.get_meta_path(ref_id);
        Ok(meta_path.exists())
    }

    async fn get_metadata(&self, ref_id: &str) -> StorageResult<PayloadMetadata> {
        self.load_metadata(ref_id).await
    }

    async fn tombstone(&self, ref_id: &str) -> StorageResult<()> {
        debug!("Tombstoning payload {}", ref_id);

        // Update metadata status
        let mut meta = self.load_metadata(ref_id).await?;
        meta.status = SealedPayloadStatus::Tombstoned;
        self.save_metadata(ref_id, &meta).await?;

        // Optionally remove the data file (keeping metadata for existence proof)
        let temp = self.find_payload_temp(ref_id).await?;
        let data_path = self.get_data_path(ref_id, temp);
        if data_path.exists() {
            fs::remove_file(&data_path).await.map_err(|e| {
                StorageError::Backend(format!("Failed to remove data file: {}", e))
            })?;
        }

        info!("Tombstoned payload {}", ref_id);
        Ok(())
    }

    async fn migrate_temperature(
        &self,
        ref_id: &str,
        target_temp: StorageTemperature,
    ) -> StorageResult<SealedPayloadRef> {
        debug!("Migrating {} to {:?}", ref_id, target_temp);

        // Read current data
        let data = self.read(ref_id).await?;
        let mut meta = self.load_metadata(ref_id).await?;

        // Get current temperature and move file
        let current_temp = meta.temperature;
        if current_temp == target_temp {
            return Err(StorageError::Backend("Already at target temperature".to_string()));
        }

        let old_path = self.get_data_path(ref_id, current_temp);
        let new_path = self.get_data_path(ref_id, target_temp);

        // Write to new location
        fs::write(&new_path, &data).await.map_err(|e| {
            StorageError::Backend(format!("Failed to write to new location: {}", e))
        })?;

        // Remove old file
        fs::remove_file(&old_path).await.map_err(|e| {
            StorageError::Backend(format!("Failed to remove old file: {}", e))
        })?;

        // Update metadata
        meta.temperature = target_temp;
        self.save_metadata(ref_id, &meta).await?;

        info!("Migrated {} from {:?} to {:?}", ref_id, current_temp, target_temp);

        // Compute encryption_meta_digest from encryption metadata
        let encryption_meta_digest = Digest::blake3(
            format!("enc:{}:{}", meta.encryption_key_version, target_temp.latency_description())
                .as_bytes()
        );

        // Return updated ref
        Ok(SealedPayloadRef {
            ref_id: ref_id.to_string(),
            checksum: Digest::from_hex(&meta.checksum).unwrap_or_default(),
            encryption_meta_digest,
            access_policy_version: "v1".to_string(),
            format_version: p2_core::types::PayloadFormatVersion::current(),
            size_bytes: meta.size_bytes,
            status: meta.status,
            temperature: target_temp,
            created_at: meta.created_at,
            last_accessed_at: meta.last_accessed_at,
            content_type: Some(meta.content_type),
            retention_policy_ref: None,
        })
    }

    async fn verify_integrity(&self, ref_id: &str) -> StorageResult<IntegrityResult> {
        debug!("Verifying integrity of {}", ref_id);

        let meta = self.load_metadata(ref_id).await?;

        if meta.status == SealedPayloadStatus::Tombstoned {
            return Ok(IntegrityResult {
                valid: true,
                expected_checksum: meta.checksum.clone(),
                actual_checksum: "tombstoned".to_string(),
                verified_at: Utc::now(),
                details: Some("Payload tombstoned, data removed".to_string()),
            });
        }

        let data = self.read(ref_id).await?;
        let actual_checksum = Digest::blake3(&data);

        if actual_checksum.to_hex() == meta.checksum {
            Ok(IntegrityResult::pass(meta.checksum))
        } else {
            warn!("Integrity check failed for {}", ref_id);
            Ok(IntegrityResult::fail(meta.checksum, actual_checksum.to_hex()))
        }
    }

    fn backend_type(&self) -> BackendType {
        BackendType::Local
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            supports_temperature: true,
            supports_streaming: false,
            supports_atomic_write: true,
            content_addressed: false,
            max_payload_size: None,
            durability_nines: 6, // Single disk, no redundancy
        }
    }

    async fn health_check(&self) -> StorageResult<HealthStatus> {
        // Check if base directory is accessible
        if !self.base_path.exists() {
            return Ok(HealthStatus::unhealthy("Base path does not exist"));
        }

        // Try to write and read a test file
        let test_path = self.base_path.join(".health_check");
        let test_data = b"health_check";

        match fs::write(&test_path, test_data).await {
            Ok(_) => {
                let _ = fs::remove_file(&test_path).await;
                Ok(HealthStatus::healthy())
            }
            Err(e) => Ok(HealthStatus::unhealthy(&format!("Write test failed: {}", e))),
        }
    }
}

// Note: Serialize/Deserialize for PayloadMetadata is now derived in traits.rs
// This allows the encryption_meta_digest field to be properly handled

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn create_test_backend() -> (LocalStorageBackend, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path()).await.unwrap();
        (backend, temp_dir)
    }

    #[tokio::test]
    async fn test_write_and_read() {
        let (backend, _temp_dir) = create_test_backend().await;

        let data = b"Hello, P2 Storage!";
        let metadata = WriteMetadata::hot("text/plain");

        let payload_ref = backend.write(data, metadata).await.unwrap();
        assert!(!payload_ref.ref_id.is_empty());
        assert_eq!(payload_ref.size_bytes, data.len() as u64);

        let read_data = backend.read(&payload_ref.ref_id).await.unwrap();
        assert_eq!(read_data, data);
    }

    #[tokio::test]
    async fn test_exists() {
        let (backend, _temp_dir) = create_test_backend().await;

        let payload_ref = backend
            .write(b"test", WriteMetadata::default())
            .await
            .unwrap();

        assert!(backend.exists(&payload_ref.ref_id).await.unwrap());
        assert!(!backend.exists("nonexistent").await.unwrap());
    }

    #[tokio::test]
    async fn test_tombstone() {
        let (backend, _temp_dir) = create_test_backend().await;

        let payload_ref = backend
            .write(b"secret data", WriteMetadata::default())
            .await
            .unwrap();

        backend.tombstone(&payload_ref.ref_id).await.unwrap();

        let meta = backend.get_metadata(&payload_ref.ref_id).await.unwrap();
        assert_eq!(meta.status, SealedPayloadStatus::Tombstoned);

        // Data should be gone
        assert!(backend.read(&payload_ref.ref_id).await.is_err());
    }

    #[tokio::test]
    async fn test_temperature_migration() {
        let (backend, _temp_dir) = create_test_backend().await;

        let data = b"migrate me";
        let metadata = WriteMetadata::hot("application/octet-stream");

        let payload_ref = backend.write(data, metadata).await.unwrap();
        assert_eq!(payload_ref.temperature, StorageTemperature::Hot);

        let migrated = backend
            .migrate_temperature(&payload_ref.ref_id, StorageTemperature::Cold)
            .await
            .unwrap();
        assert_eq!(migrated.temperature, StorageTemperature::Cold);

        // Data should still be readable
        let read_data = backend.read(&payload_ref.ref_id).await.unwrap();
        assert_eq!(read_data, data);
    }

    #[tokio::test]
    async fn test_integrity_verification() {
        let (backend, _temp_dir) = create_test_backend().await;

        let data = b"verify me";
        let payload_ref = backend
            .write(data, WriteMetadata::default())
            .await
            .unwrap();

        let result = backend.verify_integrity(&payload_ref.ref_id).await.unwrap();
        assert!(result.valid);
    }

    #[tokio::test]
    async fn test_health_check() {
        let (backend, _temp_dir) = create_test_backend().await;

        let status = backend.health_check().await.unwrap();
        assert!(status.healthy);
    }
}
