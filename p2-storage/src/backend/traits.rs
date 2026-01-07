//! P2 Storage Backend Traits
//!
//! Defines the interface for P2 storage backends.
//! Backends are replaceable - can use local filesystem, IPFS, S3, etc.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use p2_core::types::{SealedPayloadRef, SealedPayloadStatus, StorageTemperature};

use crate::error::{StorageError, StorageResult};

/// P2 Storage Backend Trait
///
/// All storage backends must implement this trait.
/// The interface is designed to be backend-agnostic.
#[async_trait]
pub trait P2StorageBackend: Send + Sync {
    /// Write encrypted payload to storage
    async fn write(&self, data: &[u8], metadata: WriteMetadata) -> StorageResult<SealedPayloadRef>;

    /// Read encrypted payload from storage
    async fn read(&self, ref_id: &str) -> StorageResult<Vec<u8>>;

    /// Check if a payload exists
    async fn exists(&self, ref_id: &str) -> StorageResult<bool>;

    /// Get payload metadata (without reading content)
    async fn get_metadata(&self, ref_id: &str) -> StorageResult<PayloadMetadata>;

    /// Tombstone a payload (right to be forgotten - soft delete)
    /// Preserves existence proof, removes content
    async fn tombstone(&self, ref_id: &str) -> StorageResult<()>;

    /// Migrate payload to a different temperature tier
    async fn migrate_temperature(
        &self,
        ref_id: &str,
        target_temp: StorageTemperature,
    ) -> StorageResult<SealedPayloadRef>;

    /// Verify payload integrity (recompute and compare checksum)
    async fn verify_integrity(&self, ref_id: &str) -> StorageResult<IntegrityResult>;

    /// Get backend type identifier
    fn backend_type(&self) -> BackendType;

    /// Get backend capabilities
    fn capabilities(&self) -> BackendCapabilities;

    /// Health check
    async fn health_check(&self) -> StorageResult<HealthStatus>;
}

/// Write metadata for new payloads
#[derive(Debug, Clone)]
pub struct WriteMetadata {
    /// Content type
    pub content_type: String,
    /// Encryption key version
    pub encryption_key_version: String,
    /// Target storage temperature
    pub temperature: StorageTemperature,
    /// Retention policy reference
    pub retention_policy_ref: Option<String>,
    /// Tags for organization
    pub tags: Vec<String>,
    /// Owner actor ID
    pub owner_id: Option<String>,
    /// Expected payload size (for routing decisions)
    pub expected_size: Option<u64>,
}

impl Default for WriteMetadata {
    fn default() -> Self {
        Self {
            content_type: "application/octet-stream".to_string(),
            encryption_key_version: "v1".to_string(),
            temperature: StorageTemperature::Hot,
            retention_policy_ref: None,
            tags: Vec::new(),
            owner_id: None,
            expected_size: None,
        }
    }
}

impl WriteMetadata {
    /// Create metadata for hot storage
    pub fn hot(content_type: &str) -> Self {
        Self {
            content_type: content_type.to_string(),
            temperature: StorageTemperature::Hot,
            ..Default::default()
        }
    }

    /// Create metadata for cold storage
    pub fn cold(content_type: &str) -> Self {
        Self {
            content_type: content_type.to_string(),
            temperature: StorageTemperature::Cold,
            ..Default::default()
        }
    }

    /// Set owner
    pub fn with_owner(mut self, owner_id: &str) -> Self {
        self.owner_id = Some(owner_id.to_string());
        self
    }

    /// Add tag
    pub fn with_tag(mut self, tag: &str) -> Self {
        self.tags.push(tag.to_string());
        self
    }
}

/// Payload metadata (without content)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PayloadMetadata {
    /// Reference ID
    pub ref_id: String,
    /// Content type
    pub content_type: String,
    /// Size in bytes
    pub size_bytes: u64,
    /// Checksum (hex encoded)
    pub checksum: String,
    /// Storage temperature
    pub temperature: StorageTemperature,
    /// Payload status
    pub status: SealedPayloadStatus,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Last accessed timestamp
    pub last_accessed_at: Option<DateTime<Utc>>,
    /// Encryption key version
    pub encryption_key_version: String,
    /// Owner actor ID
    pub owner_id: Option<String>,
    /// Tags
    pub tags: Vec<String>,
    /// Encryption metadata digest (hex encoded Blake3 hash)
    /// Used for integrity verification in SealedPayloadRef
    #[serde(default)]
    pub encryption_meta_digest: Option<String>,
}

impl PayloadMetadata {
    /// Compute or retrieve the encryption metadata digest
    ///
    /// Returns the stored digest if available, otherwise computes
    /// a deterministic digest from the encryption_key_version for
    /// backward compatibility with legacy data.
    pub fn get_encryption_meta_digest(&self) -> String {
        if let Some(ref digest) = self.encryption_meta_digest {
            digest.clone()
        } else {
            // Compute a deterministic digest from available encryption info
            // This maintains backward compatibility with legacy data
            use l0_core::types::Digest;
            let meta_str = format!(
                "encryption:v1:key_version={}",
                self.encryption_key_version
            );
            Digest::blake3(meta_str.as_bytes()).to_hex()
        }
    }
}

/// Backend type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendType {
    /// Local filesystem
    Local,
    /// IPFS
    Ipfs,
    /// S3-compatible object storage
    S3Compatible,
    /// S3 alias for routing
    S3,
    /// In-memory (testing only)
    Memory,
    /// Router (multi-backend)
    Router,
    /// Custom backend
    Custom,
}

impl Default for BackendType {
    fn default() -> Self {
        Self::Local
    }
}

impl BackendType {
    /// Get string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Ipfs => "ipfs",
            Self::S3Compatible => "s3_compatible",
            Self::S3 => "s3",
            Self::Memory => "memory",
            Self::Router => "router",
            Self::Custom => "custom",
        }
    }
}

impl std::fmt::Display for BackendType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Backend capabilities
#[derive(Debug, Clone)]
pub struct BackendCapabilities {
    /// Supports temperature tiers
    pub supports_temperature: bool,
    /// Supports streaming reads
    pub supports_streaming: bool,
    /// Supports atomic writes
    pub supports_atomic_write: bool,
    /// Supports content addressing
    pub content_addressed: bool,
    /// Maximum payload size (bytes)
    pub max_payload_size: Option<u64>,
    /// Estimated durability (nines, e.g., 11 = 99.999999999%)
    pub durability_nines: u8,
}

impl Default for BackendCapabilities {
    fn default() -> Self {
        Self {
            supports_temperature: true,
            supports_streaming: false,
            supports_atomic_write: true,
            content_addressed: false,
            max_payload_size: None,
            durability_nines: 9, // 99.9999999%
        }
    }
}

/// Integrity verification result
#[derive(Debug, Clone)]
pub struct IntegrityResult {
    /// Verification passed
    pub valid: bool,
    /// Expected checksum
    pub expected_checksum: String,
    /// Actual computed checksum
    pub actual_checksum: String,
    /// Verification timestamp
    pub verified_at: DateTime<Utc>,
    /// Additional details
    pub details: Option<String>,
}

impl IntegrityResult {
    /// Create a passing result
    pub fn pass(checksum: String) -> Self {
        Self {
            valid: true,
            expected_checksum: checksum.clone(),
            actual_checksum: checksum,
            verified_at: Utc::now(),
            details: None,
        }
    }

    /// Create a failing result
    pub fn fail(expected: String, actual: String) -> Self {
        Self {
            valid: false,
            expected_checksum: expected,
            actual_checksum: actual,
            verified_at: Utc::now(),
            details: Some("Checksum mismatch".to_string()),
        }
    }
}

/// Backend health status
#[derive(Debug, Clone)]
pub struct HealthStatus {
    /// Is healthy
    pub healthy: bool,
    /// Status message
    pub message: String,
    /// Available storage (bytes)
    pub available_bytes: Option<u64>,
    /// Used storage (bytes)
    pub used_bytes: Option<u64>,
    /// Check timestamp
    pub checked_at: DateTime<Utc>,
}

impl HealthStatus {
    /// Create healthy status
    pub fn healthy() -> Self {
        Self {
            healthy: true,
            message: "OK".to_string(),
            available_bytes: None,
            used_bytes: None,
            checked_at: Utc::now(),
        }
    }

    /// Create unhealthy status
    pub fn unhealthy(message: &str) -> Self {
        Self {
            healthy: false,
            message: message.to_string(),
            available_bytes: None,
            used_bytes: None,
            checked_at: Utc::now(),
        }
    }

    /// Create degraded status (partially healthy)
    pub fn degraded(message: &str) -> Self {
        Self {
            healthy: true, // Still operational
            message: message.to_string(),
            available_bytes: None,
            used_bytes: None,
            checked_at: Utc::now(),
        }
    }

    /// Check if status is healthy
    pub fn is_healthy(&self) -> bool {
        self.healthy
    }

    /// Get status message
    pub fn message(&self) -> &str {
        &self.message
    }
}

// ============================================================================
// Blanket implementation for Arc<T>
// ============================================================================

use std::sync::Arc;

/// Blanket implementation of P2StorageBackend for Arc<T>
/// This allows using Arc<LocalStorageBackend> directly in contexts requiring P2StorageBackend
#[async_trait]
impl<T: P2StorageBackend + ?Sized> P2StorageBackend for Arc<T> {
    async fn write(&self, data: &[u8], metadata: WriteMetadata) -> StorageResult<SealedPayloadRef> {
        (**self).write(data, metadata).await
    }

    async fn read(&self, ref_id: &str) -> StorageResult<Vec<u8>> {
        (**self).read(ref_id).await
    }

    async fn exists(&self, ref_id: &str) -> StorageResult<bool> {
        (**self).exists(ref_id).await
    }

    async fn get_metadata(&self, ref_id: &str) -> StorageResult<PayloadMetadata> {
        (**self).get_metadata(ref_id).await
    }

    async fn tombstone(&self, ref_id: &str) -> StorageResult<()> {
        (**self).tombstone(ref_id).await
    }

    async fn migrate_temperature(
        &self,
        ref_id: &str,
        target_temp: StorageTemperature,
    ) -> StorageResult<SealedPayloadRef> {
        (**self).migrate_temperature(ref_id, target_temp).await
    }

    async fn verify_integrity(&self, ref_id: &str) -> StorageResult<IntegrityResult> {
        (**self).verify_integrity(ref_id).await
    }

    fn backend_type(&self) -> BackendType {
        (**self).backend_type()
    }

    fn capabilities(&self) -> BackendCapabilities {
        (**self).capabilities()
    }

    async fn health_check(&self) -> StorageResult<HealthStatus> {
        (**self).health_check().await
    }
}
