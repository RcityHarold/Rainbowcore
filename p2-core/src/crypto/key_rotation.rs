//! Key Rotation Module
//!
//! Provides secure key rotation and versioning for P2 encryption.
//!
//! # Features
//!
//! - Version-based key management
//! - Automatic key rotation scheduling
//! - Old key archival and expiration
//! - Re-encryption support for key migration
//!
//! # Key Lifecycle
//!
//! ```text
//! Active → Deprecated → Archived → Destroyed
//! ```

use std::collections::HashMap;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::error::{P2Error, P2Result};
use super::kdf::KeyContext;

/// Key version identifier
pub type KeyVersion = String;

/// Key status in lifecycle
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStatus {
    /// Key is active and can be used for encryption/decryption
    Active,
    /// Key is deprecated - can decrypt but not encrypt
    Deprecated,
    /// Key is archived - can decrypt with special permission
    Archived,
    /// Key material has been destroyed
    Destroyed,
}

impl KeyStatus {
    /// Check if key can be used for encryption
    pub fn can_encrypt(&self) -> bool {
        matches!(self, KeyStatus::Active)
    }

    /// Check if key can be used for decryption
    pub fn can_decrypt(&self) -> bool {
        matches!(self, KeyStatus::Active | KeyStatus::Deprecated | KeyStatus::Archived)
    }
}

/// Key type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    /// Key Encryption Key (KEK) - encrypts DEKs
    Kek,
    /// Data Encryption Key (DEK) - encrypts payload data
    Dek,
    /// Master Key - root of key hierarchy
    Master,
    /// Signing Key
    Signing,
}

/// Key metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Key version identifier
    pub version: KeyVersion,
    /// Key type
    pub key_type: KeyType,
    /// Key status
    pub status: KeyStatus,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Activation timestamp
    pub activated_at: Option<DateTime<Utc>>,
    /// Deprecation timestamp
    pub deprecated_at: Option<DateTime<Utc>>,
    /// Expiration timestamp
    pub expires_at: Option<DateTime<Utc>>,
    /// Key algorithm
    pub algorithm: String,
    /// Key size in bits
    pub key_size: u32,
    /// Creator/owner
    pub owner: String,
    /// Purpose description
    pub purpose: String,
    /// Parent key version (for derived keys)
    pub parent_version: Option<KeyVersion>,
    /// Custom labels
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

impl KeyMetadata {
    /// Create new key metadata
    pub fn new(version: KeyVersion, key_type: KeyType, algorithm: &str, key_size: u32) -> Self {
        Self {
            version,
            key_type,
            status: KeyStatus::Active,
            created_at: Utc::now(),
            activated_at: Some(Utc::now()),
            deprecated_at: None,
            expires_at: None,
            algorithm: algorithm.to_string(),
            key_size,
            owner: "system".to_string(),
            purpose: String::new(),
            parent_version: None,
            labels: HashMap::new(),
        }
    }

    /// Set expiration
    pub fn with_expiration(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Set purpose
    pub fn with_purpose(mut self, purpose: &str) -> Self {
        self.purpose = purpose.to_string();
        self
    }

    /// Set owner
    pub fn with_owner(mut self, owner: &str) -> Self {
        self.owner = owner.to_string();
        self
    }

    /// Check if key is expired
    pub fn is_expired(&self) -> bool {
        self.expires_at.map(|exp| Utc::now() > exp).unwrap_or(false)
    }

    /// Deprecate the key
    pub fn deprecate(&mut self) {
        self.status = KeyStatus::Deprecated;
        self.deprecated_at = Some(Utc::now());
    }

    /// Archive the key
    pub fn archive(&mut self) {
        self.status = KeyStatus::Archived;
    }
}

/// Key rotation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationConfig {
    /// Enable automatic rotation
    pub auto_rotate: bool,
    /// Rotation interval
    pub rotation_interval_days: u32,
    /// Grace period for old keys (days)
    pub grace_period_days: u32,
    /// Archive retention period (days)
    pub archive_retention_days: u32,
    /// Minimum number of active keys to maintain
    pub min_active_keys: usize,
    /// Alert before expiration (days)
    pub alert_before_expiry_days: u32,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            auto_rotate: true,
            rotation_interval_days: 90,
            grace_period_days: 30,
            archive_retention_days: 365,
            min_active_keys: 1,
            alert_before_expiry_days: 14,
        }
    }
}

/// Key entry with material and metadata
struct KeyEntry {
    /// Key material (encrypted or plaintext depending on implementation)
    material: Vec<u8>,
    /// Key metadata
    metadata: KeyMetadata,
}

/// Key Manager for rotation and versioning
pub struct KeyManager {
    /// Keys indexed by version
    keys: RwLock<HashMap<KeyVersion, KeyEntry>>,
    /// Current active key version for each key type
    active_versions: RwLock<HashMap<KeyType, KeyVersion>>,
    /// Rotation configuration
    config: RotationConfig,
    /// Key derivation context
    kdf_context: Option<KeyContext>,
}

impl KeyManager {
    /// Create a new key manager
    pub fn new(config: RotationConfig) -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            active_versions: RwLock::new(HashMap::new()),
            config,
            kdf_context: None,
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(RotationConfig::default())
    }

    /// Initialize with master key
    pub fn with_master_key(mut self, master_key: &[u8], salt: &[u8]) -> Self {
        self.kdf_context = Some(KeyContext::new(master_key, salt));
        self
    }

    /// Register a new key
    pub async fn register_key(
        &self,
        version: KeyVersion,
        key_type: KeyType,
        material: Vec<u8>,
        metadata: KeyMetadata,
    ) -> P2Result<()> {
        let mut keys = self.keys.write().await;

        if keys.contains_key(&version) {
            return Err(P2Error::Validation(format!(
                "Key version {} already exists",
                version
            )));
        }

        keys.insert(version.clone(), KeyEntry { material, metadata });

        // Set as active if no active key for this type
        let mut active = self.active_versions.write().await;
        if !active.contains_key(&key_type) {
            active.insert(key_type, version);
        }

        Ok(())
    }

    /// Get key material by version
    pub async fn get_key(&self, version: &KeyVersion) -> P2Result<Vec<u8>> {
        let keys = self.keys.read().await;

        let entry = keys.get(version).ok_or_else(|| {
            P2Error::Encryption(format!("Key version {} not found", version))
        })?;

        if !entry.metadata.status.can_decrypt() {
            return Err(P2Error::Encryption(format!(
                "Key {} cannot be used for decryption (status: {:?})",
                version, entry.metadata.status
            )));
        }

        if entry.metadata.is_expired() {
            return Err(P2Error::Encryption(format!("Key {} is expired", version)));
        }

        Ok(entry.material.clone())
    }

    /// Get current active key for encryption
    pub async fn get_active_key(&self, key_type: KeyType) -> P2Result<(KeyVersion, Vec<u8>)> {
        let active = self.active_versions.read().await;

        let version = active.get(&key_type).ok_or_else(|| {
            P2Error::Encryption(format!("No active key for type {:?}", key_type))
        })?;

        let material = self.get_key(version).await?;
        Ok((version.clone(), material))
    }

    /// Get key metadata
    pub async fn get_metadata(&self, version: &KeyVersion) -> P2Result<KeyMetadata> {
        let keys = self.keys.read().await;

        let entry = keys.get(version).ok_or_else(|| {
            P2Error::Encryption(format!("Key version {} not found", version))
        })?;

        Ok(entry.metadata.clone())
    }

    /// Rotate to a new key version
    pub async fn rotate_key(
        &self,
        key_type: KeyType,
        new_version: KeyVersion,
        new_material: Vec<u8>,
        algorithm: &str,
        key_size: u32,
    ) -> P2Result<KeyVersion> {
        // Deprecate old active key
        if let Some(old_version) = self.active_versions.read().await.get(&key_type).cloned() {
            let mut keys = self.keys.write().await;
            if let Some(entry) = keys.get_mut(&old_version) {
                entry.metadata.deprecate();
            }
        }

        // Create metadata for new key
        let metadata = KeyMetadata::new(new_version.clone(), key_type, algorithm, key_size)
            .with_purpose("Rotated key");

        // Register new key
        let mut keys = self.keys.write().await;
        keys.insert(
            new_version.clone(),
            KeyEntry {
                material: new_material,
                metadata,
            },
        );

        // Update active version
        let mut active = self.active_versions.write().await;
        active.insert(key_type, new_version.clone());

        Ok(new_version)
    }

    /// Generate a new key using KDF
    pub async fn generate_key(
        &self,
        key_type: KeyType,
        purpose: &str,
        key_size: usize,
    ) -> P2Result<(KeyVersion, Vec<u8>)> {
        let ctx = self.kdf_context.as_ref().ok_or_else(|| {
            P2Error::Encryption("No master key configured for key generation".to_string())
        })?;

        let version = format!("{:?}-{}", key_type, Utc::now().timestamp_millis());
        let material = ctx.derive_for_purpose(purpose, key_size)?;

        Ok((version, material))
    }

    /// Deprecate a key version
    pub async fn deprecate_key(&self, version: &KeyVersion) -> P2Result<()> {
        let mut keys = self.keys.write().await;

        let entry = keys.get_mut(version).ok_or_else(|| {
            P2Error::Encryption(format!("Key version {} not found", version))
        })?;

        entry.metadata.deprecate();
        Ok(())
    }

    /// Archive a key version
    pub async fn archive_key(&self, version: &KeyVersion) -> P2Result<()> {
        let mut keys = self.keys.write().await;

        let entry = keys.get_mut(version).ok_or_else(|| {
            P2Error::Encryption(format!("Key version {} not found", version))
        })?;

        // Only deprecated keys can be archived
        if entry.metadata.status != KeyStatus::Deprecated {
            return Err(P2Error::Validation(
                "Only deprecated keys can be archived".to_string(),
            ));
        }

        entry.metadata.archive();
        Ok(())
    }

    /// List all key versions for a type
    pub async fn list_versions(&self, key_type: KeyType) -> Vec<KeyMetadata> {
        self.keys
            .read()
            .await
            .values()
            .filter(|e| e.metadata.key_type == key_type)
            .map(|e| e.metadata.clone())
            .collect()
    }

    /// Get keys that need rotation
    pub async fn get_keys_needing_rotation(&self) -> Vec<KeyMetadata> {
        let threshold = Utc::now() - Duration::days(self.config.rotation_interval_days as i64);

        self.keys
            .read()
            .await
            .values()
            .filter(|e| {
                e.metadata.status == KeyStatus::Active
                    && e.metadata.created_at < threshold
            })
            .map(|e| e.metadata.clone())
            .collect()
    }

    /// Get keys expiring soon
    pub async fn get_keys_expiring_soon(&self) -> Vec<KeyMetadata> {
        let threshold = Utc::now() + Duration::days(self.config.alert_before_expiry_days as i64);

        self.keys
            .read()
            .await
            .values()
            .filter(|e| {
                e.metadata.expires_at.map(|exp| exp < threshold).unwrap_or(false)
                    && e.metadata.status == KeyStatus::Active
            })
            .map(|e| e.metadata.clone())
            .collect()
    }

    /// Clean up expired archived keys
    pub async fn cleanup_expired(&self) -> P2Result<usize> {
        let threshold = Utc::now() - Duration::days(self.config.archive_retention_days as i64);

        let mut keys = self.keys.write().await;
        let before_count = keys.len();

        keys.retain(|_, entry| {
            !(entry.metadata.status == KeyStatus::Archived
                && entry.metadata.deprecated_at.map(|d| d < threshold).unwrap_or(false))
        });

        Ok(before_count - keys.len())
    }

    /// Get rotation statistics
    pub async fn stats(&self) -> KeyRotationStats {
        let keys = self.keys.read().await;

        let mut active = 0;
        let mut deprecated = 0;
        let mut archived = 0;

        for entry in keys.values() {
            match entry.metadata.status {
                KeyStatus::Active => active += 1,
                KeyStatus::Deprecated => deprecated += 1,
                KeyStatus::Archived => archived += 1,
                KeyStatus::Destroyed => {}
            }
        }

        KeyRotationStats {
            total_keys: keys.len(),
            active_keys: active,
            deprecated_keys: deprecated,
            archived_keys: archived,
        }
    }
}

/// Key rotation statistics
#[derive(Debug, Clone)]
pub struct KeyRotationStats {
    /// Total number of keys
    pub total_keys: usize,
    /// Number of active keys
    pub active_keys: usize,
    /// Number of deprecated keys
    pub deprecated_keys: usize,
    /// Number of archived keys
    pub archived_keys: usize,
}

/// Re-encryption job for key migration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReEncryptionJob {
    /// Job ID
    pub job_id: String,
    /// Source key version
    pub source_version: KeyVersion,
    /// Target key version
    pub target_version: KeyVersion,
    /// Total items to re-encrypt
    pub total_items: u64,
    /// Items processed
    pub processed_items: u64,
    /// Failed items
    pub failed_items: u64,
    /// Job status
    pub status: ReEncryptionStatus,
    /// Started at
    pub started_at: DateTime<Utc>,
    /// Completed at
    pub completed_at: Option<DateTime<Utc>>,
}

/// Re-encryption job status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReEncryptionStatus {
    /// Job is pending
    Pending,
    /// Job is running
    Running,
    /// Job completed successfully
    Completed,
    /// Job failed
    Failed,
    /// Job was cancelled
    Cancelled,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_register_and_get_key() {
        let manager = KeyManager::with_defaults();

        let metadata = KeyMetadata::new("v1".to_string(), KeyType::Kek, "AES-256", 256);
        manager
            .register_key("v1".to_string(), KeyType::Kek, vec![0u8; 32], metadata)
            .await
            .unwrap();

        let key = manager.get_key(&"v1".to_string()).await.unwrap();
        assert_eq!(key.len(), 32);
    }

    #[tokio::test]
    async fn test_get_active_key() {
        let manager = KeyManager::with_defaults();

        let metadata = KeyMetadata::new("kek-v1".to_string(), KeyType::Kek, "AES-256", 256);
        manager
            .register_key("kek-v1".to_string(), KeyType::Kek, vec![1u8; 32], metadata)
            .await
            .unwrap();

        let (version, key) = manager.get_active_key(KeyType::Kek).await.unwrap();
        assert_eq!(version, "kek-v1");
        assert_eq!(key.len(), 32);
    }

    #[tokio::test]
    async fn test_key_rotation() {
        let manager = KeyManager::with_defaults();

        // Register initial key
        let metadata = KeyMetadata::new("v1".to_string(), KeyType::Kek, "AES-256", 256);
        manager
            .register_key("v1".to_string(), KeyType::Kek, vec![1u8; 32], metadata)
            .await
            .unwrap();

        // Rotate to new key
        manager
            .rotate_key(KeyType::Kek, "v2".to_string(), vec![2u8; 32], "AES-256", 256)
            .await
            .unwrap();

        // New key should be active
        let (version, _) = manager.get_active_key(KeyType::Kek).await.unwrap();
        assert_eq!(version, "v2");

        // Old key should be deprecated
        let metadata = manager.get_metadata(&"v1".to_string()).await.unwrap();
        assert_eq!(metadata.status, KeyStatus::Deprecated);
    }

    #[tokio::test]
    async fn test_deprecated_key_can_decrypt() {
        let manager = KeyManager::with_defaults();

        let metadata = KeyMetadata::new("v1".to_string(), KeyType::Kek, "AES-256", 256);
        manager
            .register_key("v1".to_string(), KeyType::Kek, vec![1u8; 32], metadata)
            .await
            .unwrap();

        manager.deprecate_key(&"v1".to_string()).await.unwrap();

        // Should still be able to get deprecated key
        let key = manager.get_key(&"v1".to_string()).await.unwrap();
        assert_eq!(key.len(), 32);
    }

    #[tokio::test]
    async fn test_key_with_master() {
        let manager = KeyManager::with_defaults()
            .with_master_key(b"master_secret", b"app_salt");

        let (version, material) = manager
            .generate_key(KeyType::Dek, "test-purpose", 32)
            .await
            .unwrap();

        assert!(version.starts_with("Dek-"));
        assert_eq!(material.len(), 32);
    }

    #[tokio::test]
    async fn test_stats() {
        let manager = KeyManager::with_defaults();

        let metadata1 = KeyMetadata::new("v1".to_string(), KeyType::Kek, "AES-256", 256);
        manager
            .register_key("v1".to_string(), KeyType::Kek, vec![1u8; 32], metadata1)
            .await
            .unwrap();

        let metadata2 = KeyMetadata::new("v2".to_string(), KeyType::Kek, "AES-256", 256);
        manager
            .register_key("v2".to_string(), KeyType::Kek, vec![2u8; 32], metadata2)
            .await
            .unwrap();

        manager.deprecate_key(&"v1".to_string()).await.unwrap();

        let stats = manager.stats().await;
        assert_eq!(stats.total_keys, 2);
        assert_eq!(stats.active_keys, 1);
        assert_eq!(stats.deprecated_keys, 1);
    }
}
