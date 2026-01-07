//! Encrypted Ledger Storage
//!
//! Provides encryption utilities for ledger data storage.
//! All ledger data (evidence, audit, tickets, snapshots) should use this
//! module to ensure zero-plaintext compliance.
//!
//! # Design
//!
//! - Uses EnvelopeEncryption for data encryption
//! - Each ledger entry is encrypted with entry_id as AAD
//! - Index files are also encrypted
//! - Production mode requires a KeyStore for secure key management
//!
//! # Security
//!
//! In production, always use `EncryptedStorageConfig::with_key_store()` to ensure
//! keys are retrieved from a secure key management system (Vault, KMS, etc.).

use std::path::Path;
use std::sync::Arc;
use serde::{de::DeserializeOwned, Serialize};
use tokio::fs;

use crate::crypto::{EnvelopeEncryption, SealedEnvelope};
use crate::crypto::key_store::KeyStore;
use crate::error::{P2Error, P2Result};

/// Encrypted storage configuration
#[derive(Clone)]
pub struct EncryptedStorageConfig {
    /// KEK reference for encryption
    pub kek_ref: String,
    /// Whether encryption is enabled (false only for migration/testing)
    pub enabled: bool,
    /// Key store for secure key retrieval (required in production)
    key_store: Option<Arc<dyn KeyStore>>,
}

impl std::fmt::Debug for EncryptedStorageConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedStorageConfig")
            .field("kek_ref", &self.kek_ref)
            .field("enabled", &self.enabled)
            .field("has_key_store", &self.key_store.is_some())
            .finish()
    }
}

impl Default for EncryptedStorageConfig {
    /// Default config uses insecure key derivation - FOR DEVELOPMENT ONLY
    ///
    /// In production, use `with_key_store()` instead.
    fn default() -> Self {
        Self {
            kek_ref: "ledger-kek-v1".to_string(),
            enabled: true,
            key_store: None,
        }
    }
}

impl EncryptedStorageConfig {
    /// Create config with a KeyStore for secure key retrieval (RECOMMENDED FOR PRODUCTION)
    ///
    /// # Arguments
    /// * `key_store` - The key store to retrieve encryption keys from
    /// * `kek_ref` - The KEK reference identifier
    ///
    /// # Example
    /// ```ignore
    /// let vault_store = VaultKeyStore::new(config);
    /// let config = EncryptedStorageConfig::with_key_store(
    ///     Arc::new(vault_store),
    ///     "production-kek-v1"
    /// );
    /// ```
    pub fn with_key_store(key_store: Arc<dyn KeyStore>, kek_ref: impl Into<String>) -> Self {
        Self {
            kek_ref: kek_ref.into(),
            enabled: true,
            key_store: Some(key_store),
        }
    }

    /// Create config with specific KEK (insecure - for development only)
    ///
    /// # Security Warning
    /// This uses insecure key derivation. Use `with_key_store()` in production.
    #[deprecated(
        since = "0.1.0",
        note = "Use with_key_store() for production. This uses insecure key derivation."
    )]
    pub fn with_kek(kek_ref: impl Into<String>) -> Self {
        Self {
            kek_ref: kek_ref.into(),
            enabled: true,
            key_store: None,
        }
    }

    /// Create unencrypted config (for testing only)
    #[cfg(test)]
    pub fn unencrypted() -> Self {
        Self {
            kek_ref: String::new(),
            enabled: false,
            key_store: None,
        }
    }

    /// Check if this config uses secure key management
    pub fn is_secure(&self) -> bool {
        self.key_store.is_some()
    }

    /// Get the key store if configured
    pub fn key_store(&self) -> Option<&Arc<dyn KeyStore>> {
        self.key_store.as_ref()
    }
}

/// Encrypted storage handler for ledger data
pub struct EncryptedStorage {
    /// Encryption handler
    encryption: Option<EnvelopeEncryption>,
    /// Configuration
    config: EncryptedStorageConfig,
}

impl EncryptedStorage {
    /// Create new encrypted storage with KeyStore (RECOMMENDED FOR PRODUCTION)
    ///
    /// This is the secure way to create EncryptedStorage. Keys are retrieved
    /// from a secure key management system.
    ///
    /// # Arguments
    /// * `config` - Configuration with KeyStore
    ///
    /// # Errors
    /// Returns an error if encryption is enabled but key retrieval fails.
    pub async fn new_secure(config: EncryptedStorageConfig) -> P2Result<Self> {
        let encryption = if config.enabled {
            if let Some(key_store) = &config.key_store {
                let enc = EnvelopeEncryption::from_key_store(
                    key_store.as_ref(),
                    &config.kek_ref,
                ).await?;
                Some(enc)
            } else {
                return Err(P2Error::Configuration(
                    "Encryption enabled but no KeyStore configured. Use with_key_store() or new_insecure() for development.".to_string()
                ));
            }
        } else {
            None
        };

        Ok(Self { encryption, config })
    }

    /// Create new encrypted storage with insecure key derivation (DEVELOPMENT ONLY)
    ///
    /// # Security Warning
    /// This method uses deterministic key derivation from the KEK reference,
    /// which is NOT SECURE for production. Use `new_secure()` with a KeyStore.
    #[allow(deprecated)]
    pub fn new_insecure(config: EncryptedStorageConfig) -> Self {
        let encryption = if config.enabled {
            Some(EnvelopeEncryption::new_insecure(config.kek_ref.clone()))
        } else {
            None
        };

        Self { encryption, config }
    }

    /// Create new encrypted storage (auto-selects secure or insecure based on config)
    ///
    /// If the config has a KeyStore, this will fail because async initialization is required.
    /// Use `new_secure()` for KeyStore-based configs.
    ///
    /// # Panics
    /// Panics if the config has a KeyStore (use `new_secure()` instead).
    #[allow(deprecated)]
    pub fn new(config: EncryptedStorageConfig) -> Self {
        if config.key_store.is_some() {
            panic!(
                "EncryptedStorageConfig has a KeyStore configured. \
                Use new_secure() (async) instead of new() for secure key management."
            );
        }

        // Fallback to insecure for backward compatibility (will be deprecated)
        Self::new_insecure(config)
    }

    /// Check if encryption is enabled
    pub fn is_encrypted(&self) -> bool {
        self.config.enabled
    }

    /// Check if secure key management is being used
    pub fn is_secure(&self) -> bool {
        self.config.is_secure()
    }

    /// Write encrypted data to file
    ///
    /// # Arguments
    /// * `path` - File path to write to
    /// * `data` - Data to serialize and encrypt
    /// * `entry_id` - Entry ID used as AAD for binding
    pub async fn write<T: Serialize>(
        &self,
        path: impl AsRef<Path>,
        data: &T,
        entry_id: &str,
    ) -> P2Result<()> {
        let path = path.as_ref();

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                P2Error::Storage(format!("Failed to create directory: {}", e))
            })?;
        }

        // Serialize data
        let json = serde_json::to_string(data)
            .map_err(|e| P2Error::Serialization(format!("Failed to serialize: {}", e)))?;

        // Encrypt if enabled
        let content = if let Some(ref enc) = self.encryption {
            let sealed = enc.seal(json.as_bytes(), Some(entry_id.as_bytes()))?;
            let sealed_json = serde_json::to_string(&sealed)
                .map_err(|e| P2Error::Serialization(format!("Failed to serialize envelope: {}", e)))?;
            format!("{{\"encrypted\":true,\"data\":{}}}", sealed_json)
        } else {
            format!("{{\"encrypted\":false,\"data\":{}}}", json)
        };

        // Write to file
        fs::write(path, content).await.map_err(|e| {
            P2Error::Storage(format!("Failed to write file: {}", e))
        })?;

        Ok(())
    }

    /// Read and decrypt data from file
    ///
    /// # Arguments
    /// * `path` - File path to read from
    /// * `entry_id` - Entry ID used as AAD for verification
    pub async fn read<T: DeserializeOwned>(
        &self,
        path: impl AsRef<Path>,
        entry_id: &str,
    ) -> P2Result<T> {
        let path = path.as_ref();

        // Read file
        let content = fs::read_to_string(path).await.map_err(|e| {
            P2Error::Storage(format!("Failed to read file: {}", e))
        })?;

        // Parse wrapper
        let wrapper: EncryptedWrapper = serde_json::from_str(&content)
            .map_err(|e| P2Error::Serialization(format!("Failed to parse wrapper: {}", e)))?;

        // Decrypt if needed
        let json = if wrapper.encrypted {
            let sealed: SealedEnvelope = serde_json::from_value(wrapper.data)
                .map_err(|e| P2Error::Serialization(format!("Failed to parse envelope: {}", e)))?;

            let enc = self.encryption.as_ref().ok_or_else(|| {
                P2Error::Decryption("Encrypted data but encryption not configured".to_string())
            })?;

            let plaintext = enc.unseal_with_aad(&sealed, entry_id.as_bytes())?;
            String::from_utf8(plaintext)
                .map_err(|e| P2Error::Serialization(format!("Invalid UTF-8: {}", e)))?
        } else {
            // Legacy unencrypted data
            wrapper.data.to_string()
        };

        // Deserialize
        serde_json::from_str(&json)
            .map_err(|e| P2Error::Serialization(format!("Failed to deserialize: {}", e)))
    }

    /// Write encrypted data directly (for index files)
    pub async fn write_raw(
        &self,
        path: impl AsRef<Path>,
        data: &[u8],
        context: &str,
    ) -> P2Result<()> {
        let path = path.as_ref();

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                P2Error::Storage(format!("Failed to create directory: {}", e))
            })?;
        }

        // Encrypt if enabled
        let content = if let Some(ref enc) = self.encryption {
            let sealed = enc.seal(data, Some(context.as_bytes()))?;
            let sealed_json = serde_json::to_string(&sealed)
                .map_err(|e| P2Error::Serialization(format!("Failed to serialize envelope: {}", e)))?;
            format!("{{\"encrypted\":true,\"data\":{}}}", sealed_json)
        } else {
            let data_str = String::from_utf8_lossy(data);
            format!("{{\"encrypted\":false,\"data\":{}}}", data_str)
        };

        fs::write(path, content).await.map_err(|e| {
            P2Error::Storage(format!("Failed to write file: {}", e))
        })?;

        Ok(())
    }

    /// Read and decrypt raw data
    pub async fn read_raw(
        &self,
        path: impl AsRef<Path>,
        context: &str,
    ) -> P2Result<Vec<u8>> {
        let path = path.as_ref();

        let content = fs::read_to_string(path).await.map_err(|e| {
            P2Error::Storage(format!("Failed to read file: {}", e))
        })?;

        let wrapper: EncryptedWrapper = serde_json::from_str(&content)
            .map_err(|e| P2Error::Serialization(format!("Failed to parse wrapper: {}", e)))?;

        if wrapper.encrypted {
            let sealed: SealedEnvelope = serde_json::from_value(wrapper.data)
                .map_err(|e| P2Error::Serialization(format!("Failed to parse envelope: {}", e)))?;

            let enc = self.encryption.as_ref().ok_or_else(|| {
                P2Error::Decryption("Encrypted data but encryption not configured".to_string())
            })?;

            enc.unseal_with_aad(&sealed, context.as_bytes())
        } else {
            // Legacy unencrypted data
            Ok(wrapper.data.to_string().into_bytes())
        }
    }

    /// Check if a file contains encrypted data
    pub async fn is_file_encrypted(path: impl AsRef<Path>) -> P2Result<bool> {
        let content = fs::read_to_string(path).await.map_err(|e| {
            P2Error::Storage(format!("Failed to read file: {}", e))
        })?;

        let wrapper: EncryptedWrapper = serde_json::from_str(&content)
            .map_err(|e| P2Error::Serialization(format!("Failed to parse wrapper: {}", e)))?;

        Ok(wrapper.encrypted)
    }
}

/// Wrapper for encrypted/unencrypted data
#[derive(Debug, serde::Deserialize)]
struct EncryptedWrapper {
    encrypted: bool,
    data: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[derive(Debug, Clone, PartialEq, Serialize, serde::Deserialize)]
    struct TestData {
        id: String,
        value: i32,
    }

    #[tokio::test]
    async fn test_encrypted_write_read() {
        let temp_dir = TempDir::new().unwrap();
        let storage = EncryptedStorage::new(EncryptedStorageConfig::default());

        let data = TestData {
            id: "test-001".to_string(),
            value: 42,
        };

        let path = temp_dir.path().join("test.enc");
        storage.write(&path, &data, "test-001").await.unwrap();

        // Verify file is encrypted
        let content = fs::read_to_string(&path).await.unwrap();
        assert!(content.contains("\"encrypted\":true"));

        // Read back
        let read_data: TestData = storage.read(&path, "test-001").await.unwrap();
        assert_eq!(read_data, data);
    }

    #[tokio::test]
    async fn test_unencrypted_write_read() {
        let temp_dir = TempDir::new().unwrap();
        let storage = EncryptedStorage::new(EncryptedStorageConfig::unencrypted());

        let data = TestData {
            id: "test-002".to_string(),
            value: 100,
        };

        let path = temp_dir.path().join("test.json");
        storage.write(&path, &data, "test-002").await.unwrap();

        // Verify file is not encrypted
        let content = fs::read_to_string(&path).await.unwrap();
        assert!(content.contains("\"encrypted\":false"));

        // Read back
        let read_data: TestData = storage.read(&path, "test-002").await.unwrap();
        assert_eq!(read_data, data);
    }

    #[tokio::test]
    async fn test_wrong_entry_id_fails() {
        let temp_dir = TempDir::new().unwrap();
        let storage = EncryptedStorage::new(EncryptedStorageConfig::default());

        let data = TestData {
            id: "test-003".to_string(),
            value: 200,
        };

        let path = temp_dir.path().join("test.enc");
        storage.write(&path, &data, "correct-id").await.unwrap();

        // Reading with wrong entry_id should fail
        let result: P2Result<TestData> = storage.read(&path, "wrong-id").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_raw_write_read() {
        let temp_dir = TempDir::new().unwrap();
        let storage = EncryptedStorage::new(EncryptedStorageConfig::default());

        let data = b"raw binary data for testing";
        let path = temp_dir.path().join("raw.enc");

        storage.write_raw(&path, data, "raw-context").await.unwrap();

        let read_data = storage.read_raw(&path, "raw-context").await.unwrap();
        assert_eq!(read_data, data);
    }
}
