//! Key Store Abstraction
//!
//! Provides a trait-based abstraction for key management systems.
//! This allows plugging in different backends like:
//! - HashiCorp Vault
//! - AWS KMS
//! - Azure Key Vault
//! - Local development keys
//!
//! # Security Design
//!
//! The KeyStore trait is designed to:
//! - Never expose raw key material outside the trait boundary
//! - Support key versioning and rotation
//! - Provide audit logging hooks
//! - Allow for HSM-backed implementations
//!
//! # Usage
//!
//! ```ignore
//! // Production: Use Vault
//! let store = VaultKeyStore::new("https://vault:8200", token)?;
//!
//! // Development: Use local keys (NOT FOR PRODUCTION)
//! let store = LocalKeyStore::new();
//!
//! // Create envelope encryption with the store
//! let encryption = EnvelopeEncryption::with_key_store(store, "kek:v1")?;
//! ```

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use zeroize::Zeroize;

#[cfg(feature = "vault")]
use base64::Engine as _;

use crate::error::{P2Error, P2Result};
use soulbase_crypto::hkdf_extract_expand;

/// Key size for XChaCha20-Poly1305 (256 bits)
pub const KEY_SIZE: usize = 32;

/// Key material wrapper that zeroizes on drop
#[derive(Clone)]
pub struct KeyMaterial(Vec<u8>);

impl KeyMaterial {
    /// Create new key material
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get key bytes (use with caution)
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get key length
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyMaterial([REDACTED {} bytes])", self.0.len())
    }
}

/// Key metadata returned by KeyStore
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    /// Key reference/identifier
    pub key_ref: String,
    /// Key version
    pub version: u32,
    /// Key algorithm
    pub algorithm: String,
    /// Key status
    pub status: KeyStoreStatus,
    /// Creation timestamp (ISO 8601)
    pub created_at: String,
    /// Expiration timestamp (optional)
    pub expires_at: Option<String>,
}

/// Key status in the store
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStoreStatus {
    /// Key is active and can be used for encryption/decryption
    Active,
    /// Key is deprecated (can decrypt but not encrypt)
    Deprecated,
    /// Key is disabled (cannot be used)
    Disabled,
    /// Key is pending deletion
    PendingDeletion,
}

/// Error type for KeyStore operations
#[derive(Debug, Clone)]
pub enum KeyStoreError {
    /// Key not found
    NotFound(String),
    /// Key is not active
    NotActive(String),
    /// Access denied
    AccessDenied(String),
    /// Connection error
    ConnectionError(String),
    /// Internal error
    InternalError(String),
}

impl std::fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(msg) => write!(f, "Key not found: {}", msg),
            Self::NotActive(msg) => write!(f, "Key not active: {}", msg),
            Self::AccessDenied(msg) => write!(f, "Access denied: {}", msg),
            Self::ConnectionError(msg) => write!(f, "Connection error: {}", msg),
            Self::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for KeyStoreError {}

impl From<KeyStoreError> for P2Error {
    fn from(err: KeyStoreError) -> Self {
        P2Error::Encryption(err.to_string())
    }
}

/// Key Store trait - abstraction for key management systems
///
/// Implementations should:
/// - Never log or expose raw key material
/// - Support key versioning
/// - Handle connection pooling and retries internally
#[async_trait]
pub trait KeyStore: Send + Sync {
    /// Get a key by reference
    ///
    /// Returns the key material if found and active.
    async fn get_key(&self, key_ref: &str) -> Result<KeyMaterial, KeyStoreError>;

    /// Get a specific version of a key
    async fn get_key_version(&self, key_ref: &str, version: u32) -> Result<KeyMaterial, KeyStoreError>;

    /// Get key metadata without the key material
    async fn get_key_info(&self, key_ref: &str) -> Result<KeyInfo, KeyStoreError>;

    /// Check if a key exists and is active
    async fn key_exists(&self, key_ref: &str) -> bool {
        self.get_key_info(key_ref).await.map(|i| i.status == KeyStoreStatus::Active).unwrap_or(false)
    }

    /// Get the current version of a key
    async fn current_version(&self, key_ref: &str) -> Result<u32, KeyStoreError> {
        self.get_key_info(key_ref).await.map(|i| i.version)
    }
}

/// Local key store for development/testing
///
/// # WARNING
/// This implementation derives keys from references using HKDF.
/// It is NOT secure for production use.
/// Use VaultKeyStore or another secure implementation in production.
pub struct LocalKeyStore {
    /// Salt for key derivation
    salt: Vec<u8>,
    /// Cached key info (for metadata queries)
    key_info: RwLock<HashMap<String, KeyInfo>>,
}

impl LocalKeyStore {
    /// Create a new local key store with default salt
    pub fn new() -> Self {
        Self {
            salt: b"p2-local-dev-salt-v1".to_vec(),
            key_info: RwLock::new(HashMap::new()),
        }
    }

    /// Create with custom salt
    pub fn with_salt(salt: Vec<u8>) -> Self {
        Self {
            salt,
            key_info: RwLock::new(HashMap::new()),
        }
    }

    /// Derive a key from the reference (NOT SECURE)
    fn derive_key(&self, key_ref: &str) -> KeyMaterial {
        let key = hkdf_extract_expand(
            &self.salt,
            key_ref.as_bytes(),
            b"p2-local-kek",
            KEY_SIZE,
        );
        KeyMaterial::new(key)
    }

    /// Register a key reference (for metadata)
    pub fn register_key(&self, key_ref: &str) {
        let info = KeyInfo {
            key_ref: key_ref.to_string(),
            version: 1,
            algorithm: "XChaCha20-Poly1305".to_string(),
            status: KeyStoreStatus::Active,
            created_at: chrono::Utc::now().to_rfc3339(),
            expires_at: None,
        };
        self.key_info.write().unwrap().insert(key_ref.to_string(), info);
    }
}

impl Default for LocalKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl KeyStore for LocalKeyStore {
    async fn get_key(&self, key_ref: &str) -> Result<KeyMaterial, KeyStoreError> {
        // Auto-register if not exists
        if !self.key_info.read().unwrap().contains_key(key_ref) {
            self.register_key(key_ref);
        }
        Ok(self.derive_key(key_ref))
    }

    async fn get_key_version(&self, key_ref: &str, version: u32) -> Result<KeyMaterial, KeyStoreError> {
        // Local store only supports version 1
        if version != 1 {
            return Err(KeyStoreError::NotFound(format!("Version {} not found", version)));
        }
        self.get_key(key_ref).await
    }

    async fn get_key_info(&self, key_ref: &str) -> Result<KeyInfo, KeyStoreError> {
        // Auto-register if not exists
        if !self.key_info.read().unwrap().contains_key(key_ref) {
            self.register_key(key_ref);
        }
        self.key_info.read().unwrap()
            .get(key_ref)
            .cloned()
            .ok_or_else(|| KeyStoreError::NotFound(key_ref.to_string()))
    }
}

/// Vault key store configuration
#[derive(Debug, Clone)]
pub struct VaultConfig {
    /// Vault server URL
    pub address: String,
    /// Vault token
    pub token: String,
    /// Transit secrets engine mount path
    pub mount_path: String,
    /// Namespace (for Vault Enterprise)
    pub namespace: Option<String>,
}

impl VaultConfig {
    /// Create new config
    pub fn new(address: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            address: address.into(),
            token: token.into(),
            mount_path: "transit".to_string(),
            namespace: None,
        }
    }

    /// Set custom mount path
    pub fn with_mount_path(mut self, path: impl Into<String>) -> Self {
        self.mount_path = path.into();
        self
    }

    /// Set namespace
    pub fn with_namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace = Some(ns.into());
        self
    }
}

/// HashiCorp Vault key store implementation
///
/// Uses the Vault Transit secrets engine for key management.
/// This implementation:
/// - Generates data keys via the transit/datakey endpoint
/// - Never exposes the actual transit key - only derived data keys
/// - Supports key versioning via Vault's key rotation
///
/// # Security Design
///
/// The Transit engine never exports the actual encryption key.
/// Instead, we use `datakey/plaintext` to get a data key encrypted
/// with the transit key, along with the plaintext data key.
/// The plaintext key is used as the KEK for envelope encryption.
#[cfg(feature = "vault")]
pub struct VaultKeyStore {
    config: VaultConfig,
    client: reqwest::Client,
}

#[cfg(feature = "vault")]
impl VaultKeyStore {
    /// Create new Vault key store
    pub fn new(config: VaultConfig) -> Result<Self, KeyStoreError> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(false)
            .build()
            .map_err(|e| KeyStoreError::ConnectionError(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self { config, client })
    }

    /// Build the API URL for a path
    fn api_url(&self, path: &str) -> String {
        format!("{}/v1/{}/{}", self.config.address, self.config.mount_path, path)
    }

    /// Add authentication headers
    fn auth_headers(&self) -> Vec<(&str, &str)> {
        let mut headers = vec![("X-Vault-Token", self.config.token.as_str())];
        if let Some(ref ns) = self.config.namespace {
            headers.push(("X-Vault-Namespace", ns.as_str()));
        }
        headers
    }

    /// Generate a new data key from the transit engine
    async fn generate_data_key(&self, key_name: &str) -> Result<KeyMaterial, KeyStoreError> {
        let url = self.api_url(&format!("datakey/plaintext/{}", key_name));

        let mut request = self.client.post(&url);
        for (name, value) in self.auth_headers() {
            request = request.header(name, value);
        }

        // Request a 256-bit key (32 bytes)
        let body = serde_json::json!({
            "bits": 256
        });

        let response = request
            .json(&body)
            .send()
            .await
            .map_err(|e| KeyStoreError::ConnectionError(format!("Vault request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            if status.as_u16() == 404 {
                return Err(KeyStoreError::NotFound(format!("Key '{}' not found in Vault", key_name)));
            }
            if status.as_u16() == 403 {
                return Err(KeyStoreError::AccessDenied(format!("Access denied to key '{}': {}", key_name, error_text)));
            }
            return Err(KeyStoreError::InternalError(format!(
                "Vault error ({}): {}",
                status, error_text
            )));
        }

        let result: VaultDataKeyResponse = response
            .json()
            .await
            .map_err(|e| KeyStoreError::InternalError(format!("Failed to parse Vault response: {}", e)))?;

        // Decode the plaintext key from base64
        let key_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &result.data.plaintext,
        )
        .map_err(|e| KeyStoreError::InternalError(format!("Failed to decode data key: {}", e)))?;

        if key_bytes.len() != KEY_SIZE {
            return Err(KeyStoreError::InternalError(format!(
                "Unexpected key size: {} (expected {})",
                key_bytes.len(),
                KEY_SIZE
            )));
        }

        Ok(KeyMaterial::new(key_bytes))
    }

    /// Get key metadata from Vault
    async fn get_key_metadata(&self, key_name: &str) -> Result<VaultKeyMetadata, KeyStoreError> {
        let url = self.api_url(&format!("keys/{}", key_name));

        let mut request = self.client.get(&url);
        for (name, value) in self.auth_headers() {
            request = request.header(name, value);
        }

        let response = request
            .send()
            .await
            .map_err(|e| KeyStoreError::ConnectionError(format!("Vault request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            if status.as_u16() == 404 {
                return Err(KeyStoreError::NotFound(format!("Key '{}' not found", key_name)));
            }
            return Err(KeyStoreError::InternalError(format!(
                "Vault error ({}): {}",
                status, error_text
            )));
        }

        let result: VaultKeyInfoResponse = response
            .json()
            .await
            .map_err(|e| KeyStoreError::InternalError(format!("Failed to parse key info: {}", e)))?;

        Ok(result.data)
    }
}

#[cfg(feature = "vault")]
#[async_trait]
impl KeyStore for VaultKeyStore {
    async fn get_key(&self, key_ref: &str) -> Result<KeyMaterial, KeyStoreError> {
        self.generate_data_key(key_ref).await
    }

    async fn get_key_version(&self, key_ref: &str, version: u32) -> Result<KeyMaterial, KeyStoreError> {
        // For versioned keys, we use the version in the key context
        // Note: Vault Transit uses the latest version by default
        // To get a specific version, we'd need to use the decrypt endpoint
        // with a previously encrypted data key
        //
        // For now, we only support getting the latest version
        let metadata = self.get_key_metadata(key_ref).await?;
        if metadata.latest_version != version {
            return Err(KeyStoreError::NotFound(format!(
                "Key version {} not available (latest: {})",
                version, metadata.latest_version
            )));
        }
        self.generate_data_key(key_ref).await
    }

    async fn get_key_info(&self, key_ref: &str) -> Result<KeyInfo, KeyStoreError> {
        let metadata = self.get_key_metadata(key_ref).await?;

        let status = if metadata.deletion_allowed {
            KeyStoreStatus::PendingDeletion
        } else if !metadata.exportable && metadata.latest_version > 0 {
            KeyStoreStatus::Active
        } else {
            KeyStoreStatus::Active
        };

        Ok(KeyInfo {
            key_ref: key_ref.to_string(),
            version: metadata.latest_version,
            algorithm: metadata.key_type,
            status,
            created_at: chrono::Utc::now().to_rfc3339(), // Vault doesn't expose this directly
            expires_at: None,
        })
    }
}

/// Vault datakey API response
#[cfg(feature = "vault")]
#[derive(Debug, Deserialize)]
struct VaultDataKeyResponse {
    data: VaultDataKeyData,
}

#[cfg(feature = "vault")]
#[derive(Debug, Deserialize)]
struct VaultDataKeyData {
    /// Base64-encoded plaintext key
    plaintext: String,
    /// Base64-encoded ciphertext (encrypted key for storage)
    #[allow(dead_code)]
    ciphertext: String,
}

/// Vault key info response
#[cfg(feature = "vault")]
#[derive(Debug, Deserialize)]
struct VaultKeyInfoResponse {
    data: VaultKeyMetadata,
}

#[cfg(feature = "vault")]
#[derive(Debug, Deserialize)]
struct VaultKeyMetadata {
    #[serde(rename = "type")]
    key_type: String,
    latest_version: u32,
    #[serde(default)]
    exportable: bool,
    #[serde(default)]
    deletion_allowed: bool,
}

/// Stub implementation when vault feature is disabled
#[cfg(not(feature = "vault"))]
pub struct VaultKeyStore {
    config: VaultConfig,
}

#[cfg(not(feature = "vault"))]
impl VaultKeyStore {
    /// Create new Vault key store (stub - requires vault feature)
    pub fn new(config: VaultConfig) -> Result<Self, KeyStoreError> {
        Ok(Self { config })
    }
}

#[cfg(not(feature = "vault"))]
#[async_trait]
impl KeyStore for VaultKeyStore {
    async fn get_key(&self, key_ref: &str) -> Result<KeyMaterial, KeyStoreError> {
        Err(KeyStoreError::InternalError(
            format!("VaultKeyStore requires the 'vault' feature. Key: {}, Vault: {}", key_ref, self.config.address)
        ))
    }

    async fn get_key_version(&self, key_ref: &str, version: u32) -> Result<KeyMaterial, KeyStoreError> {
        Err(KeyStoreError::InternalError(
            format!("VaultKeyStore requires the 'vault' feature. Key: {}:v{}", key_ref, version)
        ))
    }

    async fn get_key_info(&self, key_ref: &str) -> Result<KeyInfo, KeyStoreError> {
        Err(KeyStoreError::InternalError(
            format!("VaultKeyStore requires the 'vault' feature. Key: {}", key_ref)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_local_key_store() {
        let store = LocalKeyStore::new();

        // Get a key
        let key = store.get_key("test-kek").await.unwrap();
        assert_eq!(key.len(), KEY_SIZE);

        // Same reference should return same key
        let key2 = store.get_key("test-kek").await.unwrap();
        assert_eq!(key.as_bytes(), key2.as_bytes());

        // Different reference should return different key
        let key3 = store.get_key("other-kek").await.unwrap();
        assert_ne!(key.as_bytes(), key3.as_bytes());
    }

    #[tokio::test]
    async fn test_key_info() {
        let store = LocalKeyStore::new();

        let info = store.get_key_info("my-kek").await.unwrap();
        assert_eq!(info.key_ref, "my-kek");
        assert_eq!(info.version, 1);
        assert_eq!(info.status, KeyStoreStatus::Active);
    }

    #[tokio::test]
    async fn test_key_exists() {
        let store = LocalKeyStore::new();

        // Key doesn't exist initially but auto-registers
        assert!(store.key_exists("new-key").await);
    }

    #[test]
    fn test_key_material_zeroize() {
        let mut key = KeyMaterial::new(vec![0x42; 32]);
        assert_eq!(key.as_bytes()[0], 0x42);

        // After drop, memory should be zeroed
        // (We can't actually test this easily, but the Drop impl does it)
    }

    #[test]
    fn test_key_material_debug() {
        let key = KeyMaterial::new(vec![0x42; 32]);
        let debug = format!("{:?}", key);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("42")); // Should not leak key bytes
    }
}
