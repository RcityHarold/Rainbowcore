//! Envelope Encryption
//!
//! Provides envelope encryption for sealing payloads.
//! Uses a DEK (Data Encryption Key) encrypted with a KEK (Key Encryption Key).
//!
//! # Security Design
//!
//! - **DEK**: Random 32-byte key generated per-envelope
//! - **Nonce**: Random 24-byte nonce for XChaCha20-Poly1305
//! - **Payload Encryption**: XChaCha20-Poly1305 AEAD
//! - **DEK Encryption**: XChaCha20-Poly1305 with KEK derived via HKDF
//! - **Integrity**: Blake3 digest of plaintext stored for verification
//!
//! # KeyStore Integration
//!
//! In production, use `from_key_store()` to retrieve the KEK from a secure
//! key management system (HashiCorp Vault, AWS KMS, etc.).

use l0_core::types::Digest;
use serde::{Deserialize, Serialize};
use soulbase_crypto::{Aead, XChaChaAead, hkdf_extract_expand};
use std::sync::Arc;
use zeroize::Zeroize;

use crate::crypto::key_store::{KeyMaterial, KeyStore};
use crate::error::{P2Error, P2Result};
use crate::types::EncryptionMetadata;

/// XChaCha20-Poly1305 key size (32 bytes)
const KEY_SIZE: usize = 32;

/// XChaCha20-Poly1305 nonce size (24 bytes)
const NONCE_SIZE: usize = 24;

/// HKDF salt for KEK derivation
const KEK_SALT: &[u8] = b"p2-dsn-kek-v1";

/// HKDF info for KEK derivation
const KEK_INFO: &[u8] = b"p2-envelope-kek";

/// HKDF info for DEK encryption nonce
const DEK_NONCE_INFO: &[u8] = b"p2-dek-nonce";

/// Sealed envelope - contains encrypted DEK and encrypted payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedEnvelope {
    /// Envelope version
    pub version: String,

    /// Encrypted DEK (Data Encryption Key)
    pub encrypted_dek: Vec<u8>,

    /// DEK encryption algorithm
    pub dek_algorithm: String,

    /// KEK (Key Encryption Key) reference
    pub kek_ref: String,

    /// Encrypted payload
    pub encrypted_payload: Vec<u8>,

    /// Payload encryption algorithm
    pub payload_algorithm: String,

    /// Initialization vector / nonce for payload encryption
    pub iv: Vec<u8>,

    /// Nonce for DEK encryption
    pub dek_nonce: Vec<u8>,

    /// Authentication tag is included in XChaCha20-Poly1305 ciphertext
    /// This field is kept for backwards compatibility but not used
    #[serde(default)]
    pub auth_tag: Option<Vec<u8>>,

    /// Plaintext digest (for verification after decryption)
    pub plaintext_digest: Digest,

    /// Additional authenticated data digest
    pub aad_digest: Option<Digest>,
}

impl SealedEnvelope {
    /// Get the total size of the envelope
    pub fn size_bytes(&self) -> usize {
        self.encrypted_dek.len()
            + self.encrypted_payload.len()
            + self.iv.len()
            + self.dek_nonce.len()
    }

    /// Verify that decrypted data matches the expected digest
    pub fn verify_plaintext(&self, plaintext: &[u8]) -> bool {
        Digest::blake3(plaintext) == self.plaintext_digest
    }

    /// Convert to encryption metadata
    pub fn to_metadata(&self) -> EncryptionMetadata {
        EncryptionMetadata {
            algorithm: self.payload_algorithm.clone(),
            key_version: self.kek_ref.clone(),
            kdf_params: None,
            threshold_info: None,
            iv_or_nonce: hex::encode(&self.iv),
        }
    }
}

/// Envelope encryption operations
pub struct EnvelopeEncryption {
    /// KEK reference (used to derive actual KEK)
    kek_ref: String,
    /// KEK secret material (in production, this would come from a secure key store)
    kek_secret: Vec<u8>,
    /// AEAD cipher
    aead: XChaChaAead,
}

impl EnvelopeEncryption {
    /// Create a new envelope encryption instance (INSECURE - for testing only)
    ///
    /// # Arguments
    /// * `kek_ref` - Reference identifier for the KEK
    ///
    /// # Security Warning
    /// This method derives the KEK deterministically from the reference string,
    /// which is NOT SECURE for production use. Use `from_key_store()` instead.
    ///
    /// # Panics
    /// Panics in release builds if not in test mode. Use `from_key_store()` for production.
    #[cfg(test)]
    pub fn new(kek_ref: String) -> Self {
        let kek_secret = Self::derive_kek_from_ref(&kek_ref);
        Self {
            kek_ref,
            kek_secret,
            aead: XChaChaAead::default(),
        }
    }

    /// Create a new envelope encryption instance with insecure key derivation
    ///
    /// # Security Warning
    /// **DO NOT USE IN PRODUCTION!** This method derives the KEK deterministically
    /// from the reference string. Anyone with the reference can derive the same key.
    ///
    /// Use `from_key_store()` with a proper KeyStore (Vault, KMS) in production.
    ///
    /// This method is provided only for:
    /// - Development environments
    /// - Migration scripts
    /// - Testing scenarios outside of `#[cfg(test)]`
    #[deprecated(
        since = "0.1.0",
        note = "Insecure key derivation. Use from_key_store() with a proper KeyStore in production."
    )]
    pub fn new_insecure(kek_ref: String) -> Self {
        let kek_secret = Self::derive_kek_from_ref(&kek_ref);
        Self {
            kek_ref,
            kek_secret,
            aead: XChaChaAead::default(),
        }
    }

    /// Create with an explicit KEK secret
    ///
    /// # Arguments
    /// * `kek_ref` - Reference identifier for the KEK
    /// * `kek_secret` - The actual 32-byte KEK secret
    ///
    /// # Panics
    /// Panics if `kek_secret` is not exactly 32 bytes
    pub fn with_secret(kek_ref: String, kek_secret: Vec<u8>) -> Self {
        assert_eq!(kek_secret.len(), KEY_SIZE, "KEK must be {} bytes", KEY_SIZE);
        Self {
            kek_ref,
            kek_secret,
            aead: XChaChaAead::default(),
        }
    }

    /// Create with KeyMaterial from a KeyStore
    ///
    /// # Arguments
    /// * `kek_ref` - Reference identifier for the KEK
    /// * `key_material` - The key material retrieved from a KeyStore
    ///
    /// # Errors
    /// Returns an error if the key material is not exactly 32 bytes
    pub fn with_key_material(kek_ref: String, key_material: KeyMaterial) -> P2Result<Self> {
        if key_material.len() != KEY_SIZE {
            return Err(P2Error::Encryption(format!(
                "KEK must be {} bytes, got {}",
                KEY_SIZE,
                key_material.len()
            )));
        }
        Ok(Self {
            kek_ref,
            kek_secret: key_material.as_bytes().to_vec(),
            aead: XChaChaAead::default(),
        })
    }

    /// Create an EnvelopeEncryption instance from a KeyStore
    ///
    /// This is the recommended way to create EnvelopeEncryption in production.
    /// It retrieves the KEK from a secure key management system.
    ///
    /// # Arguments
    /// * `key_store` - The key store to retrieve the KEK from
    /// * `kek_ref` - Reference identifier for the KEK
    ///
    /// # Example
    /// ```ignore
    /// // Production: Use Vault
    /// let store = VaultKeyStore::new(config);
    /// let encryption = EnvelopeEncryption::from_key_store(&store, "my-kek").await?;
    ///
    /// // Development: Use local keys
    /// let store = LocalKeyStore::new();
    /// let encryption = EnvelopeEncryption::from_key_store(&store, "dev-kek").await?;
    /// ```
    pub async fn from_key_store<S: KeyStore + ?Sized>(
        key_store: &S,
        kek_ref: &str,
    ) -> P2Result<Self> {
        let key_material = key_store.get_key(kek_ref).await?;
        Self::with_key_material(kek_ref.to_string(), key_material)
    }

    /// Create from an Arc<dyn KeyStore>
    ///
    /// Convenience method for use with boxed/arc key stores.
    pub async fn from_key_store_arc(
        key_store: Arc<dyn KeyStore>,
        kek_ref: &str,
    ) -> P2Result<Self> {
        Self::from_key_store(key_store.as_ref(), kek_ref).await
    }

    /// Derive a KEK from a reference string
    ///
    /// # Security Warning
    /// This is a placeholder implementation. In production, KEK should be
    /// retrieved from a secure key management system (e.g., HashiCorp Vault,
    /// AWS KMS, etc.), not derived from a string reference.
    fn derive_kek_from_ref(kek_ref: &str) -> Vec<u8> {
        hkdf_extract_expand(
            KEK_SALT,
            kek_ref.as_bytes(),
            KEK_INFO,
            KEY_SIZE,
        )
    }

    /// Generate cryptographically secure random bytes
    fn generate_random(len: usize) -> P2Result<Vec<u8>> {
        let mut bytes = vec![0u8; len];
        getrandom::getrandom(&mut bytes)
            .map_err(|e| P2Error::Encryption(format!("Random generation failed: {}", e)))?;
        Ok(bytes)
    }

    /// Seal (encrypt) a payload
    ///
    /// # Process
    /// 1. Generate a random DEK (32 bytes)
    /// 2. Generate a random nonce for payload encryption (24 bytes)
    /// 3. Encrypt the payload with DEK using XChaCha20-Poly1305
    /// 4. Generate a nonce for DEK encryption
    /// 5. Encrypt the DEK with KEK using XChaCha20-Poly1305
    /// 6. Return the sealed envelope
    ///
    /// # Arguments
    /// * `plaintext` - The data to encrypt
    /// * `aad` - Optional additional authenticated data
    pub fn seal(&self, plaintext: &[u8], aad: Option<&[u8]>) -> P2Result<SealedEnvelope> {
        // Compute plaintext digest before encryption
        let plaintext_digest = Digest::blake3(plaintext);
        let aad_digest = aad.map(Digest::blake3);

        // Get AAD bytes (empty if none)
        let aad_bytes = aad.unwrap_or(&[]);

        // Generate random DEK
        let mut dek = Self::generate_random(KEY_SIZE)?;

        // Generate random nonce for payload encryption
        let payload_nonce = Self::generate_random(NONCE_SIZE)?;

        // Encrypt payload with DEK
        let encrypted_payload = self.aead
            .seal(&dek, &payload_nonce, aad_bytes, plaintext)
            .map_err(|e| P2Error::Encryption(format!("Payload encryption failed: {}", e)))?;

        // Generate nonce for DEK encryption
        let dek_nonce = Self::generate_random(NONCE_SIZE)?;

        // Encrypt DEK with KEK (using kek_ref as AAD for binding)
        let encrypted_dek = self.aead
            .seal(&self.kek_secret, &dek_nonce, self.kek_ref.as_bytes(), &dek)
            .map_err(|e| P2Error::Encryption(format!("DEK encryption failed: {}", e)))?;

        // Zeroize the plaintext DEK
        dek.zeroize();

        Ok(SealedEnvelope {
            version: "v2".to_string(),
            encrypted_dek,
            dek_algorithm: "XChaCha20-Poly1305".to_string(),
            kek_ref: self.kek_ref.clone(),
            encrypted_payload,
            payload_algorithm: "XChaCha20-Poly1305".to_string(),
            iv: payload_nonce,
            dek_nonce,
            auth_tag: None, // Auth tag is included in ciphertext for XChaCha20-Poly1305
            plaintext_digest,
            aad_digest,
        })
    }

    /// Unseal (decrypt) a payload that was sealed without AAD
    ///
    /// # Process
    /// 1. Decrypt the DEK with KEK
    /// 2. Decrypt the payload with DEK
    /// 3. Verify the plaintext digest
    /// 4. Return the plaintext
    ///
    /// # Arguments
    /// * `envelope` - The sealed envelope to decrypt
    ///
    /// # Errors
    /// Returns an error if the envelope was sealed with AAD. Use `unseal_with_aad()` instead.
    pub fn unseal(&self, envelope: &SealedEnvelope) -> P2Result<Vec<u8>> {
        // Check if AAD was used during sealing
        if envelope.aad_digest.is_some() {
            return Err(P2Error::Decryption(
                "Envelope was sealed with AAD; use unseal_with_aad() instead".to_string(),
            ));
        }

        // Verify KEK reference matches
        if envelope.kek_ref != self.kek_ref {
            return Err(P2Error::Decryption(format!(
                "KEK reference mismatch: expected {}, got {}",
                self.kek_ref, envelope.kek_ref
            )));
        }

        // Decrypt DEK
        let mut dek = self.aead
            .open(
                &self.kek_secret,
                &envelope.dek_nonce,
                self.kek_ref.as_bytes(),
                &envelope.encrypted_dek,
            )
            .map_err(|e| P2Error::Decryption(format!("DEK decryption failed: {}", e)))?;

        // Decrypt payload (no AAD)
        let plaintext = self.aead
            .open(
                &dek,
                &envelope.iv,
                &[],
                &envelope.encrypted_payload,
            )
            .map_err(|e| P2Error::Decryption(format!("Payload decryption failed: {}", e)))?;

        // Zeroize the DEK
        dek.zeroize();

        // Verify plaintext digest
        if !envelope.verify_plaintext(&plaintext) {
            return Err(P2Error::IntegrityFailed(
                "Plaintext digest mismatch after decryption".to_string(),
            ));
        }

        Ok(plaintext)
    }

    /// Unseal with explicit AAD
    ///
    /// Use this when AAD was provided during sealing
    pub fn unseal_with_aad(&self, envelope: &SealedEnvelope, aad: &[u8]) -> P2Result<Vec<u8>> {
        // Verify KEK reference matches
        if envelope.kek_ref != self.kek_ref {
            return Err(P2Error::Decryption(format!(
                "KEK reference mismatch: expected {}, got {}",
                self.kek_ref, envelope.kek_ref
            )));
        }

        // Verify AAD digest if present
        if let Some(expected_digest) = &envelope.aad_digest {
            let actual_digest = Digest::blake3(aad);
            if actual_digest != *expected_digest {
                return Err(P2Error::IntegrityFailed(
                    "AAD digest mismatch".to_string(),
                ));
            }
        }

        // Decrypt DEK
        let mut dek = self.aead
            .open(
                &self.kek_secret,
                &envelope.dek_nonce,
                self.kek_ref.as_bytes(),
                &envelope.encrypted_dek,
            )
            .map_err(|e| P2Error::Decryption(format!("DEK decryption failed: {}", e)))?;

        // Decrypt payload with AAD
        let plaintext = self.aead
            .open(&dek, &envelope.iv, aad, &envelope.encrypted_payload)
            .map_err(|e| P2Error::Decryption(format!("Payload decryption failed: {}", e)))?;

        // Zeroize the DEK
        dek.zeroize();

        // Verify plaintext digest
        if !envelope.verify_plaintext(&plaintext) {
            return Err(P2Error::IntegrityFailed(
                "Plaintext digest mismatch after decryption".to_string(),
            ));
        }

        Ok(plaintext)
    }

    /// Rotate the DEK (re-encrypt with new KEK)
    ///
    /// This decrypts the DEK and re-encrypts it with a new KEK,
    /// without touching the payload encryption.
    pub fn rotate_dek(&self, envelope: &SealedEnvelope, new_encryption: &EnvelopeEncryption) -> P2Result<SealedEnvelope> {
        // Decrypt DEK with current KEK
        let mut dek = self.aead
            .open(
                &self.kek_secret,
                &envelope.dek_nonce,
                self.kek_ref.as_bytes(),
                &envelope.encrypted_dek,
            )
            .map_err(|e| P2Error::Decryption(format!("DEK decryption for rotation failed: {}", e)))?;

        // Generate new nonce for DEK encryption
        let new_dek_nonce = Self::generate_random(NONCE_SIZE)?;

        // Encrypt DEK with new KEK
        let new_encrypted_dek = new_encryption.aead
            .seal(
                &new_encryption.kek_secret,
                &new_dek_nonce,
                new_encryption.kek_ref.as_bytes(),
                &dek,
            )
            .map_err(|e| P2Error::Encryption(format!("DEK re-encryption failed: {}", e)))?;

        // Zeroize the plaintext DEK
        dek.zeroize();

        // Create new envelope with rotated DEK
        Ok(SealedEnvelope {
            version: envelope.version.clone(),
            encrypted_dek: new_encrypted_dek,
            dek_algorithm: envelope.dek_algorithm.clone(),
            kek_ref: new_encryption.kek_ref.clone(),
            encrypted_payload: envelope.encrypted_payload.clone(),
            payload_algorithm: envelope.payload_algorithm.clone(),
            iv: envelope.iv.clone(),
            dek_nonce: new_dek_nonce,
            auth_tag: None,
            plaintext_digest: envelope.plaintext_digest.clone(),
            aad_digest: envelope.aad_digest.clone(),
        })
    }

    /// Get the KEK reference
    pub fn kek_ref(&self) -> &str {
        &self.kek_ref
    }
}

/// Default implementation is only available in tests
#[cfg(test)]
impl Default for EnvelopeEncryption {
    fn default() -> Self {
        Self::new("default-kek".to_string())
    }
}

impl Drop for EnvelopeEncryption {
    fn drop(&mut self) {
        // Zeroize the KEK secret on drop
        self.kek_secret.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_and_unseal() {
        let encryption = EnvelopeEncryption::new("test-kek".to_string());
        let plaintext = b"Hello, P2!";

        let envelope = encryption.seal(plaintext, None).unwrap();

        // Verify envelope structure
        assert_eq!(envelope.version, "v2");
        assert_eq!(envelope.kek_ref, "test-kek");
        assert_eq!(envelope.payload_algorithm, "XChaCha20-Poly1305");
        assert_eq!(envelope.iv.len(), NONCE_SIZE);
        assert_eq!(envelope.dek_nonce.len(), NONCE_SIZE);

        // Verify encrypted payload is different from plaintext
        assert_ne!(envelope.encrypted_payload, plaintext);

        // Decrypt and verify
        let decrypted = encryption.unseal(&envelope).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_seal_and_unseal_with_aad() {
        let encryption = EnvelopeEncryption::new("test-kek".to_string());
        let plaintext = b"Secret message";
        let aad = b"case:ABC-123";

        let envelope = encryption.seal(plaintext, Some(aad)).unwrap();

        // Verify AAD digest is set
        assert!(envelope.aad_digest.is_some());

        // Decrypt with correct AAD
        let decrypted = encryption.unseal_with_aad(&envelope, aad).unwrap();
        assert_eq!(decrypted, plaintext);

        // Decrypt with wrong AAD should fail
        let wrong_aad = b"case:WRONG";
        let result = encryption.unseal_with_aad(&envelope, wrong_aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_envelope_size() {
        let encryption = EnvelopeEncryption::default();
        let plaintext = vec![0u8; 1000];

        let envelope = encryption.seal(&plaintext, None).unwrap();

        // Ciphertext should be larger than plaintext (includes auth tag)
        assert!(envelope.encrypted_payload.len() > plaintext.len());
        assert!(envelope.size_bytes() > plaintext.len());
    }

    #[test]
    fn test_verify_plaintext() {
        let encryption = EnvelopeEncryption::default();
        let plaintext = b"test data";

        let envelope = encryption.seal(plaintext, None).unwrap();
        assert!(envelope.verify_plaintext(plaintext));
        assert!(!envelope.verify_plaintext(b"wrong data"));
    }

    #[test]
    fn test_to_metadata() {
        let encryption = EnvelopeEncryption::new("my-kek".to_string());
        let envelope = encryption.seal(b"data", None).unwrap();

        let metadata = envelope.to_metadata();
        assert_eq!(metadata.algorithm, "XChaCha20-Poly1305");
        assert_eq!(metadata.key_version, "my-kek");
    }

    #[test]
    fn test_kek_reference_mismatch() {
        let encryption1 = EnvelopeEncryption::new("kek-1".to_string());
        let encryption2 = EnvelopeEncryption::new("kek-2".to_string());

        let plaintext = b"secret";
        let envelope = encryption1.seal(plaintext, None).unwrap();

        // Trying to decrypt with different KEK should fail
        let result = encryption2.unseal(&envelope);
        assert!(result.is_err());
    }

    #[test]
    fn test_rotate_dek() {
        let old_encryption = EnvelopeEncryption::new("old-kek".to_string());
        let new_encryption = EnvelopeEncryption::new("new-kek".to_string());

        let plaintext = b"data to rotate";
        let original_envelope = old_encryption.seal(plaintext, None).unwrap();

        // Rotate DEK
        let rotated_envelope = old_encryption.rotate_dek(&original_envelope, &new_encryption).unwrap();

        // Verify rotation
        assert_eq!(rotated_envelope.kek_ref, "new-kek");
        assert_ne!(rotated_envelope.encrypted_dek, original_envelope.encrypted_dek);
        assert_ne!(rotated_envelope.dek_nonce, original_envelope.dek_nonce);

        // Payload should be unchanged
        assert_eq!(rotated_envelope.encrypted_payload, original_envelope.encrypted_payload);
        assert_eq!(rotated_envelope.iv, original_envelope.iv);

        // Should decrypt correctly with new encryption
        let decrypted = new_encryption.unseal(&rotated_envelope).unwrap();
        assert_eq!(decrypted, plaintext);

        // Old encryption should no longer work
        let result = old_encryption.unseal(&rotated_envelope);
        assert!(result.is_err());
    }

    #[test]
    fn test_with_explicit_secret() {
        let secret = vec![0x42u8; KEY_SIZE];
        let encryption = EnvelopeEncryption::with_secret("explicit-kek".to_string(), secret);

        let plaintext = b"test with explicit key";
        let envelope = encryption.seal(plaintext, None).unwrap();
        let decrypted = encryption.unseal(&envelope).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_large_payload() {
        let encryption = EnvelopeEncryption::default();
        let plaintext = vec![0xABu8; 1024 * 1024]; // 1MB

        let envelope = encryption.seal(&plaintext, None).unwrap();
        let decrypted = encryption.unseal(&envelope).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let encryption = EnvelopeEncryption::default();
        let plaintext = b"sensitive data";

        let mut envelope = encryption.seal(plaintext, None).unwrap();

        // Tamper with the ciphertext
        if !envelope.encrypted_payload.is_empty() {
            envelope.encrypted_payload[0] ^= 0xFF;
        }

        // Decryption should fail due to authentication
        let result = encryption.unseal(&envelope);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_dek_fails() {
        let encryption = EnvelopeEncryption::default();
        let plaintext = b"sensitive data";

        let mut envelope = encryption.seal(plaintext, None).unwrap();

        // Tamper with the encrypted DEK
        if !envelope.encrypted_dek.is_empty() {
            envelope.encrypted_dek[0] ^= 0xFF;
        }

        // Decryption should fail
        let result = encryption.unseal(&envelope);
        assert!(result.is_err());
    }

    #[test]
    fn test_aad_enforcement() {
        let encryption = EnvelopeEncryption::default();
        let plaintext = b"sensitive data";
        let aad = b"case:ABC-123";

        // Seal with AAD
        let envelope = encryption.seal(plaintext, Some(aad)).unwrap();
        assert!(envelope.aad_digest.is_some());

        // unseal() should fail when AAD was used
        let result = encryption.unseal(&envelope);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("AAD"));

        // unseal_with_aad() should succeed with correct AAD
        let decrypted = encryption.unseal_with_aad(&envelope, aad).unwrap();
        assert_eq!(decrypted, plaintext);

        // unseal_with_aad() should fail with wrong AAD
        let wrong_aad = b"case:WRONG";
        let result = encryption.unseal_with_aad(&envelope, wrong_aad);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_from_key_store() {
        use crate::crypto::key_store::LocalKeyStore;

        let key_store = LocalKeyStore::new();
        let kek_ref = "test-kek-from-store";

        // Create encryption from key store
        let encryption = EnvelopeEncryption::from_key_store(&key_store, kek_ref)
            .await
            .unwrap();

        let plaintext = b"data encrypted with key from store";
        let envelope = encryption.seal(plaintext, None).unwrap();
        let decrypted = encryption.unseal(&envelope).unwrap();

        assert_eq!(decrypted, plaintext);
        assert_eq!(encryption.kek_ref(), kek_ref);
    }

    #[tokio::test]
    async fn test_from_key_store_arc() {
        use crate::crypto::key_store::LocalKeyStore;

        let key_store: Arc<dyn KeyStore> = Arc::new(LocalKeyStore::new());
        let kek_ref = "arc-kek";

        let encryption = EnvelopeEncryption::from_key_store_arc(key_store, kek_ref)
            .await
            .unwrap();

        let plaintext = b"arc key store test";
        let envelope = encryption.seal(plaintext, None).unwrap();
        let decrypted = encryption.unseal(&envelope).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_with_key_material() {
        use crate::crypto::key_store::KeyMaterial;

        let key_material = KeyMaterial::new(vec![0x42u8; KEY_SIZE]);
        let encryption = EnvelopeEncryption::with_key_material(
            "key-material-test".to_string(),
            key_material,
        ).unwrap();

        let plaintext = b"key material test";
        let envelope = encryption.seal(plaintext, None).unwrap();
        let decrypted = encryption.unseal(&envelope).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_with_key_material_wrong_size() {
        use crate::crypto::key_store::KeyMaterial;

        // Wrong size should fail
        let key_material = KeyMaterial::new(vec![0x42u8; 16]); // 16 bytes instead of 32
        let result = EnvelopeEncryption::with_key_material(
            "wrong-size".to_string(),
            key_material,
        );
        assert!(result.is_err());
    }
}
