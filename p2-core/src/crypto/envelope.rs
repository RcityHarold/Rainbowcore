//! Envelope Encryption
//!
//! Provides envelope encryption for sealing payloads.
//! Uses a DEK (Data Encryption Key) encrypted with a KEK (Key Encryption Key).

use l0_core::types::Digest;
use serde::{Deserialize, Serialize};

use crate::error::{P2Error, P2Result};
use crate::types::EncryptionMetadata;

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

    /// Initialization vector / nonce
    pub iv: Vec<u8>,

    /// Authentication tag (for AEAD)
    pub auth_tag: Option<Vec<u8>>,

    /// Plaintext digest (for verification after decryption)
    pub plaintext_digest: Digest,

    /// Additional authenticated data digest
    pub aad_digest: Option<Digest>,
}

impl SealedEnvelope {
    /// Get the total size of the envelope
    pub fn size_bytes(&self) -> usize {
        self.encrypted_dek.len() + self.encrypted_payload.len() + self.iv.len()
            + self.auth_tag.as_ref().map(|t| t.len()).unwrap_or(0)
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
    /// KEK reference
    kek_ref: String,
    /// Default algorithm for new envelopes
    default_algorithm: String,
}

impl EnvelopeEncryption {
    /// Create a new envelope encryption instance
    pub fn new(kek_ref: String) -> Self {
        Self {
            kek_ref,
            default_algorithm: "AES-256-GCM".to_string(),
        }
    }

    /// Seal (encrypt) a payload
    ///
    /// In a real implementation, this would:
    /// 1. Generate a random DEK
    /// 2. Encrypt the payload with DEK using AEAD
    /// 3. Encrypt the DEK with KEK
    /// 4. Return the sealed envelope
    pub fn seal(&self, plaintext: &[u8], aad: Option<&[u8]>) -> P2Result<SealedEnvelope> {
        // Placeholder implementation
        // In production, use proper cryptographic libraries

        let plaintext_digest = Digest::blake3(plaintext);
        let aad_digest = aad.map(Digest::blake3);

        // Generate random IV (16 bytes for AES-GCM)
        let iv = vec![0u8; 16]; // TODO: Use proper random generation

        // Placeholder: In production, encrypt with real crypto
        let encrypted_dek = vec![0u8; 32]; // Encrypted DEK placeholder
        let encrypted_payload = plaintext.to_vec(); // Placeholder - should be encrypted

        Ok(SealedEnvelope {
            version: "v1".to_string(),
            encrypted_dek,
            dek_algorithm: "AES-256-GCM".to_string(),
            kek_ref: self.kek_ref.clone(),
            encrypted_payload,
            payload_algorithm: self.default_algorithm.clone(),
            iv,
            auth_tag: Some(vec![0u8; 16]), // Placeholder auth tag
            plaintext_digest,
            aad_digest,
        })
    }

    /// Unseal (decrypt) a payload
    ///
    /// In a real implementation, this would:
    /// 1. Decrypt the DEK with KEK
    /// 2. Decrypt the payload with DEK
    /// 3. Verify the auth tag and plaintext digest
    /// 4. Return the plaintext
    pub fn unseal(&self, envelope: &SealedEnvelope) -> P2Result<Vec<u8>> {
        // Placeholder implementation
        // In production, use proper cryptographic libraries

        // Placeholder: Return the "encrypted" payload as-is
        // Real implementation would decrypt
        let plaintext = envelope.encrypted_payload.clone();

        // Verify digest
        if !envelope.verify_plaintext(&plaintext) {
            return Err(P2Error::IntegrityFailed(
                "Plaintext digest mismatch".to_string(),
            ));
        }

        Ok(plaintext)
    }

    /// Rotate the DEK (re-encrypt with new KEK)
    pub fn rotate_dek(&self, envelope: &SealedEnvelope, new_kek_ref: &str) -> P2Result<SealedEnvelope> {
        // In a real implementation:
        // 1. Decrypt the DEK with old KEK
        // 2. Encrypt the DEK with new KEK
        // 3. Return updated envelope

        let mut new_envelope = envelope.clone();
        new_envelope.kek_ref = new_kek_ref.to_string();
        Ok(new_envelope)
    }
}

impl Default for EnvelopeEncryption {
    fn default() -> Self {
        Self::new("default-kek".to_string())
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
        assert!(!envelope.encrypted_payload.is_empty());
        assert_eq!(envelope.kek_ref, "test-kek");

        let decrypted = encryption.unseal(&envelope).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_envelope_size() {
        let encryption = EnvelopeEncryption::default();
        let plaintext = vec![0u8; 1000];

        let envelope = encryption.seal(&plaintext, None).unwrap();
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
        assert_eq!(metadata.algorithm, "AES-256-GCM");
        assert_eq!(metadata.key_version, "my-kek");
    }
}
