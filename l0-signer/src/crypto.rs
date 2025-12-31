//! L0 Ed25519 Cryptographic Primitives
//!
//! Provides raw Ed25519 signing and verification for threshold signing.
//! Uses domain separation tags for different signing contexts.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;

use crate::error::{SignerError, SignerResult};

/// Domain separation tags for L0 signing contexts
pub mod domain {
    /// Domain tag for batch snapshot signing
    pub const BATCH_SNAPSHOT: &[u8] = b"L0:BatchSnapshot:v1\0";
    /// Domain tag for epoch snapshot signing
    pub const EPOCH_SNAPSHOT: &[u8] = b"L0:EpochSnapshot:v1\0";
    /// Domain tag for TipWitness signing
    pub const TIP_WITNESS: &[u8] = b"L0:TipWitness:v1\0";
    /// Domain tag for actor registration signing
    pub const ACTOR_REGISTER: &[u8] = b"L0:ActorRegister:v1\0";
    /// Domain tag for key rotation signing
    pub const KEY_ROTATE: &[u8] = b"L0:KeyRotate:v1\0";
}

/// L0 Ed25519 key pair for signing
#[derive(Clone)]
pub struct L0SigningKey {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    /// Key identifier (hex-encoded public key prefix)
    pub kid: String,
}

impl L0SigningKey {
    /// Generate a new random signing key
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let kid = hex::encode(&verifying_key.to_bytes()[..8]);
        Self {
            signing_key,
            verifying_key,
            kid,
        }
    }

    /// Create from existing secret key bytes (32 bytes)
    pub fn from_bytes(bytes: &[u8; 32]) -> SignerResult<Self> {
        let signing_key = SigningKey::from_bytes(bytes);
        let verifying_key = signing_key.verifying_key();
        let kid = hex::encode(&verifying_key.to_bytes()[..8]);
        Ok(Self {
            signing_key,
            verifying_key,
            kid,
        })
    }

    /// Create from hex-encoded secret key
    pub fn from_hex(hex_str: &str) -> SignerResult<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| SignerError::Crypto(format!("Invalid hex: {}", e)))?;
        if bytes.len() != 32 {
            return Err(SignerError::Crypto(format!(
                "Invalid key length: expected 32, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Self::from_bytes(&arr)
    }

    /// Get the public key bytes (32 bytes)
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Get the public key as hex string
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }

    /// Get the L0VerifyingKey for this signing key
    pub fn verifying_key(&self) -> L0VerifyingKey {
        L0VerifyingKey {
            verifying_key: self.verifying_key,
            pubkey_hex: self.public_key_hex(),
        }
    }

    /// Sign a message with domain separation
    ///
    /// The actual signed message is: domain_tag || message
    pub fn sign(&self, domain_tag: &[u8], message: &[u8]) -> L0Signature {
        let mut signing_input = Vec::with_capacity(domain_tag.len() + message.len());
        signing_input.extend_from_slice(domain_tag);
        signing_input.extend_from_slice(message);

        let signature = self.signing_key.sign(&signing_input);
        L0Signature {
            signature,
            signer_pubkey: self.public_key_hex(),
        }
    }

    /// Sign a batch snapshot message
    pub fn sign_batch(&self, message: &[u8]) -> L0Signature {
        self.sign(domain::BATCH_SNAPSHOT, message)
    }

    /// Sign an epoch snapshot message
    pub fn sign_epoch(&self, message: &[u8]) -> L0Signature {
        self.sign(domain::EPOCH_SNAPSHOT, message)
    }

    /// Sign a TipWitness message
    pub fn sign_tip_witness(&self, message: &[u8]) -> L0Signature {
        self.sign(domain::TIP_WITNESS, message)
    }
}

/// L0 Ed25519 public key for verification
#[derive(Clone, Debug)]
pub struct L0VerifyingKey {
    verifying_key: VerifyingKey,
    pub pubkey_hex: String,
}

impl L0VerifyingKey {
    /// Create from public key bytes (32 bytes)
    pub fn from_bytes(bytes: &[u8; 32]) -> SignerResult<Self> {
        let verifying_key = VerifyingKey::from_bytes(bytes)
            .map_err(|e| SignerError::Crypto(format!("Invalid public key: {}", e)))?;
        Ok(Self {
            verifying_key,
            pubkey_hex: hex::encode(bytes),
        })
    }

    /// Create from hex-encoded public key
    pub fn from_hex(hex_str: &str) -> SignerResult<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| SignerError::Crypto(format!("Invalid hex: {}", e)))?;
        if bytes.len() != 32 {
            return Err(SignerError::Crypto(format!(
                "Invalid public key length: expected 32, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Self::from_bytes(&arr)
    }

    /// Verify a signature with domain separation
    pub fn verify(
        &self,
        domain_tag: &[u8],
        message: &[u8],
        signature: &L0Signature,
    ) -> SignerResult<()> {
        let mut signing_input = Vec::with_capacity(domain_tag.len() + message.len());
        signing_input.extend_from_slice(domain_tag);
        signing_input.extend_from_slice(message);

        self.verifying_key
            .verify(&signing_input, &signature.signature)
            .map_err(|e| SignerError::InvalidSignature(format!("Verification failed: {}", e)))
    }

    /// Verify a batch snapshot signature
    pub fn verify_batch(&self, message: &[u8], signature: &L0Signature) -> SignerResult<()> {
        self.verify(domain::BATCH_SNAPSHOT, message, signature)
    }

    /// Verify an epoch snapshot signature
    pub fn verify_epoch(&self, message: &[u8], signature: &L0Signature) -> SignerResult<()> {
        self.verify(domain::EPOCH_SNAPSHOT, message, signature)
    }
}

/// L0 Ed25519 signature
#[derive(Clone, Debug)]
pub struct L0Signature {
    signature: Signature,
    /// Hex-encoded public key of the signer
    pub signer_pubkey: String,
}

impl L0Signature {
    /// Create from signature bytes and signer pubkey
    pub fn from_bytes(sig_bytes: &[u8; 64], signer_pubkey: String) -> SignerResult<Self> {
        let signature = Signature::from_bytes(sig_bytes);
        Ok(Self {
            signature,
            signer_pubkey,
        })
    }

    /// Get the signature bytes (64 bytes)
    pub fn to_bytes(&self) -> [u8; 64] {
        self.signature.to_bytes()
    }

    /// Get the signature as hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.signature.to_bytes())
    }

    /// Create from hex-encoded signature and signer pubkey
    pub fn from_hex(hex_str: &str, signer_pubkey: String) -> SignerResult<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| SignerError::Crypto(format!("Invalid hex: {}", e)))?;
        if bytes.len() != 64 {
            return Err(SignerError::Crypto(format!(
                "Invalid signature length: expected 64, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Self::from_bytes(&arr, signer_pubkey)
    }
}

/// Aggregated threshold signature proof
#[derive(Clone, Debug)]
pub struct AggregatedProof {
    /// Individual signatures from signers (pubkey_hex -> signature_hex)
    pub signatures: Vec<(String, String)>,
    /// Bitmap indicating which signers signed
    pub bitmap: String,
    /// Number of signatures
    pub count: u32,
    /// Required threshold
    pub threshold: u32,
}

impl AggregatedProof {
    /// Serialize the proof to a compact format
    /// Format: bitmap|sig1_pubkey:sig1_hex|sig2_pubkey:sig2_hex|...
    pub fn to_compact(&self) -> String {
        let mut parts = vec![self.bitmap.clone()];
        for (pubkey, sig) in &self.signatures {
            parts.push(format!("{}:{}", pubkey, sig));
        }
        parts.join("|")
    }

    /// Parse from compact format
    pub fn from_compact(s: &str) -> SignerResult<Self> {
        let parts: Vec<&str> = s.split('|').collect();
        if parts.is_empty() {
            return Err(SignerError::Crypto("Empty proof".to_string()));
        }

        let bitmap = parts[0].to_string();
        let mut signatures = Vec::new();

        for part in &parts[1..] {
            if let Some((pubkey, sig)) = part.split_once(':') {
                signatures.push((pubkey.to_string(), sig.to_string()));
            }
        }

        let count = signatures.len() as u32;
        Ok(Self {
            signatures,
            bitmap,
            count,
            threshold: 5, // Default L0 threshold
        })
    }

    /// Verify all signatures in the proof
    pub fn verify_all(
        &self,
        domain_tag: &[u8],
        message: &[u8],
    ) -> SignerResult<bool> {
        for (pubkey_hex, sig_hex) in &self.signatures {
            let verifying_key = L0VerifyingKey::from_hex(pubkey_hex)?;
            let signature = L0Signature::from_hex(sig_hex, pubkey_hex.clone())?;
            verifying_key.verify(domain_tag, message, &signature)?;
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let key = L0SigningKey::generate();
        assert!(!key.kid.is_empty());
        assert_eq!(key.public_key_bytes().len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let key = L0SigningKey::generate();
        let message = b"test message";

        let signature = key.sign_batch(message);

        let verifying_key = key.verifying_key();
        assert!(verifying_key.verify_batch(message, &signature).is_ok());
    }

    #[test]
    fn test_domain_separation() {
        let key = L0SigningKey::generate();
        let message = b"test message";

        // Sign with batch domain
        let batch_sig = key.sign_batch(message);

        // Verify with batch domain should succeed
        let verifying_key = key.verifying_key();
        assert!(verifying_key.verify_batch(message, &batch_sig).is_ok());

        // Verify with epoch domain should fail (wrong domain)
        assert!(verifying_key.verify_epoch(message, &batch_sig).is_err());
    }

    #[test]
    fn test_signature_serialization() {
        let key = L0SigningKey::generate();
        let message = b"test message";

        let signature = key.sign_batch(message);
        let hex = signature.to_hex();

        let restored = L0Signature::from_hex(&hex, signature.signer_pubkey.clone()).unwrap();
        assert_eq!(restored.to_hex(), hex);
    }

    #[test]
    fn test_key_from_hex() {
        let key1 = L0SigningKey::generate();
        let secret_hex = hex::encode(key1.signing_key.to_bytes());

        let key2 = L0SigningKey::from_hex(&secret_hex).unwrap();
        assert_eq!(key1.public_key_hex(), key2.public_key_hex());
    }

    #[test]
    fn test_aggregated_proof() {
        let key1 = L0SigningKey::generate();
        let key2 = L0SigningKey::generate();
        let message = b"test message";

        let sig1 = key1.sign_batch(message);
        let sig2 = key2.sign_batch(message);

        let proof = AggregatedProof {
            signatures: vec![
                (sig1.signer_pubkey.clone(), sig1.to_hex()),
                (sig2.signer_pubkey.clone(), sig2.to_hex()),
            ],
            bitmap: "110000000".to_string(),
            count: 2,
            threshold: 5,
        };

        let compact = proof.to_compact();
        let restored = AggregatedProof::from_compact(&compact).unwrap();

        assert_eq!(restored.count, 2);
        assert!(restored.verify_all(domain::BATCH_SNAPSHOT, message).is_ok());
    }
}
