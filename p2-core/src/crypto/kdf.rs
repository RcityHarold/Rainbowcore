//! Key Derivation Functions (KDF)
//!
//! Provides secure key derivation for cryptographic operations.
//!
//! # Supported KDFs
//!
//! - **HKDF**: HMAC-based Key Derivation Function (RFC 5869)
//! - **PBKDF2**: Password-Based Key Derivation Function 2 (RFC 8018)
//!
//! # Usage
//!
//! ```ignore
//! use p2_core::crypto::kdf::{KeyDerivation, KdfParams, KdfAlgorithm};
//!
//! // Derive a key using HKDF
//! let kdf = KeyDerivation::new(KdfAlgorithm::HkdfSha256);
//! let params = KdfParams::hkdf(b"salt", b"info", 32);
//! let derived_key = kdf.derive(b"input_key_material", &params)?;
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Sha512, Digest};

use crate::error::{P2Error, P2Result};

/// KDF Algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KdfAlgorithm {
    /// HKDF with SHA-256
    HkdfSha256,
    /// HKDF with SHA-512
    HkdfSha512,
    /// PBKDF2 with SHA-256
    Pbkdf2Sha256,
    /// PBKDF2 with SHA-512
    Pbkdf2Sha512,
}

impl Default for KdfAlgorithm {
    fn default() -> Self {
        Self::HkdfSha256
    }
}

/// KDF Parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    /// Salt (optional for HKDF, required for PBKDF2)
    pub salt: Option<Vec<u8>>,
    /// Info context (HKDF only)
    pub info: Option<Vec<u8>>,
    /// Output key length in bytes
    pub output_length: usize,
    /// Iteration count (PBKDF2 only)
    pub iterations: Option<u32>,
}

impl KdfParams {
    /// Create HKDF parameters
    pub fn hkdf(salt: impl AsRef<[u8]>, info: impl AsRef<[u8]>, output_length: usize) -> Self {
        Self {
            salt: Some(salt.as_ref().to_vec()),
            info: Some(info.as_ref().to_vec()),
            output_length,
            iterations: None,
        }
    }

    /// Create HKDF parameters without salt
    pub fn hkdf_no_salt(info: impl AsRef<[u8]>, output_length: usize) -> Self {
        Self {
            salt: None,
            info: Some(info.as_ref().to_vec()),
            output_length,
            iterations: None,
        }
    }

    /// Create PBKDF2 parameters
    pub fn pbkdf2(salt: impl AsRef<[u8]>, iterations: u32, output_length: usize) -> Self {
        Self {
            salt: Some(salt.as_ref().to_vec()),
            info: None,
            output_length,
            iterations: Some(iterations),
        }
    }

    /// Validate parameters for algorithm
    pub fn validate(&self, algorithm: KdfAlgorithm) -> P2Result<()> {
        if self.output_length == 0 {
            return Err(P2Error::Validation("Output length must be > 0".to_string()));
        }

        match algorithm {
            KdfAlgorithm::Pbkdf2Sha256 | KdfAlgorithm::Pbkdf2Sha512 => {
                if self.salt.is_none() || self.salt.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
                    return Err(P2Error::Validation("PBKDF2 requires salt".to_string()));
                }
                if self.iterations.unwrap_or(0) < 10000 {
                    return Err(P2Error::Validation(
                        "PBKDF2 requires at least 10000 iterations".to_string(),
                    ));
                }
            }
            _ => {}
        }

        Ok(())
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::hkdf(b"default-salt", b"p2-key-derivation", 32)
    }
}

/// Key Derivation operations
pub struct KeyDerivation {
    algorithm: KdfAlgorithm,
}

impl KeyDerivation {
    /// Create a new KDF instance
    pub fn new(algorithm: KdfAlgorithm) -> Self {
        Self { algorithm }
    }

    /// Derive a key from input key material
    pub fn derive(&self, ikm: &[u8], params: &KdfParams) -> P2Result<Vec<u8>> {
        params.validate(self.algorithm)?;

        match self.algorithm {
            KdfAlgorithm::HkdfSha256 => self.hkdf_derive::<Sha256>(ikm, params),
            KdfAlgorithm::HkdfSha512 => self.hkdf_derive::<Sha512>(ikm, params),
            KdfAlgorithm::Pbkdf2Sha256 => self.pbkdf2_derive::<Sha256>(ikm, params),
            KdfAlgorithm::Pbkdf2Sha512 => self.pbkdf2_derive::<Sha512>(ikm, params),
        }
    }

    /// HKDF implementation (RFC 5869)
    fn hkdf_derive<D: Digest + Clone>(&self, ikm: &[u8], params: &KdfParams) -> P2Result<Vec<u8>> {
        let hash_len = <D as Digest>::output_size();
        let salt = params.salt.as_deref().unwrap_or(&[]);
        let info = params.info.as_deref().unwrap_or(&[]);

        // HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
        let prk = self.hmac::<D>(salt, ikm);

        // HKDF-Expand
        let n = (params.output_length + hash_len - 1) / hash_len;
        if n > 255 {
            return Err(P2Error::Validation("Output too long for HKDF".to_string()));
        }

        let mut okm = Vec::with_capacity(params.output_length);
        let mut t = Vec::new();

        for i in 1..=n {
            let mut input = Vec::with_capacity(t.len() + info.len() + 1);
            input.extend_from_slice(&t);
            input.extend_from_slice(info);
            input.push(i as u8);

            t = self.hmac::<D>(&prk, &input);
            okm.extend_from_slice(&t);
        }

        okm.truncate(params.output_length);
        Ok(okm)
    }

    /// PBKDF2 implementation (RFC 8018)
    fn pbkdf2_derive<D: Digest + Clone>(&self, password: &[u8], params: &KdfParams) -> P2Result<Vec<u8>> {
        let salt = params.salt.as_ref()
            .ok_or_else(|| P2Error::Validation("PBKDF2 requires salt".to_string()))?;
        let iterations = params.iterations
            .ok_or_else(|| P2Error::Validation("PBKDF2 requires iterations".to_string()))?;

        let hash_len = <D as Digest>::output_size();
        let n = (params.output_length + hash_len - 1) / hash_len;

        let mut dk = Vec::with_capacity(params.output_length);

        for i in 1..=n as u32 {
            let block = self.pbkdf2_f::<D>(password, salt, iterations, i);
            dk.extend_from_slice(&block);
        }

        dk.truncate(params.output_length);
        Ok(dk)
    }

    /// PBKDF2 F function
    fn pbkdf2_f<D: Digest + Clone>(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        block_num: u32,
    ) -> Vec<u8> {
        let hash_len = <D as Digest>::output_size();

        // U1 = PRF(Password, Salt || INT(i))
        let mut salt_i = salt.to_vec();
        salt_i.extend_from_slice(&block_num.to_be_bytes());

        let mut u = self.hmac::<D>(password, &salt_i);
        let mut result = u.clone();

        // Uj = PRF(Password, U_{j-1})
        for _ in 1..iterations {
            u = self.hmac::<D>(password, &u);
            for (r, u_byte) in result.iter_mut().zip(u.iter()) {
                *r ^= u_byte;
            }
        }

        result
    }

    /// Simple HMAC implementation
    fn hmac<D: Digest + Clone>(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        let block_size = 64; // SHA-256/SHA-512 block size
        let hash_len = <D as Digest>::output_size();

        // Key processing
        let key = if key.len() > block_size {
            let mut hasher = D::new();
            hasher.update(key);
            hasher.finalize().to_vec()
        } else {
            key.to_vec()
        };

        // Pad key
        let mut key_pad = key.clone();
        key_pad.resize(block_size, 0);

        // Inner padding
        let mut ipad = vec![0x36u8; block_size];
        for (i, k) in ipad.iter_mut().zip(key_pad.iter()) {
            *i ^= k;
        }

        // Outer padding
        let mut opad = vec![0x5cu8; block_size];
        for (o, k) in opad.iter_mut().zip(key_pad.iter()) {
            *o ^= k;
        }

        // Inner hash
        let mut inner_hasher = D::new();
        inner_hasher.update(&ipad);
        inner_hasher.update(data);
        let inner_hash = inner_hasher.finalize();

        // Outer hash
        let mut outer_hasher = D::new();
        outer_hasher.update(&opad);
        outer_hasher.update(&inner_hash);
        outer_hasher.finalize().to_vec()
    }

    /// Get the algorithm
    pub fn algorithm(&self) -> KdfAlgorithm {
        self.algorithm
    }
}

impl Default for KeyDerivation {
    fn default() -> Self {
        Self::new(KdfAlgorithm::HkdfSha256)
    }
}

/// Derive a key using default settings
pub fn derive_key(ikm: &[u8], salt: &[u8], info: &[u8], output_length: usize) -> P2Result<Vec<u8>> {
    let kdf = KeyDerivation::default();
    let params = KdfParams::hkdf(salt, info, output_length);
    kdf.derive(ikm, &params)
}

/// Key derivation context for generating multiple keys
pub struct KeyContext {
    /// Master key material
    master_key: Vec<u8>,
    /// KDF instance
    kdf: KeyDerivation,
    /// Base salt
    salt: Vec<u8>,
}

impl KeyContext {
    /// Create a new key context
    pub fn new(master_key: impl AsRef<[u8]>, salt: impl AsRef<[u8]>) -> Self {
        Self {
            master_key: master_key.as_ref().to_vec(),
            salt: salt.as_ref().to_vec(),
            kdf: KeyDerivation::default(),
        }
    }

    /// Derive a key for a specific purpose
    pub fn derive_for_purpose(&self, purpose: &str, length: usize) -> P2Result<Vec<u8>> {
        let params = KdfParams::hkdf(&self.salt, purpose.as_bytes(), length);
        self.kdf.derive(&self.master_key, &params)
    }

    /// Derive an encryption key
    pub fn derive_encryption_key(&self) -> P2Result<Vec<u8>> {
        self.derive_for_purpose("p2-encryption-key", 32)
    }

    /// Derive an authentication key
    pub fn derive_auth_key(&self) -> P2Result<Vec<u8>> {
        self.derive_for_purpose("p2-auth-key", 32)
    }

    /// Derive a DEK (Data Encryption Key)
    pub fn derive_dek(&self, payload_id: &str) -> P2Result<Vec<u8>> {
        let info = format!("p2-dek:{}", payload_id);
        self.derive_for_purpose(&info, 32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_basic() {
        let kdf = KeyDerivation::new(KdfAlgorithm::HkdfSha256);
        let ikm = b"input key material";
        let params = KdfParams::hkdf(b"salt", b"info", 32);

        let key = kdf.derive(ikm, &params).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_hkdf_deterministic() {
        let kdf = KeyDerivation::new(KdfAlgorithm::HkdfSha256);
        let ikm = b"test key";
        let params = KdfParams::hkdf(b"test salt", b"test info", 32);

        let key1 = kdf.derive(ikm, &params).unwrap();
        let key2 = kdf.derive(ikm, &params).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_hkdf_different_inputs() {
        let kdf = KeyDerivation::new(KdfAlgorithm::HkdfSha256);
        let params = KdfParams::hkdf(b"salt", b"info", 32);

        let key1 = kdf.derive(b"key1", &params).unwrap();
        let key2 = kdf.derive(b"key2", &params).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_hkdf_variable_length() {
        let kdf = KeyDerivation::new(KdfAlgorithm::HkdfSha256);
        let ikm = b"test key";

        for len in [16, 32, 48, 64] {
            let params = KdfParams::hkdf(b"salt", b"info", len);
            let key = kdf.derive(ikm, &params).unwrap();
            assert_eq!(key.len(), len);
        }
    }

    #[test]
    fn test_pbkdf2_basic() {
        let kdf = KeyDerivation::new(KdfAlgorithm::Pbkdf2Sha256);
        let password = b"password";
        let params = KdfParams::pbkdf2(b"salt", 10000, 32);

        let key = kdf.derive(password, &params).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_pbkdf2_iteration_validation() {
        let kdf = KeyDerivation::new(KdfAlgorithm::Pbkdf2Sha256);
        let password = b"password";
        let params = KdfParams::pbkdf2(b"salt", 100, 32); // Too few iterations

        let result = kdf.derive(password, &params);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_context() {
        let ctx = KeyContext::new(b"master_secret", b"app_salt");

        let enc_key = ctx.derive_encryption_key().unwrap();
        let auth_key = ctx.derive_auth_key().unwrap();

        assert_eq!(enc_key.len(), 32);
        assert_eq!(auth_key.len(), 32);
        assert_ne!(enc_key, auth_key);
    }

    #[test]
    fn test_derive_key_helper() {
        let key = derive_key(b"secret", b"salt", b"info", 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_key_context_dek() {
        let ctx = KeyContext::new(b"master", b"salt");

        let dek1 = ctx.derive_dek("payload:001").unwrap();
        let dek2 = ctx.derive_dek("payload:002").unwrap();

        assert_eq!(dek1.len(), 32);
        assert_ne!(dek1, dek2);
    }
}
