//! BLS12-381 Threshold Signatures
//!
//! Implements BLS signatures for the 5/9 threshold signing scheme.
//! Uses the BLS12-381 curve via the blst library.
//!
//! Features:
//! - Individual BLS signing
//! - Signature aggregation
//! - Threshold signature verification
//! - Lagrange coefficient computation for threshold reconstruction

use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::error::{SignerError, SignerResult};

/// Domain Separation Tag for L0 BLS signatures
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_L0:v1";

/// BLS secret key wrapper
#[derive(Clone)]
pub struct BlsSecretKey {
    inner: SecretKey,
    /// Key identifier (first 8 bytes of public key hex)
    pub kid: String,
}

impl BlsSecretKey {
    /// Generate a new random BLS secret key
    pub fn generate() -> Self {
        let mut ikm = [0u8; 32];
        OsRng.fill_bytes(&mut ikm);
        let sk = SecretKey::key_gen(&ikm, &[]).expect("Key generation failed");
        let pk = sk.sk_to_pk();
        let kid = hex::encode(&pk.compress()[..8]);
        Self { inner: sk, kid }
    }

    /// Create from raw bytes (32 bytes)
    pub fn from_bytes(bytes: &[u8; 32]) -> SignerResult<Self> {
        let sk = SecretKey::from_bytes(bytes)
            .map_err(|e| SignerError::Crypto(format!("Invalid BLS secret key: {:?}", e)))?;
        let pk = sk.sk_to_pk();
        let kid = hex::encode(&pk.compress()[..8]);
        Ok(Self { inner: sk, kid })
    }

    /// Get the corresponding public key
    pub fn public_key(&self) -> BlsPublicKey {
        BlsPublicKey {
            inner: self.inner.sk_to_pk(),
        }
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> BlsSignature {
        let sig = self.inner.sign(message, DST, &[]);
        BlsSignature { inner: sig }
    }

    /// Export to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }
}

/// BLS public key wrapper
#[derive(Clone, Debug)]
pub struct BlsPublicKey {
    inner: PublicKey,
}

impl BlsPublicKey {
    /// Create from compressed bytes (48 bytes)
    pub fn from_bytes(bytes: &[u8]) -> SignerResult<Self> {
        if bytes.len() != 48 {
            return Err(SignerError::Crypto(format!(
                "Invalid BLS public key length: expected 48, got {}",
                bytes.len()
            )));
        }
        let pk = PublicKey::from_bytes(bytes)
            .map_err(|e| SignerError::Crypto(format!("Invalid BLS public key: {:?}", e)))?;
        Ok(Self { inner: pk })
    }

    /// Create from hex string
    pub fn from_hex(hex_str: &str) -> SignerResult<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| SignerError::Crypto(format!("Invalid hex: {}", e)))?;
        Self::from_bytes(&bytes)
    }

    /// Export to compressed bytes (48 bytes)
    pub fn to_bytes(&self) -> [u8; 48] {
        self.inner.compress()
    }

    /// Export to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &BlsSignature) -> SignerResult<()> {
        let result = signature.inner.verify(true, message, DST, &[], &self.inner, true);
        if result == BLST_ERROR::BLST_SUCCESS {
            Ok(())
        } else {
            Err(SignerError::InvalidSignature(format!(
                "BLS verification failed: {:?}",
                result
            )))
        }
    }
}

/// BLS signature wrapper
#[derive(Clone, Debug)]
pub struct BlsSignature {
    inner: Signature,
}

impl BlsSignature {
    /// Create from compressed bytes (96 bytes)
    pub fn from_bytes(bytes: &[u8]) -> SignerResult<Self> {
        if bytes.len() != 96 {
            return Err(SignerError::Crypto(format!(
                "Invalid BLS signature length: expected 96, got {}",
                bytes.len()
            )));
        }
        let sig = Signature::from_bytes(bytes)
            .map_err(|e| SignerError::Crypto(format!("Invalid BLS signature: {:?}", e)))?;
        Ok(Self { inner: sig })
    }

    /// Create from hex string
    pub fn from_hex(hex_str: &str) -> SignerResult<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| SignerError::Crypto(format!("Invalid hex: {}", e)))?;
        Self::from_bytes(&bytes)
    }

    /// Export to compressed bytes (96 bytes)
    pub fn to_bytes(&self) -> [u8; 96] {
        self.inner.compress()
    }

    /// Export to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }
}

/// Threshold signature share with signer metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThresholdSignatureShare {
    /// Signer index (1-based)
    pub signer_index: u32,
    /// Signer public key (hex)
    pub signer_pubkey: String,
    /// Signature bytes (hex)
    pub signature: String,
}

impl ThresholdSignatureShare {
    /// Create a new signature share
    pub fn new(signer_index: u32, pubkey: &BlsPublicKey, signature: &BlsSignature) -> Self {
        Self {
            signer_index,
            signer_pubkey: pubkey.to_hex(),
            signature: signature.to_hex(),
        }
    }

    /// Get the signature
    pub fn get_signature(&self) -> SignerResult<BlsSignature> {
        BlsSignature::from_hex(&self.signature)
    }

    /// Get the public key
    pub fn get_pubkey(&self) -> SignerResult<BlsPublicKey> {
        BlsPublicKey::from_hex(&self.signer_pubkey)
    }
}

/// Aggregated BLS signature from multiple signers
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedBlsSignature {
    /// Aggregated signature (hex)
    pub signature: String,
    /// Bitmap of signers (1 = signed)
    pub signer_bitmap: String,
    /// Number of signatures aggregated
    pub signer_count: u32,
    /// Required threshold
    pub threshold: u32,
    /// Individual signer public keys that participated (hex)
    pub signer_pubkeys: Vec<String>,
}

impl AggregatedBlsSignature {
    /// Create bitmap from signer indices
    pub fn create_bitmap(indices: &[u32], total_signers: u32) -> String {
        let mut bitmap = vec!['0'; total_signers as usize];
        for &idx in indices {
            if idx > 0 && idx <= total_signers {
                bitmap[(idx - 1) as usize] = '1';
            }
        }
        bitmap.into_iter().collect()
    }

    /// Get the aggregated signature
    pub fn get_signature(&self) -> SignerResult<BlsSignature> {
        BlsSignature::from_hex(&self.signature)
    }

    /// Check if threshold is met
    pub fn threshold_met(&self) -> bool {
        self.signer_count >= self.threshold
    }
}

/// Aggregate multiple BLS signatures into one
pub fn aggregate_signatures(shares: &[ThresholdSignatureShare]) -> SignerResult<BlsSignature> {
    if shares.is_empty() {
        return Err(SignerError::Crypto("No signatures to aggregate".to_string()));
    }

    let sigs: Vec<Signature> = shares
        .iter()
        .map(|s| s.get_signature().map(|sig| sig.inner))
        .collect::<SignerResult<Vec<_>>>()?;

    let sig_refs: Vec<&Signature> = sigs.iter().collect();

    let mut agg_sig = AggregateSignature::from_signature(&sigs[0]);
    for sig in &sig_refs[1..] {
        agg_sig.add_signature(sig, true)
            .map_err(|e| SignerError::Crypto(format!("Failed to aggregate signature: {:?}", e)))?;
    }

    Ok(BlsSignature {
        inner: agg_sig.to_signature(),
    })
}

/// Aggregate multiple BLS public keys into one
pub fn aggregate_public_keys(pubkeys: &[BlsPublicKey]) -> SignerResult<BlsPublicKey> {
    if pubkeys.is_empty() {
        return Err(SignerError::Crypto("No public keys to aggregate".to_string()));
    }

    let pk_refs: Vec<&PublicKey> = pubkeys.iter().map(|pk| &pk.inner).collect();

    let agg_pk = AggregatePublicKey::aggregate(&pk_refs, true)
        .map_err(|e| SignerError::Crypto(format!("Failed to aggregate public keys: {:?}", e)))?;

    Ok(BlsPublicKey {
        inner: agg_pk.to_public_key(),
    })
}

/// Verify an aggregated signature against multiple messages and public keys
pub fn verify_aggregated(
    message: &[u8],
    signature: &BlsSignature,
    pubkeys: &[BlsPublicKey],
) -> SignerResult<()> {
    // Aggregate the public keys
    let agg_pk = aggregate_public_keys(pubkeys)?;

    // Verify with aggregated key
    agg_pk.verify(message, signature)
}

/// Create a threshold signature from shares
pub fn create_threshold_signature(
    shares: &[ThresholdSignatureShare],
    threshold: u32,
    total_signers: u32,
) -> SignerResult<AggregatedBlsSignature> {
    if (shares.len() as u32) < threshold {
        return Err(SignerError::ThresholdNotMet {
            got: shares.len() as u32,
            need: threshold,
        });
    }

    // Aggregate the signatures
    let agg_sig = aggregate_signatures(shares)?;

    // Collect signer info
    let indices: Vec<u32> = shares.iter().map(|s| s.signer_index).collect();
    let pubkeys: Vec<String> = shares.iter().map(|s| s.signer_pubkey.clone()).collect();

    Ok(AggregatedBlsSignature {
        signature: agg_sig.to_hex(),
        signer_bitmap: AggregatedBlsSignature::create_bitmap(&indices, total_signers),
        signer_count: shares.len() as u32,
        threshold,
        signer_pubkeys: pubkeys,
    })
}

/// Verify a threshold signature
pub fn verify_threshold_signature(
    message: &[u8],
    agg_sig: &AggregatedBlsSignature,
) -> SignerResult<bool> {
    if !agg_sig.threshold_met() {
        return Ok(false);
    }

    // Parse the signature
    let signature = agg_sig.get_signature()?;

    // Parse all public keys
    let pubkeys: Vec<BlsPublicKey> = agg_sig
        .signer_pubkeys
        .iter()
        .map(|pk_hex| BlsPublicKey::from_hex(pk_hex))
        .collect::<SignerResult<Vec<_>>>()?;

    // Verify with aggregated key
    match verify_aggregated(message, &signature, &pubkeys) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Compute Lagrange coefficient for threshold reconstruction at x=0.
///
/// For a set of points with indices [x_1, x_2, ..., x_k], the Lagrange basis
/// polynomial L_i(0) = product((0 - x_j) / (x_i - x_j)) for j != i.
///
/// This function returns the coefficient as an exact rational number (numerator, denominator)
/// to avoid floating-point precision issues in cryptographic applications.
///
/// # Arguments
/// * `index` - The index i for which to compute L_i(0)
/// * `indices` - All indices in the interpolation set
///
/// # Returns
/// A tuple (numerator, denominator) representing the exact Lagrange coefficient
pub fn lagrange_coefficient_exact(index: u32, indices: &[u32]) -> (i64, i64) {
    let x_i = index as i64;
    let mut numerator: i64 = 1;
    let mut denominator: i64 = 1;

    for &idx in indices {
        if idx != index {
            let x_j = idx as i64;
            // L_i(0) = product((0 - x_j) / (x_i - x_j)) for j != i
            numerator *= -x_j;           // (0 - x_j) = -x_j
            denominator *= x_i - x_j;    // (x_i - x_j)
        }
    }

    // Reduce the fraction by GCD
    let g = gcd(numerator.abs(), denominator.abs());
    let sign = if denominator < 0 { -1 } else { 1 };

    (sign * numerator / g, (sign * denominator).abs() / g)
}

/// Greatest Common Divisor using Euclidean algorithm
fn gcd(mut a: i64, mut b: i64) -> i64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a.abs()
}

/// Compute Lagrange coefficient as a floating-point approximation.
///
/// **WARNING**: This function uses floating-point arithmetic and should NOT be used
/// for cryptographic operations that require exact arithmetic. Use `lagrange_coefficient_exact`
/// instead for applications like Shamir's Secret Sharing reconstruction.
///
/// This is provided for backward compatibility and non-critical use cases.
pub fn lagrange_coefficient(index: u32, indices: &[u32]) -> f64 {
    let (num, den) = lagrange_coefficient_exact(index, indices);
    num as f64 / den as f64
}

/// Apply Lagrange coefficient to a byte slice (for secret reconstruction)
///
/// Multiplies each byte by the numerator and divides by the denominator,
/// using modular arithmetic in the field Z_p where p = 257 (smallest prime > 256).
///
/// For proper field arithmetic, use the FieldElement type from the dkg module.
pub fn apply_lagrange_coefficient(value: &[u8], coef: (i64, i64)) -> Vec<u8> {
    const FIELD_PRIME: i64 = 257; // Smallest prime > 256

    let (num, den) = coef;

    // Compute modular inverse of denominator
    let den_mod = ((den % FIELD_PRIME) + FIELD_PRIME) % FIELD_PRIME;
    let den_inv = mod_inverse(den_mod, FIELD_PRIME).unwrap_or(1);

    // Multiply by numerator and inverse of denominator
    let num_mod = ((num % FIELD_PRIME) + FIELD_PRIME) % FIELD_PRIME;
    let multiplier = (num_mod * den_inv) % FIELD_PRIME;

    value
        .iter()
        .map(|&b| {
            let v = (b as i64 * multiplier) % FIELD_PRIME;
            v as u8
        })
        .collect()
}

/// Compute modular inverse using extended Euclidean algorithm
fn mod_inverse(a: i64, m: i64) -> Option<i64> {
    let (mut old_r, mut r) = (a, m);
    let (mut old_s, mut s) = (1i64, 0i64);

    while r != 0 {
        let quotient = old_r / r;
        (old_r, r) = (r, old_r - quotient * r);
        (old_s, s) = (s, old_s - quotient * s);
    }

    if old_r != 1 {
        None // No inverse exists
    } else {
        Some(((old_s % m) + m) % m)
    }
}

/// BLS Threshold Signer for the 5/9 scheme
pub struct BlsThresholdSigner {
    /// Our secret key
    secret_key: BlsSecretKey,
    /// Our public key
    pub public_key: BlsPublicKey,
    /// Our signer index (1-based)
    pub signer_index: u32,
    /// Total number of signers
    pub total_signers: u32,
    /// Threshold
    pub threshold: u32,
}

impl BlsThresholdSigner {
    /// Create a new threshold signer
    pub fn new(secret_key: BlsSecretKey, signer_index: u32, total_signers: u32, threshold: u32) -> Self {
        let public_key = secret_key.public_key();
        Self {
            secret_key,
            public_key,
            signer_index,
            total_signers,
            threshold,
        }
    }

    /// Create with L0's 5/9 threshold
    pub fn new_5_of_9(secret_key: BlsSecretKey, signer_index: u32) -> Self {
        Self::new(secret_key, signer_index, 9, 5)
    }

    /// Generate a new signer with random key
    pub fn generate(signer_index: u32, total_signers: u32, threshold: u32) -> Self {
        let secret_key = BlsSecretKey::generate();
        Self::new(secret_key, signer_index, total_signers, threshold)
    }

    /// Sign a message and create a share
    pub fn sign(&self, message: &[u8]) -> ThresholdSignatureShare {
        let signature = self.secret_key.sign(message);
        ThresholdSignatureShare::new(self.signer_index, &self.public_key, &signature)
    }

    /// Verify another signer's share
    pub fn verify_share(&self, message: &[u8], share: &ThresholdSignatureShare) -> SignerResult<()> {
        let pubkey = share.get_pubkey()?;
        let signature = share.get_signature()?;
        pubkey.verify(message, &signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bls_key_generation() {
        let sk = BlsSecretKey::generate();
        let pk = sk.public_key();

        assert!(!sk.kid.is_empty());
        assert_eq!(pk.to_bytes().len(), 48);
    }

    #[test]
    fn test_bls_sign_and_verify() {
        let sk = BlsSecretKey::generate();
        let pk = sk.public_key();
        let message = b"Hello, L0!";

        let signature = sk.sign(message);
        assert!(pk.verify(message, &signature).is_ok());

        // Wrong message should fail
        assert!(pk.verify(b"Wrong message", &signature).is_err());
    }

    #[test]
    fn test_bls_serialization() {
        let sk = BlsSecretKey::generate();
        let pk = sk.public_key();
        let message = b"Test message";
        let signature = sk.sign(message);

        // Serialize and deserialize public key
        let pk_bytes = pk.to_bytes();
        let pk2 = BlsPublicKey::from_bytes(&pk_bytes).unwrap();
        assert_eq!(pk.to_hex(), pk2.to_hex());

        // Serialize and deserialize signature
        let sig_bytes = signature.to_bytes();
        let sig2 = BlsSignature::from_bytes(&sig_bytes).unwrap();
        assert_eq!(signature.to_hex(), sig2.to_hex());

        // Verify with deserialized key and signature
        assert!(pk2.verify(message, &sig2).is_ok());
    }

    #[test]
    fn test_signature_aggregation() {
        let message = b"Aggregation test";

        // Create 3 signers
        let signers: Vec<BlsThresholdSigner> = (1..=3)
            .map(|i| BlsThresholdSigner::generate(i, 9, 5))
            .collect();

        // Each signer creates a share
        let shares: Vec<ThresholdSignatureShare> = signers
            .iter()
            .map(|s| s.sign(message))
            .collect();

        // Aggregate signatures
        let agg_sig = aggregate_signatures(&shares).unwrap();

        // Aggregate public keys
        let pubkeys: Vec<BlsPublicKey> = signers.iter().map(|s| s.public_key.clone()).collect();
        let agg_pk = aggregate_public_keys(&pubkeys).unwrap();

        // Verify aggregated signature
        assert!(agg_pk.verify(message, &agg_sig).is_ok());
    }

    #[test]
    fn test_threshold_signature_5_of_9() {
        let message = b"L0 batch snapshot";

        // Create 9 signers (5/9 threshold)
        let signers: Vec<BlsThresholdSigner> = (1..=9)
            .map(|i| BlsThresholdSigner::new_5_of_9(BlsSecretKey::generate(), i))
            .collect();

        // Only 5 signers create shares (meets threshold)
        let shares: Vec<ThresholdSignatureShare> = signers[..5]
            .iter()
            .map(|s| s.sign(message))
            .collect();

        // Create threshold signature
        let result = create_threshold_signature(&shares, 5, 9);
        assert!(result.is_ok());

        let agg_sig = result.unwrap();
        assert!(agg_sig.threshold_met());
        assert_eq!(agg_sig.signer_count, 5);
        assert_eq!(agg_sig.signer_bitmap, "111110000");

        // Verify threshold signature
        let valid = verify_threshold_signature(message, &agg_sig).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_threshold_not_met() {
        let message = b"L0 batch snapshot";

        // Create 4 signers (below 5/9 threshold)
        let signers: Vec<BlsThresholdSigner> = (1..=4)
            .map(|i| BlsThresholdSigner::new_5_of_9(BlsSecretKey::generate(), i))
            .collect();

        let shares: Vec<ThresholdSignatureShare> = signers
            .iter()
            .map(|s| s.sign(message))
            .collect();

        // Should fail - threshold not met
        let result = create_threshold_signature(&shares, 5, 9);
        assert!(result.is_err());
    }

    #[test]
    fn test_share_verification() {
        let message = b"Share verification test";

        let signer1 = BlsThresholdSigner::new_5_of_9(BlsSecretKey::generate(), 1);
        let signer2 = BlsThresholdSigner::new_5_of_9(BlsSecretKey::generate(), 2);

        // Signer 1 creates a share
        let share = signer1.sign(message);

        // Signer 2 verifies signer 1's share
        assert!(signer2.verify_share(message, &share).is_ok());

        // Wrong message should fail
        let wrong_message = b"Wrong message";
        assert!(signer2.verify_share(wrong_message, &share).is_err());
    }

    #[test]
    fn test_bitmap_creation() {
        let bitmap = AggregatedBlsSignature::create_bitmap(&[1, 3, 5, 7, 9], 9);
        assert_eq!(bitmap, "101010101");

        let bitmap2 = AggregatedBlsSignature::create_bitmap(&[1, 2, 3, 4, 5], 9);
        assert_eq!(bitmap2, "111110000");
    }

    #[test]
    fn test_lagrange_coefficient() {
        // For indices [1, 2, 3], compute coefficient for index 1 at x=0
        let indices = vec![1, 2, 3];
        let coef = lagrange_coefficient(1, &indices);
        // L_1(0) = (0-2)(0-3) / (1-2)(1-3) = 6 / 2 = 3
        assert!((coef - 3.0).abs() < 0.001);
    }
}
