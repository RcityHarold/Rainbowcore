//! Threshold Signature Integrity Verification (ISSUE-017)
//!
//! Enhanced verification of threshold signatures with:
//! - Full signature chain verification
//! - Signer accountability tracking
//! - Cross-verification against signer set
//! - Replay protection
//! - Signature freshness validation

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::bls::{
    verify_threshold_signature, AggregatedBlsSignature, BlsPublicKey, ThresholdSignatureShare,
};
use crate::error::{SignerError, SignerResult};
use crate::signer_set::SignerSet;

/// Result of signature integrity verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureIntegrityResult {
    /// Whether the signature is valid
    pub is_valid: bool,
    /// Verification timestamp
    pub verified_at: DateTime<Utc>,
    /// Signer set version used for verification
    pub signer_set_version: String,
    /// Number of valid signatures
    pub valid_signature_count: u32,
    /// Required threshold
    pub threshold: u32,
    /// Participating signers (pubkeys)
    pub participating_signers: Vec<String>,
    /// Verification errors (if any)
    pub errors: Vec<SignatureVerificationError>,
    /// Warnings (non-fatal issues)
    pub warnings: Vec<String>,
    /// Message digest that was signed
    pub message_digest: String,
    /// Freshness check passed
    pub freshness_valid: bool,
    /// Replay protection check passed
    pub replay_protection_valid: bool,
}

impl SignatureIntegrityResult {
    /// Check if all integrity checks passed
    pub fn all_checks_passed(&self) -> bool {
        self.is_valid
            && self.freshness_valid
            && self.replay_protection_valid
            && self.errors.is_empty()
    }

    /// Get a summary of the verification
    pub fn summary(&self) -> String {
        if self.all_checks_passed() {
            format!(
                "Valid threshold signature: {}/{} signers (threshold: {})",
                self.valid_signature_count,
                self.participating_signers.len(),
                self.threshold
            )
        } else {
            let error_msgs: Vec<String> = self.errors.iter().map(|e| e.to_string()).collect();
            format!(
                "Invalid signature: {} errors - {}",
                self.errors.len(),
                error_msgs.join(", ")
            )
        }
    }
}

/// Signature verification error types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureVerificationError {
    /// Threshold not met
    ThresholdNotMet { got: u32, need: u32 },
    /// Invalid signer (not in certified set)
    InvalidSigner { pubkey: String, reason: String },
    /// Signature cryptographically invalid
    CryptographicFailure { details: String },
    /// Signature expired (too old)
    SignatureExpired { signed_at: DateTime<Utc>, max_age: i64 },
    /// Duplicate signature detected (replay)
    ReplayDetected { signature_hash: String },
    /// Bitmap mismatch
    BitmapMismatch { expected: String, actual: String },
    /// Signer count mismatch
    SignerCountMismatch { bitmap_count: u32, pubkey_count: u32 },
    /// Message digest mismatch
    MessageDigestMismatch,
}

impl std::fmt::Display for SignatureVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ThresholdNotMet { got, need } => {
                write!(f, "Threshold not met: got {} signatures, need {}", got, need)
            }
            Self::InvalidSigner { pubkey, reason } => {
                write!(f, "Invalid signer {}: {}", &pubkey[..8], reason)
            }
            Self::CryptographicFailure { details } => {
                write!(f, "Cryptographic verification failed: {}", details)
            }
            Self::SignatureExpired { signed_at, max_age } => {
                write!(f, "Signature expired: signed at {}, max age {} seconds", signed_at, max_age)
            }
            Self::ReplayDetected { signature_hash } => {
                write!(f, "Replay detected: signature {} already used", &signature_hash[..8])
            }
            Self::BitmapMismatch { expected, actual } => {
                write!(f, "Bitmap mismatch: expected {}, got {}", expected, actual)
            }
            Self::SignerCountMismatch { bitmap_count, pubkey_count } => {
                write!(f, "Signer count mismatch: bitmap shows {}, pubkeys show {}", bitmap_count, pubkey_count)
            }
            Self::MessageDigestMismatch => {
                write!(f, "Message digest does not match expected value")
            }
        }
    }
}

/// Configuration for signature integrity verification
#[derive(Debug, Clone)]
pub struct IntegrityVerifierConfig {
    /// Maximum signature age in seconds (0 = no limit)
    pub max_signature_age_secs: i64,
    /// Enable replay protection
    pub replay_protection_enabled: bool,
    /// Maximum replay cache size
    pub replay_cache_size: usize,
    /// Strict mode (fail on any warning)
    pub strict_mode: bool,
    /// Require all signers to be in certified set
    pub require_certified_signers: bool,
}

impl Default for IntegrityVerifierConfig {
    fn default() -> Self {
        Self {
            max_signature_age_secs: 3600, // 1 hour
            replay_protection_enabled: true,
            replay_cache_size: 10000,
            strict_mode: true,
            require_certified_signers: true,
        }
    }
}

/// Threshold Signature Integrity Verifier
///
/// Provides enhanced verification of threshold signatures with
/// accountability, replay protection, and freshness checks.
pub struct SignatureIntegrityVerifier {
    /// Configuration
    config: IntegrityVerifierConfig,
    /// Seen signature hashes (for replay protection)
    seen_signatures: HashSet<String>,
    /// Verification statistics
    stats: VerificationStats,
}

/// Verification statistics
#[derive(Debug, Clone, Default)]
pub struct VerificationStats {
    /// Total verifications performed
    pub total_verifications: u64,
    /// Successful verifications
    pub successful_verifications: u64,
    /// Failed verifications
    pub failed_verifications: u64,
    /// Replay attempts blocked
    pub replay_attempts_blocked: u64,
    /// Expired signatures rejected
    pub expired_signatures_rejected: u64,
}

impl SignatureIntegrityVerifier {
    /// Create a new verifier with default config
    pub fn new() -> Self {
        Self::with_config(IntegrityVerifierConfig::default())
    }

    /// Create with custom config
    pub fn with_config(config: IntegrityVerifierConfig) -> Self {
        Self {
            config,
            seen_signatures: HashSet::new(),
            stats: VerificationStats::default(),
        }
    }

    /// Verify a threshold signature with full integrity checks
    pub fn verify_with_integrity(
        &mut self,
        message: &[u8],
        agg_sig: &AggregatedBlsSignature,
        signer_set: &SignerSet,
        signed_at: Option<DateTime<Utc>>,
    ) -> SignatureIntegrityResult {
        self.stats.total_verifications += 1;

        let mut result = SignatureIntegrityResult {
            is_valid: false,
            verified_at: Utc::now(),
            signer_set_version: signer_set.version_string(),
            valid_signature_count: 0,
            threshold: signer_set.threshold(),
            participating_signers: agg_sig.signer_pubkeys.clone(),
            errors: Vec::new(),
            warnings: Vec::new(),
            message_digest: hex::encode(sha256_digest(message)),
            freshness_valid: true,
            replay_protection_valid: true,
        };

        // Check 1: Threshold met
        if !agg_sig.threshold_met() {
            result.errors.push(SignatureVerificationError::ThresholdNotMet {
                got: agg_sig.signer_count,
                need: agg_sig.threshold,
            });
        }

        // Check 2: Bitmap consistency
        let bitmap_signer_count = agg_sig.signer_bitmap.chars().filter(|&c| c == '1').count() as u32;
        if bitmap_signer_count != agg_sig.signer_count {
            result.errors.push(SignatureVerificationError::SignerCountMismatch {
                bitmap_count: bitmap_signer_count,
                pubkey_count: agg_sig.signer_count,
            });
        }

        // Check 3: All signers are certified
        if self.config.require_certified_signers {
            for pubkey in &agg_sig.signer_pubkeys {
                if !signer_set.is_certified_signer(pubkey) {
                    if signer_set.is_observer(pubkey) {
                        result.warnings.push(format!(
                            "Signer {} is an observer, not a certified signer",
                            &pubkey[..8]
                        ));
                    } else {
                        result.errors.push(SignatureVerificationError::InvalidSigner {
                            pubkey: pubkey.clone(),
                            reason: "Not in certified signer set".to_string(),
                        });
                    }
                }
            }
        }

        // Check 4: Freshness (if signed_at provided)
        if let Some(signed_at) = signed_at {
            if self.config.max_signature_age_secs > 0 {
                let age = (Utc::now() - signed_at).num_seconds();
                if age > self.config.max_signature_age_secs {
                    result.freshness_valid = false;
                    result.errors.push(SignatureVerificationError::SignatureExpired {
                        signed_at,
                        max_age: self.config.max_signature_age_secs,
                    });
                    self.stats.expired_signatures_rejected += 1;
                }
            }
        }

        // Check 5: Replay protection
        if self.config.replay_protection_enabled {
            let sig_hash = sha256_hex(&agg_sig.signature);
            if self.seen_signatures.contains(&sig_hash) {
                result.replay_protection_valid = false;
                result.errors.push(SignatureVerificationError::ReplayDetected {
                    signature_hash: sig_hash,
                });
                self.stats.replay_attempts_blocked += 1;
            } else {
                // Add to seen set (with size limit)
                if self.seen_signatures.len() >= self.config.replay_cache_size {
                    // Remove oldest entry (simple approach - could use LRU)
                    if let Some(oldest) = self.seen_signatures.iter().next().cloned() {
                        self.seen_signatures.remove(&oldest);
                    }
                }
                self.seen_signatures.insert(sig_hash);
            }
        }

        // Check 6: Cryptographic verification
        if result.errors.is_empty() || !self.config.strict_mode {
            match verify_threshold_signature(message, agg_sig) {
                Ok(true) => {
                    result.is_valid = true;
                    result.valid_signature_count = agg_sig.signer_count;
                }
                Ok(false) => {
                    result.errors.push(SignatureVerificationError::CryptographicFailure {
                        details: "Signature verification returned false".to_string(),
                    });
                }
                Err(e) => {
                    result.errors.push(SignatureVerificationError::CryptographicFailure {
                        details: e.to_string(),
                    });
                }
            }
        }

        // Update stats
        if result.all_checks_passed() {
            self.stats.successful_verifications += 1;
        } else {
            self.stats.failed_verifications += 1;
        }

        result
    }

    /// Verify individual signature shares before aggregation
    pub fn verify_shares(
        &self,
        message: &[u8],
        shares: &[ThresholdSignatureShare],
        signer_set: &SignerSet,
    ) -> ShareVerificationResult {
        let mut result = ShareVerificationResult {
            total_shares: shares.len(),
            valid_shares: 0,
            invalid_shares: Vec::new(),
            duplicate_signers: Vec::new(),
        };

        let mut seen_indices = HashSet::new();
        let mut seen_pubkeys = HashSet::new();

        for share in shares {
            // Check for duplicate signer index
            if seen_indices.contains(&share.signer_index) {
                result.duplicate_signers.push(share.signer_index);
                continue;
            }
            seen_indices.insert(share.signer_index);

            // Check for duplicate pubkey
            if seen_pubkeys.contains(&share.signer_pubkey) {
                result.duplicate_signers.push(share.signer_index);
                continue;
            }
            seen_pubkeys.insert(share.signer_pubkey.clone());

            // Check signer is certified
            if self.config.require_certified_signers {
                if !signer_set.is_certified_signer(&share.signer_pubkey) {
                    result.invalid_shares.push(InvalidShare {
                        signer_index: share.signer_index,
                        reason: "Not in certified signer set".to_string(),
                    });
                    continue;
                }
            }

            // Verify the share cryptographically
            match self.verify_single_share(message, share) {
                Ok(()) => result.valid_shares += 1,
                Err(e) => {
                    result.invalid_shares.push(InvalidShare {
                        signer_index: share.signer_index,
                        reason: e.to_string(),
                    });
                }
            }
        }

        result
    }

    /// Verify a single signature share
    fn verify_single_share(
        &self,
        message: &[u8],
        share: &ThresholdSignatureShare,
    ) -> SignerResult<()> {
        let pubkey = share.get_pubkey()?;
        let signature = share.get_signature()?;
        pubkey.verify(message, &signature)
    }

    /// Get verification statistics
    pub fn stats(&self) -> &VerificationStats {
        &self.stats
    }

    /// Reset verification statistics
    pub fn reset_stats(&mut self) {
        self.stats = VerificationStats::default();
    }

    /// Clear replay protection cache
    pub fn clear_replay_cache(&mut self) {
        self.seen_signatures.clear();
    }

    /// Get replay cache size
    pub fn replay_cache_size(&self) -> usize {
        self.seen_signatures.len()
    }
}

impl Default for SignatureIntegrityVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of share verification
#[derive(Debug, Clone)]
pub struct ShareVerificationResult {
    /// Total shares submitted
    pub total_shares: usize,
    /// Number of valid shares
    pub valid_shares: usize,
    /// Invalid shares with reasons
    pub invalid_shares: Vec<InvalidShare>,
    /// Duplicate signer indices
    pub duplicate_signers: Vec<u32>,
}

impl ShareVerificationResult {
    /// Check if enough valid shares for threshold
    pub fn meets_threshold(&self, threshold: u32) -> bool {
        self.valid_shares as u32 >= threshold
    }

    /// Get valid share percentage
    pub fn validity_rate(&self) -> f64 {
        if self.total_shares == 0 {
            return 0.0;
        }
        self.valid_shares as f64 / self.total_shares as f64
    }
}

/// Invalid share details
#[derive(Debug, Clone)]
pub struct InvalidShare {
    /// Signer index
    pub signer_index: u32,
    /// Reason for invalidity
    pub reason: String,
}

/// Signer accountability record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerAccountabilityRecord {
    /// Signer public key
    pub signer_pubkey: String,
    /// Signer index
    pub signer_index: u32,
    /// Message digest that was signed
    pub message_digest: String,
    /// Signature timestamp
    pub signed_at: DateTime<Utc>,
    /// Verification timestamp
    pub verified_at: DateTime<Utc>,
    /// Signer set version at time of signing
    pub signer_set_version: String,
}

/// Accountability ledger for tracking signer participation
#[derive(Debug, Default)]
pub struct SignerAccountabilityLedger {
    /// Records by message digest
    records: HashMap<String, Vec<SignerAccountabilityRecord>>,
    /// Total records
    total_records: u64,
}

impl SignerAccountabilityLedger {
    /// Create a new ledger
    pub fn new() -> Self {
        Self::default()
    }

    /// Record signer participation
    pub fn record_participation(
        &mut self,
        message_digest: &str,
        signer_pubkey: &str,
        signer_index: u32,
        signed_at: DateTime<Utc>,
        signer_set_version: &str,
    ) {
        let record = SignerAccountabilityRecord {
            signer_pubkey: signer_pubkey.to_string(),
            signer_index,
            message_digest: message_digest.to_string(),
            signed_at,
            verified_at: Utc::now(),
            signer_set_version: signer_set_version.to_string(),
        };

        self.records
            .entry(message_digest.to_string())
            .or_insert_with(Vec::new)
            .push(record);

        self.total_records += 1;
    }

    /// Get records for a message
    pub fn get_records(&self, message_digest: &str) -> Option<&Vec<SignerAccountabilityRecord>> {
        self.records.get(message_digest)
    }

    /// Get all signers who signed a message
    pub fn get_signers_for_message(&self, message_digest: &str) -> Vec<String> {
        self.records
            .get(message_digest)
            .map(|records| {
                records
                    .iter()
                    .map(|r| r.signer_pubkey.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get total record count
    pub fn total_records(&self) -> u64 {
        self.total_records
    }
}

/// Compute SHA-256 digest of data
fn sha256_digest(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Compute SHA-256 hex string
fn sha256_hex(data: &str) -> String {
    hex::encode(sha256_digest(data.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::{BlsSecretKey, BlsThresholdSigner, create_threshold_signature};
    use crate::signer_set::SignerInfo;

    fn make_test_signer_set() -> SignerSet {
        let signers: Vec<SignerInfo> = (0..9)
            .map(|i| SignerInfo {
                pubkey: format!("pubkey_{}", i),
                node_id: format!("node_{}", i),
                is_observer: false,
                added_at: Utc::now(),
            })
            .collect();

        SignerSet::new(
            "test".to_string(),
            1,
            signers,
            vec![],
            Utc::now(),
            None,
        ).unwrap()
    }

    #[test]
    fn test_integrity_verifier_config() {
        let config = IntegrityVerifierConfig::default();
        assert_eq!(config.max_signature_age_secs, 3600);
        assert!(config.replay_protection_enabled);
        assert!(config.strict_mode);
    }

    #[test]
    fn test_verification_stats() {
        let mut verifier = SignatureIntegrityVerifier::new();
        assert_eq!(verifier.stats().total_verifications, 0);
        assert_eq!(verifier.stats().successful_verifications, 0);
    }

    #[test]
    fn test_accountability_ledger() {
        let mut ledger = SignerAccountabilityLedger::new();

        ledger.record_participation(
            "digest123",
            "pubkey_0",
            1,
            Utc::now(),
            "test:1",
        );

        assert_eq!(ledger.total_records(), 1);
        let signers = ledger.get_signers_for_message("digest123");
        assert_eq!(signers.len(), 1);
        assert_eq!(signers[0], "pubkey_0");
    }

    #[test]
    fn test_signature_verification_error_display() {
        let err = SignatureVerificationError::ThresholdNotMet { got: 3, need: 5 };
        assert!(err.to_string().contains("Threshold not met"));

        let err = SignatureVerificationError::SignatureExpired {
            signed_at: Utc::now(),
            max_age: 3600,
        };
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn test_share_verification_result() {
        let result = ShareVerificationResult {
            total_shares: 10,
            valid_shares: 6,
            invalid_shares: vec![],
            duplicate_signers: vec![],
        };

        assert!(result.meets_threshold(5));
        assert!(!result.meets_threshold(7));
        assert!((result.validity_rate() - 0.6).abs() < 0.001);
    }
}
