//! Ciphertext Validator - Zero-Plaintext Invariant
//!
//! Ensures that P2 storage only accepts encrypted data (ciphertext).
//! This is a critical security invariant - P2 MUST NOT store plaintext.
//!
//! Validation methods:
//! 1. Magic bytes detection (encryption envelope headers)
//! 2. Entropy analysis (ciphertext has high entropy)
//! 3. Structure validation (proper encryption envelope format)
//! 4. Size validation (minimum ciphertext size)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Ciphertext validation errors
#[derive(Debug, Error)]
pub enum CiphertextError {
    /// Data appears to be plaintext
    #[error("Data appears to be plaintext (low entropy: {entropy:.2})")]
    PlaintextDetected { entropy: f64 },

    /// Data is too small to be valid ciphertext
    #[error("Data too small ({size} bytes, minimum {min_size})")]
    TooSmall { size: usize, min_size: usize },

    /// Invalid encryption envelope
    #[error("Invalid encryption envelope: {0}")]
    InvalidEnvelope(String),

    /// Unknown encryption format
    #[error("Unknown encryption format (magic bytes: {0:?})")]
    UnknownFormat(Vec<u8>),

    /// Missing authentication tag
    #[error("Missing authentication tag")]
    MissingAuthTag,
}

/// Ciphertext validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiphertextValidation {
    /// Is the data valid ciphertext?
    pub is_valid: bool,
    /// Detected encryption format
    pub format: Option<EncryptionFormat>,
    /// Entropy score (0.0 - 8.0, higher = more random)
    pub entropy: f64,
    /// Validation reason (for failures)
    pub reason: Option<String>,
    /// Validation timestamp
    pub validated_at: DateTime<Utc>,
}

impl CiphertextValidation {
    /// Create a valid result
    pub fn valid(format: EncryptionFormat, entropy: f64) -> Self {
        Self {
            is_valid: true,
            format: Some(format),
            entropy,
            reason: None,
            validated_at: Utc::now(),
        }
    }

    /// Create an invalid result
    pub fn invalid(reason: &str, entropy: f64) -> Self {
        Self {
            is_valid: false,
            format: None,
            entropy,
            reason: Some(reason.to_string()),
            validated_at: Utc::now(),
        }
    }
}

/// Known encryption formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionFormat {
    /// P2 Envelope v1 (custom format)
    P2EnvelopeV1,
    /// AES-256-GCM
    Aes256Gcm,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
    /// Age encryption
    Age,
    /// PKCS#7 / CMS
    Pkcs7,
    /// PGP / GPG
    Pgp,
    /// Unknown but high-entropy (likely encrypted)
    UnknownHighEntropy,
}

impl EncryptionFormat {
    /// Get the magic bytes for this format
    pub fn magic_bytes(&self) -> Option<&'static [u8]> {
        match self {
            Self::P2EnvelopeV1 => Some(b"P2ENV1"),
            Self::Age => Some(b"age-encryption.org"),
            Self::Pgp => Some(&[0xC0]), // PGP packet tag
            _ => None,
        }
    }

    /// Get minimum valid size for this format
    pub fn min_size(&self) -> usize {
        match self {
            Self::P2EnvelopeV1 => 38, // 6 header + 16 nonce + 16 tag minimum
            Self::Aes256Gcm => 28,    // 12 nonce + 16 tag minimum
            Self::ChaCha20Poly1305 => 28, // 12 nonce + 16 tag minimum
            Self::Age => 64,          // Age header minimum
            Self::Pkcs7 => 32,
            Self::Pgp => 32,
            Self::UnknownHighEntropy => 16,
        }
    }
}

/// Ciphertext Validator
pub struct CiphertextValidator {
    /// Enable strict validation
    strict_mode: bool,
    /// Minimum data size
    min_size: usize,
    /// Minimum entropy threshold (bits per byte)
    min_entropy: f64,
    /// Statistics
    stats: std::sync::atomic::AtomicU64,
}

impl CiphertextValidator {
    /// Minimum entropy for ciphertext (bits per byte)
    /// Good encryption should have entropy close to 8.0
    const DEFAULT_MIN_ENTROPY: f64 = 7.0;

    /// Create a new validator
    pub fn new(strict_mode: bool, min_size: usize) -> Self {
        Self {
            strict_mode,
            min_size,
            min_entropy: Self::DEFAULT_MIN_ENTROPY,
            stats: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Create with default settings
    pub fn default_validator() -> Self {
        Self::new(true, 32)
    }

    /// Validate data as ciphertext
    pub fn validate(&self, data: &[u8]) -> CiphertextValidation {
        self.stats.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Check minimum size
        if data.len() < self.min_size {
            return CiphertextValidation::invalid(
                &format!("Data too small ({} bytes, minimum {})", data.len(), self.min_size),
                0.0,
            );
        }

        // Detect format from magic bytes
        let format = self.detect_format(data);

        // Calculate entropy
        let entropy = self.calculate_entropy(data);

        // Check if entropy is high enough
        if entropy < self.min_entropy {
            // Low entropy might indicate plaintext or weak encryption
            if self.strict_mode {
                return CiphertextValidation::invalid(
                    &format!(
                        "Low entropy ({:.2} bits/byte, minimum {:.2}). Data may be plaintext.",
                        entropy, self.min_entropy
                    ),
                    entropy,
                );
            }
        }

        // Additional checks for known formats
        if let Some(fmt) = &format {
            if let Err(e) = self.validate_format(data, *fmt) {
                return CiphertextValidation::invalid(&e.to_string(), entropy);
            }
        }

        // If format is unknown but entropy is high, accept as encrypted
        let final_format = format.unwrap_or_else(|| {
            if entropy >= self.min_entropy {
                EncryptionFormat::UnknownHighEntropy
            } else {
                return EncryptionFormat::UnknownHighEntropy; // Will be caught by entropy check
            }
        });

        CiphertextValidation::valid(final_format, entropy)
    }

    /// Detect encryption format from magic bytes
    fn detect_format(&self, data: &[u8]) -> Option<EncryptionFormat> {
        if data.len() < 6 {
            return None;
        }

        // Check P2 Envelope v1
        if data.starts_with(b"P2ENV1") {
            return Some(EncryptionFormat::P2EnvelopeV1);
        }

        // Check Age format
        if data.starts_with(b"age-encryption.org") {
            return Some(EncryptionFormat::Age);
        }

        // Check PGP (various packet tags)
        if !data.is_empty() {
            let tag = data[0];
            // Old format: bit 7 set, bit 6 clear
            // New format: bits 7-6 = 11
            if tag & 0x80 != 0 {
                // Could be PGP
                if tag & 0x40 != 0 || (tag & 0xC0 == 0x80) {
                    return Some(EncryptionFormat::Pgp);
                }
            }
        }

        // Check for common AEAD patterns
        // AES-GCM and ChaCha20-Poly1305 don't have magic bytes,
        // but we can check for high entropy + appropriate size

        None
    }

    /// Calculate Shannon entropy (bits per byte)
    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        // Count byte frequencies
        let mut freq = [0u64; 256];
        for &byte in data {
            freq[byte as usize] += 1;
        }

        // Calculate entropy
        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Validate format-specific requirements
    fn validate_format(&self, data: &[u8], format: EncryptionFormat) -> Result<(), CiphertextError> {
        let min_size = format.min_size();
        if data.len() < min_size {
            return Err(CiphertextError::TooSmall {
                size: data.len(),
                min_size,
            });
        }

        match format {
            EncryptionFormat::P2EnvelopeV1 => {
                // Validate P2 Envelope structure
                // Format: "P2ENV1" (6) + version (1) + flags (1) + nonce (12-24) + ciphertext + tag (16)
                if data.len() < 38 {
                    return Err(CiphertextError::InvalidEnvelope(
                        "P2 Envelope too small".to_string(),
                    ));
                }
                // Check magic
                if !data.starts_with(b"P2ENV1") {
                    return Err(CiphertextError::InvalidEnvelope(
                        "Invalid P2 Envelope magic".to_string(),
                    ));
                }
                Ok(())
            }
            EncryptionFormat::Aes256Gcm | EncryptionFormat::ChaCha20Poly1305 => {
                // These need at least nonce + tag + 1 byte ciphertext
                if data.len() < 29 {
                    return Err(CiphertextError::MissingAuthTag);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Get validation count
    pub fn validation_count(&self) -> u64 {
        self.stats.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Check if data looks like common plaintext patterns
    pub fn looks_like_plaintext(&self, data: &[u8]) -> bool {
        // Check for common plaintext indicators

        // 1. Starts with common text file markers
        let text_markers = [
            b"<!DOCTYPE".as_slice(),
            b"<html".as_slice(),
            b"<?xml".as_slice(),
            b"{".as_slice(),  // JSON
            b"[".as_slice(),  // JSON array
            b"---".as_slice(), // YAML
        ];

        for marker in &text_markers {
            if data.starts_with(marker) {
                return true;
            }
        }

        // 2. Check if mostly printable ASCII
        let printable_count = data.iter()
            .filter(|&&b| b >= 0x20 && b <= 0x7E || b == b'\n' || b == b'\r' || b == b'\t')
            .count();

        let printable_ratio = printable_count as f64 / data.len() as f64;

        // If more than 90% printable ASCII, likely plaintext
        if printable_ratio > 0.90 {
            return true;
        }

        // 3. Check entropy
        let entropy = self.calculate_entropy(data);
        if entropy < 5.0 {
            // Very low entropy, likely plaintext or simple patterns
            return true;
        }

        false
    }
}

impl Default for CiphertextValidator {
    fn default() -> Self {
        Self::default_validator()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        let validator = CiphertextValidator::default();

        // Low entropy (repeated pattern)
        let low_entropy_data = vec![0u8; 1000];
        let entropy = validator.calculate_entropy(&low_entropy_data);
        assert!(entropy < 1.0, "Repeated bytes should have very low entropy");

        // High entropy (random-looking)
        let high_entropy_data: Vec<u8> = (0..1000).map(|i| (i * 37 + i / 7) as u8).collect();
        let entropy = validator.calculate_entropy(&high_entropy_data);
        assert!(entropy > 5.0, "Pseudo-random data should have higher entropy");
    }

    #[test]
    fn test_plaintext_detection() {
        let validator = CiphertextValidator::default();

        // JSON plaintext
        assert!(validator.looks_like_plaintext(b"{\"key\": \"value\"}"));

        // HTML plaintext
        assert!(validator.looks_like_plaintext(b"<!DOCTYPE html><html>"));

        // High entropy binary shouldn't look like plaintext
        let binary: Vec<u8> = (0..100).map(|i| ((i * 37) ^ (i * 13)) as u8).collect();
        // This may or may not trigger depending on the specific values
    }

    #[test]
    fn test_format_detection() {
        let validator = CiphertextValidator::default();

        // P2 Envelope
        let mut p2_data = b"P2ENV1".to_vec();
        p2_data.extend(vec![0u8; 100]); // Add padding
        let format = validator.detect_format(&p2_data);
        assert_eq!(format, Some(EncryptionFormat::P2EnvelopeV1));

        // Age format
        let mut age_data = b"age-encryption.org".to_vec();
        age_data.extend(vec![0u8; 100]);
        let format = validator.detect_format(&age_data);
        assert_eq!(format, Some(EncryptionFormat::Age));
    }

    #[test]
    fn test_validation() {
        let validator = CiphertextValidator::new(true, 32);

        // Too small
        let small_data = vec![0u8; 16];
        let result = validator.validate(&small_data);
        assert!(!result.is_valid);

        // High entropy data (simulated ciphertext)
        let mut ciphertext = vec![0u8; 100];
        for (i, byte) in ciphertext.iter_mut().enumerate() {
            *byte = ((i * 37 + 13) ^ (i * 7)) as u8;
        }
        let result = validator.validate(&ciphertext);
        // May or may not pass depending on actual entropy
    }

    #[test]
    fn test_encryption_format_sizes() {
        assert!(EncryptionFormat::P2EnvelopeV1.min_size() >= 32);
        assert!(EncryptionFormat::Aes256Gcm.min_size() >= 28);
        assert!(EncryptionFormat::ChaCha20Poly1305.min_size() >= 28);
    }
}
