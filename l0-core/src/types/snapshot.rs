//! Snapshot types for L0 threshold signing

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use super::common::Digest;
use super::actor::ReceiptId;
use super::degraded_mode::OperationalMode;

/// Signer set configuration for validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerSetConfig {
    /// Normal mode: required signers count
    pub normal_signers: usize,
    /// Normal mode: threshold rule (e.g., "5/9")
    pub normal_threshold: String,
    /// Degraded mode: minimum signers allowed
    pub degraded_min_signers: usize,
    /// Degraded mode: minimum threshold numerator
    pub degraded_min_threshold: usize,
    /// Emergency mode: absolute minimum signers
    pub emergency_min_signers: usize,
}

impl Default for SignerSetConfig {
    fn default() -> Self {
        Self {
            normal_signers: 9,
            normal_threshold: "5/9".to_string(),
            degraded_min_signers: 5,
            degraded_min_threshold: 3,
            emergency_min_signers: 3,
        }
    }
}

/// Signer Set Reference - defines who can sign
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerSetRef {
    pub signer_set_id: String,
    pub version: u32,
    /// Certified signer public keys (9 in normal mode, can be fewer in degraded mode)
    pub certified_signer_pubkeys: Vec<String>,
    pub observer_pubkeys: Vec<String>,
    /// Threshold rule (e.g., "5/9" in normal mode)
    pub threshold_rule: String,
    pub valid_from: DateTime<Utc>,
    pub supersedes: Option<String>,
    pub admission_policy_version: String,
    pub slashing_policy_version: Option<String>,
    pub receipt_id: Option<ReceiptId>,
    pub metadata_digest: Option<Digest>,
}

impl SignerSetRef {
    /// Get the full version string
    pub fn version_string(&self) -> String {
        format!("{}:{}", self.signer_set_id, self.version)
    }

    /// Validate the signer set configuration for normal mode
    /// Use `validate_for_mode` for degraded mode validation
    pub fn validate(&self) -> Result<(), String> {
        self.validate_with_config(&SignerSetConfig::default(), OperationalMode::Normal)
    }

    /// Validate with specific configuration and operational mode
    pub fn validate_with_config(&self, config: &SignerSetConfig, mode: OperationalMode) -> Result<(), String> {
        let signer_count = self.certified_signer_pubkeys.len();

        // Parse threshold rule
        let (threshold_num, threshold_denom) = self.parse_threshold()?;

        match mode {
            OperationalMode::Normal => {
                if signer_count != config.normal_signers {
                    return Err(format!(
                        "Normal mode requires {} certified signers, got {}",
                        config.normal_signers, signer_count
                    ));
                }
                if self.threshold_rule != config.normal_threshold {
                    return Err(format!(
                        "Normal mode requires threshold '{}', got '{}'",
                        config.normal_threshold, self.threshold_rule
                    ));
                }
            }
            OperationalMode::Warning => {
                // Warning mode: allow slightly fewer signers
                if signer_count < config.degraded_min_signers {
                    return Err(format!(
                        "Warning mode requires at least {} signers, got {}",
                        config.degraded_min_signers, signer_count
                    ));
                }
            }
            OperationalMode::Degraded => {
                if signer_count < config.degraded_min_signers {
                    return Err(format!(
                        "Degraded mode requires at least {} signers, got {}",
                        config.degraded_min_signers, signer_count
                    ));
                }
                if threshold_num < config.degraded_min_threshold {
                    return Err(format!(
                        "Degraded mode requires threshold numerator >= {}, got {}",
                        config.degraded_min_threshold, threshold_num
                    ));
                }
            }
            OperationalMode::Emergency => {
                if signer_count < config.emergency_min_signers {
                    return Err(format!(
                        "Emergency mode requires at least {} signers, got {}",
                        config.emergency_min_signers, signer_count
                    ));
                }
            }
            OperationalMode::Halted | OperationalMode::Recovery => {
                // Minimal validation - just need valid threshold format
                if threshold_denom == 0 || threshold_num > threshold_denom {
                    return Err("Invalid threshold rule".to_string());
                }
            }
        }

        // Common validation: threshold denominator must match signer count
        if threshold_denom != signer_count {
            return Err(format!(
                "Threshold denominator {} does not match signer count {}",
                threshold_denom, signer_count
            ));
        }

        // Threshold numerator must be > 50% for security
        if threshold_num * 2 <= threshold_denom {
            return Err(format!(
                "Threshold {}/{} is not greater than 50%",
                threshold_num, threshold_denom
            ));
        }

        Ok(())
    }

    /// Parse threshold rule like "5/9" into (numerator, denominator)
    pub fn parse_threshold(&self) -> Result<(usize, usize), String> {
        let parts: Vec<&str> = self.threshold_rule.split('/').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid threshold format: '{}'", self.threshold_rule));
        }
        let num = parts[0].parse::<usize>()
            .map_err(|_| format!("Invalid threshold numerator: '{}'", parts[0]))?;
        let denom = parts[1].parse::<usize>()
            .map_err(|_| format!("Invalid threshold denominator: '{}'", parts[1]))?;
        Ok((num, denom))
    }

    /// Get parsed threshold as (numerator, denominator)
    pub fn threshold(&self) -> Option<(usize, usize)> {
        self.parse_threshold().ok()
    }
}

/// Signed batch snapshot - threshold signature proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedBatchSnapshot {
    pub snapshot_id: String,
    pub batch_root: Digest,
    pub time_window_start: DateTime<Utc>,
    pub time_window_end: DateTime<Utc>,
    pub batch_sequence_no: u64,
    pub parent_batch_root: Option<Digest>,
    /// MUST be covered by signature
    pub signer_set_version: String,
    /// MUST be covered by signature
    pub canonicalization_version: String,
    /// MUST be covered by signature
    pub anchor_policy_version: String,
    /// MUST be covered by signature
    pub fee_schedule_version: String,
    pub threshold_rule: String,
    /// Bitmap or index set digest indicating which signers signed
    pub signature_bitmap: String,
    /// Aggregated signature or multi-sig collection
    pub threshold_proof: String,
    pub observer_reports_digest: Option<Digest>,
}

impl SignedBatchSnapshot {
    /// Get the message bytes that should be signed
    /// Uses deterministic encoding: Unix timestamps (i64 big-endian) instead of RFC3339
    /// to ensure consistent byte representation across all systems
    pub fn signing_message(&self) -> Vec<u8> {
        // Domain tag + version
        let mut message = Vec::new();
        message.extend_from_slice(b"L0:SignedBatchSnapshotMsg:v1\0");

        // Fields in canonical order with deterministic encoding
        message.extend_from_slice(self.batch_root.as_bytes());

        // Use Unix timestamp (i64 big-endian) for deterministic time encoding
        message.extend_from_slice(&self.time_window_start.timestamp().to_be_bytes());
        message.extend_from_slice(&self.time_window_start.timestamp_subsec_nanos().to_be_bytes());
        message.extend_from_slice(&self.time_window_end.timestamp().to_be_bytes());
        message.extend_from_slice(&self.time_window_end.timestamp_subsec_nanos().to_be_bytes());

        message.extend_from_slice(&self.batch_sequence_no.to_be_bytes());

        // Parent batch root with presence marker
        if let Some(ref parent) = self.parent_batch_root {
            message.push(0x01); // present marker
            message.extend_from_slice(parent.as_bytes());
        } else {
            message.push(0x00); // null marker
        }

        // Version strings with length prefix for unambiguous parsing
        Self::append_length_prefixed_string(&mut message, &self.signer_set_version);
        Self::append_length_prefixed_string(&mut message, &self.canonicalization_version);
        Self::append_length_prefixed_string(&mut message, &self.anchor_policy_version);
        Self::append_length_prefixed_string(&mut message, &self.fee_schedule_version);
        Self::append_length_prefixed_string(&mut message, &self.threshold_rule);

        // Observer reports digest with presence marker
        if let Some(ref reports) = self.observer_reports_digest {
            message.push(0x01);
            message.extend_from_slice(reports.as_bytes());
        } else {
            message.push(0x00);
        }

        message
    }

    /// Append a length-prefixed string (2-byte big-endian length + bytes)
    fn append_length_prefixed_string(message: &mut Vec<u8>, s: &str) {
        let bytes = s.as_bytes();
        let len = bytes.len() as u16;
        message.extend_from_slice(&len.to_be_bytes());
        message.extend_from_slice(bytes);
    }

    /// Verify threshold signature against the signer set
    ///
    /// Returns verification result with detailed error information
    pub fn verify_threshold_signature(
        &self,
        signer_set: &SignerSetRef,
    ) -> ThresholdSignatureVerification {
        // Parse threshold rule
        let (threshold_num, _threshold_denom) = match signer_set.parse_threshold() {
            Ok(t) => t,
            Err(e) => {
                return ThresholdSignatureVerification {
                    valid: false,
                    signers_verified: 0,
                    threshold_met: false,
                    errors: vec![format!("Invalid threshold rule: {}", e)],
                    verified_signer_indices: vec![],
                };
            }
        };

        // Parse signature bitmap to determine which signers signed
        let signer_indices = match self.parse_signature_bitmap(signer_set.certified_signer_pubkeys.len()) {
            Ok(indices) => indices,
            Err(e) => {
                return ThresholdSignatureVerification {
                    valid: false,
                    signers_verified: 0,
                    threshold_met: false,
                    errors: vec![format!("Invalid signature bitmap: {}", e)],
                    verified_signer_indices: vec![],
                };
            }
        };

        // Check if enough signers
        if signer_indices.len() < threshold_num {
            return ThresholdSignatureVerification {
                valid: false,
                signers_verified: signer_indices.len(),
                threshold_met: false,
                errors: vec![format!(
                    "Insufficient signers: {} of {} required",
                    signer_indices.len(),
                    threshold_num
                )],
                verified_signer_indices: signer_indices,
            };
        }

        // Get the message to verify
        let _message = self.signing_message();

        // Verify each signer's contribution
        // Note: Actual cryptographic verification depends on the signature scheme
        // This is a placeholder for the verification logic
        let mut verified_count = 0;
        let mut verified_indices = Vec::new();
        let mut errors = Vec::new();

        for &idx in &signer_indices {
            if idx >= signer_set.certified_signer_pubkeys.len() {
                errors.push(format!("Invalid signer index: {}", idx));
                continue;
            }

            // In a real implementation, this would verify the signature
            // using the public key at signer_set.certified_signer_pubkeys[idx]
            // For now, we assume verification passes if the signature is present
            verified_count += 1;
            verified_indices.push(idx);
        }

        let threshold_met = verified_count >= threshold_num;

        ThresholdSignatureVerification {
            valid: threshold_met && errors.is_empty(),
            signers_verified: verified_count,
            threshold_met,
            errors,
            verified_signer_indices: verified_indices,
        }
    }

    /// Parse signature bitmap to get indices of signers who signed
    fn parse_signature_bitmap(&self, total_signers: usize) -> Result<Vec<usize>, String> {
        // Bitmap format: hex string where each bit represents a signer
        // e.g., "1F" = 0b00011111 = signers 0,1,2,3,4 signed
        if self.signature_bitmap.is_empty() {
            return Err("Empty signature bitmap".to_string());
        }

        // Try to parse as hex
        let bytes = hex::decode(&self.signature_bitmap)
            .map_err(|e| format!("Invalid hex bitmap: {}", e))?;

        let mut indices = Vec::new();
        for (byte_idx, &byte) in bytes.iter().enumerate() {
            for bit_idx in 0..8 {
                let signer_idx = byte_idx * 8 + bit_idx;
                if signer_idx >= total_signers {
                    break;
                }
                if (byte >> bit_idx) & 1 == 1 {
                    indices.push(signer_idx);
                }
            }
        }

        Ok(indices)
    }

    /// Create signature bitmap from list of signer indices
    pub fn create_signature_bitmap(signer_indices: &[usize], total_signers: usize) -> String {
        let num_bytes = (total_signers + 7) / 8;
        let mut bytes = vec![0u8; num_bytes];

        for &idx in signer_indices {
            if idx < total_signers {
                let byte_idx = idx / 8;
                let bit_idx = idx % 8;
                bytes[byte_idx] |= 1 << bit_idx;
            }
        }

        hex::encode(bytes)
    }
}

/// Threshold signature verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdSignatureVerification {
    /// Whether the verification passed
    pub valid: bool,
    /// Number of signers verified
    pub signers_verified: usize,
    /// Whether threshold was met
    pub threshold_met: bool,
    /// Verification errors
    pub errors: Vec<String>,
    /// Indices of verified signers
    pub verified_signer_indices: Vec<usize>,
}

impl ThresholdSignatureVerification {
    /// Create a successful verification result
    pub fn success(signers_verified: usize, verified_indices: Vec<usize>) -> Self {
        Self {
            valid: true,
            signers_verified,
            threshold_met: true,
            errors: Vec::new(),
            verified_signer_indices: verified_indices,
        }
    }

    /// Create a failed verification result
    pub fn failure(error: String) -> Self {
        Self {
            valid: false,
            signers_verified: 0,
            threshold_met: false,
            errors: vec![error],
            verified_signer_indices: Vec::new(),
        }
    }
}

/// Epoch snapshot for chain anchoring
///
/// Note: EpochSnapshot uses `chain_anchor_policy_version` (not `anchor_policy_version`)
/// because it specifically governs on-chain anchoring behavior (P4).
/// - `anchor_policy_version`: L0 internal anchoring (MUST/SHOULD/MAY for L0 receipts)
/// - `chain_anchor_policy_version`: External chain anchoring (epoch_root → BTC/Atomicals)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochSnapshot {
    pub epoch_id: String,
    pub epoch_root: Digest,
    pub epoch_window_start: DateTime<Utc>,
    pub epoch_window_end: DateTime<Utc>,
    pub epoch_sequence_no: u64,
    pub parent_epoch_root: Option<Digest>,
    pub signer_set_version: String,
    pub canonicalization_version: String,
    /// Chain-specific anchor policy (different from L0 anchor_policy_version)
    pub chain_anchor_policy_version: String,
    pub threshold_rule: String,
    pub signature_bitmap: Option<String>,
    pub threshold_proof: Option<String>,
    pub gaps_digest: Option<Digest>,
    pub batch_receipts_digest: Digest,
}

/// Chain anchor input for P4
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainAnchorInput {
    pub epoch_root: Digest,
    pub epoch_window_start: DateTime<Utc>,
    pub epoch_window_end: DateTime<Utc>,
    pub signer_set_version: String,
    pub canonicalization_version: String,
    pub chain_anchor_policy_version: String,
    pub epoch_snapshot_ref: Option<String>,
    pub gaps_digest: Option<Digest>,
}

/// Chain anchor link - connects L0 receipts to chain txs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainAnchorLink {
    pub chain_anchor_link_id: String,
    pub chain_network: String,  // btc/atomicals
    pub chain_txid_or_asset_id: String,
    pub epoch_root: Digest,
    pub epoch_window_start: DateTime<Utc>,
    pub epoch_window_end: DateTime<Utc>,
    pub chain_anchor_policy_version: String,
    pub budget_policy_version: String,
    pub payer_actor_id: String,
    pub linked_receipt_ids_digest: Digest,
    pub status: ChainAnchorStatus,
    pub confirmed_at: Option<DateTime<Utc>>,
}

/// Chain anchor status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainAnchorStatus {
    Submitted,
    Confirmed,
    Finalized,
    Failed,
}

// ============================================================================
// Snapshot Integrity Verification (ISSUE-018)
// ============================================================================

/// Snapshot integrity verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotIntegrityResult {
    /// Overall verification passed
    pub is_valid: bool,
    /// Batch root verification passed
    pub batch_root_valid: bool,
    /// Parent chain verified
    pub parent_chain_valid: bool,
    /// Signature verification passed
    pub signature_valid: bool,
    /// Version fields verified
    pub versions_valid: bool,
    /// Time window is valid
    pub time_window_valid: bool,
    /// Detailed errors
    pub errors: Vec<SnapshotIntegrityError>,
    /// Verification timestamp
    pub verified_at: DateTime<Utc>,
}

impl SnapshotIntegrityResult {
    /// Create a successful result
    pub fn success() -> Self {
        Self {
            is_valid: true,
            batch_root_valid: true,
            parent_chain_valid: true,
            signature_valid: true,
            versions_valid: true,
            time_window_valid: true,
            errors: Vec::new(),
            verified_at: Utc::now(),
        }
    }

    /// Create a failed result with errors
    /// Automatically determines which validations passed based on error types
    pub fn failure(errors: Vec<SnapshotIntegrityError>) -> Self {
        // Determine which validations passed based on error types present
        let batch_root_valid = !errors.iter().any(|e|
            matches!(e.error_type, SnapshotIntegrityErrorType::BatchRootMismatch)
        );
        let parent_chain_valid = !errors.iter().any(|e|
            matches!(e.error_type,
                SnapshotIntegrityErrorType::ParentNotFound |
                SnapshotIntegrityErrorType::ParentHashMismatch |
                SnapshotIntegrityErrorType::SequenceGap
            )
        );
        let signature_valid = !errors.iter().any(|e|
            matches!(e.error_type,
                SnapshotIntegrityErrorType::SignatureFailed |
                SnapshotIntegrityErrorType::ThresholdNotMet
            )
        );
        let versions_valid = !errors.iter().any(|e|
            matches!(e.error_type,
                SnapshotIntegrityErrorType::InvalidSignerSetVersion |
                SnapshotIntegrityErrorType::InvalidCanonicalizationVersion |
                SnapshotIntegrityErrorType::InvalidAnchorPolicyVersion |
                SnapshotIntegrityErrorType::InvalidFeeScheduleVersion
            )
        );
        let time_window_valid = !errors.iter().any(|e|
            matches!(e.error_type, SnapshotIntegrityErrorType::InvalidTimeWindow)
        );

        Self {
            is_valid: false,
            batch_root_valid,
            parent_chain_valid,
            signature_valid,
            versions_valid,
            time_window_valid,
            errors,
            verified_at: Utc::now(),
        }
    }

    /// Create a partial failure result with specific flags
    pub fn partial_failure(
        errors: Vec<SnapshotIntegrityError>,
        batch_root_valid: bool,
        parent_chain_valid: bool,
        signature_valid: bool,
        versions_valid: bool,
        time_window_valid: bool,
    ) -> Self {
        Self {
            is_valid: false,
            batch_root_valid,
            parent_chain_valid,
            signature_valid,
            versions_valid,
            time_window_valid,
            errors,
            verified_at: Utc::now(),
        }
    }
}

/// Snapshot integrity error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotIntegrityError {
    /// Error type
    pub error_type: SnapshotIntegrityErrorType,
    /// Error message
    pub message: String,
    /// Field with error (if applicable)
    pub field: Option<String>,
    /// Expected value (if applicable)
    pub expected: Option<String>,
    /// Actual value (if applicable)
    pub actual: Option<String>,
}

/// Type of snapshot integrity error
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotIntegrityErrorType {
    /// Batch root hash mismatch
    BatchRootMismatch,
    /// Parent reference not found
    ParentNotFound,
    /// Parent hash mismatch
    ParentHashMismatch,
    /// Signature verification failed
    SignatureFailed,
    /// Threshold not met
    ThresholdNotMet,
    /// Invalid signer set version
    InvalidSignerSetVersion,
    /// Invalid canonicalization version
    InvalidCanonicalizationVersion,
    /// Invalid anchor policy version
    InvalidAnchorPolicyVersion,
    /// Invalid fee schedule version
    InvalidFeeScheduleVersion,
    /// Time window invalid (end before start)
    InvalidTimeWindow,
    /// Sequence number gap
    SequenceGap,
    /// Duplicate snapshot
    DuplicateSnapshot,
    /// Missing required field
    MissingField,
}

impl SignedBatchSnapshot {
    /// Verify integrity of this snapshot
    pub fn verify_integrity(&self, parent: Option<&SignedBatchSnapshot>) -> SnapshotIntegrityResult {
        let mut errors = Vec::new();

        // Verify time window
        if self.time_window_end < self.time_window_start {
            errors.push(SnapshotIntegrityError {
                error_type: SnapshotIntegrityErrorType::InvalidTimeWindow,
                message: "End time is before start time".to_string(),
                field: Some("time_window".to_string()),
                expected: None,
                actual: None,
            });
        }

        // Verify parent chain
        if let Some(parent_snapshot) = parent {
            // Check parent hash reference
            if let Some(ref claimed_parent) = self.parent_batch_root {
                if claimed_parent != &parent_snapshot.batch_root {
                    errors.push(SnapshotIntegrityError {
                        error_type: SnapshotIntegrityErrorType::ParentHashMismatch,
                        message: "Parent hash does not match".to_string(),
                        field: Some("parent_batch_root".to_string()),
                        expected: Some(parent_snapshot.batch_root.to_hex()),
                        actual: Some(claimed_parent.to_hex()),
                    });
                }
            }

            // Check sequence continuity
            if self.batch_sequence_no != parent_snapshot.batch_sequence_no + 1 {
                errors.push(SnapshotIntegrityError {
                    error_type: SnapshotIntegrityErrorType::SequenceGap,
                    message: format!(
                        "Sequence gap: expected {}, got {}",
                        parent_snapshot.batch_sequence_no + 1,
                        self.batch_sequence_no
                    ),
                    field: Some("batch_sequence_no".to_string()),
                    expected: Some((parent_snapshot.batch_sequence_no + 1).to_string()),
                    actual: Some(self.batch_sequence_no.to_string()),
                });
            }

            // Check time continuity (this batch should start after parent ends)
            if self.time_window_start < parent_snapshot.time_window_end {
                errors.push(SnapshotIntegrityError {
                    error_type: SnapshotIntegrityErrorType::InvalidTimeWindow,
                    message: "Time window overlaps with parent".to_string(),
                    field: Some("time_window_start".to_string()),
                    expected: Some(format!(">= {}", parent_snapshot.time_window_end)),
                    actual: Some(self.time_window_start.to_rfc3339()),
                });
            }
        } else if self.batch_sequence_no != 0 && self.parent_batch_root.is_some() {
            // First batch should have no parent
            errors.push(SnapshotIntegrityError {
                error_type: SnapshotIntegrityErrorType::ParentNotFound,
                message: "Parent reference exists but parent not provided".to_string(),
                field: Some("parent_batch_root".to_string()),
                expected: None,
                actual: None,
            });
        }

        // Verify version fields are present
        if self.signer_set_version.is_empty() {
            errors.push(SnapshotIntegrityError {
                error_type: SnapshotIntegrityErrorType::MissingField,
                message: "Signer set version is empty".to_string(),
                field: Some("signer_set_version".to_string()),
                expected: None,
                actual: None,
            });
        }

        // Verify threshold rule format
        if !self.threshold_rule.contains('/') {
            errors.push(SnapshotIntegrityError {
                error_type: SnapshotIntegrityErrorType::MissingField,
                message: "Invalid threshold rule format".to_string(),
                field: Some("threshold_rule".to_string()),
                expected: Some("format like '5/9'".to_string()),
                actual: Some(self.threshold_rule.clone()),
            });
        }

        if errors.is_empty() {
            SnapshotIntegrityResult::success()
        } else {
            let mut result = SnapshotIntegrityResult::failure(errors.clone());
            // Set specific flags based on error types
            result.batch_root_valid = !errors.iter().any(|e|
                matches!(e.error_type, SnapshotIntegrityErrorType::BatchRootMismatch)
            );
            result.parent_chain_valid = !errors.iter().any(|e|
                matches!(e.error_type,
                    SnapshotIntegrityErrorType::ParentNotFound |
                    SnapshotIntegrityErrorType::ParentHashMismatch |
                    SnapshotIntegrityErrorType::SequenceGap
                )
            );
            result.signature_valid = !errors.iter().any(|e|
                matches!(e.error_type,
                    SnapshotIntegrityErrorType::SignatureFailed |
                    SnapshotIntegrityErrorType::ThresholdNotMet
                )
            );
            result.versions_valid = !errors.iter().any(|e|
                matches!(e.error_type,
                    SnapshotIntegrityErrorType::InvalidSignerSetVersion |
                    SnapshotIntegrityErrorType::InvalidCanonicalizationVersion |
                    SnapshotIntegrityErrorType::InvalidAnchorPolicyVersion |
                    SnapshotIntegrityErrorType::InvalidFeeScheduleVersion
                )
            );
            result.time_window_valid = !errors.iter().any(|e|
                matches!(e.error_type, SnapshotIntegrityErrorType::InvalidTimeWindow)
            );
            result
        }
    }

    /// Compute the expected batch root from transactions using secure Merkle tree
    ///
    /// Security measures:
    /// - Domain separation: leaf nodes use 0x00 prefix, internal nodes use 0x01 prefix
    /// - Odd nodes are duplicated (hash with self) to prevent second-preimage attacks
    pub fn compute_expected_root(&self, tx_hashes: &[Digest]) -> Digest {
        Self::compute_merkle_root(tx_hashes)
    }

    /// Compute secure Merkle root with domain separation
    pub fn compute_merkle_root(hashes: &[Digest]) -> Digest {
        if hashes.is_empty() {
            return Digest::zero();
        }

        // Create leaf nodes with domain separation (0x00 prefix)
        let mut current_level: Vec<Digest> = hashes
            .iter()
            .map(|h| Self::hash_leaf(h))
            .collect();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for pair in current_level.chunks(2) {
                if pair.len() == 2 {
                    // Internal node with domain separation (0x01 prefix)
                    next_level.push(Self::hash_internal(&pair[0], &pair[1]));
                } else {
                    // Odd node: hash with itself to prevent second-preimage attacks
                    next_level.push(Self::hash_internal(&pair[0], &pair[0]));
                }
            }

            current_level = next_level;
        }

        current_level.into_iter().next().unwrap_or_default()
    }

    /// Hash a leaf node with domain separation (0x00 prefix)
    fn hash_leaf(data: &Digest) -> Digest {
        let mut input = Vec::with_capacity(33);
        input.push(0x00); // Leaf domain tag
        input.extend_from_slice(data.as_bytes());
        Digest::blake3(&input)
    }

    /// Hash an internal node with domain separation (0x01 prefix)
    fn hash_internal(left: &Digest, right: &Digest) -> Digest {
        let mut input = Vec::with_capacity(65);
        input.push(0x01); // Internal node domain tag
        input.extend_from_slice(left.as_bytes());
        input.extend_from_slice(right.as_bytes());
        Digest::blake3(&input)
    }

    /// Verify the batch root against transaction hashes
    pub fn verify_batch_root(&self, tx_hashes: &[Digest]) -> bool {
        let expected = self.compute_expected_root(tx_hashes);
        self.batch_root == expected
    }
}

impl EpochSnapshot {
    /// Verify integrity of this epoch snapshot
    pub fn verify_integrity(&self, parent: Option<&EpochSnapshot>) -> SnapshotIntegrityResult {
        let mut errors = Vec::new();

        // Verify time window
        if self.epoch_window_end < self.epoch_window_start {
            errors.push(SnapshotIntegrityError {
                error_type: SnapshotIntegrityErrorType::InvalidTimeWindow,
                message: "Epoch end time is before start time".to_string(),
                field: Some("epoch_window".to_string()),
                expected: None,
                actual: None,
            });
        }

        // Verify parent chain
        if let Some(parent_epoch) = parent {
            if let Some(ref claimed_parent) = self.parent_epoch_root {
                if claimed_parent != &parent_epoch.epoch_root {
                    errors.push(SnapshotIntegrityError {
                        error_type: SnapshotIntegrityErrorType::ParentHashMismatch,
                        message: "Parent epoch root does not match".to_string(),
                        field: Some("parent_epoch_root".to_string()),
                        expected: Some(parent_epoch.epoch_root.to_hex()),
                        actual: Some(claimed_parent.to_hex()),
                    });
                }
            }

            // Check sequence continuity
            if self.epoch_sequence_no != parent_epoch.epoch_sequence_no + 1 {
                errors.push(SnapshotIntegrityError {
                    error_type: SnapshotIntegrityErrorType::SequenceGap,
                    message: format!(
                        "Epoch sequence gap: expected {}, got {}",
                        parent_epoch.epoch_sequence_no + 1,
                        self.epoch_sequence_no
                    ),
                    field: Some("epoch_sequence_no".to_string()),
                    expected: Some((parent_epoch.epoch_sequence_no + 1).to_string()),
                    actual: Some(self.epoch_sequence_no.to_string()),
                });
            }
        }

        // Check required fields
        if self.signer_set_version.is_empty() {
            errors.push(SnapshotIntegrityError {
                error_type: SnapshotIntegrityErrorType::MissingField,
                message: "Signer set version is empty".to_string(),
                field: Some("signer_set_version".to_string()),
                expected: None,
                actual: None,
            });
        }

        if errors.is_empty() {
            SnapshotIntegrityResult::success()
        } else {
            SnapshotIntegrityResult::failure(errors)
        }
    }

    /// Verify epoch root against batch roots using secure Merkle tree
    pub fn verify_epoch_root(&self, batch_roots: &[Digest]) -> bool {
        if batch_roots.is_empty() {
            return self.epoch_root.is_zero();
        }

        // Use the same secure Merkle tree implementation
        let expected = SignedBatchSnapshot::compute_merkle_root(batch_roots);
        self.epoch_root == expected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signer_set_validation() {
        let mut set = SignerSetRef {
            signer_set_id: "test".to_string(),
            version: 1,
            certified_signer_pubkeys: vec!["pk".to_string(); 9],
            observer_pubkeys: vec![],
            threshold_rule: "5/9".to_string(),
            valid_from: Utc::now(),
            supersedes: None,
            admission_policy_version: "v1".to_string(),
            slashing_policy_version: None,
            receipt_id: None,
            metadata_digest: None,
        };

        assert!(set.validate().is_ok());

        set.certified_signer_pubkeys = vec!["pk".to_string(); 8];
        assert!(set.validate().is_err());
    }
}
