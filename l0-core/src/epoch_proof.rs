//! Epoch Proof Generation and Verification (ISSUE-018)
//!
//! This module implements the complete epoch proof workflow:
//! - Merkle tree construction from batch roots
//! - Epoch root computation
//! - Inclusion proof generation
//! - Proof verification
//!
//! # Epoch Structure
//!
//! An epoch contains multiple batches, each with its own root hash.
//! The epoch root is the Merkle root of all batch roots:
//!
//! ```text
//!                    EpochRoot
//!                   /          \
//!              H01               H23
//!             /    \            /    \
//!          B0        B1      B2        B3  (Batch Roots)
//! ```
//!
//! # Usage
//!
//! ```ignore
//! let builder = EpochProofBuilder::new(epoch_sequence);
//! builder.add_batch(batch_root, batch_id);
//! // ... add more batches
//! let epoch_proof = builder.build(signer_set_version, signature, bitmap)?;
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use soulbase_crypto::{Digester, DefaultDigester};

use crate::types::{Digest, EpochProof, MerklePathNode};

/// Error types for epoch proof operations
#[derive(Debug, Clone)]
pub enum EpochProofError {
    /// No batches to build proof from
    NoBatches,
    /// Invalid batch index
    InvalidBatchIndex { index: usize, total: usize },
    /// Proof verification failed
    VerificationFailed { reason: String },
    /// Invalid proof structure
    InvalidProofStructure { details: String },
    /// Signature verification failed
    SignatureVerificationFailed,
    /// Merkle path invalid
    InvalidMerklePath,
}

impl std::fmt::Display for EpochProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoBatches => write!(f, "No batches to build epoch proof from"),
            Self::InvalidBatchIndex { index, total } => {
                write!(f, "Invalid batch index {} (total batches: {})", index, total)
            }
            Self::VerificationFailed { reason } => {
                write!(f, "Epoch proof verification failed: {}", reason)
            }
            Self::InvalidProofStructure { details } => {
                write!(f, "Invalid epoch proof structure: {}", details)
            }
            Self::SignatureVerificationFailed => write!(f, "Signature verification failed"),
            Self::InvalidMerklePath => write!(f, "Invalid Merkle path"),
        }
    }
}

impl std::error::Error for EpochProofError {}

/// Result type for epoch proof operations
pub type EpochProofResult<T> = Result<T, EpochProofError>;

/// Batch information for epoch proof construction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchInfo {
    /// Batch ID
    pub batch_id: String,
    /// Batch root hash
    pub root: Digest,
    /// Batch sequence number within epoch
    pub sequence: u64,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Epoch proof builder
///
/// Collects batch roots and builds the epoch Merkle tree.
#[derive(Debug)]
pub struct EpochProofBuilder {
    /// Epoch sequence number
    pub epoch_sequence: u64,
    /// Collected batches
    batches: Vec<BatchInfo>,
    /// Epoch start time
    pub epoch_start: Option<DateTime<Utc>>,
    /// Epoch end time
    pub epoch_end: Option<DateTime<Utc>>,
}

impl EpochProofBuilder {
    /// Create a new epoch proof builder
    pub fn new(epoch_sequence: u64) -> Self {
        Self {
            epoch_sequence,
            batches: Vec::new(),
            epoch_start: None,
            epoch_end: None,
        }
    }

    /// Add a batch to the epoch
    pub fn add_batch(&mut self, batch_id: String, root: Digest, timestamp: DateTime<Utc>) {
        let sequence = self.batches.len() as u64;
        self.batches.push(BatchInfo {
            batch_id,
            root,
            sequence,
            timestamp,
        });

        // Update epoch time range
        if self.epoch_start.is_none() || timestamp < self.epoch_start.unwrap() {
            self.epoch_start = Some(timestamp);
        }
        if self.epoch_end.is_none() || timestamp > self.epoch_end.unwrap() {
            self.epoch_end = Some(timestamp);
        }
    }

    /// Get the number of batches
    pub fn batch_count(&self) -> usize {
        self.batches.len()
    }

    /// Compute the epoch root (Merkle root of all batch roots)
    pub fn compute_epoch_root(&self) -> EpochProofResult<Digest> {
        if self.batches.is_empty() {
            return Err(EpochProofError::NoBatches);
        }

        let leaves: Vec<[u8; 32]> = self.batches.iter().map(|b| b.root.0).collect();
        Ok(Digest::new(compute_merkle_root(&leaves)))
    }

    /// Build the complete epoch proof
    pub fn build(
        &self,
        signer_set_version: String,
        signature: String,
        signer_bitmap: String,
    ) -> EpochProofResult<EpochProof> {
        let root = self.compute_epoch_root()?;

        // For the proof, we include an empty path since this is the root itself
        // Actual inclusion proofs for specific batches are generated separately
        Ok(EpochProof {
            root,
            merkle_path: Vec::new(), // Root needs no path
            signer_set_version,
            signature,
            signer_bitmap,
        })
    }

    /// Generate an inclusion proof for a specific batch
    pub fn generate_inclusion_proof(&self, batch_index: usize) -> EpochProofResult<Vec<MerklePathNode>> {
        if batch_index >= self.batches.len() {
            return Err(EpochProofError::InvalidBatchIndex {
                index: batch_index,
                total: self.batches.len(),
            });
        }

        let leaves: Vec<[u8; 32]> = self.batches.iter().map(|b| b.root.0).collect();
        Ok(generate_merkle_proof(&leaves, batch_index))
    }

    /// Build epoch proof with inclusion proof for specific batch
    pub fn build_with_inclusion(
        &self,
        batch_index: usize,
        signer_set_version: String,
        signature: String,
        signer_bitmap: String,
    ) -> EpochProofResult<EpochProof> {
        let root = self.compute_epoch_root()?;
        let merkle_path = self.generate_inclusion_proof(batch_index)?;

        Ok(EpochProof {
            root,
            merkle_path,
            signer_set_version,
            signature,
            signer_bitmap,
        })
    }

    /// Get all batch info
    pub fn batches(&self) -> &[BatchInfo] {
        &self.batches
    }
}

/// Epoch proof verifier
pub struct EpochProofVerifier;

impl EpochProofVerifier {
    /// Verify an epoch proof
    pub fn verify(proof: &EpochProof) -> EpochProofResult<bool> {
        // Basic structure validation
        if proof.root.is_zero() {
            return Err(EpochProofError::InvalidProofStructure {
                details: "Epoch root is zero".to_string(),
            });
        }

        if proof.signature.is_empty() {
            return Err(EpochProofError::InvalidProofStructure {
                details: "Signature is empty".to_string(),
            });
        }

        if proof.signer_bitmap.is_empty() {
            return Err(EpochProofError::InvalidProofStructure {
                details: "Signer bitmap is empty".to_string(),
            });
        }

        // Verify signer count meets threshold (5/9)
        let signer_count = proof.signer_bitmap.chars().filter(|&c| c == '1').count();
        if signer_count < 5 {
            return Err(EpochProofError::VerificationFailed {
                reason: format!(
                    "Threshold not met: {} signers, need 5",
                    signer_count
                ),
            });
        }

        // Note: Full signature verification would require the signer set
        // and access to the signing service. This is a structural check.
        Ok(true)
    }

    /// Verify batch inclusion in epoch
    pub fn verify_batch_inclusion(
        batch_root: &Digest,
        proof: &EpochProof,
        _batch_index: usize,
    ) -> EpochProofResult<bool> {
        if proof.merkle_path.is_empty() {
            // If no path, this might be a root-level proof
            return Ok(proof.root == *batch_root);
        }

        // Reconstruct the root from the batch root and merkle path
        let mut current = batch_root.0;

        for node in &proof.merkle_path {
            current = if node.position == 0 {
                // Node is on the left, current is on the right
                hash_pair(&node.hash.0, &current)
            } else {
                // Current is on the left, node is on the right
                hash_pair(&current, &node.hash.0)
            };
        }

        Ok(current == proof.root.0)
    }

    /// Verify complete epoch proof with signature
    pub fn verify_with_signature(
        proof: &EpochProof,
        message: &[u8],
        verify_fn: impl Fn(&str, &[u8]) -> bool,
    ) -> EpochProofResult<bool> {
        // First verify structure
        Self::verify(proof)?;

        // Then verify signature
        if !verify_fn(&proof.signature, message) {
            return Err(EpochProofError::SignatureVerificationFailed);
        }

        Ok(true)
    }
}

/// Compute Merkle root from leaves
fn compute_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }

    if leaves.len() == 1 {
        return leaves[0];
    }

    // Pad to power of 2 if needed
    let mut layer: Vec<[u8; 32]> = leaves.to_vec();
    while !layer.len().is_power_of_two() {
        layer.push([0u8; 32]); // Pad with zeros
    }

    // Build tree bottom-up
    while layer.len() > 1 {
        let mut next_layer = Vec::new();
        for chunk in layer.chunks(2) {
            let hash = hash_pair(&chunk[0], &chunk[1]);
            next_layer.push(hash);
        }
        layer = next_layer;
    }

    layer[0]
}

/// Generate Merkle proof for a leaf
fn generate_merkle_proof(leaves: &[[u8; 32]], index: usize) -> Vec<MerklePathNode> {
    if leaves.len() <= 1 {
        return Vec::new();
    }

    let mut proof = Vec::new();
    let mut layer: Vec<[u8; 32]> = leaves.to_vec();

    // Pad to power of 2 if needed
    while !layer.len().is_power_of_two() {
        layer.push([0u8; 32]);
    }

    let mut idx = index;

    while layer.len() > 1 {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };

        if sibling_idx < layer.len() {
            proof.push(MerklePathNode {
                hash: Digest::new(layer[sibling_idx]),
                position: if idx % 2 == 0 { 1 } else { 0 }, // Position of sibling
            });
        }

        // Build next layer
        let mut next_layer = Vec::new();
        for chunk in layer.chunks(2) {
            let hash = hash_pair(&chunk[0], &chunk[1]);
            next_layer.push(hash);
        }
        layer = next_layer;
        idx /= 2;
    }

    proof
}

/// Hash two 32-byte values together using BLAKE3
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let digester = DefaultDigester;
    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(left);
    combined.extend_from_slice(right);
    let digest = digester.blake3(&combined).expect("BLAKE3 digest failed");
    let mut output = [0u8; 32];
    output.copy_from_slice(digest.as_bytes());
    output
}

/// Epoch metadata for tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochMetadata {
    /// Epoch sequence number
    pub sequence: u64,
    /// Epoch root hash
    pub root: Digest,
    /// Number of batches
    pub batch_count: u64,
    /// Start timestamp
    pub start_time: DateTime<Utc>,
    /// End timestamp
    pub end_time: DateTime<Utc>,
    /// Signer set version
    pub signer_set_version: String,
    /// Anchor status
    pub anchor_status: EpochAnchorStatus,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
}

/// Epoch anchor status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpochAnchorStatus {
    /// Not yet anchored
    Pending,
    /// Anchor submitted
    Submitted,
    /// Anchor confirmed
    Confirmed,
    /// Anchor finalized
    Finalized,
    /// Anchor failed
    Failed,
}

impl Default for EpochAnchorStatus {
    fn default() -> Self {
        Self::Pending
    }
}

/// Epoch ledger for tracking epochs
#[derive(Debug, Default)]
pub struct EpochLedger {
    /// Epochs by sequence number
    epochs: std::collections::HashMap<u64, EpochMetadata>,
    /// Latest epoch sequence
    latest_sequence: u64,
}

impl EpochLedger {
    /// Create a new epoch ledger
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a new epoch
    pub fn record_epoch(&mut self, metadata: EpochMetadata) {
        let sequence = metadata.sequence;
        self.epochs.insert(sequence, metadata);
        if sequence > self.latest_sequence {
            self.latest_sequence = sequence;
        }
    }

    /// Get epoch by sequence
    pub fn get_epoch(&self, sequence: u64) -> Option<&EpochMetadata> {
        self.epochs.get(&sequence)
    }

    /// Get latest epoch
    pub fn latest_epoch(&self) -> Option<&EpochMetadata> {
        self.epochs.get(&self.latest_sequence)
    }

    /// Get latest sequence number
    pub fn latest_sequence(&self) -> u64 {
        self.latest_sequence
    }

    /// Update epoch anchor status
    pub fn update_anchor_status(&mut self, sequence: u64, status: EpochAnchorStatus) -> bool {
        if let Some(epoch) = self.epochs.get_mut(&sequence) {
            epoch.anchor_status = status;
            true
        } else {
            false
        }
    }

    /// Get all pending epochs (not yet anchored)
    pub fn pending_epochs(&self) -> Vec<&EpochMetadata> {
        self.epochs
            .values()
            .filter(|e| matches!(e.anchor_status, EpochAnchorStatus::Pending))
            .collect()
    }

    /// Get total epoch count
    pub fn epoch_count(&self) -> usize {
        self.epochs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_digest(value: u8) -> Digest {
        let mut bytes = [0u8; 32];
        bytes[0] = value;
        Digest::new(bytes)
    }

    #[test]
    fn test_epoch_proof_builder() {
        let mut builder = EpochProofBuilder::new(1);

        builder.add_batch("batch:001".to_string(), make_test_digest(1), Utc::now());
        builder.add_batch("batch:002".to_string(), make_test_digest(2), Utc::now());
        builder.add_batch("batch:003".to_string(), make_test_digest(3), Utc::now());

        assert_eq!(builder.batch_count(), 3);

        let root = builder.compute_epoch_root().unwrap();
        assert!(!root.is_zero());
    }

    #[test]
    fn test_epoch_proof_build() {
        let mut builder = EpochProofBuilder::new(1);
        builder.add_batch("batch:001".to_string(), make_test_digest(1), Utc::now());
        builder.add_batch("batch:002".to_string(), make_test_digest(2), Utc::now());

        let proof = builder.build(
            "signer_set:1".to_string(),
            "signature_hex".to_string(),
            "111110000".to_string(),
        ).unwrap();

        assert!(!proof.root.is_zero());
        assert_eq!(proof.signer_set_version, "signer_set:1");
    }

    #[test]
    fn test_merkle_root_single_leaf() {
        let leaves = vec![[1u8; 32]];
        let root = compute_merkle_root(&leaves);
        assert_eq!(root, [1u8; 32]); // Single leaf is its own root
    }

    #[test]
    fn test_merkle_root_multiple_leaves() {
        let leaves = vec![
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            [4u8; 32],
        ];

        let root = compute_merkle_root(&leaves);
        assert_ne!(root, [0u8; 32]);

        // Verify determinism
        let root2 = compute_merkle_root(&leaves);
        assert_eq!(root, root2);
    }

    #[test]
    fn test_merkle_proof_generation_and_verification() {
        let leaves = vec![
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            [4u8; 32],
        ];

        let root = compute_merkle_root(&leaves);

        // Generate proof for leaf 0
        let proof = generate_merkle_proof(&leaves, 0);
        assert!(!proof.is_empty());

        // Verify proof
        let mut current = leaves[0];
        for node in &proof {
            current = if node.position == 0 {
                hash_pair(&node.hash.0, &current)
            } else {
                hash_pair(&current, &node.hash.0)
            };
        }
        assert_eq!(current, root);
    }

    #[test]
    fn test_epoch_proof_verifier() {
        let mut builder = EpochProofBuilder::new(1);
        builder.add_batch("batch:001".to_string(), make_test_digest(1), Utc::now());
        builder.add_batch("batch:002".to_string(), make_test_digest(2), Utc::now());

        let proof = builder.build(
            "signer_set:1".to_string(),
            "signature_hex".to_string(),
            "111110000".to_string(), // 5 signers
        ).unwrap();

        assert!(EpochProofVerifier::verify(&proof).unwrap());
    }

    #[test]
    fn test_epoch_proof_verifier_threshold_not_met() {
        let mut builder = EpochProofBuilder::new(1);
        builder.add_batch("batch:001".to_string(), make_test_digest(1), Utc::now());

        let proof = builder.build(
            "signer_set:1".to_string(),
            "signature_hex".to_string(),
            "111100000".to_string(), // Only 4 signers
        ).unwrap();

        assert!(EpochProofVerifier::verify(&proof).is_err());
    }

    #[test]
    fn test_batch_inclusion_verification() {
        let mut builder = EpochProofBuilder::new(1);
        let batch_root = make_test_digest(1);
        builder.add_batch("batch:001".to_string(), batch_root.clone(), Utc::now());
        builder.add_batch("batch:002".to_string(), make_test_digest(2), Utc::now());

        let proof = builder.build_with_inclusion(
            0,
            "signer_set:1".to_string(),
            "signature_hex".to_string(),
            "111110000".to_string(),
        ).unwrap();

        let result = EpochProofVerifier::verify_batch_inclusion(&batch_root, &proof, 0);
        assert!(result.unwrap());
    }

    #[test]
    fn test_epoch_ledger() {
        let mut ledger = EpochLedger::new();

        let metadata = EpochMetadata {
            sequence: 1,
            root: make_test_digest(1),
            batch_count: 10,
            start_time: Utc::now(),
            end_time: Utc::now(),
            signer_set_version: "v1".to_string(),
            anchor_status: EpochAnchorStatus::Pending,
            created_at: Utc::now(),
        };

        ledger.record_epoch(metadata);
        assert_eq!(ledger.epoch_count(), 1);
        assert_eq!(ledger.latest_sequence(), 1);

        let epoch = ledger.get_epoch(1).unwrap();
        assert_eq!(epoch.batch_count, 10);

        ledger.update_anchor_status(1, EpochAnchorStatus::Confirmed);
        let epoch = ledger.get_epoch(1).unwrap();
        assert_eq!(epoch.anchor_status, EpochAnchorStatus::Confirmed);
    }
}
