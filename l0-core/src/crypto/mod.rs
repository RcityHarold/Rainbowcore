//! Cryptographic primitives for L0
//!
//! This module provides cryptographic primitives specific to L0:
//! - Merkle trees for batch/epoch aggregation
//! - Commitment chain verification

pub mod merkle;

pub use merkle::{IncrementalMerkleTree, MerkleProof, MerkleTree};
