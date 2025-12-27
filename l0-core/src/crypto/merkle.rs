//! Merkle tree implementation for L0
//!
//! This module provides a binary Merkle tree for batch/epoch roots.
//! Uses L0Digest (BLAKE3) for all hash computations.

use crate::types::L0Digest;
use serde::{Deserialize, Serialize};

/// Merkle tree for L0 batch/epoch aggregation
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// All nodes in the tree (leaves + internal nodes)
    /// Stored in level order: leaves first, then internal nodes up to root
    nodes: Vec<L0Digest>,
    /// Number of leaves
    leaf_count: usize,
}

impl MerkleTree {
    /// Build a Merkle tree from leaf digests
    ///
    /// If the number of leaves is not a power of 2, the last leaf is duplicated
    /// to complete the tree (standard Merkle tree padding).
    pub fn build(leaves: &[L0Digest]) -> Self {
        if leaves.is_empty() {
            return Self {
                nodes: vec![L0Digest::zero()],
                leaf_count: 0,
            };
        }

        // Pad leaves to power of 2
        let n = leaves.len().next_power_of_two();
        let mut nodes = Vec::with_capacity(2 * n - 1);

        // Add leaves (with padding)
        nodes.extend_from_slice(leaves);
        while nodes.len() < n {
            nodes.push(nodes.last().unwrap().clone());
        }

        // Build internal nodes level by level
        let mut level_start = 0;
        let mut level_size = n;

        while level_size > 1 {
            let next_level_size = level_size / 2;
            for i in 0..next_level_size {
                let left = &nodes[level_start + 2 * i];
                let right = &nodes[level_start + 2 * i + 1];
                nodes.push(L0Digest::combine(left, right));
            }
            level_start += level_size;
            level_size = next_level_size;
        }

        Self {
            nodes,
            leaf_count: leaves.len(),
        }
    }

    /// Get the root hash of the tree
    pub fn root(&self) -> L0Digest {
        self.nodes.last().cloned().unwrap_or_else(L0Digest::zero)
    }

    /// Get number of leaves
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Generate a Merkle proof for a leaf at the given index
    pub fn proof(&self, leaf_index: usize) -> Option<MerkleProof> {
        if leaf_index >= self.leaf_count || self.leaf_count == 0 {
            return None;
        }

        let n = self.leaf_count.next_power_of_two();
        let mut proof_hashes = Vec::new();
        let mut proof_positions = Vec::new();

        let mut idx = leaf_index;
        let mut level_start = 0;
        let mut level_size = n;

        while level_size > 1 {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            let sibling = &self.nodes[level_start + sibling_idx];
            proof_hashes.push(sibling.clone());
            proof_positions.push(idx % 2 == 0); // true = sibling is on right

            // Move to parent level
            idx /= 2;
            level_start += level_size;
            level_size /= 2;
        }

        Some(MerkleProof {
            leaf_index,
            leaf_hash: self.nodes[leaf_index].clone(),
            proof_hashes,
            proof_positions,
        })
    }
}

/// Merkle proof for a leaf
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Index of the leaf in the tree
    pub leaf_index: usize,
    /// Hash of the leaf
    pub leaf_hash: L0Digest,
    /// Sibling hashes along the path to root
    pub proof_hashes: Vec<L0Digest>,
    /// Position of each sibling (true = right, false = left)
    pub proof_positions: Vec<bool>,
}

impl MerkleProof {
    /// Verify the proof against a root hash
    pub fn verify(&self, root: &L0Digest) -> bool {
        if self.proof_hashes.len() != self.proof_positions.len() {
            return false;
        }

        let mut current = self.leaf_hash.clone();

        for (sibling, is_right) in self.proof_hashes.iter().zip(self.proof_positions.iter()) {
            if *is_right {
                current = L0Digest::combine(&current, sibling);
            } else {
                current = L0Digest::combine(sibling, &current);
            }
        }

        &current == root
    }

    /// Compute the root from this proof
    pub fn compute_root(&self) -> L0Digest {
        let mut current = self.leaf_hash.clone();

        for (sibling, is_right) in self.proof_hashes.iter().zip(self.proof_positions.iter()) {
            if *is_right {
                current = L0Digest::combine(&current, sibling);
            } else {
                current = L0Digest::combine(sibling, &current);
            }
        }

        current
    }
}

/// Incremental Merkle tree for streaming leaf addition
///
/// This is useful for building Merkle trees when leaves arrive incrementally.
#[derive(Debug, Clone)]
pub struct IncrementalMerkleTree {
    /// Accumulated partial trees at each level
    partials: Vec<Option<L0Digest>>,
    /// Total leaf count
    count: usize,
}

impl IncrementalMerkleTree {
    /// Create a new incremental Merkle tree
    pub fn new() -> Self {
        Self {
            partials: Vec::new(),
            count: 0,
        }
    }

    /// Add a leaf to the tree
    pub fn add(&mut self, leaf: L0Digest) {
        self.count += 1;
        let mut current = leaf;
        let mut level = 0;

        // Propagate up the tree
        loop {
            if level >= self.partials.len() {
                self.partials.push(Some(current));
                break;
            }

            match self.partials[level].take() {
                Some(sibling) => {
                    // Combine with sibling and propagate up
                    current = L0Digest::combine(&sibling, &current);
                    level += 1;
                }
                None => {
                    // Store at this level
                    self.partials[level] = Some(current);
                    break;
                }
            }
        }
    }

    /// Get the current root (finalizes the tree)
    pub fn root(&self) -> L0Digest {
        if self.count == 0 {
            return L0Digest::zero();
        }

        // Combine all partial trees
        let mut current: Option<L0Digest> = None;

        for partial in &self.partials {
            current = match (&current, partial) {
                (None, Some(p)) => Some(p.clone()),
                (Some(c), Some(p)) => Some(L0Digest::combine(p, c)),
                (Some(c), None) => {
                    // Duplicate for padding
                    Some(L0Digest::combine(c, c))
                }
                (None, None) => None,
            };
        }

        current.unwrap_or_else(L0Digest::zero)
    }

    /// Get number of leaves added
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for IncrementalMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_single_leaf() {
        let leaf = L0Digest::blake3(b"test");
        let tree = MerkleTree::build(&[leaf.clone()]);

        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.root(), leaf);
    }

    #[test]
    fn test_merkle_tree_two_leaves() {
        let leaf1 = L0Digest::blake3(b"leaf1");
        let leaf2 = L0Digest::blake3(b"leaf2");
        let tree = MerkleTree::build(&[leaf1.clone(), leaf2.clone()]);

        let expected_root = L0Digest::combine(&leaf1, &leaf2);
        assert_eq!(tree.leaf_count(), 2);
        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn test_merkle_tree_four_leaves() {
        let leaves: Vec<L0Digest> = (0..4)
            .map(|i| L0Digest::blake3(format!("leaf{}", i).as_bytes()))
            .collect();

        let tree = MerkleTree::build(&leaves);
        assert_eq!(tree.leaf_count(), 4);

        // Verify structure
        let n01 = L0Digest::combine(&leaves[0], &leaves[1]);
        let n23 = L0Digest::combine(&leaves[2], &leaves[3]);
        let expected_root = L0Digest::combine(&n01, &n23);
        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn test_merkle_proof_verification() {
        let leaves: Vec<L0Digest> = (0..4)
            .map(|i| L0Digest::blake3(format!("leaf{}", i).as_bytes()))
            .collect();

        let tree = MerkleTree::build(&leaves);
        let root = tree.root();

        // Verify proof for each leaf
        for i in 0..4 {
            let proof = tree.proof(i).unwrap();
            assert!(proof.verify(&root), "Proof for leaf {} should verify", i);
            assert_eq!(proof.compute_root(), root);
        }
    }

    #[test]
    fn test_merkle_proof_invalid_root() {
        let leaves: Vec<L0Digest> = (0..4)
            .map(|i| L0Digest::blake3(format!("leaf{}", i).as_bytes()))
            .collect();

        let tree = MerkleTree::build(&leaves);
        let proof = tree.proof(0).unwrap();

        // Verify against wrong root
        let wrong_root = L0Digest::blake3(b"wrong");
        assert!(!proof.verify(&wrong_root));
    }

    #[test]
    fn test_incremental_matches_batch() {
        let leaves: Vec<L0Digest> = (0..8)
            .map(|i| L0Digest::blake3(format!("leaf{}", i).as_bytes()))
            .collect();

        // Build batch tree
        let batch_tree = MerkleTree::build(&leaves);

        // Build incrementally
        let mut incr_tree = IncrementalMerkleTree::new();
        for leaf in &leaves {
            incr_tree.add(leaf.clone());
        }

        assert_eq!(batch_tree.root(), incr_tree.root());
    }

    #[test]
    fn test_empty_tree() {
        let tree = MerkleTree::build(&[]);
        assert_eq!(tree.leaf_count(), 0);
        assert!(tree.root().is_zero());
        assert!(tree.proof(0).is_none());
    }
}
