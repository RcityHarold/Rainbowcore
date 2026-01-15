//! Merkle Tree Module
//!
//! Chapter 2: Result root computation for reward distributions
//!
//! Provides Merkle tree construction and proof verification for:
//! - Reward distribution result roots
//! - Attribution tree verification
//! - Event set membership proofs

use crate::canon::Canonicalizer;
use crate::error::P3Result;
use crate::types::{P3Digest, RewardDistributionEntry};
use serde::Serialize;

/// Merkle tree builder
pub struct MerkleTreeBuilder {
    /// Domain separation tag
    domain_tag: String,
    /// Canonicalizer for leaf hashing
    canon: Canonicalizer,
}

impl MerkleTreeBuilder {
    /// Create new builder with domain tag
    pub fn new(domain_tag: &str) -> Self {
        Self {
            domain_tag: domain_tag.to_string(),
            canon: Canonicalizer::v1(),
        }
    }

    /// Create builder for result root
    pub fn for_result_root() -> Self {
        Self::new("p3:result_root")
    }

    /// Create builder for attribution tree
    pub fn for_attribution() -> Self {
        Self::new("p3:attribution")
    }

    /// Build result root from reward distribution entries
    pub fn build_result_root(&self, entries: &[RewardDistributionEntry]) -> P3Result<MerkleRoot> {
        if entries.is_empty() {
            return Ok(MerkleRoot::empty());
        }

        // Hash each entry to create leaves
        let leaves: Vec<P3Digest> = entries
            .iter()
            .map(|e| self.hash_leaf(e))
            .collect::<P3Result<Vec<_>>>()?;

        // Build tree from leaves
        let root = self.build_tree(&leaves);

        Ok(MerkleRoot {
            root,
            leaf_count: entries.len(),
            domain_tag: self.domain_tag.clone(),
        })
    }

    /// Build Merkle tree from arbitrary serializable items
    pub fn build_tree_from<T: Serialize>(&self, items: &[T]) -> P3Result<MerkleRoot> {
        if items.is_empty() {
            return Ok(MerkleRoot::empty());
        }

        let leaves: Vec<P3Digest> = items
            .iter()
            .map(|item| self.hash_leaf(item))
            .collect::<P3Result<Vec<_>>>()?;

        let root = self.build_tree(&leaves);

        Ok(MerkleRoot {
            root,
            leaf_count: items.len(),
            domain_tag: self.domain_tag.clone(),
        })
    }

    /// Hash a leaf item
    fn hash_leaf<T: Serialize>(&self, item: &T) -> P3Result<P3Digest> {
        let canonical = self.canon.canonicalize(item)?;
        Ok(self.hash_with_domain(&canonical, &format!("{}:leaf", self.domain_tag)))
    }

    /// Hash internal node (two children)
    fn hash_node(&self, left: &P3Digest, right: &P3Digest) -> P3Digest {
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&left.0);
        data.extend_from_slice(&right.0);
        self.hash_with_domain(&data, &format!("{}:node", self.domain_tag))
    }

    /// Hash with domain separation
    fn hash_with_domain(&self, data: &[u8], domain: &str) -> P3Digest {
        let mut tagged = Vec::with_capacity(domain.len() + 1 + data.len());
        tagged.extend_from_slice(domain.as_bytes());
        tagged.push(0x00);
        tagged.extend_from_slice(data);
        P3Digest::blake3(&tagged)
    }

    /// Build tree from leaf digests
    fn build_tree(&self, leaves: &[P3Digest]) -> P3Digest {
        if leaves.is_empty() {
            return P3Digest::zero();
        }
        if leaves.len() == 1 {
            return leaves[0].clone();
        }

        // Build tree bottom-up
        let mut current_level = leaves.to_vec();

        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);

            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    next_level.push(self.hash_node(&chunk[0], &chunk[1]));
                } else {
                    // Odd number of nodes: promote the single node
                    next_level.push(chunk[0].clone());
                }
            }

            current_level = next_level;
        }

        current_level[0].clone()
    }

    /// Generate proof for leaf at index
    pub fn generate_proof(&self, leaves: &[P3Digest], index: usize) -> Option<MerkleProof> {
        if index >= leaves.len() || leaves.is_empty() {
            return None;
        }

        let mut proof_path = Vec::new();
        let mut current_level = leaves.to_vec();
        let mut current_index = index;

        while current_level.len() > 1 {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            if sibling_index < current_level.len() {
                let is_left = current_index % 2 == 1;
                proof_path.push(ProofNode {
                    digest: current_level[sibling_index].clone(),
                    is_left,
                });
            }

            // Build next level
            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    next_level.push(self.hash_node(&chunk[0], &chunk[1]));
                } else {
                    next_level.push(chunk[0].clone());
                }
            }

            current_level = next_level;
            current_index /= 2;
        }

        Some(MerkleProof {
            leaf_index: index,
            path: proof_path,
            root: current_level[0].clone(),
        })
    }

    /// Verify a Merkle proof
    pub fn verify_proof(&self, leaf: &P3Digest, proof: &MerkleProof) -> bool {
        let mut current = leaf.clone();

        for node in &proof.path {
            current = if node.is_left {
                self.hash_node(&node.digest, &current)
            } else {
                self.hash_node(&current, &node.digest)
            };
        }

        current == proof.root
    }
}

impl Default for MerkleTreeBuilder {
    fn default() -> Self {
        Self::for_result_root()
    }
}

/// Merkle tree root
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleRoot {
    /// Root digest
    pub root: P3Digest,
    /// Number of leaves
    pub leaf_count: usize,
    /// Domain tag used
    pub domain_tag: String,
}

impl MerkleRoot {
    /// Create empty root
    pub fn empty() -> Self {
        Self {
            root: P3Digest::zero(),
            leaf_count: 0,
            domain_tag: String::new(),
        }
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.leaf_count == 0
    }
}

/// Merkle proof node
#[derive(Clone, Debug)]
pub struct ProofNode {
    /// Sibling digest
    pub digest: P3Digest,
    /// Is this sibling on the left?
    pub is_left: bool,
}

/// Merkle inclusion proof
#[derive(Clone, Debug)]
pub struct MerkleProof {
    /// Index of the leaf
    pub leaf_index: usize,
    /// Path from leaf to root
    pub path: Vec<ProofNode>,
    /// Expected root
    pub root: P3Digest,
}

impl MerkleProof {
    /// Get proof length (tree depth)
    pub fn depth(&self) -> usize {
        self.path.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ActorId, PoolId, RewardPoints};
    use rust_decimal::Decimal;

    fn create_test_entry(recipient: &str, amount: i64) -> RewardDistributionEntry {
        RewardDistributionEntry {
            entry_id: format!("entry:{}", recipient),
            recipient: ActorId::new(recipient),
            pool_id: PoolId::new("pool:reward"),
            amount: RewardPoints(Decimal::new(amount, 0)),
            attribution_ref: None,
            distribution_ref: "dist:1".to_string(),
        }
    }

    #[test]
    fn test_empty_tree() {
        let builder = MerkleTreeBuilder::for_result_root();
        let root = builder.build_result_root(&[]).unwrap();
        assert!(root.is_empty());
        assert_eq!(root.leaf_count, 0);
    }

    #[test]
    fn test_single_leaf() {
        let builder = MerkleTreeBuilder::for_result_root();
        let entries = vec![create_test_entry("alice", 100)];
        let root = builder.build_result_root(&entries).unwrap();
        assert!(!root.is_empty());
        assert_eq!(root.leaf_count, 1);
    }

    #[test]
    fn test_multiple_leaves() {
        let builder = MerkleTreeBuilder::for_result_root();
        let entries = vec![
            create_test_entry("alice", 100),
            create_test_entry("bob", 200),
            create_test_entry("charlie", 300),
        ];
        let root = builder.build_result_root(&entries).unwrap();
        assert_eq!(root.leaf_count, 3);
    }

    #[test]
    fn test_deterministic_root() {
        let builder = MerkleTreeBuilder::for_result_root();
        let entries = vec![
            create_test_entry("alice", 100),
            create_test_entry("bob", 200),
        ];

        let root1 = builder.build_result_root(&entries).unwrap();
        let root2 = builder.build_result_root(&entries).unwrap();

        assert_eq!(root1.root, root2.root);
    }

    #[test]
    fn test_different_entries_different_root() {
        let builder = MerkleTreeBuilder::for_result_root();

        let entries1 = vec![create_test_entry("alice", 100)];
        let entries2 = vec![create_test_entry("alice", 200)];

        let root1 = builder.build_result_root(&entries1).unwrap();
        let root2 = builder.build_result_root(&entries2).unwrap();

        assert_ne!(root1.root, root2.root);
    }

    #[test]
    fn test_proof_generation_and_verification() {
        let builder = MerkleTreeBuilder::for_result_root();

        // Create leaves directly for proof testing
        let leaves: Vec<P3Digest> = (0..4)
            .map(|i| P3Digest::blake3(format!("leaf:{}", i).as_bytes()))
            .collect();

        // Generate proof for each leaf
        for i in 0..leaves.len() {
            let proof = builder.generate_proof(&leaves, i).unwrap();
            assert!(builder.verify_proof(&leaves[i], &proof));
        }
    }

    #[test]
    fn test_invalid_proof() {
        let builder = MerkleTreeBuilder::for_result_root();

        let leaves: Vec<P3Digest> = (0..4)
            .map(|i| P3Digest::blake3(format!("leaf:{}", i).as_bytes()))
            .collect();

        let proof = builder.generate_proof(&leaves, 0).unwrap();

        // Wrong leaf should fail verification
        let wrong_leaf = P3Digest::blake3(b"wrong");
        assert!(!builder.verify_proof(&wrong_leaf, &proof));
    }

    #[test]
    fn test_proof_out_of_bounds() {
        let builder = MerkleTreeBuilder::for_result_root();
        let leaves: Vec<P3Digest> = vec![P3Digest::blake3(b"leaf")];

        // Index out of bounds
        assert!(builder.generate_proof(&leaves, 5).is_none());
    }
}
