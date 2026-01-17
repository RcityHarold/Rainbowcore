//! Merkle 证明验证
//!
//! 提供 Bitcoin 交易的 Merkle 证明验证功能。
//!
//! # 用途
//!
//! - SPV 验证：轻客户端验证交易包含在区块中
//! - 独立验证：无需完整节点即可验证锚定

use sha2::{Digest, Sha256};

use crate::error::{P4Error, P4Result};
use crate::types::MerkleProof;

/// 验证 Merkle 证明
///
/// 验证交易哈希是否通过 Merkle 证明连接到区块头中的 Merkle 根。
///
/// # Arguments
///
/// * `proof` - Merkle 证明
/// * `txid` - 交易ID（小端序，与 Bitcoin RPC 返回格式一致）
///
/// # Returns
///
/// 如果证明有效返回 `Ok(true)`，否则返回 `Ok(false)`
pub fn verify_merkle_proof(proof: &MerkleProof, txid: &str) -> P4Result<bool> {
    // 解析 txid（从十六进制字符串）
    let txid_bytes = hex::decode(txid).map_err(|e| {
        P4Error::InvalidInput(format!("Invalid txid hex: {}", e))
    })?;

    if txid_bytes.len() != 32 {
        return Err(P4Error::InvalidInput(format!(
            "Invalid txid length: expected 32, got {}",
            txid_bytes.len()
        )));
    }

    // Bitcoin txid 是小端序显示，需要反转为大端序进行 Merkle 计算
    let mut tx_hash = [0u8; 32];
    for (i, b) in txid_bytes.iter().rev().enumerate() {
        tx_hash[i] = *b;
    }

    // 转换 siblings 为 [u8; 32] 格式
    let siblings: Vec<[u8; 32]> = proof.siblings.to_vec();

    // 计算 Merkle 路径
    let computed_root = compute_merkle_root(&tx_hash, proof.tx_index, &siblings);

    // 提取区块头中的 Merkle 根
    let expected_root = extract_merkle_root(&proof.block_header);

    // 比较（注意：区块头中的 Merkle 根也是小端序存储）
    Ok(computed_root == expected_root)
}

/// 验证 Merkle 证明（使用原始字节）
pub fn verify_merkle_proof_bytes(
    proof: &MerkleProof,
    tx_hash: &[u8; 32],
) -> P4Result<bool> {
    let siblings: Vec<[u8; 32]> = proof.siblings.to_vec();
    let computed_root = compute_merkle_root(tx_hash, proof.tx_index, &siblings);
    let expected_root = extract_merkle_root(&proof.block_header);
    Ok(computed_root == expected_root)
}

/// 从区块头提取 Merkle 根
///
/// Bitcoin 区块头结构（80字节）:
/// - Version: 4 bytes
/// - Previous Block Hash: 32 bytes
/// - Merkle Root: 32 bytes (offset 36)
/// - Timestamp: 4 bytes
/// - Bits: 4 bytes
/// - Nonce: 4 bytes
pub fn extract_merkle_root(block_header: &[u8; 80]) -> [u8; 32] {
    let mut root = [0u8; 32];
    root.copy_from_slice(&block_header[36..68]);
    root
}

/// 从区块头提取前一个区块哈希
pub fn extract_prev_block_hash(block_header: &[u8; 80]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&block_header[4..36]);
    hash
}

/// 从区块头提取时间戳
pub fn extract_timestamp(block_header: &[u8; 80]) -> u32 {
    u32::from_le_bytes([
        block_header[68],
        block_header[69],
        block_header[70],
        block_header[71],
    ])
}

/// 计算区块头哈希
pub fn compute_block_hash(block_header: &[u8; 80]) -> [u8; 32] {
    double_sha256(block_header)
}

/// 计算 Merkle 根
///
/// 从交易哈希和兄弟节点计算 Merkle 根。
fn compute_merkle_root(
    tx_hash: &[u8; 32],
    tx_index: u32,
    siblings: &[[u8; 32]],
) -> [u8; 32] {
    let mut current = *tx_hash;
    let mut index = tx_index;

    for sibling in siblings {
        // 根据索引决定当前节点是左子还是右子
        if index.is_multiple_of(2) {
            // 当前节点是左子，兄弟是右子
            current = hash_pair(&current, sibling);
        } else {
            // 当前节点是右子，兄弟是左子
            current = hash_pair(sibling, &current);
        }
        index /= 2;
    }

    current
}

/// 计算两个哈希的父节点
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(left);
    data[32..].copy_from_slice(right);
    double_sha256(&data)
}

/// Bitcoin 双重 SHA256
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

/// 从交易列表构建 Merkle 树
pub fn build_merkle_tree(tx_hashes: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
    if tx_hashes.is_empty() {
        return vec![];
    }

    let mut levels: Vec<Vec<[u8; 32]>> = vec![tx_hashes.to_vec()];

    while levels.last().unwrap().len() > 1 {
        let current_level = levels.last().unwrap();
        let mut next_level = Vec::new();

        let mut i = 0;
        while i < current_level.len() {
            let left = &current_level[i];
            // 如果是奇数个节点，复制最后一个
            let right = if i + 1 < current_level.len() {
                &current_level[i + 1]
            } else {
                left
            };

            next_level.push(hash_pair(left, right));
            i += 2;
        }

        levels.push(next_level);
    }

    levels
}

/// 从 Merkle 树生成证明
pub fn generate_merkle_proof(
    tx_hashes: &[[u8; 32]],
    tx_index: usize,
    block_header: [u8; 80],
) -> Option<MerkleProof> {
    if tx_index >= tx_hashes.len() {
        return None;
    }

    let tree = build_merkle_tree(tx_hashes);
    let mut siblings = Vec::new();
    let mut index = tx_index;

    for level in tree.iter().take(tree.len() - 1) {
        let sibling_index = if index.is_multiple_of(2) {
            index + 1
        } else {
            index - 1
        };

        // 如果兄弟索引超出范围，使用自身（奇数节点情况）
        let sibling = if sibling_index < level.len() {
            level[sibling_index]
        } else {
            level[index]
        };

        siblings.push(sibling);
        index /= 2;
    }

    Some(MerkleProof {
        tx_index: tx_index as u32,
        siblings,
        block_header,
    })
}

/// Merkle 证明验证结果
#[derive(Debug, Clone)]
pub struct MerkleVerificationResult {
    /// 是否有效
    pub is_valid: bool,
    /// 计算得到的 Merkle 根
    pub computed_root: [u8; 32],
    /// 期望的 Merkle 根
    pub expected_root: [u8; 32],
    /// 区块哈希
    pub block_hash: [u8; 32],
}

/// 详细验证 Merkle 证明
pub fn verify_merkle_proof_detailed(
    proof: &MerkleProof,
    tx_hash: &[u8; 32],
) -> MerkleVerificationResult {
    let siblings: Vec<[u8; 32]> = proof.siblings.to_vec();
    let computed_root = compute_merkle_root(tx_hash, proof.tx_index, &siblings);
    let expected_root = extract_merkle_root(&proof.block_header);
    let block_hash = compute_block_hash(&proof.block_header);

    MerkleVerificationResult {
        is_valid: computed_root == expected_root,
        computed_root,
        expected_root,
        block_hash,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_double_sha256() {
        // 测试向量：空字符串的双重 SHA256
        let result = double_sha256(&[]);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hash_pair() {
        let left = [0x11u8; 32];
        let right = [0x22u8; 32];

        let result = hash_pair(&left, &right);
        assert_eq!(result.len(), 32);

        // 验证顺序敏感性
        let result2 = hash_pair(&right, &left);
        assert_ne!(result, result2);
    }

    #[test]
    fn test_build_merkle_tree_single() {
        let tx_hashes = [[0x11u8; 32]];
        let tree = build_merkle_tree(&tx_hashes);

        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].len(), 1);
        assert_eq!(tree[0][0], tx_hashes[0]);
    }

    #[test]
    fn test_build_merkle_tree_two() {
        let tx_hashes = [[0x11u8; 32], [0x22u8; 32]];
        let tree = build_merkle_tree(&tx_hashes);

        assert_eq!(tree.len(), 2);
        assert_eq!(tree[0].len(), 2);
        assert_eq!(tree[1].len(), 1);

        // 验证根是两个叶子的哈希
        let expected_root = hash_pair(&tx_hashes[0], &tx_hashes[1]);
        assert_eq!(tree[1][0], expected_root);
    }

    #[test]
    fn test_build_merkle_tree_three() {
        let tx_hashes = [[0x11u8; 32], [0x22u8; 32], [0x33u8; 32]];
        let tree = build_merkle_tree(&tx_hashes);

        assert_eq!(tree.len(), 3);
        assert_eq!(tree[0].len(), 3);
        assert_eq!(tree[1].len(), 2);
        assert_eq!(tree[2].len(), 1);
    }

    #[test]
    fn test_generate_and_verify_proof() {
        let tx_hashes = [
            [0x11u8; 32],
            [0x22u8; 32],
            [0x33u8; 32],
            [0x44u8; 32],
        ];

        // 构建树以获取正确的 Merkle 根
        let tree = build_merkle_tree(&tx_hashes);
        let merkle_root = tree.last().unwrap()[0];

        // 创建包含正确 Merkle 根的区块头
        let mut block_header = [0u8; 80];
        block_header[36..68].copy_from_slice(&merkle_root);

        // 为第二个交易生成证明
        let proof = generate_merkle_proof(&tx_hashes, 1, block_header).unwrap();

        // 验证证明
        let result = verify_merkle_proof_bytes(&proof, &tx_hashes[1]).unwrap();
        assert!(result);

        // 验证错误的交易应该失败
        let result = verify_merkle_proof_bytes(&proof, &tx_hashes[0]).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_merkle_proof_extract() {
        let mut block_header = [0u8; 80];
        // 设置 Merkle 根
        let merkle_root = [0xAB; 32];
        block_header[36..68].copy_from_slice(&merkle_root);

        assert_eq!(extract_merkle_root(&block_header), merkle_root);
    }

    #[test]
    fn test_compute_merkle_root_fn() {
        // 简单两个交易的情况
        let tx1 = [0x11u8; 32];
        let tx2 = [0x22u8; 32];

        let expected_root = hash_pair(&tx1, &tx2);

        // 从 tx1 计算（index 0，兄弟是 tx2）
        let computed = compute_merkle_root(&tx1, 0, &[tx2]);
        assert_eq!(computed, expected_root);

        // 从 tx2 计算（index 1，兄弟是 tx1）
        let computed = compute_merkle_root(&tx2, 1, &[tx1]);
        assert_eq!(computed, expected_root);
    }

    #[test]
    fn test_verification_result() {
        let tx_hash = [0x11u8; 32];
        let sibling = [0x22u8; 32];
        let merkle_root = hash_pair(&tx_hash, &sibling);

        let mut block_header = [0u8; 80];
        block_header[36..68].copy_from_slice(&merkle_root);

        let proof = MerkleProof {
            tx_index: 0,
            siblings: vec![sibling],
            block_header,
        };
        let result = verify_merkle_proof_detailed(&proof, &tx_hash);

        assert!(result.is_valid);
        assert_eq!(result.computed_root, result.expected_root);
    }
}
