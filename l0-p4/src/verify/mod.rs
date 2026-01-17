//! 验证模块
//!
//! 提供链锚定验证功能。
//!
//! # 核心功能
//!
//! - Link 验证：验证 ChainAnchorLink 的有效性
//! - Merkle 证明验证：SPV 验证交易包含在区块中
//! - 伪背书检测：检测系统中的异常状态
//!
//! # 设计原则
//!
//! - 独立验证：无需信任任何中间层
//! - 完整审计：所有验证结果可追溯
//! - 防伪造：确保链锚定的真实性

pub mod merkle;
pub mod fake_endorsement;

pub use merkle::{
    MerkleVerificationResult,
    verify_merkle_proof, verify_merkle_proof_bytes, verify_merkle_proof_detailed,
    build_merkle_tree, generate_merkle_proof,
    extract_merkle_root, extract_prev_block_hash, extract_timestamp,
    compute_block_hash, double_sha256,
};

pub use fake_endorsement::{
    FakeEndorsementDetector, FakeEndorsement, FakeEndorsementType,
    FakeEndorsementEvidence, DetectionSummary,
};

use crate::error::{P4Error, P4Result};
use crate::tx_builder::parse_anchor_from_tx;
use crate::types::{ChainAnchorInput, ChainAnchorLink};

/// 验证 Link 与 Input 的匹配
///
/// 验证 ChainAnchorLink 是否正确对应给定的 ChainAnchorInput。
///
/// # 验证项目
///
/// 1. epoch_root 匹配
/// 2. epoch_sequence 匹配
/// 3. linked_receipt_ids_digest 匹配
/// 4. 交易数据中的锚定数据匹配
/// 5. Merkle 证明（如有）
pub fn verify_anchor_link(
    link: &ChainAnchorLink,
    expected_input: &ChainAnchorInput,
) -> P4Result<LinkVerificationResult> {
    let mut result = LinkVerificationResult::new(link.link_id, expected_input.input_id);

    // 1. 验证 epoch_root 匹配
    if link.epoch_root != expected_input.epoch_root {
        result.add_mismatch(
            VerificationMismatch::EpochRoot {
                expected: expected_input.epoch_root,
                actual: link.epoch_root,
            }
        );
    }

    // 2. 验证 epoch_sequence 匹配
    if link.epoch_sequence != expected_input.epoch_sequence {
        result.add_mismatch(
            VerificationMismatch::EpochSequence {
                expected: expected_input.epoch_sequence,
                actual: link.epoch_sequence,
            }
        );
    }

    // 3. 验证 linked_receipt_ids_digest 匹配
    if link.linked_receipt_ids_digest != expected_input.linked_receipt_ids_digest {
        result.add_mismatch(
            VerificationMismatch::LinkedReceiptIdsDigest {
                expected: expected_input.linked_receipt_ids_digest,
                actual: link.linked_receipt_ids_digest,
            }
        );
    }

    // 4. 验证交易数据中的锚定数据
    if let Some(ref tx_hex) = link.tx_hex {
        match parse_anchor_from_tx(tx_hex) {
            Ok(Some(parsed)) => {
                if parsed.epoch_root != expected_input.epoch_root {
                    result.add_mismatch(
                        VerificationMismatch::TransactionData {
                            description: "epoch_root in transaction does not match".to_string(),
                        }
                    );
                }
                if parsed.epoch_sequence != expected_input.epoch_sequence {
                    result.add_mismatch(
                        VerificationMismatch::TransactionData {
                            description: "epoch_sequence in transaction does not match".to_string(),
                        }
                    );
                }
            }
            Ok(None) => {
                result.add_mismatch(
                    VerificationMismatch::TransactionData {
                        description: "No anchor data found in transaction".to_string(),
                    }
                );
            }
            Err(e) => {
                result.add_mismatch(
                    VerificationMismatch::TransactionData {
                        description: format!("Failed to parse transaction: {}", e),
                    }
                );
            }
        }
    }

    // 5. 验证 Merkle 证明（如有）
    if let Some(ref proof) = link.merkle_proof {
        match verify_merkle_proof(proof, &link.txid_or_asset_id) {
            Ok(true) => {
                result.merkle_proof_valid = Some(true);
            }
            Ok(false) => {
                result.merkle_proof_valid = Some(false);
                result.add_mismatch(
                    VerificationMismatch::MerkleProof {
                        description: "Merkle proof verification failed".to_string(),
                    }
                );
            }
            Err(e) => {
                result.merkle_proof_valid = Some(false);
                result.add_mismatch(
                    VerificationMismatch::MerkleProof {
                        description: format!("Merkle proof error: {}", e),
                    }
                );
            }
        }
    }

    Ok(result)
}

/// 批量验证 Link
pub fn verify_anchor_bundle(
    links: &[ChainAnchorLink],
    inputs: &[ChainAnchorInput],
) -> P4Result<BundleVerificationResult> {
    if links.len() != inputs.len() {
        return Err(P4Error::InvalidInput(format!(
            "Link count ({}) does not match input count ({})",
            links.len(), inputs.len()
        )));
    }

    let mut results = Vec::new();

    for (link, input) in links.iter().zip(inputs.iter()) {
        let result = verify_anchor_link(link, input)?;
        results.push(result);
    }

    let all_valid = results.iter().all(|r| r.is_valid());
    let valid_count = results.iter().filter(|r| r.is_valid()).count();

    Ok(BundleVerificationResult {
        all_valid,
        total_count: results.len(),
        valid_count,
        invalid_count: results.len() - valid_count,
        individual_results: results,
    })
}

/// 验证确认数
pub fn verify_confirmations(
    link: &ChainAnchorLink,
    required: u32,
) -> ConfirmationVerificationResult {
    ConfirmationVerificationResult {
        link_id: link.link_id,
        current_confirmations: link.confirmations,
        required_confirmations: required,
        is_sufficient: link.confirmations >= required,
    }
}

/// Link 验证结果
#[derive(Debug, Clone)]
pub struct LinkVerificationResult {
    /// Link ID
    pub link_id: [u8; 32],
    /// Input ID
    pub input_id: [u8; 32],
    /// 不匹配项
    pub mismatches: Vec<VerificationMismatch>,
    /// Merkle 证明是否有效
    pub merkle_proof_valid: Option<bool>,
}

impl LinkVerificationResult {
    /// 创建新的验证结果
    pub fn new(link_id: [u8; 32], input_id: [u8; 32]) -> Self {
        Self {
            link_id,
            input_id,
            mismatches: Vec::new(),
            merkle_proof_valid: None,
        }
    }

    /// 添加不匹配项
    pub fn add_mismatch(&mut self, mismatch: VerificationMismatch) {
        self.mismatches.push(mismatch);
    }

    /// 是否验证通过
    pub fn is_valid(&self) -> bool {
        self.mismatches.is_empty()
    }

    /// 获取不匹配数量
    pub fn mismatch_count(&self) -> usize {
        self.mismatches.len()
    }
}

/// 验证不匹配类型
#[derive(Debug, Clone)]
pub enum VerificationMismatch {
    /// epoch_root 不匹配
    EpochRoot {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// epoch_sequence 不匹配
    EpochSequence {
        expected: u64,
        actual: u64,
    },
    /// linked_receipt_ids_digest 不匹配
    LinkedReceiptIdsDigest {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// 交易数据不匹配
    TransactionData {
        description: String,
    },
    /// Merkle 证明不匹配
    MerkleProof {
        description: String,
    },
}

impl std::fmt::Display for VerificationMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EpochRoot { expected, actual } => {
                write!(f, "epoch_root mismatch: expected {}, got {}",
                    hex::encode(&expected[..8]),
                    hex::encode(&actual[..8])
                )
            }
            Self::EpochSequence { expected, actual } => {
                write!(f, "epoch_sequence mismatch: expected {}, got {}", expected, actual)
            }
            Self::LinkedReceiptIdsDigest { expected, actual } => {
                write!(f, "linked_receipt_ids_digest mismatch: expected {}, got {}",
                    hex::encode(&expected[..8]),
                    hex::encode(&actual[..8])
                )
            }
            Self::TransactionData { description } => {
                write!(f, "transaction data mismatch: {}", description)
            }
            Self::MerkleProof { description } => {
                write!(f, "merkle proof mismatch: {}", description)
            }
        }
    }
}

/// 批量验证结果
#[derive(Debug, Clone)]
pub struct BundleVerificationResult {
    /// 是否全部通过
    pub all_valid: bool,
    /// 总数
    pub total_count: usize,
    /// 通过数
    pub valid_count: usize,
    /// 失败数
    pub invalid_count: usize,
    /// 个体结果
    pub individual_results: Vec<LinkVerificationResult>,
}

/// 确认数验证结果
#[derive(Debug, Clone)]
pub struct ConfirmationVerificationResult {
    /// Link ID
    pub link_id: [u8; 32],
    /// 当前确认数
    pub current_confirmations: u32,
    /// 所需确认数
    pub required_confirmations: u32,
    /// 是否满足要求
    pub is_sufficient: bool,
}

/// 完整验证（包含链上确认）
pub async fn verify_anchor_link_complete<S: crate::storage::AnchorStorage + 'static>(
    link: &ChainAnchorLink,
    input: &ChainAnchorInput,
    storage: std::sync::Arc<S>,
    required_confirmations: u32,
) -> P4Result<CompleteVerificationResult> {
    // 基本验证
    let link_result = verify_anchor_link(link, input)?;

    // 确认数验证
    let confirmation_result = verify_confirmations(link, required_confirmations);

    // 伪背书检测
    let detector = FakeEndorsementDetector::new(storage, required_confirmations);
    let fake_endorsement = detector.detect(&input.input_id).await?;

    Ok(CompleteVerificationResult {
        link_verification: link_result,
        confirmation_verification: confirmation_result,
        fake_endorsement,
        is_fully_valid: false, // 将在下面计算
    }.compute_validity())
}

/// 完整验证结果
#[derive(Debug, Clone)]
pub struct CompleteVerificationResult {
    /// Link 验证结果
    pub link_verification: LinkVerificationResult,
    /// 确认数验证结果
    pub confirmation_verification: ConfirmationVerificationResult,
    /// 伪背书检测结果
    pub fake_endorsement: Option<FakeEndorsement>,
    /// 是否完全有效
    pub is_fully_valid: bool,
}

impl CompleteVerificationResult {
    /// 计算最终有效性
    fn compute_validity(mut self) -> Self {
        self.is_fully_valid = self.link_verification.is_valid()
            && self.confirmation_verification.is_sufficient
            && self.fake_endorsement.is_none();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AnchorPriority, ChainType, PolicyVersion};

    fn create_test_input() -> ChainAnchorInput {
        ChainAnchorInput::new(
            1,
            [0x12; 32],
            [0x34; 32],
            AnchorPriority::Must,
        )
    }

    fn create_matching_link(input: &ChainAnchorInput) -> ChainAnchorLink {
        ChainAnchorLink::new(
            [0xAB; 32], // job_id
            input.input_id,
            ChainType::Bitcoin,
            "txid123".to_string(),
            input.epoch_sequence,
            input.epoch_root,
            input.linked_receipt_ids_digest,
            PolicyVersion::default(),
        )
    }

    #[test]
    fn test_verify_matching_link() {
        let input = create_test_input();
        let link = create_matching_link(&input);

        let result = verify_anchor_link(&link, &input).unwrap();
        assert!(result.is_valid());
        assert_eq!(result.mismatch_count(), 0);
    }

    #[test]
    fn test_verify_epoch_root_mismatch() {
        let input = create_test_input();
        let mut link = create_matching_link(&input);
        link.epoch_root = [0xFF; 32]; // 不匹配的 epoch_root

        let result = verify_anchor_link(&link, &input).unwrap();
        assert!(!result.is_valid());
        assert!(result.mismatches.iter().any(|m| matches!(m, VerificationMismatch::EpochRoot { .. })));
    }

    #[test]
    fn test_verify_epoch_sequence_mismatch() {
        let input = create_test_input();
        let mut link = create_matching_link(&input);
        link.epoch_sequence = 999; // 不匹配的 epoch_sequence

        let result = verify_anchor_link(&link, &input).unwrap();
        assert!(!result.is_valid());
        assert!(result.mismatches.iter().any(|m| matches!(m, VerificationMismatch::EpochSequence { .. })));
    }

    #[test]
    fn test_verify_bundle() {
        let input1 = create_test_input();
        let link1 = create_matching_link(&input1);

        let input2 = ChainAnchorInput::new(2, [0x56; 32], [0x78; 32], AnchorPriority::Should);
        let link2 = create_matching_link(&input2);

        let result = verify_anchor_bundle(&[link1, link2], &[input1, input2]).unwrap();
        assert!(result.all_valid);
        assert_eq!(result.valid_count, 2);
        assert_eq!(result.invalid_count, 0);
    }

    #[test]
    fn test_verify_confirmations() {
        let input = create_test_input();
        let mut link = create_matching_link(&input);
        link.confirmations = 3;

        let result = verify_confirmations(&link, 6);
        assert!(!result.is_sufficient);
        assert_eq!(result.current_confirmations, 3);
        assert_eq!(result.required_confirmations, 6);

        link.confirmations = 6;
        let result = verify_confirmations(&link, 6);
        assert!(result.is_sufficient);
    }

    #[test]
    fn test_verification_mismatch_display() {
        let mismatch = VerificationMismatch::EpochSequence {
            expected: 1,
            actual: 2,
        };
        assert!(format!("{}", mismatch).contains("epoch_sequence mismatch"));
    }
}
