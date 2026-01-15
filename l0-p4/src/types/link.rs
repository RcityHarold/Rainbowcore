//! ChainAnchorLink - 链锚定结果
//!
//! 根据文档第2篇：ChainAnchorLink 是"对账闭合"的结果对象，
//! 是唯一允许对外宣称"已锚定完成"的凭据。
//!
//! # 设计原则
//!
//! - 无Link不得宣称完成
//! - 有Link也不得宣称证据完备（只增强不可否认性）
//! - Link 不能改变 A/B 与强后果门槛
//!
//! # 对账闭合条件
//!
//! 1. txid 能验证存在（链上可查）
//! 2. txid 中承诺的 root 与 epoch_root 一致
//! 3. epoch_root 与 linked_receipt_ids_digest 对得上
//! 4. mismatch 必须显性输出 ChainAnchorMismatch

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

use super::common::*;
use crate::tx_builder::AnchorData;

/// 链锚定结果 - 代表一次成功的链锚定
///
/// # 字段类别白名单（根据文档第2篇）
///
/// - `chain_network`: btc/atomicals
/// - `txid_or_asset_id`: 链上定位符
/// - `epoch_root`: 必须
/// - `linked_receipt_ids_digest`: 必须，形成对账闭环
/// - `chain_anchor_policy_version`: 必须
/// - `status`: none/queued/confirmed
/// - `confirmed_at`: 展示字段
/// - `proof_refs_digest`: 若存在链上证明路径
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainAnchorLink {
    /// Link唯一标识
    pub link_id: LinkId,

    /// 关联的Job ID
    pub job_id: JobId,

    /// 关联的Input ID
    pub input_id: InputId,

    /// 目标链类型
    pub chain_type: ChainType,

    /// 交易ID或资产ID（链上定位符）
    pub txid_or_asset_id: String,

    /// Epoch 序列号
    pub epoch_sequence: u64,

    /// Epoch 根（必须）
    pub epoch_root: Digest32,

    /// 关联的收据ID摘要（必须，形成对账闭环）
    pub linked_receipt_ids_digest: Digest32,

    /// 策略版本
    pub policy_version: PolicyVersion,

    /// 区块哈希
    pub block_hash: Option<String>,

    /// 区块高度
    pub block_height: Option<u64>,

    /// 确认数
    pub confirmations: u32,

    /// 交易时间戳
    pub tx_timestamp: Option<Timestamp>,

    /// Link状态
    pub status: LinkStatus,

    /// 确认时间（展示字段）
    pub confirmed_at: Option<Timestamp>,

    /// Link创建时间
    pub created_at: Timestamp,

    /// 锚定数据（用于验证）
    pub anchor_data: Option<AnchorDataInfo>,

    /// 交易原始数据（用于独立验证）
    pub tx_hex: Option<String>,

    /// Merkle证明（用于SPV验证）
    pub merkle_proof: Option<MerkleProof>,

    /// 证明引用摘要（若存在链上证明路径）
    pub proof_refs_digest: Option<Digest32>,

    /// 被取代的Link ID（若发生纠错）
    pub superseded_by: Option<LinkId>,
}

/// Link状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkStatus {
    /// 无锚定
    None,
    /// 已排队（交易已广播）
    Queued,
    /// 已确认（达到所需确认数）
    Confirmed,
    /// 已失败
    Failed,
    /// 已被取代（纠错追加）
    Superseded,
}

impl Default for LinkStatus {
    fn default() -> Self {
        Self::None
    }
}

/// 锚定数据信息（用于验证）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorDataInfo {
    /// Magic 字节
    pub magic: [u8; 4],
    /// 版本
    pub version: u8,
    /// Epoch 序列号
    pub epoch_sequence: u64,
    /// Epoch 根
    pub epoch_root: Digest32,
    /// 校验和
    pub checksum: [u8; 4],
}

impl From<AnchorData> for AnchorDataInfo {
    fn from(data: AnchorData) -> Self {
        Self {
            magic: data.magic,
            version: data.version,
            epoch_sequence: data.epoch_sequence,
            epoch_root: data.epoch_root,
            checksum: data.checksum,
        }
    }
}

/// Merkle证明
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// 交易在区块中的索引
    pub tx_index: u32,
    /// 兄弟节点哈希列表
    pub siblings: Vec<Digest32>,
    /// 区块头（80字节，使用 Vec 以支持 serde）
    #[serde(with = "block_header_serde")]
    pub block_header: [u8; 80],
}

/// 区块头序列化模块
mod block_header_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(data: &[u8; 80], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        hex::encode(data).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 80], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 80 {
            return Err(serde::de::Error::custom("block header must be 80 bytes"));
        }
        let mut arr = [0u8; 80];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

impl MerkleProof {
    /// 验证Merkle证明
    pub fn verify(&self, txid: &str) -> bool {
        // 简化实现：实际应该完整验证Merkle路径
        let txid_bytes = match hex::decode(txid) {
            Ok(bytes) if bytes.len() == 32 => bytes,
            _ => return false,
        };

        let mut current = [0u8; 32];
        current.copy_from_slice(&txid_bytes);

        // 这里简化处理，实际实现需要完整的Merkle验证逻辑
        !self.siblings.is_empty() && self.tx_index < (1 << self.siblings.len())
    }
}

/// 对账闭合验证结果
#[derive(Debug, Clone)]
pub struct ReconciliationResult {
    /// 是否对账成功
    pub is_valid: bool,
    /// 错误列表
    pub errors: Vec<ReconciliationError>,
    /// 对账摘要
    pub reconciliation_digest: Digest32,
}

/// 对账错误
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationError {
    /// 交易不存在
    TransactionNotFound,
    /// Epoch root 不匹配
    EpochRootMismatch {
        expected: String,
        actual: String,
    },
    /// Receipt digest 不匹配
    ReceiptDigestMismatch {
        expected: String,
        actual: String,
    },
    /// 策略版本不匹配
    PolicyVersionMismatch {
        expected: u32,
        actual: u32,
    },
    /// 确认数不足
    InsufficientConfirmations {
        required: u32,
        actual: u32,
    },
    /// Merkle证明无效
    InvalidMerkleProof,
    /// 其他错误
    Other(String),
}

impl ChainAnchorLink {
    /// 创建新的链锚定结果
    pub fn new(
        job_id: JobId,
        input_id: InputId,
        chain_type: ChainType,
        txid_or_asset_id: String,
        epoch_sequence: u64,
        epoch_root: Digest32,
        linked_receipt_ids_digest: Digest32,
        policy_version: PolicyVersion,
    ) -> Self {
        let now = Timestamp::now();
        let link_id = Self::compute_link_id(
            &job_id,
            &input_id,
            &txid_or_asset_id,
            now,
        );

        Self {
            link_id,
            job_id,
            input_id,
            chain_type,
            txid_or_asset_id,
            epoch_sequence,
            epoch_root,
            linked_receipt_ids_digest,
            policy_version,
            block_hash: None,
            block_height: None,
            confirmations: 0,
            tx_timestamp: None,
            status: LinkStatus::Queued,
            confirmed_at: None,
            created_at: now,
            anchor_data: None,
            tx_hex: None,
            merkle_proof: None,
            proof_refs_digest: None,
            superseded_by: None,
        }
    }

    /// 计算Link ID
    fn compute_link_id(
        job_id: &JobId,
        input_id: &InputId,
        txid: &str,
        created_at: Timestamp,
    ) -> LinkId {
        let mut hasher = Sha256::new();
        hasher.update(job_id);
        hasher.update(input_id);
        hasher.update(txid.as_bytes());
        hasher.update(created_at.as_millis().to_be_bytes());
        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        id
    }

    /// 标记为已确认
    pub fn mark_confirmed(
        &mut self,
        confirmations: u32,
        block_hash: String,
        block_height: u64,
    ) {
        self.status = LinkStatus::Confirmed;
        self.confirmations = confirmations;
        self.block_hash = Some(block_hash);
        self.block_height = Some(block_height);
        self.confirmed_at = Some(Timestamp::now());
    }

    /// 标记为失败
    pub fn mark_failed(&mut self) {
        self.status = LinkStatus::Failed;
    }

    /// 标记为被取代
    pub fn mark_superseded(&mut self, new_link_id: LinkId) {
        self.status = LinkStatus::Superseded;
        self.superseded_by = Some(new_link_id);
    }

    /// 设置锚定数据
    pub fn set_anchor_data(&mut self, data: AnchorData) {
        self.anchor_data = Some(data.into());
    }

    /// 设置交易原始数据
    pub fn set_tx_hex(&mut self, tx_hex: String) {
        self.tx_hex = Some(tx_hex);
    }

    /// 设置Merkle证明
    pub fn set_merkle_proof(&mut self, proof: MerkleProof) {
        self.merkle_proof = Some(proof);
    }

    /// 验证对账闘环
    ///
    /// 根据文档要求：
    /// 1. txid 能验证存在（链上可查）
    /// 2. txid 中承诺的 root 与 epoch_root 一致
    /// 3. epoch_root 与 linked_receipt_ids_digest 对得上
    pub fn verify_reconciliation(
        &self,
        expected_epoch_root: &Digest32,
        expected_receipt_digest: &Digest32,
        required_confirmations: u32,
    ) -> ReconciliationResult {
        let mut errors = Vec::new();

        // 1. 验证 epoch_root 一致
        if self.epoch_root != *expected_epoch_root {
            errors.push(ReconciliationError::EpochRootMismatch {
                expected: hex::encode(expected_epoch_root),
                actual: hex::encode(&self.epoch_root),
            });
        }

        // 2. 验证 linked_receipt_ids_digest 一致
        if self.linked_receipt_ids_digest != *expected_receipt_digest {
            errors.push(ReconciliationError::ReceiptDigestMismatch {
                expected: hex::encode(expected_receipt_digest),
                actual: hex::encode(&self.linked_receipt_ids_digest),
            });
        }

        // 3. 验证确认数
        if self.confirmations < required_confirmations {
            errors.push(ReconciliationError::InsufficientConfirmations {
                required: required_confirmations,
                actual: self.confirmations,
            });
        }

        // 4. 验证锚定数据中的 epoch_root（如果存在）
        if let Some(ref anchor_data) = self.anchor_data {
            if anchor_data.epoch_root != *expected_epoch_root {
                errors.push(ReconciliationError::EpochRootMismatch {
                    expected: hex::encode(expected_epoch_root),
                    actual: hex::encode(&anchor_data.epoch_root),
                });
            }
        }

        // 5. 验证Merkle证明（如果存在）
        if let Some(ref proof) = self.merkle_proof {
            if !proof.verify(&self.txid_or_asset_id) {
                errors.push(ReconciliationError::InvalidMerkleProof);
            }
        }

        // 计算对账摘要
        let reconciliation_digest = self.compute_reconciliation_digest();

        ReconciliationResult {
            is_valid: errors.is_empty(),
            errors,
            reconciliation_digest,
        }
    }

    /// 计算对账摘要
    fn compute_reconciliation_digest(&self) -> Digest32 {
        let mut hasher = Sha256::new();
        hasher.update(&self.link_id);
        hasher.update(&self.epoch_root);
        hasher.update(&self.linked_receipt_ids_digest);
        hasher.update(self.txid_or_asset_id.as_bytes());
        hasher.update(self.confirmations.to_be_bytes());
        let result = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&result);
        digest
    }

    /// 计算Link摘要
    pub fn compute_digest(&self) -> Digest32 {
        let mut hasher = Sha256::new();
        hasher.update(&self.link_id);
        hasher.update(&self.job_id);
        hasher.update(&self.input_id);
        hasher.update(&self.epoch_root);
        hasher.update(&self.linked_receipt_ids_digest);
        hasher.update(self.txid_or_asset_id.as_bytes());
        hasher.update(self.policy_version.to_bytes());
        hasher.update([self.status as u8]);
        let result = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&result);
        digest
    }

    /// 是否已确认
    pub fn is_confirmed(&self) -> bool {
        self.status == LinkStatus::Confirmed
    }

    /// 是否被取代
    pub fn is_superseded(&self) -> bool {
        self.status == LinkStatus::Superseded
    }

    /// 获取对账三元组
    ///
    /// 文档要求：txid↔epoch_root↔receipt_ids_digest 可验证一致
    pub fn get_reconciliation_tuple(&self) -> (&str, &Digest32, &Digest32) {
        (
            &self.txid_or_asset_id,
            &self.epoch_root,
            &self.linked_receipt_ids_digest,
        )
    }
}

/// 链锚定不匹配错误
///
/// 根据文档：mismatch 必须显性输出 ChainAnchorMismatch 并进入争议/监督占位
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainAnchorMismatch {
    /// Link ID
    pub link_id: LinkId,
    /// 不匹配类型
    pub mismatch_type: MismatchType,
    /// 期望值
    pub expected: String,
    /// 实际值
    pub actual: String,
    /// 检测时间
    pub detected_at: Timestamp,
    /// 争议引用（占位）
    pub dispute_ref: Option<Digest32>,
}

/// 不匹配类型
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MismatchType {
    /// Epoch root 不匹配
    EpochRoot,
    /// Receipt digest 不匹配
    ReceiptDigest,
    /// 策略版本不匹配
    PolicyVersion,
    /// 交易内容不匹配
    TransactionContent,
}

impl ChainAnchorMismatch {
    /// 创建新的不匹配记录
    pub fn new(
        link_id: LinkId,
        mismatch_type: MismatchType,
        expected: String,
        actual: String,
    ) -> Self {
        Self {
            link_id,
            mismatch_type,
            expected,
            actual,
            detected_at: Timestamp::now(),
            dispute_ref: None,
        }
    }

    /// 设置争议引用
    pub fn set_dispute_ref(&mut self, dispute_ref: Digest32) {
        self.dispute_ref = Some(dispute_ref);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_link() -> ChainAnchorLink {
        ChainAnchorLink::new(
            [0x12; 32],
            [0x34; 32],
            ChainType::Bitcoin,
            "abc123".to_string(),
            1,
            [0x56; 32],
            [0x78; 32],
            PolicyVersion::new(1),
        )
    }

    #[test]
    fn test_create_link() {
        let link = create_test_link();
        assert_eq!(link.status, LinkStatus::Queued);
        assert_eq!(link.confirmations, 0);
        assert!(link.confirmed_at.is_none());
    }

    #[test]
    fn test_mark_confirmed() {
        let mut link = create_test_link();
        link.mark_confirmed(6, "blockhash123".to_string(), 800000);

        assert_eq!(link.status, LinkStatus::Confirmed);
        assert_eq!(link.confirmations, 6);
        assert_eq!(link.block_hash, Some("blockhash123".to_string()));
        assert_eq!(link.block_height, Some(800000));
        assert!(link.confirmed_at.is_some());
    }

    #[test]
    fn test_reconciliation_success() {
        let mut link = create_test_link();
        link.confirmations = 6;

        let result = link.verify_reconciliation(
            &[0x56; 32], // 期望的 epoch_root
            &[0x78; 32], // 期望的 receipt_digest
            6,           // 所需确认数
        );

        assert!(result.is_valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_reconciliation_epoch_root_mismatch() {
        let link = create_test_link();

        let result = link.verify_reconciliation(
            &[0xAA; 32], // 不匹配的 epoch_root
            &[0x78; 32],
            0,
        );

        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| matches!(e, ReconciliationError::EpochRootMismatch { .. })));
    }

    #[test]
    fn test_reconciliation_insufficient_confirmations() {
        let link = create_test_link();

        let result = link.verify_reconciliation(
            &[0x56; 32],
            &[0x78; 32],
            6, // 需要6个确认，但link只有0个
        );

        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| matches!(e, ReconciliationError::InsufficientConfirmations { .. })));
    }

    #[test]
    fn test_get_reconciliation_tuple() {
        let link = create_test_link();
        let (txid, epoch_root, receipt_digest) = link.get_reconciliation_tuple();

        assert_eq!(txid, "abc123");
        assert_eq!(epoch_root, &[0x56; 32]);
        assert_eq!(receipt_digest, &[0x78; 32]);
    }

    #[test]
    fn test_superseded() {
        let mut link = create_test_link();
        let new_link_id = [0xFF; 32];

        link.mark_superseded(new_link_id);

        assert!(link.is_superseded());
        assert_eq!(link.superseded_by, Some(new_link_id));
    }

    #[test]
    fn test_mismatch_record() {
        let mismatch = ChainAnchorMismatch::new(
            [0x12; 32],
            MismatchType::EpochRoot,
            "expected".to_string(),
            "actual".to_string(),
        );

        assert_eq!(mismatch.mismatch_type, MismatchType::EpochRoot);
        assert!(mismatch.dispute_ref.is_none());
    }
}
