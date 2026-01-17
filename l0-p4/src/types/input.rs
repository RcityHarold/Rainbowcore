//! ChainAnchorInput - 链锚定输入承诺
//!
//! 根据文档第2篇：ChainAnchorInput 是"要锚的承诺根"与"可对账引用集合"的输入合同。
//!
//! # 设计原则
//!
//! - Input 由 L0（P1）产出或承诺，不由执行器私造
//! - Input 必须引用 P1 序列事实：epoch_root（ΔE）与 linked_receipts_digest
//! - 禁止：用"执行器本地日志/本地批次号"冒充输入承诺

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

use super::common::*;

/// 链锚定输入 - 代表一个待锚定的承诺
///
/// # 字段类别白名单（根据文档第2篇）
///
/// - `input_id`: 幂等主键
/// - `epoch_root`: 主路锚定根（必须）
/// - `epoch_window`: 窗口语义（必须可对账）
/// - `linked_receipt_ids_digest`: 要被锚定的L0回执集合摘要（必须）
/// - `signer_set_version`: 阈签集合版本
/// - `chain_anchor_policy_version`: 对象池策略版本（必须）
/// - `canonicalization_version`: 用于重算digest（必须）
/// - `created_at`: 展示字段
/// - `gaps_digest`: 缺口显性化（不许静默）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainAnchorInput {
    /// 输入唯一标识（幂等主键）
    pub input_id: InputId,

    /// Epoch序列号
    pub epoch_sequence: u64,

    /// Epoch根（32字节哈希）- 主路锚定根
    pub epoch_root: Digest32,

    /// Epoch 窗口开始
    pub epoch_window_start: Timestamp,

    /// Epoch 窗口结束
    pub epoch_window_end: Timestamp,

    /// 关联的收据ID摘要 - 要被锚定的L0回执集合摘要
    pub linked_receipt_ids_digest: Digest32,

    /// 签名集合版本
    pub signer_set_version: u32,

    /// 策略版本 - 对象池策略版本
    pub policy_version: PolicyVersion,

    /// 规范版本 - 用于重算digest
    pub canon_version: CanonVersion,

    /// 创建时间戳（展示字段）
    pub created_at: Timestamp,

    /// 优先级（MUST/SHOULD/MAY）
    pub priority: AnchorPriority,

    /// 输入状态
    pub status: InputStatus,

    /// 缺口摘要（可选）- 缺口显性化，不许静默
    /// 若存在缺口，必须在此显性记录
    pub gaps_digest: Option<Digest32>,

    /// 覆盖证明引用（可选）
    /// 证明该 epoch_root 内批次根枚举未被选择性遗漏
    pub coverage_proof_ref: Option<Digest32>,
}

/// 输入状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum InputStatus {
    /// 待处理
    #[default]
    Pending,
    /// 已排队（等待Job创建）
    Queued,
    /// 已提交（Job已创建）
    Submitted,
    /// 已完成（Link已创建）
    Completed,
    /// 已失败（不可重试）
    Failed,
    /// 已跳过（非MUST级别，显性跳过）
    Skipped,
}


impl ChainAnchorInput {
    /// 创建新的锚定输入
    pub fn new(
        epoch_sequence: u64,
        epoch_root: Digest32,
        linked_receipt_ids_digest: Digest32,
        priority: AnchorPriority,
    ) -> Self {
        let now = Timestamp::now();
        let input_id = Self::compute_input_id(
            epoch_sequence,
            &epoch_root,
            &linked_receipt_ids_digest,
            now,
        );

        Self {
            input_id,
            epoch_sequence,
            epoch_root,
            epoch_window_start: now,
            epoch_window_end: now,
            linked_receipt_ids_digest,
            signer_set_version: 1,
            policy_version: PolicyVersion::default(),
            canon_version: CanonVersion::default(),
            created_at: now,
            priority,
            status: InputStatus::Pending,
            gaps_digest: None,
            coverage_proof_ref: None,
        }
    }

    /// 使用完整参数创建锚定输入
    #[allow(clippy::too_many_arguments)]
    pub fn with_full_params(
        epoch_sequence: u64,
        epoch_root: Digest32,
        epoch_window_start: Timestamp,
        epoch_window_end: Timestamp,
        linked_receipt_ids_digest: Digest32,
        signer_set_version: u32,
        policy_version: PolicyVersion,
        canon_version: CanonVersion,
        priority: AnchorPriority,
    ) -> Self {
        let now = Timestamp::now();
        let input_id = Self::compute_input_id(
            epoch_sequence,
            &epoch_root,
            &linked_receipt_ids_digest,
            now,
        );

        Self {
            input_id,
            epoch_sequence,
            epoch_root,
            epoch_window_start,
            epoch_window_end,
            linked_receipt_ids_digest,
            signer_set_version,
            policy_version,
            canon_version,
            created_at: now,
            priority,
            status: InputStatus::Pending,
            gaps_digest: None,
            coverage_proof_ref: None,
        }
    }

    /// 计算输入ID
    fn compute_input_id(
        epoch_sequence: u64,
        epoch_root: &Digest32,
        linked_receipt_ids_digest: &Digest32,
        created_at: Timestamp,
    ) -> InputId {
        let mut hasher = Sha256::new();
        hasher.update(epoch_sequence.to_be_bytes());
        hasher.update(epoch_root);
        hasher.update(linked_receipt_ids_digest);
        hasher.update(created_at.as_millis().to_be_bytes());
        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        id
    }

    /// 计算 anchor_input_digest
    ///
    /// 公式: H(canonical(Input))
    /// 同Input→同digest（跨实现一致）
    pub fn compute_digest(&self) -> Digest32 {
        let mut hasher = Sha256::new();

        // 按照规范顺序序列化
        hasher.update(self.epoch_root);
        hasher.update(self.epoch_sequence.to_be_bytes());
        hasher.update(self.linked_receipt_ids_digest);
        hasher.update(self.signer_set_version.to_be_bytes());
        hasher.update(self.policy_version.to_bytes());
        hasher.update(self.canon_version.to_bytes());
        hasher.update(self.epoch_window_start.as_millis().to_be_bytes());
        hasher.update(self.epoch_window_end.as_millis().to_be_bytes());

        // 可选字段
        if let Some(ref gaps) = self.gaps_digest {
            hasher.update([1u8]); // 标记存在
            hasher.update(gaps);
        } else {
            hasher.update([0u8]); // 标记不存在
        }

        let result = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&result);
        digest
    }

    /// 计算幂等键
    ///
    /// 公式: H(canonical(epoch_root + linked_receipt_ids_digest + policy_version + canon_version))
    pub fn compute_idempotency_key(&self) -> IdempotencyKey {
        let mut hasher = Sha256::new();

        // epoch_root
        hasher.update(self.epoch_root);

        // linked_receipt_ids_digest
        hasher.update(self.linked_receipt_ids_digest);

        // policy_version (as bytes)
        hasher.update(self.policy_version.to_bytes());

        // canon_version (as bytes)
        hasher.update(self.canon_version.to_bytes());

        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    /// 设置状态
    pub fn set_status(&mut self, status: InputStatus) {
        self.status = status;
    }

    /// 设置缺口摘要
    pub fn set_gaps_digest(&mut self, gaps: Digest32) {
        self.gaps_digest = Some(gaps);
    }

    /// 设置覆盖证明引用
    pub fn set_coverage_proof_ref(&mut self, proof_ref: Digest32) {
        self.coverage_proof_ref = Some(proof_ref);
    }

    /// 检查是否有缺口
    pub fn has_gaps(&self) -> bool {
        self.gaps_digest.is_some()
    }

    /// 检查是否有覆盖证明
    pub fn has_coverage_proof(&self) -> bool {
        self.coverage_proof_ref.is_some()
    }

    /// 验证输入完备性
    ///
    /// 根据文档要求，Input SHOULD 携带"覆盖证明引用"占位
    /// 缺覆盖证明时必须显性化（gaps_digest / MissingCoverageProof）
    pub fn validate_completeness(&self) -> InputValidationResult {
        let mut warnings = Vec::new();
        let mut errors = Vec::new();

        // 检查必填字段
        if self.epoch_root == [0u8; 32] {
            errors.push(InputValidationError::MissingEpochRoot);
        }

        if self.linked_receipt_ids_digest == [0u8; 32] {
            errors.push(InputValidationError::MissingLinkedReceiptsDigest);
        }

        // 检查窗口有效性
        if self.epoch_window_end < self.epoch_window_start {
            errors.push(InputValidationError::InvalidEpochWindow);
        }

        // 检查覆盖证明（警告级别）
        if !self.has_coverage_proof() && !self.has_gaps() {
            warnings.push(InputValidationWarning::MissingCoverageProof);
        }

        InputValidationResult {
            is_valid: errors.is_empty(),
            errors,
            warnings,
        }
    }

    /// 是否是 MUST 级别
    pub fn is_must(&self) -> bool {
        self.priority == AnchorPriority::Must
    }

    /// 是否已完成
    pub fn is_completed(&self) -> bool {
        self.status == InputStatus::Completed
    }

    /// 是否可以被丢弃（只有 MAY 级别可以）
    pub fn can_be_dropped(&self) -> bool {
        self.priority == AnchorPriority::May
    }
}

/// 输入验证结果
#[derive(Debug, Clone)]
pub struct InputValidationResult {
    pub is_valid: bool,
    pub errors: Vec<InputValidationError>,
    pub warnings: Vec<InputValidationWarning>,
}

/// 输入验证错误
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputValidationError {
    /// 缺少 epoch_root
    MissingEpochRoot,
    /// 缺少 linked_receipt_ids_digest
    MissingLinkedReceiptsDigest,
    /// 无效的 epoch 窗口
    InvalidEpochWindow,
    /// 未知的策略版本
    UnknownPolicyVersion,
    /// 未知的规范版本
    UnknownCanonVersion,
}

/// 输入验证警告
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputValidationWarning {
    /// 缺少覆盖证明
    MissingCoverageProof,
    /// 存在缺口
    HasGaps,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_input() {
        let epoch_root = [0x12; 32];
        let receipt_digest = [0x34; 32];

        let input = ChainAnchorInput::new(
            1,
            epoch_root,
            receipt_digest,
            AnchorPriority::Must,
        );

        assert_eq!(input.epoch_sequence, 1);
        assert_eq!(input.epoch_root, epoch_root);
        assert_eq!(input.linked_receipt_ids_digest, receipt_digest);
        assert_eq!(input.priority, AnchorPriority::Must);
        assert_eq!(input.status, InputStatus::Pending);
    }

    #[test]
    fn test_compute_idempotency_key() {
        let epoch_root = [0x12; 32];
        let receipt_digest = [0x34; 32];

        let input1 = ChainAnchorInput::new(1, epoch_root, receipt_digest, AnchorPriority::Must);
        let input2 = ChainAnchorInput::new(1, epoch_root, receipt_digest, AnchorPriority::Must);

        // 相同的核心参数应该产生相同的幂等键
        assert_eq!(
            input1.compute_idempotency_key(),
            input2.compute_idempotency_key()
        );
    }

    #[test]
    fn test_idempotency_key_differs_with_different_params() {
        let input1 = ChainAnchorInput::new(1, [0x12; 32], [0x34; 32], AnchorPriority::Must);
        let input2 = ChainAnchorInput::new(2, [0x12; 32], [0x34; 32], AnchorPriority::Must);

        // 注意：幂等键不包含 epoch_sequence，所以这两个应该相同
        // 如果需要区分，需要修改幂等键计算公式
        let key1 = input1.compute_idempotency_key();
        let key2 = input2.compute_idempotency_key();

        // 不同的 epoch_root 应该产生不同的幂等键
        let input3 = ChainAnchorInput::new(1, [0x56; 32], [0x34; 32], AnchorPriority::Must);
        assert_ne!(key1, input3.compute_idempotency_key());
    }

    #[test]
    fn test_validation() {
        let input = ChainAnchorInput::new(
            1,
            [0x12; 32],
            [0x34; 32],
            AnchorPriority::Must,
        );

        let result = input.validate_completeness();
        assert!(result.is_valid);
        // 应该有警告：缺少覆盖证明
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn test_validation_missing_epoch_root() {
        let input = ChainAnchorInput::new(
            1,
            [0x00; 32], // 零值 epoch_root
            [0x34; 32],
            AnchorPriority::Must,
        );

        let result = input.validate_completeness();
        assert!(!result.is_valid);
        assert!(result.errors.contains(&InputValidationError::MissingEpochRoot));
    }

    #[test]
    fn test_priority_can_be_dropped() {
        let must_input = ChainAnchorInput::new(1, [0x12; 32], [0x34; 32], AnchorPriority::Must);
        let should_input = ChainAnchorInput::new(1, [0x12; 32], [0x34; 32], AnchorPriority::Should);
        let may_input = ChainAnchorInput::new(1, [0x12; 32], [0x34; 32], AnchorPriority::May);

        assert!(!must_input.can_be_dropped());
        assert!(!should_input.can_be_dropped());
        assert!(may_input.can_be_dropped());
    }
}
