//! ReconcileResult - 对账结果
//!
//! 根据文档第1篇和第9篇：实现三状态分离输出。
//!
//! # 三状态分离（P4 必须输出的公共语义模板）
//!
//! - `evidence_status`: A/B/pending_evidence（来自P1/P2，P4不得改写）
//! - `execution_status`: pending/executed/resolved（来自执行闘环）
//! - `chain_anchor_status`: none/queued/confirmed（P4唯一负责）
//!
//! # 三状态"不可混同"硬规则
//!
//! - confirmed ≠ A
//! - executed ≠ resolved（resolved=对账闭合）
//! - 任何"强结算/强清算已完成"叙事必须同时满足：证据门槛+执行证明+链锚状态

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

use super::common::*;
use super::link::ReconciliationError;

/// 对账结果 - 输入与链锚定的最终对账
///
/// 实现文档要求的三状态分离输出。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconcileResult {
    /// 对账ID
    pub reconcile_id: ReconcileId,

    /// 关联的Input ID
    pub input_id: InputId,

    /// 关联的Link ID（成功时必须有）
    pub link_id: Option<LinkId>,

    /// 关联的Job ID
    pub job_id: Option<JobId>,

    /// 对账状态
    pub status: ReconcileStatus,

    /// 证据状态（与链锚定状态分离）
    /// 来自P1/P2，P4不得改写
    pub evidence_status: EvidenceStatus,

    /// 执行状态
    /// 来自执行闘环
    pub execution_status: ExecutionStatus,

    /// 链锚定状态
    /// P4唯一负责
    pub chain_anchor_status: ChainAnchorStatus,

    /// 对账时间
    pub reconciled_at: Timestamp,

    /// 失败原因（如有）
    pub failure_reason: Option<ReconcileFailure>,

    /// 错误码列表（稳定排序）
    pub error_codes: Vec<ReconcileErrorCode>,

    /// 对账摘要
    pub reconcile_digest: Digest32,

    /// 关联引用摘要（对账入口摘要）
    pub linked_refs_digest: Digest32,
}

/// 对账状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum ReconcileStatus {
    /// 成功（三状态均完成）
    Success,
    /// 部分成功（链锚定成功但证据未完成）
    PartialSuccess,
    /// 失败
    Failed,
    /// 待处理
    #[default]
    Pending,
}


/// 证据状态（与链锚定分离）
///
/// 来自P1/P2，P4不得改写。
/// 核心原则：confirmed ≠ A（链锚定不等于证据完备）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum EvidenceStatus {
    /// 证据等级A（完整）
    /// 注意：这不受链锚定影响
    A,
    /// 证据等级B（不完整）
    B,
    /// 证据待处理
    #[default]
    PendingEvidence,
    /// 证据缺失
    Missing,
}


impl EvidenceStatus {
    /// 是否是完整证据
    pub fn is_complete(&self) -> bool {
        *self == Self::A
    }

    /// 是否允许强后果（强结算/强清算）
    pub fn allows_strong_consequence(&self) -> bool {
        *self == Self::A
    }
}

/// 执行状态
///
/// 来自执行闘环。
/// 核心原则：executed ≠ resolved（resolved=对账闭合）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum ExecutionStatus {
    /// 未开始
    #[default]
    NotStarted,
    /// 执行中
    InProgress,
    /// 执行成功
    Executed,
    /// 已对账闭合（resolved=对账闭合）
    Resolved,
    /// 执行失败
    Failed,
}


impl ExecutionStatus {
    /// 是否已执行
    pub fn is_executed(&self) -> bool {
        matches!(self, Self::Executed | Self::Resolved)
    }

    /// 是否已对账闭合
    pub fn is_resolved(&self) -> bool {
        *self == Self::Resolved
    }
}

/// 链锚定状态
///
/// P4唯一负责的状态。
/// 核心原则：confirmed ≠ A（链锚定不等于证据完备）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum ChainAnchorStatus {
    /// 未锚定
    #[default]
    None,
    /// 已排队
    Queued,
    /// 已确认
    Confirmed,
    /// 失败
    Failed,
}


impl ChainAnchorStatus {
    /// 是否已确认
    pub fn is_confirmed(&self) -> bool {
        *self == Self::Confirmed
    }
}

/// 对账失败原因
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconcileFailure {
    /// 无Link
    NoLink,
    /// Link验证失败
    LinkVerificationFailed(Vec<ReconciliationError>),
    /// 证据缺失
    EvidenceMissing,
    /// 执行失败
    ExecutionFailed(String),
    /// 超时
    Timeout,
    /// 其他原因
    Other(String),
}

/// 对账错误码
///
/// 根据文档第10篇：稳定排序的错误码
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum ReconcileErrorCode {
    // 1xxx: 输入错误
    InvalidInput = 1001,
    MissingEpochRoot = 1002,
    MissingReceiptDigest = 1003,
    InvalidPolicyVersion = 1004,

    // 2xxx: 执行错误
    ExecutionNotStarted = 2001,
    ExecutionInProgress = 2002,
    ExecutionFailed = 2003,

    // 3xxx: Link错误
    NoLink = 3001,
    LinkNotConfirmed = 3002,
    LinkMismatch = 3003,
    LinkSuperseded = 3004,

    // 4xxx: 证据错误
    EvidencePending = 4001,
    EvidenceMissing = 4002,
    EvidenceNotA = 4003,

    // 5xxx: 对账错误
    ReconcileMismatch = 5001,
    ReconcileTimeout = 5002,

    // 9xxx: 内部错误
    InternalError = 9001,
}

impl ReconcileResult {
    /// 创建成功的对账结果
    pub fn success(
        input_id: InputId,
        link_id: LinkId,
        job_id: JobId,
        evidence_status: EvidenceStatus,
    ) -> Self {
        let now = Timestamp::now();
        let linked_refs_digest = Self::compute_linked_refs_digest(&input_id, &link_id, &job_id);
        let reconcile_id = Self::compute_reconcile_id(&input_id, &link_id, now);

        let mut result = Self {
            reconcile_id,
            input_id,
            link_id: Some(link_id),
            job_id: Some(job_id),
            status: ReconcileStatus::Success,
            evidence_status,
            execution_status: ExecutionStatus::Resolved,
            chain_anchor_status: ChainAnchorStatus::Confirmed,
            reconciled_at: now,
            failure_reason: None,
            error_codes: Vec::new(),
            reconcile_digest: [0u8; 32],
            linked_refs_digest,
        };

        result.reconcile_digest = result.compute_digest();
        result
    }

    /// 创建部分成功的对账结果
    /// 链锚定成功但证据未完成
    pub fn partial_success(
        input_id: InputId,
        link_id: LinkId,
        job_id: JobId,
        evidence_status: EvidenceStatus,
    ) -> Self {
        let now = Timestamp::now();
        let linked_refs_digest = Self::compute_linked_refs_digest(&input_id, &link_id, &job_id);
        let reconcile_id = Self::compute_reconcile_id(&input_id, &link_id, now);

        let mut error_codes = Vec::new();
        if !evidence_status.is_complete() {
            error_codes.push(ReconcileErrorCode::EvidenceNotA);
        }

        let mut result = Self {
            reconcile_id,
            input_id,
            link_id: Some(link_id),
            job_id: Some(job_id),
            status: ReconcileStatus::PartialSuccess,
            evidence_status,
            execution_status: ExecutionStatus::Resolved,
            chain_anchor_status: ChainAnchorStatus::Confirmed,
            reconciled_at: now,
            failure_reason: None,
            error_codes,
            reconcile_digest: [0u8; 32],
            linked_refs_digest,
        };

        result.reconcile_digest = result.compute_digest();
        result
    }

    /// 创建失败的对账结果
    pub fn failure(
        input_id: InputId,
        job_id: Option<JobId>,
        failure_reason: ReconcileFailure,
        evidence_status: EvidenceStatus,
        execution_status: ExecutionStatus,
        chain_anchor_status: ChainAnchorStatus,
    ) -> Self {
        let now = Timestamp::now();
        let linked_refs_digest = Self::compute_linked_refs_digest_without_link(&input_id, &job_id);
        let reconcile_id = Self::compute_reconcile_id_without_link(&input_id, now);

        let error_codes = Self::derive_error_codes(
            &failure_reason,
            &evidence_status,
            &execution_status,
            &chain_anchor_status,
        );

        let mut result = Self {
            reconcile_id,
            input_id,
            link_id: None,
            job_id,
            status: ReconcileStatus::Failed,
            evidence_status,
            execution_status,
            chain_anchor_status,
            reconciled_at: now,
            failure_reason: Some(failure_reason),
            error_codes,
            reconcile_digest: [0u8; 32],
            linked_refs_digest,
        };

        result.reconcile_digest = result.compute_digest();
        result
    }

    /// 创建待处理的对账结果
    pub fn pending(input_id: InputId) -> Self {
        let now = Timestamp::now();
        let linked_refs_digest = Self::compute_linked_refs_digest_without_link(&input_id, &None);
        let reconcile_id = Self::compute_reconcile_id_without_link(&input_id, now);

        let mut result = Self {
            reconcile_id,
            input_id,
            link_id: None,
            job_id: None,
            status: ReconcileStatus::Pending,
            evidence_status: EvidenceStatus::PendingEvidence,
            execution_status: ExecutionStatus::NotStarted,
            chain_anchor_status: ChainAnchorStatus::None,
            reconciled_at: now,
            failure_reason: None,
            error_codes: Vec::new(),
            reconcile_digest: [0u8; 32],
            linked_refs_digest,
        };

        result.reconcile_digest = result.compute_digest();
        result
    }

    /// 计算对账ID
    fn compute_reconcile_id(
        input_id: &InputId,
        link_id: &LinkId,
        reconciled_at: Timestamp,
    ) -> ReconcileId {
        let mut hasher = Sha256::new();
        hasher.update(input_id);
        hasher.update(link_id);
        hasher.update(reconciled_at.as_millis().to_be_bytes());
        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        id
    }

    /// 计算对账ID（无Link）
    fn compute_reconcile_id_without_link(
        input_id: &InputId,
        reconciled_at: Timestamp,
    ) -> ReconcileId {
        let mut hasher = Sha256::new();
        hasher.update(input_id);
        hasher.update(reconciled_at.as_millis().to_be_bytes());
        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        id
    }

    /// 计算关联引用摘要
    fn compute_linked_refs_digest(
        input_id: &InputId,
        link_id: &LinkId,
        job_id: &JobId,
    ) -> Digest32 {
        let mut hasher = Sha256::new();
        hasher.update(input_id);
        hasher.update(link_id);
        hasher.update(job_id);
        let result = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&result);
        digest
    }

    /// 计算关联引用摘要（无Link）
    fn compute_linked_refs_digest_without_link(
        input_id: &InputId,
        job_id: &Option<JobId>,
    ) -> Digest32 {
        let mut hasher = Sha256::new();
        hasher.update(input_id);
        if let Some(job_id) = job_id {
            hasher.update(job_id);
        }
        let result = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&result);
        digest
    }

    /// 从失败原因派生错误码
    fn derive_error_codes(
        failure_reason: &ReconcileFailure,
        evidence_status: &EvidenceStatus,
        execution_status: &ExecutionStatus,
        chain_anchor_status: &ChainAnchorStatus,
    ) -> Vec<ReconcileErrorCode> {
        let mut codes = Vec::new();

        // 根据失败原因添加错误码
        match failure_reason {
            ReconcileFailure::NoLink => {
                codes.push(ReconcileErrorCode::NoLink);
            }
            ReconcileFailure::LinkVerificationFailed(_) => {
                codes.push(ReconcileErrorCode::LinkMismatch);
            }
            ReconcileFailure::EvidenceMissing => {
                codes.push(ReconcileErrorCode::EvidenceMissing);
            }
            ReconcileFailure::ExecutionFailed(_) => {
                codes.push(ReconcileErrorCode::ExecutionFailed);
            }
            ReconcileFailure::Timeout => {
                codes.push(ReconcileErrorCode::ReconcileTimeout);
            }
            ReconcileFailure::Other(_) => {
                codes.push(ReconcileErrorCode::InternalError);
            }
        }

        // 根据三状态添加额外错误码
        if !evidence_status.is_complete() {
            codes.push(ReconcileErrorCode::EvidenceNotA);
        }

        if !execution_status.is_resolved() {
            match execution_status {
                ExecutionStatus::NotStarted => codes.push(ReconcileErrorCode::ExecutionNotStarted),
                ExecutionStatus::InProgress => codes.push(ReconcileErrorCode::ExecutionInProgress),
                ExecutionStatus::Failed => codes.push(ReconcileErrorCode::ExecutionFailed),
                _ => {}
            }
        }

        if !chain_anchor_status.is_confirmed() {
            codes.push(ReconcileErrorCode::LinkNotConfirmed);
        }

        // 排序保证稳定性
        codes.sort_by_key(|c| *c as u32);
        codes.dedup();
        codes
    }

    /// 计算对账结果摘要
    fn compute_digest(&self) -> Digest32 {
        let mut hasher = Sha256::new();
        hasher.update(self.reconcile_id);
        hasher.update(self.input_id);
        if let Some(ref link_id) = self.link_id {
            hasher.update(link_id);
        }
        hasher.update([self.status as u8]);
        hasher.update([self.evidence_status as u8]);
        hasher.update([self.execution_status as u8]);
        hasher.update([self.chain_anchor_status as u8]);
        hasher.update(self.reconciled_at.as_millis().to_be_bytes());
        let result = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&result);
        digest
    }

    /// 验证三状态一致性
    ///
    /// 文档要求：任何"强结算/强清算已完成"叙事必须同时满足：
    /// 证据门槛+执行证明+链锚状态
    pub fn validate_three_state_consistency(&self) -> ThreeStateValidation {
        let mut issues = Vec::new();

        // 检查 confirmed ≠ A 的混淆
        if self.chain_anchor_status == ChainAnchorStatus::Confirmed
            && self.evidence_status != EvidenceStatus::A
        {
            // 这是合法的，但需要记录
            issues.push(ThreeStateIssue::ConfirmedButNotA);
        }

        // 检查 executed ≠ resolved 的混淆
        if self.execution_status == ExecutionStatus::Executed
            && self.chain_anchor_status != ChainAnchorStatus::Confirmed
        {
            issues.push(ThreeStateIssue::ExecutedButNotResolved);
        }

        // 检查是否可以宣称"强后果完成"
        let can_claim_strong_consequence = self.evidence_status == EvidenceStatus::A
            && self.execution_status == ExecutionStatus::Resolved
            && self.chain_anchor_status == ChainAnchorStatus::Confirmed;

        ThreeStateValidation {
            is_consistent: issues.is_empty(),
            can_claim_strong_consequence,
            issues,
        }
    }

    /// 是否成功
    pub fn is_success(&self) -> bool {
        self.status == ReconcileStatus::Success
    }

    /// 是否可以宣称完成
    ///
    /// 文档要求：无Link不得宣称完成
    pub fn can_claim_completion(&self) -> bool {
        self.link_id.is_some() && self.chain_anchor_status == ChainAnchorStatus::Confirmed
    }

    /// 是否可以宣称强后果
    ///
    /// 文档要求：必须同时满足证据门槛+执行证明+链锚状态
    pub fn can_claim_strong_consequence(&self) -> bool {
        self.evidence_status == EvidenceStatus::A
            && self.execution_status == ExecutionStatus::Resolved
            && self.chain_anchor_status == ChainAnchorStatus::Confirmed
    }
}

/// 三状态验证结果
#[derive(Debug, Clone)]
pub struct ThreeStateValidation {
    /// 是否一致
    pub is_consistent: bool,
    /// 是否可以宣称强后果
    pub can_claim_strong_consequence: bool,
    /// 问题列表
    pub issues: Vec<ThreeStateIssue>,
}

/// 三状态问题
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreeStateIssue {
    /// 链锚定已确认但证据非A级
    /// 这是合法的，但需要注意不能混淆
    ConfirmedButNotA,
    /// 已执行但未对账闭合
    ExecutedButNotResolved,
    /// 宣称强后果但条件不满足
    InvalidStrongConsequenceClaim,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_success_result() {
        let result = ReconcileResult::success(
            [0x12; 32],
            [0x34; 32],
            [0x56; 32],
            EvidenceStatus::A,
        );

        assert!(result.is_success());
        assert!(result.can_claim_completion());
        assert!(result.can_claim_strong_consequence());
        assert!(result.error_codes.is_empty());
    }

    #[test]
    fn test_partial_success_result() {
        let result = ReconcileResult::partial_success(
            [0x12; 32],
            [0x34; 32],
            [0x56; 32],
            EvidenceStatus::B, // 证据不完整
        );

        assert_eq!(result.status, ReconcileStatus::PartialSuccess);
        assert!(result.can_claim_completion()); // 链锚定完成
        assert!(!result.can_claim_strong_consequence()); // 但不能宣称强后果
        assert!(result.error_codes.contains(&ReconcileErrorCode::EvidenceNotA));
    }

    #[test]
    fn test_failure_result() {
        let result = ReconcileResult::failure(
            [0x12; 32],
            Some([0x56; 32]),
            ReconcileFailure::NoLink,
            EvidenceStatus::PendingEvidence,
            ExecutionStatus::NotStarted,
            ChainAnchorStatus::None,
        );

        assert_eq!(result.status, ReconcileStatus::Failed);
        assert!(!result.can_claim_completion());
        assert!(result.error_codes.contains(&ReconcileErrorCode::NoLink));
    }

    #[test]
    fn test_three_state_validation() {
        // 正确的三状态
        let result = ReconcileResult::success(
            [0x12; 32],
            [0x34; 32],
            [0x56; 32],
            EvidenceStatus::A,
        );

        let validation = result.validate_three_state_consistency();
        assert!(validation.is_consistent);
        assert!(validation.can_claim_strong_consequence);

        // 链锚定确认但证据非A（合法但需注意）
        let result2 = ReconcileResult::partial_success(
            [0x12; 32],
            [0x34; 32],
            [0x56; 32],
            EvidenceStatus::B,
        );

        let validation2 = result2.validate_three_state_consistency();
        assert!(!validation2.can_claim_strong_consequence);
        assert!(validation2.issues.contains(&ThreeStateIssue::ConfirmedButNotA));
    }

    #[test]
    fn test_confirmed_not_equal_a() {
        // 核心测试：confirmed ≠ A
        let result = ReconcileResult::partial_success(
            [0x12; 32],
            [0x34; 32],
            [0x56; 32],
            EvidenceStatus::B,
        );

        // 链锚定已确认
        assert_eq!(result.chain_anchor_status, ChainAnchorStatus::Confirmed);
        // 但证据不是A
        assert_eq!(result.evidence_status, EvidenceStatus::B);
        // 不能宣称强后果
        assert!(!result.can_claim_strong_consequence());
    }

    #[test]
    fn test_error_codes_sorted() {
        let result = ReconcileResult::failure(
            [0x12; 32],
            None,
            ReconcileFailure::NoLink,
            EvidenceStatus::Missing,
            ExecutionStatus::NotStarted,
            ChainAnchorStatus::None,
        );

        // 错误码应该是排序的
        let codes = &result.error_codes;
        for i in 1..codes.len() {
            assert!(codes[i - 1] as u32 <= codes[i] as u32);
        }
    }
}
