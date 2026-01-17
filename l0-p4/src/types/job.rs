//! ChainAnchorJob - 链锚定作业对象
//!
//! 根据文档第2篇：ChainAnchorJob 是"执行尝试"的最小审计与队列单位。
//! 成功或失败都要留痕，任意状态不得"删除作业"来洗失败。
//!
//! # 状态机
//!
//! ```text
//! queued ─────┬──→ submitted ──→ confirmed ──→ finalized
//!             │         │            │
//!             │         └────────────┴──→ failed ──→ retry_scheduled
//!             │                                           │
//!             └──→ cap_blocked ←──────────────────────────┘
//! ```
//!
//! # AttemptChain
//!
//! 所有尝试都记录在 AttemptChain 中，失败不得静默，重试必须归并。

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

use super::common::*;

/// 链锚定作业 - 代表一次锚定执行尝试
///
/// # 字段类别白名单（根据文档第2篇）
///
/// - `job_id`: 幂等主键
/// - `anchor_input_ref`: 必须引用Input
/// - `priority_class`: must/should/may
/// - `status`: 状态机状态
/// - `retry_count` / `next_retry_at`: 重试信息
/// - `cap_blocked_reason`: 预算/队列阻塞原因
/// - `failure_reason_digest`: 失败对象化（必备）
/// - `budget_spend_ref`: 公共预算支付时必备
/// - `proposed_tx_template_digest`: 交易模板摘要
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainAnchorJob {
    /// 作业唯一标识
    pub job_id: JobId,

    /// 关联的输入ID
    pub input_id: InputId,

    /// 幂等键（防止重复提交）
    pub idempotency_key: IdempotencyKey,

    /// 目标链类型
    pub chain_type: ChainType,

    /// 优先级（继承自 Input）
    pub priority: AnchorPriority,

    /// 作业状态
    pub status: JobStatus,

    /// 尝试链（所有尝试记录）
    pub attempt_chain: AttemptChain,

    /// 预估费用（satoshis）
    pub estimated_fee: u64,

    /// 实际费用（satoshis，提交后填充）
    pub actual_fee: Option<u64>,

    /// 创建时间
    pub created_at: Timestamp,

    /// 最后更新时间
    pub updated_at: Timestamp,

    /// 交易ID（提交后填充）
    pub txid: Option<String>,

    /// 确认数（确认后填充）
    pub confirmations: u32,

    /// 重试次数
    pub retry_count: u32,

    /// 下次重试时间
    pub next_retry_at: Option<Timestamp>,

    /// Cap 阻塞原因（预算/队列阻塞原因）
    pub cap_blocked_reason: Option<CapBlockedReason>,

    /// 失败原因摘要（失败对象化，必备）
    pub failure_reason_digest: Option<Digest32>,

    /// 预算支出引用（公共预算支付时必备）
    pub budget_spend_ref: Option<Digest32>,

    /// 交易模板摘要（可选：不含明文，仅摘要）
    pub proposed_tx_template_digest: Option<Digest32>,
}

/// 作业状态机
///
/// 根据文档第2篇：
/// - queued → submitted → confirmed → finalized
/// - queued → cap_blocked（cap不足，只能排队）
/// - submitted/confirmed → failed（失败不得静默）
/// - failed → retry_scheduled（幂等重试，必须归并）
/// - 任意状态不得"删除作业"来洗失败
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum JobStatus {
    /// 已排队（等待执行）
    #[default]
    Queued,

    /// 已提交（交易已广播）
    Submitted,

    /// 已确认（达到所需确认数）
    Confirmed,

    /// 已最终化（完全完成）
    Finalized,

    /// 已失败（本次尝试失败）
    Failed,

    /// 已调度重试
    RetryScheduled,

    /// Cap受阻（预算不足）
    CapBlocked,
}


impl JobStatus {
    /// 是否是终态
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Finalized | Self::Failed)
    }

    /// 是否可以转换到目标状态
    pub fn can_transition_to(&self, target: JobStatus) -> bool {
        match (self, target) {
            // 从 Queued 可以转换
            (Self::Queued, Self::Submitted) => true,
            (Self::Queued, Self::CapBlocked) => true,
            (Self::Queued, Self::Failed) => true,

            // 从 Submitted 可以转换
            (Self::Submitted, Self::Confirmed) => true,
            (Self::Submitted, Self::Failed) => true,

            // 从 Confirmed 可以转换
            (Self::Confirmed, Self::Finalized) => true,
            (Self::Confirmed, Self::Failed) => true,

            // 从 Failed 可以转换（重试）
            (Self::Failed, Self::RetryScheduled) => true,

            // 从 RetryScheduled 可以转换
            (Self::RetryScheduled, Self::Queued) => true,
            (Self::RetryScheduled, Self::Failed) => true,

            // 从 CapBlocked 可以转换
            (Self::CapBlocked, Self::Queued) => true,
            (Self::CapBlocked, Self::Failed) => true,

            // 其他转换不允许
            _ => false,
        }
    }
}

/// Cap 阻塞原因
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapBlockedReason {
    /// 预算不足
    InsufficientBudget {
        required: u64,
        available: u64,
    },
    /// 队列已满
    QueueFull {
        queue_size: usize,
        max_size: usize,
    },
    /// 费率过高
    FeeRateTooHigh {
        current_rate: u64,
        max_rate: u64,
    },
    /// 其他原因
    Other(String),
}

/// 尝试链 - 记录所有尝试
///
/// 根据文档要求：重试必须归并（attempt链占位），防审计噪声化
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttemptChain {
    pub attempts: Vec<AttemptRecord>,
}

impl AttemptChain {
    /// 创建新的尝试链
    pub fn new() -> Self {
        Self {
            attempts: Vec::new(),
        }
    }

    /// 添加尝试记录
    pub fn add_attempt(&mut self, record: AttemptRecord) {
        self.attempts.push(record);
    }

    /// 获取尝试次数
    pub fn attempt_count(&self) -> u32 {
        self.attempts.len() as u32
    }

    /// 获取最后一次尝试
    pub fn last_attempt(&self) -> Option<&AttemptRecord> {
        self.attempts.last()
    }

    /// 获取所有成功的尝试
    pub fn successful_attempts(&self) -> Vec<&AttemptRecord> {
        self.attempts
            .iter()
            .filter(|a| a.result == AttemptResult::Success)
            .collect()
    }

    /// 获取所有失败的尝试
    pub fn failed_attempts(&self) -> Vec<&AttemptRecord> {
        self.attempts
            .iter()
            .filter(|a| a.result == AttemptResult::Failed)
            .collect()
    }

    /// 计算尝试链摘要
    pub fn compute_digest(&self) -> Digest32 {
        let mut hasher = Sha256::new();
        for attempt in &self.attempts {
            hasher.update(attempt.attempt_number.to_be_bytes());
            hasher.update(attempt.attempted_at.as_millis().to_be_bytes());
            hasher.update([attempt.result as u8]);
            if let Some(ref txid) = attempt.txid {
                hasher.update(txid.as_bytes());
            }
        }
        let result = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&result);
        digest
    }
}

/// 单次尝试记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttemptRecord {
    /// 尝试序号
    pub attempt_number: u32,

    /// 尝试时间
    pub attempted_at: Timestamp,

    /// 尝试结果
    pub result: AttemptResult,

    /// 错误信息（如有）
    pub error: Option<AnchorError>,

    /// 交易ID（如有）
    pub txid: Option<String>,

    /// 费用（如有）
    pub fee: Option<u64>,

    /// 确认数（如有）
    pub confirmations: Option<u32>,
}

impl AttemptRecord {
    /// 创建成功的尝试记录
    pub fn success(attempt_number: u32, txid: String, fee: u64) -> Self {
        Self {
            attempt_number,
            attempted_at: Timestamp::now(),
            result: AttemptResult::Success,
            error: None,
            txid: Some(txid),
            fee: Some(fee),
            confirmations: None,
        }
    }

    /// 创建失败的尝试记录
    pub fn failure(attempt_number: u32, error: AnchorError) -> Self {
        Self {
            attempt_number,
            attempted_at: Timestamp::now(),
            result: AttemptResult::Failed,
            error: Some(error),
            txid: None,
            fee: None,
            confirmations: None,
        }
    }

    /// 创建超时的尝试记录
    pub fn timeout(attempt_number: u32) -> Self {
        Self {
            attempt_number,
            attempted_at: Timestamp::now(),
            result: AttemptResult::Timeout,
            error: Some(AnchorError::Timeout),
            txid: None,
            fee: None,
            confirmations: None,
        }
    }

    /// 创建 Cap 阻塞的尝试记录
    pub fn cap_blocked(attempt_number: u32, reason: CapBlockedReason) -> Self {
        Self {
            attempt_number,
            attempted_at: Timestamp::now(),
            result: AttemptResult::CapBlocked,
            error: Some(AnchorError::CapBlocked(reason)),
            txid: None,
            fee: None,
            confirmations: None,
        }
    }
}

/// 尝试结果
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptResult {
    /// 成功
    Success = 0,
    /// 失败
    Failed = 1,
    /// 超时
    Timeout = 2,
    /// Cap 阻塞
    CapBlocked = 3,
}

/// 锚定错误
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorError {
    /// 超时
    Timeout,
    /// Cap 阻塞
    CapBlocked(CapBlockedReason),
    /// 交易被拒绝
    TransactionRejected(String),
    /// RPC 错误
    RpcError(String),
    /// 签名错误
    SigningError(String),
    /// 费用不足
    InsufficientFee,
    /// 网络错误
    NetworkError(String),
    /// 其他错误
    Other(String),
}

impl AnchorError {
    /// 计算错误摘要
    pub fn compute_digest(&self) -> Digest32 {
        let mut hasher = Sha256::new();
        let error_str = format!("{:?}", self);
        hasher.update(error_str.as_bytes());
        let result = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&result);
        digest
    }
}

impl ChainAnchorJob {
    /// 创建新的锚定作业
    pub fn new(
        input_id: InputId,
        idempotency_key: IdempotencyKey,
        chain_type: ChainType,
        priority: AnchorPriority,
        estimated_fee: u64,
    ) -> Self {
        let now = Timestamp::now();
        let job_id = Self::compute_job_id(&input_id, &idempotency_key, now);

        Self {
            job_id,
            input_id,
            idempotency_key,
            chain_type,
            priority,
            status: JobStatus::Queued,
            attempt_chain: AttemptChain::new(),
            estimated_fee,
            actual_fee: None,
            created_at: now,
            updated_at: now,
            txid: None,
            confirmations: 0,
            retry_count: 0,
            next_retry_at: None,
            cap_blocked_reason: None,
            failure_reason_digest: None,
            budget_spend_ref: None,
            proposed_tx_template_digest: None,
        }
    }

    /// 计算作业ID
    fn compute_job_id(
        input_id: &InputId,
        idempotency_key: &IdempotencyKey,
        created_at: Timestamp,
    ) -> JobId {
        let mut hasher = Sha256::new();
        hasher.update(input_id);
        hasher.update(idempotency_key);
        hasher.update(created_at.as_millis().to_be_bytes());
        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        id
    }

    /// 转换状态
    pub fn transition_to(&mut self, new_status: JobStatus) -> Result<(), JobTransitionError> {
        if !self.status.can_transition_to(new_status) {
            return Err(JobTransitionError::InvalidTransition {
                from: self.status,
                to: new_status,
            });
        }

        self.status = new_status;
        self.updated_at = Timestamp::now();
        Ok(())
    }

    /// 标记为已提交
    pub fn mark_submitted(&mut self, txid: String, actual_fee: u64) -> Result<(), JobTransitionError> {
        self.transition_to(JobStatus::Submitted)?;
        self.txid = Some(txid.clone());
        self.actual_fee = Some(actual_fee);

        // 添加尝试记录
        self.attempt_chain.add_attempt(AttemptRecord::success(
            self.attempt_chain.attempt_count() + 1,
            txid,
            actual_fee,
        ));

        Ok(())
    }

    /// 标记为已确认
    pub fn mark_confirmed(&mut self, confirmations: u32) -> Result<(), JobTransitionError> {
        self.transition_to(JobStatus::Confirmed)?;
        self.confirmations = confirmations;
        Ok(())
    }

    /// 标记为已最终化
    pub fn mark_finalized(&mut self) -> Result<(), JobTransitionError> {
        self.transition_to(JobStatus::Finalized)
    }

    /// 标记为失败
    pub fn mark_failed(&mut self, error: AnchorError) -> Result<(), JobTransitionError> {
        self.transition_to(JobStatus::Failed)?;
        self.failure_reason_digest = Some(error.compute_digest());

        // 添加尝试记录
        self.attempt_chain.add_attempt(AttemptRecord::failure(
            self.attempt_chain.attempt_count() + 1,
            error,
        ));

        Ok(())
    }

    /// 标记为 Cap 阻塞
    pub fn mark_cap_blocked(&mut self, reason: CapBlockedReason) -> Result<(), JobTransitionError> {
        self.transition_to(JobStatus::CapBlocked)?;
        self.cap_blocked_reason = Some(reason.clone());

        // 添加尝试记录
        self.attempt_chain.add_attempt(AttemptRecord::cap_blocked(
            self.attempt_chain.attempt_count() + 1,
            reason,
        ));

        Ok(())
    }

    /// 调度重试
    pub fn schedule_retry(&mut self, retry_at: Timestamp) -> Result<(), JobTransitionError> {
        self.transition_to(JobStatus::RetryScheduled)?;
        self.retry_count += 1;
        self.next_retry_at = Some(retry_at);
        Ok(())
    }

    /// 重新入队（从重试或 Cap 阻塞恢复）
    pub fn requeue(&mut self) -> Result<(), JobTransitionError> {
        self.transition_to(JobStatus::Queued)?;
        self.cap_blocked_reason = None;
        self.next_retry_at = None;
        Ok(())
    }

    /// 设置预算支出引用
    pub fn set_budget_spend_ref(&mut self, spend_ref: Digest32) {
        self.budget_spend_ref = Some(spend_ref);
    }

    /// 设置交易模板摘要
    pub fn set_tx_template_digest(&mut self, digest: Digest32) {
        self.proposed_tx_template_digest = Some(digest);
    }

    /// 是否是 MUST 级别
    pub fn is_must(&self) -> bool {
        self.priority == AnchorPriority::Must
    }

    /// 是否已完成
    pub fn is_completed(&self) -> bool {
        self.status == JobStatus::Finalized
    }

    /// 是否可重试
    pub fn can_retry(&self, max_retries: u32) -> bool {
        self.retry_count < max_retries && !self.status.is_terminal()
    }

    /// 获取尝试次数
    pub fn attempt_count(&self) -> u32 {
        self.attempt_chain.attempt_count()
    }
}

/// 作业状态转换错误
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobTransitionError {
    /// 无效的状态转换
    InvalidTransition { from: JobStatus, to: JobStatus },
}

impl std::fmt::Display for JobTransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTransition { from, to } => {
                write!(f, "Invalid job transition from {:?} to {:?}", from, to)
            }
        }
    }
}

impl std::error::Error for JobTransitionError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_job() -> ChainAnchorJob {
        ChainAnchorJob::new(
            [0x12; 32],
            [0x34; 32],
            ChainType::Bitcoin,
            AnchorPriority::Must,
            10000,
        )
    }

    #[test]
    fn test_create_job() {
        let job = create_test_job();
        assert_eq!(job.status, JobStatus::Queued);
        assert_eq!(job.retry_count, 0);
        assert!(job.txid.is_none());
    }

    #[test]
    fn test_job_state_transitions() {
        let mut job = create_test_job();

        // Queued -> Submitted
        assert!(job.mark_submitted("txid123".to_string(), 9500).is_ok());
        assert_eq!(job.status, JobStatus::Submitted);
        assert_eq!(job.txid, Some("txid123".to_string()));

        // Submitted -> Confirmed
        assert!(job.mark_confirmed(6).is_ok());
        assert_eq!(job.status, JobStatus::Confirmed);
        assert_eq!(job.confirmations, 6);

        // Confirmed -> Finalized
        assert!(job.mark_finalized().is_ok());
        assert_eq!(job.status, JobStatus::Finalized);
    }

    #[test]
    fn test_invalid_transition() {
        let mut job = create_test_job();

        // 不能直接从 Queued 转换到 Finalized
        let result = job.transition_to(JobStatus::Finalized);
        assert!(result.is_err());
    }

    #[test]
    fn test_cap_blocked() {
        let mut job = create_test_job();

        let reason = CapBlockedReason::InsufficientBudget {
            required: 10000,
            available: 5000,
        };

        assert!(job.mark_cap_blocked(reason.clone()).is_ok());
        assert_eq!(job.status, JobStatus::CapBlocked);
        assert_eq!(job.cap_blocked_reason, Some(reason));

        // 可以从 CapBlocked 重新入队
        assert!(job.requeue().is_ok());
        assert_eq!(job.status, JobStatus::Queued);
        assert!(job.cap_blocked_reason.is_none());
    }

    #[test]
    fn test_retry_scheduling() {
        let mut job = create_test_job();

        // 先失败
        assert!(job.mark_failed(AnchorError::Timeout).is_ok());
        assert_eq!(job.status, JobStatus::Failed);

        // 调度重试
        let retry_at = Timestamp::from_millis(Timestamp::now().as_millis() + 60000);
        assert!(job.schedule_retry(retry_at).is_ok());
        assert_eq!(job.status, JobStatus::RetryScheduled);
        assert_eq!(job.retry_count, 1);

        // 重新入队
        assert!(job.requeue().is_ok());
        assert_eq!(job.status, JobStatus::Queued);
    }

    #[test]
    fn test_attempt_chain() {
        let mut job = create_test_job();

        // 第一次尝试失败
        job.attempt_chain
            .add_attempt(AttemptRecord::failure(1, AnchorError::NetworkError("test".to_string())));

        // 第二次尝试成功
        job.attempt_chain
            .add_attempt(AttemptRecord::success(2, "txid123".to_string(), 9500));

        assert_eq!(job.attempt_chain.attempt_count(), 2);
        assert_eq!(job.attempt_chain.failed_attempts().len(), 1);
        assert_eq!(job.attempt_chain.successful_attempts().len(), 1);
    }

    #[test]
    fn test_attempt_chain_digest() {
        let mut chain1 = AttemptChain::new();
        chain1.add_attempt(AttemptRecord::success(1, "txid1".to_string(), 1000));

        let mut chain2 = AttemptChain::new();
        chain2.add_attempt(AttemptRecord::success(1, "txid1".to_string(), 1000));

        // 相同的尝试链应该产生相同的摘要（忽略时间戳差异）
        // 注意：由于时间戳，实际上会不同，这里只是测试摘要计算功能
        let digest1 = chain1.compute_digest();
        assert_ne!(digest1, [0u8; 32]);
    }
}
