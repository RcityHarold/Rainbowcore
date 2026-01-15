//! AnchorOps 执行闭环
//!
//! 实现 P4 层的五阶段执行闭环：
//! ```text
//! Input → Quote → Submit → Confirm → Link → Reconcile
//! ```
//!
//! # 设计原则
//!
//! - 每个阶段都是原子操作
//! - 失败必须记录到 AttemptChain
//! - 幂等键检查必须在 Submit 前执行
//! - MUST 级别的任务不可丢弃

pub mod quote;
pub mod submit;
pub mod confirm;
pub mod link;
pub mod reconcile;
pub mod idempotency;

use std::sync::Arc;

use crate::bitcoin::BitcoinRpcClient;
use crate::error::{P4Error, P4Result};
use crate::storage::AnchorStorage;
use crate::tx_builder::AnchorTxBuilder;
use crate::types::{
    ChainAnchorInput, ChainAnchorJob, ChainAnchorLink, ChainType,
    ReconcileResult, Timestamp,
};
use crate::P4Config;

pub use quote::{QuoteResult, QuoteError};
pub use submit::{SubmitResult, SubmitError};
pub use confirm::{ConfirmResult, ConfirmError};
pub use link::{LinkResult, LinkError};
pub use reconcile::{ReconcileError};
pub use idempotency::{IdempotencyChecker, IdempotencyCheckResult};

/// AnchorOps 执行器
///
/// 负责执行完整的锚定闭环，从报价到对账。
pub struct AnchorOps<S: AnchorStorage> {
    /// Bitcoin RPC 客户端
    bitcoin_rpc: Arc<BitcoinRpcClient>,
    /// 交易构建器
    tx_builder: Arc<AnchorTxBuilder>,
    /// 存储
    storage: Arc<S>,
    /// 配置
    config: P4Config,
    /// 幂等性检查器
    idempotency_checker: IdempotencyChecker<S>,
}

impl<S: AnchorStorage + 'static> AnchorOps<S> {
    /// 创建新的 AnchorOps 执行器
    pub fn new(
        bitcoin_rpc: Arc<BitcoinRpcClient>,
        tx_builder: Arc<AnchorTxBuilder>,
        storage: Arc<S>,
        config: P4Config,
    ) -> Self {
        let idempotency_checker = IdempotencyChecker::new(storage.clone());

        Self {
            bitcoin_rpc,
            tx_builder,
            storage,
            config,
            idempotency_checker,
        }
    }

    /// 阶段 1: Quote - 估算费用
    ///
    /// 根据当前网络状况估算锚定所需的费用。
    pub async fn quote(&self, input: &ChainAnchorInput) -> P4Result<QuoteResult> {
        quote::execute(self, input).await
    }

    /// 阶段 2: Submit - 提交交易
    ///
    /// 构建并广播锚定交易到比特币网络。
    /// 在提交前会进行幂等性检查，防止重复锚定。
    pub async fn submit(&self, job: &mut ChainAnchorJob, input: &ChainAnchorInput) -> P4Result<SubmitResult> {
        // 幂等性检查
        match self.idempotency_checker.check(&job.idempotency_key).await? {
            IdempotencyCheckResult::AlreadyExists(existing) => {
                return Err(P4Error::InvalidInput(format!(
                    "Job already exists with status {:?}",
                    existing.status
                )));
            }
            IdempotencyCheckResult::InProgress(existing) => {
                return Err(P4Error::InvalidInput(format!(
                    "Job already in progress: {:?}",
                    existing.job_id
                )));
            }
            IdempotencyCheckResult::AllowRetry(_) | IdempotencyCheckResult::NotExists => {
                // 允许继续
            }
        }

        submit::execute(self, job, input).await
    }

    /// 阶段 3: Confirm - 等待确认
    ///
    /// 等待交易达到所需的确认数。
    pub async fn confirm(&self, job: &mut ChainAnchorJob) -> P4Result<ConfirmResult> {
        confirm::execute(self, job).await
    }

    /// 阶段 4: Link - 创建链锚定结果
    ///
    /// 当交易确认后，创建 ChainAnchorLink 作为锚定凭证。
    pub async fn link(&self, job: &ChainAnchorJob, input: &ChainAnchorInput) -> P4Result<ChainAnchorLink> {
        link::execute(self, job, input).await
    }

    /// 阶段 5: Reconcile - 对账
    ///
    /// 创建最终的对账结果，验证三状态分离。
    pub async fn reconcile(
        &self,
        input: &ChainAnchorInput,
        job: Option<&ChainAnchorJob>,
        link: Option<&ChainAnchorLink>,
    ) -> P4Result<ReconcileResult> {
        reconcile::execute(self, input, job, link).await
    }

    /// 创建作业
    ///
    /// 根据输入和报价结果创建新的锚定作业。
    pub async fn create_job(
        &self,
        input: &ChainAnchorInput,
        quote: &QuoteResult,
    ) -> P4Result<ChainAnchorJob> {
        // 计算幂等键
        let idempotency_key = input.compute_idempotency_key();

        let job = ChainAnchorJob::new(
            input.input_id,
            idempotency_key,
            ChainType::Bitcoin,
            input.priority,
            quote.estimated_fee,
        );

        // 保存作业
        self.storage.save_job(&job).await?;

        Ok(job)
    }

    /// 执行完整闭环
    ///
    /// 依次执行所有阶段，返回最终对账结果。
    pub async fn execute_full_cycle(
        &self,
        mut input: ChainAnchorInput,
    ) -> P4Result<ReconcileResult> {
        // 1. Quote
        let quote = self.quote(&input).await?;

        // 2. 创建 Job
        let mut job = self.create_job(&input, &quote).await?;

        // 3. Submit - 传入 input
        let _submit_result = self.submit(&mut job, &input).await?;

        // 4. 更新 Job 状态
        self.storage.save_job(&job).await?;

        // 5. Confirm
        let _confirm_result = self.confirm(&mut job).await?;

        // 6. 更新 Job 状态
        self.storage.save_job(&job).await?;

        // 7. Link - 传入 input
        let link = self.link(&job, &input).await?;

        // 8. 保存 Link
        self.storage.save_link(&link).await?;

        // 9. Reconcile - 传入 job 和 link
        let result = self.reconcile(&input, Some(&job), Some(&link)).await?;

        // 10. 保存对账结果
        self.storage.save_reconcile(&result).await?;

        // 11. 更新输入状态
        input.status = crate::types::InputStatus::Completed;
        self.storage.save_input(&input).await?;

        Ok(result)
    }

    /// 获取 Bitcoin RPC 客户端
    pub fn bitcoin_rpc(&self) -> &Arc<BitcoinRpcClient> {
        &self.bitcoin_rpc
    }

    /// 获取交易构建器
    pub fn tx_builder(&self) -> &Arc<AnchorTxBuilder> {
        &self.tx_builder
    }

    /// 获取存储
    pub fn storage(&self) -> &Arc<S> {
        &self.storage
    }

    /// 获取配置
    pub fn config(&self) -> &P4Config {
        &self.config
    }
}

/// 执行上下文
///
/// 提供执行过程中所需的上下文信息。
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    /// 执行开始时间
    pub started_at: Timestamp,
    /// 超时时间（毫秒）
    pub timeout_ms: u64,
    /// 是否允许重试
    pub allow_retry: bool,
    /// 最大重试次数
    pub max_retries: u32,
}

impl Default for ExecutionContext {
    fn default() -> Self {
        Self {
            started_at: Timestamp::now(),
            timeout_ms: 60_000, // 1 分钟
            allow_retry: true,
            max_retries: 3,
        }
    }
}

impl ExecutionContext {
    /// 创建用于 MUST 级别的上下文
    pub fn for_must() -> Self {
        Self {
            started_at: Timestamp::now(),
            timeout_ms: 300_000, // 5 分钟
            allow_retry: true,
            max_retries: 10, // MUST 级别重试次数更多
        }
    }

    /// 创建用于 MAY 级别的上下文
    pub fn for_may() -> Self {
        Self {
            started_at: Timestamp::now(),
            timeout_ms: 30_000, // 30 秒
            allow_retry: false, // MAY 级别不重试
            max_retries: 0,
        }
    }

    /// 检查是否超时
    pub fn is_timeout(&self) -> bool {
        let elapsed = Timestamp::now().as_millis() - self.started_at.as_millis();
        elapsed > self.timeout_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_context_default() {
        let ctx = ExecutionContext::default();
        assert_eq!(ctx.timeout_ms, 60_000);
        assert!(ctx.allow_retry);
        assert_eq!(ctx.max_retries, 3);
    }

    #[test]
    fn test_execution_context_for_must() {
        let ctx = ExecutionContext::for_must();
        assert_eq!(ctx.timeout_ms, 300_000);
        assert!(ctx.allow_retry);
        assert_eq!(ctx.max_retries, 10);
    }

    #[test]
    fn test_execution_context_for_may() {
        let ctx = ExecutionContext::for_may();
        assert_eq!(ctx.timeout_ms, 30_000);
        assert!(!ctx.allow_retry);
        assert_eq!(ctx.max_retries, 0);
    }
}
