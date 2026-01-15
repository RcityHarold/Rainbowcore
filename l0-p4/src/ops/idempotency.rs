//! 幂等键管理
//!
//! 防止同一输入产生多个成功的链锚定。
//!
//! # 幂等键计算公式
//!
//! ```text
//! H(canonical(epoch_root + linked_receipt_ids_digest + policy_version + canon_version))
//! ```

use std::sync::Arc;

use crate::error::P4Result;
use crate::storage::AnchorStorage;
use crate::types::{ChainAnchorInput, ChainAnchorJob, IdempotencyKey, JobStatus};

/// 幂等性检查结果
#[derive(Debug, Clone)]
pub enum IdempotencyCheckResult {
    /// 不存在，允许创建
    NotExists,
    /// 已存在成功的 Job
    AlreadyExists(ChainAnchorJob),
    /// 正在进行中
    InProgress(ChainAnchorJob),
    /// 允许重试（之前失败）
    AllowRetry(ChainAnchorJob),
}

/// 幂等性检查器
pub struct IdempotencyChecker<S: AnchorStorage> {
    storage: Arc<S>,
}

impl<S: AnchorStorage> IdempotencyChecker<S> {
    /// 创建新的幂等性检查器
    pub fn new(storage: Arc<S>) -> Self {
        Self { storage }
    }

    /// 检查幂等性
    ///
    /// 根据幂等键查找已存在的 Job：
    /// - 如果已存在成功的 Job，返回 `AlreadyExists`
    /// - 如果存在进行中的 Job，返回 `InProgress`
    /// - 如果存在失败的 Job，返回 `AllowRetry`
    /// - 如果不存在，返回 `NotExists`
    pub async fn check(&self, key: &IdempotencyKey) -> P4Result<IdempotencyCheckResult> {
        if let Some(existing_job) = self.storage.get_job_by_idempotency_key(key).await? {
            match existing_job.status {
                JobStatus::Confirmed | JobStatus::Finalized => {
                    // 已成功完成
                    tracing::debug!(
                        "Idempotency check: job {:?} already confirmed",
                        hex::encode(&existing_job.job_id[..8])
                    );
                    return Ok(IdempotencyCheckResult::AlreadyExists(existing_job));
                }
                JobStatus::Queued | JobStatus::Submitted => {
                    // 正在进行中
                    tracing::debug!(
                        "Idempotency check: job {:?} in progress",
                        hex::encode(&existing_job.job_id[..8])
                    );
                    return Ok(IdempotencyCheckResult::InProgress(existing_job));
                }
                JobStatus::Failed | JobStatus::RetryScheduled => {
                    // 失败或待重试，允许新尝试
                    tracing::debug!(
                        "Idempotency check: job {:?} failed, allowing retry",
                        hex::encode(&existing_job.job_id[..8])
                    );
                    return Ok(IdempotencyCheckResult::AllowRetry(existing_job));
                }
                JobStatus::CapBlocked => {
                    // Cap 阻塞，视为进行中
                    tracing::debug!(
                        "Idempotency check: job {:?} cap blocked",
                        hex::encode(&existing_job.job_id[..8])
                    );
                    return Ok(IdempotencyCheckResult::InProgress(existing_job));
                }
            }
        }

        Ok(IdempotencyCheckResult::NotExists)
    }

    /// 检查输入是否已有成功的锚定
    pub async fn is_input_anchored(&self, input: &ChainAnchorInput) -> P4Result<bool> {
        let key = input.compute_idempotency_key();

        match self.check(&key).await? {
            IdempotencyCheckResult::AlreadyExists(_) => Ok(true),
            _ => Ok(false),
        }
    }

    /// 获取输入对应的最新 Job
    pub async fn get_latest_job(&self, input: &ChainAnchorInput) -> P4Result<Option<ChainAnchorJob>> {
        let key = input.compute_idempotency_key();
        self.storage.get_job_by_idempotency_key(&key).await
    }
}

/// 计算幂等键
///
/// 公式: H(canonical(epoch_root + linked_receipt_ids_digest + policy_version + canon_version))
///
/// 此函数已在 ChainAnchorInput 中实现，这里提供一个便捷函数。
pub fn compute_idempotency_key(input: &ChainAnchorInput) -> IdempotencyKey {
    input.compute_idempotency_key()
}

/// 验证幂等键是否匹配
pub fn verify_idempotency_key(
    input: &ChainAnchorInput,
    key: &IdempotencyKey,
) -> bool {
    let computed = input.compute_idempotency_key();
    &computed == key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;
    use crate::types::{AnchorPriority, ChainType};

    fn create_test_input() -> ChainAnchorInput {
        ChainAnchorInput::new(
            1,
            [0x12; 32],
            [0x34; 32],
            AnchorPriority::Must,
        )
    }

    fn create_test_job(input: &ChainAnchorInput, status: JobStatus) -> ChainAnchorJob {
        let idempotency_key = input.compute_idempotency_key();
        let mut job = ChainAnchorJob::new(
            input.input_id,
            idempotency_key,
            ChainType::Bitcoin,
            input.priority,
            10000,
        );
        job.status = status;
        job
    }

    #[tokio::test]
    async fn test_idempotency_check_not_exists() {
        let storage = Arc::new(MemoryStorage::new());
        let checker = IdempotencyChecker::new(storage);

        let input = create_test_input();
        let key = input.compute_idempotency_key();

        let result = checker.check(&key).await.unwrap();
        assert!(matches!(result, IdempotencyCheckResult::NotExists));
    }

    #[tokio::test]
    async fn test_idempotency_check_already_exists() {
        let storage = Arc::new(MemoryStorage::new());

        let input = create_test_input();
        let job = create_test_job(&input, JobStatus::Confirmed);

        storage.save_job(&job).await.unwrap();

        let checker = IdempotencyChecker::new(storage);
        let key = input.compute_idempotency_key();

        let result = checker.check(&key).await.unwrap();
        assert!(matches!(result, IdempotencyCheckResult::AlreadyExists(_)));
    }

    #[tokio::test]
    async fn test_idempotency_check_in_progress() {
        let storage = Arc::new(MemoryStorage::new());

        let input = create_test_input();
        let job = create_test_job(&input, JobStatus::Submitted);

        storage.save_job(&job).await.unwrap();

        let checker = IdempotencyChecker::new(storage);
        let key = input.compute_idempotency_key();

        let result = checker.check(&key).await.unwrap();
        assert!(matches!(result, IdempotencyCheckResult::InProgress(_)));
    }

    #[tokio::test]
    async fn test_idempotency_check_allow_retry() {
        let storage = Arc::new(MemoryStorage::new());

        let input = create_test_input();
        let job = create_test_job(&input, JobStatus::Failed);

        storage.save_job(&job).await.unwrap();

        let checker = IdempotencyChecker::new(storage);
        let key = input.compute_idempotency_key();

        let result = checker.check(&key).await.unwrap();
        assert!(matches!(result, IdempotencyCheckResult::AllowRetry(_)));
    }

    #[test]
    fn test_verify_idempotency_key() {
        let input = create_test_input();
        let key = input.compute_idempotency_key();

        assert!(verify_idempotency_key(&input, &key));
        assert!(!verify_idempotency_key(&input, &[0x00; 32]));
    }
}
