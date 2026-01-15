//! Submit 阶段 - 交易提交
//!
//! 构建并广播锚定交易到比特币网络。

use serde::{Deserialize, Serialize};

use crate::error::{P4Error, P4Result};
use crate::storage::AnchorStorage;
use crate::types::{
    AnchorError, AttemptRecord, ChainAnchorInput, ChainAnchorJob, JobStatus, Timestamp,
};

use super::AnchorOps;

/// Submit 结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitResult {
    /// 交易ID
    pub txid: String,
    /// 实际费用（satoshis）
    pub actual_fee: u64,
    /// 交易大小（vBytes）
    pub tx_size: u64,
    /// 提交时间
    pub submitted_at: Timestamp,
    /// 交易原始数据（hex）
    pub tx_hex: String,
}

/// Submit 错误
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SubmitError {
    /// 交易构建失败
    BuildFailed(String),
    /// 广播失败
    BroadcastFailed(String),
    /// UTXO 不足
    InsufficientUtxos,
    /// 费用不足
    InsufficientFee { required: u64, available: u64 },
    /// 交易被拒绝
    TransactionRejected(String),
    /// 网络错误
    NetworkError(String),
}

impl std::fmt::Display for SubmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubmitError::BuildFailed(msg) => {
                write!(f, "Transaction build failed: {}", msg)
            }
            SubmitError::BroadcastFailed(msg) => {
                write!(f, "Broadcast failed: {}", msg)
            }
            SubmitError::InsufficientUtxos => {
                write!(f, "Insufficient UTXOs for transaction")
            }
            SubmitError::InsufficientFee { required, available } => {
                write!(
                    f,
                    "Insufficient fee: required {} satoshis, available {}",
                    required, available
                )
            }
            SubmitError::TransactionRejected(msg) => {
                write!(f, "Transaction rejected: {}", msg)
            }
            SubmitError::NetworkError(msg) => {
                write!(f, "Network error: {}", msg)
            }
        }
    }
}

impl std::error::Error for SubmitError {}

/// 执行 Submit 阶段
pub async fn execute<S: AnchorStorage + 'static>(
    ops: &AnchorOps<S>,
    job: &mut ChainAnchorJob,
    input: &ChainAnchorInput,
) -> P4Result<SubmitResult> {
    let tx_builder = ops.tx_builder();
    let config = ops.config();

    // 记录尝试开始
    let attempt_number = job.attempt_chain.attempt_count() + 1;

    tracing::info!(
        "Submit attempt {} for job {:?}",
        attempt_number,
        hex::encode(&job.job_id[..8])
    );

    // 构建并广播交易 - 使用 input 中的 epoch_sequence 和 epoch_root
    let result = tx_builder
        .anchor_epoch(input.epoch_sequence, &input.epoch_root, None)
        .await;

    match result {
        Ok(txid) => {
            // 成功 - 获取交易详情
            let tx_info = ops
                .bitcoin_rpc()
                .get_transaction_info(&txid)
                .await
                .ok();

            // TransactionInfo 没有 fee/size 字段，使用估算值
            let actual_fee = job.estimated_fee;
            let tx_hex = tx_info.as_ref().map(|i| i.hex.clone()).unwrap_or_default();

            // 使用 Job 的方法标记为已提交
            if let Err(e) = job.mark_submitted(txid.clone(), actual_fee) {
                tracing::warn!("Failed to mark job as submitted: {}", e);
                // 即使状态转换失败，也继续返回成功结果
                job.txid = Some(txid.clone());
                job.actual_fee = Some(actual_fee);
                job.status = JobStatus::Submitted;
                job.updated_at = Timestamp::now();
            }

            let submit_result = SubmitResult {
                txid,
                actual_fee,
                tx_size: 0, // TransactionInfo 没有 size 字段
                submitted_at: Timestamp::now(),
                tx_hex,
            };

            tracing::info!(
                "Submit successful for job {:?}: txid={}",
                hex::encode(&job.job_id[..8]),
                submit_result.txid
            );

            Ok(submit_result)
        }
        Err(e) => {
            // 失败 - 记录失败尝试
            let anchor_error = map_error_to_anchor_error(&e);

            // 使用 Job 的方法标记为失败
            if let Err(transition_err) = job.mark_failed(anchor_error.clone()) {
                tracing::warn!("Failed to mark job as failed: {}", transition_err);
                // 手动设置状态
                job.status = JobStatus::Failed;
                job.updated_at = Timestamp::now();
                // 手动添加尝试记录
                job.attempt_chain.add_attempt(AttemptRecord::failure(
                    attempt_number,
                    anchor_error.clone(),
                ));
            }

            // 检查是否可以重试
            let max_retries = config.max_retries;
            if is_retriable_error(&e) && job.can_retry(max_retries) {
                let retry_at = calculate_next_retry_time(attempt_number);
                if let Err(e) = job.schedule_retry(retry_at) {
                    tracing::warn!("Failed to schedule retry: {}", e);
                }
            }

            tracing::error!(
                "Submit failed for job {:?}: {}",
                hex::encode(&job.job_id[..8]),
                e
            );

            Err(e)
        }
    }
}

/// 将 P4Error 映射为 AnchorError
fn map_error_to_anchor_error(error: &P4Error) -> AnchorError {
    match error {
        P4Error::RpcConnection(msg) => AnchorError::RpcError(msg.clone()),
        P4Error::Network(msg) => AnchorError::NetworkError(msg.clone()),
        P4Error::TransactionBroadcast(msg) => AnchorError::TransactionRejected(msg.clone()),
        P4Error::InsufficientFunds { .. } => AnchorError::InsufficientFee,
        P4Error::ConfirmationTimeout { .. } => AnchorError::Timeout,
        _ => AnchorError::Other(error.to_string()),
    }
}

/// 判断错误是否可重试
fn is_retriable_error(error: &P4Error) -> bool {
    match error {
        P4Error::RpcConnection(_) => true,
        P4Error::Network(_) => true,
        P4Error::TransactionBroadcast(msg) => {
            // 某些广播错误可以重试
            !msg.contains("already in block chain")
                && !msg.contains("transaction already in block chain")
                && !msg.contains("bad-txns-inputs-spent")
        }
        P4Error::InsufficientFunds { .. } => false,
        _ => false,
    }
}

/// 计算下次重试时间
fn calculate_next_retry_time(attempt_number: u32) -> Timestamp {
    // 指数退避: 30s, 60s, 120s, 240s, ...
    let base_delay_ms = 30_000u64;
    let delay_ms = base_delay_ms * (1 << attempt_number.min(5));
    let max_delay_ms = 10 * 60 * 1000; // 最大 10 分钟

    Timestamp::from_millis(Timestamp::now().as_millis() + delay_ms.min(max_delay_ms))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_submit_error_display() {
        let err = SubmitError::InsufficientFee {
            required: 1000,
            available: 500,
        };
        assert!(err.to_string().contains("1000"));
        assert!(err.to_string().contains("500"));
    }

    #[test]
    fn test_is_retriable_error() {
        assert!(is_retriable_error(&P4Error::RpcConnection("timeout".to_string())));
        assert!(is_retriable_error(&P4Error::Network("connection refused".to_string())));
        assert!(!is_retriable_error(&P4Error::InsufficientFunds {
            required: 1000,
            available: 500,
        }));
    }

    #[test]
    fn test_calculate_next_retry_time() {
        let now = Timestamp::now();
        let next = calculate_next_retry_time(1);
        assert!(next.as_millis() > now.as_millis());
        assert!(next.as_millis() - now.as_millis() >= 60_000); // 至少 60 秒
    }
}
