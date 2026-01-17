//! Confirm 阶段 - 确认等待
//!
//! 等待交易达到所需的确认数。

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::error::{P4Error, P4Result};
use crate::storage::AnchorStorage;
use crate::types::{ChainAnchorJob, JobStatus, Timestamp};

use super::AnchorOps;

/// Confirm 结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmResult {
    /// 交易ID
    pub txid: String,
    /// 确认数
    pub confirmations: u32,
    /// 区块哈希
    pub block_hash: String,
    /// 区块高度
    pub block_height: u64,
    /// 确认时间
    pub confirmed_at: Timestamp,
}

/// Confirm 错误
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConfirmError {
    /// 交易未找到
    TransactionNotFound(String),
    /// 确认超时
    ConfirmationTimeout { txid: String, confirmations: u32 },
    /// 交易被替换
    TransactionReplaced { original_txid: String, replacement_txid: String },
    /// 交易被丢弃
    TransactionDropped(String),
}

impl std::fmt::Display for ConfirmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfirmError::TransactionNotFound(txid) => {
                write!(f, "Transaction not found: {}", txid)
            }
            ConfirmError::ConfirmationTimeout { txid, confirmations } => {
                write!(
                    f,
                    "Confirmation timeout for {}: only {} confirmations",
                    txid, confirmations
                )
            }
            ConfirmError::TransactionReplaced { original_txid, replacement_txid } => {
                write!(
                    f,
                    "Transaction {} replaced by {}",
                    original_txid, replacement_txid
                )
            }
            ConfirmError::TransactionDropped(txid) => {
                write!(f, "Transaction dropped from mempool: {}", txid)
            }
        }
    }
}

impl std::error::Error for ConfirmError {}

/// 默认轮询间隔（秒）
const DEFAULT_POLL_INTERVAL_SECS: u64 = 30;

/// 默认超时时间（秒）- 2 小时
const DEFAULT_TIMEOUT_SECS: u64 = 2 * 60 * 60;

/// 执行 Confirm 阶段
pub async fn execute<S: AnchorStorage + 'static>(
    ops: &AnchorOps<S>,
    job: &mut ChainAnchorJob,
) -> P4Result<ConfirmResult> {
    let bitcoin_rpc = ops.bitcoin_rpc();
    let config = ops.config();

    // 确保有交易ID
    let txid = job.txid.as_ref().ok_or_else(|| {
        P4Error::InvalidInput("Job has no txid, cannot confirm".to_string())
    })?;

    // 获取所需确认数
    let required_confirmations = config.bitcoin.network.required_confirmations();

    // 获取超时和轮询间隔
    let poll_interval = Duration::from_secs(
        config.confirmation_interval_secs.max(DEFAULT_POLL_INTERVAL_SECS)
    );
    let timeout = Duration::from_secs(DEFAULT_TIMEOUT_SECS);

    let start_time = std::time::Instant::now();

    tracing::info!(
        "Waiting for {} confirmations for txid {}",
        required_confirmations,
        txid
    );

    loop {
        // 检查超时
        if start_time.elapsed() > timeout {
            return Err(P4Error::ConfirmationTimeout {
                attempts: (start_time.elapsed().as_secs() / poll_interval.as_secs()) as u32,
            });
        }

        // 查询确认数
        match bitcoin_rpc.get_transaction_confirmations(txid).await {
            Ok(confirmations) => {
                job.confirmations = confirmations;
                job.updated_at = Timestamp::now();

                tracing::debug!(
                    "Transaction {} has {} confirmations (need {})",
                    txid,
                    confirmations,
                    required_confirmations
                );

                if confirmations >= required_confirmations {
                    // 获取交易详细信息
                    let tx_info = bitcoin_rpc.get_transaction_info(txid).await?;

                    // 更新作业状态
                    job.status = JobStatus::Confirmed;
                    job.updated_at = Timestamp::now();

                    let result = ConfirmResult {
                        txid: txid.clone(),
                        confirmations,
                        block_hash: tx_info.blockhash.unwrap_or_default(),
                        block_height: tx_info.blockheight.unwrap_or(0),
                        confirmed_at: Timestamp::now(),
                    };

                    tracing::info!(
                        "Transaction {} confirmed with {} confirmations at block {}",
                        txid,
                        confirmations,
                        result.block_height
                    );

                    return Ok(result);
                }
            }
            Err(e) => {
                // 检查交易是否仍在内存池中
                if e.to_string().contains("not found") {
                    // 交易可能已被丢弃
                    tracing::warn!("Transaction {} not found, may have been dropped", txid);
                    // 继续等待一段时间，可能是临时问题
                }
            }
        }

        // 等待下一次轮询
        tokio::time::sleep(poll_interval).await;
    }
}

/// 检查交易是否在内存池中
pub async fn is_in_mempool<S: AnchorStorage + 'static>(
    ops: &AnchorOps<S>,
    txid: &str,
) -> P4Result<bool> {
    let bitcoin_rpc = ops.bitcoin_rpc();

    match bitcoin_rpc.get_transaction_confirmations(txid).await {
        Ok(confirmations) => Ok(confirmations == 0),
        Err(_) => Ok(false),
    }
}

/// 获取当前确认数（不等待）
pub async fn get_confirmations<S: AnchorStorage + 'static>(
    ops: &AnchorOps<S>,
    txid: &str,
) -> P4Result<u32> {
    ops.bitcoin_rpc().get_transaction_confirmations(txid).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confirm_error_display() {
        let err = ConfirmError::ConfirmationTimeout {
            txid: "abc123".to_string(),
            confirmations: 2,
        };
        assert!(err.to_string().contains("abc123"));
        assert!(err.to_string().contains("2"));
    }

    #[test]
    fn test_confirm_result() {
        let result = ConfirmResult {
            txid: "abc123".to_string(),
            confirmations: 6,
            block_hash: "block123".to_string(),
            block_height: 100000,
            confirmed_at: Timestamp::now(),
        };

        assert_eq!(result.confirmations, 6);
        assert_eq!(result.block_height, 100000);
    }
}
