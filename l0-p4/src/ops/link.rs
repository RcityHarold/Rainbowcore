//! Link 阶段 - 链锚定结果创建
//!
//! 当交易确认后，创建 ChainAnchorLink 作为锚定凭证。

use serde::{Deserialize, Serialize};

use crate::error::{P4Error, P4Result};
use crate::storage::AnchorStorage;
use crate::tx_builder::parse_anchor_from_tx;
use crate::types::{
    AnchorDataInfo, ChainAnchorInput, ChainAnchorJob, ChainAnchorLink, JobStatus,
    LinkStatus, PolicyVersion,
};

use super::AnchorOps;

/// Link 结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkResult {
    /// 创建的 Link
    pub link: ChainAnchorLink,
    /// 是否验证通过
    pub verified: bool,
}

/// Link 错误
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LinkError {
    /// Job 状态不正确
    InvalidJobStatus(String),
    /// 交易数据获取失败
    TransactionDataFailed(String),
    /// 锚定数据验证失败
    AnchorDataMismatch {
        expected_epoch: u64,
        actual_epoch: u64,
    },
    /// 区块信息获取失败
    BlockInfoFailed(String),
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkError::InvalidJobStatus(status) => {
                write!(f, "Invalid job status for link creation: {}", status)
            }
            LinkError::TransactionDataFailed(msg) => {
                write!(f, "Failed to get transaction data: {}", msg)
            }
            LinkError::AnchorDataMismatch { expected_epoch, actual_epoch } => {
                write!(
                    f,
                    "Anchor data mismatch: expected epoch {}, got {}",
                    expected_epoch, actual_epoch
                )
            }
            LinkError::BlockInfoFailed(msg) => {
                write!(f, "Failed to get block info: {}", msg)
            }
        }
    }
}

impl std::error::Error for LinkError {}

/// 执行 Link 阶段
pub async fn execute<S: AnchorStorage + 'static>(
    ops: &AnchorOps<S>,
    job: &ChainAnchorJob,
    input: &ChainAnchorInput,
) -> P4Result<ChainAnchorLink> {
    let bitcoin_rpc = ops.bitcoin_rpc();

    // 验证作业状态
    if job.status != JobStatus::Confirmed {
        return Err(P4Error::StateTransition(format!(
            "Job must be Confirmed to create Link, current status: {:?}",
            job.status
        )));
    }

    // 获取交易ID
    let txid = job.txid.as_ref().ok_or_else(|| {
        P4Error::InvalidInput("Job has no txid".to_string())
    })?;

    // 获取交易详情
    let tx_info = bitcoin_rpc.get_transaction_info(txid).await?;

    // 验证锚定数据
    let parsed_anchor = parse_anchor_from_tx(&tx_info.hex)?
        .ok_or_else(|| P4Error::InvalidInput("No anchor data found in transaction".to_string()))?;

    // 验证 epoch_sequence 匹配（从 input 获取）
    if parsed_anchor.epoch_sequence != input.epoch_sequence {
        return Err(P4Error::InvalidInput(format!(
            "Epoch mismatch: input has {}, transaction has {}",
            input.epoch_sequence, parsed_anchor.epoch_sequence
        )));
    }

    // 验证 epoch_root 匹配（从 input 获取）
    if parsed_anchor.epoch_root != input.epoch_root {
        return Err(P4Error::InvalidInput(format!(
            "Epoch root mismatch in transaction"
        )));
    }

    // 获取区块信息
    let block_hash = tx_info.blockhash.clone();
    let block_height = tx_info.blockheight;
    let confirmations = job.confirmations;

    // 创建锚定数据信息
    let anchor_data_info = AnchorDataInfo {
        epoch_sequence: parsed_anchor.epoch_sequence,
        epoch_root: parsed_anchor.epoch_root,
        magic: crate::tx_builder::L0_ANCHOR_MAGIC,
        version: 1,
        checksum: [0u8; 4], // 从解析的数据中获取
    };

    // 创建 Link - 使用正确的参数
    let mut link = ChainAnchorLink::new(
        job.job_id,
        input.input_id,
        job.chain_type,
        txid.clone(),
        input.epoch_sequence,
        input.epoch_root,
        input.linked_receipt_ids_digest,
        PolicyVersion::default(),
    );

    // 更新 Link 状态为已确认
    if let (Some(hash), Some(height)) = (block_hash, block_height) {
        link.mark_confirmed(confirmations, hash, height);
    } else {
        link.status = LinkStatus::Confirmed;
        link.confirmations = confirmations;
    }

    link.set_tx_hex(tx_info.hex);
    link.anchor_data = Some(anchor_data_info);

    tracing::info!(
        "Created Link {:?} for job {:?}, txid={}, block={:?}",
        hex::encode(&link.link_id[..8]),
        hex::encode(&job.job_id[..8]),
        txid,
        block_height
    );

    Ok(link)
}

/// 验证 Link 的完整性
pub fn verify_link(link: &ChainAnchorLink, expected_epoch_root: &[u8; 32]) -> bool {
    // 验证 epoch_root 匹配
    if &link.epoch_root != expected_epoch_root {
        return false;
    }

    // 验证状态
    if link.status != LinkStatus::Confirmed {
        return false;
    }

    true
}

/// 从交易 hex 中提取并验证锚定数据
pub fn extract_and_verify_anchor(
    tx_hex: &str,
    expected_epoch: u64,
    expected_root: &[u8; 32],
) -> P4Result<bool> {
    let parsed = parse_anchor_from_tx(tx_hex)?;

    match parsed {
        Some(anchor) => {
            Ok(anchor.epoch_sequence == expected_epoch && &anchor.epoch_root == expected_root)
        }
        None => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ChainType, AnchorPriority};

    #[test]
    fn test_link_error_display() {
        let err = LinkError::AnchorDataMismatch {
            expected_epoch: 100,
            actual_epoch: 101,
        };
        assert!(err.to_string().contains("100"));
        assert!(err.to_string().contains("101"));
    }

    #[test]
    fn test_verify_link() {
        let epoch_root = [0x12; 32];
        let linked_receipt_digest = [0x34; 32];
        let mut link = ChainAnchorLink::new(
            [0x01; 32],
            [0x02; 32],
            ChainType::Bitcoin,
            "txid123".to_string(),
            1,
            epoch_root,
            linked_receipt_digest,
            PolicyVersion::default(),
        );
        link.status = LinkStatus::Confirmed;

        assert!(verify_link(&link, &epoch_root));
        assert!(!verify_link(&link, &[0x34; 32]));
    }
}
