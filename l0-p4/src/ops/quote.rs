//! Quote 阶段 - 费用估算
//!
//! 根据当前网络状况估算锚定所需的费用。

use serde::{Deserialize, Serialize};

use crate::error::{P4Error, P4Result};
use crate::storage::AnchorStorage;
use crate::types::{ChainAnchorInput, ChainType, Timestamp};

use super::AnchorOps;

/// Quote 结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteResult {
    /// 估算费用（satoshis）
    pub estimated_fee: u64,
    /// 费率（sat/vB）
    pub fee_rate: u64,
    /// 估算交易大小（vBytes）
    pub estimated_size: u64,
    /// 目标确认块数
    pub target_blocks: u32,
    /// 报价时间
    pub quoted_at: Timestamp,
    /// 报价有效期（毫秒）
    pub valid_until: Timestamp,
    /// 链类型
    pub chain_type: ChainType,
}

impl QuoteResult {
    /// 检查报价是否仍然有效
    pub fn is_valid(&self) -> bool {
        Timestamp::now().as_millis() < self.valid_until.as_millis()
    }

    /// 获取剩余有效时间（毫秒）
    pub fn remaining_validity_ms(&self) -> u64 {
        let now = Timestamp::now().as_millis();
        let until = self.valid_until.as_millis();
        until.saturating_sub(now)
    }
}

/// Quote 错误
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QuoteError {
    /// 无法估算费率
    FeeEstimationFailed(String),
    /// 费率过高
    FeeRateTooHigh { estimated: u64, max_allowed: u64 },
    /// 网络不可用
    NetworkUnavailable,
}

impl std::fmt::Display for QuoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuoteError::FeeEstimationFailed(msg) => {
                write!(f, "Fee estimation failed: {}", msg)
            }
            QuoteError::FeeRateTooHigh { estimated, max_allowed } => {
                write!(
                    f,
                    "Fee rate too high: {} sat/vB (max: {} sat/vB)",
                    estimated, max_allowed
                )
            }
            QuoteError::NetworkUnavailable => {
                write!(f, "Bitcoin network unavailable")
            }
        }
    }
}

impl std::error::Error for QuoteError {}

/// OP_RETURN 锚定交易的估算大小
/// - 输入: ~148 vBytes (P2WPKH)
/// - 输出 (change): ~31 vBytes (P2WPKH)
/// - OP_RETURN 输出: ~60 vBytes (49 bytes data + overhead)
/// - 其他开销: ~11 vBytes
const ESTIMATED_TX_SIZE_VBYTES: u64 = 250;

/// 报价有效期（毫秒）- 10 分钟
const QUOTE_VALIDITY_MS: u64 = 10 * 60 * 1000;

/// 默认费率估算目标块数
const DEFAULT_TARGET_BLOCKS: u32 = 6;

/// 最低费率（sat/vB）
const MIN_FEE_RATE: u64 = 1;

/// 执行 Quote 阶段
pub async fn execute<S: AnchorStorage + 'static>(
    ops: &AnchorOps<S>,
    input: &ChainAnchorInput,
) -> P4Result<QuoteResult> {
    let config = ops.config();
    let bitcoin_rpc = ops.bitcoin_rpc();

    // 确定目标确认块数
    let target_blocks = DEFAULT_TARGET_BLOCKS;

    // 估算费率
    let fee_rate = match bitcoin_rpc.estimate_smart_fee(target_blocks).await {
        Ok(rate) => rate.max(MIN_FEE_RATE),
        Err(e) => {
            // 如果估算失败，使用配置的默认费率
            tracing::warn!("Fee estimation failed, using fallback rate: {}", e);
            config.default_fee_rate.unwrap_or(MIN_FEE_RATE)
        }
    };

    // 检查费率是否过高
    if let Some(max_rate) = config.max_fee_rate {
        if fee_rate > max_rate {
            return Err(P4Error::Configuration(format!(
                "Fee rate {} sat/vB exceeds maximum {} sat/vB",
                fee_rate, max_rate
            )));
        }
    }

    // 计算估算费用
    let estimated_size = ESTIMATED_TX_SIZE_VBYTES;
    let estimated_fee = fee_rate * estimated_size;

    // 检查单笔费用是否过高
    if let Some(max_fee) = config.max_single_tx_fee {
        if estimated_fee > max_fee {
            return Err(P4Error::Configuration(format!(
                "Estimated fee {} satoshis exceeds maximum {} satoshis",
                estimated_fee, max_fee
            )));
        }
    }

    // 计算有效期
    let now = Timestamp::now();
    let valid_until = Timestamp::from_millis(now.as_millis() + QUOTE_VALIDITY_MS);

    let result = QuoteResult {
        estimated_fee,
        fee_rate,
        estimated_size,
        target_blocks,
        quoted_at: now,
        valid_until,
        chain_type: ChainType::Bitcoin,
    };

    tracing::info!(
        "Quote for input {:?}: {} satoshis ({} sat/vB)",
        hex::encode(&input.input_id[..8]),
        estimated_fee,
        fee_rate
    );

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quote_result_validity() {
        let now = Timestamp::now();
        let valid_until = Timestamp::from_millis(now.as_millis() + 10000);

        let result = QuoteResult {
            estimated_fee: 5000,
            fee_rate: 20,
            estimated_size: 250,
            target_blocks: 6,
            quoted_at: now,
            valid_until,
            chain_type: ChainType::Bitcoin,
        };

        assert!(result.is_valid());
        assert!(result.remaining_validity_ms() > 0);
    }

    #[test]
    fn test_quote_result_expired() {
        let now = Timestamp::now();
        let valid_until = Timestamp::from_millis(now.as_millis().saturating_sub(1000));

        let result = QuoteResult {
            estimated_fee: 5000,
            fee_rate: 20,
            estimated_size: 250,
            target_blocks: 6,
            quoted_at: Timestamp::from_millis(now.as_millis().saturating_sub(2000)),
            valid_until,
            chain_type: ChainType::Bitcoin,
        };

        assert!(!result.is_valid());
        assert_eq!(result.remaining_validity_ms(), 0);
    }

    #[test]
    fn test_quote_error_display() {
        let err = QuoteError::FeeRateTooHigh {
            estimated: 100,
            max_allowed: 50,
        };
        assert!(err.to_string().contains("100"));
        assert!(err.to_string().contains("50"));
    }
}
