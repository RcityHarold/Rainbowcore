//! 链锚定策略版本
//!
//! 根据文档第5篇：ChainAnchorPolicyVersion 定义锚定行为的版本化配置。
//!
//! # 设计原则
//!
//! - 策略版本必须显性化
//! - 同 epoch_root 使用不同策略版本产生不同幂等键
//! - 策略变更必须有公示期

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::types::{AnchorPriority, Timestamp};

/// 链锚定策略版本
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainAnchorPolicyVersion {
    /// 版本号
    pub version: u32,

    /// 生效时间
    pub effective_from: Timestamp,

    /// 失效时间（None 表示永久有效）
    pub effective_until: Option<Timestamp>,

    /// MUST池配置
    pub must_pool: PoolConfig,

    /// SHOULD池配置
    pub should_pool: PoolConfig,

    /// MAY池配置
    pub may_pool: PoolConfig,

    /// 费率配置
    pub fee_config: FeeConfig,

    /// 确认数要求
    pub confirmation_requirements: ConfirmationRequirements,

    /// 重试配置
    pub retry_config: RetryConfig,

    /// Cap配置
    pub cap_config: CapConfig,

    /// 策略描述
    pub description: String,
}

/// 对象池配置
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PoolConfig {
    /// 最大队列长度
    pub max_queue_size: usize,

    /// 最大等待时间（毫秒）
    pub max_wait_duration_ms: u64,

    /// 批量处理大小
    pub batch_size: usize,

    /// 是否允许降级时丢弃
    pub allow_drop_on_degradation: bool,

    /// 优先级权重（用于调度）
    pub priority_weight: u32,
}

impl PoolConfig {
    /// 获取最大等待时间
    pub fn max_wait_duration(&self) -> Duration {
        Duration::from_millis(self.max_wait_duration_ms)
    }
}

/// 费率配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeConfig {
    /// 基础费率（sat/vB）
    pub base_fee_rate: u64,

    /// 最大费率（sat/vB）
    pub max_fee_rate: u64,

    /// 费率估算目标块数
    pub fee_estimation_blocks: u32,

    /// 最大单笔费用（satoshis）
    pub max_single_tx_fee: u64,

    /// 费率调整系数（1.0 = 不调整）
    pub fee_adjustment_factor: f64,
}

/// 确认数要求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmationRequirements {
    /// 主网所需确认数
    pub mainnet: u32,

    /// 测试网所需确认数
    pub testnet: u32,

    /// Signet所需确认数
    pub signet: u32,

    /// Regtest所需确认数
    pub regtest: u32,
}

/// 重试配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// 最大重试次数
    pub max_retries: u32,

    /// 初始退避时间（毫秒）
    pub initial_backoff_ms: u64,

    /// 最大退避时间（毫秒）
    pub max_backoff_ms: u64,

    /// 退避乘数
    pub backoff_multiplier: f64,

    /// 是否启用抖动
    pub jitter_enabled: bool,
}

impl RetryConfig {
    /// 获取初始退避时间
    pub fn initial_backoff(&self) -> Duration {
        Duration::from_millis(self.initial_backoff_ms)
    }

    /// 获取最大退避时间
    pub fn max_backoff(&self) -> Duration {
        Duration::from_millis(self.max_backoff_ms)
    }

    /// 计算第 n 次重试的退避时间
    pub fn backoff_for_attempt(&self, attempt: u32) -> Duration {
        let base = self.initial_backoff_ms as f64;
        let multiplied = base * self.backoff_multiplier.powi(attempt as i32);
        let clamped = multiplied.min(self.max_backoff_ms as f64);
        Duration::from_millis(clamped as u64)
    }
}

/// Cap配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapConfig {
    /// 每日预算上限（satoshis）
    pub daily_budget_cap: u64,

    /// 单笔交易预算上限（satoshis）
    pub single_tx_budget_cap: u64,

    /// 预算预警阈值（百分比，0-100）
    pub budget_warning_threshold: u8,

    /// 预算耗尽时的降级策略
    pub exhaustion_strategy: ExhaustionStrategy,

    /// 是否启用预算滚动（未使用预算可累积）
    pub budget_rollover_enabled: bool,

    /// 最大滚动预算（satoshis）
    pub max_rollover_budget: u64,
}

/// 预算耗尽策略
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExhaustionStrategy {
    /// 丢弃 MAY 级别
    DropMay,
    /// 暂停 SHOULD 和 MAY
    PauseShouldMay,
    /// 全部暂停（仅处理已提交的）
    PauseAll,
    /// 排队等待（不丢弃）
    QueueAll,
}

impl Default for ChainAnchorPolicyVersion {
    fn default() -> Self {
        Self {
            version: 1,
            effective_from: Timestamp::now(),
            effective_until: None,
            must_pool: PoolConfig::default_for_priority(AnchorPriority::Must),
            should_pool: PoolConfig::default_for_priority(AnchorPriority::Should),
            may_pool: PoolConfig::default_for_priority(AnchorPriority::May),
            fee_config: FeeConfig::default(),
            confirmation_requirements: ConfirmationRequirements::default(),
            retry_config: RetryConfig::default(),
            cap_config: CapConfig::default(),
            description: "Default policy version".to_string(),
        }
    }
}

impl PoolConfig {
    /// 根据优先级创建默认配置
    pub fn default_for_priority(priority: AnchorPriority) -> Self {
        match priority {
            AnchorPriority::Must => Self {
                max_queue_size: 10000,
                max_wait_duration_ms: 24 * 60 * 60 * 1000, // 24 小时
                batch_size: 1, // MUST 单独处理
                allow_drop_on_degradation: false, // MUST 不可丢弃
                priority_weight: 100,
            },
            AnchorPriority::Should => Self {
                max_queue_size: 5000,
                max_wait_duration_ms: 6 * 60 * 60 * 1000, // 6 小时
                batch_size: 10,
                allow_drop_on_degradation: false, // SHOULD 也不可随意丢弃
                priority_weight: 50,
            },
            AnchorPriority::May => Self {
                max_queue_size: 1000,
                max_wait_duration_ms: 60 * 60 * 1000, // 1 小时
                batch_size: 50,
                allow_drop_on_degradation: true, // MAY 可丢弃
                priority_weight: 10,
            },
        }
    }
}

impl Default for FeeConfig {
    fn default() -> Self {
        Self {
            base_fee_rate: 10,       // 10 sat/vB
            max_fee_rate: 500,       // 500 sat/vB
            fee_estimation_blocks: 6,
            max_single_tx_fee: 100_000, // 0.001 BTC
            fee_adjustment_factor: 1.0,
        }
    }
}

impl Default for ConfirmationRequirements {
    fn default() -> Self {
        Self {
            mainnet: 6,
            testnet: 3,
            signet: 3,
            regtest: 1,
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 5,
            initial_backoff_ms: 30_000,   // 30 秒
            max_backoff_ms: 600_000,       // 10 分钟
            backoff_multiplier: 2.0,
            jitter_enabled: true,
        }
    }
}

impl Default for CapConfig {
    fn default() -> Self {
        Self {
            daily_budget_cap: 10_000_000,        // 0.1 BTC
            single_tx_budget_cap: 500_000,       // 0.005 BTC
            budget_warning_threshold: 80,        // 80%
            exhaustion_strategy: ExhaustionStrategy::DropMay,
            budget_rollover_enabled: false,
            max_rollover_budget: 5_000_000,      // 0.05 BTC
        }
    }
}

impl ChainAnchorPolicyVersion {
    /// 创建新版本
    pub fn new(version: u32) -> Self {
        Self {
            version,
            ..Default::default()
        }
    }

    /// 检查策略是否在指定时间有效
    pub fn is_effective_at(&self, timestamp: Timestamp) -> bool {
        if timestamp < self.effective_from {
            return false;
        }

        if let Some(until) = self.effective_until {
            if timestamp >= until {
                return false;
            }
        }

        true
    }

    /// 检查策略当前是否有效
    pub fn is_currently_effective(&self) -> bool {
        self.is_effective_at(Timestamp::now())
    }

    /// 获取指定优先级的池配置
    pub fn pool_config_for(&self, priority: AnchorPriority) -> &PoolConfig {
        match priority {
            AnchorPriority::Must => &self.must_pool,
            AnchorPriority::Should => &self.should_pool,
            AnchorPriority::May => &self.may_pool,
        }
    }

    /// 序列化为字节（用于幂等键计算）
    pub fn to_bytes(&self) -> Vec<u8> {
        // 只使用版本号，确保同版本策略产生相同幂等键
        self.version.to_be_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy() {
        let policy = ChainAnchorPolicyVersion::default();
        assert_eq!(policy.version, 1);
        assert!(policy.is_currently_effective());
    }

    #[test]
    fn test_pool_config_priorities() {
        let policy = ChainAnchorPolicyVersion::default();

        // MUST 不可丢弃
        assert!(!policy.must_pool.allow_drop_on_degradation);
        // SHOULD 也不可丢弃
        assert!(!policy.should_pool.allow_drop_on_degradation);
        // MAY 可丢弃
        assert!(policy.may_pool.allow_drop_on_degradation);
    }

    #[test]
    fn test_retry_backoff() {
        let config = RetryConfig::default();

        let backoff_0 = config.backoff_for_attempt(0);
        let backoff_1 = config.backoff_for_attempt(1);
        let backoff_2 = config.backoff_for_attempt(2);

        // 指数增长
        assert!(backoff_1 > backoff_0);
        assert!(backoff_2 > backoff_1);

        // 不超过最大值
        let backoff_10 = config.backoff_for_attempt(10);
        assert!(backoff_10.as_millis() <= config.max_backoff_ms as u128);
    }

    #[test]
    fn test_policy_effectiveness() {
        let mut policy = ChainAnchorPolicyVersion::default();

        // 设置过去的生效时间
        policy.effective_from = Timestamp::from_millis(0);

        // 设置未来的失效时间
        policy.effective_until = Some(Timestamp::from_millis(u64::MAX));

        assert!(policy.is_currently_effective());

        // 设置已失效
        policy.effective_until = Some(Timestamp::from_millis(0));
        assert!(!policy.is_currently_effective());
    }

    #[test]
    fn test_confirmation_requirements() {
        let reqs = ConfirmationRequirements::default();
        assert_eq!(reqs.mainnet, 6);
        assert_eq!(reqs.testnet, 3);
        assert_eq!(reqs.regtest, 1);
    }
}
