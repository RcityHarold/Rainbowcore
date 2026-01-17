//! P4 Integration Module
//!
//! 提供与 L0 核心层和 P3 经济层的集成接口。
//!
//! # 设计原则
//!
//! - **松耦合**: 通过 trait 定义接口，允许多种实现
//! - **异步**: 所有接口都是异步的，支持高并发
//! - **可测试**: 提供 Mock 实现用于测试

pub mod l0;
pub mod p3;

pub use l0::*;
pub use p3::*;

use crate::types::Timestamp;

/// Epoch 信息
#[derive(Debug, Clone)]
pub struct EpochInfo {
    /// Epoch 序列号
    pub sequence: u64,
    /// Epoch 根哈希
    pub epoch_root: [u8; 32],
    /// Epoch 窗口开始时间
    pub window_start: Timestamp,
    /// Epoch 窗口结束时间
    pub window_end: Timestamp,
    /// 签名者集合版本
    pub signer_set_version: u32,
    /// 锚定状态
    pub anchor_status: EpochAnchorState,
}

/// Epoch 锚定状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EpochAnchorState {
    /// 待锚定
    #[default]
    Pending,
    /// 已提交
    Submitted,
    /// 已确认
    Confirmed,
    /// 已完成
    Finalized,
    /// 失败
    Failed,
}

/// 预算信息
#[derive(Debug, Clone)]
pub struct BudgetInfo {
    /// 总预算（satoshis）
    pub total_budget: u64,
    /// 已使用预算
    pub used_budget: u64,
    /// 可用预算
    pub available_budget: u64,
    /// 预留预算
    pub reserved_budget: u64,
    /// 预算周期开始时间
    pub period_start: Timestamp,
    /// 预算周期结束时间
    pub period_end: Timestamp,
}

impl BudgetInfo {
    /// 检查是否有足够的预算
    pub fn has_sufficient_budget(&self, required: u64) -> bool {
        self.available_budget >= required
    }
}

/// 支出报告
#[derive(Debug, Clone)]
pub struct SpendReport {
    /// 报告 ID
    pub report_id: [u8; 32],
    /// 关联的 Job ID
    pub job_id: [u8; 32],
    /// 支出金额（satoshis）
    pub amount: u64,
    /// 支出类型
    pub spend_type: SpendType,
    /// 交易 ID（如有）
    pub txid: Option<String>,
    /// 时间戳
    pub timestamp: Timestamp,
}

/// 支出类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendType {
    /// 锚定费用
    AnchorFee,
    /// 重试费用
    RetryFee,
    /// 紧急锚定费用
    EmergencyFee,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_anchor_state_default() {
        assert_eq!(EpochAnchorState::default(), EpochAnchorState::Pending);
    }

    #[test]
    fn test_budget_info_sufficient() {
        let budget = BudgetInfo {
            total_budget: 100000,
            used_budget: 30000,
            available_budget: 60000,
            reserved_budget: 10000,
            period_start: Timestamp::now(),
            period_end: Timestamp::now(),
        };

        assert!(budget.has_sufficient_budget(50000));
        assert!(!budget.has_sufficient_budget(70000));
    }
}
