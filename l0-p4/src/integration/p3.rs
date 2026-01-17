//! P3 Economic Layer Integration
//!
//! 提供与 P3 经济层的集成接口，用于：
//! - 获取锚定预算
//! - 报告锚定支出
//! - 请求预算分配
//! - 获取推荐费率

use std::sync::Arc;
use async_trait::async_trait;
use tokio::sync::RwLock;
use tracing::{info, warn};
use rust_decimal::Decimal;

use crate::error::{P4Error, P4Result};
use crate::types::{AnchorPriority, Timestamp};
use crate::cap::BudgetSpendEntry as P4BudgetSpendEntry;

use super::{BudgetInfo, SpendReport, SpendType};

/// P3 经济层集成 Trait
///
/// 定义与 P3 经济层交互的接口。
/// 实现者需要提供预算管理和支出报告功能。
#[async_trait]
pub trait P3Integration: Send + Sync {
    /// 获取锚定预算
    ///
    /// 返回当前预算周期的预算信息。
    async fn get_anchor_budget(&self) -> P4Result<BudgetInfo>;

    /// 报告锚定支出
    ///
    /// 向 P3 层报告一笔锚定支出。
    async fn report_anchor_spend(&self, report: &SpendReport) -> P4Result<()>;

    /// 报告 BudgetSpendEntry
    ///
    /// 从 P4 Cap 模块的 BudgetSpendEntry 创建支出报告。
    async fn report_spend_entry(&self, entry: &P4BudgetSpendEntry) -> P4Result<()>;

    /// 请求预算分配
    ///
    /// 当预算不足时，请求额外预算分配。
    async fn request_budget_allocation(
        &self,
        amount: u64,
        priority: AnchorPriority,
        reason: &str,
    ) -> P4Result<bool>;

    /// 获取推荐费率
    ///
    /// 返回当前推荐的交易费率（satoshis/vByte）。
    async fn get_recommended_fee_rate(&self) -> P4Result<u64>;

    /// 获取单笔交易最大费用
    ///
    /// 返回单笔锚定交易的最大允许费用。
    async fn get_max_single_tx_fee(&self) -> P4Result<u64>;

    /// 发送预算警报
    ///
    /// 当预算低于阈值时发送警报。
    async fn send_budget_alert(&self, remaining_percentage: f64) -> P4Result<()>;

    /// 刷新预算周期
    ///
    /// 获取新的预算周期信息。
    async fn refresh_budget_period(&self) -> P4Result<BudgetInfo>;
}

/// P3 集成的 Mock 实现
///
/// 用于测试和开发环境。
pub struct MockP3Integration {
    /// 模拟预算
    budget: Arc<RwLock<BudgetInfo>>,
    /// 推荐费率
    fee_rate: Arc<RwLock<u64>>,
    /// 最大单笔费用
    max_tx_fee: Arc<RwLock<u64>>,
}

impl MockP3Integration {
    /// 创建新的 Mock 实现
    pub fn new() -> Self {
        let now = Timestamp::now();
        let budget = BudgetInfo {
            total_budget: 1_000_000, // 0.01 BTC
            used_budget: 0,
            available_budget: 1_000_000,
            reserved_budget: 0,
            period_start: now,
            period_end: Timestamp::from_millis(now.as_millis() + 86400000 * 30), // 30 days
        };

        Self {
            budget: Arc::new(RwLock::new(budget)),
            fee_rate: Arc::new(RwLock::new(10)), // 10 sat/vB
            max_tx_fee: Arc::new(RwLock::new(50_000)), // 50,000 satoshis
        }
    }

    /// 设置预算
    pub async fn set_budget(&self, budget: BudgetInfo) {
        let mut b = self.budget.write().await;
        *b = budget;
    }

    /// 设置费率
    pub async fn set_fee_rate(&self, rate: u64) {
        let mut r = self.fee_rate.write().await;
        *r = rate;
    }
}

impl Default for MockP3Integration {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl P3Integration for MockP3Integration {
    async fn get_anchor_budget(&self) -> P4Result<BudgetInfo> {
        let budget = self.budget.read().await;
        Ok(budget.clone())
    }

    async fn report_anchor_spend(&self, report: &SpendReport) -> P4Result<()> {
        let mut budget = self.budget.write().await;

        if report.amount > budget.available_budget {
            return Err(P4Error::BudgetInsufficient {
                required: report.amount,
                available: budget.available_budget,
            });
        }

        budget.used_budget += report.amount;
        budget.available_budget -= report.amount;

        info!(
            "Recorded spend: {} satoshis for {:?}, txid: {:?}",
            report.amount, report.spend_type, report.txid
        );

        Ok(())
    }

    async fn report_spend_entry(&self, entry: &P4BudgetSpendEntry) -> P4Result<()> {
        use sha2::{Sha256, Digest};

        // 生成 report_id
        let mut hasher = Sha256::new();
        hasher.update(entry.entry_id);
        hasher.update(entry.reserved_at.as_millis().to_be_bytes());
        let hash = hasher.finalize();
        let mut report_id = [0u8; 32];
        report_id.copy_from_slice(&hash);

        // 转换 spend_type
        let spend_type = match entry.category {
            crate::cap::AccountingCategory::AnchorFee => SpendType::AnchorFee,
            crate::cap::AccountingCategory::ProtocolTax => SpendType::AnchorFee,
            crate::cap::AccountingCategory::SystemSubsidy => SpendType::EmergencyFee,
        };

        // 使用实际金额，如果没有则使用预留金额
        let amount = entry.actual_amount.unwrap_or(entry.reserved_amount);

        let report = SpendReport {
            report_id,
            job_id: entry.job_id,
            amount,
            spend_type,
            txid: None, // P4BudgetSpendEntry 不包含 txid
            timestamp: entry.reserved_at,
        };

        self.report_anchor_spend(&report).await
    }

    async fn request_budget_allocation(
        &self,
        amount: u64,
        priority: AnchorPriority,
        reason: &str,
    ) -> P4Result<bool> {
        let mut budget = self.budget.write().await;

        // Mock: 只允许 MUST 级别的额外分配
        if priority != AnchorPriority::Must {
            info!(
                "Budget allocation denied for {:?} priority: {}",
                priority, reason
            );
            return Ok(false);
        }

        // 分配额外预算
        budget.total_budget += amount;
        budget.available_budget += amount;

        info!(
            "Budget allocation approved: {} satoshis for {:?}, reason: {}",
            amount, priority, reason
        );

        Ok(true)
    }

    async fn get_recommended_fee_rate(&self) -> P4Result<u64> {
        let rate = self.fee_rate.read().await;
        Ok(*rate)
    }

    async fn get_max_single_tx_fee(&self) -> P4Result<u64> {
        let max_fee = self.max_tx_fee.read().await;
        Ok(*max_fee)
    }

    async fn send_budget_alert(&self, remaining_percentage: f64) -> P4Result<()> {
        warn!(
            "Budget alert: {}% remaining",
            (remaining_percentage * 100.0).round()
        );
        Ok(())
    }

    async fn refresh_budget_period(&self) -> P4Result<BudgetInfo> {
        let now = Timestamp::now();
        let mut budget = self.budget.write().await;

        // Mock: 重置预算周期
        budget.period_start = now;
        budget.period_end = Timestamp::from_millis(now.as_millis() + 86400000 * 30);
        budget.used_budget = 0;
        budget.available_budget = budget.total_budget;
        budget.reserved_budget = 0;

        Ok(budget.clone())
    }
}

/// P3 集成的生产实现
///
/// 连接到实际的 P3 经济层 TreasuryManager。
pub struct P3IntegrationImpl {
    /// P3 TreasuryManager 引用
    treasury: Arc<RwLock<p3_core::TreasuryManager>>,
    /// 当前 EpochId
    current_epoch_id: Arc<RwLock<p3_core::EpochId>>,
    /// 锚定专用池（默认使用 InfraPool）
    anchor_pool: p3_core::TreasuryPool,
    /// 费率缓存
    fee_rate_cache: Arc<RwLock<u64>>,
    /// 最大单笔费用
    max_tx_fee: u64,
}

impl P3IntegrationImpl {
    /// 创建新的 P3 集成实例
    pub fn new(
        treasury: Arc<RwLock<p3_core::TreasuryManager>>,
        initial_epoch_id: p3_core::EpochId,
    ) -> Self {
        Self {
            treasury,
            current_epoch_id: Arc::new(RwLock::new(initial_epoch_id)),
            anchor_pool: p3_core::TreasuryPool::InfraPool, // 锚定费从基础设施池支出
            fee_rate_cache: Arc::new(RwLock::new(10)), // 默认 10 sat/vB
            max_tx_fee: 100_000, // 默认最大 100,000 satoshis
        }
    }

    /// 更新当前 Epoch ID
    pub async fn set_epoch_id(&self, epoch_id: p3_core::EpochId) {
        let mut current = self.current_epoch_id.write().await;
        *current = epoch_id;
    }

    /// 更新费率缓存
    pub async fn set_fee_rate(&self, rate: u64) {
        let mut cache = self.fee_rate_cache.write().await;
        *cache = rate;
    }

    /// 将 satoshis 转换为 Decimal
    fn satoshis_to_decimal(satoshis: u64) -> Decimal {
        Decimal::new(satoshis as i64, 0)
    }

    /// 将 Decimal 转换为 satoshis
    fn decimal_to_satoshis(amount: Decimal) -> u64 {
        // 使用 trunc 去掉小数部分，然后安全转换为 u64
        amount.trunc().to_string().parse().unwrap_or(0)
    }

    /// 获取 spend reason type
    fn get_spend_reason(spend_type: SpendType) -> p3_core::SpendReasonType {
        match spend_type {
            SpendType::AnchorFee => p3_core::SpendReasonType::Anchor,
            SpendType::RetryFee => p3_core::SpendReasonType::Anchor,
            SpendType::EmergencyFee => p3_core::SpendReasonType::Anchor,
        }
    }
}

#[async_trait]
impl P3Integration for P3IntegrationImpl {
    async fn get_anchor_budget(&self) -> P4Result<BudgetInfo> {
        let treasury = self.treasury.read().await;

        // 获取锚定池的余额
        let pool_state = treasury.get_pool(&self.anchor_pool).ok_or_else(|| {
            P4Error::EconUnavailable("Anchor pool not found".to_string())
        })?;

        let total_balance = Self::decimal_to_satoshis(pool_state.balance);
        let used = Self::decimal_to_satoshis(pool_state.spend_total);

        let now = Timestamp::now();

        Ok(BudgetInfo {
            total_budget: total_balance + used, // 总预算 = 当前余额 + 已用
            used_budget: used,
            available_budget: total_balance,
            reserved_budget: 0, // P3 TreasuryManager 不跟踪预留
            period_start: now, // 简化：使用当前时间
            period_end: Timestamp::from_millis(now.as_millis() + 86400000 * 30),
        })
    }

    async fn report_anchor_spend(&self, report: &SpendReport) -> P4Result<()> {
        let mut treasury = self.treasury.write().await;
        let epoch_id = self.current_epoch_id.read().await;

        let amount = Self::satoshis_to_decimal(report.amount);
        let reason = Self::get_spend_reason(report.spend_type);

        // 从锚定池支出
        treasury
            .spend(self.anchor_pool.clone(), amount, reason, &epoch_id)
            .map_err(|e| P4Error::BudgetOperationFailed(e.to_string()))?;

        info!(
            "P3 spend recorded: {} satoshis from {:?} for {:?}",
            report.amount,
            self.anchor_pool.name(),
            report.spend_type
        );

        Ok(())
    }

    async fn report_spend_entry(&self, entry: &P4BudgetSpendEntry) -> P4Result<()> {
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();
        hasher.update(entry.entry_id);
        hasher.update(entry.reserved_at.as_millis().to_be_bytes());
        let hash = hasher.finalize();
        let mut report_id = [0u8; 32];
        report_id.copy_from_slice(&hash);

        let spend_type = match entry.category {
            crate::cap::AccountingCategory::AnchorFee => SpendType::AnchorFee,
            crate::cap::AccountingCategory::ProtocolTax => SpendType::AnchorFee,
            crate::cap::AccountingCategory::SystemSubsidy => SpendType::EmergencyFee,
        };

        // 使用实际金额，如果没有则使用预留金额
        let amount = entry.actual_amount.unwrap_or(entry.reserved_amount);

        let report = SpendReport {
            report_id,
            job_id: entry.job_id,
            amount,
            spend_type,
            txid: None, // P4BudgetSpendEntry 不包含 txid
            timestamp: entry.reserved_at,
        };

        self.report_anchor_spend(&report).await
    }

    async fn request_budget_allocation(
        &self,
        amount: u64,
        priority: AnchorPriority,
        reason: &str,
    ) -> P4Result<bool> {
        // P3 TreasuryManager 不直接支持预算分配
        // 需要通过 capture_income 或外部治理流程
        info!(
            "P3 budget allocation request: {} satoshis, {:?}, reason: {}",
            amount, priority, reason
        );

        // 只对 MUST 优先级自动批准（模拟）
        if priority == AnchorPriority::Must {
            warn!(
                "Auto-approving MUST priority budget allocation: {} satoshis",
                amount
            );
            // 在实际实现中，这里应该调用 P3 治理 API
            return Ok(true);
        }

        Ok(false)
    }

    async fn get_recommended_fee_rate(&self) -> P4Result<u64> {
        let rate = self.fee_rate_cache.read().await;
        Ok(*rate)
    }

    async fn get_max_single_tx_fee(&self) -> P4Result<u64> {
        Ok(self.max_tx_fee)
    }

    async fn send_budget_alert(&self, remaining_percentage: f64) -> P4Result<()> {
        warn!(
            "P3 Budget alert: {}% remaining in anchor pool",
            (remaining_percentage * 100.0).round()
        );
        // 在实际实现中，这里应该发送到 P3 监控系统
        Ok(())
    }

    async fn refresh_budget_period(&self) -> P4Result<BudgetInfo> {
        // 刷新预算信息
        self.get_anchor_budget().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_p3_integration() {
        let mock = MockP3Integration::new();

        // 测试获取预算
        let budget = mock.get_anchor_budget().await.unwrap();
        assert_eq!(budget.total_budget, 1_000_000);
        assert_eq!(budget.available_budget, 1_000_000);

        // 测试报告支出
        let report = SpendReport {
            report_id: [1u8; 32],
            job_id: [2u8; 32],
            amount: 10_000,
            spend_type: SpendType::AnchorFee,
            txid: Some("txid123".to_string()),
            timestamp: Timestamp::now(),
        };

        mock.report_anchor_spend(&report).await.unwrap();

        // 验证预算已更新
        let budget = mock.get_anchor_budget().await.unwrap();
        assert_eq!(budget.used_budget, 10_000);
        assert_eq!(budget.available_budget, 990_000);
    }

    #[tokio::test]
    async fn test_budget_allocation() {
        let mock = MockP3Integration::new();

        // MUST 优先级应该被批准
        let approved = mock
            .request_budget_allocation(50_000, AnchorPriority::Must, "Emergency anchor")
            .await
            .unwrap();
        assert!(approved);

        // Should 优先级应该被拒绝
        let approved = mock
            .request_budget_allocation(50_000, AnchorPriority::Should, "Regular anchor")
            .await
            .unwrap();
        assert!(!approved);
    }

    #[tokio::test]
    async fn test_insufficient_budget() {
        let mock = MockP3Integration::new();

        // 设置低预算
        mock.set_budget(BudgetInfo {
            total_budget: 1000,
            used_budget: 0,
            available_budget: 1000,
            reserved_budget: 0,
            period_start: Timestamp::now(),
            period_end: Timestamp::now(),
        })
        .await;

        // 尝试超额支出
        let report = SpendReport {
            report_id: [1u8; 32],
            job_id: [2u8; 32],
            amount: 5000, // 超过可用预算
            spend_type: SpendType::AnchorFee,
            txid: None,
            timestamp: Timestamp::now(),
        };

        let result = mock.report_anchor_spend(&report).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_fee_rate() {
        let mock = MockP3Integration::new();

        // 默认费率
        let rate = mock.get_recommended_fee_rate().await.unwrap();
        assert_eq!(rate, 10);

        // 更新费率
        mock.set_fee_rate(20).await;
        let rate = mock.get_recommended_fee_rate().await.unwrap();
        assert_eq!(rate, 20);
    }

    #[tokio::test]
    async fn test_p3_integration_impl_with_treasury() {
        // 创建真实的 TreasuryManager
        let treasury = Arc::new(RwLock::new(p3_core::TreasuryManager::new()));

        // 设置 Treasury Context（需要初始化预算）
        {
            let mut t = treasury.write().await;
            let ratios = p3_core::PoolRatios::default();
            let ratio_version = p3_core::PoolRatioVersion {
                ratio_id: "ratio:test".to_string(),
                version: "v1".to_string(),
                valid_from: p3_core::EpochId::new("epoch:1"),
                supersedes: None,
                issuer_ref: "test".to_string(),
                ratio_digest: ratios.compute_digest(),
                canonicalization_version: p3_core::CanonVersion::v1(),
                ratios,
            };
            let ctx = p3_core::TreasuryContext::new(p3_core::EpochId::new("epoch:1"), ratio_version);
            t.set_context(ctx);

            // 注入一些初始资金
            t.capture_income(Decimal::new(100_000, 0), &p3_core::EpochId::new("epoch:1"))
                .unwrap();
        }

        // 创建集成实例
        let integration = P3IntegrationImpl::new(treasury.clone(), p3_core::EpochId::new("epoch:1"));

        // 测试获取预算
        let budget = integration.get_anchor_budget().await.unwrap();
        assert!(budget.available_budget > 0);

        // 测试报告支出
        let report = SpendReport {
            report_id: [1u8; 32],
            job_id: [2u8; 32],
            amount: 1000,
            spend_type: SpendType::AnchorFee,
            txid: Some("txid123".to_string()),
            timestamp: Timestamp::now(),
        };

        integration.report_anchor_spend(&report).await.unwrap();

        // 验证预算已减少
        let budget_after = integration.get_anchor_budget().await.unwrap();
        assert!(budget_after.available_budget < budget.available_budget);
    }
}
