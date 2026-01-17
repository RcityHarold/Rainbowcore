//! Cap管理器
//!
//! 管理锚定预算，确保预算使用符合策略要求。
//!
//! # 设计原则
//!
//! - MUST队列不丢弃：cap不足只能 pending，不得静默
//! - 预算预留与确认分离
//! - 支持预算滚动（可选）
//! - 预算耗尽时触发降级

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};

use crate::error::{P4Error, P4Result};
use crate::types::{JobId, Timestamp, AnchorPriority};
use crate::policy::CapConfig;

use super::accounting::AccountingCategory;

/// 预算支出条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetSpendEntry {
    /// 条目ID
    pub entry_id: [u8; 32],

    /// 关联的 Job ID
    pub job_id: JobId,

    /// 预留金额（satoshis）
    pub reserved_amount: u64,

    /// 实际支出金额（确认后填充）
    pub actual_amount: Option<u64>,

    /// 会计分类
    pub category: AccountingCategory,

    /// 优先级
    pub priority: AnchorPriority,

    /// 预留时间
    pub reserved_at: Timestamp,

    /// 确认时间
    pub confirmed_at: Option<Timestamp>,

    /// 状态
    pub status: BudgetSpendStatus,
}

/// 预算支出状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetSpendStatus {
    /// 已预留
    Reserved,
    /// 已确认（实际支出）
    Confirmed,
    /// 已释放（未使用）
    Released,
    /// 已失败
    Failed,
}

/// Cap管理器 - 管理锚定预算
pub struct CapManager {
    /// 当前预算（satoshis）
    current_budget: Arc<RwLock<u64>>,

    /// 预算上限
    budget_cap: u64,

    /// 待处理锚定成本（已预留但未确认）
    pending_anchor_cost: Arc<RwLock<u64>>,

    /// 支出条目（按Job ID索引）
    spend_entries: Arc<RwLock<HashMap<JobId, BudgetSpendEntry>>>,

    /// 历史支出记录
    spend_history: Arc<RwLock<Vec<BudgetSpendEntry>>>,

    /// 今日已支出（用于日上限检查）
    daily_spent: Arc<RwLock<u64>>,

    /// 今日日期（用于重置日支出）
    current_day: Arc<RwLock<u64>>,

    /// 配置
    config: CapConfig,

    /// 滚动预算（从前一日累积）
    rollover_budget: Arc<RwLock<u64>>,

    /// 统计信息
    stats: Arc<RwLock<CapManagerStats>>,
}

/// Cap管理器统计
#[derive(Debug, Clone, Default)]
pub struct CapManagerStats {
    /// 总预留次数
    pub total_reservations: u64,
    /// 总确认次数
    pub total_confirmations: u64,
    /// 总释放次数
    pub total_releases: u64,
    /// 总失败次数
    pub total_failures: u64,
    /// 总预留金额
    pub total_reserved_amount: u64,
    /// 总支出金额
    pub total_spent_amount: u64,
    /// Cap阻塞次数
    pub cap_blocked_count: u64,
    /// 预算警告次数
    pub budget_warning_count: u64,
}

impl CapManager {
    /// 创建新的Cap管理器
    pub fn new(initial_budget: u64, config: CapConfig) -> Self {
        let budget_cap = config.daily_budget_cap;

        Self {
            current_budget: Arc::new(RwLock::new(initial_budget.min(budget_cap))),
            budget_cap,
            pending_anchor_cost: Arc::new(RwLock::new(0)),
            spend_entries: Arc::new(RwLock::new(HashMap::new())),
            spend_history: Arc::new(RwLock::new(Vec::new())),
            daily_spent: Arc::new(RwLock::new(0)),
            current_day: Arc::new(RwLock::new(Self::get_current_day())),
            config,
            rollover_budget: Arc::new(RwLock::new(0)),
            stats: Arc::new(RwLock::new(CapManagerStats::default())),
        }
    }

    /// 使用默认配置创建
    pub fn with_default() -> Self {
        Self::new(CapConfig::default().daily_budget_cap, CapConfig::default())
    }

    /// 获取当前日期（天数，自Unix纪元）
    fn get_current_day() -> u64 {
        Timestamp::now().as_millis() / (24 * 60 * 60 * 1000)
    }

    /// 检查并重置日预算（如果是新的一天）
    async fn check_and_reset_daily_budget(&self) {
        let today = Self::get_current_day();
        let mut current_day = self.current_day.write().await;

        if *current_day != today {
            // 新的一天，处理滚动预算
            if self.config.budget_rollover_enabled {
                let unused = {
                    let current = *self.current_budget.read().await;
                    let pending = *self.pending_anchor_cost.read().await;
                    current.saturating_sub(pending)
                };

                let mut rollover = self.rollover_budget.write().await;
                *rollover = (*rollover + unused).min(self.config.max_rollover_budget);
            }

            // 重置日支出
            *self.daily_spent.write().await = 0;

            // 重置当前预算为上限 + 滚动预算
            let rollover = *self.rollover_budget.read().await;
            *self.current_budget.write().await = self.budget_cap + rollover;

            *current_day = today;

            tracing::info!(
                "Daily budget reset: cap={}, rollover={}",
                self.budget_cap,
                rollover
            );
        }
    }

    /// 检查预算是否充足
    pub async fn check_budget(&self, required: u64) -> P4Result<()> {
        self.check_and_reset_daily_budget().await;

        let current = *self.current_budget.read().await;
        let pending = *self.pending_anchor_cost.read().await;
        let available = current.saturating_sub(pending);

        if available < required {
            let mut stats = self.stats.write().await;
            stats.cap_blocked_count += 1;

            return Err(P4Error::CapExhausted {
                required,
                available,
            });
        }

        // 检查单笔上限
        if required > self.config.single_tx_budget_cap {
            return Err(P4Error::BudgetOperationFailed(format!(
                "Single transaction budget {} exceeds cap {}",
                required, self.config.single_tx_budget_cap
            )));
        }

        Ok(())
    }

    /// 检查是否接近预算警告阈值
    pub async fn check_budget_warning(&self) -> Option<u8> {
        let current = *self.current_budget.read().await;
        let pending = *self.pending_anchor_cost.read().await;
        let available = current.saturating_sub(pending);

        let usage_percent = if self.budget_cap > 0 {
            ((self.budget_cap - available) * 100 / self.budget_cap) as u8
        } else {
            100
        };

        if usage_percent >= self.config.budget_warning_threshold {
            Some(usage_percent)
        } else {
            None
        }
    }

    /// 预留预算
    pub async fn reserve(
        &self,
        amount: u64,
        job_id: JobId,
        priority: AnchorPriority,
        category: AccountingCategory,
    ) -> P4Result<BudgetSpendEntry> {
        // 检查是否已经预留
        {
            let entries = self.spend_entries.read().await;
            if entries.contains_key(&job_id) {
                return Err(P4Error::BudgetAlreadyReserved(
                    hex::encode(&job_id[..8])
                ));
            }
        }

        // 检查预算
        self.check_budget(amount).await?;

        // 创建预留条目
        let entry = BudgetSpendEntry {
            entry_id: crate::types::generate_random_id(),
            job_id,
            reserved_amount: amount,
            actual_amount: None,
            category,
            priority,
            reserved_at: Timestamp::now(),
            confirmed_at: None,
            status: BudgetSpendStatus::Reserved,
        };

        // 更新待处理成本
        *self.pending_anchor_cost.write().await += amount;

        // 保存条目
        self.spend_entries.write().await.insert(job_id, entry.clone());

        // 更新统计
        {
            let mut stats = self.stats.write().await;
            stats.total_reservations += 1;
            stats.total_reserved_amount += amount;
        }

        tracing::debug!(
            "Budget reserved: job={}, amount={}, category={:?}",
            hex::encode(&job_id[..8]),
            amount,
            category
        );

        // 检查预算警告
        if let Some(usage) = self.check_budget_warning().await {
            let mut stats = self.stats.write().await;
            stats.budget_warning_count += 1;
            tracing::warn!("Budget warning: {}% used", usage);
        }

        Ok(entry)
    }

    /// 确认支出（实际扣除预算）
    pub async fn confirm(&self, job_id: &JobId, actual_amount: u64) -> P4Result<BudgetSpendEntry> {
        let mut entries = self.spend_entries.write().await;

        let entry = entries.get_mut(job_id).ok_or_else(|| {
            P4Error::BudgetEntryNotFound(hex::encode(&job_id[..8]))
        })?;

        if entry.status != BudgetSpendStatus::Reserved {
            return Err(P4Error::BudgetOperationFailed(format!(
                "Entry is not in reserved state: {:?}",
                entry.status
            )));
        }

        // 更新条目
        entry.actual_amount = Some(actual_amount);
        entry.confirmed_at = Some(Timestamp::now());
        entry.status = BudgetSpendStatus::Confirmed;

        // 更新预算
        let reserved = entry.reserved_amount;
        *self.pending_anchor_cost.write().await -= reserved;
        *self.current_budget.write().await -= actual_amount;
        *self.daily_spent.write().await += actual_amount;

        // 更新统计
        {
            let mut stats = self.stats.write().await;
            stats.total_confirmations += 1;
            stats.total_spent_amount += actual_amount;
        }

        let result = entry.clone();

        // 移动到历史记录
        let removed = entries.remove(job_id).unwrap();
        self.spend_history.write().await.push(removed);

        tracing::debug!(
            "Budget confirmed: job={}, reserved={}, actual={}",
            hex::encode(&job_id[..8]),
            reserved,
            actual_amount
        );

        Ok(result)
    }

    /// 释放预留（未使用）
    pub async fn release(&self, job_id: &JobId) -> P4Result<BudgetSpendEntry> {
        let mut entries = self.spend_entries.write().await;

        let entry = entries.get_mut(job_id).ok_or_else(|| {
            P4Error::BudgetEntryNotFound(hex::encode(&job_id[..8]))
        })?;

        if entry.status != BudgetSpendStatus::Reserved {
            return Err(P4Error::BudgetOperationFailed(format!(
                "Entry is not in reserved state: {:?}",
                entry.status
            )));
        }

        // 更新条目状态
        entry.status = BudgetSpendStatus::Released;

        // 释放预留
        let reserved = entry.reserved_amount;
        *self.pending_anchor_cost.write().await -= reserved;

        // 更新统计
        {
            let mut stats = self.stats.write().await;
            stats.total_releases += 1;
        }

        let result = entry.clone();

        // 移动到历史记录
        let removed = entries.remove(job_id).unwrap();
        self.spend_history.write().await.push(removed);

        tracing::debug!(
            "Budget released: job={}, amount={}",
            hex::encode(&job_id[..8]),
            reserved
        );

        Ok(result)
    }

    /// 标记失败
    pub async fn mark_failed(&self, job_id: &JobId) -> P4Result<BudgetSpendEntry> {
        let mut entries = self.spend_entries.write().await;

        let entry = entries.get_mut(job_id).ok_or_else(|| {
            P4Error::BudgetEntryNotFound(hex::encode(&job_id[..8]))
        })?;

        if entry.status != BudgetSpendStatus::Reserved {
            return Err(P4Error::BudgetOperationFailed(format!(
                "Entry is not in reserved state: {:?}",
                entry.status
            )));
        }

        // 更新条目状态
        entry.status = BudgetSpendStatus::Failed;

        // 释放预留
        let reserved = entry.reserved_amount;
        *self.pending_anchor_cost.write().await -= reserved;

        // 更新统计
        {
            let mut stats = self.stats.write().await;
            stats.total_failures += 1;
        }

        let result = entry.clone();

        // 移动到历史记录
        let removed = entries.remove(job_id).unwrap();
        self.spend_history.write().await.push(removed);

        tracing::debug!(
            "Budget marked failed: job={}, amount={}",
            hex::encode(&job_id[..8]),
            reserved
        );

        Ok(result)
    }

    /// 获取当前可用预算
    pub async fn available_budget(&self) -> u64 {
        self.check_and_reset_daily_budget().await;

        let current = *self.current_budget.read().await;
        let pending = *self.pending_anchor_cost.read().await;
        current.saturating_sub(pending)
    }

    /// 获取待处理预算
    pub async fn pending_budget(&self) -> u64 {
        *self.pending_anchor_cost.read().await
    }

    /// 获取今日已支出
    pub async fn daily_spent(&self) -> u64 {
        *self.daily_spent.read().await
    }

    /// 获取滚动预算
    pub async fn rollover_budget(&self) -> u64 {
        *self.rollover_budget.read().await
    }

    /// 获取预算使用百分比
    pub async fn usage_percent(&self) -> u8 {
        let current = *self.current_budget.read().await;
        let pending = *self.pending_anchor_cost.read().await;
        let available = current.saturating_sub(pending);

        if self.budget_cap > 0 {
            ((self.budget_cap - available) * 100 / self.budget_cap) as u8
        } else {
            100
        }
    }

    /// 获取指定Job的预留条目
    pub async fn get_entry(&self, job_id: &JobId) -> Option<BudgetSpendEntry> {
        self.spend_entries.read().await.get(job_id).cloned()
    }

    /// 获取所有活跃的预留条目
    pub async fn get_active_entries(&self) -> Vec<BudgetSpendEntry> {
        self.spend_entries.read().await.values().cloned().collect()
    }

    /// 获取历史记录
    pub async fn get_history(&self, limit: usize) -> Vec<BudgetSpendEntry> {
        let history = self.spend_history.read().await;
        history.iter().rev().take(limit).cloned().collect()
    }

    /// 获取统计信息
    pub async fn get_stats(&self) -> CapManagerStats {
        self.stats.read().await.clone()
    }

    /// 获取配置
    pub fn config(&self) -> &CapConfig {
        &self.config
    }

    /// 是否可以处理指定优先级（根据耗尽策略）
    pub async fn can_process_priority(&self, priority: AnchorPriority) -> bool {
        if let Some(_usage) = self.check_budget_warning().await {
            // 预算紧张，检查耗尽策略
            match self.config.exhaustion_strategy {
                crate::policy::ExhaustionStrategy::DropMay => {
                    // 只丢弃 MAY
                    priority != AnchorPriority::May
                }
                crate::policy::ExhaustionStrategy::PauseShouldMay => {
                    // 暂停 SHOULD 和 MAY
                    priority == AnchorPriority::Must
                }
                crate::policy::ExhaustionStrategy::PauseAll => {
                    // 全部暂停（仅处理已提交的）
                    false
                }
                crate::policy::ExhaustionStrategy::QueueAll => {
                    // 排队等待（不丢弃）
                    true
                }
            }
        } else {
            true
        }
    }

    /// 补充预算
    pub async fn replenish(&self, amount: u64) {
        let mut current = self.current_budget.write().await;
        *current = (*current + amount).min(self.budget_cap + *self.rollover_budget.read().await);

        tracing::info!("Budget replenished: amount={}, new_total={}", amount, *current);
    }

    /// 设置预算上限
    pub async fn set_budget_cap(&mut self, new_cap: u64) {
        self.budget_cap = new_cap;
        tracing::info!("Budget cap updated: {}", new_cap);
    }
}

impl Default for CapManager {
    fn default() -> Self {
        Self::with_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> CapConfig {
        CapConfig {
            daily_budget_cap: 1_000_000,
            single_tx_budget_cap: 100_000,
            budget_warning_threshold: 80,
            exhaustion_strategy: crate::policy::ExhaustionStrategy::DropMay,
            budget_rollover_enabled: false,
            max_rollover_budget: 500_000,
        }
    }

    #[tokio::test]
    async fn test_create_cap_manager() {
        let config = create_test_config();
        let manager = CapManager::new(1_000_000, config);

        assert_eq!(manager.available_budget().await, 1_000_000);
        assert_eq!(manager.pending_budget().await, 0);
    }

    #[tokio::test]
    async fn test_reserve_and_confirm() {
        let config = create_test_config();
        let manager = CapManager::new(1_000_000, config);

        let job_id = [0x12; 32];
        let entry = manager.reserve(
            10_000,
            job_id,
            AnchorPriority::Must,
            AccountingCategory::ProtocolTax,
        ).await.unwrap();

        assert_eq!(entry.reserved_amount, 10_000);
        assert_eq!(entry.status, BudgetSpendStatus::Reserved);

        // 检查预算变化
        assert_eq!(manager.pending_budget().await, 10_000);
        assert_eq!(manager.available_budget().await, 990_000);

        // 确认
        let confirmed = manager.confirm(&job_id, 8_000).await.unwrap();
        assert_eq!(confirmed.actual_amount, Some(8_000));
        assert_eq!(confirmed.status, BudgetSpendStatus::Confirmed);

        // 检查预算变化
        assert_eq!(manager.pending_budget().await, 0);
        assert_eq!(manager.available_budget().await, 992_000);
    }

    #[tokio::test]
    async fn test_reserve_and_release() {
        let config = create_test_config();
        let manager = CapManager::new(1_000_000, config);

        let job_id = [0x34; 32];
        manager.reserve(
            20_000,
            job_id,
            AnchorPriority::Should,
            AccountingCategory::AnchorFee,
        ).await.unwrap();

        assert_eq!(manager.pending_budget().await, 20_000);

        // 释放
        let released = manager.release(&job_id).await.unwrap();
        assert_eq!(released.status, BudgetSpendStatus::Released);

        // 预算应该恢复
        assert_eq!(manager.pending_budget().await, 0);
        assert_eq!(manager.available_budget().await, 1_000_000);
    }

    #[tokio::test]
    async fn test_cap_exhausted() {
        let config = create_test_config();
        let manager = CapManager::new(50_000, config);

        // 尝试预留超过可用预算
        let job_id = [0x56; 32];
        let result = manager.reserve(
            100_000,
            job_id,
            AnchorPriority::May,
            AccountingCategory::AnchorFee,
        ).await;

        assert!(matches!(result, Err(P4Error::CapExhausted { .. })));
    }

    #[tokio::test]
    async fn test_single_tx_cap() {
        let config = create_test_config();
        let manager = CapManager::new(1_000_000, config);

        // 尝试预留超过单笔上限
        let job_id = [0x78; 32];
        let result = manager.reserve(
            200_000, // 超过单笔上限 100_000
            job_id,
            AnchorPriority::Must,
            AccountingCategory::ProtocolTax,
        ).await;

        assert!(matches!(result, Err(P4Error::BudgetOperationFailed(_))));
    }

    #[tokio::test]
    async fn test_duplicate_reservation() {
        let config = create_test_config();
        let manager = CapManager::new(1_000_000, config);

        let job_id = [0x9a; 32];

        // 第一次预留成功
        manager.reserve(
            10_000,
            job_id,
            AnchorPriority::Must,
            AccountingCategory::ProtocolTax,
        ).await.unwrap();

        // 第二次预留应该失败
        let result = manager.reserve(
            10_000,
            job_id,
            AnchorPriority::Must,
            AccountingCategory::ProtocolTax,
        ).await;

        assert!(matches!(result, Err(P4Error::BudgetAlreadyReserved(_))));
    }

    #[tokio::test]
    async fn test_stats() {
        let config = create_test_config();
        let manager = CapManager::new(1_000_000, config);

        let job_id1 = [0xbc; 32];
        let job_id2 = [0xde; 32];

        manager.reserve(10_000, job_id1, AnchorPriority::Must, AccountingCategory::ProtocolTax).await.unwrap();
        manager.reserve(20_000, job_id2, AnchorPriority::Should, AccountingCategory::AnchorFee).await.unwrap();

        manager.confirm(&job_id1, 8_000).await.unwrap();
        manager.release(&job_id2).await.unwrap();

        let stats = manager.get_stats().await;
        assert_eq!(stats.total_reservations, 2);
        assert_eq!(stats.total_confirmations, 1);
        assert_eq!(stats.total_releases, 1);
        assert_eq!(stats.total_reserved_amount, 30_000);
        assert_eq!(stats.total_spent_amount, 8_000);
    }
}
