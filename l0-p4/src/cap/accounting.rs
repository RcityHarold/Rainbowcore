//! 会计分类（不混税三列）
//!
//! 区分不同性质的锚定费用，确保税务合规。
//!
//! # 三列原则
//!
//! - 协议税（Protocol Tax）: 必须支付的协议层费用
//! - 锚定费（Anchor Fee）: 链上交易手续费
//! - 系统补贴（System Subsidy）: 系统承担的补贴费用
//!
//! # 设计原则
//!
//! - 不同类别不混合
//! - 每个支出必须有明确分类
//! - 支持审计追踪

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};

use crate::types::{JobId, Timestamp};

/// 会计分类（不混税三列）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountingCategory {
    /// 协议税 - 必须支付的协议层费用
    ProtocolTax,
    /// 锚定费 - 链上交易手续费
    #[default]
    AnchorFee,
    /// 系统补贴 - 系统承担的补贴费用
    SystemSubsidy,
}

impl std::fmt::Display for AccountingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProtocolTax => write!(f, "protocol_tax"),
            Self::AnchorFee => write!(f, "anchor_fee"),
            Self::SystemSubsidy => write!(f, "system_subsidy"),
        }
    }
}

/// 会计条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountingEntry {
    /// 条目ID
    pub entry_id: [u8; 32],

    /// 关联的 Job ID
    pub job_id: JobId,

    /// 分类
    pub category: AccountingCategory,

    /// 金额（satoshis）
    pub amount: u64,

    /// 创建时间
    pub created_at: Timestamp,

    /// 描述
    pub description: String,

    /// 元数据
    pub metadata: HashMap<String, String>,
}

/// 分类汇总
#[derive(Debug, Clone, Default)]
pub struct CategorySummary {
    /// 总金额
    pub total_amount: u64,
    /// 条目数量
    pub entry_count: u64,
    /// 最后更新时间
    pub last_updated: Option<Timestamp>,
}

/// 会计账本
pub struct AccountingLedger {
    /// 按分类索引的条目
    entries_by_category: Arc<RwLock<HashMap<AccountingCategory, Vec<AccountingEntry>>>>,

    /// 按Job索引的条目
    entries_by_job: Arc<RwLock<HashMap<JobId, Vec<AccountingEntry>>>>,

    /// 分类汇总
    summaries: Arc<RwLock<HashMap<AccountingCategory, CategorySummary>>>,
}

impl AccountingLedger {
    /// 创建新的账本
    pub fn new() -> Self {
        let mut summaries = HashMap::new();
        summaries.insert(AccountingCategory::ProtocolTax, CategorySummary::default());
        summaries.insert(AccountingCategory::AnchorFee, CategorySummary::default());
        summaries.insert(AccountingCategory::SystemSubsidy, CategorySummary::default());

        Self {
            entries_by_category: Arc::new(RwLock::new(HashMap::new())),
            entries_by_job: Arc::new(RwLock::new(HashMap::new())),
            summaries: Arc::new(RwLock::new(summaries)),
        }
    }

    /// 记录支出
    pub async fn record_expense(
        &self,
        job_id: JobId,
        category: AccountingCategory,
        amount: u64,
        description: impl Into<String>,
    ) -> AccountingEntry {
        let entry = AccountingEntry {
            entry_id: crate::types::generate_random_id(),
            job_id,
            category,
            amount,
            created_at: Timestamp::now(),
            description: description.into(),
            metadata: HashMap::new(),
        };

        // 添加到分类索引
        {
            let mut by_category = self.entries_by_category.write().await;
            by_category.entry(category).or_default().push(entry.clone());
        }

        // 添加到Job索引
        {
            let mut by_job = self.entries_by_job.write().await;
            by_job.entry(job_id).or_default().push(entry.clone());
        }

        // 更新汇总
        {
            let mut summaries = self.summaries.write().await;
            let summary = summaries.entry(category).or_default();
            summary.total_amount += amount;
            summary.entry_count += 1;
            summary.last_updated = Some(Timestamp::now());
        }

        tracing::debug!(
            "Recorded expense: job={}, category={}, amount={}",
            hex::encode(&job_id[..8]),
            category,
            amount
        );

        entry
    }

    /// 记录支出（带元数据）
    pub async fn record_expense_with_metadata(
        &self,
        job_id: JobId,
        category: AccountingCategory,
        amount: u64,
        description: impl Into<String>,
        metadata: HashMap<String, String>,
    ) -> AccountingEntry {
        let entry = AccountingEntry {
            entry_id: crate::types::generate_random_id(),
            job_id,
            category,
            amount,
            created_at: Timestamp::now(),
            description: description.into(),
            metadata,
        };

        // 添加到分类索引
        {
            let mut by_category = self.entries_by_category.write().await;
            by_category.entry(category).or_default().push(entry.clone());
        }

        // 添加到Job索引
        {
            let mut by_job = self.entries_by_job.write().await;
            by_job.entry(job_id).or_default().push(entry.clone());
        }

        // 更新汇总
        {
            let mut summaries = self.summaries.write().await;
            let summary = summaries.entry(category).or_default();
            summary.total_amount += amount;
            summary.entry_count += 1;
            summary.last_updated = Some(Timestamp::now());
        }

        entry
    }

    /// 获取分类汇总
    pub async fn get_summary(&self, category: AccountingCategory) -> CategorySummary {
        self.summaries
            .read()
            .await
            .get(&category)
            .cloned()
            .unwrap_or_default()
    }

    /// 获取所有分类汇总
    pub async fn get_all_summaries(&self) -> HashMap<AccountingCategory, CategorySummary> {
        self.summaries.read().await.clone()
    }

    /// 获取总支出
    pub async fn total_expenses(&self) -> u64 {
        self.summaries
            .read()
            .await
            .values()
            .map(|s| s.total_amount)
            .sum()
    }

    /// 获取分类支出
    pub async fn category_expenses(&self, category: AccountingCategory) -> u64 {
        self.summaries
            .read()
            .await
            .get(&category)
            .map(|s| s.total_amount)
            .unwrap_or(0)
    }

    /// 获取Job的所有条目
    pub async fn get_entries_by_job(&self, job_id: &JobId) -> Vec<AccountingEntry> {
        self.entries_by_job
            .read()
            .await
            .get(job_id)
            .cloned()
            .unwrap_or_default()
    }

    /// 获取分类的所有条目
    pub async fn get_entries_by_category(&self, category: AccountingCategory) -> Vec<AccountingEntry> {
        self.entries_by_category
            .read()
            .await
            .get(&category)
            .cloned()
            .unwrap_or_default()
    }

    /// 获取最近的条目
    pub async fn get_recent_entries(&self, limit: usize) -> Vec<AccountingEntry> {
        let by_category = self.entries_by_category.read().await;
        let mut all_entries: Vec<_> = by_category
            .values()
            .flatten()
            .cloned()
            .collect();

        all_entries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        all_entries.truncate(limit);
        all_entries
    }

    /// 生成分类报告
    pub async fn generate_report(&self) -> AccountingReport {
        let summaries = self.get_all_summaries().await;

        let protocol_tax = summaries
            .get(&AccountingCategory::ProtocolTax)
            .cloned()
            .unwrap_or_default();
        let anchor_fee = summaries
            .get(&AccountingCategory::AnchorFee)
            .cloned()
            .unwrap_or_default();
        let system_subsidy = summaries
            .get(&AccountingCategory::SystemSubsidy)
            .cloned()
            .unwrap_or_default();

        AccountingReport {
            generated_at: Timestamp::now(),
            protocol_tax_total: protocol_tax.total_amount,
            anchor_fee_total: anchor_fee.total_amount,
            system_subsidy_total: system_subsidy.total_amount,
            total_expenses: protocol_tax.total_amount + anchor_fee.total_amount + system_subsidy.total_amount,
            protocol_tax_count: protocol_tax.entry_count,
            anchor_fee_count: anchor_fee.entry_count,
            system_subsidy_count: system_subsidy.entry_count,
        }
    }
}

impl Default for AccountingLedger {
    fn default() -> Self {
        Self::new()
    }
}

/// 会计报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountingReport {
    /// 生成时间
    pub generated_at: Timestamp,
    /// 协议税总额
    pub protocol_tax_total: u64,
    /// 锚定费总额
    pub anchor_fee_total: u64,
    /// 系统补贴总额
    pub system_subsidy_total: u64,
    /// 总支出
    pub total_expenses: u64,
    /// 协议税条目数
    pub protocol_tax_count: u64,
    /// 锚定费条目数
    pub anchor_fee_count: u64,
    /// 系统补贴条目数
    pub system_subsidy_count: u64,
}

/// 降级阻塞原因
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradationBlockReason {
    /// DSN 不可用
    DsnDown,
    /// 经济系统不可用
    EconDown,
    /// Cap预算耗尽
    AnchorCap,
}

impl std::fmt::Display for DegradationBlockReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DsnDown => write!(f, "dsn_down"),
            Self::EconDown => write!(f, "econ_down"),
            Self::AnchorCap => write!(f, "anchor_cap"),
        }
    }
}

/// Pending分类
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingCategory {
    /// 数据待处理
    Data,
    /// 执行待处理
    Execution,
    /// 预算待处理
    Budget,
    /// 版本待处理
    Version,
}

impl std::fmt::Display for PendingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Data => write!(f, "data"),
            Self::Execution => write!(f, "execution"),
            Self::Budget => write!(f, "budget"),
            Self::Version => write!(f, "version"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_record_expense() {
        let ledger = AccountingLedger::new();

        let job_id = [0x12; 32];

        ledger.record_expense(
            job_id,
            AccountingCategory::ProtocolTax,
            1000,
            "Protocol tax for epoch 1",
        ).await;

        ledger.record_expense(
            job_id,
            AccountingCategory::AnchorFee,
            500,
            "Transaction fee",
        ).await;

        assert_eq!(ledger.category_expenses(AccountingCategory::ProtocolTax).await, 1000);
        assert_eq!(ledger.category_expenses(AccountingCategory::AnchorFee).await, 500);
        assert_eq!(ledger.total_expenses().await, 1500);
    }

    #[tokio::test]
    async fn test_get_entries_by_job() {
        let ledger = AccountingLedger::new();

        let job_id = [0x34; 32];

        ledger.record_expense(job_id, AccountingCategory::ProtocolTax, 1000, "Tax 1").await;
        ledger.record_expense(job_id, AccountingCategory::AnchorFee, 500, "Fee 1").await;

        let entries = ledger.get_entries_by_job(&job_id).await;
        assert_eq!(entries.len(), 2);
    }

    #[tokio::test]
    async fn test_generate_report() {
        let ledger = AccountingLedger::new();

        let job_id1 = [0x56; 32];
        let job_id2 = [0x78; 32];

        ledger.record_expense(job_id1, AccountingCategory::ProtocolTax, 1000, "Tax 1").await;
        ledger.record_expense(job_id1, AccountingCategory::AnchorFee, 500, "Fee 1").await;
        ledger.record_expense(job_id2, AccountingCategory::SystemSubsidy, 200, "Subsidy 1").await;

        let report = ledger.generate_report().await;

        assert_eq!(report.protocol_tax_total, 1000);
        assert_eq!(report.anchor_fee_total, 500);
        assert_eq!(report.system_subsidy_total, 200);
        assert_eq!(report.total_expenses, 1700);
        assert_eq!(report.protocol_tax_count, 1);
        assert_eq!(report.anchor_fee_count, 1);
        assert_eq!(report.system_subsidy_count, 1);
    }

    #[tokio::test]
    async fn test_get_summary() {
        let ledger = AccountingLedger::new();

        let job_id = [0x9a; 32];

        ledger.record_expense(job_id, AccountingCategory::AnchorFee, 100, "Fee 1").await;
        ledger.record_expense(job_id, AccountingCategory::AnchorFee, 200, "Fee 2").await;

        let summary = ledger.get_summary(AccountingCategory::AnchorFee).await;
        assert_eq!(summary.total_amount, 300);
        assert_eq!(summary.entry_count, 2);
        assert!(summary.last_updated.is_some());
    }

    #[test]
    fn test_accounting_category_display() {
        assert_eq!(format!("{}", AccountingCategory::ProtocolTax), "protocol_tax");
        assert_eq!(format!("{}", AccountingCategory::AnchorFee), "anchor_fee");
        assert_eq!(format!("{}", AccountingCategory::SystemSubsidy), "system_subsidy");
    }
}
