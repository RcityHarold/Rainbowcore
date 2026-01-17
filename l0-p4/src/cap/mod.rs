//! Cap治理模块
//!
//! 管理锚定预算和会计分类。
//!
//! # 核心组件
//!
//! - `CapManager`: 预算管理器
//! - `AccountingLedger`: 会计账本
//! - `AccountingCategory`: 会计分类（不混税三列）
//!
//! # 设计原则
//!
//! - MUST队列不丢弃：cap不足只能 pending，不得静默
//! - 预算预留与确认分离
//! - 不同会计分类不混合

pub mod manager;
pub mod accounting;

pub use manager::{
    CapManager,
    CapManagerStats,
    BudgetSpendEntry,
    BudgetSpendStatus,
};

pub use accounting::{
    AccountingCategory,
    AccountingEntry,
    AccountingLedger,
    AccountingReport,
    CategorySummary,
    DegradationBlockReason,
    PendingCategory,
};
