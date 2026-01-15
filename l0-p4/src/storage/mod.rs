//! P4 存储层
//!
//! 提供锚定对象的持久化存储接口和实现。
//!
//! # 设计原则
//!
//! 根据文档要求：
//! - MUST级别的Input必须持久化，不可丢弃
//! - 失败不得静默，所有尝试记录必须保留
//! - 支持幂等键查询，防止重复锚定

pub mod memory;
pub mod sled;

use async_trait::async_trait;

use crate::error::P4Result;
use crate::types::{
    ChainAnchorInput, ChainAnchorJob, ChainAnchorLink, ReconcileResult,
    InputId, JobId, LinkId, ReconcileId, IdempotencyKey, AnchorPriority,
};

/// 锚定存储接口
///
/// 定义 P4 层所需的所有存储操作。
#[async_trait]
pub trait AnchorStorage: Send + Sync {
    // ==================== Input 操作 ====================

    /// 保存锚定输入
    async fn save_input(&self, input: &ChainAnchorInput) -> P4Result<()>;

    /// 获取锚定输入
    async fn get_input(&self, input_id: &InputId) -> P4Result<Option<ChainAnchorInput>>;

    /// 删除锚定输入
    async fn delete_input(&self, input_id: &InputId) -> P4Result<()>;

    /// 列出所有待处理的输入
    async fn list_pending_inputs(&self) -> P4Result<Vec<ChainAnchorInput>>;

    /// 列出指定优先级的输入
    async fn list_inputs_by_priority(&self, priority: AnchorPriority) -> P4Result<Vec<ChainAnchorInput>>;

    /// 持久化 MUST 级别的输入（用于降级恢复）
    async fn persist_must_input(&self, input: &ChainAnchorInput) -> P4Result<()>;

    /// 加载所有持久化的 MUST 输入
    async fn load_persisted_must_inputs(&self) -> P4Result<Vec<ChainAnchorInput>>;

    // ==================== Job 操作 ====================

    /// 保存锚定作业
    async fn save_job(&self, job: &ChainAnchorJob) -> P4Result<()>;

    /// 获取锚定作业
    async fn get_job(&self, job_id: &JobId) -> P4Result<Option<ChainAnchorJob>>;

    /// 根据幂等键获取作业
    async fn get_job_by_idempotency_key(&self, key: &IdempotencyKey) -> P4Result<Option<ChainAnchorJob>>;

    /// 根据输入ID获取作业
    async fn get_jobs_by_input(&self, input_id: &InputId) -> P4Result<Vec<ChainAnchorJob>>;

    /// 删除锚定作业
    async fn delete_job(&self, job_id: &JobId) -> P4Result<()>;

    /// 列出所有待处理的作业
    async fn list_pending_jobs(&self) -> P4Result<Vec<ChainAnchorJob>>;

    /// 列出需要重试的作业
    async fn list_retry_scheduled_jobs(&self) -> P4Result<Vec<ChainAnchorJob>>;

    // ==================== Link 操作 ====================

    /// 保存链锚定结果
    async fn save_link(&self, link: &ChainAnchorLink) -> P4Result<()>;

    /// 获取链锚定结果
    async fn get_link(&self, link_id: &LinkId) -> P4Result<Option<ChainAnchorLink>>;

    /// 根据输入ID获取链锚定结果
    async fn get_link_by_input(&self, input_id: &InputId) -> P4Result<Option<ChainAnchorLink>>;

    /// 根据交易ID获取链锚定结果
    async fn get_link_by_txid(&self, txid: &str) -> P4Result<Option<ChainAnchorLink>>;

    /// 删除链锚定结果
    async fn delete_link(&self, link_id: &LinkId) -> P4Result<()>;

    // ==================== Reconcile 操作 ====================

    /// 保存对账结果
    async fn save_reconcile(&self, result: &ReconcileResult) -> P4Result<()>;

    /// 获取对账结果
    async fn get_reconcile(&self, reconcile_id: &ReconcileId) -> P4Result<Option<ReconcileResult>>;

    /// 根据输入ID获取对账结果
    async fn get_reconcile_by_input(&self, input_id: &InputId) -> P4Result<Option<ReconcileResult>>;

    /// 删除对账结果
    async fn delete_reconcile(&self, reconcile_id: &ReconcileId) -> P4Result<()>;

    // ==================== 批量操作 ====================

    /// 获取统计信息
    async fn get_stats(&self) -> P4Result<StorageStats>;

    /// 清理过期数据
    async fn cleanup_expired(&self, before_timestamp: u64) -> P4Result<u64>;
}

/// 存储统计信息
#[derive(Debug, Clone, Default)]
pub struct StorageStats {
    /// 输入总数
    pub total_inputs: u64,
    /// 待处理输入数
    pub pending_inputs: u64,
    /// MUST级别输入数
    pub must_inputs: u64,
    /// 作业总数
    pub total_jobs: u64,
    /// 待处理作业数
    pub pending_jobs: u64,
    /// 待重试作业数
    pub retry_scheduled_jobs: u64,
    /// 链接总数
    pub total_links: u64,
    /// 已确认链接数
    pub confirmed_links: u64,
    /// 对账结果总数
    pub total_reconciles: u64,
    /// 成功对账数
    pub successful_reconciles: u64,
}

/// 存储配置
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// 数据目录
    pub data_dir: String,
    /// 是否启用 WAL
    pub enable_wal: bool,
    /// 缓存大小（字节）
    pub cache_size: usize,
    /// 是否启用压缩
    pub enable_compression: bool,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            data_dir: "./p4_data".to_string(),
            enable_wal: true,
            cache_size: 64 * 1024 * 1024, // 64MB
            enable_compression: true,
        }
    }
}

impl StorageConfig {
    /// 创建开发配置
    pub fn development() -> Self {
        Self {
            data_dir: "./p4_dev_data".to_string(),
            enable_wal: false,
            cache_size: 16 * 1024 * 1024, // 16MB
            enable_compression: false,
        }
    }

    /// 创建测试配置（内存存储）
    pub fn test() -> Self {
        Self {
            data_dir: "".to_string(), // 内存存储
            enable_wal: false,
            cache_size: 4 * 1024 * 1024, // 4MB
            enable_compression: false,
        }
    }
}

// 重新导出
pub use memory::MemoryStorage;
pub use self::sled::SledStorage;
