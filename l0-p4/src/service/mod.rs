//! P4 Service Layer
//!
//! 提供完整的 P4 服务层，整合所有组件。
//!
//! # 核心功能
//!
//! - 完整的 Input → Job → Link → Reconcile 流程
//! - 降级处理与自动恢复
//! - Cap 预算管理
//! - 后台任务处理
//! - 监控指标
//!
//! # 使用示例
//!
//! ```rust,ignore
//! use l0_p4::{P4Service, P4ServiceConfig};
//!
//! async fn example() {
//!     let config = P4ServiceConfig::development();
//!     let service = P4Service::new(config).await.unwrap();
//!
//!     // 提交锚定请求
//!     let input = service.submit_anchor(epoch_seq, epoch_root, priority).await?;
//!
//!     // 等待确认
//!     let link = service.wait_for_link(&input.input_id).await?;
//! }
//! ```

mod builder;
mod runner;

pub use builder::P4ServiceBuilder;
pub use runner::{BackgroundRunner, RunnerHandle};

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use crate::bitcoin::BitcoinRpcClient;
use crate::cap::{CapManager, AccountingLedger};
use crate::config::P4Config;
use crate::degradation::{DegradationHandler, DegradationSignal, RecoveryManager};
use crate::error::{P4Error, P4Result};
use crate::policy::{PolicyManager, CapConfig};
use crate::pool::AnchorPool;
use crate::storage::AnchorStorage;
use crate::tx_builder::AnchorTxBuilder;
use crate::types::{
    AnchorPriority, ChainAnchorInput, ChainAnchorJob, ChainAnchorLink,
    InputId, Timestamp,
};
use crate::verify::{
    FakeEndorsementDetector, verify_anchor_link, verify_confirmations,
    CompleteVerificationResult,
};

/// P4 服务配置
#[derive(Debug, Clone)]
pub struct P4ServiceConfig {
    /// 基础 P4 配置
    pub p4_config: P4Config,
    /// Cap 配置
    pub cap_config: CapConfig,
    /// 后台处理间隔（秒）
    pub background_interval_secs: u64,
    /// 确认检查间隔（秒）
    pub confirmation_check_interval_secs: u64,
    /// 是否启用自动恢复
    pub enable_auto_recovery: bool,
    /// 所需确认数
    pub required_confirmations: u32,
}

impl Default for P4ServiceConfig {
    fn default() -> Self {
        Self {
            p4_config: P4Config::default(),
            cap_config: CapConfig::default(),
            background_interval_secs: 60,
            confirmation_check_interval_secs: 30,
            enable_auto_recovery: true,
            required_confirmations: 6,
        }
    }
}

impl P4ServiceConfig {
    /// 开发配置
    pub fn development() -> Self {
        Self {
            p4_config: P4Config::development(),
            cap_config: CapConfig {
                daily_budget_cap: 1_000_000,     // 0.01 BTC for testing
                single_tx_budget_cap: 100_000,   // 0.001 BTC
                budget_warning_threshold: 20,
                exhaustion_strategy: crate::policy::ExhaustionStrategy::DropMay,
                budget_rollover_enabled: false,
                max_rollover_budget: 0,
            },
            background_interval_secs: 10,
            confirmation_check_interval_secs: 5,
            enable_auto_recovery: true,
            required_confirmations: 1,        // 快速确认
        }
    }

    /// 生产配置
    pub fn production() -> Self {
        Self {
            p4_config: P4Config::default(),
            cap_config: CapConfig {
                daily_budget_cap: 50_000,        // 0.0005 BTC
                single_tx_budget_cap: 5_000,     // 0.00005 BTC
                budget_warning_threshold: 20,
                exhaustion_strategy: crate::policy::ExhaustionStrategy::PauseShouldMay,
                budget_rollover_enabled: true,
                max_rollover_budget: 25_000,
            },
            background_interval_secs: 120,
            confirmation_check_interval_secs: 60,
            enable_auto_recovery: true,
            required_confirmations: 6,
        }
    }
}

/// P4 服务状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStatus {
    /// 初始化中
    Initializing,
    /// 运行中
    Running,
    /// 降级运行
    Degraded,
    /// 已暂停
    Paused,
    /// 已停止
    Stopped,
}

impl std::fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Initializing => write!(f, "INITIALIZING"),
            Self::Running => write!(f, "RUNNING"),
            Self::Degraded => write!(f, "DEGRADED"),
            Self::Paused => write!(f, "PAUSED"),
            Self::Stopped => write!(f, "STOPPED"),
        }
    }
}

/// P4 服务统计
#[derive(Debug, Clone, Default)]
pub struct ServiceStats {
    /// 服务启动时间
    pub started_at: Option<Timestamp>,
    /// 处理的输入总数
    pub total_inputs_processed: u64,
    /// 成功锚定数
    pub successful_anchors: u64,
    /// 失败锚定数
    pub failed_anchors: u64,
    /// 当前队列大小
    pub current_queue_size: usize,
    /// 当前预算使用
    pub current_budget_used: u64,
    /// 当前预算剩余
    pub current_budget_remaining: u64,
    /// 降级次数
    pub degradation_count: u64,
    /// 恢复次数
    pub recovery_count: u64,
}

/// P4 服务层
///
/// 整合所有 P4 组件，提供完整的锚定服务。
pub struct P4Service<S: AnchorStorage + 'static> {
    /// 配置
    config: P4ServiceConfig,
    /// 存储
    storage: Arc<S>,
    /// Bitcoin RPC 客户端
    bitcoin_rpc: Arc<BitcoinRpcClient>,
    /// 交易构建器
    tx_builder: Arc<AnchorTxBuilder>,
    /// 锚定池
    pool: Arc<AnchorPool<S>>,
    /// Cap 管理器
    cap_manager: Arc<CapManager>,
    /// 降级处理器
    degradation_handler: Arc<DegradationHandler<S>>,
    /// 恢复管理器
    recovery_manager: Arc<RecoveryManager>,
    /// 策略管理器
    policy_manager: Arc<PolicyManager>,
    /// 会计账本
    accounting: Arc<RwLock<AccountingLedger>>,
    /// 服务状态
    status: Arc<RwLock<ServiceStatus>>,
    /// 统计信息
    stats: Arc<RwLock<ServiceStats>>,
    /// 后台运行器句柄
    runner_handle: Arc<RwLock<Option<RunnerHandle>>>,
}

impl<S: AnchorStorage + 'static> P4Service<S> {
    /// 使用 Builder 创建服务
    pub fn builder() -> P4ServiceBuilder<S> {
        P4ServiceBuilder::new()
    }

    /// 获取服务状态
    pub async fn status(&self) -> ServiceStatus {
        *self.status.read().await
    }

    /// 获取服务统计
    pub async fn stats(&self) -> ServiceStats {
        let mut stats = self.stats.read().await.clone();

        // 更新实时数据
        let pool_stats = self.pool.stats().await;
        stats.current_queue_size = pool_stats.must_size
            + pool_stats.should_size
            + pool_stats.may_size;

        let cap_stats = self.cap_manager.get_stats().await;
        stats.current_budget_used = cap_stats.total_spent_amount;
        stats.current_budget_remaining = cap_stats.total_reserved_amount;

        stats
    }

    /// 提交锚定请求
    ///
    /// 创建 ChainAnchorInput 并加入处理队列。
    pub async fn submit_anchor(
        &self,
        epoch_sequence: u64,
        epoch_root: [u8; 32],
        linked_receipt_ids_digest: [u8; 32],
        priority: AnchorPriority,
    ) -> P4Result<ChainAnchorInput> {
        // 检查服务状态
        let status = self.status().await;
        if status == ServiceStatus::Stopped {
            return Err(P4Error::InvalidInput("Service is stopped".to_string()));
        }

        // 创建 Input
        let input = ChainAnchorInput::new(
            epoch_sequence,
            epoch_root,
            linked_receipt_ids_digest,
            priority,
        );

        // 验证 Input
        let validation = input.validate_completeness();
        if !validation.is_valid {
            return Err(P4Error::InvalidInput(format!(
                "Input validation failed: {:?}",
                validation.errors
            )));
        }

        // 保存到存储
        self.storage.save_input(&input).await?;

        // 加入队列
        self.pool.enqueue(input.clone()).await?;

        // 更新统计
        {
            let mut stats = self.stats.write().await;
            stats.total_inputs_processed += 1;
        }

        info!(
            "Submitted anchor request: epoch={}, priority={:?}, input_id={}",
            epoch_sequence,
            priority,
            hex::encode(&input.input_id[..8])
        );

        Ok(input)
    }

    /// 获取 Input 状态
    pub async fn get_input(&self, input_id: &InputId) -> P4Result<Option<ChainAnchorInput>> {
        self.storage.get_input(input_id).await
    }

    /// 获取 Job 列表
    pub async fn get_jobs_by_input(&self, input_id: &InputId) -> P4Result<Vec<ChainAnchorJob>> {
        self.storage.get_jobs_by_input(input_id).await
    }

    /// 获取 Link
    pub async fn get_link_by_input(&self, input_id: &InputId) -> P4Result<Option<ChainAnchorLink>> {
        self.storage.get_link_by_input(input_id).await
    }

    /// 验证 Link
    pub async fn verify_link(
        &self,
        input_id: &InputId,
    ) -> P4Result<Option<CompleteVerificationResult>> {
        let input = self.storage.get_input(input_id).await?;
        let link = self.storage.get_link_by_input(input_id).await?;

        match (input, link) {
            (Some(input), Some(link)) => {
                let link_result = verify_anchor_link(&link, &input)?;
                let confirmation_result = verify_confirmations(&link, self.config.required_confirmations);

                let detector = FakeEndorsementDetector::new(
                    self.storage.clone(),
                    self.config.required_confirmations,
                );
                let fake_endorsement = detector.detect(input_id).await?;

                let is_fully_valid = link_result.is_valid()
                    && confirmation_result.is_sufficient
                    && fake_endorsement.is_none();

                Ok(Some(CompleteVerificationResult {
                    link_verification: link_result,
                    confirmation_verification: confirmation_result,
                    fake_endorsement,
                    is_fully_valid,
                }))
            }
            _ => Ok(None),
        }
    }

    /// 处理降级信号
    pub async fn handle_degradation(&self, signal: DegradationSignal, reason: &str) -> P4Result<()> {
        info!("Handling degradation signal: {:?}, reason: {}", signal, reason);

        self.degradation_handler.handle_signal(signal, reason).await?;

        // 更新服务状态
        {
            let mut status = self.status.write().await;
            *status = ServiceStatus::Degraded;
        }

        // 更新统计
        {
            let mut stats = self.stats.write().await;
            stats.degradation_count += 1;
        }

        Ok(())
    }

    /// 恢复降级
    pub async fn recover_degradation(&self, signal: DegradationSignal, reason: &str) -> P4Result<()> {
        info!("Recovering from degradation: {:?}, reason: {}", signal, reason);

        self.degradation_handler.recover_signal(signal, reason).await?;

        // 检查是否完全恢复
        let summary = self.degradation_handler.get_summary().await;
        if summary.active_signals.is_empty() {
            let mut status = self.status.write().await;
            *status = ServiceStatus::Running;
        }

        // 更新统计
        {
            let mut stats = self.stats.write().await;
            stats.recovery_count += 1;
        }

        Ok(())
    }

    /// 获取降级状态摘要
    pub async fn get_degradation_summary(&self) -> crate::degradation::DegradationSummary {
        self.degradation_handler.get_summary().await
    }

    /// 获取 Cap 管理器统计
    pub async fn get_cap_stats(&self) -> crate::cap::CapManagerStats {
        self.cap_manager.get_stats().await
    }

    /// 获取会计报告
    pub async fn get_accounting_report(&self) -> crate::cap::AccountingReport {
        self.accounting.read().await.generate_report().await
    }

    /// 启动后台服务
    pub async fn start(&self) -> P4Result<()> {
        info!("Starting P4 service...");

        {
            let mut status = self.status.write().await;
            *status = ServiceStatus::Running;
        }

        {
            let mut stats = self.stats.write().await;
            stats.started_at = Some(Timestamp::now());
        }

        // 启动后台运行器
        let runner = BackgroundRunner::new(
            self.storage.clone(),
            self.pool.clone(),
            self.cap_manager.clone(),
            self.degradation_handler.clone(),
            self.recovery_manager.clone(),
            self.bitcoin_rpc.clone(),
            self.tx_builder.clone(),
            self.config.p4_config.clone(),
            self.config.clone(),
        );

        let handle = runner.start().await;

        {
            let mut runner_handle = self.runner_handle.write().await;
            *runner_handle = Some(handle);
        }

        info!("P4 service started");
        Ok(())
    }

    /// 停止服务
    pub async fn stop(&self) -> P4Result<()> {
        info!("Stopping P4 service...");

        // 停止后台运行器
        {
            let mut runner_handle = self.runner_handle.write().await;
            if let Some(handle) = runner_handle.take() {
                handle.stop().await;
            }
        }

        {
            let mut status = self.status.write().await;
            *status = ServiceStatus::Stopped;
        }

        info!("P4 service stopped");
        Ok(())
    }

    /// 暂停服务
    pub async fn pause(&self) -> P4Result<()> {
        info!("Pausing P4 service...");

        {
            let mut status = self.status.write().await;
            *status = ServiceStatus::Paused;
        }

        Ok(())
    }

    /// 恢复服务
    pub async fn resume(&self) -> P4Result<()> {
        info!("Resuming P4 service...");

        let degradation_summary = self.degradation_handler.get_summary().await;

        {
            let mut status = self.status.write().await;
            *status = if degradation_summary.active_signals.is_empty() {
                ServiceStatus::Running
            } else {
                ServiceStatus::Degraded
            };
        }

        Ok(())
    }

    /// 获取配置
    pub fn config(&self) -> &P4ServiceConfig {
        &self.config
    }

    /// 获取存储
    pub fn storage(&self) -> &Arc<S> {
        &self.storage
    }

    /// 获取 Bitcoin RPC 客户端
    pub fn bitcoin_rpc(&self) -> &Arc<BitcoinRpcClient> {
        &self.bitcoin_rpc
    }

    /// 获取锚定池
    pub fn pool(&self) -> &Arc<AnchorPool<S>> {
        &self.pool
    }

    /// 获取 Cap 管理器
    pub fn cap_manager(&self) -> &Arc<CapManager> {
        &self.cap_manager
    }

    /// 获取降级处理器
    pub fn degradation_handler(&self) -> &Arc<DegradationHandler<S>> {
        &self.degradation_handler
    }

    /// 获取策略管理器
    pub fn policy_manager(&self) -> &Arc<PolicyManager> {
        &self.policy_manager
    }

    // ========== 批量操作 API ==========

    /// 批量提交锚定请求
    ///
    /// 提交多个锚定请求，返回成功提交的 Input 列表和错误列表。
    pub async fn submit_anchor_batch(
        &self,
        requests: Vec<BatchAnchorRequest>,
    ) -> BatchSubmitResult {
        let mut successful = Vec::new();
        let mut failed = Vec::new();

        for request in requests {
            match self.submit_anchor(
                request.epoch_sequence,
                request.epoch_root,
                request.linked_receipt_ids_digest,
                request.priority,
            ).await {
                Ok(input) => {
                    successful.push(BatchSubmitSuccess {
                        epoch_sequence: request.epoch_sequence,
                        input_id: input.input_id,
                    });
                }
                Err(e) => {
                    failed.push(BatchSubmitFailure {
                        epoch_sequence: request.epoch_sequence,
                        error: e.to_string(),
                    });
                }
            }
        }

        BatchSubmitResult {
            total_requested: successful.len() + failed.len(),
            successful_count: successful.len(),
            failed_count: failed.len(),
            successful,
            failed,
        }
    }

    /// 批量获取 Input
    pub async fn get_inputs_batch(
        &self,
        input_ids: &[InputId],
    ) -> P4Result<Vec<(InputId, Option<ChainAnchorInput>)>> {
        let mut results = Vec::with_capacity(input_ids.len());

        for input_id in input_ids {
            let input = self.storage.get_input(input_id).await?;
            results.push((*input_id, input));
        }

        Ok(results)
    }

    /// 批量获取 Link
    pub async fn get_links_batch(
        &self,
        input_ids: &[InputId],
    ) -> P4Result<Vec<(InputId, Option<ChainAnchorLink>)>> {
        let mut results = Vec::with_capacity(input_ids.len());

        for input_id in input_ids {
            let link = self.storage.get_link_by_input(input_id).await?;
            results.push((*input_id, link));
        }

        Ok(results)
    }

    /// 批量验证 Link
    pub async fn verify_links_batch(
        &self,
        input_ids: &[InputId],
    ) -> BatchVerifyResult {
        let mut results = Vec::new();
        let mut verified_count = 0;
        let mut failed_count = 0;

        for input_id in input_ids {
            match self.verify_link(input_id).await {
                Ok(Some(result)) => {
                    if result.is_fully_valid {
                        verified_count += 1;
                    } else {
                        failed_count += 1;
                    }
                    results.push(BatchVerifyItem {
                        input_id: *input_id,
                        result: Some(result),
                        error: None,
                    });
                }
                Ok(None) => {
                    results.push(BatchVerifyItem {
                        input_id: *input_id,
                        result: None,
                        error: Some("Input or Link not found".to_string()),
                    });
                }
                Err(e) => {
                    failed_count += 1;
                    results.push(BatchVerifyItem {
                        input_id: *input_id,
                        result: None,
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        BatchVerifyResult {
            total_checked: input_ids.len(),
            verified_count,
            failed_count,
            not_found_count: input_ids.len() - verified_count - failed_count,
            results,
        }
    }

    /// 批量查询状态
    pub async fn get_status_batch(
        &self,
        input_ids: &[InputId],
    ) -> P4Result<Vec<BatchStatusItem>> {
        let mut results = Vec::with_capacity(input_ids.len());

        for input_id in input_ids {
            let input = self.storage.get_input(input_id).await?;
            let jobs = self.storage.get_jobs_by_input(input_id).await?;
            let link = self.storage.get_link_by_input(input_id).await?;

            let status = if let Some(ref l) = link {
                if l.confirmations >= self.config.required_confirmations {
                    AnchorStatus::Confirmed
                } else {
                    AnchorStatus::Submitted
                }
            } else if !jobs.is_empty() {
                AnchorStatus::Processing
            } else if input.is_some() {
                AnchorStatus::Queued
            } else {
                AnchorStatus::NotFound
            };

            results.push(BatchStatusItem {
                input_id: *input_id,
                status,
                input,
                latest_job: jobs.into_iter().max_by_key(|j| j.created_at.as_millis()),
                link,
            });
        }

        Ok(results)
    }
}

/// 批量锚定请求
#[derive(Debug, Clone)]
pub struct BatchAnchorRequest {
    /// Epoch 序列号
    pub epoch_sequence: u64,
    /// Epoch 根
    pub epoch_root: [u8; 32],
    /// 关联收据 ID 摘要
    pub linked_receipt_ids_digest: [u8; 32],
    /// 优先级
    pub priority: AnchorPriority,
}

/// 批量提交结果
#[derive(Debug, Clone)]
pub struct BatchSubmitResult {
    /// 请求总数
    pub total_requested: usize,
    /// 成功数
    pub successful_count: usize,
    /// 失败数
    pub failed_count: usize,
    /// 成功列表
    pub successful: Vec<BatchSubmitSuccess>,
    /// 失败列表
    pub failed: Vec<BatchSubmitFailure>,
}

/// 批量提交成功项
#[derive(Debug, Clone)]
pub struct BatchSubmitSuccess {
    /// Epoch 序列号
    pub epoch_sequence: u64,
    /// 生成的 Input ID
    pub input_id: InputId,
}

/// 批量提交失败项
#[derive(Debug, Clone)]
pub struct BatchSubmitFailure {
    /// Epoch 序列号
    pub epoch_sequence: u64,
    /// 错误信息
    pub error: String,
}

/// 批量验证结果
#[derive(Debug, Clone)]
pub struct BatchVerifyResult {
    /// 检查总数
    pub total_checked: usize,
    /// 验证通过数
    pub verified_count: usize,
    /// 验证失败数
    pub failed_count: usize,
    /// 未找到数
    pub not_found_count: usize,
    /// 详细结果
    pub results: Vec<BatchVerifyItem>,
}

/// 批量验证项
#[derive(Debug, Clone)]
pub struct BatchVerifyItem {
    /// Input ID
    pub input_id: InputId,
    /// 验证结果
    pub result: Option<CompleteVerificationResult>,
    /// 错误信息
    pub error: Option<String>,
}

/// 锚定状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorStatus {
    /// 未找到
    NotFound,
    /// 已入队
    Queued,
    /// 处理中
    Processing,
    /// 已提交（等待确认）
    Submitted,
    /// 已确认
    Confirmed,
}

impl std::fmt::Display for AnchorStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "NOT_FOUND"),
            Self::Queued => write!(f, "QUEUED"),
            Self::Processing => write!(f, "PROCESSING"),
            Self::Submitted => write!(f, "SUBMITTED"),
            Self::Confirmed => write!(f, "CONFIRMED"),
        }
    }
}

/// 批量状态项
#[derive(Debug, Clone)]
pub struct BatchStatusItem {
    /// Input ID
    pub input_id: InputId,
    /// 当前状态
    pub status: AnchorStatus,
    /// Input（如存在）
    pub input: Option<ChainAnchorInput>,
    /// 最新 Job（如存在）
    pub latest_job: Option<ChainAnchorJob>,
    /// Link（如存在）
    pub link: Option<ChainAnchorLink>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;

    #[test]
    fn test_service_config_default() {
        let config = P4ServiceConfig::default();
        assert_eq!(config.required_confirmations, 6);
        assert!(config.enable_auto_recovery);
    }

    #[test]
    fn test_service_config_development() {
        let config = P4ServiceConfig::development();
        assert_eq!(config.required_confirmations, 1);
        assert_eq!(config.background_interval_secs, 10);
    }

    #[test]
    fn test_service_config_production() {
        let config = P4ServiceConfig::production();
        assert_eq!(config.required_confirmations, 6);
        assert_eq!(config.background_interval_secs, 120);
        assert!(config.cap_config.budget_rollover_enabled);
    }

    #[test]
    fn test_service_status_display() {
        assert_eq!(format!("{}", ServiceStatus::Running), "RUNNING");
        assert_eq!(format!("{}", ServiceStatus::Degraded), "DEGRADED");
        assert_eq!(format!("{}", ServiceStatus::Paused), "PAUSED");
        assert_eq!(format!("{}", ServiceStatus::Stopped), "STOPPED");
        assert_eq!(format!("{}", ServiceStatus::Initializing), "INITIALIZING");
    }

    #[test]
    fn test_anchor_status_display() {
        assert_eq!(format!("{}", AnchorStatus::NotFound), "NOT_FOUND");
        assert_eq!(format!("{}", AnchorStatus::Queued), "QUEUED");
        assert_eq!(format!("{}", AnchorStatus::Processing), "PROCESSING");
        assert_eq!(format!("{}", AnchorStatus::Submitted), "SUBMITTED");
        assert_eq!(format!("{}", AnchorStatus::Confirmed), "CONFIRMED");
    }

    #[test]
    fn test_batch_anchor_request() {
        let request = BatchAnchorRequest {
            epoch_sequence: 100,
            epoch_root: [0x12; 32],
            linked_receipt_ids_digest: [0x34; 32],
            priority: AnchorPriority::Must,
        };
        assert_eq!(request.epoch_sequence, 100);
        assert_eq!(request.priority, AnchorPriority::Must);
    }

    #[test]
    fn test_batch_submit_result() {
        let result = BatchSubmitResult {
            total_requested: 5,
            successful_count: 3,
            failed_count: 2,
            successful: vec![
                BatchSubmitSuccess {
                    epoch_sequence: 1,
                    input_id: [0x01; 32],
                },
                BatchSubmitSuccess {
                    epoch_sequence: 2,
                    input_id: [0x02; 32],
                },
                BatchSubmitSuccess {
                    epoch_sequence: 3,
                    input_id: [0x03; 32],
                },
            ],
            failed: vec![
                BatchSubmitFailure {
                    epoch_sequence: 4,
                    error: "Test error 1".to_string(),
                },
                BatchSubmitFailure {
                    epoch_sequence: 5,
                    error: "Test error 2".to_string(),
                },
            ],
        };

        assert_eq!(result.total_requested, 5);
        assert_eq!(result.successful_count, 3);
        assert_eq!(result.failed_count, 2);
        assert_eq!(result.successful.len(), 3);
        assert_eq!(result.failed.len(), 2);
    }

    #[test]
    fn test_batch_verify_result() {
        let result = BatchVerifyResult {
            total_checked: 10,
            verified_count: 7,
            failed_count: 2,
            not_found_count: 1,
            results: vec![],
        };

        assert_eq!(result.total_checked, 10);
        assert_eq!(result.verified_count, 7);
        assert_eq!(result.failed_count, 2);
        assert_eq!(result.not_found_count, 1);
    }

    #[tokio::test]
    async fn test_service_build_and_status() {
        let storage = Arc::new(MemoryStorage::new());
        let service = P4ServiceBuilder::new()
            .config(P4ServiceConfig::development())
            .storage(storage)
            .build()
            .await
            .expect("Service build should succeed");

        // Initial status should be Initializing
        assert_eq!(service.status().await, ServiceStatus::Initializing);
    }

    #[tokio::test]
    async fn test_service_submit_anchor() {
        let storage = Arc::new(MemoryStorage::new());
        let service = P4ServiceBuilder::new()
            .config(P4ServiceConfig::development())
            .storage(storage)
            .build()
            .await
            .unwrap();

        // Submit an anchor request
        let result = service.submit_anchor(
            1,
            [0x12; 32],
            [0x34; 32],
            AnchorPriority::Must,
        ).await;

        assert!(result.is_ok());
        let input = result.unwrap();
        assert_eq!(input.epoch_sequence, 1);
        assert_eq!(input.epoch_root, [0x12; 32]);
        assert_eq!(input.priority, AnchorPriority::Must);

        // Verify the input is stored
        let retrieved = service.get_input(&input.input_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().epoch_sequence, 1);
    }

    #[tokio::test]
    async fn test_service_batch_submit() {
        let storage = Arc::new(MemoryStorage::new());
        let service = P4ServiceBuilder::new()
            .config(P4ServiceConfig::development())
            .storage(storage)
            .build()
            .await
            .unwrap();

        // Create batch requests
        let requests = vec![
            BatchAnchorRequest {
                epoch_sequence: 1,
                epoch_root: [0x01; 32],
                linked_receipt_ids_digest: [0x11; 32],
                priority: AnchorPriority::Must,
            },
            BatchAnchorRequest {
                epoch_sequence: 2,
                epoch_root: [0x02; 32],
                linked_receipt_ids_digest: [0x22; 32],
                priority: AnchorPriority::Should,
            },
            BatchAnchorRequest {
                epoch_sequence: 3,
                epoch_root: [0x03; 32],
                linked_receipt_ids_digest: [0x33; 32],
                priority: AnchorPriority::May,
            },
        ];

        let result = service.submit_anchor_batch(requests).await;

        assert_eq!(result.total_requested, 3);
        assert_eq!(result.successful_count, 3);
        assert_eq!(result.failed_count, 0);

        // Verify all inputs are stored
        for success in &result.successful {
            let input = service.get_input(&success.input_id).await.unwrap();
            assert!(input.is_some());
        }
    }

    #[tokio::test]
    async fn test_service_batch_get_inputs() {
        let storage = Arc::new(MemoryStorage::new());
        let service = P4ServiceBuilder::new()
            .config(P4ServiceConfig::development())
            .storage(storage)
            .build()
            .await
            .unwrap();

        // Submit some inputs
        let input1 = service.submit_anchor(1, [0x01; 32], [0x11; 32], AnchorPriority::Must).await.unwrap();
        let input2 = service.submit_anchor(2, [0x02; 32], [0x22; 32], AnchorPriority::Should).await.unwrap();

        // Batch get
        let results = service.get_inputs_batch(&[input1.input_id, input2.input_id, [0xFF; 32]]).await.unwrap();

        assert_eq!(results.len(), 3);
        assert!(results[0].1.is_some()); // Found
        assert!(results[1].1.is_some()); // Found
        assert!(results[2].1.is_none()); // Not found
    }

    #[tokio::test]
    async fn test_service_batch_status() {
        let storage = Arc::new(MemoryStorage::new());
        let service = P4ServiceBuilder::new()
            .config(P4ServiceConfig::development())
            .storage(storage)
            .build()
            .await
            .unwrap();

        // Submit an input
        let input = service.submit_anchor(1, [0x01; 32], [0x11; 32], AnchorPriority::Must).await.unwrap();

        // Check batch status
        let results = service.get_status_batch(&[input.input_id, [0xFF; 32]]).await.unwrap();

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].status, AnchorStatus::Queued);
        assert!(results[0].input.is_some());
        assert_eq!(results[1].status, AnchorStatus::NotFound);
        assert!(results[1].input.is_none());
    }

    #[tokio::test]
    async fn test_service_stats() {
        let storage = Arc::new(MemoryStorage::new());
        let service = P4ServiceBuilder::new()
            .config(P4ServiceConfig::development())
            .storage(storage)
            .build()
            .await
            .unwrap();

        // Get initial stats
        let initial_stats = service.stats().await;
        assert_eq!(initial_stats.total_inputs_processed, 0);

        // Submit some inputs
        service.submit_anchor(1, [0x01; 32], [0x11; 32], AnchorPriority::Must).await.unwrap();
        service.submit_anchor(2, [0x02; 32], [0x22; 32], AnchorPriority::Should).await.unwrap();

        // Check updated stats
        let updated_stats = service.stats().await;
        assert_eq!(updated_stats.total_inputs_processed, 2);
    }

    #[tokio::test]
    async fn test_service_pause_resume() {
        let storage = Arc::new(MemoryStorage::new());
        let service = P4ServiceBuilder::new()
            .config(P4ServiceConfig::development())
            .storage(storage)
            .build()
            .await
            .unwrap();

        // Start the service
        service.start().await.unwrap();
        assert_eq!(service.status().await, ServiceStatus::Running);

        // Pause
        service.pause().await.unwrap();
        assert_eq!(service.status().await, ServiceStatus::Paused);

        // Resume
        service.resume().await.unwrap();
        assert_eq!(service.status().await, ServiceStatus::Running);

        // Stop
        service.stop().await.unwrap();
        assert_eq!(service.status().await, ServiceStatus::Stopped);
    }

    #[tokio::test]
    async fn test_service_cap_stats() {
        let storage = Arc::new(MemoryStorage::new());
        let service = P4ServiceBuilder::new()
            .config(P4ServiceConfig::development())
            .storage(storage)
            .build()
            .await
            .unwrap();

        let cap_stats = service.get_cap_stats().await;
        // Just verify we can get stats without error
        assert!(cap_stats.total_spent_amount >= 0);
    }

    #[tokio::test]
    async fn test_service_degradation_summary() {
        let storage = Arc::new(MemoryStorage::new());
        let service = P4ServiceBuilder::new()
            .config(P4ServiceConfig::development())
            .storage(storage)
            .build()
            .await
            .unwrap();

        let summary = service.get_degradation_summary().await;
        // Initially no active degradations
        assert!(!summary.is_degraded);
        assert!(summary.active_signals.is_empty());
    }
}
