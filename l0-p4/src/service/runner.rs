//! P4 Background Runner
//!
//! 后台任务处理器，负责：
//! - 定期处理队列中的锚定请求
//! - 检查确认状态
//! - 执行自动恢复
//! - 清理过期数据

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tokio::time::interval;
use tracing::{debug, info, warn, error};

use crate::bitcoin::BitcoinRpcClient;
use crate::cap::CapManager;
use crate::degradation::{DegradationHandler, DegradationSignal, RecoveryManager};
use crate::error::{P4Error, P4Result};
use crate::ops::AnchorOps;
use crate::pool::AnchorPool;
use crate::storage::AnchorStorage;
use crate::tx_builder::AnchorTxBuilder;
use crate::types::{AnchorPriority, ChainAnchorInput, JobStatus, InputStatus};
use crate::P4Config;

use super::P4ServiceConfig;

/// 后台运行器
pub struct BackgroundRunner<S: AnchorStorage + 'static> {
    storage: Arc<S>,
    pool: Arc<AnchorPool<S>>,
    cap_manager: Arc<CapManager>,
    degradation_handler: Arc<DegradationHandler<S>>,
    recovery_manager: Arc<RecoveryManager>,
    bitcoin_rpc: Arc<BitcoinRpcClient>,
    tx_builder: Arc<AnchorTxBuilder>,
    p4_config: P4Config,
    config: P4ServiceConfig,
}

impl<S: AnchorStorage + 'static> BackgroundRunner<S> {
    /// 创建新的后台运行器
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        storage: Arc<S>,
        pool: Arc<AnchorPool<S>>,
        cap_manager: Arc<CapManager>,
        degradation_handler: Arc<DegradationHandler<S>>,
        recovery_manager: Arc<RecoveryManager>,
        bitcoin_rpc: Arc<BitcoinRpcClient>,
        tx_builder: Arc<AnchorTxBuilder>,
        p4_config: P4Config,
        config: P4ServiceConfig,
    ) -> Self {
        Self {
            storage,
            pool,
            cap_manager,
            degradation_handler,
            recovery_manager,
            bitcoin_rpc,
            tx_builder,
            p4_config,
            config,
        }
    }

    /// 启动后台运行器
    pub async fn start(self) -> RunnerHandle {
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        let running = Arc::new(RwLock::new(true));
        let running_clone = running.clone();

        let background_interval = Duration::from_secs(self.config.background_interval_secs);
        let confirmation_interval = Duration::from_secs(self.config.confirmation_check_interval_secs);
        let required_confirmations = self.config.required_confirmations;

        // 启动主处理任务
        let storage = self.storage.clone();
        let pool = self.pool.clone();
        let cap_manager = self.cap_manager.clone();
        let degradation_handler = self.degradation_handler.clone();
        let recovery_manager = self.recovery_manager.clone();
        let bitcoin_rpc = self.bitcoin_rpc.clone();
        let tx_builder = self.tx_builder.clone();
        let p4_config = self.p4_config.clone();
        let enable_auto_recovery = self.config.enable_auto_recovery;

        tokio::spawn(async move {
            let mut background_timer = interval(background_interval);
            let mut confirmation_timer = interval(confirmation_interval);

            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        info!("Background runner received shutdown signal");
                        break;
                    }
                    _ = background_timer.tick() => {
                        if *running_clone.read().await {
                            if let Err(e) = Self::process_queue(
                                &storage,
                                &pool,
                                &cap_manager,
                                &degradation_handler,
                                &bitcoin_rpc,
                                &tx_builder,
                                &p4_config,
                            ).await {
                                error!("Error processing queue: {}", e);
                            }
                        }
                    }
                    _ = confirmation_timer.tick() => {
                        if *running_clone.read().await {
                            if let Err(e) = Self::check_confirmations(
                                &storage,
                                &bitcoin_rpc,
                                required_confirmations,
                            ).await {
                                error!("Error checking confirmations: {}", e);
                            }

                            if enable_auto_recovery {
                                if let Err(e) = Self::run_auto_recovery(
                                    &degradation_handler,
                                    &recovery_manager,
                                    &bitcoin_rpc,
                                ).await {
                                    error!("Error running auto recovery: {}", e);
                                }
                            }
                        }
                    }
                }
            }

            info!("Background runner stopped");
        });

        RunnerHandle {
            shutdown_tx,
            running,
        }
    }

    /// 处理队列
    async fn process_queue(
        storage: &Arc<S>,
        pool: &Arc<AnchorPool<S>>,
        cap_manager: &Arc<CapManager>,
        degradation_handler: &Arc<DegradationHandler<S>>,
        bitcoin_rpc: &Arc<BitcoinRpcClient>,
        tx_builder: &Arc<AnchorTxBuilder>,
        p4_config: &P4Config,
    ) -> P4Result<()> {
        debug!("Processing anchor queue...");

        // 获取降级状态
        let summary = degradation_handler.get_summary().await;

        // 根据降级状态决定处理哪些优先级
        let priorities = if summary.active_signals.is_empty() {
            vec![AnchorPriority::Must, AnchorPriority::Should, AnchorPriority::May]
        } else {
            // 降级模式下只处理 MUST
            vec![AnchorPriority::Must]
        };

        // 创建 AnchorOps 执行器
        let anchor_ops = AnchorOps::new(
            bitcoin_rpc.clone(),
            tx_builder.clone(),
            storage.clone(),
            p4_config.clone(),
        );

        for priority in priorities {
            // 检查 Cap 是否允许
            let can_process = degradation_handler.can_process(priority).await;
            if !can_process {
                debug!("Cannot process {:?} due to degradation", priority);
                continue;
            }

            // 尝试从队列获取项目（dequeue 按优先级自动选择）
            if let Some(item) = pool.dequeue().await {
                let input_id_hex = hex::encode(&item.input_id[..8]);
                debug!(
                    "Dequeued item: input_id={}, priority={:?}",
                    input_id_hex,
                    priority
                );

                // 从存储获取完整的 Input
                let input = match storage.get_input(&item.input_id).await {
                    Ok(Some(input)) => input,
                    Ok(None) => {
                        warn!("Input not found for queued item: {}", input_id_hex);
                        continue;
                    }
                    Err(e) => {
                        error!("Failed to get input {}: {}", input_id_hex, e);
                        continue;
                    }
                };

                // 执行完整的锚定闭环
                match Self::execute_anchor_cycle(&anchor_ops, input, cap_manager).await {
                    Ok(()) => {
                        info!("Successfully anchored input: {}", input_id_hex);
                    }
                    Err(e) => {
                        error!("Failed to anchor input {}: {}", input_id_hex, e);
                        // 根据优先级决定是否重新入队
                        if priority == AnchorPriority::Must {
                            // MUST 级别重新入队等待下次处理
                            warn!("Re-queuing MUST priority input: {}", input_id_hex);
                            // 更新 Input 状态为 Pending 等待重试
                            if let Ok(Some(mut input)) = storage.get_input(&item.input_id).await {
                                input.status = InputStatus::Pending;
                                let _ = storage.save_input(&input).await;
                                // 重新加入队列
                                let _ = pool.enqueue(input).await;
                            }
                        }
                    }
                }
            }
        }

        // 清理过期项目
        let expired = pool.cleanup_expired().await;
        let total_expired = expired.must_expired + expired.should_expired + expired.may_expired;
        if total_expired > 0 {
            info!(
                "Cleaned up {} expired items (must: {}, should: {}, may: {})",
                total_expired,
                expired.must_expired,
                expired.should_expired,
                expired.may_expired
            );
        }

        Ok(())
    }

    /// 执行锚定闭环
    async fn execute_anchor_cycle(
        anchor_ops: &AnchorOps<S>,
        input: ChainAnchorInput,
        cap_manager: &Arc<CapManager>,
    ) -> P4Result<()> {
        use crate::cap::AccountingCategory;

        let input_id_hex = hex::encode(&input.input_id[..8]);
        let priority = input.priority;

        // 1. Quote - 估算费用
        info!("Starting anchor cycle for input: {}", input_id_hex);
        let quote = anchor_ops.quote(&input).await?;
        debug!("Quote result: estimated_fee={} sat", quote.estimated_fee);

        // 2. 创建 Job（需要先创建以获取 job_id）
        let mut job = anchor_ops.create_job(&input, &quote).await?;
        let job_id = job.job_id;
        debug!("Job created: job_id={}", hex::encode(&job_id[..8]));

        // 3. 预留预算
        let _reservation = cap_manager.reserve(
            quote.estimated_fee,
            job_id,
            priority,
            AccountingCategory::AnchorFee,
        ).await?;
        debug!("Budget reserved: job_id={}, amount={}", hex::encode(&job_id[..8]), quote.estimated_fee);

        // 4. Submit - 提交交易
        match anchor_ops.submit(&mut job, &input).await {
            Ok(submit_result) => {
                info!(
                    "Transaction submitted: job_id={}, txid={}",
                    hex::encode(&job_id[..8]),
                    submit_result.txid
                );

                // 5. 确认预算使用
                cap_manager.confirm(&job_id, quote.estimated_fee).await?;

                // 保存 Job 状态
                anchor_ops.storage().save_job(&job).await?;
            }
            Err(e) => {
                // 释放预算
                let _ = cap_manager.release(&job_id).await;
                return Err(e);
            }
        }

        Ok(())
    }

    /// 检查确认状态
    async fn check_confirmations(
        storage: &Arc<S>,
        bitcoin_rpc: &Arc<BitcoinRpcClient>,
        required_confirmations: u32,
    ) -> P4Result<()> {
        debug!("Checking confirmation status...");

        // 获取待处理的 Jobs
        let pending_jobs = storage.list_pending_jobs().await?;

        for mut job in pending_jobs {
            if job.status == JobStatus::Submitted {
                let job_id_hex = hex::encode(&job.job_id[..8]);

                // 检查是否有 txid
                let txid = match &job.txid {
                    Some(txid) => txid.clone(),
                    None => {
                        warn!("Job {} has no txid", job_id_hex);
                        continue;
                    }
                };

                // 查询交易确认状态
                match bitcoin_rpc.get_transaction_confirmations(&txid).await {
                    Ok(confirmations) => {
                        debug!(
                            "Job {} txid={} has {} confirmations",
                            job_id_hex, txid, confirmations
                        );

                        // 更新 Job 的确认数
                        job.confirmations = confirmations;

                        if confirmations >= required_confirmations {
                            // 交易已确认
                            info!(
                                "Job {} confirmed with {} confirmations",
                                job_id_hex, confirmations
                            );
                            job.status = JobStatus::Confirmed;

                            // 获取区块信息并创建 Link
                            let mut block_hash = None;
                            let mut block_height = None;
                            if let Ok(tx_info) = bitcoin_rpc.get_transaction_info(&txid).await {
                                if let Some(hash) = tx_info.blockhash {
                                    block_hash = Some(hash.clone());
                                    if let Ok(block_info) = bitcoin_rpc.get_block(&hash).await {
                                        block_height = Some(block_info.height);
                                    }
                                }
                            }

                            // 创建 Link
                            if let Err(e) = Self::create_link_for_job(
                                storage,
                                &job,
                                confirmations,
                                block_hash,
                                block_height,
                            ).await {
                                error!("Failed to create link for job {}: {}", job_id_hex, e);
                            }
                        }

                        // 保存更新后的 Job
                        storage.save_job(&job).await?;
                    }
                    Err(P4Error::TransactionNotFound(_)) => {
                        // 交易未找到，可能被替换或丢弃
                        warn!("Transaction {} not found for job {}", txid, job_id_hex);
                        job.status = JobStatus::Failed;
                        // 记录失败尝试
                        job.attempt_chain.add_attempt(crate::types::AttemptRecord::failure(
                            job.attempt_chain.attempt_count() + 1,
                            crate::types::AnchorError::Other("Transaction not found in blockchain".to_string()),
                        ));
                        storage.save_job(&job).await?;
                    }
                    Err(e) => {
                        // RPC 错误，记录但不改变状态
                        error!("Error checking confirmations for job {}: {}", job_id_hex, e);
                    }
                }
            }
        }

        Ok(())
    }

    /// 为已确认的 Job 创建 Link
    async fn create_link_for_job(
        storage: &Arc<S>,
        job: &crate::types::ChainAnchorJob,
        confirmations: u32,
        block_hash: Option<String>,
        block_height: Option<u64>,
    ) -> P4Result<()> {
        use crate::types::{ChainAnchorLink, ChainType, PolicyVersion};

        let txid = job.txid.as_ref().ok_or_else(|| {
            P4Error::InvalidInput("Job has no txid".to_string())
        })?;

        // 获取 Input
        let input = storage.get_input(&job.input_id).await?.ok_or_else(|| {
            P4Error::InvalidInput("Input not found".to_string())
        })?;

        // 创建 Link
        let mut link = ChainAnchorLink::new(
            job.job_id,
            job.input_id,
            ChainType::Bitcoin,
            txid.clone(),
            input.epoch_sequence,
            input.epoch_root,
            input.linked_receipt_ids_digest,
            PolicyVersion::new(1), // 默认策略版本
        );

        // 更新确认信息
        if let (Some(hash), Some(height)) = (block_hash, block_height) {
            link.mark_confirmed(confirmations, hash, height);
        }

        // 保存 Link
        storage.save_link(&link).await?;

        info!(
            "Created link {} for job {}",
            hex::encode(&link.link_id[..8]),
            hex::encode(&job.job_id[..8])
        );

        // 更新 Input 状态
        let mut input = input;
        input.status = InputStatus::Completed;
        storage.save_input(&input).await?;

        Ok(())
    }

    /// 运行自动恢复
    async fn run_auto_recovery(
        degradation_handler: &Arc<DegradationHandler<S>>,
        _recovery_manager: &Arc<RecoveryManager>,
        bitcoin_rpc: &Arc<BitcoinRpcClient>,
    ) -> P4Result<()> {
        debug!("Running auto recovery check...");

        let summary = degradation_handler.get_summary().await;

        if summary.active_signals.is_empty() {
            return Ok(());
        }

        // 检查每个活跃的降级信号
        for signal in &summary.active_signals {
            let can_recover = match signal {
                DegradationSignal::BitcoinDown => {
                    // 检查 Bitcoin RPC 是否恢复
                    Self::check_bitcoin_rpc_health(bitcoin_rpc).await
                }
                DegradationSignal::FeeRateTooHigh => {
                    // 检查费率是否恢复正常
                    Self::check_fee_rate(bitcoin_rpc).await
                }
                DegradationSignal::AnchorCap => {
                    // Cap 耗尽需要手动恢复或等待新周期
                    false
                }
                DegradationSignal::DsnDown => {
                    // DSN 不可用通常需要外部恢复
                    false
                }
                DegradationSignal::L0Down => {
                    // L0 不可用通常需要外部恢复
                    false
                }
                DegradationSignal::EconDown => {
                    // 经济系统不可用通常需要外部恢复
                    false
                }
            };

            if can_recover {
                info!("Signal {:?} can be recovered, attempting recovery", signal);
                if let Err(e) = degradation_handler.recover_signal(
                    *signal,
                    "Auto recovery - health check passed"
                ).await {
                    error!("Failed to recover signal {:?}: {}", signal, e);
                } else {
                    info!("Successfully recovered from {:?}", signal);
                }
            } else {
                debug!("Signal {:?} not ready for recovery", signal);
            }
        }

        Ok(())
    }

    /// 检查 Bitcoin RPC 健康状态
    async fn check_bitcoin_rpc_health(bitcoin_rpc: &Arc<BitcoinRpcClient>) -> bool {
        match bitcoin_rpc.ping().await {
            Ok(()) => {
                debug!("Bitcoin RPC health check passed");
                true
            }
            Err(e) => {
                debug!("Bitcoin RPC health check failed: {}", e);
                false
            }
        }
    }

    /// 检查费率是否正常
    async fn check_fee_rate(bitcoin_rpc: &Arc<BitcoinRpcClient>) -> bool {
        match bitcoin_rpc.estimate_smart_fee(6).await {
            Ok(fee_rate) => {
                // 如果费率低于 100 sat/vB，认为费率正常
                let is_normal = fee_rate < 100;
                debug!("Current fee rate: {} sat/vB, is_normal: {}", fee_rate, is_normal);
                is_normal
            }
            Err(e) => {
                debug!("Fee rate check failed: {}", e);
                false
            }
        }
    }
}

/// 运行器句柄
pub struct RunnerHandle {
    shutdown_tx: mpsc::Sender<()>,
    running: Arc<RwLock<bool>>,
}

impl RunnerHandle {
    /// 停止运行器
    pub async fn stop(self) {
        *self.running.write().await = false;
        let _ = self.shutdown_tx.send(()).await;
    }

    /// 暂停运行器
    pub async fn pause(&self) {
        *self.running.write().await = false;
    }

    /// 恢复运行器
    pub async fn resume(&self) {
        *self.running.write().await = true;
    }

    /// 检查是否运行中
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;
    use crate::degradation::DegradationConfig;
    use crate::policy::ChainAnchorPolicyVersion;

    #[tokio::test]
    async fn test_runner_handle() {
        let (tx, _rx) = mpsc::channel(1);
        let handle = RunnerHandle {
            shutdown_tx: tx,
            running: Arc::new(RwLock::new(true)),
        };

        assert!(handle.is_running().await);

        handle.pause().await;
        assert!(!handle.is_running().await);

        handle.resume().await;
        assert!(handle.is_running().await);
    }
}
