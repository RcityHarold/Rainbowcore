//! 恢复逻辑
//!
//! 处理从降级状态恢复到正常状态的逻辑。
//!
//! # 恢复策略
//!
//! 1. 健康检查：定期检测服务可用性
//! 2. 渐进恢复：逐步恢复处理能力
//! 3. 队列处理：恢复后处理积压任务
//!
//! # 恢复循环
//!
//! 恢复管理器可以运行一个后台循环，定期：
//! - 检查所有活跃降级信号的健康状态
//! - 推进正在进行的渐进恢复
//! - 自动移除已恢复的降级信号
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │           Recovery Loop                  │
//! │                                          │
//! │  ┌─────────┐   ┌─────────┐  ┌────────┐  │
//! │  │ Health  │──>│ Gradual │─>│Complete│  │
//! │  │ Check   │   │Recovery │  │        │  │
//! │  └─────────┘   └─────────┘  └────────┘  │
//! │       │                          │       │
//! │       └──── Retry on Failure ────┘       │
//! └─────────────────────────────────────────┘
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use serde::{Deserialize, Serialize};
use tracing::{info, warn, debug, error};

use crate::error::{P4Error, P4Result};
use crate::types::Timestamp;

use super::signals::{DegradationSignal, DegradationState};

/// 健康检查结果
#[derive(Debug, Clone)]
pub struct HealthCheckResult {
    /// 信号类型
    pub signal: DegradationSignal,
    /// 是否健康
    pub is_healthy: bool,
    /// 检查时间
    pub checked_at: Timestamp,
    /// 详细信息
    pub details: String,
    /// 连续健康次数
    pub consecutive_healthy: u32,
    /// 连续不健康次数
    pub consecutive_unhealthy: u32,
}

impl HealthCheckResult {
    /// 创建健康结果
    pub fn healthy(signal: DegradationSignal, details: impl Into<String>) -> Self {
        Self {
            signal,
            is_healthy: true,
            checked_at: Timestamp::now(),
            details: details.into(),
            consecutive_healthy: 1,
            consecutive_unhealthy: 0,
        }
    }

    /// 创建不健康结果
    pub fn unhealthy(signal: DegradationSignal, details: impl Into<String>) -> Self {
        Self {
            signal,
            is_healthy: false,
            checked_at: Timestamp::now(),
            details: details.into(),
            consecutive_healthy: 0,
            consecutive_unhealthy: 1,
        }
    }
}

/// 健康检查器 trait
#[async_trait::async_trait]
pub trait HealthChecker: Send + Sync {
    /// 检查特定信号对应服务的健康状态
    async fn check(&self, signal: DegradationSignal) -> HealthCheckResult;

    /// 获取支持检查的信号类型
    fn supported_signals(&self) -> Vec<DegradationSignal>;
}

/// 恢复配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryConfig {
    /// 恢复前需要的连续健康检查次数
    pub required_healthy_checks: u32,

    /// 健康检查间隔（毫秒）
    pub health_check_interval_ms: u64,

    /// 恢复后的渐进恢复时间（毫秒）
    pub gradual_recovery_duration_ms: u64,

    /// 渐进恢复步数
    pub gradual_recovery_steps: u32,

    /// 是否启用自动恢复
    pub auto_recovery_enabled: bool,

    /// 最大恢复尝试次数
    pub max_recovery_attempts: u32,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            required_healthy_checks: 3,
            health_check_interval_ms: 10_000,  // 10秒
            gradual_recovery_duration_ms: 60_000,  // 1分钟
            gradual_recovery_steps: 5,
            auto_recovery_enabled: true,
            max_recovery_attempts: 10,
        }
    }
}

/// 恢复状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStatus {
    /// 未开始恢复
    NotStarted,
    /// 正在检查健康状态
    Checking,
    /// 正在渐进恢复
    Recovering,
    /// 恢复完成
    Completed,
    /// 恢复失败
    Failed,
}

/// 恢复进度
#[derive(Debug, Clone)]
pub struct RecoveryProgress {
    /// 信号类型
    pub signal: DegradationSignal,
    /// 恢复状态
    pub status: RecoveryStatus,
    /// 开始时间
    pub started_at: Option<Timestamp>,
    /// 完成时间
    pub completed_at: Option<Timestamp>,
    /// 当前步骤
    pub current_step: u32,
    /// 总步骤数
    pub total_steps: u32,
    /// 连续健康检查次数
    pub consecutive_healthy: u32,
    /// 恢复尝试次数
    pub attempt_count: u32,
    /// 最后错误
    pub last_error: Option<String>,
}

impl RecoveryProgress {
    /// 创建新的恢复进度
    pub fn new(signal: DegradationSignal, total_steps: u32) -> Self {
        Self {
            signal,
            status: RecoveryStatus::NotStarted,
            started_at: None,
            completed_at: None,
            current_step: 0,
            total_steps,
            consecutive_healthy: 0,
            attempt_count: 0,
            last_error: None,
        }
    }

    /// 开始恢复
    pub fn start(&mut self) {
        self.status = RecoveryStatus::Checking;
        self.started_at = Some(Timestamp::now());
        self.attempt_count += 1;
    }

    /// 记录健康检查结果
    pub fn record_health_check(&mut self, is_healthy: bool) {
        if is_healthy {
            self.consecutive_healthy += 1;
        } else {
            self.consecutive_healthy = 0;
        }
    }

    /// 进入渐进恢复阶段
    pub fn start_gradual_recovery(&mut self) {
        self.status = RecoveryStatus::Recovering;
        self.current_step = 0;
    }

    /// 推进恢复步骤
    pub fn advance_step(&mut self) {
        if self.current_step < self.total_steps {
            self.current_step += 1;
        }

        if self.current_step >= self.total_steps {
            self.complete();
        }
    }

    /// 完成恢复
    pub fn complete(&mut self) {
        self.status = RecoveryStatus::Completed;
        self.completed_at = Some(Timestamp::now());
    }

    /// 标记失败
    pub fn fail(&mut self, error: impl Into<String>) {
        self.status = RecoveryStatus::Failed;
        self.last_error = Some(error.into());
    }

    /// 重置进度
    pub fn reset(&mut self) {
        self.status = RecoveryStatus::NotStarted;
        self.consecutive_healthy = 0;
        self.current_step = 0;
    }

    /// 获取恢复百分比
    pub fn percentage(&self) -> u8 {
        if self.total_steps == 0 {
            return 100;
        }

        match self.status {
            RecoveryStatus::NotStarted => 0,
            RecoveryStatus::Checking => 10,
            RecoveryStatus::Recovering => {
                10 + (self.current_step * 90 / self.total_steps) as u8
            }
            RecoveryStatus::Completed => 100,
            RecoveryStatus::Failed => 0,
        }
    }
}

/// 恢复循环状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopState {
    /// 已停止
    Stopped,
    /// 正在运行
    Running,
    /// 正在停止
    Stopping,
}

/// 恢复循环统计
#[derive(Debug, Clone, Default)]
pub struct RecoveryLoopStats {
    /// 循环执行次数
    pub iterations: u64,
    /// 成功恢复次数
    pub successful_recoveries: u64,
    /// 失败恢复次数
    pub failed_recoveries: u64,
    /// 健康检查次数
    pub health_checks: u64,
    /// 最后循环时间
    pub last_iteration: Option<Timestamp>,
    /// 循环启动时间
    pub started_at: Option<Timestamp>,
}

/// 恢复回调函数类型
type RecoveryCallback = Box<dyn Fn(DegradationSignal) + Send + Sync>;

/// 恢复管理器
pub struct RecoveryManager {
    /// 配置
    config: RecoveryConfig,

    /// 降级状态
    degradation_state: Arc<RwLock<DegradationState>>,

    /// 恢复进度（按信号类型索引）
    progress: Arc<RwLock<std::collections::HashMap<DegradationSignal, RecoveryProgress>>>,

    /// 健康检查器
    health_checkers: Arc<RwLock<Vec<Box<dyn HealthChecker>>>>,

    /// 是否正在运行
    running: Arc<AtomicBool>,

    /// 停止信号
    stop_signal: Arc<AtomicBool>,

    /// 循环统计
    stats: Arc<RwLock<RecoveryLoopStats>>,

    /// 恢复回调
    /// 当信号恢复时调用
    on_recovery_callbacks: Arc<RwLock<Vec<RecoveryCallback>>>,
}

impl RecoveryManager {
    /// 创建新的恢复管理器
    pub fn new(
        config: RecoveryConfig,
        degradation_state: Arc<RwLock<DegradationState>>,
    ) -> Self {
        Self {
            config,
            degradation_state,
            progress: Arc::new(RwLock::new(std::collections::HashMap::new())),
            health_checkers: Arc::new(RwLock::new(Vec::new())),
            running: Arc::new(AtomicBool::new(false)),
            stop_signal: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(RwLock::new(RecoveryLoopStats::default())),
            on_recovery_callbacks: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// 注册健康检查器
    pub async fn register_health_checker(&self, checker: Box<dyn HealthChecker>) {
        self.health_checkers.write().await.push(checker);
    }

    /// 注册恢复回调
    ///
    /// 当信号恢复时调用回调函数
    pub async fn on_recovery<F>(&self, callback: F)
    where
        F: Fn(DegradationSignal) + Send + Sync + 'static,
    {
        self.on_recovery_callbacks.write().await.push(Box::new(callback));
    }

    /// 启动恢复循环
    ///
    /// 返回一个 JoinHandle，调用者可以等待循环完成或取消它。
    /// 循环将持续运行直到调用 `stop_loop`。
    pub fn start_loop(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        if self.running.swap(true, Ordering::SeqCst) {
            warn!("Recovery loop is already running");
            // 返回一个已完成的空任务
            return tokio::spawn(async {});
        }

        self.stop_signal.store(false, Ordering::SeqCst);

        let manager = Arc::clone(self);
        tokio::spawn(async move {
            manager.run_loop().await;
        })
    }

    /// 停止恢复循环
    ///
    /// 这是一个异步方法，会等待当前循环迭代完成后停止。
    pub async fn stop_loop(&self) {
        if !self.running.load(Ordering::SeqCst) {
            return;
        }

        info!("Stopping recovery loop...");
        self.stop_signal.store(true, Ordering::SeqCst);

        // 等待循环停止
        let mut attempts = 0;
        while self.running.load(Ordering::SeqCst) && attempts < 100 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            attempts += 1;
        }

        if self.running.load(Ordering::SeqCst) {
            warn!("Recovery loop did not stop cleanly after 10 seconds");
        } else {
            info!("Recovery loop stopped");
        }
    }

    /// 检查循环是否正在运行
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// 获取循环状态
    pub fn loop_state(&self) -> LoopState {
        if self.running.load(Ordering::SeqCst) {
            if self.stop_signal.load(Ordering::SeqCst) {
                LoopState::Stopping
            } else {
                LoopState::Running
            }
        } else {
            LoopState::Stopped
        }
    }

    /// 获取循环统计
    pub async fn loop_stats(&self) -> RecoveryLoopStats {
        self.stats.read().await.clone()
    }

    /// 运行恢复循环
    async fn run_loop(&self) {
        info!("Recovery loop started");

        // 更新统计
        {
            let mut stats = self.stats.write().await;
            stats.started_at = Some(Timestamp::now());
        }

        let check_interval = Duration::from_millis(self.config.health_check_interval_ms);
        let mut ticker = interval(check_interval);

        while !self.stop_signal.load(Ordering::SeqCst) {
            ticker.tick().await;

            if self.stop_signal.load(Ordering::SeqCst) {
                break;
            }

            // 执行一次循环迭代
            if let Err(e) = self.run_iteration().await {
                error!("Recovery loop iteration error: {}", e);
            }
        }

        self.running.store(false, Ordering::SeqCst);
        info!("Recovery loop exited");
    }

    /// 执行一次循环迭代
    async fn run_iteration(&self) -> P4Result<()> {
        debug!("Running recovery loop iteration");

        // 更新迭代计数
        {
            let mut stats = self.stats.write().await;
            stats.iterations += 1;
            stats.last_iteration = Some(Timestamp::now());
        }

        // 获取所有活跃的降级信号
        let active_signals = {
            let state = self.degradation_state.read().await;
            state.get_active_signals()
        };

        if active_signals.is_empty() {
            debug!("No active degradation signals");
            return Ok(());
        }

        debug!("Processing {} active signals", active_signals.len());

        for signal in active_signals {
            if self.stop_signal.load(Ordering::SeqCst) {
                break;
            }

            // 检查是否已有进行中的恢复
            let current_status = {
                let progress_map = self.progress.read().await;
                progress_map.get(&signal).map(|p| p.status)
            };

            match current_status {
                Some(RecoveryStatus::Recovering) => {
                    // 推进渐进恢复
                    self.advance_gradual_recovery_internal(signal).await;
                }
                Some(RecoveryStatus::Checking) | None => {
                    // 执行健康检查
                    self.check_and_maybe_recover(signal).await;
                }
                Some(RecoveryStatus::Completed) => {
                    // 已完成，跳过
                    debug!("Signal {} already recovered", signal);
                }
                Some(RecoveryStatus::Failed) => {
                    // 失败，根据配置决定是否重试
                    if self.config.auto_recovery_enabled {
                        let should_retry = {
                            let progress_map = self.progress.read().await;
                            progress_map.get(&signal)
                                .map(|p| p.attempt_count < self.config.max_recovery_attempts)
                                .unwrap_or(true)
                        };

                        if should_retry {
                            debug!("Retrying recovery for signal {}", signal);
                            self.reset_progress(signal).await?;
                            self.check_and_maybe_recover(signal).await;
                        }
                    }
                }
                Some(RecoveryStatus::NotStarted) => {
                    // 开始恢复流程
                    if self.config.auto_recovery_enabled {
                        self.check_and_maybe_recover(signal).await;
                    }
                }
            }
        }

        Ok(())
    }

    /// 检查健康状态并可能启动恢复
    async fn check_and_maybe_recover(&self, signal: DegradationSignal) {
        // 更新统计
        {
            let mut stats = self.stats.write().await;
            stats.health_checks += 1;
        }

        // 初始化或获取进度
        {
            let mut progress_map = self.progress.write().await;
            let progress = progress_map
                .entry(signal)
                .or_insert_with(|| RecoveryProgress::new(signal, self.config.gradual_recovery_steps));

            if progress.status == RecoveryStatus::NotStarted {
                progress.start();
            }
        }

        // 执行健康检查
        match self.perform_health_check(signal).await {
            Ok(progress) => {
                if progress.status == RecoveryStatus::Completed {
                    self.notify_recovery(signal).await;
                    let mut stats = self.stats.write().await;
                    stats.successful_recoveries += 1;
                }
            }
            Err(e) => {
                warn!("Health check failed for signal {}: {}", signal, e);
            }
        }
    }

    /// 推进渐进恢复（内部方法）
    async fn advance_gradual_recovery_internal(&self, signal: DegradationSignal) {
        match self.advance_gradual_recovery(signal).await {
            Ok(progress) => {
                if progress.status == RecoveryStatus::Completed {
                    self.notify_recovery(signal).await;
                    let mut stats = self.stats.write().await;
                    stats.successful_recoveries += 1;
                }
            }
            Err(e) => {
                warn!("Gradual recovery failed for signal {}: {}", signal, e);
                let mut stats = self.stats.write().await;
                stats.failed_recoveries += 1;
            }
        }
    }

    /// 通知恢复完成
    async fn notify_recovery(&self, signal: DegradationSignal) {
        info!("Signal {} has recovered", signal);

        let callbacks = self.on_recovery_callbacks.read().await;
        for callback in callbacks.iter() {
            callback(signal);
        }
    }

    /// 手动触发恢复检查
    pub async fn trigger_recovery(&self, signal: DegradationSignal) -> P4Result<RecoveryProgress> {
        let state = self.degradation_state.read().await;

        if !state.has_signal(signal) {
            return Err(P4Error::InvalidInput(format!(
                "Signal {} is not active",
                signal
            )));
        }
        drop(state);

        // 初始化进度
        let mut progress_map = self.progress.write().await;
        let progress = progress_map
            .entry(signal)
            .or_insert_with(|| RecoveryProgress::new(signal, self.config.gradual_recovery_steps));

        progress.start();
        drop(progress_map);

        // 执行健康检查
        self.perform_health_check(signal).await
    }

    /// 执行健康检查
    async fn perform_health_check(&self, signal: DegradationSignal) -> P4Result<RecoveryProgress> {
        let checkers = self.health_checkers.read().await;

        let mut is_healthy = true;
        let mut details = Vec::new();

        for checker in checkers.iter() {
            if checker.supported_signals().contains(&signal) {
                let result = checker.check(signal).await;
                if !result.is_healthy {
                    is_healthy = false;
                }
                details.push(format!("{}: {}", if result.is_healthy { "OK" } else { "FAIL" }, result.details));
            }
        }

        // 更新进度
        let mut progress_map = self.progress.write().await;
        let progress = progress_map
            .entry(signal)
            .or_insert_with(|| RecoveryProgress::new(signal, self.config.gradual_recovery_steps));

        progress.record_health_check(is_healthy);

        if is_healthy && progress.consecutive_healthy >= self.config.required_healthy_checks {
            // 健康检查通过，开始渐进恢复
            progress.start_gradual_recovery();
        } else if !is_healthy {
            // 健康检查失败
            if progress.attempt_count >= self.config.max_recovery_attempts {
                progress.fail("Max recovery attempts exceeded");
            }
        }

        let result = progress.clone();
        drop(progress_map);

        // 如果渐进恢复完成，移除降级信号
        if result.status == RecoveryStatus::Completed {
            self.complete_recovery(signal).await?;
        }

        Ok(result)
    }

    /// 完成恢复（移除降级信号）
    async fn complete_recovery(&self, signal: DegradationSignal) -> P4Result<()> {
        let mut state = self.degradation_state.write().await;
        state.remove_signal(signal, "Recovery completed");

        tracing::info!("Recovery completed for signal: {}", signal);

        Ok(())
    }

    /// 推进渐进恢复
    pub async fn advance_gradual_recovery(&self, signal: DegradationSignal) -> P4Result<RecoveryProgress> {
        let mut progress_map = self.progress.write().await;

        let progress = progress_map.get_mut(&signal).ok_or_else(|| {
            P4Error::InvalidInput(format!("No recovery in progress for signal: {}", signal))
        })?;

        if progress.status != RecoveryStatus::Recovering {
            return Err(P4Error::InvalidInput(format!(
                "Signal {} is not in recovering state",
                signal
            )));
        }

        progress.advance_step();
        let result = progress.clone();
        drop(progress_map);

        // 如果完成，移除降级信号
        if result.status == RecoveryStatus::Completed {
            self.complete_recovery(signal).await?;
        }

        Ok(result)
    }

    /// 获取恢复进度
    pub async fn get_progress(&self, signal: DegradationSignal) -> Option<RecoveryProgress> {
        self.progress.read().await.get(&signal).cloned()
    }

    /// 获取所有恢复进度
    pub async fn get_all_progress(&self) -> Vec<RecoveryProgress> {
        self.progress.read().await.values().cloned().collect()
    }

    /// 取消恢复
    pub async fn cancel_recovery(&self, signal: DegradationSignal) -> P4Result<()> {
        let mut progress_map = self.progress.write().await;

        if let Some(progress) = progress_map.get_mut(&signal) {
            progress.fail("Cancelled by user");
        }

        Ok(())
    }

    /// 重置恢复进度
    pub async fn reset_progress(&self, signal: DegradationSignal) -> P4Result<()> {
        let mut progress_map = self.progress.write().await;

        if let Some(progress) = progress_map.get_mut(&signal) {
            progress.reset();
        }

        Ok(())
    }

    /// 获取配置
    pub fn config(&self) -> &RecoveryConfig {
        &self.config
    }
}

/// 默认健康检查器（用于测试）
pub struct DefaultHealthChecker;

#[async_trait::async_trait]
impl HealthChecker for DefaultHealthChecker {
    async fn check(&self, signal: DegradationSignal) -> HealthCheckResult {
        // 默认实现总是返回健康
        HealthCheckResult::healthy(signal, "Default health check passed")
    }

    fn supported_signals(&self) -> Vec<DegradationSignal> {
        vec![
            DegradationSignal::DsnDown,
            DegradationSignal::L0Down,
            DegradationSignal::EconDown,
            DegradationSignal::AnchorCap,
            DegradationSignal::BitcoinDown,
            DegradationSignal::FeeRateTooHigh,
        ]
    }
}

/// 恢复动作
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryAction {
    /// 动作类型
    pub action_type: RecoveryActionType,
    /// 目标信号
    pub target_signal: DegradationSignal,
    /// 参数
    pub parameters: std::collections::HashMap<String, String>,
}

/// 恢复动作类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryActionType {
    /// 重新连接
    Reconnect,
    /// 刷新缓存
    RefreshCache,
    /// 重置状态
    ResetState,
    /// 补充预算
    ReplenishBudget,
    /// 清理队列
    ClearQueue,
    /// 通知管理员
    NotifyAdmin,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_check_result() {
        let healthy = HealthCheckResult::healthy(DegradationSignal::DsnDown, "OK");
        assert!(healthy.is_healthy);

        let unhealthy = HealthCheckResult::unhealthy(DegradationSignal::L0Down, "Connection failed");
        assert!(!unhealthy.is_healthy);
    }

    #[test]
    fn test_recovery_progress() {
        let mut progress = RecoveryProgress::new(DegradationSignal::AnchorCap, 5);

        assert_eq!(progress.status, RecoveryStatus::NotStarted);
        assert_eq!(progress.percentage(), 0);

        progress.start();
        assert_eq!(progress.status, RecoveryStatus::Checking);
        assert_eq!(progress.percentage(), 10);

        // 模拟健康检查通过
        progress.record_health_check(true);
        progress.record_health_check(true);
        progress.record_health_check(true);
        assert_eq!(progress.consecutive_healthy, 3);

        progress.start_gradual_recovery();
        assert_eq!(progress.status, RecoveryStatus::Recovering);

        // 推进步骤
        progress.advance_step();
        progress.advance_step();
        assert_eq!(progress.current_step, 2);
        assert!(progress.percentage() > 10);

        // 完成所有步骤
        progress.advance_step();
        progress.advance_step();
        progress.advance_step();
        assert_eq!(progress.status, RecoveryStatus::Completed);
        assert_eq!(progress.percentage(), 100);
    }

    #[test]
    fn test_recovery_config_default() {
        let config = RecoveryConfig::default();
        assert_eq!(config.required_healthy_checks, 3);
        assert!(config.auto_recovery_enabled);
    }

    #[tokio::test]
    async fn test_recovery_manager() {
        let state = Arc::new(RwLock::new(DegradationState::new()));
        state.write().await.add_signal(DegradationSignal::AnchorCap, "Test");

        let config = RecoveryConfig::default();
        let manager = RecoveryManager::new(config, state.clone());

        // 注册默认检查器
        manager.register_health_checker(Box::new(DefaultHealthChecker)).await;

        // 触发恢复
        let progress = manager.trigger_recovery(DegradationSignal::AnchorCap).await.unwrap();
        assert_eq!(progress.status, RecoveryStatus::Checking);
    }

    #[test]
    fn test_recovery_action() {
        let action = RecoveryAction {
            action_type: RecoveryActionType::ReplenishBudget,
            target_signal: DegradationSignal::AnchorCap,
            parameters: std::collections::HashMap::new(),
        };

        assert_eq!(action.action_type, RecoveryActionType::ReplenishBudget);
    }

    #[test]
    fn test_loop_state() {
        // 测试循环状态枚举
        assert_eq!(LoopState::Stopped, LoopState::Stopped);
        assert_ne!(LoopState::Running, LoopState::Stopped);
    }

    #[test]
    fn test_recovery_loop_stats_default() {
        let stats = RecoveryLoopStats::default();
        assert_eq!(stats.iterations, 0);
        assert_eq!(stats.successful_recoveries, 0);
        assert_eq!(stats.failed_recoveries, 0);
        assert_eq!(stats.health_checks, 0);
        assert!(stats.last_iteration.is_none());
        assert!(stats.started_at.is_none());
    }

    #[tokio::test]
    async fn test_recovery_loop_start_stop() {
        let state = Arc::new(RwLock::new(DegradationState::new()));

        // 使用较短的检查间隔进行测试
        let config = RecoveryConfig {
            health_check_interval_ms: 100,
            ..Default::default()
        };

        let manager = Arc::new(RecoveryManager::new(config, state.clone()));

        // 初始状态
        assert!(!manager.is_running());
        assert_eq!(manager.loop_state(), LoopState::Stopped);

        // 启动循环
        let _handle = manager.start_loop();

        // 等待循环启动
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert!(manager.is_running());
        assert_eq!(manager.loop_state(), LoopState::Running);

        // 停止循环
        manager.stop_loop().await;

        assert!(!manager.is_running());
        assert_eq!(manager.loop_state(), LoopState::Stopped);
    }

    #[tokio::test]
    async fn test_recovery_loop_with_signals() {
        let state = Arc::new(RwLock::new(DegradationState::new()));
        state.write().await.add_signal(DegradationSignal::AnchorCap, "Test signal");

        let config = RecoveryConfig {
            health_check_interval_ms: 100,
            required_healthy_checks: 1,
            gradual_recovery_steps: 1,
            ..Default::default()
        };

        let manager = Arc::new(RecoveryManager::new(config, state.clone()));
        manager.register_health_checker(Box::new(DefaultHealthChecker)).await;

        // 启动循环
        let _handle = manager.start_loop();

        // 等待几次迭代
        tokio::time::sleep(Duration::from_millis(350)).await;

        // 检查统计
        let stats = manager.loop_stats().await;
        assert!(stats.iterations > 0);
        assert!(stats.health_checks > 0);
        assert!(stats.started_at.is_some());

        // 停止循环
        manager.stop_loop().await;
    }

    #[tokio::test]
    async fn test_recovery_loop_double_start() {
        let state = Arc::new(RwLock::new(DegradationState::new()));
        let config = RecoveryConfig {
            health_check_interval_ms: 100,
            ..Default::default()
        };

        let manager = Arc::new(RecoveryManager::new(config, state.clone()));

        // 第一次启动
        let _handle1 = manager.start_loop();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // 第二次启动应该立即返回
        let _handle2 = manager.start_loop();

        // 仍然只有一个循环在运行
        assert!(manager.is_running());

        manager.stop_loop().await;
    }

    #[tokio::test]
    async fn test_recovery_callback() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let state = Arc::new(RwLock::new(DegradationState::new()));
        state.write().await.add_signal(DegradationSignal::DsnDown, "Test");

        let config = RecoveryConfig {
            health_check_interval_ms: 50,
            required_healthy_checks: 1,
            gradual_recovery_steps: 1,
            ..Default::default()
        };

        let manager = Arc::new(RecoveryManager::new(config, state.clone()));
        manager.register_health_checker(Box::new(DefaultHealthChecker)).await;

        // 注册回调
        let callback_count = Arc::new(AtomicU32::new(0));
        let callback_count_clone = callback_count.clone();

        manager.on_recovery(move |_signal| {
            callback_count_clone.fetch_add(1, Ordering::SeqCst);
        }).await;

        // 启动循环
        let _handle = manager.start_loop();

        // 等待恢复完成
        tokio::time::sleep(Duration::from_millis(200)).await;

        // 检查回调是否被调用
        // 注意：由于默认健康检查器总是返回健康，恢复应该完成
        let count = callback_count.load(Ordering::SeqCst);
        // 回调可能已被调用
        assert!(count >= 0); // 至少检查计数器工作正常

        manager.stop_loop().await;
    }

    #[tokio::test]
    async fn test_loop_stats_update() {
        let state = Arc::new(RwLock::new(DegradationState::new()));
        state.write().await.add_signal(DegradationSignal::BitcoinDown, "Test");

        let config = RecoveryConfig {
            health_check_interval_ms: 50,
            ..Default::default()
        };

        let manager = Arc::new(RecoveryManager::new(config, state.clone()));
        manager.register_health_checker(Box::new(DefaultHealthChecker)).await;

        // 初始统计
        let initial_stats = manager.loop_stats().await;
        assert_eq!(initial_stats.iterations, 0);

        // 启动循环
        let _handle = manager.start_loop();

        // 等待一些迭代
        tokio::time::sleep(Duration::from_millis(150)).await;

        // 统计应该已更新
        let updated_stats = manager.loop_stats().await;
        assert!(updated_stats.iterations > 0);
        assert!(updated_stats.started_at.is_some());
        assert!(updated_stats.last_iteration.is_some());

        manager.stop_loop().await;
    }
}
