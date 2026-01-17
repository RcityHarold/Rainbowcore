//! 降级处理模块
//!
//! 处理系统降级状态和恢复逻辑。
//!
//! # 核心组件
//!
//! - `DegradationHandler`: 降级处理器
//! - `DegradationSignal`: 降级信号类型
//! - `RecoveryManager`: 恢复管理器
//!
//! # 设计原则
//!
//! - MUST队列不丢弃：降级时只能排队，不能静默丢弃
//! - 显性化降级原因：所有降级必须记录
//! - 渐进恢复：恢复后逐步恢复处理能力

pub mod signals;
pub mod recovery;

pub use signals::{
    DegradationSignal, DegradationEvent, DegradationEventType,
    DegradationState, DegradationStrategy, determine_strategy,
};

pub use recovery::{
    HealthCheckResult, HealthChecker, RecoveryConfig, RecoveryStatus,
    RecoveryProgress, RecoveryManager, RecoveryAction, RecoveryActionType,
    DefaultHealthChecker,
};

use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::P4Result;
use crate::pool::AnchorPool;
use crate::cap::CapManager;
use crate::storage::AnchorStorage;
use crate::types::AnchorPriority;

/// 降级处理器
pub struct DegradationHandler<S: AnchorStorage> {
    /// 降级状态
    state: Arc<RwLock<DegradationState>>,

    /// 对象池
    pool: Arc<AnchorPool<S>>,

    /// Cap管理器
    cap_manager: Arc<CapManager>,

    /// 恢复管理器
    recovery_manager: Arc<RecoveryManager>,

    /// 配置
    config: DegradationConfig,

    /// 事件监听器
    listeners: Arc<RwLock<Vec<Box<dyn DegradationListener>>>>,
}

/// 降级配置
#[derive(Debug, Clone)]
pub struct DegradationConfig {
    /// 是否启用自动恢复
    pub auto_recovery_enabled: bool,

    /// 最大保留事件数
    pub max_event_history: usize,

    /// 降级时是否持久化MUST队列
    pub persist_must_on_degradation: bool,

    /// Cap预警触发降级的阈值（百分比）
    pub cap_warning_degradation_threshold: u8,
}

impl Default for DegradationConfig {
    fn default() -> Self {
        Self {
            auto_recovery_enabled: true,
            max_event_history: 1000,
            persist_must_on_degradation: true,
            cap_warning_degradation_threshold: 95,
        }
    }
}

/// 降级事件监听器
#[async_trait::async_trait]
pub trait DegradationListener: Send + Sync {
    /// 降级开始时调用
    async fn on_degradation_start(&self, signal: DegradationSignal);

    /// 降级恢复时调用
    async fn on_degradation_recover(&self, signal: DegradationSignal);

    /// 策略决定时调用
    async fn on_strategy_applied(&self, signal: DegradationSignal, priority: AnchorPriority, strategy: DegradationStrategy);
}

impl<S: AnchorStorage + 'static> DegradationHandler<S> {
    /// 创建新的降级处理器
    pub fn new(
        pool: Arc<AnchorPool<S>>,
        cap_manager: Arc<CapManager>,
        config: DegradationConfig,
    ) -> Self {
        let state = Arc::new(RwLock::new(DegradationState::new()));
        let recovery_config = RecoveryConfig {
            auto_recovery_enabled: config.auto_recovery_enabled,
            ..Default::default()
        };
        let recovery_manager = Arc::new(RecoveryManager::new(
            recovery_config,
            state.clone(),
        ));

        Self {
            state,
            pool,
            cap_manager,
            recovery_manager,
            config,
            listeners: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// 处理降级信号
    pub async fn handle_signal(&self, signal: DegradationSignal, reason: impl Into<String>) -> P4Result<()> {
        let reason_str = reason.into();

        // 更新状态
        {
            let mut state = self.state.write().await;
            state.add_signal(signal, &reason_str);
        }

        // 通知监听器
        {
            let listeners = self.listeners.read().await;
            for listener in listeners.iter() {
                listener.on_degradation_start(signal).await;
            }
        }

        // 根据信号类型执行特定处理
        match signal {
            DegradationSignal::DsnDown => {
                // DSN不可用：暂停所有锚定，持久化MUST池
                if self.config.persist_must_on_degradation {
                    self.pool.persist_must_pool().await?;
                }
                tracing::warn!("DSN down: {}", reason_str);
            }
            DegradationSignal::L0Down => {
                // L0不可用：无法获取新的epoch_root，等待恢复
                if self.config.persist_must_on_degradation {
                    self.pool.persist_must_pool().await?;
                }
                tracing::warn!("L0 down: {}", reason_str);
            }
            DegradationSignal::EconDown => {
                // 经济系统不可用：使用缓存预算继续
                tracing::warn!("Econ down: {}", reason_str);
            }
            DegradationSignal::AnchorCap => {
                // Cap耗尽：丢弃MAY，暂停SHOULD，保留MUST
                self.handle_cap_exhaustion().await?;
                tracing::warn!("Cap exhausted: {}", reason_str);
            }
            DegradationSignal::BitcoinDown => {
                // Bitcoin节点不可用
                if self.config.persist_must_on_degradation {
                    self.pool.persist_must_pool().await?;
                }
                tracing::error!("Bitcoin node down: {}", reason_str);
            }
            DegradationSignal::FeeRateTooHigh => {
                // 费率过高：暂停MAY和SHOULD
                tracing::warn!("Fee rate too high: {}", reason_str);
            }
        }

        Ok(())
    }

    /// 处理Cap耗尽
    async fn handle_cap_exhaustion(&self) -> P4Result<()> {
        // 根据策略配置决定如何处理各优先级
        let exhaustion_strategy = self.cap_manager.config().exhaustion_strategy;

        match exhaustion_strategy {
            crate::policy::ExhaustionStrategy::DropMay => {
                // 丢弃MAY池
                let dropped = self.pool.drop_may_pool().await?;
                tracing::info!("Dropped {} MAY items due to cap exhaustion", dropped);
            }
            crate::policy::ExhaustionStrategy::PauseShouldMay => {
                // 暂停SHOULD和MAY（不丢弃）
                tracing::info!("Pausing SHOULD and MAY processing due to cap exhaustion");
            }
            crate::policy::ExhaustionStrategy::PauseAll => {
                // 全部暂停
                tracing::info!("Pausing all processing due to cap exhaustion");
            }
            crate::policy::ExhaustionStrategy::QueueAll => {
                // 继续排队（不丢弃任何）
                tracing::info!("Queueing all items due to cap exhaustion");
            }
        }

        Ok(())
    }

    /// 恢复降级信号
    pub async fn recover_signal(&self, signal: DegradationSignal, reason: impl Into<String>) -> P4Result<bool> {
        let reason_str = reason.into();

        let was_active = {
            let mut state = self.state.write().await;
            state.remove_signal(signal, &reason_str)
        };

        if was_active {
            // 通知监听器
            let listeners = self.listeners.read().await;
            for listener in listeners.iter() {
                listener.on_degradation_recover(signal).await;
            }

            tracing::info!("Signal {} recovered: {}", signal, reason_str);
        }

        Ok(was_active)
    }

    /// 检查是否可以处理指定优先级
    pub async fn can_process(&self, priority: AnchorPriority) -> bool {
        let state = self.state.read().await;
        state.can_process(priority)
    }

    /// 获取处理策略
    pub async fn get_strategy(&self, priority: AnchorPriority) -> DegradationStrategy {
        let state = self.state.read().await;

        if state.active_signals.is_empty() {
            return DegradationStrategy::Continue;
        }

        // 找出最严格的策略
        let mut most_restrictive = DegradationStrategy::Continue;

        for signal in state.active_signals.iter() {
            let strategy = determine_strategy(*signal, priority);

            // 策略优先级：Drop > Pause > Queue > Retry > Continue
            most_restrictive = match (most_restrictive, strategy) {
                (DegradationStrategy::Drop, _) => DegradationStrategy::Drop,
                (_, DegradationStrategy::Drop) => DegradationStrategy::Drop,
                (DegradationStrategy::Pause, _) => DegradationStrategy::Pause,
                (_, DegradationStrategy::Pause) => DegradationStrategy::Pause,
                (DegradationStrategy::Queue, _) => DegradationStrategy::Queue,
                (_, DegradationStrategy::Queue) => DegradationStrategy::Queue,
                (DegradationStrategy::Retry, _) => DegradationStrategy::Retry,
                (_, DegradationStrategy::Retry) => DegradationStrategy::Retry,
                _ => DegradationStrategy::Continue,
            };
        }

        // 通知监听器
        let listeners = self.listeners.read().await;
        for listener in listeners.iter() {
            for signal in state.active_signals.iter() {
                listener.on_strategy_applied(*signal, priority, most_restrictive).await;
            }
        }

        most_restrictive
    }

    /// 获取阻止指定优先级的信号
    pub async fn blocking_signals(&self, priority: AnchorPriority) -> Vec<DegradationSignal> {
        let state = self.state.read().await;
        state.blocking_signals(priority)
    }

    /// 检查是否处于降级状态
    pub async fn is_degraded(&self) -> bool {
        let state = self.state.read().await;
        state.is_degraded()
    }

    /// 获取当前降级状态
    pub async fn get_state(&self) -> DegradationState {
        self.state.read().await.clone()
    }

    /// 获取活跃的降级信号
    pub async fn get_active_signals(&self) -> Vec<DegradationSignal> {
        let state = self.state.read().await;
        state.get_active_signals()
    }

    /// 获取最近的降级事件
    pub async fn get_recent_events(&self, limit: usize) -> Vec<DegradationEvent> {
        let state = self.state.read().await;
        state.get_recent_events(limit)
    }

    /// 获取最高严重级别
    pub async fn max_severity(&self) -> u8 {
        let state = self.state.read().await;
        state.max_severity()
    }

    /// 添加监听器
    pub async fn add_listener(&self, listener: Box<dyn DegradationListener>) {
        self.listeners.write().await.push(listener);
    }

    /// 获取恢复管理器
    pub fn recovery_manager(&self) -> &Arc<RecoveryManager> {
        &self.recovery_manager
    }

    /// 触发恢复检查
    pub async fn trigger_recovery(&self, signal: DegradationSignal) -> P4Result<RecoveryProgress> {
        self.recovery_manager.trigger_recovery(signal).await
    }

    /// 清除所有降级信号（紧急恢复）
    pub async fn emergency_clear(&self) -> P4Result<()> {
        let signals: Vec<_> = {
            let state = self.state.read().await;
            state.get_active_signals()
        };

        for signal in signals {
            self.recover_signal(signal, "Emergency clear").await?;
        }

        tracing::warn!("Emergency clear: all degradation signals removed");
        Ok(())
    }

    /// 检查Cap状态并可能触发降级
    pub async fn check_cap_status(&self) -> P4Result<()> {
        let usage = self.cap_manager.usage_percent().await;

        if usage >= self.config.cap_warning_degradation_threshold {
            if !self.state.read().await.has_signal(DegradationSignal::AnchorCap) {
                self.handle_signal(
                    DegradationSignal::AnchorCap,
                    format!("Budget usage at {}%", usage),
                ).await?;
            }
        } else if usage < self.config.cap_warning_degradation_threshold - 10 {
            // 预留10%的恢复余量
            if self.state.read().await.has_signal(DegradationSignal::AnchorCap) {
                self.recover_signal(
                    DegradationSignal::AnchorCap,
                    format!("Budget usage dropped to {}%", usage),
                ).await?;
            }
        }

        Ok(())
    }
}

/// 降级状态摘要
#[derive(Debug, Clone)]
pub struct DegradationSummary {
    /// 是否降级
    pub is_degraded: bool,
    /// 活跃信号数量
    pub active_signal_count: usize,
    /// 最高严重级别
    pub max_severity: u8,
    /// 活跃信号列表
    pub active_signals: Vec<DegradationSignal>,
    /// MUST是否可处理
    pub can_process_must: bool,
    /// SHOULD是否可处理
    pub can_process_should: bool,
    /// MAY是否可处理
    pub can_process_may: bool,
}

impl<S: AnchorStorage + 'static> DegradationHandler<S> {
    /// 获取降级摘要
    pub async fn get_summary(&self) -> DegradationSummary {
        let state = self.state.read().await;

        DegradationSummary {
            is_degraded: state.is_degraded(),
            active_signal_count: state.active_signals.len(),
            max_severity: state.max_severity(),
            active_signals: state.get_active_signals(),
            can_process_must: state.can_process(AnchorPriority::Must),
            can_process_should: state.can_process(AnchorPriority::Should),
            can_process_may: state.can_process(AnchorPriority::May),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;
    use crate::policy::ChainAnchorPolicyVersion;

    fn create_test_handler() -> DegradationHandler<MemoryStorage> {
        let storage = Arc::new(MemoryStorage::new());
        let policy = ChainAnchorPolicyVersion::default();
        let pool = Arc::new(AnchorPool::new(storage, policy));
        let cap_manager = Arc::new(CapManager::with_default());
        let config = DegradationConfig::default();

        DegradationHandler::new(pool, cap_manager, config)
    }

    #[tokio::test]
    async fn test_handle_signal() {
        let handler = create_test_handler();

        handler.handle_signal(DegradationSignal::AnchorCap, "Test").await.unwrap();

        assert!(handler.is_degraded().await);
        assert!(handler.get_active_signals().await.contains(&DegradationSignal::AnchorCap));
    }

    #[tokio::test]
    async fn test_recover_signal() {
        let handler = create_test_handler();

        handler.handle_signal(DegradationSignal::EconDown, "Test").await.unwrap();
        assert!(handler.is_degraded().await);

        let recovered = handler.recover_signal(DegradationSignal::EconDown, "Recovered").await.unwrap();
        assert!(recovered);
        assert!(!handler.is_degraded().await);
    }

    #[tokio::test]
    async fn test_can_process() {
        let handler = create_test_handler();

        // 无降级时，所有优先级都可处理
        assert!(handler.can_process(AnchorPriority::Must).await);
        assert!(handler.can_process(AnchorPriority::Should).await);
        assert!(handler.can_process(AnchorPriority::May).await);

        // Cap降级时，MUST仍可处理
        handler.handle_signal(DegradationSignal::AnchorCap, "Test").await.unwrap();
        assert!(handler.can_process(AnchorPriority::Must).await);
        assert!(!handler.can_process(AnchorPriority::Should).await);
        assert!(!handler.can_process(AnchorPriority::May).await);
    }

    #[tokio::test]
    async fn test_get_strategy() {
        let handler = create_test_handler();

        // 无降级时，策略为Continue
        let strategy = handler.get_strategy(AnchorPriority::May).await;
        assert_eq!(strategy, DegradationStrategy::Continue);

        // Cap降级时，MAY策略为Drop
        handler.handle_signal(DegradationSignal::AnchorCap, "Test").await.unwrap();
        let strategy = handler.get_strategy(AnchorPriority::May).await;
        assert_eq!(strategy, DegradationStrategy::Drop);

        // MUST策略仍为Continue
        let strategy = handler.get_strategy(AnchorPriority::Must).await;
        assert_eq!(strategy, DegradationStrategy::Continue);
    }

    #[tokio::test]
    async fn test_emergency_clear() {
        let handler = create_test_handler();

        handler.handle_signal(DegradationSignal::AnchorCap, "Test1").await.unwrap();
        handler.handle_signal(DegradationSignal::EconDown, "Test2").await.unwrap();
        assert!(handler.is_degraded().await);

        handler.emergency_clear().await.unwrap();
        assert!(!handler.is_degraded().await);
    }

    #[tokio::test]
    async fn test_get_summary() {
        let handler = create_test_handler();

        handler.handle_signal(DegradationSignal::AnchorCap, "Test").await.unwrap();

        let summary = handler.get_summary().await;
        assert!(summary.is_degraded);
        assert_eq!(summary.active_signal_count, 1);
        assert!(summary.can_process_must);
        assert!(!summary.can_process_should);
        assert!(!summary.can_process_may);
    }

    #[tokio::test]
    async fn test_max_severity() {
        let handler = create_test_handler();

        assert_eq!(handler.max_severity().await, 0);

        handler.handle_signal(DegradationSignal::EconDown, "Test").await.unwrap();
        assert_eq!(handler.max_severity().await, DegradationSignal::EconDown.severity());

        handler.handle_signal(DegradationSignal::L0Down, "Test").await.unwrap();
        assert_eq!(handler.max_severity().await, DegradationSignal::L0Down.severity());
    }
}
