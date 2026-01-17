//! 降级信号定义
//!
//! 定义系统降级时的信号类型和处理策略。
//!
//! # 四类降级信号
//!
//! 1. DSN不可用 (DsnDown): 无法访问数据服务网络
//! 2. L0不可用 (L0Down): 无法获取新的epoch_root
//! 3. 经济系统不可用 (EconDown): 无法更新预算
//! 4. Cap预算耗尽 (AnchorCap): 锚定预算不足

use std::collections::HashSet;
use std::fmt;
use serde::{Deserialize, Serialize};

use crate::types::{AnchorPriority, Timestamp};

/// 降级信号类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradationSignal {
    /// DSN不可用 - 无法访问数据服务网络
    DsnDown,

    /// L0不可用 - 无法获取新的epoch_root
    L0Down,

    /// 经济系统不可用 - 无法更新预算
    EconDown,

    /// Cap预算耗尽 - 锚定预算不足
    AnchorCap,

    /// Bitcoin节点不可用
    BitcoinDown,

    /// 费率过高 - 超出最大费率限制
    FeeRateTooHigh,
}

impl fmt::Display for DegradationSignal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DsnDown => write!(f, "DSN_DOWN"),
            Self::L0Down => write!(f, "L0_DOWN"),
            Self::EconDown => write!(f, "ECON_DOWN"),
            Self::AnchorCap => write!(f, "ANCHOR_CAP"),
            Self::BitcoinDown => write!(f, "BITCOIN_DOWN"),
            Self::FeeRateTooHigh => write!(f, "FEE_RATE_TOO_HIGH"),
        }
    }
}

impl DegradationSignal {
    /// 获取信号的严重级别 (1-5, 5最严重)
    pub fn severity(&self) -> u8 {
        match self {
            Self::FeeRateTooHigh => 1,   // 低 - 可等待
            Self::EconDown => 2,         // 中低 - 使用缓存预算
            Self::AnchorCap => 3,        // 中 - 部分功能降级
            Self::DsnDown => 4,          // 高 - 影响数据获取
            Self::L0Down => 5,           // 最高 - 影响核心功能
            Self::BitcoinDown => 5,      // 最高 - 无法锚定
        }
    }

    /// 是否影响 MUST 级别任务
    pub fn affects_must(&self) -> bool {
        match self {
            Self::DsnDown => true,
            Self::L0Down => true,
            Self::BitcoinDown => true,
            Self::AnchorCap => false,    // MUST不受Cap影响，只排队
            Self::EconDown => false,
            Self::FeeRateTooHigh => false,
        }
    }

    /// 是否影响 SHOULD 级别任务
    pub fn affects_should(&self) -> bool {
        match self {
            Self::DsnDown => true,
            Self::L0Down => true,
            Self::BitcoinDown => true,
            Self::AnchorCap => true,     // SHOULD受Cap影响，暂停
            Self::EconDown => false,
            Self::FeeRateTooHigh => true,
        }
    }

    /// 是否影响 MAY 级别任务
    pub fn affects_may(&self) -> bool {
        // MAY级别受所有降级信号影响
        true
    }

    /// 检查是否可以处理指定优先级
    pub fn can_process(&self, priority: AnchorPriority) -> bool {
        match priority {
            AnchorPriority::Must => !self.affects_must(),
            AnchorPriority::Should => !self.affects_should(),
            AnchorPriority::May => !self.affects_may(),
        }
    }

    /// 获取推荐的恢复检查间隔（毫秒）
    pub fn recovery_check_interval_ms(&self) -> u64 {
        match self {
            Self::FeeRateTooHigh => 60_000,     // 1分钟
            Self::EconDown => 30_000,           // 30秒
            Self::AnchorCap => 60_000,          // 1分钟
            Self::DsnDown => 10_000,            // 10秒
            Self::L0Down => 5_000,              // 5秒
            Self::BitcoinDown => 15_000,        // 15秒
        }
    }
}

/// 降级事件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegradationEvent {
    /// 信号类型
    pub signal: DegradationSignal,

    /// 事件时间
    pub timestamp: Timestamp,

    /// 事件类型
    pub event_type: DegradationEventType,

    /// 原因描述
    pub reason: String,

    /// 关联的错误码
    pub error_code: Option<u32>,

    /// 元数据
    pub metadata: std::collections::HashMap<String, String>,
}

/// 降级事件类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradationEventType {
    /// 降级开始
    Started,
    /// 降级恢复
    Recovered,
    /// 降级升级（更严重）
    Escalated,
    /// 降级持续确认
    Confirmed,
}

impl DegradationEvent {
    /// 创建降级开始事件
    pub fn started(signal: DegradationSignal, reason: impl Into<String>) -> Self {
        Self {
            signal,
            timestamp: Timestamp::now(),
            event_type: DegradationEventType::Started,
            reason: reason.into(),
            error_code: None,
            metadata: std::collections::HashMap::new(),
        }
    }

    /// 创建恢复事件
    pub fn recovered(signal: DegradationSignal, reason: impl Into<String>) -> Self {
        Self {
            signal,
            timestamp: Timestamp::now(),
            event_type: DegradationEventType::Recovered,
            reason: reason.into(),
            error_code: None,
            metadata: std::collections::HashMap::new(),
        }
    }

    /// 添加错误码
    pub fn with_error_code(mut self, code: u32) -> Self {
        self.error_code = Some(code);
        self
    }

    /// 添加元数据
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// 降级状态
#[derive(Debug, Clone)]
pub struct DegradationState {
    /// 当前活跃的降级信号
    pub active_signals: HashSet<DegradationSignal>,

    /// 最近的降级事件
    pub recent_events: Vec<DegradationEvent>,

    /// 最大事件历史数量
    max_event_history: usize,
}

impl Default for DegradationState {
    fn default() -> Self {
        Self::new()
    }
}

impl DegradationState {
    /// 创建新的降级状态
    pub fn new() -> Self {
        Self {
            active_signals: HashSet::new(),
            recent_events: Vec::new(),
            max_event_history: 100,
        }
    }

    /// 添加降级信号
    pub fn add_signal(&mut self, signal: DegradationSignal, reason: impl Into<String>) {
        let is_new = self.active_signals.insert(signal);

        let event_type = if is_new {
            DegradationEventType::Started
        } else {
            DegradationEventType::Confirmed
        };

        self.add_event(DegradationEvent {
            signal,
            timestamp: Timestamp::now(),
            event_type,
            reason: reason.into(),
            error_code: None,
            metadata: std::collections::HashMap::new(),
        });

        if is_new {
            tracing::warn!("Degradation signal activated: {}", signal);
        }
    }

    /// 移除降级信号（恢复）
    pub fn remove_signal(&mut self, signal: DegradationSignal, reason: impl Into<String>) -> bool {
        let was_present = self.active_signals.remove(&signal);

        if was_present {
            self.add_event(DegradationEvent::recovered(signal, reason));
            tracing::info!("Degradation signal recovered: {}", signal);
        }

        was_present
    }

    /// 添加事件到历史
    fn add_event(&mut self, event: DegradationEvent) {
        self.recent_events.push(event);

        // 保持历史大小限制
        if self.recent_events.len() > self.max_event_history {
            self.recent_events.remove(0);
        }
    }

    /// 检查是否有活跃的降级信号
    pub fn is_degraded(&self) -> bool {
        !self.active_signals.is_empty()
    }

    /// 检查特定信号是否活跃
    pub fn has_signal(&self, signal: DegradationSignal) -> bool {
        self.active_signals.contains(&signal)
    }

    /// 获取最高严重级别
    pub fn max_severity(&self) -> u8 {
        self.active_signals
            .iter()
            .map(|s| s.severity())
            .max()
            .unwrap_or(0)
    }

    /// 检查是否可以处理指定优先级
    pub fn can_process(&self, priority: AnchorPriority) -> bool {
        // 如果没有降级信号，可以处理任何优先级
        if self.active_signals.is_empty() {
            return true;
        }

        // 检查所有活跃信号是否允许处理该优先级
        self.active_signals.iter().all(|s| s.can_process(priority))
    }

    /// 获取阻止指定优先级处理的信号
    pub fn blocking_signals(&self, priority: AnchorPriority) -> Vec<DegradationSignal> {
        self.active_signals
            .iter()
            .filter(|s| !s.can_process(priority))
            .copied()
            .collect()
    }

    /// 获取所有活跃信号
    pub fn get_active_signals(&self) -> Vec<DegradationSignal> {
        self.active_signals.iter().copied().collect()
    }

    /// 获取最近的事件
    pub fn get_recent_events(&self, limit: usize) -> Vec<DegradationEvent> {
        self.recent_events
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// 清除所有信号（紧急恢复）
    pub fn clear_all(&mut self) {
        for signal in self.active_signals.clone() {
            self.remove_signal(signal, "Emergency clear");
        }
    }
}

/// 降级策略
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradationStrategy {
    /// 继续处理（忽略降级）
    Continue,
    /// 暂停处理
    Pause,
    /// 丢弃任务（仅MAY级别）
    Drop,
    /// 排队等待
    Queue,
    /// 重试后再决定
    Retry,
}

/// 根据信号和优先级决定策略
pub fn determine_strategy(
    signal: DegradationSignal,
    priority: AnchorPriority,
) -> DegradationStrategy {
    match (signal, priority) {
        // MUST级别 - 永不丢弃
        (_, AnchorPriority::Must) => {
            if signal.affects_must() {
                DegradationStrategy::Queue
            } else {
                DegradationStrategy::Continue
            }
        }

        // SHOULD级别 - 可暂停但不丢弃
        (DegradationSignal::AnchorCap, AnchorPriority::Should) => DegradationStrategy::Pause,
        (DegradationSignal::FeeRateTooHigh, AnchorPriority::Should) => DegradationStrategy::Pause,
        (_, AnchorPriority::Should) => {
            if signal.affects_should() {
                DegradationStrategy::Queue
            } else {
                DegradationStrategy::Continue
            }
        }

        // MAY级别 - 可丢弃
        (DegradationSignal::AnchorCap, AnchorPriority::May) => DegradationStrategy::Drop,
        (DegradationSignal::FeeRateTooHigh, AnchorPriority::May) => DegradationStrategy::Drop,
        (_, AnchorPriority::May) => {
            if signal.severity() >= 4 {
                DegradationStrategy::Drop
            } else {
                DegradationStrategy::Pause
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signal_severity() {
        assert!(DegradationSignal::L0Down.severity() > DegradationSignal::EconDown.severity());
        assert!(DegradationSignal::BitcoinDown.severity() > DegradationSignal::AnchorCap.severity());
    }

    #[test]
    fn test_signal_affects_priority() {
        let cap = DegradationSignal::AnchorCap;

        // Cap不影响MUST
        assert!(!cap.affects_must());
        // Cap影响SHOULD
        assert!(cap.affects_should());
        // Cap影响MAY
        assert!(cap.affects_may());
    }

    #[test]
    fn test_degradation_state() {
        let mut state = DegradationState::new();

        assert!(!state.is_degraded());

        state.add_signal(DegradationSignal::AnchorCap, "Budget exhausted");
        assert!(state.is_degraded());
        assert!(state.has_signal(DegradationSignal::AnchorCap));

        // MUST可处理
        assert!(state.can_process(AnchorPriority::Must));
        // SHOULD不可处理
        assert!(!state.can_process(AnchorPriority::Should));
        // MAY不可处理
        assert!(!state.can_process(AnchorPriority::May));
    }

    #[test]
    fn test_remove_signal() {
        let mut state = DegradationState::new();

        state.add_signal(DegradationSignal::EconDown, "Econ unavailable");
        assert!(state.is_degraded());

        let removed = state.remove_signal(DegradationSignal::EconDown, "Econ recovered");
        assert!(removed);
        assert!(!state.is_degraded());
    }

    #[test]
    fn test_determine_strategy() {
        // MUST + Cap = Queue (not drop)
        assert_eq!(
            determine_strategy(DegradationSignal::AnchorCap, AnchorPriority::Must),
            DegradationStrategy::Continue  // Cap doesn't affect MUST
        );

        // SHOULD + Cap = Pause
        assert_eq!(
            determine_strategy(DegradationSignal::AnchorCap, AnchorPriority::Should),
            DegradationStrategy::Pause
        );

        // MAY + Cap = Drop
        assert_eq!(
            determine_strategy(DegradationSignal::AnchorCap, AnchorPriority::May),
            DegradationStrategy::Drop
        );

        // MUST + L0Down = Queue
        assert_eq!(
            determine_strategy(DegradationSignal::L0Down, AnchorPriority::Must),
            DegradationStrategy::Queue
        );
    }

    #[test]
    fn test_max_severity() {
        let mut state = DegradationState::new();

        assert_eq!(state.max_severity(), 0);

        state.add_signal(DegradationSignal::EconDown, "test");
        assert_eq!(state.max_severity(), DegradationSignal::EconDown.severity());

        state.add_signal(DegradationSignal::L0Down, "test");
        assert_eq!(state.max_severity(), DegradationSignal::L0Down.severity());
    }

    #[test]
    fn test_blocking_signals() {
        let mut state = DegradationState::new();

        state.add_signal(DegradationSignal::AnchorCap, "Cap exhausted");
        state.add_signal(DegradationSignal::EconDown, "Econ down");

        // MUST is only blocked by... nothing in this case (Cap doesn't affect MUST, EconDown doesn't affect MUST)
        let must_blockers = state.blocking_signals(AnchorPriority::Must);
        assert!(must_blockers.is_empty());

        // SHOULD is blocked by Cap
        let should_blockers = state.blocking_signals(AnchorPriority::Should);
        assert!(should_blockers.contains(&DegradationSignal::AnchorCap));
    }
}
