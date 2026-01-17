//! 锚定对象池
//!
//! 管理待锚定输入的三级优先队列。
//!
//! # 设计原则
//!
//! - MUST 不可丢弃，必须持久化
//! - SHOULD 可延迟，但不可随意丢弃
//! - MAY 可根据预算情况丢弃
//! - 优先级调度：MUST > SHOULD > MAY

use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::{P4Error, P4Result};
use crate::policy::{ChainAnchorPolicyVersion, PoolConfig};
use crate::storage::AnchorStorage;
use crate::types::{AnchorPriority, ChainAnchorInput, InputId, Timestamp};

/// 锚定对象池
pub struct AnchorPool<S: AnchorStorage> {
    /// MUST池（不可丢弃）
    must_pool: Arc<RwLock<PriorityQueue>>,

    /// SHOULD池
    should_pool: Arc<RwLock<PriorityQueue>>,

    /// MAY池
    may_pool: Arc<RwLock<PriorityQueue>>,

    /// 策略版本
    policy: Arc<RwLock<ChainAnchorPolicyVersion>>,

    /// 持久化存储
    storage: Arc<S>,

    /// 池统计信息
    stats: Arc<RwLock<PoolStats>>,
}

/// 优先队列
#[derive(Debug, Default)]
pub struct PriorityQueue {
    /// 队列中的输入
    items: VecDeque<QueueItem>,

    /// 配置
    config: PoolConfig,
}

/// 队列项
#[derive(Debug, Clone)]
pub struct QueueItem {
    /// 输入
    pub input: ChainAnchorInput,

    /// 入队时间
    pub enqueued_at: Timestamp,

    /// 优先级分数（用于内部排序）
    pub priority_score: u64,
}

/// 池统计信息
#[derive(Debug, Clone, Default)]
pub struct PoolStats {
    /// MUST 池大小
    pub must_size: usize,

    /// SHOULD 池大小
    pub should_size: usize,

    /// MAY 池大小
    pub may_size: usize,

    /// 总入队数
    pub total_enqueued: u64,

    /// 总出队数
    pub total_dequeued: u64,

    /// 总丢弃数（降级丢弃）
    pub total_dropped: u64,

    /// 总超时数
    pub total_expired: u64,
}

/// 降级信号
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DegradationSignal {
    /// DSN 不可用
    DsnDown,
    /// L0 不可用
    L0Down,
    /// 经济系统不可用
    EconDown,
    /// Cap 预算耗尽
    CapExhausted,
}

impl PriorityQueue {
    /// 创建新队列
    pub fn new(config: PoolConfig) -> Self {
        Self {
            items: VecDeque::new(),
            config,
        }
    }

    /// 入队
    pub fn push(&mut self, input: ChainAnchorInput) -> P4Result<()> {
        // 检查队列是否已满
        if self.items.len() >= self.config.max_queue_size {
            return Err(P4Error::InvalidInput(format!(
                "Queue full: {} items",
                self.items.len()
            )));
        }

        let item = QueueItem {
            priority_score: Self::calculate_priority_score(&input),
            input,
            enqueued_at: Timestamp::now(),
        };

        // 按优先级插入（高优先级在前）
        let pos = self.items.iter()
            .position(|i| i.priority_score < item.priority_score)
            .unwrap_or(self.items.len());

        self.items.insert(pos, item);
        Ok(())
    }

    /// 出队
    pub fn pop(&mut self) -> Option<ChainAnchorInput> {
        self.items.pop_front().map(|item| item.input)
    }

    /// 查看队首
    pub fn peek(&self) -> Option<&ChainAnchorInput> {
        self.items.front().map(|item| &item.input)
    }

    /// 队列大小
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// 是否为空
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// 清空队列
    pub fn clear(&mut self) -> Vec<ChainAnchorInput> {
        self.items.drain(..).map(|item| item.input).collect()
    }

    /// 移除过期项
    pub fn remove_expired(&mut self) -> Vec<ChainAnchorInput> {
        let now = Timestamp::now();
        let max_wait = self.config.max_wait_duration_ms;

        let mut expired = Vec::new();
        self.items.retain(|item| {
            let elapsed = now.as_millis() - item.enqueued_at.as_millis();
            if elapsed > max_wait {
                expired.push(item.input.clone());
                false
            } else {
                true
            }
        });

        expired
    }

    /// 按 input_id 移除
    pub fn remove_by_id(&mut self, input_id: &InputId) -> Option<ChainAnchorInput> {
        let pos = self.items.iter().position(|item| &item.input.input_id == input_id)?;
        self.items.remove(pos).map(|item| item.input)
    }

    /// 计算优先级分数
    fn calculate_priority_score(input: &ChainAnchorInput) -> u64 {
        // 基础分数：epoch_sequence（越早越优先）
        let base_score = u64::MAX - input.epoch_sequence;

        // 时间因素：等待时间越长优先级越高
        let age_bonus = Timestamp::now().as_millis().saturating_sub(input.created_at.as_millis()) / 1000;

        base_score.saturating_add(age_bonus)
    }
}

impl<S: AnchorStorage + 'static> AnchorPool<S> {
    /// 创建新的对象池
    pub fn new(storage: Arc<S>, policy: ChainAnchorPolicyVersion) -> Self {
        Self {
            must_pool: Arc::new(RwLock::new(PriorityQueue::new(policy.must_pool.clone()))),
            should_pool: Arc::new(RwLock::new(PriorityQueue::new(policy.should_pool.clone()))),
            may_pool: Arc::new(RwLock::new(PriorityQueue::new(policy.may_pool.clone()))),
            policy: Arc::new(RwLock::new(policy)),
            storage,
            stats: Arc::new(RwLock::new(PoolStats::default())),
        }
    }

    /// 入队
    pub async fn enqueue(&self, input: ChainAnchorInput) -> P4Result<()> {
        let priority = input.priority;

        match priority {
            AnchorPriority::Must => {
                // MUST 级别必须持久化
                self.storage.persist_must_input(&input).await?;
                self.must_pool.write().await.push(input)?;
            }
            AnchorPriority::Should => {
                self.should_pool.write().await.push(input)?;
            }
            AnchorPriority::May => {
                self.may_pool.write().await.push(input)?;
            }
        }

        // 更新统计
        let mut stats = self.stats.write().await;
        stats.total_enqueued += 1;
        match priority {
            AnchorPriority::Must => stats.must_size += 1,
            AnchorPriority::Should => stats.should_size += 1,
            AnchorPriority::May => stats.may_size += 1,
        }

        Ok(())
    }

    /// 出队（按优先级）
    pub async fn dequeue(&self) -> Option<ChainAnchorInput> {
        // 优先处理 MUST
        if let Some(input) = self.must_pool.write().await.pop() {
            self.update_dequeue_stats(AnchorPriority::Must).await;
            return Some(input);
        }

        // 其次 SHOULD
        if let Some(input) = self.should_pool.write().await.pop() {
            self.update_dequeue_stats(AnchorPriority::Should).await;
            return Some(input);
        }

        // 最后 MAY
        if let Some(input) = self.may_pool.write().await.pop() {
            self.update_dequeue_stats(AnchorPriority::May).await;
            return Some(input);
        }

        None
    }

    /// 批量出队
    pub async fn dequeue_batch(&self, max_count: usize) -> Vec<ChainAnchorInput> {
        let mut batch = Vec::with_capacity(max_count);

        for _ in 0..max_count {
            match self.dequeue().await {
                Some(input) => batch.push(input),
                None => break,
            }
        }

        batch
    }

    /// 降级处理
    pub async fn handle_degradation(&self, signal: DegradationSignal) -> P4Result<DegradationResult> {
        let mut result = DegradationResult::default();

        match signal {
            DegradationSignal::CapExhausted => {
                // Cap 耗尽：MAY 池可丢弃，SHOULD 池暂停，MUST 池保留
                let policy = self.policy.read().await;
                if policy.may_pool.allow_drop_on_degradation {
                    let dropped = self.may_pool.write().await.clear();
                    result.dropped_count = dropped.len();

                    let mut stats = self.stats.write().await;
                    stats.total_dropped += dropped.len() as u64;
                    stats.may_size = 0;
                }
            }
            DegradationSignal::DsnDown | DegradationSignal::L0Down => {
                // DSN/L0 不可用：所有池暂停，MUST 池持久化
                self.persist_must_pool().await?;
                result.must_persisted = true;
            }
            DegradationSignal::EconDown => {
                // 经济系统不可用：继续使用缓存预算
                // 不做额外处理
            }
        }

        tracing::warn!(
            "Degradation handled: {:?}, dropped={}, persisted={}",
            signal,
            result.dropped_count,
            result.must_persisted
        );

        Ok(result)
    }

    /// 持久化 MUST 池
    pub async fn persist_must_pool(&self) -> P4Result<usize> {
        let pool = self.must_pool.read().await;
        let mut count = 0;

        for item in pool.items.iter() {
            self.storage.persist_must_input(&item.input).await?;
            count += 1;
        }

        Ok(count)
    }

    /// 从持久化存储恢复 MUST 池
    pub async fn restore_must_pool(&self) -> P4Result<usize> {
        let inputs = self.storage.load_persisted_must_inputs().await?;
        let count = inputs.len();

        let mut pool = self.must_pool.write().await;
        for input in inputs {
            let _ = pool.push(input); // 忽略可能的队列满错误
        }

        let mut stats = self.stats.write().await;
        stats.must_size = pool.len();

        tracing::info!("Restored {} MUST inputs from persistence", count);

        Ok(count)
    }

    /// 清理过期项
    pub async fn cleanup_expired(&self) -> ExpiredCleanupResult {
        let mut result = ExpiredCleanupResult::default();

        // MUST 池不清理过期（只记录）
        let must_expired = self.must_pool.write().await.remove_expired();
        result.must_expired = must_expired.len();

        // SHOULD 池过期项重新入队到 MAY（降级）
        let should_expired = self.should_pool.write().await.remove_expired();
        result.should_expired = should_expired.len();

        // MAY 池过期项直接丢弃
        let may_expired = self.may_pool.write().await.remove_expired();
        result.may_expired = may_expired.len();

        // 更新统计
        let mut stats = self.stats.write().await;
        stats.total_expired += (result.must_expired + result.should_expired + result.may_expired) as u64;
        stats.must_size = self.must_pool.read().await.len();
        stats.should_size = self.should_pool.read().await.len();
        stats.may_size = self.may_pool.read().await.len();

        result
    }

    /// 获取池统计
    pub async fn stats(&self) -> PoolStats {
        let mut stats = self.stats.read().await.clone();
        stats.must_size = self.must_pool.read().await.len();
        stats.should_size = self.should_pool.read().await.len();
        stats.may_size = self.may_pool.read().await.len();
        stats
    }

    /// 更新策略
    pub async fn update_policy(&self, policy: ChainAnchorPolicyVersion) {
        *self.policy.write().await = policy.clone();
        self.must_pool.write().await.config = policy.must_pool;
        self.should_pool.write().await.config = policy.should_pool;
        self.may_pool.write().await.config = policy.may_pool;
    }

    /// 更新出队统计
    async fn update_dequeue_stats(&self, priority: AnchorPriority) {
        let mut stats = self.stats.write().await;
        stats.total_dequeued += 1;
        match priority {
            AnchorPriority::Must => stats.must_size = stats.must_size.saturating_sub(1),
            AnchorPriority::Should => stats.should_size = stats.should_size.saturating_sub(1),
            AnchorPriority::May => stats.may_size = stats.may_size.saturating_sub(1),
        }
    }

    /// 丢弃 MAY 池（降级时使用）
    pub async fn drop_may_pool(&self) -> P4Result<usize> {
        let dropped = self.may_pool.write().await.clear();
        let count = dropped.len();

        let mut stats = self.stats.write().await;
        stats.total_dropped += count as u64;
        stats.may_size = 0;

        tracing::warn!("Dropped {} items from MAY pool", count);
        Ok(count)
    }

    /// 获取队列大小
    pub async fn queue_sizes(&self) -> (usize, usize, usize) {
        (
            self.must_pool.read().await.len(),
            self.should_pool.read().await.len(),
            self.may_pool.read().await.len(),
        )
    }

    /// 检查是否有待处理项
    pub async fn has_pending(&self) -> bool {
        !self.must_pool.read().await.is_empty()
            || !self.should_pool.read().await.is_empty()
            || !self.may_pool.read().await.is_empty()
    }

    /// 获取总待处理数
    pub async fn total_pending(&self) -> usize {
        let (must, should, may) = self.queue_sizes().await;
        must + should + may
    }
}

/// 降级处理结果
#[derive(Debug, Clone, Default)]
pub struct DegradationResult {
    /// 丢弃的输入数
    pub dropped_count: usize,
    /// MUST 池是否已持久化
    pub must_persisted: bool,
}

/// 过期清理结果
#[derive(Debug, Clone, Default)]
pub struct ExpiredCleanupResult {
    /// MUST 过期数（不会被丢弃）
    pub must_expired: usize,
    /// SHOULD 过期数
    pub should_expired: usize,
    /// MAY 过期数
    pub may_expired: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;

    fn create_test_input(priority: AnchorPriority, epoch_seq: u64) -> ChainAnchorInput {
        ChainAnchorInput::new(
            epoch_seq,
            [0x12; 32],
            [0x34; 32],
            priority,
        )
    }

    #[tokio::test]
    async fn test_priority_ordering() {
        let storage = Arc::new(MemoryStorage::new());
        let policy = ChainAnchorPolicyVersion::default();
        let pool = AnchorPool::new(storage, policy);

        // 入队不同优先级
        pool.enqueue(create_test_input(AnchorPriority::May, 3)).await.unwrap();
        pool.enqueue(create_test_input(AnchorPriority::Should, 2)).await.unwrap();
        pool.enqueue(create_test_input(AnchorPriority::Must, 1)).await.unwrap();

        // 出队顺序应该是 MUST > SHOULD > MAY
        let first = pool.dequeue().await.unwrap();
        assert_eq!(first.priority, AnchorPriority::Must);

        let second = pool.dequeue().await.unwrap();
        assert_eq!(second.priority, AnchorPriority::Should);

        let third = pool.dequeue().await.unwrap();
        assert_eq!(third.priority, AnchorPriority::May);
    }

    #[tokio::test]
    async fn test_pool_stats() {
        let storage = Arc::new(MemoryStorage::new());
        let policy = ChainAnchorPolicyVersion::default();
        let pool = AnchorPool::new(storage, policy);

        pool.enqueue(create_test_input(AnchorPriority::Must, 1)).await.unwrap();
        pool.enqueue(create_test_input(AnchorPriority::Should, 2)).await.unwrap();
        pool.enqueue(create_test_input(AnchorPriority::May, 3)).await.unwrap();

        let stats = pool.stats().await;
        assert_eq!(stats.must_size, 1);
        assert_eq!(stats.should_size, 1);
        assert_eq!(stats.may_size, 1);
        assert_eq!(stats.total_enqueued, 3);
    }

    #[tokio::test]
    async fn test_degradation_drop_may() {
        let storage = Arc::new(MemoryStorage::new());
        let policy = ChainAnchorPolicyVersion::default();
        let pool = AnchorPool::new(storage, policy);

        pool.enqueue(create_test_input(AnchorPriority::Must, 1)).await.unwrap();
        pool.enqueue(create_test_input(AnchorPriority::May, 2)).await.unwrap();
        pool.enqueue(create_test_input(AnchorPriority::May, 3)).await.unwrap();

        let result = pool.handle_degradation(DegradationSignal::CapExhausted).await.unwrap();
        assert_eq!(result.dropped_count, 2); // MAY 被丢弃

        let stats = pool.stats().await;
        assert_eq!(stats.must_size, 1); // MUST 保留
        assert_eq!(stats.may_size, 0);  // MAY 被清空
    }
}
