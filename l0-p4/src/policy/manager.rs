//! 策略管理器
//!
//! 管理 ChainAnchorPolicyVersion 的生命周期。
//!
//! # 设计原则
//!
//! - 策略变更必须有公示期
//! - 支持策略回滚
//! - 保留历史策略用于验证

use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::{P4Error, P4Result};
use crate::types::Timestamp;

use super::version::ChainAnchorPolicyVersion;

/// 策略管理器
pub struct PolicyManager {
    /// 当前活跃策略
    current_policy: Arc<RwLock<ChainAnchorPolicyVersion>>,

    /// 历史策略（按版本号索引）
    history: Arc<RwLock<BTreeMap<u32, ChainAnchorPolicyVersion>>>,

    /// 待生效策略（已公示但未生效）
    pending_policy: Arc<RwLock<Option<ChainAnchorPolicyVersion>>>,

    /// 策略变更监听器
    change_listeners: Arc<RwLock<Vec<Box<dyn PolicyChangeListener>>>>,
}

/// 策略变更监听器
#[async_trait::async_trait]
pub trait PolicyChangeListener: Send + Sync {
    /// 策略即将变更
    async fn on_policy_pending(&self, new_policy: &ChainAnchorPolicyVersion);

    /// 策略已变更
    async fn on_policy_changed(&self, old_policy: &ChainAnchorPolicyVersion, new_policy: &ChainAnchorPolicyVersion);
}

impl PolicyManager {
    /// 创建新的策略管理器
    pub fn new(initial_policy: ChainAnchorPolicyVersion) -> Self {
        let version = initial_policy.version;
        let mut history = BTreeMap::new();
        history.insert(version, initial_policy.clone());

        Self {
            current_policy: Arc::new(RwLock::new(initial_policy)),
            history: Arc::new(RwLock::new(history)),
            pending_policy: Arc::new(RwLock::new(None)),
            change_listeners: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// 使用默认策略创建
    pub fn with_default() -> Self {
        Self::new(ChainAnchorPolicyVersion::default())
    }

    /// 获取当前策略
    pub async fn current(&self) -> ChainAnchorPolicyVersion {
        self.current_policy.read().await.clone()
    }

    /// 获取当前策略的引用
    pub async fn current_ref(&self) -> tokio::sync::RwLockReadGuard<'_, ChainAnchorPolicyVersion> {
        self.current_policy.read().await
    }

    /// 获取指定版本的策略
    pub async fn get_version(&self, version: u32) -> Option<ChainAnchorPolicyVersion> {
        self.history.read().await.get(&version).cloned()
    }

    /// 获取最新版本号
    pub async fn latest_version(&self) -> u32 {
        self.current_policy.read().await.version
    }

    /// 提交新策略（进入公示期）
    pub async fn submit_new_policy(&self, policy: ChainAnchorPolicyVersion) -> P4Result<()> {
        // 验证版本号递增
        let current = self.current_policy.read().await;
        if policy.version <= current.version {
            return Err(P4Error::InvalidInput(format!(
                "New policy version {} must be greater than current version {}",
                policy.version, current.version
            )));
        }
        drop(current);

        // 验证生效时间在未来
        if policy.effective_from <= Timestamp::now() {
            return Err(P4Error::InvalidInput(
                "New policy effective_from must be in the future".to_string()
            ));
        }

        // 设置为待生效
        *self.pending_policy.write().await = Some(policy.clone());

        // 通知监听器
        let listeners = self.change_listeners.read().await;
        for listener in listeners.iter() {
            listener.on_policy_pending(&policy).await;
        }

        tracing::info!(
            "New policy version {} submitted, effective from {:?}",
            policy.version,
            policy.effective_from
        );

        Ok(())
    }

    /// 激活待生效策略
    pub async fn activate_pending_policy(&self) -> P4Result<bool> {
        let pending = self.pending_policy.read().await.clone();

        if let Some(new_policy) = pending {
            // 检查是否已到生效时间
            if new_policy.effective_from <= Timestamp::now() {
                let old_policy = self.current_policy.read().await.clone();

                // 更新当前策略
                *self.current_policy.write().await = new_policy.clone();

                // 添加到历史
                self.history.write().await.insert(new_policy.version, new_policy.clone());

                // 清除待生效
                *self.pending_policy.write().await = None;

                // 通知监听器
                let listeners = self.change_listeners.read().await;
                for listener in listeners.iter() {
                    listener.on_policy_changed(&old_policy, &new_policy).await;
                }

                tracing::info!(
                    "Policy activated: {} -> {}",
                    old_policy.version,
                    new_policy.version
                );

                return Ok(true);
            }
        }

        Ok(false)
    }

    /// 取消待生效策略
    pub async fn cancel_pending_policy(&self) -> P4Result<Option<ChainAnchorPolicyVersion>> {
        let pending = self.pending_policy.write().await.take();

        if let Some(ref policy) = pending {
            tracing::info!("Pending policy version {} cancelled", policy.version);
        }

        Ok(pending)
    }

    /// 获取待生效策略
    pub async fn get_pending(&self) -> Option<ChainAnchorPolicyVersion> {
        self.pending_policy.read().await.clone()
    }

    /// 添加策略变更监听器
    pub async fn add_listener(&self, listener: Box<dyn PolicyChangeListener>) {
        self.change_listeners.write().await.push(listener);
    }

    /// 检查策略是否有待生效更新
    pub async fn has_pending_update(&self) -> bool {
        self.pending_policy.read().await.is_some()
    }

    /// 获取历史策略列表
    pub async fn list_history(&self) -> Vec<ChainAnchorPolicyVersion> {
        self.history.read().await.values().cloned().collect()
    }

    /// 回滚到指定版本
    pub async fn rollback_to_version(&self, version: u32) -> P4Result<()> {
        let history = self.history.read().await;

        let target_policy = history.get(&version).ok_or_else(|| {
            P4Error::InvalidInput(format!("Policy version {} not found in history", version))
        })?;

        let old_policy = self.current_policy.read().await.clone();

        if target_policy.version >= old_policy.version {
            return Err(P4Error::InvalidInput(
                "Rollback target must be an earlier version".to_string()
            ));
        }

        // 创建回滚策略（新版本号，但使用旧配置）
        let mut rollback_policy = target_policy.clone();
        rollback_policy.version = old_policy.version + 1;
        rollback_policy.effective_from = Timestamp::now();
        rollback_policy.description = format!(
            "Rollback to version {} configuration",
            version
        );

        drop(history);

        // 直接激活（紧急回滚不需要公示期）
        *self.current_policy.write().await = rollback_policy.clone();
        self.history.write().await.insert(rollback_policy.version, rollback_policy.clone());

        // 通知监听器
        let listeners = self.change_listeners.read().await;
        for listener in listeners.iter() {
            listener.on_policy_changed(&old_policy, &rollback_policy).await;
        }

        tracing::warn!(
            "Emergency rollback: {} -> {} (based on {})",
            old_policy.version,
            rollback_policy.version,
            version
        );

        Ok(())
    }
}

impl Default for PolicyManager {
    fn default() -> Self {
        Self::with_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_policy_manager() {
        let manager = PolicyManager::with_default();
        let policy = manager.current().await;
        assert_eq!(policy.version, 1);
    }

    #[tokio::test]
    async fn test_submit_new_policy() {
        let manager = PolicyManager::with_default();

        let mut new_policy = ChainAnchorPolicyVersion::new(2);
        new_policy.effective_from = Timestamp::from_millis(
            Timestamp::now().as_millis() + 3600_000 // 1小时后
        );

        let result = manager.submit_new_policy(new_policy).await;
        assert!(result.is_ok());
        assert!(manager.has_pending_update().await);
    }

    #[tokio::test]
    async fn test_reject_lower_version() {
        let manager = PolicyManager::with_default();

        let mut new_policy = ChainAnchorPolicyVersion::new(0); // 版本号太低
        new_policy.effective_from = Timestamp::from_millis(
            Timestamp::now().as_millis() + 3600_000
        );

        let result = manager.submit_new_policy(new_policy).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_cancel_pending() {
        let manager = PolicyManager::with_default();

        let mut new_policy = ChainAnchorPolicyVersion::new(2);
        new_policy.effective_from = Timestamp::from_millis(
            Timestamp::now().as_millis() + 3600_000
        );

        manager.submit_new_policy(new_policy).await.unwrap();
        assert!(manager.has_pending_update().await);

        let cancelled = manager.cancel_pending_policy().await.unwrap();
        assert!(cancelled.is_some());
        assert!(!manager.has_pending_update().await);
    }

    #[tokio::test]
    async fn test_get_version_history() {
        let manager = PolicyManager::with_default();

        let history = manager.list_history().await;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].version, 1);
    }
}
