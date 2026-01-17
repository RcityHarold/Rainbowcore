//! P4 Service Builder
//!
//! 提供 P4Service 的构建器模式。

use std::sync::Arc;
use tokio::sync::RwLock;

use crate::bitcoin::BitcoinRpcClient;
use crate::cap::{CapManager, AccountingLedger};
use crate::degradation::{DegradationHandler, DegradationConfig};
use crate::error::{P4Error, P4Result};
use crate::policy::{PolicyManager, ChainAnchorPolicyVersion};
use crate::pool::AnchorPool;
use crate::storage::AnchorStorage;
use crate::tx_builder::AnchorTxBuilder;

use super::{P4Service, P4ServiceConfig, ServiceStatus, ServiceStats};

/// P4 Service Builder
pub struct P4ServiceBuilder<S: AnchorStorage + 'static> {
    config: Option<P4ServiceConfig>,
    storage: Option<Arc<S>>,
    bitcoin_rpc: Option<Arc<BitcoinRpcClient>>,
    policy_version: Option<ChainAnchorPolicyVersion>,
}

impl<S: AnchorStorage + 'static> P4ServiceBuilder<S> {
    /// 创建新的 Builder
    pub fn new() -> Self {
        Self {
            config: None,
            storage: None,
            bitcoin_rpc: None,
            policy_version: None,
        }
    }

    /// 设置配置
    pub fn config(mut self, config: P4ServiceConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// 设置存储
    pub fn storage(mut self, storage: Arc<S>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// 设置 Bitcoin RPC 客户端
    pub fn bitcoin_rpc(mut self, rpc: Arc<BitcoinRpcClient>) -> Self {
        self.bitcoin_rpc = Some(rpc);
        self
    }

    /// 设置策略版本
    pub fn policy_version(mut self, version: ChainAnchorPolicyVersion) -> Self {
        self.policy_version = Some(version);
        self
    }

    /// 构建服务
    pub async fn build(self) -> P4Result<P4Service<S>> {
        let config = self.config.unwrap_or_default();
        let storage = self.storage.ok_or_else(|| {
            P4Error::Configuration("Storage is required".to_string())
        })?;

        // 创建或使用提供的 Bitcoin RPC
        let bitcoin_rpc = match self.bitcoin_rpc {
            Some(rpc) => rpc,
            None => {
                let rpc = BitcoinRpcClient::new(config.p4_config.bitcoin.clone())?;
                Arc::new(rpc)
            }
        };

        // 创建交易构建器
        let tx_builder = Arc::new(AnchorTxBuilder::new(
            bitcoin_rpc.clone(),
            config.p4_config.clone(),
        ));

        // 创建策略版本
        let policy_version = self.policy_version.unwrap_or_default();

        // 创建策略管理器
        let policy_manager = Arc::new(PolicyManager::new(policy_version.clone()));

        // 创建 Cap 管理器
        let cap_manager = Arc::new(CapManager::new(
            config.cap_config.daily_budget_cap,
            config.cap_config.clone(),
        ));

        // 创建锚定池
        let pool = Arc::new(AnchorPool::new(
            storage.clone(),
            policy_version.clone(),
        ));

        // 创建降级处理器
        let degradation_handler = Arc::new(DegradationHandler::new(
            pool.clone(),
            cap_manager.clone(),
            DegradationConfig::default(),
        ));

        // 从降级处理器获取恢复管理器
        let recovery_manager = degradation_handler.recovery_manager().clone();

        // 创建会计账本
        let accounting = Arc::new(RwLock::new(AccountingLedger::new()));

        Ok(P4Service {
            config,
            storage,
            bitcoin_rpc,
            tx_builder,
            pool,
            cap_manager,
            degradation_handler,
            recovery_manager,
            policy_manager,
            accounting,
            status: Arc::new(RwLock::new(ServiceStatus::Initializing)),
            stats: Arc::new(RwLock::new(ServiceStats::default())),
            runner_handle: Arc::new(RwLock::new(None)),
        })
    }
}

impl<S: AnchorStorage + 'static> Default for P4ServiceBuilder<S> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;

    #[tokio::test]
    async fn test_builder_requires_storage() {
        let result = P4ServiceBuilder::<MemoryStorage>::new()
            .config(P4ServiceConfig::development())
            .build()
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_builder_with_storage() {
        let storage = Arc::new(MemoryStorage::new());
        let result = P4ServiceBuilder::new()
            .config(P4ServiceConfig::development())
            .storage(storage)
            .build()
            .await;

        // Builder 成功构建服务（RPC 客户端仅在实际调用时才连接）
        assert!(result.is_ok());

        let service = result.unwrap();
        assert_eq!(service.config().required_confirmations, 1);
    }
}
