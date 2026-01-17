//! L0 Core Layer Integration
//!
//! 提供与 L0 核心层的集成接口，用于：
//! - 获取当前 Epoch 信息
//! - 获取 Epoch Root
//! - 更新 Epoch 锚定状态
//! - 获取待锚定的 Epoch 列表
//! - 获取关联收据摘要
//!
//! ## 架构
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    L0Integration                         │
//! │  (trait: get_epoch, update_status, get_receipt_digest)  │
//! └─────────────────────────────────────────────────────────┘
//!                            │
//!              ┌─────────────┴─────────────┐
//!              │                           │
//!              ▼                           ▼
//! ┌─────────────────────┐     ┌─────────────────────────────┐
//! │  MockL0Integration  │     │    L0IntegrationImpl        │
//! │    (for testing)    │     │  ┌─────────────────────┐    │
//! └─────────────────────┘     │  │    EpochLedger      │    │
//!                             │  └─────────────────────┘    │
//!                             │  ┌─────────────────────┐    │
//!                             │  │ReceiptDigestProvider│    │
//!                             │  └─────────────────────┘    │
//!                             └─────────────────────────────┘
//! ```

use std::sync::Arc;
use std::collections::HashMap;
use async_trait::async_trait;
use sha2::{Sha256, Digest as Sha2Digest};
use tokio::sync::RwLock;
use tracing::{info, warn, debug};

use crate::error::{P4Error, P4Result};
use crate::types::{ChainAnchorInput, AnchorPriority, Timestamp, PolicyVersion, CanonVersion};

use super::{EpochInfo, EpochAnchorState};

// ============================================================================
// Receipt Digest Provider
// ============================================================================

/// 收据摘要提供者 Trait
///
/// 用于计算或获取指定 Epoch 的关联收据 ID 摘要。
/// 不同的实现可以使用不同的策略：
/// - 缓存/回退：使用预设值或基于 epoch_root 计算
/// - ReceiptLedger：从实际的收据账本查询并计算
#[async_trait]
pub trait ReceiptDigestProvider: Send + Sync {
    /// 获取指定 Epoch 的收据摘要
    async fn get_receipt_digest(&self, epoch_seq: u64, epoch_root: &[u8; 32]) -> P4Result<[u8; 32]>;

    /// 设置指定 Epoch 的收据摘要（用于缓存）
    async fn set_receipt_digest(&self, epoch_seq: u64, digest: [u8; 32]);

    /// 清除缓存
    async fn clear_cache(&self);
}

/// 基于缓存的收据摘要提供者
///
/// 使用内存缓存存储摘要，未命中时使用回退计算。
pub struct CachedReceiptDigestProvider {
    cache: Arc<RwLock<HashMap<u64, [u8; 32]>>>,
}

impl CachedReceiptDigestProvider {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 计算回退摘要
    fn compute_fallback(epoch_root: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(epoch_root);
        hasher.update(b"linked_receipt_ids");
        let hash = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&hash);
        digest
    }
}

impl Default for CachedReceiptDigestProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ReceiptDigestProvider for CachedReceiptDigestProvider {
    async fn get_receipt_digest(&self, epoch_seq: u64, epoch_root: &[u8; 32]) -> P4Result<[u8; 32]> {
        // 检查缓存
        {
            let cache = self.cache.read().await;
            if let Some(digest) = cache.get(&epoch_seq) {
                debug!("Receipt digest cache hit for epoch {}", epoch_seq);
                return Ok(*digest);
            }
        }

        // 缓存未命中，使用回退计算
        debug!("Receipt digest cache miss for epoch {}, using fallback", epoch_seq);
        let digest = Self::compute_fallback(epoch_root);

        // 缓存计算结果
        {
            let mut cache = self.cache.write().await;
            cache.insert(epoch_seq, digest);
        }

        Ok(digest)
    }

    async fn set_receipt_digest(&self, epoch_seq: u64, digest: [u8; 32]) {
        let mut cache = self.cache.write().await;
        cache.insert(epoch_seq, digest);
        debug!("Receipt digest set for epoch {}", epoch_seq);
    }

    async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
        debug!("Receipt digest cache cleared");
    }
}

/// 基于 ReceiptLedger 的收据摘要提供者
///
/// 从 L0 ReceiptLedger 查询收据并计算摘要。
pub struct ReceiptLedgerDigestProvider<R: l0_core::ledger::ReceiptLedger + 'static> {
    receipt_ledger: Arc<R>,
    /// 每个 Epoch 的起始 batch 序号映射
    /// key: epoch_seq, value: (start_batch_seq, batch_count)
    epoch_batch_map: Arc<RwLock<HashMap<u64, (u64, u64)>>>,
    /// 缓存已计算的摘要
    cache: Arc<RwLock<HashMap<u64, [u8; 32]>>>,
}

impl<R: l0_core::ledger::ReceiptLedger + 'static> ReceiptLedgerDigestProvider<R> {
    pub fn new(receipt_ledger: Arc<R>) -> Self {
        Self {
            receipt_ledger,
            epoch_batch_map: Arc::new(RwLock::new(HashMap::new())),
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 设置 Epoch 的 batch 范围
    ///
    /// 当创建或发现新的 Epoch 时，需要调用此方法设置 batch 范围。
    pub async fn set_epoch_batch_range(&self, epoch_seq: u64, start_batch: u64, batch_count: u64) {
        let mut map = self.epoch_batch_map.write().await;
        map.insert(epoch_seq, (start_batch, batch_count));
        debug!(
            "Set epoch {} batch range: start={}, count={}",
            epoch_seq, start_batch, batch_count
        );
    }

    /// 从收据列表计算摘要
    fn compute_digest_from_receipts(receipts: &[l0_core::L0Receipt]) -> [u8; 32] {
        let mut hasher = Sha256::new();

        // 收集并排序收据 ID
        let mut receipt_ids: Vec<_> = receipts.iter().map(|r| r.receipt_id.as_str()).collect();
        receipt_ids.sort();

        // 计算摘要
        hasher.update(b"linked_receipt_ids:");
        for id in receipt_ids {
            hasher.update(id.as_bytes());
            hasher.update(b"|");
        }

        let hash = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&hash);
        digest
    }
}

#[async_trait]
impl<R: l0_core::ledger::ReceiptLedger + 'static> ReceiptDigestProvider for ReceiptLedgerDigestProvider<R> {
    async fn get_receipt_digest(&self, epoch_seq: u64, epoch_root: &[u8; 32]) -> P4Result<[u8; 32]> {
        // 检查缓存
        {
            let cache = self.cache.read().await;
            if let Some(digest) = cache.get(&epoch_seq) {
                return Ok(*digest);
            }
        }

        // 获取 Epoch 的 batch 范围
        let (start_batch, batch_count) = {
            let map = self.epoch_batch_map.read().await;
            match map.get(&epoch_seq) {
                Some(&range) => range,
                None => {
                    warn!(
                        "Epoch {} batch range not set, using fallback digest",
                        epoch_seq
                    );
                    let digest = CachedReceiptDigestProvider::compute_fallback(epoch_root);
                    return Ok(digest);
                }
            }
        };

        // 从 ReceiptLedger 获取所有相关收据
        let mut all_receipts = Vec::new();
        for batch_seq in start_batch..start_batch + batch_count {
            match self.receipt_ledger.get_receipts_by_batch(batch_seq).await {
                Ok(receipts) => all_receipts.extend(receipts),
                Err(e) => {
                    warn!(
                        "Failed to get receipts for batch {}: {}, using fallback",
                        batch_seq, e
                    );
                    let digest = CachedReceiptDigestProvider::compute_fallback(epoch_root);
                    return Ok(digest);
                }
            }
        }

        // 计算摘要
        let digest = if all_receipts.is_empty() {
            debug!("No receipts found for epoch {}, using empty digest", epoch_seq);
            // 空收据列表的摘要
            let mut hasher = Sha256::new();
            hasher.update(b"linked_receipt_ids:empty");
            let hash = hasher.finalize();
            let mut d = [0u8; 32];
            d.copy_from_slice(&hash);
            d
        } else {
            debug!(
                "Computing receipt digest for epoch {} from {} receipts",
                epoch_seq,
                all_receipts.len()
            );
            Self::compute_digest_from_receipts(&all_receipts)
        };

        // 缓存结果
        {
            let mut cache = self.cache.write().await;
            cache.insert(epoch_seq, digest);
        }

        Ok(digest)
    }

    async fn set_receipt_digest(&self, epoch_seq: u64, digest: [u8; 32]) {
        let mut cache = self.cache.write().await;
        cache.insert(epoch_seq, digest);
    }

    async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
        let mut map = self.epoch_batch_map.write().await;
        map.clear();
    }
}

// ============================================================================
// L0 Integration Trait
// ============================================================================

/// L0 核心层集成 Trait
///
/// 定义与 L0 核心层交互的接口。
/// 实现者需要提供 Epoch 相关的查询和更新功能。
#[async_trait]
pub trait L0Integration: Send + Sync {
    /// 获取当前 Epoch 信息
    ///
    /// 返回最新的 Epoch 元数据。
    async fn get_current_epoch(&self) -> P4Result<EpochInfo>;

    /// 获取指定 Epoch 的根哈希
    ///
    /// # Arguments
    /// * `epoch_seq` - Epoch 序列号
    ///
    /// # Returns
    /// * `Ok([u8; 32])` - Epoch 根哈希
    /// * `Err` - 如果 Epoch 不存在或发生错误
    async fn get_epoch_root(&self, epoch_seq: u64) -> P4Result<[u8; 32]>;

    /// 获取指定 Epoch 的完整信息
    async fn get_epoch_info(&self, epoch_seq: u64) -> P4Result<Option<EpochInfo>>;

    /// 获取待锚定的 Epoch 列表
    ///
    /// 返回所有状态为 Pending 的 Epoch。
    async fn get_pending_epochs(&self) -> P4Result<Vec<EpochInfo>>;

    /// 更新 Epoch 锚定状态
    ///
    /// # Arguments
    /// * `epoch_seq` - Epoch 序列号
    /// * `status` - 新的锚定状态
    /// * `txid` - 交易 ID（可选）
    async fn update_epoch_anchor_status(
        &self,
        epoch_seq: u64,
        status: EpochAnchorState,
        txid: Option<String>,
    ) -> P4Result<()>;

    /// 将 Epoch 转换为 ChainAnchorInput
    ///
    /// 从 L0 Epoch 创建 P4 锚定输入。
    async fn epoch_to_anchor_input(
        &self,
        epoch_seq: u64,
        priority: AnchorPriority,
    ) -> P4Result<ChainAnchorInput>;

    /// 获取关联的收据 ID 摘要
    ///
    /// 计算指定 Epoch 内所有收据的摘要。
    async fn get_linked_receipt_ids_digest(&self, epoch_seq: u64) -> P4Result<[u8; 32]>;
}

/// L0 集成的 Mock 实现
///
/// 用于测试和开发环境。
pub struct MockL0Integration {
    /// 模拟的 Epoch 数据
    epochs: Arc<RwLock<Vec<EpochInfo>>>,
    /// 当前 Epoch 序列号
    current_sequence: Arc<RwLock<u64>>,
}

impl MockL0Integration {
    /// 创建新的 Mock 实现
    pub fn new() -> Self {
        Self {
            epochs: Arc::new(RwLock::new(Vec::new())),
            current_sequence: Arc::new(RwLock::new(0)),
        }
    }

    /// 添加模拟 Epoch
    pub async fn add_epoch(&self, epoch: EpochInfo) {
        let mut epochs = self.epochs.write().await;
        let mut current = self.current_sequence.write().await;

        if epoch.sequence > *current {
            *current = epoch.sequence;
        }

        epochs.push(epoch);
    }

    /// 生成测试 Epoch
    pub async fn generate_test_epoch(&self, sequence: u64) -> EpochInfo {
        let mut hasher = Sha256::new();
        hasher.update(format!("epoch_{}", sequence).as_bytes());
        let hash = hasher.finalize();
        let mut epoch_root = [0u8; 32];
        epoch_root.copy_from_slice(&hash);

        let now = Timestamp::now();
        EpochInfo {
            sequence,
            epoch_root,
            window_start: Timestamp::from_millis(now.as_millis() - 3600000), // 1 hour ago
            window_end: now,
            signer_set_version: 1,
            anchor_status: EpochAnchorState::Pending,
        }
    }
}

impl Default for MockL0Integration {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl L0Integration for MockL0Integration {
    async fn get_current_epoch(&self) -> P4Result<EpochInfo> {
        let current = *self.current_sequence.read().await;
        let epochs = self.epochs.read().await;

        epochs
            .iter()
            .find(|e| e.sequence == current)
            .cloned()
            .ok_or(P4Error::EpochNotFound(current))
    }

    async fn get_epoch_root(&self, epoch_seq: u64) -> P4Result<[u8; 32]> {
        let epochs = self.epochs.read().await;

        epochs
            .iter()
            .find(|e| e.sequence == epoch_seq)
            .map(|e| e.epoch_root)
            .ok_or(P4Error::EpochNotFound(epoch_seq))
    }

    async fn get_epoch_info(&self, epoch_seq: u64) -> P4Result<Option<EpochInfo>> {
        let epochs = self.epochs.read().await;
        Ok(epochs.iter().find(|e| e.sequence == epoch_seq).cloned())
    }

    async fn get_pending_epochs(&self) -> P4Result<Vec<EpochInfo>> {
        let epochs = self.epochs.read().await;
        Ok(epochs
            .iter()
            .filter(|e| e.anchor_status == EpochAnchorState::Pending)
            .cloned()
            .collect())
    }

    async fn update_epoch_anchor_status(
        &self,
        epoch_seq: u64,
        status: EpochAnchorState,
        txid: Option<String>,
    ) -> P4Result<()> {
        let mut epochs = self.epochs.write().await;

        if let Some(epoch) = epochs.iter_mut().find(|e| e.sequence == epoch_seq) {
            epoch.anchor_status = status;
            info!(
                "Updated epoch {} anchor status to {:?}, txid: {:?}",
                epoch_seq, status, txid
            );
            Ok(())
        } else {
            Err(P4Error::EpochNotFound(epoch_seq))
        }
    }

    async fn epoch_to_anchor_input(
        &self,
        epoch_seq: u64,
        priority: AnchorPriority,
    ) -> P4Result<ChainAnchorInput> {
        let epoch = self
            .get_epoch_info(epoch_seq)
            .await?
            .ok_or(P4Error::EpochNotFound(epoch_seq))?;

        let linked_receipt_ids_digest = self.get_linked_receipt_ids_digest(epoch_seq).await?;

        Ok(ChainAnchorInput::with_full_params(
            epoch_seq,
            epoch.epoch_root,
            epoch.window_start,
            epoch.window_end,
            linked_receipt_ids_digest,
            epoch.signer_set_version,
            PolicyVersion::new(1),
            CanonVersion::new(1),
            priority,
        ))
    }

    async fn get_linked_receipt_ids_digest(&self, epoch_seq: u64) -> P4Result<[u8; 32]> {
        // Mock: 生成基于 epoch_seq 的摘要
        let mut hasher = Sha256::new();
        hasher.update(format!("receipts_epoch_{}", epoch_seq).as_bytes());
        let hash = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&hash);
        Ok(digest)
    }
}

/// L0 集成的生产实现
///
/// 连接到实际的 L0 核心层 EpochLedger。
/// 可选地连接到 ReceiptLedger 获取收据摘要。
pub struct L0IntegrationImpl {
    /// L0 Epoch Ledger 引用
    epoch_ledger: Arc<RwLock<l0_core::EpochLedger>>,
    /// 收据摘要提供者
    receipt_digest_provider: Arc<dyn ReceiptDigestProvider>,
}

impl L0IntegrationImpl {
    /// 创建新的 L0 集成实例（使用默认的缓存摘要提供者）
    pub fn new(epoch_ledger: Arc<RwLock<l0_core::EpochLedger>>) -> Self {
        Self {
            epoch_ledger,
            receipt_digest_provider: Arc::new(CachedReceiptDigestProvider::new()),
        }
    }

    /// 使用指定的收据摘要提供者创建 L0 集成实例
    pub fn with_receipt_provider(
        epoch_ledger: Arc<RwLock<l0_core::EpochLedger>>,
        receipt_digest_provider: Arc<dyn ReceiptDigestProvider>,
    ) -> Self {
        Self {
            epoch_ledger,
            receipt_digest_provider,
        }
    }

    /// 使用 ReceiptLedger 创建 L0 集成实例
    ///
    /// 这将创建一个使用真实 ReceiptLedger 来计算收据摘要的实例。
    pub fn with_receipt_ledger<R: l0_core::ledger::ReceiptLedger + 'static>(
        epoch_ledger: Arc<RwLock<l0_core::EpochLedger>>,
        receipt_ledger: Arc<R>,
    ) -> Self {
        let provider = Arc::new(ReceiptLedgerDigestProvider::new(receipt_ledger));
        Self {
            epoch_ledger,
            receipt_digest_provider: provider,
        }
    }

    /// 获取收据摘要提供者的引用
    ///
    /// 用于设置 Epoch 批次映射等配置。
    pub fn receipt_provider(&self) -> &Arc<dyn ReceiptDigestProvider> {
        &self.receipt_digest_provider
    }

    /// 设置指定 Epoch 的收据摘要
    ///
    /// 当外部系统（如 ReceiptLedger 实现）计算出收据摘要后，
    /// 可以通过此方法设置缓存。
    pub async fn set_receipt_digest(&self, epoch_seq: u64, digest: [u8; 32]) {
        self.receipt_digest_provider.set_receipt_digest(epoch_seq, digest).await;
    }

    /// 从 l0_core::EpochMetadata 转换为 EpochInfo
    fn convert_metadata(metadata: &l0_core::EpochMetadata) -> EpochInfo {
        // 转换 epoch root: l0_core::L0Digest -> [u8; 32]
        let epoch_root = metadata.root.0;

        // 转换锚定状态
        let anchor_status = match metadata.anchor_status {
            l0_core::EpochAnchorStatus::Pending => EpochAnchorState::Pending,
            l0_core::EpochAnchorStatus::Submitted => EpochAnchorState::Submitted,
            l0_core::EpochAnchorStatus::Confirmed => EpochAnchorState::Confirmed,
            l0_core::EpochAnchorStatus::Finalized => EpochAnchorState::Finalized,
            l0_core::EpochAnchorStatus::Failed => EpochAnchorState::Failed,
        };

        // 转换时间戳: chrono::DateTime<Utc> -> Timestamp
        let window_start = Timestamp::from_millis(metadata.start_time.timestamp_millis() as u64);
        let window_end = Timestamp::from_millis(metadata.end_time.timestamp_millis() as u64);

        // 解析 signer_set_version (String -> u32)
        // 支持多种格式: "v1", "1", "signer_set:v1", "signer_set:1"
        let signer_set_version = Self::parse_signer_set_version(&metadata.signer_set_version);

        EpochInfo {
            sequence: metadata.sequence,
            epoch_root,
            window_start,
            window_end,
            signer_set_version,
            anchor_status,
        }
    }

    /// 解析 signer_set_version 字符串
    ///
    /// 支持多种格式:
    /// - "v1", "v2" -> 1, 2
    /// - "1", "2" -> 1, 2
    /// - "signer_set:v1" -> 1
    /// - "signer_set:1" -> 1
    /// - 其他格式 -> 使用字符串哈希的低 32 位
    fn parse_signer_set_version(version_str: &str) -> u32 {
        let cleaned = version_str
            .trim()
            .trim_start_matches("signer_set:")
            .trim_start_matches("signer-set:")
            .trim_start_matches("signers:")
            .trim_start_matches('v')
            .trim_start_matches('V');

        // 尝试直接解析为数字
        if let Ok(v) = cleaned.parse::<u32>() {
            return v;
        }

        // 如果无法解析为数字，使用字符串哈希
        // 这确保相同的版本字符串总是返回相同的版本号
        warn!(
            "Could not parse signer_set_version '{}' as number, using hash-based version",
            version_str
        );

        let mut hasher = Sha256::new();
        hasher.update(version_str.as_bytes());
        let hash = hasher.finalize();

        // 使用哈希的前 4 字节作为版本号
        u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
    }

    /// 将 P4 EpochAnchorState 转换为 l0_core::EpochAnchorStatus
    fn convert_status(status: EpochAnchorState) -> l0_core::EpochAnchorStatus {
        match status {
            EpochAnchorState::Pending => l0_core::EpochAnchorStatus::Pending,
            EpochAnchorState::Submitted => l0_core::EpochAnchorStatus::Submitted,
            EpochAnchorState::Confirmed => l0_core::EpochAnchorStatus::Confirmed,
            EpochAnchorState::Finalized => l0_core::EpochAnchorStatus::Finalized,
            EpochAnchorState::Failed => l0_core::EpochAnchorStatus::Failed,
        }
    }
}

#[async_trait]
impl L0Integration for L0IntegrationImpl {
    async fn get_current_epoch(&self) -> P4Result<EpochInfo> {
        let ledger = self.epoch_ledger.read().await;
        ledger
            .latest_epoch()
            .map(Self::convert_metadata)
            .ok_or_else(|| P4Error::Configuration("No epochs in ledger".to_string()))
    }

    async fn get_epoch_root(&self, epoch_seq: u64) -> P4Result<[u8; 32]> {
        let ledger = self.epoch_ledger.read().await;
        ledger
            .get_epoch(epoch_seq)
            .map(|m| m.root.0)
            .ok_or(P4Error::EpochNotFound(epoch_seq))
    }

    async fn get_epoch_info(&self, epoch_seq: u64) -> P4Result<Option<EpochInfo>> {
        let ledger = self.epoch_ledger.read().await;
        Ok(ledger.get_epoch(epoch_seq).map(Self::convert_metadata))
    }

    async fn get_pending_epochs(&self) -> P4Result<Vec<EpochInfo>> {
        let ledger = self.epoch_ledger.read().await;
        Ok(ledger
            .pending_epochs()
            .iter()
            .map(|m| Self::convert_metadata(m))
            .collect())
    }

    async fn update_epoch_anchor_status(
        &self,
        epoch_seq: u64,
        status: EpochAnchorState,
        txid: Option<String>,
    ) -> P4Result<()> {
        let mut ledger = self.epoch_ledger.write().await;

        let l0_status = Self::convert_status(status);
        let updated = ledger.update_anchor_status(epoch_seq, l0_status);

        if updated {
            info!(
                "Updated epoch {} anchor status to {:?}, txid: {:?}",
                epoch_seq, status, txid
            );
            Ok(())
        } else {
            Err(P4Error::EpochNotFound(epoch_seq))
        }
    }

    async fn epoch_to_anchor_input(
        &self,
        epoch_seq: u64,
        priority: AnchorPriority,
    ) -> P4Result<ChainAnchorInput> {
        let epoch = self
            .get_epoch_info(epoch_seq)
            .await?
            .ok_or(P4Error::EpochNotFound(epoch_seq))?;

        let linked_receipt_ids_digest = self.get_linked_receipt_ids_digest(epoch_seq).await?;

        Ok(ChainAnchorInput::with_full_params(
            epoch_seq,
            epoch.epoch_root,
            epoch.window_start,
            epoch.window_end,
            linked_receipt_ids_digest,
            epoch.signer_set_version,
            PolicyVersion::new(1),
            CanonVersion::new(1),
            priority,
        ))
    }

    async fn get_linked_receipt_ids_digest(&self, epoch_seq: u64) -> P4Result<[u8; 32]> {
        // 获取 epoch root 用于回退计算
        let root = self.get_epoch_root(epoch_seq).await?;

        // 委托给收据摘要提供者
        self.receipt_digest_provider.get_receipt_digest(epoch_seq, &root).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::InputStatus;

    #[tokio::test]
    async fn test_mock_l0_integration() {
        let mock = MockL0Integration::new();

        // 生成测试 Epoch
        let epoch = mock.generate_test_epoch(1).await;
        mock.add_epoch(epoch.clone()).await;

        // 测试获取当前 Epoch
        let current = mock.get_current_epoch().await.unwrap();
        assert_eq!(current.sequence, 1);

        // 测试获取 Epoch 根
        let root = mock.get_epoch_root(1).await.unwrap();
        assert_eq!(root, epoch.epoch_root);

        // 测试获取待锚定 Epoch
        let pending = mock.get_pending_epochs().await.unwrap();
        assert_eq!(pending.len(), 1);

        // 测试更新状态
        mock.update_epoch_anchor_status(1, EpochAnchorState::Submitted, Some("txid123".to_string()))
            .await
            .unwrap();

        let updated = mock.get_epoch_info(1).await.unwrap().unwrap();
        assert_eq!(updated.anchor_status, EpochAnchorState::Submitted);

        // 更新后不再 Pending
        let pending = mock.get_pending_epochs().await.unwrap();
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn test_epoch_to_anchor_input() {
        let mock = MockL0Integration::new();

        let epoch = mock.generate_test_epoch(1).await;
        mock.add_epoch(epoch).await;

        let input = mock
            .epoch_to_anchor_input(1, AnchorPriority::Must)
            .await
            .unwrap();

        assert_eq!(input.epoch_sequence, 1);
        assert_eq!(input.priority, AnchorPriority::Must);
        assert_eq!(input.status, InputStatus::Pending);
    }

    #[tokio::test]
    async fn test_epoch_not_found() {
        let mock = MockL0Integration::new();

        let result = mock.get_epoch_root(999).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_l0_integration_impl_with_ledger() {
        use chrono::Utc;

        // 创建真实的 EpochLedger
        let ledger = Arc::new(RwLock::new(l0_core::EpochLedger::new()));

        // 添加一个测试 Epoch
        {
            let mut ledger_guard = ledger.write().await;
            let metadata = l0_core::EpochMetadata {
                sequence: 1,
                root: l0_core::L0Digest::new([1u8; 32]),
                batch_count: 10,
                start_time: Utc::now() - chrono::Duration::hours(1),
                end_time: Utc::now(),
                signer_set_version: "v1".to_string(),
                anchor_status: l0_core::EpochAnchorStatus::Pending,
                created_at: Utc::now(),
            };
            ledger_guard.record_epoch(metadata);
        }

        // 创建集成实例
        let integration = L0IntegrationImpl::new(ledger.clone());

        // 测试获取当前 Epoch
        let current = integration.get_current_epoch().await.unwrap();
        assert_eq!(current.sequence, 1);
        assert_eq!(current.epoch_root, [1u8; 32]);
        assert_eq!(current.anchor_status, EpochAnchorState::Pending);

        // 测试获取 Epoch root
        let root = integration.get_epoch_root(1).await.unwrap();
        assert_eq!(root, [1u8; 32]);

        // 测试获取待锚定 Epochs
        let pending = integration.get_pending_epochs().await.unwrap();
        assert_eq!(pending.len(), 1);

        // 测试更新锚定状态
        integration
            .update_epoch_anchor_status(1, EpochAnchorState::Submitted, Some("txid123".to_string()))
            .await
            .unwrap();

        // 验证状态已更新
        let updated = integration.get_epoch_info(1).await.unwrap().unwrap();
        assert_eq!(updated.anchor_status, EpochAnchorState::Submitted);

        // 更新后不再 Pending
        let pending = integration.get_pending_epochs().await.unwrap();
        assert!(pending.is_empty());
    }

    #[test]
    fn test_parse_signer_set_version() {
        // 测试各种格式
        assert_eq!(L0IntegrationImpl::parse_signer_set_version("v1"), 1);
        assert_eq!(L0IntegrationImpl::parse_signer_set_version("V1"), 1);
        assert_eq!(L0IntegrationImpl::parse_signer_set_version("1"), 1);
        assert_eq!(L0IntegrationImpl::parse_signer_set_version("v123"), 123);
        assert_eq!(L0IntegrationImpl::parse_signer_set_version("signer_set:v1"), 1);
        assert_eq!(L0IntegrationImpl::parse_signer_set_version("signer_set:1"), 1);
        assert_eq!(L0IntegrationImpl::parse_signer_set_version("signer-set:v2"), 2);
        assert_eq!(L0IntegrationImpl::parse_signer_set_version("signers:v3"), 3);
        assert_eq!(L0IntegrationImpl::parse_signer_set_version("  v5  "), 5);

        // 测试非数字格式 - 应该返回哈希值
        let hash_based_1 = L0IntegrationImpl::parse_signer_set_version("some-custom-version");
        let hash_based_2 = L0IntegrationImpl::parse_signer_set_version("some-custom-version");
        assert_eq!(hash_based_1, hash_based_2); // 相同输入应该返回相同结果

        let different = L0IntegrationImpl::parse_signer_set_version("another-version");
        assert_ne!(hash_based_1, different); // 不同输入应该不同
    }

    #[tokio::test]
    async fn test_receipt_digest_cache() {
        let ledger = Arc::new(RwLock::new(l0_core::EpochLedger::new()));

        // 添加一个测试 Epoch
        {
            use chrono::Utc;
            let mut ledger_guard = ledger.write().await;
            let metadata = l0_core::EpochMetadata {
                sequence: 1,
                root: l0_core::L0Digest::new([1u8; 32]),
                batch_count: 10,
                start_time: Utc::now() - chrono::Duration::hours(1),
                end_time: Utc::now(),
                signer_set_version: "v1".to_string(),
                anchor_status: l0_core::EpochAnchorStatus::Pending,
                created_at: Utc::now(),
            };
            ledger_guard.record_epoch(metadata);
        }

        let integration = L0IntegrationImpl::new(ledger);

        // 首次获取 - 使用回退计算
        let digest1 = integration.get_linked_receipt_ids_digest(1).await.unwrap();

        // 设置自定义摘要
        let custom_digest = [42u8; 32];
        integration.set_receipt_digest(1, custom_digest).await;

        // 再次获取 - 应该使用缓存的自定义值
        let digest2 = integration.get_linked_receipt_ids_digest(1).await.unwrap();
        assert_eq!(digest2, custom_digest);
        assert_ne!(digest1, digest2);
    }

    #[tokio::test]
    async fn test_cached_receipt_digest_provider() {
        let provider = CachedReceiptDigestProvider::new();
        let epoch_root = [1u8; 32];

        // 首次获取 - 使用回退计算
        let digest1 = provider.get_receipt_digest(1, &epoch_root).await.unwrap();
        assert_ne!(digest1, [0u8; 32]); // 不应该是全零

        // 相同的输入应该返回相同的结果
        let digest2 = provider.get_receipt_digest(1, &epoch_root).await.unwrap();
        assert_eq!(digest1, digest2);

        // 手动设置摘要
        let custom_digest = [42u8; 32];
        provider.set_receipt_digest(1, custom_digest).await;

        // 获取应该返回自定义摘要
        let digest3 = provider.get_receipt_digest(1, &epoch_root).await.unwrap();
        assert_eq!(digest3, custom_digest);

        // 清除缓存
        provider.clear_cache().await;

        // 再次获取应该重新计算
        let digest4 = provider.get_receipt_digest(1, &epoch_root).await.unwrap();
        assert_eq!(digest4, digest1); // 回退计算结果相同
        assert_ne!(digest4, custom_digest);
    }

    #[tokio::test]
    async fn test_l0_integration_with_custom_provider() {
        use chrono::Utc;

        // 创建自定义的 provider
        let custom_provider = Arc::new(CachedReceiptDigestProvider::new());

        // 预设摘要
        let preset_digest = [99u8; 32];
        custom_provider.set_receipt_digest(1, preset_digest).await;

        // 创建 EpochLedger 并添加 Epoch
        let ledger = Arc::new(RwLock::new(l0_core::EpochLedger::new()));
        {
            let mut ledger_guard = ledger.write().await;
            let metadata = l0_core::EpochMetadata {
                sequence: 1,
                root: l0_core::L0Digest::new([1u8; 32]),
                batch_count: 10,
                start_time: Utc::now() - chrono::Duration::hours(1),
                end_time: Utc::now(),
                signer_set_version: "v1".to_string(),
                anchor_status: l0_core::EpochAnchorStatus::Pending,
                created_at: Utc::now(),
            };
            ledger_guard.record_epoch(metadata);
        }

        // 使用自定义 provider 创建集成
        let integration = L0IntegrationImpl::with_receipt_provider(
            ledger,
            custom_provider as Arc<dyn ReceiptDigestProvider>,
        );

        // 获取摘要应该使用预设值
        let digest = integration.get_linked_receipt_ids_digest(1).await.unwrap();
        assert_eq!(digest, preset_digest);
    }

    #[tokio::test]
    async fn test_receipt_provider_accessor() {
        let ledger = Arc::new(RwLock::new(l0_core::EpochLedger::new()));
        let integration = L0IntegrationImpl::new(ledger);

        // 获取 provider 并设置摘要
        let provider = integration.receipt_provider();
        provider.set_receipt_digest(999, [88u8; 32]).await;

        // 通过 integration 获取应该能得到设置的值（但会因为找不到 epoch 而失败）
        // 这里只是验证 provider 可以被访问
        assert!(integration.get_linked_receipt_ids_digest(999).await.is_err());
    }
}
