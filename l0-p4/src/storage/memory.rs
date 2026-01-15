//! 内存存储实现
//!
//! 提供基于内存的存储实现，主要用于测试和开发。

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::{AnchorStorage, StorageStats};
use crate::error::{P4Error, P4Result};
use crate::types::{
    AnchorPriority, ChainAnchorInput, ChainAnchorJob, ChainAnchorLink,
    IdempotencyKey, InputId, InputStatus, JobId, JobStatus, LinkId,
    LinkStatus, ReconcileId, ReconcileResult, ReconcileStatus,
};

/// 内存存储
///
/// 线程安全的内存存储实现，使用 RwLock 保护共享数据。
#[derive(Debug)]
pub struct MemoryStorage {
    inputs: Arc<RwLock<HashMap<InputId, ChainAnchorInput>>>,
    jobs: Arc<RwLock<HashMap<JobId, ChainAnchorJob>>>,
    links: Arc<RwLock<HashMap<LinkId, ChainAnchorLink>>>,
    reconciles: Arc<RwLock<HashMap<ReconcileId, ReconcileResult>>>,
    // 索引
    idempotency_index: Arc<RwLock<HashMap<IdempotencyKey, JobId>>>,
    input_to_jobs: Arc<RwLock<HashMap<InputId, Vec<JobId>>>>,
    input_to_link: Arc<RwLock<HashMap<InputId, LinkId>>>,
    input_to_reconcile: Arc<RwLock<HashMap<InputId, ReconcileId>>>,
    txid_to_link: Arc<RwLock<HashMap<String, LinkId>>>,
    // MUST 持久化列表
    must_inputs: Arc<RwLock<HashMap<InputId, ChainAnchorInput>>>,
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStorage {
    /// 创建新的内存存储
    pub fn new() -> Self {
        Self {
            inputs: Arc::new(RwLock::new(HashMap::new())),
            jobs: Arc::new(RwLock::new(HashMap::new())),
            links: Arc::new(RwLock::new(HashMap::new())),
            reconciles: Arc::new(RwLock::new(HashMap::new())),
            idempotency_index: Arc::new(RwLock::new(HashMap::new())),
            input_to_jobs: Arc::new(RwLock::new(HashMap::new())),
            input_to_link: Arc::new(RwLock::new(HashMap::new())),
            input_to_reconcile: Arc::new(RwLock::new(HashMap::new())),
            txid_to_link: Arc::new(RwLock::new(HashMap::new())),
            must_inputs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 清空所有数据
    pub async fn clear(&self) {
        self.inputs.write().await.clear();
        self.jobs.write().await.clear();
        self.links.write().await.clear();
        self.reconciles.write().await.clear();
        self.idempotency_index.write().await.clear();
        self.input_to_jobs.write().await.clear();
        self.input_to_link.write().await.clear();
        self.input_to_reconcile.write().await.clear();
        self.txid_to_link.write().await.clear();
        self.must_inputs.write().await.clear();
    }
}

#[async_trait]
impl AnchorStorage for MemoryStorage {
    // ==================== Input 操作 ====================

    async fn save_input(&self, input: &ChainAnchorInput) -> P4Result<()> {
        let mut inputs = self.inputs.write().await;
        inputs.insert(input.input_id, input.clone());

        // 如果是 MUST 级别，也保存到持久化列表
        if input.priority == AnchorPriority::Must {
            let mut must_inputs = self.must_inputs.write().await;
            must_inputs.insert(input.input_id, input.clone());
        }

        Ok(())
    }

    async fn get_input(&self, input_id: &InputId) -> P4Result<Option<ChainAnchorInput>> {
        let inputs = self.inputs.read().await;
        Ok(inputs.get(input_id).cloned())
    }

    async fn delete_input(&self, input_id: &InputId) -> P4Result<()> {
        let mut inputs = self.inputs.write().await;
        inputs.remove(input_id);

        let mut must_inputs = self.must_inputs.write().await;
        must_inputs.remove(input_id);

        Ok(())
    }

    async fn list_pending_inputs(&self) -> P4Result<Vec<ChainAnchorInput>> {
        let inputs = self.inputs.read().await;
        Ok(inputs
            .values()
            .filter(|i| matches!(i.status, InputStatus::Pending | InputStatus::Queued))
            .cloned()
            .collect())
    }

    async fn list_inputs_by_priority(&self, priority: AnchorPriority) -> P4Result<Vec<ChainAnchorInput>> {
        let inputs = self.inputs.read().await;
        Ok(inputs
            .values()
            .filter(|i| i.priority == priority)
            .cloned()
            .collect())
    }

    async fn persist_must_input(&self, input: &ChainAnchorInput) -> P4Result<()> {
        if input.priority != AnchorPriority::Must {
            return Err(P4Error::InvalidInput(
                "Only MUST priority inputs can be persisted".to_string(),
            ));
        }

        let mut must_inputs = self.must_inputs.write().await;
        must_inputs.insert(input.input_id, input.clone());
        Ok(())
    }

    async fn load_persisted_must_inputs(&self) -> P4Result<Vec<ChainAnchorInput>> {
        let must_inputs = self.must_inputs.read().await;
        Ok(must_inputs.values().cloned().collect())
    }

    // ==================== Job 操作 ====================

    async fn save_job(&self, job: &ChainAnchorJob) -> P4Result<()> {
        let mut jobs = self.jobs.write().await;
        jobs.insert(job.job_id, job.clone());

        // 更新幂等键索引
        let mut idempotency_index = self.idempotency_index.write().await;
        idempotency_index.insert(job.idempotency_key, job.job_id);

        // 更新输入到作业索引
        let mut input_to_jobs = self.input_to_jobs.write().await;
        input_to_jobs
            .entry(job.input_id)
            .or_default()
            .push(job.job_id);

        Ok(())
    }

    async fn get_job(&self, job_id: &JobId) -> P4Result<Option<ChainAnchorJob>> {
        let jobs = self.jobs.read().await;
        Ok(jobs.get(job_id).cloned())
    }

    async fn get_job_by_idempotency_key(&self, key: &IdempotencyKey) -> P4Result<Option<ChainAnchorJob>> {
        let idempotency_index = self.idempotency_index.read().await;
        if let Some(job_id) = idempotency_index.get(key) {
            let jobs = self.jobs.read().await;
            return Ok(jobs.get(job_id).cloned());
        }
        Ok(None)
    }

    async fn get_jobs_by_input(&self, input_id: &InputId) -> P4Result<Vec<ChainAnchorJob>> {
        let input_to_jobs = self.input_to_jobs.read().await;
        if let Some(job_ids) = input_to_jobs.get(input_id) {
            let jobs = self.jobs.read().await;
            return Ok(job_ids
                .iter()
                .filter_map(|id| jobs.get(id).cloned())
                .collect());
        }
        Ok(Vec::new())
    }

    async fn delete_job(&self, job_id: &JobId) -> P4Result<()> {
        let mut jobs = self.jobs.write().await;
        if let Some(job) = jobs.remove(job_id) {
            // 清理索引
            let mut idempotency_index = self.idempotency_index.write().await;
            idempotency_index.remove(&job.idempotency_key);

            let mut input_to_jobs = self.input_to_jobs.write().await;
            if let Some(job_ids) = input_to_jobs.get_mut(&job.input_id) {
                job_ids.retain(|id| id != job_id);
            }
        }
        Ok(())
    }

    async fn list_pending_jobs(&self) -> P4Result<Vec<ChainAnchorJob>> {
        let jobs = self.jobs.read().await;
        Ok(jobs
            .values()
            .filter(|j| matches!(j.status, JobStatus::Queued | JobStatus::Submitted))
            .cloned()
            .collect())
    }

    async fn list_retry_scheduled_jobs(&self) -> P4Result<Vec<ChainAnchorJob>> {
        let jobs = self.jobs.read().await;
        Ok(jobs
            .values()
            .filter(|j| j.status == JobStatus::RetryScheduled)
            .cloned()
            .collect())
    }

    // ==================== Link 操作 ====================

    async fn save_link(&self, link: &ChainAnchorLink) -> P4Result<()> {
        let mut links = self.links.write().await;
        links.insert(link.link_id, link.clone());

        // 更新索引
        let mut input_to_link = self.input_to_link.write().await;
        input_to_link.insert(link.input_id, link.link_id);

        let mut txid_to_link = self.txid_to_link.write().await;
        txid_to_link.insert(link.txid_or_asset_id.clone(), link.link_id);

        Ok(())
    }

    async fn get_link(&self, link_id: &LinkId) -> P4Result<Option<ChainAnchorLink>> {
        let links = self.links.read().await;
        Ok(links.get(link_id).cloned())
    }

    async fn get_link_by_input(&self, input_id: &InputId) -> P4Result<Option<ChainAnchorLink>> {
        let input_to_link = self.input_to_link.read().await;
        if let Some(link_id) = input_to_link.get(input_id) {
            let links = self.links.read().await;
            return Ok(links.get(link_id).cloned());
        }
        Ok(None)
    }

    async fn get_link_by_txid(&self, txid: &str) -> P4Result<Option<ChainAnchorLink>> {
        let txid_to_link = self.txid_to_link.read().await;
        if let Some(link_id) = txid_to_link.get(txid) {
            let links = self.links.read().await;
            return Ok(links.get(link_id).cloned());
        }
        Ok(None)
    }

    async fn delete_link(&self, link_id: &LinkId) -> P4Result<()> {
        let mut links = self.links.write().await;
        if let Some(link) = links.remove(link_id) {
            // 清理索引
            let mut input_to_link = self.input_to_link.write().await;
            input_to_link.remove(&link.input_id);

            let mut txid_to_link = self.txid_to_link.write().await;
            txid_to_link.remove(&link.txid_or_asset_id);
        }
        Ok(())
    }

    // ==================== Reconcile 操作 ====================

    async fn save_reconcile(&self, result: &ReconcileResult) -> P4Result<()> {
        let mut reconciles = self.reconciles.write().await;
        reconciles.insert(result.reconcile_id, result.clone());

        // 更新索引
        let mut input_to_reconcile = self.input_to_reconcile.write().await;
        input_to_reconcile.insert(result.input_id, result.reconcile_id);

        Ok(())
    }

    async fn get_reconcile(&self, reconcile_id: &ReconcileId) -> P4Result<Option<ReconcileResult>> {
        let reconciles = self.reconciles.read().await;
        Ok(reconciles.get(reconcile_id).cloned())
    }

    async fn get_reconcile_by_input(&self, input_id: &InputId) -> P4Result<Option<ReconcileResult>> {
        let input_to_reconcile = self.input_to_reconcile.read().await;
        if let Some(reconcile_id) = input_to_reconcile.get(input_id) {
            let reconciles = self.reconciles.read().await;
            return Ok(reconciles.get(reconcile_id).cloned());
        }
        Ok(None)
    }

    async fn delete_reconcile(&self, reconcile_id: &ReconcileId) -> P4Result<()> {
        let mut reconciles = self.reconciles.write().await;
        if let Some(result) = reconciles.remove(reconcile_id) {
            let mut input_to_reconcile = self.input_to_reconcile.write().await;
            input_to_reconcile.remove(&result.input_id);
        }
        Ok(())
    }

    // ==================== 批量操作 ====================

    async fn get_stats(&self) -> P4Result<StorageStats> {
        let inputs = self.inputs.read().await;
        let jobs = self.jobs.read().await;
        let links = self.links.read().await;
        let reconciles = self.reconciles.read().await;

        let pending_inputs = inputs
            .values()
            .filter(|i| matches!(i.status, InputStatus::Pending | InputStatus::Queued))
            .count() as u64;

        let must_inputs = inputs
            .values()
            .filter(|i| i.priority == AnchorPriority::Must)
            .count() as u64;

        let pending_jobs = jobs
            .values()
            .filter(|j| matches!(j.status, JobStatus::Queued | JobStatus::Submitted))
            .count() as u64;

        let retry_scheduled_jobs = jobs
            .values()
            .filter(|j| j.status == JobStatus::RetryScheduled)
            .count() as u64;

        let confirmed_links = links
            .values()
            .filter(|l| l.status == LinkStatus::Confirmed)
            .count() as u64;

        let successful_reconciles = reconciles
            .values()
            .filter(|r| r.status == ReconcileStatus::Success)
            .count() as u64;

        Ok(StorageStats {
            total_inputs: inputs.len() as u64,
            pending_inputs,
            must_inputs,
            total_jobs: jobs.len() as u64,
            pending_jobs,
            retry_scheduled_jobs,
            total_links: links.len() as u64,
            confirmed_links,
            total_reconciles: reconciles.len() as u64,
            successful_reconciles,
        })
    }

    async fn cleanup_expired(&self, before_timestamp: u64) -> P4Result<u64> {
        let mut count = 0u64;

        // 清理过期的已完成输入
        {
            let mut inputs = self.inputs.write().await;
            let to_remove: Vec<InputId> = inputs
                .iter()
                .filter(|(_, i)| {
                    i.status == InputStatus::Completed
                        && i.created_at.as_millis() < before_timestamp
                })
                .map(|(id, _)| *id)
                .collect();

            for id in to_remove {
                inputs.remove(&id);
                count += 1;
            }
        }

        // 清理过期的已完成作业
        {
            let mut jobs = self.jobs.write().await;
            let to_remove: Vec<JobId> = jobs
                .iter()
                .filter(|(_, j)| {
                    j.status == JobStatus::Finalized
                        && j.created_at.as_millis() < before_timestamp
                })
                .map(|(id, _)| *id)
                .collect();

            for id in to_remove {
                jobs.remove(&id);
                count += 1;
            }
        }

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ChainType, PolicyVersion};

    fn create_test_input(priority: AnchorPriority) -> ChainAnchorInput {
        // 使用不同的 epoch_sequence 确保每个输入有唯一的 input_id
        let epoch_seq = match priority {
            AnchorPriority::Must => 1,
            AnchorPriority::Should => 2,
            AnchorPriority::May => 3,
        };
        ChainAnchorInput::new(
            epoch_seq,
            [0x12; 32],
            [0x34; 32],
            priority,
        )
    }

    fn create_test_job(input_id: InputId) -> ChainAnchorJob {
        ChainAnchorJob::new(
            input_id,
            [0x56; 32],
            ChainType::Bitcoin,
            AnchorPriority::Must,
            10000,
        )
    }

    fn create_test_link(input_id: InputId, job_id: JobId) -> ChainAnchorLink {
        ChainAnchorLink::new(
            job_id,
            input_id,
            ChainType::Bitcoin,
            "txid123".to_string(),
            1,
            [0x78; 32],
            [0x9A; 32],
            PolicyVersion::new(1),
        )
    }

    #[tokio::test]
    async fn test_input_crud() {
        let storage = MemoryStorage::new();

        // Create
        let input = create_test_input(AnchorPriority::Must);
        storage.save_input(&input).await.unwrap();

        // Read
        let retrieved = storage.get_input(&input.input_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().input_id, input.input_id);

        // Delete
        storage.delete_input(&input.input_id).await.unwrap();
        let deleted = storage.get_input(&input.input_id).await.unwrap();
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn test_must_input_persistence() {
        let storage = MemoryStorage::new();

        let must_input = create_test_input(AnchorPriority::Must);
        let should_input = create_test_input(AnchorPriority::Should);

        storage.save_input(&must_input).await.unwrap();
        storage.save_input(&should_input).await.unwrap();

        let must_inputs = storage.load_persisted_must_inputs().await.unwrap();
        assert_eq!(must_inputs.len(), 1);
        assert_eq!(must_inputs[0].input_id, must_input.input_id);
    }

    #[tokio::test]
    async fn test_job_idempotency_index() {
        let storage = MemoryStorage::new();

        let input = create_test_input(AnchorPriority::Must);
        let job = create_test_job(input.input_id);

        storage.save_job(&job).await.unwrap();

        // 通过幂等键查询
        let retrieved = storage
            .get_job_by_idempotency_key(&job.idempotency_key)
            .await
            .unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().job_id, job.job_id);
    }

    #[tokio::test]
    async fn test_link_txid_index() {
        let storage = MemoryStorage::new();

        let input = create_test_input(AnchorPriority::Must);
        let job = create_test_job(input.input_id);
        let link = create_test_link(input.input_id, job.job_id);

        storage.save_link(&link).await.unwrap();

        // 通过 txid 查询
        let retrieved = storage.get_link_by_txid("txid123").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().link_id, link.link_id);

        // 通过 input_id 查询
        let by_input = storage.get_link_by_input(&input.input_id).await.unwrap();
        assert!(by_input.is_some());
    }

    #[tokio::test]
    async fn test_storage_stats() {
        let storage = MemoryStorage::new();

        let input = create_test_input(AnchorPriority::Must);
        let job = create_test_job(input.input_id);
        let link = create_test_link(input.input_id, job.job_id);

        storage.save_input(&input).await.unwrap();
        storage.save_job(&job).await.unwrap();
        storage.save_link(&link).await.unwrap();

        let stats = storage.get_stats().await.unwrap();
        assert_eq!(stats.total_inputs, 1);
        assert_eq!(stats.total_jobs, 1);
        assert_eq!(stats.total_links, 1);
        assert_eq!(stats.must_inputs, 1);
    }

    #[tokio::test]
    async fn test_list_by_priority() {
        let storage = MemoryStorage::new();

        let must_input = create_test_input(AnchorPriority::Must);
        let should_input = create_test_input(AnchorPriority::Should);
        let may_input = create_test_input(AnchorPriority::May);

        storage.save_input(&must_input).await.unwrap();
        storage.save_input(&should_input).await.unwrap();
        storage.save_input(&may_input).await.unwrap();

        let must_list = storage.list_inputs_by_priority(AnchorPriority::Must).await.unwrap();
        assert_eq!(must_list.len(), 1);

        let should_list = storage.list_inputs_by_priority(AnchorPriority::Should).await.unwrap();
        assert_eq!(should_list.len(), 1);
    }

    #[tokio::test]
    async fn test_clear() {
        let storage = MemoryStorage::new();

        let input = create_test_input(AnchorPriority::Must);
        storage.save_input(&input).await.unwrap();

        let stats = storage.get_stats().await.unwrap();
        assert_eq!(stats.total_inputs, 1);

        storage.clear().await;

        let stats = storage.get_stats().await.unwrap();
        assert_eq!(stats.total_inputs, 0);
    }
}
