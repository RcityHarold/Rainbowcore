//! Sled 持久化存储实现
//!
//! 提供基于 Sled 嵌入式数据库的持久化存储实现。

use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};
use std::path::Path;

use super::{AnchorStorage, StorageConfig, StorageStats};
use crate::error::{P4Error, P4Result};
use crate::types::{
    AnchorPriority, ChainAnchorInput, ChainAnchorJob, ChainAnchorLink, IdempotencyKey,
    InputId, InputStatus, JobId, JobStatus, LinkId, LinkStatus, ReconcileId,
    ReconcileResult, ReconcileStatus,
};

/// Tree 名称常量
const INPUTS_TREE: &str = "inputs";
const JOBS_TREE: &str = "jobs";
const LINKS_TREE: &str = "links";
const RECONCILES_TREE: &str = "reconciles";
const IDEMPOTENCY_INDEX_TREE: &str = "idempotency_index";
const INPUT_TO_JOBS_TREE: &str = "input_to_jobs";
const INPUT_TO_LINK_TREE: &str = "input_to_link";
const INPUT_TO_RECONCILE_TREE: &str = "input_to_reconcile";
const TXID_TO_LINK_TREE: &str = "txid_to_link";
const MUST_INPUTS_TREE: &str = "must_inputs";

/// Sled 持久化存储
///
/// 使用 Sled 嵌入式数据库进行持久化存储。
#[derive(Debug, Clone)]
pub struct SledStorage {
    db: sled::Db,
    inputs: sled::Tree,
    jobs: sled::Tree,
    links: sled::Tree,
    reconciles: sled::Tree,
    idempotency_index: sled::Tree,
    input_to_jobs: sled::Tree,
    input_to_link: sled::Tree,
    input_to_reconcile: sled::Tree,
    txid_to_link: sled::Tree,
    must_inputs: sled::Tree,
}

impl SledStorage {
    /// 使用配置创建新的 Sled 存储
    pub fn new(config: &StorageConfig) -> P4Result<Self> {
        Self::open(&config.data_dir)
    }

    /// 打开或创建 Sled 数据库
    pub fn open<P: AsRef<Path>>(path: P) -> P4Result<Self> {
        let db = sled::open(path).map_err(|e| P4Error::Storage(format!("Failed to open sled db: {}", e)))?;

        let inputs = db.open_tree(INPUTS_TREE)
            .map_err(|e| P4Error::Storage(format!("Failed to open inputs tree: {}", e)))?;
        let jobs = db.open_tree(JOBS_TREE)
            .map_err(|e| P4Error::Storage(format!("Failed to open jobs tree: {}", e)))?;
        let links = db.open_tree(LINKS_TREE)
            .map_err(|e| P4Error::Storage(format!("Failed to open links tree: {}", e)))?;
        let reconciles = db.open_tree(RECONCILES_TREE)
            .map_err(|e| P4Error::Storage(format!("Failed to open reconciles tree: {}", e)))?;
        let idempotency_index = db.open_tree(IDEMPOTENCY_INDEX_TREE)
            .map_err(|e| P4Error::Storage(format!("Failed to open idempotency_index tree: {}", e)))?;
        let input_to_jobs = db.open_tree(INPUT_TO_JOBS_TREE)
            .map_err(|e| P4Error::Storage(format!("Failed to open input_to_jobs tree: {}", e)))?;
        let input_to_link = db.open_tree(INPUT_TO_LINK_TREE)
            .map_err(|e| P4Error::Storage(format!("Failed to open input_to_link tree: {}", e)))?;
        let input_to_reconcile = db.open_tree(INPUT_TO_RECONCILE_TREE)
            .map_err(|e| P4Error::Storage(format!("Failed to open input_to_reconcile tree: {}", e)))?;
        let txid_to_link = db.open_tree(TXID_TO_LINK_TREE)
            .map_err(|e| P4Error::Storage(format!("Failed to open txid_to_link tree: {}", e)))?;
        let must_inputs = db.open_tree(MUST_INPUTS_TREE)
            .map_err(|e| P4Error::Storage(format!("Failed to open must_inputs tree: {}", e)))?;

        Ok(Self {
            db,
            inputs,
            jobs,
            links,
            reconciles,
            idempotency_index,
            input_to_jobs,
            input_to_link,
            input_to_reconcile,
            txid_to_link,
            must_inputs,
        })
    }

    /// 清空所有数据（慎用）
    pub fn clear(&self) -> P4Result<()> {
        self.inputs.clear().map_err(|e| P4Error::Storage(format!("Failed to clear inputs: {}", e)))?;
        self.jobs.clear().map_err(|e| P4Error::Storage(format!("Failed to clear jobs: {}", e)))?;
        self.links.clear().map_err(|e| P4Error::Storage(format!("Failed to clear links: {}", e)))?;
        self.reconciles.clear().map_err(|e| P4Error::Storage(format!("Failed to clear reconciles: {}", e)))?;
        self.idempotency_index.clear().map_err(|e| P4Error::Storage(format!("Failed to clear idempotency_index: {}", e)))?;
        self.input_to_jobs.clear().map_err(|e| P4Error::Storage(format!("Failed to clear input_to_jobs: {}", e)))?;
        self.input_to_link.clear().map_err(|e| P4Error::Storage(format!("Failed to clear input_to_link: {}", e)))?;
        self.input_to_reconcile.clear().map_err(|e| P4Error::Storage(format!("Failed to clear input_to_reconcile: {}", e)))?;
        self.txid_to_link.clear().map_err(|e| P4Error::Storage(format!("Failed to clear txid_to_link: {}", e)))?;
        self.must_inputs.clear().map_err(|e| P4Error::Storage(format!("Failed to clear must_inputs: {}", e)))?;
        Ok(())
    }

    /// 刷新到磁盘
    pub fn flush(&self) -> P4Result<()> {
        self.db.flush().map_err(|e| P4Error::Storage(format!("Failed to flush db: {}", e)))?;
        Ok(())
    }

    // ==================== 辅助方法 ====================

    fn serialize<T: Serialize>(value: &T) -> P4Result<Vec<u8>> {
        serde_json::to_vec(value).map_err(|e| P4Error::Serialization(e.to_string()))
    }

    fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> P4Result<T> {
        serde_json::from_slice(bytes).map_err(|e| P4Error::Serialization(e.to_string()))
    }

    fn input_id_to_key(id: &InputId) -> Vec<u8> {
        id.to_vec()
    }

    fn job_id_to_key(id: &JobId) -> Vec<u8> {
        id.to_vec()
    }

    fn link_id_to_key(id: &LinkId) -> Vec<u8> {
        id.to_vec()
    }

    fn reconcile_id_to_key(id: &ReconcileId) -> Vec<u8> {
        id.to_vec()
    }

    fn idempotency_key_to_key(key: &IdempotencyKey) -> Vec<u8> {
        key.to_vec()
    }
}

#[async_trait]
impl AnchorStorage for SledStorage {
    // ==================== Input 操作 ====================

    async fn save_input(&self, input: &ChainAnchorInput) -> P4Result<()> {
        let key = Self::input_id_to_key(&input.input_id);
        let value = Self::serialize(input)?;

        self.inputs.insert(&key, value)
            .map_err(|e| P4Error::Storage(format!("Failed to save input: {}", e)))?;

        // 如果是 MUST 级别，也保存到持久化列表
        if input.priority == AnchorPriority::Must {
            let must_value = Self::serialize(input)?;
            self.must_inputs.insert(&key, must_value)
                .map_err(|e| P4Error::Storage(format!("Failed to save must input: {}", e)))?;
        }

        Ok(())
    }

    async fn get_input(&self, input_id: &InputId) -> P4Result<Option<ChainAnchorInput>> {
        let key = Self::input_id_to_key(input_id);

        match self.inputs.get(&key).map_err(|e| P4Error::Storage(format!("Failed to get input: {}", e)))? {
            Some(bytes) => Ok(Some(Self::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    async fn delete_input(&self, input_id: &InputId) -> P4Result<()> {
        let key = Self::input_id_to_key(input_id);

        self.inputs.remove(&key)
            .map_err(|e| P4Error::Storage(format!("Failed to delete input: {}", e)))?;
        self.must_inputs.remove(&key)
            .map_err(|e| P4Error::Storage(format!("Failed to delete must input: {}", e)))?;

        Ok(())
    }

    async fn list_pending_inputs(&self) -> P4Result<Vec<ChainAnchorInput>> {
        let mut inputs = Vec::new();

        for item in self.inputs.iter() {
            let (_, value) = item.map_err(|e| P4Error::Storage(format!("Failed to iterate inputs: {}", e)))?;
            let input: ChainAnchorInput = Self::deserialize(&value)?;
            if matches!(input.status, InputStatus::Pending | InputStatus::Queued) {
                inputs.push(input);
            }
        }

        Ok(inputs)
    }

    async fn list_inputs_by_priority(&self, priority: AnchorPriority) -> P4Result<Vec<ChainAnchorInput>> {
        let mut inputs = Vec::new();

        for item in self.inputs.iter() {
            let (_, value) = item.map_err(|e| P4Error::Storage(format!("Failed to iterate inputs: {}", e)))?;
            let input: ChainAnchorInput = Self::deserialize(&value)?;
            if input.priority == priority {
                inputs.push(input);
            }
        }

        Ok(inputs)
    }

    async fn persist_must_input(&self, input: &ChainAnchorInput) -> P4Result<()> {
        if input.priority != AnchorPriority::Must {
            return Err(P4Error::InvalidInput(
                "Only MUST priority inputs can be persisted".to_string(),
            ));
        }

        let key = Self::input_id_to_key(&input.input_id);
        let value = Self::serialize(input)?;

        self.must_inputs.insert(&key, value)
            .map_err(|e| P4Error::Storage(format!("Failed to persist must input: {}", e)))?;

        Ok(())
    }

    async fn load_persisted_must_inputs(&self) -> P4Result<Vec<ChainAnchorInput>> {
        let mut inputs = Vec::new();

        for item in self.must_inputs.iter() {
            let (_, value) = item.map_err(|e| P4Error::Storage(format!("Failed to iterate must inputs: {}", e)))?;
            let input: ChainAnchorInput = Self::deserialize(&value)?;
            inputs.push(input);
        }

        Ok(inputs)
    }

    // ==================== Job 操作 ====================

    async fn save_job(&self, job: &ChainAnchorJob) -> P4Result<()> {
        let key = Self::job_id_to_key(&job.job_id);
        let value = Self::serialize(job)?;

        self.jobs.insert(&key, value)
            .map_err(|e| P4Error::Storage(format!("Failed to save job: {}", e)))?;

        // 更新幂等键索引
        let idempotency_key = Self::idempotency_key_to_key(&job.idempotency_key);
        self.idempotency_index.insert(&idempotency_key, key.clone())
            .map_err(|e| P4Error::Storage(format!("Failed to update idempotency index: {}", e)))?;

        // 更新输入到作业索引
        let input_key = Self::input_id_to_key(&job.input_id);
        let mut job_ids: Vec<JobId> = match self.input_to_jobs.get(&input_key)
            .map_err(|e| P4Error::Storage(format!("Failed to get input_to_jobs: {}", e)))? {
            Some(bytes) => Self::deserialize(&bytes)?,
            None => Vec::new(),
        };
        if !job_ids.contains(&job.job_id) {
            job_ids.push(job.job_id);
            let job_ids_value = Self::serialize(&job_ids)?;
            self.input_to_jobs.insert(&input_key, job_ids_value)
                .map_err(|e| P4Error::Storage(format!("Failed to update input_to_jobs: {}", e)))?;
        }

        Ok(())
    }

    async fn get_job(&self, job_id: &JobId) -> P4Result<Option<ChainAnchorJob>> {
        let key = Self::job_id_to_key(job_id);

        match self.jobs.get(&key).map_err(|e| P4Error::Storage(format!("Failed to get job: {}", e)))? {
            Some(bytes) => Ok(Some(Self::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    async fn get_job_by_idempotency_key(&self, key: &IdempotencyKey) -> P4Result<Option<ChainAnchorJob>> {
        let idempotency_key = Self::idempotency_key_to_key(key);

        match self.idempotency_index.get(&idempotency_key)
            .map_err(|e| P4Error::Storage(format!("Failed to get idempotency index: {}", e)))? {
            Some(job_key) => {
                match self.jobs.get(&job_key)
                    .map_err(|e| P4Error::Storage(format!("Failed to get job: {}", e)))? {
                    Some(bytes) => Ok(Some(Self::deserialize(&bytes)?)),
                    None => Ok(None),
                }
            }
            None => Ok(None),
        }
    }

    async fn get_jobs_by_input(&self, input_id: &InputId) -> P4Result<Vec<ChainAnchorJob>> {
        let input_key = Self::input_id_to_key(input_id);

        match self.input_to_jobs.get(&input_key)
            .map_err(|e| P4Error::Storage(format!("Failed to get input_to_jobs: {}", e)))? {
            Some(bytes) => {
                let job_ids: Vec<JobId> = Self::deserialize(&bytes)?;
                let mut jobs = Vec::new();
                for job_id in job_ids {
                    if let Some(job) = self.get_job(&job_id).await? {
                        jobs.push(job);
                    }
                }
                Ok(jobs)
            }
            None => Ok(Vec::new()),
        }
    }

    async fn delete_job(&self, job_id: &JobId) -> P4Result<()> {
        let key = Self::job_id_to_key(job_id);

        // 获取作业以便清理索引
        if let Some(bytes) = self.jobs.get(&key)
            .map_err(|e| P4Error::Storage(format!("Failed to get job for deletion: {}", e)))? {
            let job: ChainAnchorJob = Self::deserialize(&bytes)?;

            // 清理幂等键索引
            let idempotency_key = Self::idempotency_key_to_key(&job.idempotency_key);
            self.idempotency_index.remove(&idempotency_key)
                .map_err(|e| P4Error::Storage(format!("Failed to remove idempotency index: {}", e)))?;

            // 清理输入到作业索引
            let input_key = Self::input_id_to_key(&job.input_id);
            if let Some(bytes) = self.input_to_jobs.get(&input_key)
                .map_err(|e| P4Error::Storage(format!("Failed to get input_to_jobs: {}", e)))? {
                let mut job_ids: Vec<JobId> = Self::deserialize(&bytes)?;
                job_ids.retain(|id| id != job_id);
                if job_ids.is_empty() {
                    self.input_to_jobs.remove(&input_key)
                        .map_err(|e| P4Error::Storage(format!("Failed to remove input_to_jobs: {}", e)))?;
                } else {
                    let job_ids_value = Self::serialize(&job_ids)?;
                    self.input_to_jobs.insert(&input_key, job_ids_value)
                        .map_err(|e| P4Error::Storage(format!("Failed to update input_to_jobs: {}", e)))?;
                }
            }
        }

        self.jobs.remove(&key)
            .map_err(|e| P4Error::Storage(format!("Failed to delete job: {}", e)))?;

        Ok(())
    }

    async fn list_pending_jobs(&self) -> P4Result<Vec<ChainAnchorJob>> {
        let mut jobs = Vec::new();

        for item in self.jobs.iter() {
            let (_, value) = item.map_err(|e| P4Error::Storage(format!("Failed to iterate jobs: {}", e)))?;
            let job: ChainAnchorJob = Self::deserialize(&value)?;
            if matches!(job.status, JobStatus::Queued | JobStatus::Submitted) {
                jobs.push(job);
            }
        }

        Ok(jobs)
    }

    async fn list_retry_scheduled_jobs(&self) -> P4Result<Vec<ChainAnchorJob>> {
        let mut jobs = Vec::new();

        for item in self.jobs.iter() {
            let (_, value) = item.map_err(|e| P4Error::Storage(format!("Failed to iterate jobs: {}", e)))?;
            let job: ChainAnchorJob = Self::deserialize(&value)?;
            if job.status == JobStatus::RetryScheduled {
                jobs.push(job);
            }
        }

        Ok(jobs)
    }

    // ==================== Link 操作 ====================

    async fn save_link(&self, link: &ChainAnchorLink) -> P4Result<()> {
        let key = Self::link_id_to_key(&link.link_id);
        let value = Self::serialize(link)?;

        self.links.insert(&key, value)
            .map_err(|e| P4Error::Storage(format!("Failed to save link: {}", e)))?;

        // 更新索引
        let input_key = Self::input_id_to_key(&link.input_id);
        self.input_to_link.insert(&input_key, key.clone())
            .map_err(|e| P4Error::Storage(format!("Failed to update input_to_link: {}", e)))?;

        self.txid_to_link.insert(link.txid_or_asset_id.as_bytes(), key)
            .map_err(|e| P4Error::Storage(format!("Failed to update txid_to_link: {}", e)))?;

        Ok(())
    }

    async fn get_link(&self, link_id: &LinkId) -> P4Result<Option<ChainAnchorLink>> {
        let key = Self::link_id_to_key(link_id);

        match self.links.get(&key).map_err(|e| P4Error::Storage(format!("Failed to get link: {}", e)))? {
            Some(bytes) => Ok(Some(Self::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    async fn get_link_by_input(&self, input_id: &InputId) -> P4Result<Option<ChainAnchorLink>> {
        let input_key = Self::input_id_to_key(input_id);

        match self.input_to_link.get(&input_key)
            .map_err(|e| P4Error::Storage(format!("Failed to get input_to_link: {}", e)))? {
            Some(link_key) => {
                match self.links.get(&link_key)
                    .map_err(|e| P4Error::Storage(format!("Failed to get link: {}", e)))? {
                    Some(bytes) => Ok(Some(Self::deserialize(&bytes)?)),
                    None => Ok(None),
                }
            }
            None => Ok(None),
        }
    }

    async fn get_link_by_txid(&self, txid: &str) -> P4Result<Option<ChainAnchorLink>> {
        match self.txid_to_link.get(txid.as_bytes())
            .map_err(|e| P4Error::Storage(format!("Failed to get txid_to_link: {}", e)))? {
            Some(link_key) => {
                match self.links.get(&link_key)
                    .map_err(|e| P4Error::Storage(format!("Failed to get link: {}", e)))? {
                    Some(bytes) => Ok(Some(Self::deserialize(&bytes)?)),
                    None => Ok(None),
                }
            }
            None => Ok(None),
        }
    }

    async fn delete_link(&self, link_id: &LinkId) -> P4Result<()> {
        let key = Self::link_id_to_key(link_id);

        // 获取链接以便清理索引
        if let Some(bytes) = self.links.get(&key)
            .map_err(|e| P4Error::Storage(format!("Failed to get link for deletion: {}", e)))? {
            let link: ChainAnchorLink = Self::deserialize(&bytes)?;

            // 清理索引
            let input_key = Self::input_id_to_key(&link.input_id);
            self.input_to_link.remove(&input_key)
                .map_err(|e| P4Error::Storage(format!("Failed to remove input_to_link: {}", e)))?;
            self.txid_to_link.remove(link.txid_or_asset_id.as_bytes())
                .map_err(|e| P4Error::Storage(format!("Failed to remove txid_to_link: {}", e)))?;
        }

        self.links.remove(&key)
            .map_err(|e| P4Error::Storage(format!("Failed to delete link: {}", e)))?;

        Ok(())
    }

    // ==================== Reconcile 操作 ====================

    async fn save_reconcile(&self, result: &ReconcileResult) -> P4Result<()> {
        let key = Self::reconcile_id_to_key(&result.reconcile_id);
        let value = Self::serialize(result)?;

        self.reconciles.insert(&key, value)
            .map_err(|e| P4Error::Storage(format!("Failed to save reconcile: {}", e)))?;

        // 更新索引
        let input_key = Self::input_id_to_key(&result.input_id);
        self.input_to_reconcile.insert(&input_key, key)
            .map_err(|e| P4Error::Storage(format!("Failed to update input_to_reconcile: {}", e)))?;

        Ok(())
    }

    async fn get_reconcile(&self, reconcile_id: &ReconcileId) -> P4Result<Option<ReconcileResult>> {
        let key = Self::reconcile_id_to_key(reconcile_id);

        match self.reconciles.get(&key)
            .map_err(|e| P4Error::Storage(format!("Failed to get reconcile: {}", e)))? {
            Some(bytes) => Ok(Some(Self::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    async fn get_reconcile_by_input(&self, input_id: &InputId) -> P4Result<Option<ReconcileResult>> {
        let input_key = Self::input_id_to_key(input_id);

        match self.input_to_reconcile.get(&input_key)
            .map_err(|e| P4Error::Storage(format!("Failed to get input_to_reconcile: {}", e)))? {
            Some(reconcile_key) => {
                match self.reconciles.get(&reconcile_key)
                    .map_err(|e| P4Error::Storage(format!("Failed to get reconcile: {}", e)))? {
                    Some(bytes) => Ok(Some(Self::deserialize(&bytes)?)),
                    None => Ok(None),
                }
            }
            None => Ok(None),
        }
    }

    async fn delete_reconcile(&self, reconcile_id: &ReconcileId) -> P4Result<()> {
        let key = Self::reconcile_id_to_key(reconcile_id);

        // 获取对账结果以便清理索引
        if let Some(bytes) = self.reconciles.get(&key)
            .map_err(|e| P4Error::Storage(format!("Failed to get reconcile for deletion: {}", e)))? {
            let result: ReconcileResult = Self::deserialize(&bytes)?;

            // 清理索引
            let input_key = Self::input_id_to_key(&result.input_id);
            self.input_to_reconcile.remove(&input_key)
                .map_err(|e| P4Error::Storage(format!("Failed to remove input_to_reconcile: {}", e)))?;
        }

        self.reconciles.remove(&key)
            .map_err(|e| P4Error::Storage(format!("Failed to delete reconcile: {}", e)))?;

        Ok(())
    }

    // ==================== 批量操作 ====================

    async fn get_stats(&self) -> P4Result<StorageStats> {
        let mut stats = StorageStats::default();

        // 统计输入
        for item in self.inputs.iter() {
            let (_, value) = item.map_err(|e| P4Error::Storage(format!("Failed to iterate inputs: {}", e)))?;
            let input: ChainAnchorInput = Self::deserialize(&value)?;
            stats.total_inputs += 1;
            if matches!(input.status, InputStatus::Pending | InputStatus::Queued) {
                stats.pending_inputs += 1;
            }
            if input.priority == AnchorPriority::Must {
                stats.must_inputs += 1;
            }
        }

        // 统计作业
        for item in self.jobs.iter() {
            let (_, value) = item.map_err(|e| P4Error::Storage(format!("Failed to iterate jobs: {}", e)))?;
            let job: ChainAnchorJob = Self::deserialize(&value)?;
            stats.total_jobs += 1;
            if matches!(job.status, JobStatus::Queued | JobStatus::Submitted) {
                stats.pending_jobs += 1;
            }
            if job.status == JobStatus::RetryScheduled {
                stats.retry_scheduled_jobs += 1;
            }
        }

        // 统计链接
        for item in self.links.iter() {
            let (_, value) = item.map_err(|e| P4Error::Storage(format!("Failed to iterate links: {}", e)))?;
            let link: ChainAnchorLink = Self::deserialize(&value)?;
            stats.total_links += 1;
            if link.status == LinkStatus::Confirmed {
                stats.confirmed_links += 1;
            }
        }

        // 统计对账结果
        for item in self.reconciles.iter() {
            let (_, value) = item.map_err(|e| P4Error::Storage(format!("Failed to iterate reconciles: {}", e)))?;
            let result: ReconcileResult = Self::deserialize(&value)?;
            stats.total_reconciles += 1;
            if result.status == ReconcileStatus::Success {
                stats.successful_reconciles += 1;
            }
        }

        Ok(stats)
    }

    async fn cleanup_expired(&self, before_timestamp: u64) -> P4Result<u64> {
        let mut count = 0u64;

        // 清理过期的已完成输入
        let mut to_remove_inputs = Vec::new();
        for item in self.inputs.iter() {
            let (key, value) = item.map_err(|e| P4Error::Storage(format!("Failed to iterate inputs: {}", e)))?;
            let input: ChainAnchorInput = Self::deserialize(&value)?;
            if input.status == InputStatus::Completed && input.created_at.as_millis() < before_timestamp {
                to_remove_inputs.push(key.to_vec());
            }
        }
        for key in to_remove_inputs {
            self.inputs.remove(&key)
                .map_err(|e| P4Error::Storage(format!("Failed to remove expired input: {}", e)))?;
            count += 1;
        }

        // 清理过期的已完成作业
        let mut to_remove_jobs = Vec::new();
        for item in self.jobs.iter() {
            let (key, value) = item.map_err(|e| P4Error::Storage(format!("Failed to iterate jobs: {}", e)))?;
            let job: ChainAnchorJob = Self::deserialize(&value)?;
            if job.status == JobStatus::Finalized && job.created_at.as_millis() < before_timestamp {
                to_remove_jobs.push(key.to_vec());
            }
        }
        for key in to_remove_jobs {
            self.jobs.remove(&key)
                .map_err(|e| P4Error::Storage(format!("Failed to remove expired job: {}", e)))?;
            count += 1;
        }

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ChainType, PolicyVersion};
    use tempfile::tempdir;

    fn create_test_input(epoch_seq: u64, priority: AnchorPriority) -> ChainAnchorInput {
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
    async fn test_sled_input_crud() {
        let dir = tempdir().unwrap();
        let storage = SledStorage::open(dir.path()).unwrap();

        // Create
        let input = create_test_input(1, AnchorPriority::Must);
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
    async fn test_sled_must_input_persistence() {
        let dir = tempdir().unwrap();
        let storage = SledStorage::open(dir.path()).unwrap();

        let must_input = create_test_input(1, AnchorPriority::Must);
        let should_input = create_test_input(2, AnchorPriority::Should);

        storage.save_input(&must_input).await.unwrap();
        storage.save_input(&should_input).await.unwrap();

        let must_inputs = storage.load_persisted_must_inputs().await.unwrap();
        assert_eq!(must_inputs.len(), 1);
        assert_eq!(must_inputs[0].input_id, must_input.input_id);
    }

    #[tokio::test]
    async fn test_sled_job_idempotency_index() {
        let dir = tempdir().unwrap();
        let storage = SledStorage::open(dir.path()).unwrap();

        let input = create_test_input(1, AnchorPriority::Must);
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
    async fn test_sled_link_txid_index() {
        let dir = tempdir().unwrap();
        let storage = SledStorage::open(dir.path()).unwrap();

        let input = create_test_input(1, AnchorPriority::Must);
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
    async fn test_sled_storage_stats() {
        let dir = tempdir().unwrap();
        let storage = SledStorage::open(dir.path()).unwrap();

        let input = create_test_input(1, AnchorPriority::Must);
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
    async fn test_sled_list_by_priority() {
        let dir = tempdir().unwrap();
        let storage = SledStorage::open(dir.path()).unwrap();

        let must_input = create_test_input(1, AnchorPriority::Must);
        let should_input = create_test_input(2, AnchorPriority::Should);
        let may_input = create_test_input(3, AnchorPriority::May);

        storage.save_input(&must_input).await.unwrap();
        storage.save_input(&should_input).await.unwrap();
        storage.save_input(&may_input).await.unwrap();

        let must_list = storage.list_inputs_by_priority(AnchorPriority::Must).await.unwrap();
        assert_eq!(must_list.len(), 1);

        let should_list = storage.list_inputs_by_priority(AnchorPriority::Should).await.unwrap();
        assert_eq!(should_list.len(), 1);
    }

    #[tokio::test]
    async fn test_sled_persistence() {
        let dir = tempdir().unwrap();

        // 创建存储并写入数据
        {
            let storage = SledStorage::open(dir.path()).unwrap();
            let input = create_test_input(1, AnchorPriority::Must);
            storage.save_input(&input).await.unwrap();
            storage.flush().unwrap();
        }

        // 重新打开存储并验证数据仍然存在
        {
            let storage = SledStorage::open(dir.path()).unwrap();
            let inputs = storage.list_inputs_by_priority(AnchorPriority::Must).await.unwrap();
            assert_eq!(inputs.len(), 1);
        }
    }

    #[tokio::test]
    async fn test_sled_clear() {
        let dir = tempdir().unwrap();
        let storage = SledStorage::open(dir.path()).unwrap();

        let input = create_test_input(1, AnchorPriority::Must);
        storage.save_input(&input).await.unwrap();

        let stats = storage.get_stats().await.unwrap();
        assert_eq!(stats.total_inputs, 1);

        storage.clear().unwrap();

        let stats = storage.get_stats().await.unwrap();
        assert_eq!(stats.total_inputs, 0);
    }
}
