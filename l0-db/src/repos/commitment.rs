//! Commitment repository - Causality Ledger storage

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

use crate::error::L0DbResult;

/// Commitment entity for SurrealDB storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentEntity {
    pub id: String,
    pub commitment_id: String,
    pub actor_id: String,
    pub scope_type: String,
    pub commitment_digest: String,
    pub parent_commitment_ref: Option<String>,
    pub sequence_no: u64,
    pub created_at: DateTime<Utc>,
    pub receipt_id: Option<String>,
}

/// Commitment repository trait
#[async_trait]
pub trait CommitmentRepository: Send + Sync {
    async fn create(&self, entity: CommitmentEntity) -> L0DbResult<CommitmentEntity>;
    async fn get_by_id(&self, commitment_id: &str) -> L0DbResult<Option<CommitmentEntity>>;
    async fn get_chain(&self, actor_id: &str, limit: u32) -> L0DbResult<Vec<CommitmentEntity>>;
    async fn get_latest(&self, actor_id: &str) -> L0DbResult<Option<CommitmentEntity>>;
}
