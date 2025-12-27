//! Actor repository - Identity Ledger storage

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

use crate::error::L0DbResult;

/// Actor entity for SurrealDB storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorEntity {
    pub id: String,
    pub actor_id: String,
    pub actor_type: String,
    pub node_actor_id: String,
    pub public_key: String,
    pub payment_address_slot: Option<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub receipt_id: Option<String>,
    pub metadata_digest: Option<String>,
}

/// Actor repository trait
#[async_trait]
pub trait ActorRepository: Send + Sync {
    async fn create(&self, entity: ActorEntity) -> L0DbResult<ActorEntity>;
    async fn get_by_id(&self, actor_id: &str) -> L0DbResult<Option<ActorEntity>>;
    async fn get_by_pubkey(&self, public_key: &str) -> L0DbResult<Option<ActorEntity>>;
    async fn update_status(&self, actor_id: &str, status: &str) -> L0DbResult<()>;
    async fn update_pubkey(&self, actor_id: &str, new_pubkey: &str) -> L0DbResult<()>;
    async fn list_by_type(&self, actor_type: Option<&str>, limit: u32) -> L0DbResult<Vec<ActorEntity>>;
}
