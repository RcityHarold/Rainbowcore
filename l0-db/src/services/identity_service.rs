//! Identity Ledger Service Implementation
//!
//! Implements the IdentityLedger trait using l0-db repositories.

use async_trait::async_trait;
use chrono::Utc;
use l0_core::error::LedgerError;
use l0_core::ledger::{IdentityLedger, Ledger, LedgerResult, QueryOptions};
use l0_core::types::{
    ActorId, ActorRecord, ActorStatus, ActorType, Digest, KeyRotateRecord, NodeActorId, ReceiptId,
};
use soulbase_types::prelude::TenantId;
use std::sync::Arc;

use crate::entities::ActorEntity;
use crate::repos::L0Database;
use crate::error::L0DbError;

/// Identity Ledger Service
pub struct IdentityService {
    database: Arc<L0Database>,
    tenant_id: TenantId,
    sequence: std::sync::atomic::AtomicU64,
}

impl IdentityService {
    /// Create a new Identity Service
    pub fn new(database: Arc<L0Database>, tenant_id: TenantId) -> Self {
        Self {
            database,
            tenant_id,
            sequence: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Generate a new actor ID
    fn generate_actor_id(&self) -> ActorId {
        let seq = self
            .sequence
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let timestamp = Utc::now().timestamp_micros();
        ActorId(format!("actor_{:016x}_{:08x}", timestamp, seq))
    }

    /// Convert database error to ledger error
    fn map_db_error(e: L0DbError) -> LedgerError {
        LedgerError::Storage(e.to_string())
    }

    /// Convert ActorEntity to ActorRecord
    fn entity_to_record(entity: &ActorEntity) -> ActorRecord {
        ActorRecord {
            actor_id: ActorId(entity.actor_id.clone()),
            actor_type: match entity.actor_type.as_str() {
                "human_actor" => ActorType::HumanActor,
                "ai_actor" => ActorType::AiActor,
                "node_actor" => ActorType::NodeActor,
                "group_actor" => ActorType::GroupActor,
                _ => ActorType::HumanActor, // fallback
            },
            node_actor_id: NodeActorId(entity.node_actor_id.clone()),
            public_key: entity.public_key.clone(),
            payment_address_slot: entity.payment_address_slot.clone(),
            status: match entity.status.as_str() {
                "active" => ActorStatus::Active,
                "suspended" => ActorStatus::Suspended,
                "in_repair" => ActorStatus::InRepair,
                "terminated" => ActorStatus::Terminated,
                _ => ActorStatus::Active,
            },
            created_at: entity.created_at,
            updated_at: entity.updated_at,
            receipt_id: entity.receipt_id.as_ref().map(|id| ReceiptId(id.clone())),
            metadata_digest: entity
                .metadata_digest
                .as_ref()
                .map(|d| Digest::from_hex(d).unwrap_or_default()),
        }
    }
}

#[async_trait]
impl Ledger for IdentityService {
    fn name(&self) -> &'static str {
        "identity"
    }

    async fn current_sequence(&self) -> LedgerResult<u64> {
        Ok(self.sequence.load(std::sync::atomic::Ordering::SeqCst))
    }

    async fn current_root(&self) -> LedgerResult<Digest> {
        // TODO: Compute actual Merkle root of all actors
        Ok(Digest::zero())
    }

    async fn verify_integrity(&self) -> LedgerResult<bool> {
        // TODO: Implement integrity verification
        Ok(true)
    }
}

#[async_trait]
impl IdentityLedger for IdentityService {
    async fn register_actor(
        &self,
        actor_type: ActorType,
        public_key: String,
        node_actor_id: String,
    ) -> LedgerResult<ActorRecord> {
        let actor_id = self.generate_actor_id();

        let type_str = match actor_type {
            ActorType::HumanActor => "human_actor",
            ActorType::AiActor => "ai_actor",
            ActorType::NodeActor => "node_actor",
            ActorType::GroupActor => "group_actor",
        };

        let entity = ActorEntity::new(
            self.tenant_id.clone(),
            actor_id.0.clone(),
            type_str.to_string(),
            node_actor_id,
            public_key,
        );

        let created = self
            .database
            .actors
            .create(&entity)
            .await
            .map_err(Self::map_db_error)?;

        Ok(Self::entity_to_record(&created))
    }

    async fn get_actor(&self, actor_id: &ActorId) -> LedgerResult<Option<ActorRecord>> {
        let result = self
            .database
            .actors
            .get_by_id(&self.tenant_id, &actor_id.0)
            .await
            .map_err(Self::map_db_error)?;

        Ok(result.map(|e| Self::entity_to_record(&e)))
    }

    async fn get_actor_by_pubkey(&self, public_key: &str) -> LedgerResult<Option<ActorRecord>> {
        let result = self
            .database
            .actors
            .get_by_pubkey(&self.tenant_id, public_key)
            .await
            .map_err(Self::map_db_error)?;

        Ok(result.map(|e| Self::entity_to_record(&e)))
    }

    async fn update_status(
        &self,
        actor_id: &ActorId,
        new_status: ActorStatus,
        _reason_digest: Option<Digest>,
    ) -> LedgerResult<ReceiptId> {
        let status_str = match new_status {
            ActorStatus::Active => "active",
            ActorStatus::Suspended => "suspended",
            ActorStatus::InRepair => "in_repair",
            ActorStatus::Terminated => "terminated",
        };

        self.database
            .actors
            .update_status(&self.tenant_id, &actor_id.0, status_str)
            .await
            .map_err(Self::map_db_error)?;

        // TODO: Generate actual receipt
        let receipt_id = ReceiptId(format!("receipt_{}", Utc::now().timestamp_micros()));
        Ok(receipt_id)
    }

    async fn rotate_key(
        &self,
        actor_id: &ActorId,
        new_public_key: String,
        reason_digest: Option<Digest>,
    ) -> LedgerResult<KeyRotateRecord> {
        // Get current actor to capture old key
        let actor = self
            .get_actor(actor_id)
            .await?
            .ok_or_else(|| LedgerError::NotFound(format!("Actor {} not found", actor_id.0)))?;

        let old_key = actor.public_key.clone();

        // Update the key
        self.database
            .actors
            .rotate_key(&self.tenant_id, &actor_id.0, &new_public_key)
            .await
            .map_err(Self::map_db_error)?;

        // Create rotation record
        let record = KeyRotateRecord {
            actor_id: actor_id.clone(),
            old_public_key: old_key,
            new_public_key,
            rotated_at: Utc::now(),
            reason_digest,
            receipt_id: None, // TODO: Generate receipt
        };

        Ok(record)
    }

    async fn get_key_history(
        &self,
        _actor_id: &ActorId,
        _options: QueryOptions,
    ) -> LedgerResult<Vec<KeyRotateRecord>> {
        // TODO: Implement key history retrieval from l0_key_rotation table
        Ok(vec![])
    }

    async fn list_actors(
        &self,
        actor_type: Option<ActorType>,
        _status: Option<ActorStatus>,
        options: QueryOptions,
    ) -> LedgerResult<Vec<ActorRecord>> {
        let type_str = actor_type.map(|t| match t {
            ActorType::HumanActor => "human_actor",
            ActorType::AiActor => "ai_actor",
            ActorType::NodeActor => "node_actor",
            ActorType::GroupActor => "group_actor",
        });

        let limit = options.limit.unwrap_or(100);

        let entities = self
            .database
            .actors
            .list_by_type(&self.tenant_id, type_str, limit)
            .await
            .map_err(Self::map_db_error)?;

        Ok(entities.iter().map(Self::entity_to_record).collect())
    }
}
