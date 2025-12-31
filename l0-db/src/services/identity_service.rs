//! Identity Ledger Service Implementation
//!
//! Implements the IdentityLedger trait using l0-db repositories.

use async_trait::async_trait;
use chrono::Utc;
use l0_core::crypto::IncrementalMerkleTree;
use l0_core::error::LedgerError;
use l0_core::ledger::{IdentityLedger, Ledger, LedgerResult, QueryOptions};
use l0_core::types::{
    ActorId, ActorRecord, ActorStatus, ActorType, Digest, KeyRotateRecord, NodeActorId, ReceiptId,
};
use soulbase_types::prelude::TenantId;
use std::sync::Arc;

use soulbase_storage::model::Entity;
use crate::entities::{ActorEntity, KeyRotationEntity};
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
        // Compute Merkle root of all actors
        let actors = self
            .database
            .actors
            .list_all(&self.tenant_id)
            .await
            .map_err(Self::map_db_error)?;

        if actors.is_empty() {
            return Ok(Digest::zero());
        }

        let mut tree = IncrementalMerkleTree::new();
        for actor in &actors {
            // Compute digest from actor data: actor_id + public_key + status
            let actor_data = format!(
                "{}:{}:{}:{}",
                actor.actor_id, actor.actor_type, actor.public_key, actor.status
            );
            let digest = Digest::blake3(actor_data.as_bytes());
            tree.add(digest);
        }

        Ok(tree.root())
    }

    async fn verify_integrity(&self) -> LedgerResult<bool> {
        // Verify integrity by checking:
        // 1. All actors have valid structure
        // 2. No duplicate actor_ids
        // 3. All required fields are present
        let actors = self
            .database
            .actors
            .list_all(&self.tenant_id)
            .await
            .map_err(Self::map_db_error)?;

        let mut seen_ids = std::collections::HashSet::new();
        for actor in &actors {
            // Check for duplicate actor_ids
            if !seen_ids.insert(&actor.actor_id) {
                return Ok(false);
            }

            // Check required fields are not empty
            if actor.actor_id.is_empty()
                || actor.public_key.is_empty()
                || actor.actor_type.is_empty()
            {
                return Ok(false);
            }

            // Validate actor_type
            if !["human_actor", "ai_actor", "node_actor", "group_actor"]
                .contains(&actor.actor_type.as_str())
            {
                return Ok(false);
            }

            // Validate status
            if !["active", "suspended", "in_repair", "terminated"]
                .contains(&actor.status.as_str())
            {
                return Ok(false);
            }
        }

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
        reason_digest: Option<Digest>,
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

        // Generate receipt ID based on action, actor, timestamp and reason
        let seq = self
            .sequence
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let timestamp = Utc::now().timestamp_micros();
        let _reason_digest = reason_digest; // Preserved for future audit logging
        let receipt_id = ReceiptId(format!(
            "rcpt_status_{}_{}_{:016x}_{:08x}",
            actor_id.0, status_str, timestamp, seq
        ));

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
        let now = Utc::now();

        // Update the key in actor table
        self.database
            .actors
            .rotate_key(&self.tenant_id, &actor_id.0, &new_public_key)
            .await
            .map_err(Self::map_db_error)?;

        // Generate receipt ID
        let seq = self
            .sequence
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let receipt_id = ReceiptId(format!(
            "rcpt_keyrot_{}_{:016x}_{:08x}",
            actor_id.0,
            now.timestamp_micros(),
            seq
        ));

        // Create key rotation entity and persist to database
        let rotation_entity = KeyRotationEntity {
            id: format!(
                "{}:{}:{}",
                KeyRotationEntity::TABLE,
                self.tenant_id.0,
                now.timestamp_micros()
            ),
            tenant_id: self.tenant_id.clone(),
            actor_id: actor_id.0.clone(),
            old_public_key: old_key.clone(),
            new_public_key: new_public_key.clone(),
            rotated_at: now,
            reason_digest: reason_digest.as_ref().map(|d| d.to_hex()),
            receipt_id: Some(receipt_id.0.clone()),
        };

        // Save key rotation record
        self.database
            .actors
            .create_key_rotation(&rotation_entity)
            .await
            .map_err(Self::map_db_error)?;

        // Create and return rotation record
        let record = KeyRotateRecord {
            actor_id: actor_id.clone(),
            old_public_key: old_key,
            new_public_key,
            rotated_at: now,
            reason_digest,
            receipt_id: Some(receipt_id),
        };

        Ok(record)
    }

    async fn get_key_history(
        &self,
        actor_id: &ActorId,
        options: QueryOptions,
    ) -> LedgerResult<Vec<KeyRotateRecord>> {
        let limit = options.limit.unwrap_or(100);

        let rotations = self
            .database
            .actors
            .get_key_rotations(&self.tenant_id, &actor_id.0, limit)
            .await
            .map_err(Self::map_db_error)?;

        Ok(rotations
            .into_iter()
            .map(|entity| KeyRotateRecord {
                actor_id: ActorId(entity.actor_id),
                old_public_key: entity.old_public_key,
                new_public_key: entity.new_public_key,
                rotated_at: entity.rotated_at,
                reason_digest: entity
                    .reason_digest
                    .and_then(|d| Digest::from_hex(&d).ok()),
                receipt_id: entity.receipt_id.map(ReceiptId),
            })
            .collect())
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
