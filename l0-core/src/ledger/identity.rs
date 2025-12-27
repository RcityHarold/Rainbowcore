//! Identity Ledger - Actor registration and key management
//!
//! The Identity Ledger is the authoritative source for:
//! - Actor registration (human, AI, node, group)
//! - Public key bindings
//! - Key rotation history
//! - Actor status tracking

use async_trait::async_trait;
use crate::types::{
    ActorId, ActorRecord, ActorStatus, ActorType,
    KeyRotateRecord, Digest, ReceiptId,
};
use super::{Ledger, LedgerResult, QueryOptions};

/// Identity Ledger trait
#[async_trait]
pub trait IdentityLedger: Ledger {
    /// Register a new actor
    async fn register_actor(
        &self,
        actor_type: ActorType,
        public_key: String,
        node_actor_id: String,
    ) -> LedgerResult<ActorRecord>;

    /// Get actor by ID
    async fn get_actor(&self, actor_id: &ActorId) -> LedgerResult<Option<ActorRecord>>;

    /// Get actor by public key
    async fn get_actor_by_pubkey(&self, public_key: &str) -> LedgerResult<Option<ActorRecord>>;

    /// Update actor status
    async fn update_status(
        &self,
        actor_id: &ActorId,
        new_status: ActorStatus,
        reason_digest: Option<Digest>,
    ) -> LedgerResult<ReceiptId>;

    /// Rotate actor's key
    async fn rotate_key(
        &self,
        actor_id: &ActorId,
        new_public_key: String,
        reason_digest: Option<Digest>,
    ) -> LedgerResult<KeyRotateRecord>;

    /// Get key rotation history
    async fn get_key_history(
        &self,
        actor_id: &ActorId,
        options: QueryOptions,
    ) -> LedgerResult<Vec<KeyRotateRecord>>;

    /// List actors by type
    async fn list_actors(
        &self,
        actor_type: Option<ActorType>,
        status: Option<ActorStatus>,
        options: QueryOptions,
    ) -> LedgerResult<Vec<ActorRecord>>;

    /// Verify actor exists and is active
    async fn verify_actor(&self, actor_id: &ActorId) -> LedgerResult<bool> {
        match self.get_actor(actor_id).await? {
            Some(actor) => Ok(actor.status == ActorStatus::Active),
            None => Ok(false),
        }
    }
}
