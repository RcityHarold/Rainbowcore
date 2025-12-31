//! Actor repository implementation

use soulbase_storage::model::Entity;
use soulbase_storage::spi::Datastore;
use soulbase_storage::surreal::SurrealDatastore;
use soulbase_types::prelude::TenantId;
use std::sync::Arc;

use crate::entities::ActorEntity;
use crate::error::{L0DbError, L0DbResult};

/// L0 Actor Repository
pub struct L0ActorRepo {
    datastore: Arc<SurrealDatastore>,
}

impl L0ActorRepo {
    pub fn new(datastore: Arc<SurrealDatastore>) -> Self {
        Self { datastore }
    }

    /// Create a new actor
    pub async fn create(&self, entity: &ActorEntity) -> L0DbResult<ActorEntity> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        // Create the entity and then select with type::string(id) to convert Thing to String
        let create_query = format!("CREATE {} CONTENT $data", ActorEntity::TABLE);
        let entity_clone = entity.clone();

        client
            .query(&create_query)
            .bind(("data", entity_clone))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        // Fetch the created entity with proper id conversion
        let select_query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND actor_id = $actor_id LIMIT 1",
            ActorEntity::TABLE
        );

        let actor_id_str = entity.actor_id.clone();
        let tenant_str = entity.tenant_id.0.clone();
        let mut response = client
            .query(&select_query)
            .bind(("tenant", tenant_str))
            .bind(("actor_id", actor_id_str))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        let result: Option<ActorEntity> = response
            .take(0)
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        result.ok_or_else(|| L0DbError::QueryError("Failed to create actor".to_string()))
    }

    /// Get actor by ID
    pub async fn get_by_id(
        &self,
        tenant: &TenantId,
        actor_id: &str,
    ) -> L0DbResult<Option<ActorEntity>> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND actor_id = $actor_id LIMIT 1",
            ActorEntity::TABLE
        );

        let tenant_str = tenant.0.clone();
        let actor_id_str = actor_id.to_string();

        let mut response = client
            .query(&query)
            .bind(("tenant", tenant_str))
            .bind(("actor_id", actor_id_str))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        let result: Option<ActorEntity> = response
            .take(0)
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        Ok(result)
    }

    /// Get actor by public key
    pub async fn get_by_pubkey(
        &self,
        tenant: &TenantId,
        public_key: &str,
    ) -> L0DbResult<Option<ActorEntity>> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND public_key = $pubkey LIMIT 1",
            ActorEntity::TABLE
        );

        let tenant_str = tenant.0.clone();
        let pubkey_str = public_key.to_string();

        let mut response = client
            .query(&query)
            .bind(("tenant", tenant_str))
            .bind(("pubkey", pubkey_str))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        let result: Option<ActorEntity> = response
            .take(0)
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        Ok(result)
    }

    /// Update actor status
    pub async fn update_status(
        &self,
        tenant: &TenantId,
        actor_id: &str,
        status: &str,
    ) -> L0DbResult<()> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        let query = format!(
            "UPDATE {} SET status = $status, updated_at = time::now() WHERE tenant_id = $tenant AND actor_id = $actor_id",
            ActorEntity::TABLE
        );

        let tenant_str = tenant.0.clone();
        let actor_id_str = actor_id.to_string();
        let status_str = status.to_string();

        client
            .query(&query)
            .bind(("tenant", tenant_str))
            .bind(("actor_id", actor_id_str))
            .bind(("status", status_str))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        Ok(())
    }

    /// Update actor public key (key rotation)
    pub async fn rotate_key(
        &self,
        tenant: &TenantId,
        actor_id: &str,
        new_pubkey: &str,
    ) -> L0DbResult<()> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        let query = format!(
            "UPDATE {} SET public_key = $pubkey, updated_at = time::now() WHERE tenant_id = $tenant AND actor_id = $actor_id",
            ActorEntity::TABLE
        );

        let tenant_str = tenant.0.clone();
        let actor_id_str = actor_id.to_string();
        let pubkey_str = new_pubkey.to_string();

        client
            .query(&query)
            .bind(("tenant", tenant_str))
            .bind(("actor_id", actor_id_str))
            .bind(("pubkey", pubkey_str))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        Ok(())
    }

    /// List actors by type
    pub async fn list_by_type(
        &self,
        tenant: &TenantId,
        actor_type: Option<&str>,
        limit: u32,
    ) -> L0DbResult<Vec<ActorEntity>> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        let tenant_str = tenant.0.clone();

        let mut response = match actor_type {
            Some(at) => {
                let query = format!(
                    "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND actor_type = $type ORDER BY created_at DESC LIMIT $limit",
                    ActorEntity::TABLE
                );
                let actor_type_str = at.to_string();
                client
                    .query(&query)
                    .bind(("tenant", tenant_str))
                    .bind(("type", actor_type_str))
                    .bind(("limit", limit))
                    .await
                    .map_err(|e| L0DbError::QueryError(e.to_string()))?
            }
            None => {
                let query = format!(
                    "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant ORDER BY created_at DESC LIMIT $limit",
                    ActorEntity::TABLE
                );
                client
                    .query(&query)
                    .bind(("tenant", tenant_str))
                    .bind(("limit", limit))
                    .await
                    .map_err(|e| L0DbError::QueryError(e.to_string()))?
            }
        };

        let results: Vec<ActorEntity> = response
            .take(0)
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        Ok(results)
    }

    /// Check if actor exists
    pub async fn exists(&self, tenant: &TenantId, actor_id: &str) -> L0DbResult<bool> {
        Ok(self.get_by_id(tenant, actor_id).await?.is_some())
    }

    /// List all actors for Merkle root computation
    pub async fn list_all(&self, tenant: &TenantId) -> L0DbResult<Vec<ActorEntity>> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant ORDER BY created_at ASC",
            ActorEntity::TABLE
        );

        let tenant_str = tenant.0.clone();
        let mut response = client
            .query(&query)
            .bind(("tenant", tenant_str))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        let results: Vec<ActorEntity> = response
            .take(0)
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        Ok(results)
    }

    /// Create key rotation record
    pub async fn create_key_rotation(
        &self,
        entity: &crate::entities::KeyRotationEntity,
    ) -> L0DbResult<crate::entities::KeyRotationEntity> {
        use soulbase_storage::model::Entity;

        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        let create_query = format!(
            "CREATE {} CONTENT $data",
            crate::entities::KeyRotationEntity::TABLE
        );
        let entity_clone = entity.clone();

        client
            .query(&create_query)
            .bind(("data", entity_clone))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        // Fetch with type::string(id) to convert Thing to String
        let select_query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND actor_id = $actor_id AND rotated_at = $rotated_at LIMIT 1",
            crate::entities::KeyRotationEntity::TABLE
        );

        let tenant_str = entity.tenant_id.0.clone();
        let actor_id_str = entity.actor_id.clone();
        let rotated_at = entity.rotated_at;

        let mut response = client
            .query(&select_query)
            .bind(("tenant", tenant_str))
            .bind(("actor_id", actor_id_str))
            .bind(("rotated_at", rotated_at))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        let result: Option<crate::entities::KeyRotationEntity> = response
            .take(0)
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        result.ok_or_else(|| L0DbError::QueryError("Failed to create key rotation".to_string()))
    }

    /// Get key rotation history for an actor
    pub async fn get_key_rotations(
        &self,
        tenant: &TenantId,
        actor_id: &str,
        limit: u32,
    ) -> L0DbResult<Vec<crate::entities::KeyRotationEntity>> {
        use soulbase_storage::model::Entity;

        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND actor_id = $actor_id ORDER BY rotated_at DESC LIMIT $limit",
            crate::entities::KeyRotationEntity::TABLE
        );

        let tenant_str = tenant.0.clone();
        let actor_id_str = actor_id.to_string();

        let mut response = client
            .query(&query)
            .bind(("tenant", tenant_str))
            .bind(("actor_id", actor_id_str))
            .bind(("limit", limit))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        let results: Vec<crate::entities::KeyRotationEntity> = response
            .take(0)
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        Ok(results)
    }
}
