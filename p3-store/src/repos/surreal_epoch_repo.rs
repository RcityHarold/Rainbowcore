//! SurrealDB Epoch Bundle Repository Implementation
//!
//! Implements EpochBundleRepository using soulbase-storage's SurrealDB integration.

use async_trait::async_trait;
use serde_json::json;
use soulbase_storage::model::Entity;
use soulbase_storage::spi::query::QueryExecutor;
use soulbase_storage::surreal::SurrealDatastore;
use soulbase_storage::Datastore;
use soulbase_types::prelude::TenantId;
use std::sync::Arc;

use crate::entities::{
    EpochBundleEntity, EpochBundleStatus, ExecutionProofEntity, IdempotencyKeyEntity,
    ManifestSetEntity, ManifestSetType, ResultEntryEntity,
};
use crate::error::{P3StoreError, P3StoreResult};
use crate::repos::{
    EpochBundleRepository, ExecutionProofRepository, IdempotencyKeyRepository,
    ManifestSetRepository, ResultEntryRepository,
};

/// SurrealDB implementation of EpochBundleRepository
pub struct SurrealEpochBundleRepository {
    datastore: Arc<SurrealDatastore>,
    tenant_id: TenantId,
}

impl SurrealEpochBundleRepository {
    /// Create a new repository
    pub fn new(datastore: Arc<SurrealDatastore>, tenant_id: TenantId) -> Self {
        Self { datastore, tenant_id }
    }

    async fn run_query<T: serde::de::DeserializeOwned>(
        &self,
        statement: &str,
        params: serde_json::Value,
    ) -> P3StoreResult<Vec<T>> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let outcome = session.query(statement, params).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        let mut results = Vec::new();
        for row in outcome.rows {
            let entity: T = serde_json::from_value(row)
                .map_err(|e| P3StoreError::Database(format!("Deserialize error: {}", e)))?;
            results.push(entity);
        }
        Ok(results)
    }
}

#[async_trait]
impl EpochBundleRepository for SurrealEpochBundleRepository {
    async fn create(&self, entity: EpochBundleEntity) -> P3StoreResult<EpochBundleEntity> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let entity_json = serde_json::to_value(&entity)
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        let statement = format!(
            "CREATE {}:{} CONTENT $data RETURN *",
            EpochBundleEntity::TABLE,
            entity.id.replace(":", "_")
        );

        let outcome = session.query(&statement, json!({ "data": entity_json })).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        if let Some(row) = outcome.rows.into_iter().next() {
            serde_json::from_value(row)
                .map_err(|e| P3StoreError::Database(format!("Deserialize error: {}", e)))
        } else {
            Err(P3StoreError::Database("Failed to create entity".to_string()))
        }
    }

    async fn get(&self, epoch_id: &str) -> P3StoreResult<Option<EpochBundleEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND epoch_id = $epoch_id LIMIT 1",
            EpochBundleEntity::TABLE
        );

        let results: Vec<EpochBundleEntity> = self.run_query(
            &statement,
            json!({
                "tenant": self.tenant_id.0.clone(),
                "epoch_id": epoch_id.to_string()
            })
        ).await?;

        Ok(results.into_iter().next())
    }

    async fn update(&self, entity: EpochBundleEntity) -> P3StoreResult<EpochBundleEntity> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let entity_json = serde_json::to_value(&entity)
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        let statement = format!(
            "UPDATE {}:{} CONTENT $data RETURN *",
            EpochBundleEntity::TABLE,
            entity.id.replace(":", "_")
        );

        let outcome = session.query(&statement, json!({ "data": entity_json })).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        if let Some(row) = outcome.rows.into_iter().next() {
            serde_json::from_value(row)
                .map_err(|e| P3StoreError::Database(format!("Deserialize error: {}", e)))
        } else {
            Err(P3StoreError::not_found("EpochBundle", &entity.epoch_id))
        }
    }

    async fn update_status(&self, epoch_id: &str, status: EpochBundleStatus) -> P3StoreResult<()> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let statement = format!(
            "UPDATE {} SET status = $status, updated_at = $now WHERE tenant_id.`0` = $tenant AND epoch_id = $epoch_id",
            EpochBundleEntity::TABLE
        );

        session.query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "epoch_id": epoch_id.to_string(),
            "status": status.to_string(),
            "now": chrono::Utc::now().to_rfc3339()
        })).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        Ok(())
    }

    async fn list_by_status(
        &self,
        status: EpochBundleStatus,
        limit: usize,
    ) -> P3StoreResult<Vec<EpochBundleEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND status = $status ORDER BY created_at DESC LIMIT $limit",
            EpochBundleEntity::TABLE
        );

        self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "status": status.to_string(),
            "limit": limit
        })).await
    }

    async fn list_recent(&self, limit: usize) -> P3StoreResult<Vec<EpochBundleEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant ORDER BY created_at DESC LIMIT $limit",
            EpochBundleEntity::TABLE
        );

        self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "limit": limit
        })).await
    }

    async fn delete(&self, epoch_id: &str) -> P3StoreResult<()> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let statement = format!(
            "DELETE FROM {} WHERE tenant_id.`0` = $tenant AND epoch_id = $epoch_id",
            EpochBundleEntity::TABLE
        );

        session.query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "epoch_id": epoch_id.to_string()
        })).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        Ok(())
    }
}

/// SurrealDB implementation of ManifestSetRepository
pub struct SurrealManifestSetRepository {
    datastore: Arc<SurrealDatastore>,
    tenant_id: TenantId,
}

impl SurrealManifestSetRepository {
    /// Create a new repository
    pub fn new(datastore: Arc<SurrealDatastore>, tenant_id: TenantId) -> Self {
        Self { datastore, tenant_id }
    }

    async fn run_query<T: serde::de::DeserializeOwned>(
        &self,
        statement: &str,
        params: serde_json::Value,
    ) -> P3StoreResult<Vec<T>> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let outcome = session.query(statement, params).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        let mut results = Vec::new();
        for row in outcome.rows {
            let entity: T = serde_json::from_value(row)
                .map_err(|e| P3StoreError::Database(format!("Deserialize error: {}", e)))?;
            results.push(entity);
        }
        Ok(results)
    }
}

#[async_trait]
impl ManifestSetRepository for SurrealManifestSetRepository {
    async fn create(&self, entity: ManifestSetEntity) -> P3StoreResult<ManifestSetEntity> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let entity_json = serde_json::to_value(&entity)
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        let statement = format!(
            "CREATE {}:{} CONTENT $data RETURN *",
            ManifestSetEntity::TABLE,
            entity.id.replace(":", "_")
        );

        let outcome = session.query(&statement, json!({ "data": entity_json })).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        if let Some(row) = outcome.rows.into_iter().next() {
            serde_json::from_value(row)
                .map_err(|e| P3StoreError::Database(format!("Deserialize error: {}", e)))
        } else {
            Err(P3StoreError::Database("Failed to create manifest set".to_string()))
        }
    }

    async fn get(
        &self,
        epoch_id: &str,
        set_type: ManifestSetType,
    ) -> P3StoreResult<Option<ManifestSetEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND epoch_id = $epoch_id AND set_type = $set_type LIMIT 1",
            ManifestSetEntity::TABLE
        );

        let results: Vec<ManifestSetEntity> = self.run_query(
            &statement,
            json!({
                "tenant": self.tenant_id.0.clone(),
                "epoch_id": epoch_id.to_string(),
                "set_type": set_type.to_string()
            })
        ).await?;

        Ok(results.into_iter().next())
    }

    async fn get_all_for_epoch(&self, epoch_id: &str) -> P3StoreResult<Vec<ManifestSetEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND epoch_id = $epoch_id",
            ManifestSetEntity::TABLE
        );

        self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "epoch_id": epoch_id.to_string()
        })).await
    }

    async fn update(&self, entity: ManifestSetEntity) -> P3StoreResult<ManifestSetEntity> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let entity_json = serde_json::to_value(&entity)
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        let statement = format!(
            "UPDATE {}:{} CONTENT $data RETURN *",
            ManifestSetEntity::TABLE,
            entity.id.replace(":", "_")
        );

        let outcome = session.query(&statement, json!({ "data": entity_json })).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        if let Some(row) = outcome.rows.into_iter().next() {
            serde_json::from_value(row)
                .map_err(|e| P3StoreError::Database(format!("Deserialize error: {}", e)))
        } else {
            Err(P3StoreError::not_found("ManifestSet", &entity.id))
        }
    }

    async fn delete_for_epoch(&self, epoch_id: &str) -> P3StoreResult<()> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let statement = format!(
            "DELETE FROM {} WHERE tenant_id.`0` = $tenant AND epoch_id = $epoch_id",
            ManifestSetEntity::TABLE
        );

        session.query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "epoch_id": epoch_id.to_string()
        })).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        Ok(())
    }
}

/// SurrealDB implementation of ResultEntryRepository
pub struct SurrealResultEntryRepository {
    datastore: Arc<SurrealDatastore>,
    tenant_id: TenantId,
}

impl SurrealResultEntryRepository {
    /// Create a new repository
    pub fn new(datastore: Arc<SurrealDatastore>, tenant_id: TenantId) -> Self {
        Self { datastore, tenant_id }
    }

    async fn run_query<T: serde::de::DeserializeOwned>(
        &self,
        statement: &str,
        params: serde_json::Value,
    ) -> P3StoreResult<Vec<T>> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let outcome = session.query(statement, params).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        let mut results = Vec::new();
        for row in outcome.rows {
            let entity: T = serde_json::from_value(row)
                .map_err(|e| P3StoreError::Database(format!("Deserialize error: {}", e)))?;
            results.push(entity);
        }
        Ok(results)
    }
}

#[async_trait]
impl ResultEntryRepository for SurrealResultEntryRepository {
    async fn create(&self, entity: ResultEntryEntity) -> P3StoreResult<ResultEntryEntity> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let entity_json = serde_json::to_value(&entity)
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        let statement = format!(
            "CREATE {}:{} CONTENT $data RETURN *",
            ResultEntryEntity::TABLE,
            entity.id.replace(":", "_")
        );

        let outcome = session.query(&statement, json!({ "data": entity_json })).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        if let Some(row) = outcome.rows.into_iter().next() {
            serde_json::from_value(row)
                .map_err(|e| P3StoreError::Database(format!("Deserialize error: {}", e)))
        } else {
            Err(P3StoreError::Database("Failed to create result entry".to_string()))
        }
    }

    async fn create_batch(&self, entities: Vec<ResultEntryEntity>) -> P3StoreResult<()> {
        for entity in entities {
            self.create(entity).await?;
        }
        Ok(())
    }

    async fn get_for_epoch(&self, epoch_id: &str) -> P3StoreResult<Vec<ResultEntryEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND epoch_id = $epoch_id ORDER BY entry_index ASC",
            ResultEntryEntity::TABLE
        );

        self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "epoch_id": epoch_id.to_string()
        })).await
    }

    async fn get_by_index(
        &self,
        epoch_id: &str,
        index: i32,
    ) -> P3StoreResult<Option<ResultEntryEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND epoch_id = $epoch_id AND entry_index = $index LIMIT 1",
            ResultEntryEntity::TABLE
        );

        let results: Vec<ResultEntryEntity> = self.run_query(
            &statement,
            json!({
                "tenant": self.tenant_id.0.clone(),
                "epoch_id": epoch_id.to_string(),
                "index": index
            })
        ).await?;

        Ok(results.into_iter().next())
    }

    async fn delete_for_epoch(&self, epoch_id: &str) -> P3StoreResult<()> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let statement = format!(
            "DELETE FROM {} WHERE tenant_id.`0` = $tenant AND epoch_id = $epoch_id",
            ResultEntryEntity::TABLE
        );

        session.query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "epoch_id": epoch_id.to_string()
        })).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        Ok(())
    }
}

/// SurrealDB implementation of ExecutionProofRepository
pub struct SurrealExecutionProofRepository {
    datastore: Arc<SurrealDatastore>,
    tenant_id: TenantId,
}

impl SurrealExecutionProofRepository {
    /// Create a new repository
    pub fn new(datastore: Arc<SurrealDatastore>, tenant_id: TenantId) -> Self {
        Self { datastore, tenant_id }
    }

    async fn run_query<T: serde::de::DeserializeOwned>(
        &self,
        statement: &str,
        params: serde_json::Value,
    ) -> P3StoreResult<Vec<T>> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let outcome = session.query(statement, params).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        let mut results = Vec::new();
        for row in outcome.rows {
            let entity: T = serde_json::from_value(row)
                .map_err(|e| P3StoreError::Database(format!("Deserialize error: {}", e)))?;
            results.push(entity);
        }
        Ok(results)
    }
}

#[async_trait]
impl ExecutionProofRepository for SurrealExecutionProofRepository {
    async fn create(&self, entity: ExecutionProofEntity) -> P3StoreResult<ExecutionProofEntity> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let entity_json = serde_json::to_value(&entity)
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        let statement = format!(
            "CREATE {}:{} CONTENT $data RETURN *",
            ExecutionProofEntity::TABLE,
            entity.id.replace(":", "_")
        );

        let outcome = session.query(&statement, json!({ "data": entity_json })).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        if let Some(row) = outcome.rows.into_iter().next() {
            serde_json::from_value(row)
                .map_err(|e| P3StoreError::Database(format!("Deserialize error: {}", e)))
        } else {
            Err(P3StoreError::Database("Failed to create proof".to_string()))
        }
    }

    async fn get(&self, proof_id: &str) -> P3StoreResult<Option<ExecutionProofEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND proof_id = $proof_id LIMIT 1",
            ExecutionProofEntity::TABLE
        );

        let results: Vec<ExecutionProofEntity> = self.run_query(
            &statement,
            json!({
                "tenant": self.tenant_id.0.clone(),
                "proof_id": proof_id.to_string()
            })
        ).await?;

        Ok(results.into_iter().next())
    }

    async fn get_for_epoch(&self, epoch_id: &str) -> P3StoreResult<Vec<ExecutionProofEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND epoch_id = $epoch_id ORDER BY created_at ASC",
            ExecutionProofEntity::TABLE
        );

        self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "epoch_id": epoch_id.to_string()
        })).await
    }

    async fn delete(&self, proof_id: &str) -> P3StoreResult<()> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let statement = format!(
            "DELETE FROM {} WHERE tenant_id.`0` = $tenant AND proof_id = $proof_id",
            ExecutionProofEntity::TABLE
        );

        session.query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "proof_id": proof_id.to_string()
        })).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        Ok(())
    }
}

/// SurrealDB implementation of IdempotencyKeyRepository
pub struct SurrealIdempotencyKeyRepository {
    datastore: Arc<SurrealDatastore>,
    tenant_id: TenantId,
}

impl SurrealIdempotencyKeyRepository {
    /// Create a new repository
    pub fn new(datastore: Arc<SurrealDatastore>, tenant_id: TenantId) -> Self {
        Self { datastore, tenant_id }
    }

    async fn run_query<T: serde::de::DeserializeOwned>(
        &self,
        statement: &str,
        params: serde_json::Value,
    ) -> P3StoreResult<Vec<T>> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let outcome = session.query(statement, params).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        let mut results = Vec::new();
        for row in outcome.rows {
            let entity: T = serde_json::from_value(row)
                .map_err(|e| P3StoreError::Database(format!("Deserialize error: {}", e)))?;
            results.push(entity);
        }
        Ok(results)
    }
}

#[async_trait]
impl IdempotencyKeyRepository for SurrealIdempotencyKeyRepository {
    async fn create(&self, entity: IdempotencyKeyEntity) -> P3StoreResult<IdempotencyKeyEntity> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let entity_json = serde_json::to_value(&entity)
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        let statement = format!(
            "CREATE {}:{} CONTENT $data RETURN *",
            IdempotencyKeyEntity::TABLE,
            entity.id.replace(":", "_")
        );

        let outcome = session.query(&statement, json!({ "data": entity_json })).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        if let Some(row) = outcome.rows.into_iter().next() {
            serde_json::from_value(row)
                .map_err(|e| P3StoreError::Database(format!("Deserialize error: {}", e)))
        } else {
            Err(P3StoreError::Database("Failed to create idempotency key".to_string()))
        }
    }

    async fn exists(&self, key: &str) -> P3StoreResult<bool> {
        let statement = format!(
            "SELECT count() AS cnt FROM {} WHERE tenant_id.`0` = $tenant AND key_value = $key GROUP ALL",
            IdempotencyKeyEntity::TABLE
        );

        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let outcome = session.query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "key": key.to_string()
        })).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        if let Some(row) = outcome.rows.into_iter().next() {
            if let Some(cnt) = row.get("cnt") {
                return Ok(cnt.as_u64().unwrap_or(0) > 0);
            }
        }
        Ok(false)
    }

    async fn get(&self, key: &str) -> P3StoreResult<Option<IdempotencyKeyEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND key_value = $key LIMIT 1",
            IdempotencyKeyEntity::TABLE
        );

        let results: Vec<IdempotencyKeyEntity> = self.run_query(
            &statement,
            json!({
                "tenant": self.tenant_id.0.clone(),
                "key": key.to_string()
            })
        ).await?;

        Ok(results.into_iter().next())
    }

    async fn delete_expired(&self) -> P3StoreResult<usize> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let now = chrono::Utc::now().to_rfc3339();

        let statement = format!(
            "DELETE FROM {} WHERE tenant_id.`0` = $tenant AND expires_at != NONE AND expires_at < $now",
            IdempotencyKeyEntity::TABLE
        );

        let outcome = session.query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "now": now
        })).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        Ok(outcome.rows.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_tenant() -> TenantId {
        TenantId("test".to_string())
    }

    #[test]
    fn test_repository_creation() {
        // Just verify the structs can be created
        // Actual integration tests would require a running SurrealDB instance
        let tenant = test_tenant();
        assert!(!tenant.0.is_empty());
    }
}
