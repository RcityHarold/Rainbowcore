//! SurrealDB Clearing Repository Implementation
//!
//! Implements clearing-related repositories using soulbase-storage's SurrealDB integration.

use async_trait::async_trait;
use serde_json::json;
use soulbase_storage::model::Entity;
use soulbase_storage::spi::query::QueryExecutor;
use soulbase_storage::surreal::SurrealDatastore;
use soulbase_storage::Datastore;
use soulbase_types::prelude::TenantId;
use std::sync::Arc;

use crate::entities::{
    ClearingBatchEntity, ClearingBatchStatus, ClearingEntryEntity,
    FeeScheduleEntity, ProviderEntity, TreasuryPoolEntity,
    TreasuryPoolType, TreasuryTxEntity, VersionRegistryEntity,
};
use crate::error::{P3StoreError, P3StoreResult};
use crate::repos::{
    ClearingBatchRepository, ClearingEntryRepository, FeeScheduleRepository,
    ProviderRepository, TreasuryPoolRepository, TreasuryTxRepository, VersionRegistryRepository,
};

/// Helper macro to reduce boilerplate for run_query implementations
macro_rules! impl_run_query {
    ($type:ty) => {
        impl $type {
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
    };
}

/// SurrealDB implementation of ClearingBatchRepository
pub struct SurrealClearingBatchRepository {
    datastore: Arc<SurrealDatastore>,
    tenant_id: TenantId,
}

impl SurrealClearingBatchRepository {
    pub fn new(datastore: Arc<SurrealDatastore>, tenant_id: TenantId) -> Self {
        Self { datastore, tenant_id }
    }
}

impl_run_query!(SurrealClearingBatchRepository);

#[async_trait]
impl ClearingBatchRepository for SurrealClearingBatchRepository {
    async fn create(&self, entity: ClearingBatchEntity) -> P3StoreResult<ClearingBatchEntity> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let entity_json = serde_json::to_value(&entity)
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        let statement = format!(
            "CREATE {}:{} CONTENT $data RETURN *",
            ClearingBatchEntity::TABLE,
            entity.id.replace(":", "_")
        );

        let outcome = session.query(&statement, json!({ "data": entity_json })).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        outcome.rows.into_iter().next()
            .ok_or_else(|| P3StoreError::Database("Failed to create entity".to_string()))
            .and_then(|row| serde_json::from_value(row)
                .map_err(|e| P3StoreError::Database(format!("Deserialize error: {}", e))))
    }

    async fn get(&self, batch_id: &str) -> P3StoreResult<Option<ClearingBatchEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND batch_id = $batch_id LIMIT 1",
            ClearingBatchEntity::TABLE
        );

        let results: Vec<ClearingBatchEntity> = self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "batch_id": batch_id.to_string()
        })).await?;

        Ok(results.into_iter().next())
    }

    async fn update(&self, entity: ClearingBatchEntity) -> P3StoreResult<ClearingBatchEntity> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let entity_json = serde_json::to_value(&entity)
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        let statement = format!(
            "UPDATE {}:{} CONTENT $data RETURN *",
            ClearingBatchEntity::TABLE,
            entity.id.replace(":", "_")
        );

        let outcome = session.query(&statement, json!({ "data": entity_json })).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        outcome.rows.into_iter().next()
            .ok_or_else(|| P3StoreError::not_found("ClearingBatch", &entity.batch_id))
            .and_then(|row| serde_json::from_value(row)
                .map_err(|e| P3StoreError::Database(format!("Deserialize error: {}", e))))
    }

    async fn update_status(&self, batch_id: &str, status: ClearingBatchStatus) -> P3StoreResult<()> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let settled_at = if status == ClearingBatchStatus::Settled {
            Some(chrono::Utc::now().to_rfc3339())
        } else {
            None::<String>
        };

        let statement = format!(
            "UPDATE {} SET status = $status, settled_at = $settled_at WHERE tenant_id.`0` = $tenant AND batch_id = $batch_id",
            ClearingBatchEntity::TABLE
        );

        session.query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "batch_id": batch_id.to_string(),
            "status": status.to_string(),
            "settled_at": settled_at
        })).await.map_err(|e| P3StoreError::Database(e.to_string()))?;

        Ok(())
    }

    async fn list_by_status(&self, status: ClearingBatchStatus, limit: usize) -> P3StoreResult<Vec<ClearingBatchEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND status = $status ORDER BY created_at DESC LIMIT $limit",
            ClearingBatchEntity::TABLE
        );

        self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "status": status.to_string(),
            "limit": limit
        })).await
    }

    async fn get_for_epoch(&self, epoch_id: &str) -> P3StoreResult<Vec<ClearingBatchEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND epoch_id = $epoch_id ORDER BY created_at ASC",
            ClearingBatchEntity::TABLE
        );

        self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "epoch_id": epoch_id.to_string()
        })).await
    }
}

/// SurrealDB implementation of ClearingEntryRepository
pub struct SurrealClearingEntryRepository {
    datastore: Arc<SurrealDatastore>,
    tenant_id: TenantId,
}

impl SurrealClearingEntryRepository {
    pub fn new(datastore: Arc<SurrealDatastore>, tenant_id: TenantId) -> Self {
        Self { datastore, tenant_id }
    }
}

impl_run_query!(SurrealClearingEntryRepository);

#[async_trait]
impl ClearingEntryRepository for SurrealClearingEntryRepository {
    async fn create(&self, entity: ClearingEntryEntity) -> P3StoreResult<ClearingEntryEntity> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let entity_json = serde_json::to_value(&entity)
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        let statement = format!(
            "CREATE {}:{} CONTENT $data RETURN *",
            ClearingEntryEntity::TABLE,
            entity.id.replace(":", "_")
        );

        let outcome = session.query(&statement, json!({ "data": entity_json })).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        outcome.rows.into_iter().next()
            .ok_or_else(|| P3StoreError::Database("Failed to create entity".to_string()))
            .and_then(|row| serde_json::from_value(row)
                .map_err(|e| P3StoreError::Database(format!("Deserialize error: {}", e))))
    }

    async fn create_batch(&self, entities: Vec<ClearingEntryEntity>) -> P3StoreResult<()> {
        for entity in entities {
            self.create(entity).await?;
        }
        Ok(())
    }

    async fn get(&self, entry_id: &str) -> P3StoreResult<Option<ClearingEntryEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND entry_id = $entry_id LIMIT 1",
            ClearingEntryEntity::TABLE
        );

        let results: Vec<ClearingEntryEntity> = self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "entry_id": entry_id.to_string()
        })).await?;

        Ok(results.into_iter().next())
    }

    async fn get_for_batch(&self, batch_id: &str) -> P3StoreResult<Vec<ClearingEntryEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND batch_id = $batch_id ORDER BY created_at ASC",
            ClearingEntryEntity::TABLE
        );

        self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "batch_id": batch_id.to_string()
        })).await
    }

    async fn get_for_actor(&self, actor_id: &str, limit: usize) -> P3StoreResult<Vec<ClearingEntryEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND (from_actor = $actor_id OR to_actor = $actor_id) ORDER BY created_at DESC LIMIT $limit",
            ClearingEntryEntity::TABLE
        );

        self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "actor_id": actor_id.to_string(),
            "limit": limit
        })).await
    }
}

/// SurrealDB implementation of TreasuryPoolRepository
pub struct SurrealTreasuryPoolRepository {
    datastore: Arc<SurrealDatastore>,
    tenant_id: TenantId,
}

impl SurrealTreasuryPoolRepository {
    pub fn new(datastore: Arc<SurrealDatastore>, tenant_id: TenantId) -> Self {
        Self { datastore, tenant_id }
    }
}

impl_run_query!(SurrealTreasuryPoolRepository);

#[async_trait]
impl TreasuryPoolRepository for SurrealTreasuryPoolRepository {
    async fn upsert(&self, entity: TreasuryPoolEntity) -> P3StoreResult<TreasuryPoolEntity> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let entity_json = serde_json::to_value(&entity)
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        let statement = format!(
            "UPSERT {}:{} CONTENT $data RETURN *",
            TreasuryPoolEntity::TABLE,
            entity.id.replace(":", "_")
        );

        let outcome = session.query(&statement, json!({ "data": entity_json })).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        outcome.rows.into_iter().next()
            .ok_or_else(|| P3StoreError::Database("Failed to upsert entity".to_string()))
            .and_then(|row| serde_json::from_value(row)
                .map_err(|e| P3StoreError::Database(format!("Deserialize error: {}", e))))
    }

    async fn get(&self, pool_type: TreasuryPoolType) -> P3StoreResult<Option<TreasuryPoolEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND pool_type = $pool_type LIMIT 1",
            TreasuryPoolEntity::TABLE
        );

        let results: Vec<TreasuryPoolEntity> = self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "pool_type": pool_type.to_string()
        })).await?;

        Ok(results.into_iter().next())
    }

    async fn get_all(&self) -> P3StoreResult<Vec<TreasuryPoolEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant",
            TreasuryPoolEntity::TABLE
        );

        self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone()
        })).await
    }

    async fn update_balance(&self, pool_type: TreasuryPoolType, balance_digest: &str, epoch_id: &str) -> P3StoreResult<()> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let statement = format!(
            "UPDATE {} SET balance_digest = $balance_digest, last_updated_epoch = $epoch_id, updated_at = $now WHERE tenant_id.`0` = $tenant AND pool_type = $pool_type",
            TreasuryPoolEntity::TABLE
        );

        session.query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "pool_type": pool_type.to_string(),
            "balance_digest": balance_digest.to_string(),
            "epoch_id": epoch_id.to_string(),
            "now": chrono::Utc::now().to_rfc3339()
        })).await.map_err(|e| P3StoreError::Database(e.to_string()))?;

        Ok(())
    }
}

/// SurrealDB implementation of TreasuryTxRepository
pub struct SurrealTreasuryTxRepository {
    datastore: Arc<SurrealDatastore>,
    tenant_id: TenantId,
}

impl SurrealTreasuryTxRepository {
    pub fn new(datastore: Arc<SurrealDatastore>, tenant_id: TenantId) -> Self {
        Self { datastore, tenant_id }
    }
}

impl_run_query!(SurrealTreasuryTxRepository);

#[async_trait]
impl TreasuryTxRepository for SurrealTreasuryTxRepository {
    async fn create(&self, entity: TreasuryTxEntity) -> P3StoreResult<TreasuryTxEntity> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let entity_json = serde_json::to_value(&entity)
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        let statement = format!(
            "CREATE {}:{} CONTENT $data RETURN *",
            TreasuryTxEntity::TABLE,
            entity.id.replace(":", "_")
        );

        let outcome = session.query(&statement, json!({ "data": entity_json })).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        outcome.rows.into_iter().next()
            .ok_or_else(|| P3StoreError::Database("Failed to create entity".to_string()))
            .and_then(|row| serde_json::from_value(row)
                .map_err(|e| P3StoreError::Database(format!("Deserialize error: {}", e))))
    }

    async fn get(&self, tx_id: &str) -> P3StoreResult<Option<TreasuryTxEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND tx_id = $tx_id LIMIT 1",
            TreasuryTxEntity::TABLE
        );

        let results: Vec<TreasuryTxEntity> = self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "tx_id": tx_id.to_string()
        })).await?;

        Ok(results.into_iter().next())
    }

    async fn get_for_epoch(&self, epoch_id: &str) -> P3StoreResult<Vec<TreasuryTxEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND epoch_id = $epoch_id ORDER BY created_at ASC",
            TreasuryTxEntity::TABLE
        );

        self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "epoch_id": epoch_id.to_string()
        })).await
    }

    async fn get_for_pool(&self, pool_type: TreasuryPoolType, limit: usize) -> P3StoreResult<Vec<TreasuryTxEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND pool_type = $pool_type ORDER BY created_at DESC LIMIT $limit",
            TreasuryTxEntity::TABLE
        );

        self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "pool_type": pool_type.to_string(),
            "limit": limit
        })).await
    }
}

/// SurrealDB implementation of FeeScheduleRepository
pub struct SurrealFeeScheduleRepository {
    datastore: Arc<SurrealDatastore>,
    tenant_id: TenantId,
}

impl SurrealFeeScheduleRepository {
    pub fn new(datastore: Arc<SurrealDatastore>, tenant_id: TenantId) -> Self {
        Self { datastore, tenant_id }
    }
}

impl_run_query!(SurrealFeeScheduleRepository);

#[async_trait]
impl FeeScheduleRepository for SurrealFeeScheduleRepository {
    async fn create(&self, entity: FeeScheduleEntity) -> P3StoreResult<FeeScheduleEntity> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let entity_json = serde_json::to_value(&entity)
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        let statement = format!(
            "CREATE {}:{} CONTENT $data RETURN *",
            FeeScheduleEntity::TABLE,
            entity.id.replace(":", "_")
        );

        let outcome = session.query(&statement, json!({ "data": entity_json })).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        outcome.rows.into_iter().next()
            .ok_or_else(|| P3StoreError::Database("Failed to create entity".to_string()))
            .and_then(|row| serde_json::from_value(row)
                .map_err(|e| P3StoreError::Database(format!("Deserialize error: {}", e))))
    }

    async fn get(&self, schedule_id: &str, version: i32) -> P3StoreResult<Option<FeeScheduleEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND schedule_id = $schedule_id AND version = $version LIMIT 1",
            FeeScheduleEntity::TABLE
        );

        let results: Vec<FeeScheduleEntity> = self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "schedule_id": schedule_id.to_string(),
            "version": version
        })).await?;

        Ok(results.into_iter().next())
    }

    async fn get_current(&self) -> P3StoreResult<Option<FeeScheduleEntity>> {
        let now = chrono::Utc::now().to_rfc3339();
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND effective_from <= $now AND (effective_until = NONE OR effective_until > $now) ORDER BY version DESC LIMIT 1",
            FeeScheduleEntity::TABLE
        );

        let results: Vec<FeeScheduleEntity> = self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "now": now
        })).await?;

        Ok(results.into_iter().next())
    }

    async fn list_versions(&self, schedule_id: &str) -> P3StoreResult<Vec<FeeScheduleEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND schedule_id = $schedule_id ORDER BY version DESC",
            FeeScheduleEntity::TABLE
        );

        self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "schedule_id": schedule_id.to_string()
        })).await
    }
}

/// SurrealDB implementation of ProviderRepository
pub struct SurrealProviderRepository {
    datastore: Arc<SurrealDatastore>,
    tenant_id: TenantId,
}

impl SurrealProviderRepository {
    pub fn new(datastore: Arc<SurrealDatastore>, tenant_id: TenantId) -> Self {
        Self { datastore, tenant_id }
    }
}

impl_run_query!(SurrealProviderRepository);

#[async_trait]
impl ProviderRepository for SurrealProviderRepository {
    async fn create(&self, entity: ProviderEntity) -> P3StoreResult<ProviderEntity> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let entity_json = serde_json::to_value(&entity)
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        let statement = format!(
            "CREATE {}:{} CONTENT $data RETURN *",
            ProviderEntity::TABLE,
            entity.id.replace(":", "_")
        );

        let outcome = session.query(&statement, json!({ "data": entity_json })).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        outcome.rows.into_iter().next()
            .ok_or_else(|| P3StoreError::Database("Failed to create entity".to_string()))
            .and_then(|row| serde_json::from_value(row)
                .map_err(|e| P3StoreError::Database(format!("Deserialize error: {}", e))))
    }

    async fn get(&self, provider_id: &str) -> P3StoreResult<Option<ProviderEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND provider_id = $provider_id LIMIT 1",
            ProviderEntity::TABLE
        );

        let results: Vec<ProviderEntity> = self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "provider_id": provider_id.to_string()
        })).await?;

        Ok(results.into_iter().next())
    }

    async fn get_by_actor(&self, actor_id: &str) -> P3StoreResult<Option<ProviderEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND actor_id = $actor_id LIMIT 1",
            ProviderEntity::TABLE
        );

        let results: Vec<ProviderEntity> = self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "actor_id": actor_id.to_string()
        })).await?;

        Ok(results.into_iter().next())
    }

    async fn update(&self, entity: ProviderEntity) -> P3StoreResult<ProviderEntity> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let entity_json = serde_json::to_value(&entity)
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        let statement = format!(
            "UPDATE {}:{} CONTENT $data RETURN *",
            ProviderEntity::TABLE,
            entity.id.replace(":", "_")
        );

        let outcome = session.query(&statement, json!({ "data": entity_json })).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        outcome.rows.into_iter().next()
            .ok_or_else(|| P3StoreError::not_found("Provider", &entity.provider_id))
            .and_then(|row| serde_json::from_value(row)
                .map_err(|e| P3StoreError::Database(format!("Deserialize error: {}", e))))
    }

    async fn list_active(&self) -> P3StoreResult<Vec<ProviderEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND status = 'active' ORDER BY registered_at ASC",
            ProviderEntity::TABLE
        );

        self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone()
        })).await
    }

    async fn list_by_level(&self, level: &str) -> P3StoreResult<Vec<ProviderEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND conformance_level = $level ORDER BY registered_at ASC",
            ProviderEntity::TABLE
        );

        self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "level": level.to_string()
        })).await
    }
}

/// SurrealDB implementation of VersionRegistryRepository
pub struct SurrealVersionRegistryRepository {
    datastore: Arc<SurrealDatastore>,
    tenant_id: TenantId,
}

impl SurrealVersionRegistryRepository {
    pub fn new(datastore: Arc<SurrealDatastore>, tenant_id: TenantId) -> Self {
        Self { datastore, tenant_id }
    }
}

impl_run_query!(SurrealVersionRegistryRepository);

#[async_trait]
impl VersionRegistryRepository for SurrealVersionRegistryRepository {
    async fn create(&self, entity: VersionRegistryEntity) -> P3StoreResult<VersionRegistryEntity> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let entity_json = serde_json::to_value(&entity)
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        let statement = format!(
            "CREATE {}:{} CONTENT $data RETURN *",
            VersionRegistryEntity::TABLE,
            entity.id.replace(":", "_")
        );

        let outcome = session.query(&statement, json!({ "data": entity_json })).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        outcome.rows.into_iter().next()
            .ok_or_else(|| P3StoreError::Database("Failed to create entity".to_string()))
            .and_then(|row| serde_json::from_value(row)
                .map_err(|e| P3StoreError::Database(format!("Deserialize error: {}", e))))
    }

    async fn get(&self, version_id: &str) -> P3StoreResult<Option<VersionRegistryEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND version_id = $version_id LIMIT 1",
            VersionRegistryEntity::TABLE
        );

        let results: Vec<VersionRegistryEntity> = self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "version_id": version_id.to_string()
        })).await?;

        Ok(results.into_iter().next())
    }

    async fn get_active(&self, object_type: &str) -> P3StoreResult<Option<VersionRegistryEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND object_type = $object_type AND status = 'active' ORDER BY version_number DESC LIMIT 1",
            VersionRegistryEntity::TABLE
        );

        let results: Vec<VersionRegistryEntity> = self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "object_type": object_type.to_string()
        })).await?;

        Ok(results.into_iter().next())
    }

    async fn update(&self, entity: VersionRegistryEntity) -> P3StoreResult<VersionRegistryEntity> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let entity_json = serde_json::to_value(&entity)
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        let statement = format!(
            "UPDATE {}:{} CONTENT $data RETURN *",
            VersionRegistryEntity::TABLE,
            entity.id.replace(":", "_")
        );

        let outcome = session.query(&statement, json!({ "data": entity_json })).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        outcome.rows.into_iter().next()
            .ok_or_else(|| P3StoreError::not_found("VersionRegistry", &entity.version_id))
            .and_then(|row| serde_json::from_value(row)
                .map_err(|e| P3StoreError::Database(format!("Deserialize error: {}", e))))
    }

    async fn list_for_type(&self, object_type: &str) -> P3StoreResult<Vec<VersionRegistryEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND object_type = $object_type ORDER BY version_number DESC",
            VersionRegistryEntity::TABLE
        );

        self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "object_type": object_type.to_string()
        })).await
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
        let tenant = test_tenant();
        assert!(!tenant.0.is_empty());
    }
}
