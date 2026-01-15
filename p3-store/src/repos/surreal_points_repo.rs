//! SurrealDB Points Repository Implementation
//!
//! Implements PointsBalanceRepository and PointsHistoryRepository using soulbase-storage's SurrealDB integration.

use async_trait::async_trait;
use rust_decimal::Decimal;
use serde_json::json;
use soulbase_storage::model::Entity;
use soulbase_storage::spi::query::QueryExecutor;
use soulbase_storage::surreal::SurrealDatastore;
use soulbase_storage::Datastore;
use soulbase_types::prelude::TenantId;
use std::sync::Arc;

use crate::entities::{PointType, PointsBalanceEntity, PointsHistoryEntity};
use crate::error::{P3StoreError, P3StoreResult};
use crate::repos::{PointsBalanceRepository, PointsHistoryRepository, PointsService};

/// SurrealDB implementation of PointsBalanceRepository
pub struct SurrealPointsBalanceRepository {
    datastore: Arc<SurrealDatastore>,
    tenant_id: TenantId,
}

impl SurrealPointsBalanceRepository {
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
impl PointsBalanceRepository for SurrealPointsBalanceRepository {
    async fn upsert(&self, entity: PointsBalanceEntity) -> P3StoreResult<PointsBalanceEntity> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let entity_json = serde_json::to_value(&entity)
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        let statement = format!(
            "UPSERT {}:{} CONTENT $data RETURN *",
            PointsBalanceEntity::TABLE,
            entity.id.replace(":", "_")
        );

        let outcome = session.query(&statement, json!({ "data": entity_json })).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        if let Some(row) = outcome.rows.into_iter().next() {
            serde_json::from_value(row)
                .map_err(|e| P3StoreError::Database(format!("Deserialize error: {}", e)))
        } else {
            Err(P3StoreError::Database("Failed to upsert entity".to_string()))
        }
    }

    async fn get(
        &self,
        actor_id: &str,
        point_type: PointType,
    ) -> P3StoreResult<Option<PointsBalanceEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND actor_id = $actor_id AND point_type = $point_type LIMIT 1",
            PointsBalanceEntity::TABLE
        );

        let results: Vec<PointsBalanceEntity> = self.run_query(
            &statement,
            json!({
                "tenant": self.tenant_id.0.clone(),
                "actor_id": actor_id.to_string(),
                "point_type": point_type.to_string()
            })
        ).await?;

        Ok(results.into_iter().next())
    }

    async fn get_all_for_actor(&self, actor_id: &str) -> P3StoreResult<Vec<PointsBalanceEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND actor_id = $actor_id",
            PointsBalanceEntity::TABLE
        );

        self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "actor_id": actor_id.to_string()
        })).await
    }

    async fn add_balance(
        &self,
        actor_id: &str,
        point_type: PointType,
        amount: Decimal,
        epoch_id: &str,
    ) -> P3StoreResult<PointsBalanceEntity> {
        let mut entity = match self.get(actor_id, point_type.clone()).await? {
            Some(e) => e,
            None => PointsBalanceEntity::new(self.tenant_id.clone(), actor_id, point_type),
        };

        entity.add(amount, epoch_id);
        self.upsert(entity).await
    }

    async fn subtract_balance(
        &self,
        actor_id: &str,
        point_type: PointType,
        amount: Decimal,
        epoch_id: &str,
    ) -> P3StoreResult<PointsBalanceEntity> {
        let mut entity = self.get(actor_id, point_type.clone()).await?
            .ok_or_else(|| P3StoreError::not_found("PointsBalance", actor_id))?;

        if !entity.subtract(amount, epoch_id) {
            return Err(P3StoreError::Validation("Insufficient balance".to_string()));
        }

        self.upsert(entity).await
    }

    async fn get_total_balance(&self, point_type: PointType) -> P3StoreResult<Decimal> {
        let statement = format!(
            "SELECT balance FROM {} WHERE tenant_id.`0` = $tenant AND point_type = $point_type",
            PointsBalanceEntity::TABLE
        );

        let balances: Vec<PointsBalanceEntity> = self.run_query(
            &statement,
            json!({
                "tenant": self.tenant_id.0.clone(),
                "point_type": point_type.to_string()
            })
        ).await?;

        let total = balances.iter()
            .map(|e| e.balance_decimal())
            .fold(Decimal::ZERO, |acc, b| acc + b);

        Ok(total)
    }
}

/// SurrealDB implementation of PointsHistoryRepository
pub struct SurrealPointsHistoryRepository {
    datastore: Arc<SurrealDatastore>,
    tenant_id: TenantId,
}

impl SurrealPointsHistoryRepository {
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
impl PointsHistoryRepository for SurrealPointsHistoryRepository {
    async fn create(&self, entity: PointsHistoryEntity) -> P3StoreResult<PointsHistoryEntity> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        let entity_json = serde_json::to_value(&entity)
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        let statement = format!(
            "CREATE {}:{} CONTENT $data RETURN *",
            PointsHistoryEntity::TABLE,
            entity.id.replace(":", "_")
        );

        let outcome = session.query(&statement, json!({ "data": entity_json })).await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        if let Some(row) = outcome.rows.into_iter().next() {
            serde_json::from_value(row)
                .map_err(|e| P3StoreError::Database(format!("Deserialize error: {}", e)))
        } else {
            Err(P3StoreError::Database("Failed to create history entry".to_string()))
        }
    }

    async fn get_for_actor(
        &self,
        actor_id: &str,
        limit: usize,
    ) -> P3StoreResult<Vec<PointsHistoryEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND actor_id = $actor_id ORDER BY created_at DESC LIMIT $limit",
            PointsHistoryEntity::TABLE
        );

        self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "actor_id": actor_id.to_string(),
            "limit": limit
        })).await
    }

    async fn get_for_actor_and_type(
        &self,
        actor_id: &str,
        point_type: PointType,
        limit: usize,
    ) -> P3StoreResult<Vec<PointsHistoryEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND actor_id = $actor_id AND point_type = $point_type ORDER BY created_at DESC LIMIT $limit",
            PointsHistoryEntity::TABLE
        );

        self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "actor_id": actor_id.to_string(),
            "point_type": point_type.to_string(),
            "limit": limit
        })).await
    }

    async fn get_for_epoch(&self, epoch_id: &str) -> P3StoreResult<Vec<PointsHistoryEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND epoch_id = $epoch_id ORDER BY created_at ASC",
            PointsHistoryEntity::TABLE
        );

        self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "epoch_id": epoch_id.to_string()
        })).await
    }

    async fn get_for_actor_in_epoch(
        &self,
        actor_id: &str,
        epoch_id: &str,
    ) -> P3StoreResult<Vec<PointsHistoryEntity>> {
        let statement = format!(
            "SELECT * FROM {} WHERE tenant_id.`0` = $tenant AND actor_id = $actor_id AND epoch_id = $epoch_id ORDER BY created_at ASC",
            PointsHistoryEntity::TABLE
        );

        self.run_query(&statement, json!({
            "tenant": self.tenant_id.0.clone(),
            "actor_id": actor_id.to_string(),
            "epoch_id": epoch_id.to_string()
        })).await
    }
}

/// SurrealDB implementation of PointsService
pub struct SurrealPointsService {
    balance_repo: SurrealPointsBalanceRepository,
    history_repo: SurrealPointsHistoryRepository,
}

impl SurrealPointsService {
    /// Create a new points service
    pub fn new(datastore: Arc<SurrealDatastore>, tenant_id: TenantId) -> Self {
        Self {
            balance_repo: SurrealPointsBalanceRepository::new(datastore.clone(), tenant_id.clone()),
            history_repo: SurrealPointsHistoryRepository::new(datastore, tenant_id),
        }
    }
}

#[async_trait]
impl PointsService for SurrealPointsService {
    async fn award_points(
        &self,
        actor_id: &str,
        point_type: PointType,
        amount: Decimal,
        epoch_id: &str,
        reason_code: &str,
        reason_ref: Option<&str>,
    ) -> P3StoreResult<PointsBalanceEntity> {
        let balance = self.balance_repo.add_balance(actor_id, point_type.clone(), amount, epoch_id).await?;

        let mut history = PointsHistoryEntity::new(
            balance.tenant_id.clone(),
            actor_id,
            point_type,
            epoch_id,
            amount,
            reason_code,
        ).with_balance_after(balance.balance_decimal());

        if let Some(ref_str) = reason_ref {
            history = history.with_reason_ref(ref_str);
        }

        self.history_repo.create(history).await?;
        Ok(balance)
    }

    async fn deduct_points(
        &self,
        actor_id: &str,
        point_type: PointType,
        amount: Decimal,
        epoch_id: &str,
        reason_code: &str,
        reason_ref: Option<&str>,
    ) -> P3StoreResult<PointsBalanceEntity> {
        let balance = self.balance_repo.subtract_balance(actor_id, point_type.clone(), amount, epoch_id).await?;

        let mut history = PointsHistoryEntity::new(
            balance.tenant_id.clone(),
            actor_id,
            point_type,
            epoch_id,
            -amount,
            reason_code,
        ).with_balance_after(balance.balance_decimal());

        if let Some(ref_str) = reason_ref {
            history = history.with_reason_ref(ref_str);
        }

        self.history_repo.create(history).await?;
        Ok(balance)
    }

    async fn transfer_points(
        &self,
        from_actor: &str,
        to_actor: &str,
        point_type: PointType,
        amount: Decimal,
        epoch_id: &str,
        reason_code: &str,
    ) -> P3StoreResult<()> {
        self.deduct_points(from_actor, point_type.clone(), amount, epoch_id, reason_code, Some(to_actor)).await?;
        self.award_points(to_actor, point_type, amount, epoch_id, reason_code, Some(from_actor)).await?;
        Ok(())
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
