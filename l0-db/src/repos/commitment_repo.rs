//! Commitment repository implementation

use chrono::{DateTime, Utc};
use soulbase_storage::model::Entity;
use soulbase_storage::spi::Datastore;
use soulbase_storage::surreal::SurrealDatastore;
use soulbase_types::prelude::TenantId;
use std::sync::Arc;

use crate::entities::{BatchSnapshotEntity, CommitmentEntity, EpochSnapshotEntity};
use crate::error::{L0DbError, L0DbResult};

/// L0 Commitment Repository
pub struct L0CommitmentRepo {
    datastore: Arc<SurrealDatastore>,
}

impl L0CommitmentRepo {
    pub fn new(datastore: Arc<SurrealDatastore>) -> Self {
        Self { datastore }
    }

    /// Create a new commitment
    pub async fn create(&self, entity: &CommitmentEntity) -> L0DbResult<CommitmentEntity> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        let query = format!("CREATE {} CONTENT $data RETURN AFTER", CommitmentEntity::TABLE);
        let entity_clone = entity.clone();

        let mut response = client
            .query(&query)
            .bind(("data", entity_clone))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        let result: Option<CommitmentEntity> = response
            .take(0)
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        result.ok_or_else(|| L0DbError::QueryError("Failed to create commitment".to_string()))
    }

    /// Get commitment by ID
    pub async fn get_by_id(
        &self,
        tenant: &TenantId,
        commitment_id: &str,
    ) -> L0DbResult<Option<CommitmentEntity>> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        let query = format!(
            "SELECT * FROM {} WHERE tenant_id.inner = $tenant AND commitment_id = $commitment_id LIMIT 1",
            CommitmentEntity::TABLE
        );

        let tenant_str = tenant.0.clone();
        let commitment_id_str = commitment_id.to_string();

        let mut response = client
            .query(&query)
            .bind(("tenant", tenant_str))
            .bind(("commitment_id", commitment_id_str))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        let result: Option<CommitmentEntity> = response
            .take(0)
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        Ok(result)
    }

    /// Get commitment chain for an actor
    pub async fn get_chain(
        &self,
        tenant: &TenantId,
        actor_id: &str,
        limit: u32,
    ) -> L0DbResult<Vec<CommitmentEntity>> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        let query = format!(
            "SELECT * FROM {} WHERE tenant_id.inner = $tenant AND actor_id = $actor ORDER BY sequence_no DESC LIMIT $limit",
            CommitmentEntity::TABLE
        );

        let tenant_str = tenant.0.clone();
        let actor_str = actor_id.to_string();

        let mut response = client
            .query(&query)
            .bind(("tenant", tenant_str))
            .bind(("actor", actor_str))
            .bind(("limit", limit))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        let results: Vec<CommitmentEntity> = response
            .take(0)
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        Ok(results)
    }

    /// Get latest commitment for an actor
    pub async fn get_latest(
        &self,
        tenant: &TenantId,
        actor_id: &str,
    ) -> L0DbResult<Option<CommitmentEntity>> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        let query = format!(
            "SELECT * FROM {} WHERE tenant_id.inner = $tenant AND actor_id = $actor ORDER BY sequence_no DESC LIMIT 1",
            CommitmentEntity::TABLE
        );

        let tenant_str = tenant.0.clone();
        let actor_str = actor_id.to_string();

        let mut response = client
            .query(&query)
            .bind(("tenant", tenant_str))
            .bind(("actor", actor_str))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        let result: Option<CommitmentEntity> = response
            .take(0)
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        Ok(result)
    }

    /// Get commitments pending inclusion in batch
    pub async fn get_pending_batch(
        &self,
        tenant: &TenantId,
        limit: u32,
    ) -> L0DbResult<Vec<CommitmentEntity>> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        let query = format!(
            "SELECT * FROM {} WHERE tenant_id.inner = $tenant AND batch_sequence_no IS NONE ORDER BY created_at ASC LIMIT $limit",
            CommitmentEntity::TABLE
        );

        let tenant_str = tenant.0.clone();

        let mut response = client
            .query(&query)
            .bind(("tenant", tenant_str))
            .bind(("limit", limit))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        let results: Vec<CommitmentEntity> = response
            .take(0)
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        Ok(results)
    }

    /// Mark commitments as included in batch
    pub async fn mark_batched(
        &self,
        tenant: &TenantId,
        commitment_ids: &[String],
        batch_sequence_no: u64,
    ) -> L0DbResult<()> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        for id in commitment_ids {
            let query = format!(
                "UPDATE {} SET batch_sequence_no = $batch_seq WHERE tenant_id.inner = $tenant AND commitment_id = $id",
                CommitmentEntity::TABLE
            );

            let tenant_str = tenant.0.clone();
            let id_str = id.clone();

            client
                .query(&query)
                .bind(("tenant", tenant_str))
                .bind(("id", id_str))
                .bind(("batch_seq", batch_sequence_no))
                .await
                .map_err(|e| L0DbError::QueryError(e.to_string()))?;
        }
        Ok(())
    }

    /// Create batch snapshot
    pub async fn create_batch_snapshot(
        &self,
        entity: &BatchSnapshotEntity,
    ) -> L0DbResult<BatchSnapshotEntity> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        let query = format!("CREATE {} CONTENT $data RETURN AFTER", BatchSnapshotEntity::TABLE);
        let entity_clone = entity.clone();

        let mut response = client
            .query(&query)
            .bind(("data", entity_clone))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        let result: Option<BatchSnapshotEntity> = response
            .take(0)
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        result.ok_or_else(|| L0DbError::QueryError("Failed to create batch snapshot".to_string()))
    }

    /// Get batch snapshot by sequence number
    pub async fn get_batch_snapshot(
        &self,
        tenant: &TenantId,
        sequence_no: u64,
    ) -> L0DbResult<Option<BatchSnapshotEntity>> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        let query = format!(
            "SELECT * FROM {} WHERE tenant_id.inner = $tenant AND batch_sequence_no = $seq LIMIT 1",
            BatchSnapshotEntity::TABLE
        );

        let tenant_str = tenant.0.clone();

        let mut response = client
            .query(&query)
            .bind(("tenant", tenant_str))
            .bind(("seq", sequence_no))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        let result: Option<BatchSnapshotEntity> = response
            .take(0)
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        Ok(result)
    }

    /// Get latest batch snapshot
    pub async fn get_latest_batch(
        &self,
        tenant: &TenantId,
    ) -> L0DbResult<Option<BatchSnapshotEntity>> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        let query = format!(
            "SELECT * FROM {} WHERE tenant_id.inner = $tenant ORDER BY batch_sequence_no DESC LIMIT 1",
            BatchSnapshotEntity::TABLE
        );

        let tenant_str = tenant.0.clone();

        let mut response = client
            .query(&query)
            .bind(("tenant", tenant_str))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        let result: Option<BatchSnapshotEntity> = response
            .take(0)
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        Ok(result)
    }

    /// Get commitments by batch sequence number
    pub async fn get_commitments_by_batch(
        &self,
        tenant: &TenantId,
        batch_sequence_no: u64,
    ) -> L0DbResult<Vec<CommitmentEntity>> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        let query = format!(
            "SELECT * FROM {} WHERE tenant_id.inner = $tenant AND batch_sequence_no = $batch_seq ORDER BY sequence_no ASC",
            CommitmentEntity::TABLE
        );

        let tenant_str = tenant.0.clone();

        let mut response = client
            .query(&query)
            .bind(("tenant", tenant_str))
            .bind(("batch_seq", batch_sequence_no))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        let results: Vec<CommitmentEntity> = response
            .take(0)
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        Ok(results)
    }

    /// Get commitment chain for an actor with optional scope filter
    pub async fn get_chain_with_scope(
        &self,
        tenant: &TenantId,
        actor_id: &str,
        scope_type: Option<&str>,
        limit: u32,
    ) -> L0DbResult<Vec<CommitmentEntity>> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        let query = match scope_type {
            Some(_) => format!(
                "SELECT * FROM {} WHERE tenant_id.inner = $tenant AND actor_id = $actor AND scope_type = $scope ORDER BY sequence_no DESC LIMIT $limit",
                CommitmentEntity::TABLE
            ),
            None => format!(
                "SELECT * FROM {} WHERE tenant_id.inner = $tenant AND actor_id = $actor ORDER BY sequence_no DESC LIMIT $limit",
                CommitmentEntity::TABLE
            ),
        };

        let tenant_str = tenant.0.clone();
        let actor_str = actor_id.to_string();

        let mut response = if let Some(scope) = scope_type {
            client
                .query(&query)
                .bind(("tenant", tenant_str))
                .bind(("actor", actor_str))
                .bind(("scope", scope.to_string()))
                .bind(("limit", limit))
                .await
                .map_err(|e| L0DbError::QueryError(e.to_string()))?
        } else {
            client
                .query(&query)
                .bind(("tenant", tenant_str))
                .bind(("actor", actor_str))
                .bind(("limit", limit))
                .await
                .map_err(|e| L0DbError::QueryError(e.to_string()))?
        };

        let results: Vec<CommitmentEntity> = response
            .take(0)
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        Ok(results)
    }

    /// Get commitments within a time window
    pub async fn get_in_time_window(
        &self,
        tenant: &TenantId,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        scope_type: Option<&str>,
    ) -> L0DbResult<Vec<CommitmentEntity>> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        let query = match scope_type {
            Some(_) => format!(
                "SELECT * FROM {} WHERE tenant_id.inner = $tenant AND created_at >= $start AND created_at <= $end AND scope_type = $scope ORDER BY created_at ASC",
                CommitmentEntity::TABLE
            ),
            None => format!(
                "SELECT * FROM {} WHERE tenant_id.inner = $tenant AND created_at >= $start AND created_at <= $end ORDER BY created_at ASC",
                CommitmentEntity::TABLE
            ),
        };

        let tenant_str = tenant.0.clone();

        let mut response = if let Some(scope) = scope_type {
            client
                .query(&query)
                .bind(("tenant", tenant_str))
                .bind(("start", start))
                .bind(("end", end))
                .bind(("scope", scope.to_string()))
                .await
                .map_err(|e| L0DbError::QueryError(e.to_string()))?
        } else {
            client
                .query(&query)
                .bind(("tenant", tenant_str))
                .bind(("start", start))
                .bind(("end", end))
                .await
                .map_err(|e| L0DbError::QueryError(e.to_string()))?
        };

        let results: Vec<CommitmentEntity> = response
            .take(0)
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        Ok(results)
    }

    /// Create epoch snapshot
    pub async fn create_epoch_snapshot(
        &self,
        entity: &EpochSnapshotEntity,
    ) -> L0DbResult<EpochSnapshotEntity> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        let query = format!("CREATE {} CONTENT $data RETURN AFTER", EpochSnapshotEntity::TABLE);
        let entity_clone = entity.clone();

        let mut response = client
            .query(&query)
            .bind(("data", entity_clone))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        let result: Option<EpochSnapshotEntity> = response
            .take(0)
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        result.ok_or_else(|| L0DbError::QueryError("Failed to create epoch snapshot".to_string()))
    }

    /// Get epoch snapshot by sequence number
    pub async fn get_epoch_snapshot(
        &self,
        tenant: &TenantId,
        sequence_no: u64,
    ) -> L0DbResult<Option<EpochSnapshotEntity>> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        let query = format!(
            "SELECT * FROM {} WHERE tenant_id.inner = $tenant AND epoch_sequence_no = $seq LIMIT 1",
            EpochSnapshotEntity::TABLE
        );

        let tenant_str = tenant.0.clone();

        let mut response = client
            .query(&query)
            .bind(("tenant", tenant_str))
            .bind(("seq", sequence_no))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        let result: Option<EpochSnapshotEntity> = response
            .take(0)
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        Ok(result)
    }
}
