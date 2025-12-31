//! Receipt repository implementation

use soulbase_storage::model::Entity;
use soulbase_storage::spi::Datastore;
use soulbase_storage::surreal::SurrealDatastore;
use soulbase_types::prelude::TenantId;
use std::sync::Arc;

use crate::entities::{FeeReceiptEntity, ReceiptEntity, TipWitnessEntity};
use crate::error::{L0DbError, L0DbResult};

/// L0 Receipt Repository
pub struct L0ReceiptRepo {
    datastore: Arc<SurrealDatastore>,
}

impl L0ReceiptRepo {
    pub fn new(datastore: Arc<SurrealDatastore>) -> Self {
        Self { datastore }
    }

    /// Create a new receipt
    pub async fn create(&self, entity: &ReceiptEntity) -> L0DbResult<ReceiptEntity> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        // Create the entity first
        let create_query = format!("CREATE {} CONTENT $data", ReceiptEntity::TABLE);
        let entity_clone = entity.clone();

        client
            .query(&create_query)
            .bind(("data", entity_clone))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        // Fetch with type::string(id) to convert Thing to String
        let select_query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND receipt_id = $receipt_id LIMIT 1",
            ReceiptEntity::TABLE
        );

        let receipt_id_str = entity.receipt_id.clone();
        let tenant_str = entity.tenant_id.0.clone();
        let mut response = client
            .query(&select_query)
            .bind(("tenant", tenant_str))
            .bind(("receipt_id", receipt_id_str))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        let result: Option<ReceiptEntity> = response
            .take(0)
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        result.ok_or_else(|| L0DbError::QueryError("Failed to create receipt".to_string()))
    }

    /// Get receipt by ID
    pub async fn get_by_id(
        &self,
        tenant: &TenantId,
        receipt_id: &str,
    ) -> L0DbResult<Option<ReceiptEntity>> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND receipt_id = $receipt_id LIMIT 1",
            ReceiptEntity::TABLE
        );

        let tenant_str = tenant.0.clone();
        let receipt_id_str = receipt_id.to_string();

        let mut response = client
            .query(&query)
            .bind(("tenant", tenant_str))
            .bind(("receipt_id", receipt_id_str))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        let result: Option<ReceiptEntity> = response
            .take(0)
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        Ok(result)
    }

    /// Get receipts by batch sequence
    pub async fn get_by_batch(
        &self,
        tenant: &TenantId,
        batch_seq: u64,
    ) -> L0DbResult<Vec<ReceiptEntity>> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND batch_sequence_no = $batch_seq",
            ReceiptEntity::TABLE
        );

        let tenant_str = tenant.0.clone();

        let mut response = client
            .query(&query)
            .bind(("tenant", tenant_str))
            .bind(("batch_seq", batch_seq))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        let results: Vec<ReceiptEntity> = response
            .take(0)
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        Ok(results)
    }

    /// Verify receipt exists and is valid
    pub async fn verify(&self, tenant: &TenantId, receipt_id: &str) -> L0DbResult<bool> {
        let receipt = self.get_by_id(tenant, receipt_id).await?;
        Ok(receipt.map(|r| r.is_valid()).unwrap_or(false))
    }

    /// Mark receipt as rejected
    pub async fn reject(
        &self,
        tenant: &TenantId,
        receipt_id: &str,
        reason_code: &str,
    ) -> L0DbResult<()> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        let query = format!(
            "UPDATE {} SET rejected = true, reject_reason_code = $reason WHERE tenant_id = $tenant AND receipt_id = $receipt_id",
            ReceiptEntity::TABLE
        );

        let tenant_str = tenant.0.clone();
        let receipt_id_str = receipt_id.to_string();
        let reason_str = reason_code.to_string();

        client
            .query(&query)
            .bind(("tenant", tenant_str))
            .bind(("receipt_id", receipt_id_str))
            .bind(("reason", reason_str))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        Ok(())
    }

    // ==================== TipWitness Operations ====================

    /// Create TipWitness (mandatory, free)
    pub async fn create_tip_witness(
        &self,
        entity: &TipWitnessEntity,
    ) -> L0DbResult<TipWitnessEntity> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        // Create the entity first
        let create_query = format!("CREATE {} CONTENT $data", TipWitnessEntity::TABLE);
        let entity_clone = entity.clone();

        client
            .query(&create_query)
            .bind(("data", entity_clone))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        // Fetch with type::string(id) to convert Thing to String
        let select_query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND tip_witness_id = $tip_witness_id LIMIT 1",
            TipWitnessEntity::TABLE
        );

        let tip_witness_id_str = entity.tip_witness_id.clone();
        let tenant_str = entity.tenant_id.0.clone();
        let mut response = client
            .query(&select_query)
            .bind(("tenant", tenant_str))
            .bind(("tip_witness_id", tip_witness_id_str))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        let result: Option<TipWitnessEntity> = response
            .take(0)
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        result.ok_or_else(|| L0DbError::QueryError("Failed to create tip witness".to_string()))
    }

    /// Get latest TipWitness for actor
    pub async fn get_latest_tip_witness(
        &self,
        tenant: &TenantId,
        actor_id: &str,
    ) -> L0DbResult<Option<TipWitnessEntity>> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND actor_id = $actor ORDER BY witnessed_at DESC LIMIT 1",
            TipWitnessEntity::TABLE
        );

        let tenant_str = tenant.0.clone();
        let actor_str = actor_id.to_string();

        let mut response = client
            .query(&query)
            .bind(("tenant", tenant_str))
            .bind(("actor", actor_str))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        let result: Option<TipWitnessEntity> = response
            .take(0)
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        Ok(result)
    }

    /// Get TipWitness history for actor
    pub async fn get_tip_witness_history(
        &self,
        tenant: &TenantId,
        actor_id: &str,
        limit: u32,
    ) -> L0DbResult<Vec<TipWitnessEntity>> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND actor_id = $actor ORDER BY witnessed_at DESC LIMIT $limit",
            TipWitnessEntity::TABLE
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

        let results: Vec<TipWitnessEntity> = response
            .take(0)
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        Ok(results)
    }

    // ==================== FeeReceipt Operations ====================

    /// Create fee receipt
    pub async fn create_fee_receipt(
        &self,
        entity: &FeeReceiptEntity,
    ) -> L0DbResult<FeeReceiptEntity> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        // Create the entity first
        let create_query = format!("CREATE {} CONTENT $data", FeeReceiptEntity::TABLE);
        let entity_clone = entity.clone();

        client
            .query(&create_query)
            .bind(("data", entity_clone))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        // Fetch with type::string(id) to convert Thing to String
        let select_query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND fee_receipt_id = $fee_receipt_id LIMIT 1",
            FeeReceiptEntity::TABLE
        );

        let fee_receipt_id_str = entity.fee_receipt_id.clone();
        let tenant_str = entity.tenant_id.0.clone();
        let mut response = client
            .query(&select_query)
            .bind(("tenant", tenant_str))
            .bind(("fee_receipt_id", fee_receipt_id_str))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        let result: Option<FeeReceiptEntity> = response
            .take(0)
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        result.ok_or_else(|| L0DbError::QueryError("Failed to create fee receipt".to_string()))
    }

    /// Get fee receipt by ID
    pub async fn get_fee_receipt(
        &self,
        tenant: &TenantId,
        fee_receipt_id: &str,
    ) -> L0DbResult<Option<FeeReceiptEntity>> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND fee_receipt_id = $fee_id LIMIT 1",
            FeeReceiptEntity::TABLE
        );

        let tenant_str = tenant.0.clone();
        let fee_id_str = fee_receipt_id.to_string();

        let mut response = client
            .query(&query)
            .bind(("tenant", tenant_str))
            .bind(("fee_id", fee_id_str))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        let result: Option<FeeReceiptEntity> = response
            .take(0)
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        Ok(result)
    }

    /// Mark fee receipt as settled
    pub async fn settle_fee_receipt(
        &self,
        tenant: &TenantId,
        fee_receipt_id: &str,
    ) -> L0DbResult<()> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        let query = format!(
            "UPDATE {} SET status = 'settled', settled_at = time::now() WHERE tenant_id = $tenant AND fee_receipt_id = $fee_id",
            FeeReceiptEntity::TABLE
        );

        let tenant_str = tenant.0.clone();
        let fee_id_str = fee_receipt_id.to_string();

        client
            .query(&query)
            .bind(("tenant", tenant_str))
            .bind(("fee_id", fee_id_str))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        Ok(())
    }

    /// Get pending fee receipts for a payer
    pub async fn get_pending_fees(
        &self,
        tenant: &TenantId,
        payer_actor_id: &str,
    ) -> L0DbResult<Vec<FeeReceiptEntity>> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND payer_actor_id = $payer AND status = 'pending' ORDER BY created_at ASC",
            FeeReceiptEntity::TABLE
        );

        let tenant_str = tenant.0.clone();
        let payer_str = payer_actor_id.to_string();

        let mut response = client
            .query(&query)
            .bind(("tenant", tenant_str))
            .bind(("payer", payer_str))
            .await
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        let results: Vec<FeeReceiptEntity> = response
            .take(0)
            .map_err(|e| L0DbError::QueryError(e.to_string()))?;

        Ok(results)
    }
}
