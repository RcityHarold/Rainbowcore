//! Clearing Repository

use async_trait::async_trait;
use crate::entities::{
    ClearingBatchEntity, ClearingBatchStatus, ClearingEntryEntity,
    TreasuryPoolEntity, TreasuryPoolType, TreasuryTxEntity,
    FeeScheduleEntity, ProviderEntity, VersionRegistryEntity,
};
use crate::error::{P3StoreError, P3StoreResult};

/// Clearing batch repository trait
#[async_trait]
pub trait ClearingBatchRepository: Send + Sync {
    /// Create a clearing batch
    async fn create(&self, entity: ClearingBatchEntity) -> P3StoreResult<ClearingBatchEntity>;

    /// Get clearing batch by ID
    async fn get(&self, batch_id: &str) -> P3StoreResult<Option<ClearingBatchEntity>>;

    /// Get clearing batch by ID, error if not found
    async fn get_required(&self, batch_id: &str) -> P3StoreResult<ClearingBatchEntity> {
        self.get(batch_id)
            .await?
            .ok_or_else(|| P3StoreError::not_found("ClearingBatch", batch_id))
    }

    /// Update clearing batch
    async fn update(&self, entity: ClearingBatchEntity) -> P3StoreResult<ClearingBatchEntity>;

    /// Update batch status
    async fn update_status(&self, batch_id: &str, status: ClearingBatchStatus) -> P3StoreResult<()>;

    /// List batches by status
    async fn list_by_status(
        &self,
        status: ClearingBatchStatus,
        limit: usize,
    ) -> P3StoreResult<Vec<ClearingBatchEntity>>;

    /// Get batches for epoch
    async fn get_for_epoch(&self, epoch_id: &str) -> P3StoreResult<Vec<ClearingBatchEntity>>;
}

/// Clearing entry repository trait
#[async_trait]
pub trait ClearingEntryRepository: Send + Sync {
    /// Create a clearing entry
    async fn create(&self, entity: ClearingEntryEntity) -> P3StoreResult<ClearingEntryEntity>;

    /// Batch create clearing entries
    async fn create_batch(&self, entities: Vec<ClearingEntryEntity>) -> P3StoreResult<()>;

    /// Get clearing entry by ID
    async fn get(&self, entry_id: &str) -> P3StoreResult<Option<ClearingEntryEntity>>;

    /// Get entries for batch
    async fn get_for_batch(&self, batch_id: &str) -> P3StoreResult<Vec<ClearingEntryEntity>>;

    /// Get entries involving actor
    async fn get_for_actor(
        &self,
        actor_id: &str,
        limit: usize,
    ) -> P3StoreResult<Vec<ClearingEntryEntity>>;
}

/// Treasury pool repository trait
#[async_trait]
pub trait TreasuryPoolRepository: Send + Sync {
    /// Create or update treasury pool
    async fn upsert(&self, entity: TreasuryPoolEntity) -> P3StoreResult<TreasuryPoolEntity>;

    /// Get treasury pool by type
    async fn get(&self, pool_type: TreasuryPoolType) -> P3StoreResult<Option<TreasuryPoolEntity>>;

    /// Get all treasury pools
    async fn get_all(&self) -> P3StoreResult<Vec<TreasuryPoolEntity>>;

    /// Update pool balance
    async fn update_balance(
        &self,
        pool_type: TreasuryPoolType,
        balance_digest: &str,
        epoch_id: &str,
    ) -> P3StoreResult<()>;
}

/// Treasury transaction repository trait
#[async_trait]
pub trait TreasuryTxRepository: Send + Sync {
    /// Create a treasury transaction
    async fn create(&self, entity: TreasuryTxEntity) -> P3StoreResult<TreasuryTxEntity>;

    /// Get treasury transaction by ID
    async fn get(&self, tx_id: &str) -> P3StoreResult<Option<TreasuryTxEntity>>;

    /// Get transactions for epoch
    async fn get_for_epoch(&self, epoch_id: &str) -> P3StoreResult<Vec<TreasuryTxEntity>>;

    /// Get transactions for pool
    async fn get_for_pool(
        &self,
        pool_type: TreasuryPoolType,
        limit: usize,
    ) -> P3StoreResult<Vec<TreasuryTxEntity>>;
}

/// Fee schedule repository trait
#[async_trait]
pub trait FeeScheduleRepository: Send + Sync {
    /// Create a fee schedule
    async fn create(&self, entity: FeeScheduleEntity) -> P3StoreResult<FeeScheduleEntity>;

    /// Get fee schedule by ID and version
    async fn get(&self, schedule_id: &str, version: i32) -> P3StoreResult<Option<FeeScheduleEntity>>;

    /// Get current effective fee schedule
    async fn get_current(&self) -> P3StoreResult<Option<FeeScheduleEntity>>;

    /// List all versions of a schedule
    async fn list_versions(&self, schedule_id: &str) -> P3StoreResult<Vec<FeeScheduleEntity>>;
}

/// Provider repository trait
#[async_trait]
pub trait ProviderRepository: Send + Sync {
    /// Create a provider
    async fn create(&self, entity: ProviderEntity) -> P3StoreResult<ProviderEntity>;

    /// Get provider by ID
    async fn get(&self, provider_id: &str) -> P3StoreResult<Option<ProviderEntity>>;

    /// Get provider by actor ID
    async fn get_by_actor(&self, actor_id: &str) -> P3StoreResult<Option<ProviderEntity>>;

    /// Update provider
    async fn update(&self, entity: ProviderEntity) -> P3StoreResult<ProviderEntity>;

    /// List active providers
    async fn list_active(&self) -> P3StoreResult<Vec<ProviderEntity>>;

    /// List providers by conformance level
    async fn list_by_level(&self, level: &str) -> P3StoreResult<Vec<ProviderEntity>>;
}

/// Version registry repository trait
#[async_trait]
pub trait VersionRegistryRepository: Send + Sync {
    /// Create a version entry
    async fn create(&self, entity: VersionRegistryEntity) -> P3StoreResult<VersionRegistryEntity>;

    /// Get version by ID
    async fn get(&self, version_id: &str) -> P3StoreResult<Option<VersionRegistryEntity>>;

    /// Get active version for object type
    async fn get_active(&self, object_type: &str) -> P3StoreResult<Option<VersionRegistryEntity>>;

    /// Update version
    async fn update(&self, entity: VersionRegistryEntity) -> P3StoreResult<VersionRegistryEntity>;

    /// List versions for object type
    async fn list_for_type(&self, object_type: &str) -> P3StoreResult<Vec<VersionRegistryEntity>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Repository trait tests would go here with mock implementations
}
