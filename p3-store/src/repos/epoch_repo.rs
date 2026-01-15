//! Epoch Bundle Repository

use async_trait::async_trait;
use crate::entities::{
    EpochBundleEntity, EpochBundleStatus, ExecutionProofEntity, IdempotencyKeyEntity,
    ManifestSetEntity, ManifestSetType, ResultEntryEntity,
};
use crate::error::{P3StoreError, P3StoreResult};

/// Epoch bundle repository trait
#[async_trait]
pub trait EpochBundleRepository: Send + Sync {
    /// Create a new epoch bundle
    async fn create(&self, entity: EpochBundleEntity) -> P3StoreResult<EpochBundleEntity>;

    /// Get epoch bundle by ID
    async fn get(&self, epoch_id: &str) -> P3StoreResult<Option<EpochBundleEntity>>;

    /// Get epoch bundle by ID, error if not found
    async fn get_required(&self, epoch_id: &str) -> P3StoreResult<EpochBundleEntity> {
        self.get(epoch_id)
            .await?
            .ok_or_else(|| P3StoreError::not_found("EpochBundle", epoch_id))
    }

    /// Update epoch bundle
    async fn update(&self, entity: EpochBundleEntity) -> P3StoreResult<EpochBundleEntity>;

    /// Update epoch bundle status
    async fn update_status(&self, epoch_id: &str, status: EpochBundleStatus) -> P3StoreResult<()>;

    /// List epoch bundles by status
    async fn list_by_status(
        &self,
        status: EpochBundleStatus,
        limit: usize,
    ) -> P3StoreResult<Vec<EpochBundleEntity>>;

    /// List recent epoch bundles
    async fn list_recent(&self, limit: usize) -> P3StoreResult<Vec<EpochBundleEntity>>;

    /// Delete epoch bundle
    async fn delete(&self, epoch_id: &str) -> P3StoreResult<()>;
}

/// Manifest set repository trait
#[async_trait]
pub trait ManifestSetRepository: Send + Sync {
    /// Create a manifest set
    async fn create(&self, entity: ManifestSetEntity) -> P3StoreResult<ManifestSetEntity>;

    /// Get manifest set by epoch ID and type
    async fn get(
        &self,
        epoch_id: &str,
        set_type: ManifestSetType,
    ) -> P3StoreResult<Option<ManifestSetEntity>>;

    /// Get all manifest sets for an epoch
    async fn get_all_for_epoch(&self, epoch_id: &str) -> P3StoreResult<Vec<ManifestSetEntity>>;

    /// Update manifest set
    async fn update(&self, entity: ManifestSetEntity) -> P3StoreResult<ManifestSetEntity>;

    /// Delete manifest sets for epoch
    async fn delete_for_epoch(&self, epoch_id: &str) -> P3StoreResult<()>;
}

/// Result entry repository trait
#[async_trait]
pub trait ResultEntryRepository: Send + Sync {
    /// Create a result entry
    async fn create(&self, entity: ResultEntryEntity) -> P3StoreResult<ResultEntryEntity>;

    /// Batch create result entries
    async fn create_batch(&self, entities: Vec<ResultEntryEntity>) -> P3StoreResult<()>;

    /// Get result entries for epoch
    async fn get_for_epoch(&self, epoch_id: &str) -> P3StoreResult<Vec<ResultEntryEntity>>;

    /// Get result entry by index
    async fn get_by_index(
        &self,
        epoch_id: &str,
        index: i32,
    ) -> P3StoreResult<Option<ResultEntryEntity>>;

    /// Delete result entries for epoch
    async fn delete_for_epoch(&self, epoch_id: &str) -> P3StoreResult<()>;
}

/// Execution proof repository trait
#[async_trait]
pub trait ExecutionProofRepository: Send + Sync {
    /// Create an execution proof
    async fn create(&self, entity: ExecutionProofEntity) -> P3StoreResult<ExecutionProofEntity>;

    /// Get execution proof by ID
    async fn get(&self, proof_id: &str) -> P3StoreResult<Option<ExecutionProofEntity>>;

    /// Get proofs for epoch
    async fn get_for_epoch(&self, epoch_id: &str) -> P3StoreResult<Vec<ExecutionProofEntity>>;

    /// Delete proof
    async fn delete(&self, proof_id: &str) -> P3StoreResult<()>;
}

/// Idempotency key repository trait
#[async_trait]
pub trait IdempotencyKeyRepository: Send + Sync {
    /// Create an idempotency key
    async fn create(&self, entity: IdempotencyKeyEntity) -> P3StoreResult<IdempotencyKeyEntity>;

    /// Check if key exists
    async fn exists(&self, key: &str) -> P3StoreResult<bool>;

    /// Get idempotency key
    async fn get(&self, key: &str) -> P3StoreResult<Option<IdempotencyKeyEntity>>;

    /// Delete expired keys
    async fn delete_expired(&self) -> P3StoreResult<usize>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Repository trait tests would go here with mock implementations
}
