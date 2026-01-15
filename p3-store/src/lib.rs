//! P3 Store - Economy Layer Storage
//!
//! Provides storage integration for P3 Economy Layer using soulbase-storage.
//!
//! This crate implements the storage layer for P3 economy operations
//! using SurrealDB (via soulbase-storage) as the persistence layer.
//!
//! # Architecture
//!
//! Reuses soulbase-storage capabilities:
//! - `SurrealDatastore` - SurrealDB connection management
//! - `Repository<E>` - Generic CRUD operations
//! - `Session` / `Transaction` - Transaction support
//! - `HealthCheck` - Health checking
//!
//! # Usage Example
//!
//! ```ignore
//! use p3_store::{P3Database, EpochBundleEntity};
//! use soulbase_storage::surreal::SurrealDatastore;
//! use std::sync::Arc;
//!
//! async fn example() {
//!     let datastore = Arc::new(SurrealDatastore::connect("mem://").await.unwrap());
//!     let db = P3Database::new(datastore);
//!     db.init_schema().await.unwrap();
//! }
//! ```

pub mod entities;
pub mod error;
pub mod repos;
pub mod schema;

// Re-export main types
pub use entities::*;
pub use error::*;
pub use repos::*;
pub use schema::P3_SCHEMA;

// Re-export soulbase-storage for convenience
pub use soulbase_storage::model::{Entity, Page, QueryParams};
pub use soulbase_storage::spi::Datastore;
pub use soulbase_storage::surreal::{SurrealConfig, SurrealDatastore};

use soulbase_types::prelude::TenantId;
use std::sync::Arc;

/// P3 Database facade
///
/// Provides unified access to P3 storage operations.
///
/// # Example
///
/// ```ignore
/// use p3_store::P3Database;
/// use soulbase_storage::surreal::SurrealDatastore;
/// use soulbase_types::prelude::TenantId;
/// use std::sync::Arc;
///
/// async fn example() {
///     let datastore = Arc::new(SurrealDatastore::connect("mem://").await.unwrap());
///     let tenant_id = TenantId("default".to_string());
///     let db = P3Database::new(datastore, tenant_id);
///
///     // Initialize schema (run once on startup)
///     db.init_schema().await.unwrap();
///
///     // Use repositories
///     let balance = db.points_balance().get("actor:1", PointType::ACP).await;
/// }
/// ```
pub struct P3Database {
    /// Underlying datastore
    datastore: Arc<SurrealDatastore>,
    /// Tenant ID for multi-tenancy
    tenant_id: TenantId,
    /// Epoch bundle repository
    pub epoch_bundles: SurrealEpochBundleRepository,
    /// Manifest set repository
    pub manifest_sets: SurrealManifestSetRepository,
    /// Result entry repository
    pub result_entries: SurrealResultEntryRepository,
    /// Execution proof repository
    pub execution_proofs: SurrealExecutionProofRepository,
    /// Idempotency key repository
    pub idempotency_keys: SurrealIdempotencyKeyRepository,
    /// Points balance repository
    pub points_balances: SurrealPointsBalanceRepository,
    /// Points history repository
    pub points_history: SurrealPointsHistoryRepository,
    /// Clearing batch repository
    pub clearing_batches: SurrealClearingBatchRepository,
    /// Clearing entry repository
    pub clearing_entries: SurrealClearingEntryRepository,
    /// Treasury pool repository
    pub treasury_pools: SurrealTreasuryPoolRepository,
    /// Treasury transaction repository
    pub treasury_txs: SurrealTreasuryTxRepository,
    /// Fee schedule repository
    pub fee_schedules: SurrealFeeScheduleRepository,
    /// Provider repository
    pub providers: SurrealProviderRepository,
    /// Version registry repository
    pub version_registry: SurrealVersionRegistryRepository,
}

impl P3Database {
    /// Create new P3 database instance
    pub fn new(datastore: Arc<SurrealDatastore>, tenant_id: TenantId) -> Self {
        Self {
            epoch_bundles: SurrealEpochBundleRepository::new(datastore.clone(), tenant_id.clone()),
            manifest_sets: SurrealManifestSetRepository::new(datastore.clone(), tenant_id.clone()),
            result_entries: SurrealResultEntryRepository::new(datastore.clone(), tenant_id.clone()),
            execution_proofs: SurrealExecutionProofRepository::new(datastore.clone(), tenant_id.clone()),
            idempotency_keys: SurrealIdempotencyKeyRepository::new(datastore.clone(), tenant_id.clone()),
            points_balances: SurrealPointsBalanceRepository::new(datastore.clone(), tenant_id.clone()),
            points_history: SurrealPointsHistoryRepository::new(datastore.clone(), tenant_id.clone()),
            clearing_batches: SurrealClearingBatchRepository::new(datastore.clone(), tenant_id.clone()),
            clearing_entries: SurrealClearingEntryRepository::new(datastore.clone(), tenant_id.clone()),
            treasury_pools: SurrealTreasuryPoolRepository::new(datastore.clone(), tenant_id.clone()),
            treasury_txs: SurrealTreasuryTxRepository::new(datastore.clone(), tenant_id.clone()),
            fee_schedules: SurrealFeeScheduleRepository::new(datastore.clone(), tenant_id.clone()),
            providers: SurrealProviderRepository::new(datastore.clone(), tenant_id.clone()),
            version_registry: SurrealVersionRegistryRepository::new(datastore.clone(), tenant_id.clone()),
            datastore,
            tenant_id,
        }
    }

    /// Initialize database schema
    ///
    /// This should be called once on application startup to ensure
    /// all required tables exist in SurrealDB.
    pub async fn init_schema(&self) -> P3StoreResult<()> {
        let session = self.datastore.session().await
            .map_err(|e| P3StoreError::Connection(e.to_string()))?;

        // Execute schema creation using the SurrealDB client
        session.client()
            .query(P3_SCHEMA)
            .await
            .map_err(|e| P3StoreError::Database(e.to_string()))?;

        tracing::info!("P3 database schema initialized successfully");
        Ok(())
    }

    /// Check database health
    pub async fn health_check(&self) -> P3StoreResult<bool> {
        use soulbase_storage::spi::HealthCheck;
        self.datastore
            .ping()
            .await
            .map(|_| true)
            .map_err(|e| P3StoreError::Connection(e.to_string()))
    }

    /// Get the underlying datastore
    pub fn datastore(&self) -> &Arc<SurrealDatastore> {
        &self.datastore
    }

    /// Get the tenant ID
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Create a points service for composite operations
    pub fn points_service(&self) -> SurrealPointsService {
        SurrealPointsService::new(self.datastore.clone(), self.tenant_id.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p3_schema_is_valid() {
        // Schema should be non-empty
        assert!(!P3_SCHEMA.is_empty());
        // Schema should contain table definitions
        assert!(P3_SCHEMA.contains("DEFINE TABLE"));
        // Schema should contain P3 tables
        assert!(P3_SCHEMA.contains("p3_epoch_bundle"));
        assert!(P3_SCHEMA.contains("p3_manifest_set"));
        assert!(P3_SCHEMA.contains("p3_points_balance"));
        assert!(P3_SCHEMA.contains("p3_treasury_pool"));
        assert!(P3_SCHEMA.contains("p3_clearing_batch"));
    }
}
