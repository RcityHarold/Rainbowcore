//! L0 Repository implementations
//!
//! Implements storage operations using soulbase-storage's SurrealDB backend.

mod actor_repo;
mod commitment_repo;
mod receipt_repo;

pub use actor_repo::*;
pub use commitment_repo::*;
pub use receipt_repo::*;

use crate::error::{L0DbError, L0DbResult};
use soulbase_storage::spi::Datastore;
use soulbase_storage::surreal::SurrealDatastore;
use std::sync::Arc;

/// L0 Database service - main entry point for storage operations
pub struct L0Database {
    datastore: Arc<SurrealDatastore>,
    pub actors: L0ActorRepo,
    pub commitments: L0CommitmentRepo,
    pub receipts: L0ReceiptRepo,
}

impl L0Database {
    /// Create a new L0Database with the given SurrealDB datastore
    pub fn new(datastore: Arc<SurrealDatastore>) -> Self {
        Self {
            datastore: datastore.clone(),
            actors: L0ActorRepo::new(datastore.clone()),
            commitments: L0CommitmentRepo::new(datastore.clone()),
            receipts: L0ReceiptRepo::new(datastore),
        }
    }

    /// Get the underlying datastore
    pub fn datastore(&self) -> &Arc<SurrealDatastore> {
        &self.datastore
    }

    /// Initialize L0 schema in the database
    pub async fn init_schema(&self) -> L0DbResult<()> {
        let session = self.datastore.session().await.map_err(L0DbError::Storage)?;
        let client = session.client();

        // Execute schema creation
        client
            .query(crate::schema::L0_SCHEMA)
            .await
            .map_err(|e| L0DbError::SchemaError(e.to_string()))?;

        Ok(())
    }

    /// Check database health
    pub async fn health_check(&self) -> L0DbResult<bool> {
        use soulbase_storage::spi::HealthCheck;
        self.datastore
            .ping()
            .await
            .map(|_| true)
            .map_err(L0DbError::Storage)
    }
}
