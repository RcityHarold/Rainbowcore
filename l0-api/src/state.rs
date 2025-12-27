//! Application state for the API server

use l0_db::{CausalityService, IdentityService, L0Database, SurrealDatastore};
use soulbase_types::prelude::TenantId;
use std::sync::Arc;

/// API server state
#[derive(Clone)]
pub struct AppState {
    /// Identity service
    pub identity: Arc<IdentityService>,
    /// Causality service
    pub causality: Arc<CausalityService>,
    /// Node ID (if running as a node)
    pub node_id: Option<String>,
    /// API version
    pub version: String,
}

impl AppState {
    /// Create new app state from database
    pub async fn new(
        datastore: Arc<SurrealDatastore>,
        tenant_id: TenantId,
        node_id: Option<String>,
    ) -> Result<Self, l0_core::error::LedgerError> {
        let database = Arc::new(L0Database::new(datastore));

        // Initialize schema
        database.init_schema().await.map_err(|e| {
            l0_core::error::LedgerError::Storage(e.to_string())
        })?;

        let identity = Arc::new(IdentityService::new(database.clone(), tenant_id.clone()));
        let causality = Arc::new(CausalityService::new(database, tenant_id));

        // Initialize causality service
        causality.init().await?;

        Ok(Self {
            identity,
            causality,
            node_id,
            version: env!("CARGO_PKG_VERSION").to_string(),
        })
    }
}

/// API server configuration
#[derive(Debug, Clone)]
pub struct ApiConfig {
    pub host: String,
    pub port: u16,
    pub enable_cors: bool,
    pub tenant_id: String,
    pub node_id: Option<String>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 3000,
            enable_cors: true,
            tenant_id: "default".to_string(),
            node_id: None,
        }
    }
}
