//! Application state for the API server

use l0_db::{
    AnchorService, BackfillService, CausalityService, ConsentService, DisputeService,
    IdentityService, KnowledgeService, L0Database, ReceiptService, SurrealDatastore,
    TipWitnessService,
};
use soulbase_types::prelude::TenantId;
use std::sync::Arc;

/// API server state
#[derive(Clone)]
pub struct AppState {
    /// Identity service
    pub identity: Arc<IdentityService>,
    /// Causality service
    pub causality: Arc<CausalityService>,
    /// Knowledge service
    pub knowledge: Arc<KnowledgeService>,
    /// Consent service
    pub consent: Arc<ConsentService>,
    /// Dispute service
    pub dispute: Arc<DisputeService>,
    /// Receipt service
    pub receipt: Arc<ReceiptService>,
    /// TipWitness service
    pub tipwitness: Arc<TipWitnessService>,
    /// Backfill service
    pub backfill: Arc<BackfillService>,
    /// Anchor service
    pub anchor: Arc<AnchorService>,
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
        let database = Arc::new(L0Database::new(datastore.clone()));

        // Initialize schema
        database.init_schema().await.map_err(|e| {
            l0_core::error::LedgerError::Storage(e.to_string())
        })?;

        let identity = Arc::new(IdentityService::new(database.clone(), tenant_id.clone()));
        let causality = Arc::new(CausalityService::new(database.clone(), tenant_id.clone()));
        let knowledge = Arc::new(KnowledgeService::new(datastore.clone(), tenant_id.clone()));
        let consent = Arc::new(ConsentService::new(datastore.clone(), tenant_id.clone()));
        let dispute = Arc::new(DisputeService::new(datastore.clone(), tenant_id.clone()));
        let receipt = Arc::new(ReceiptService::new(datastore.clone(), tenant_id.clone()));
        let tipwitness = Arc::new(TipWitnessService::new(database, tenant_id.clone()));
        let backfill = Arc::new(BackfillService::new(datastore.clone(), tenant_id.clone()));
        let anchor = Arc::new(AnchorService::new(datastore.clone(), tenant_id));

        // Initialize causality service
        causality.init().await?;

        Ok(Self {
            identity,
            causality,
            knowledge,
            consent,
            dispute,
            receipt,
            tipwitness,
            backfill,
            anchor,
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
