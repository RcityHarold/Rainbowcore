//! Application State
//!
//! Shared state for the P3 API service.

use chrono::{DateTime, Utc};
use p3_core::types::disclosure::{ExportTicket, QueryAuditRecord, ViewerContext};
use p3_executor::P3Executor;
use p3_store::{P3Database, SurrealConfig, SurrealDatastore};
use p3_verifier::Verifier;
use soulbase_types::prelude::TenantId;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::auth::AuthConfig;
use crate::error::ApiError;

/// Application configuration
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// Service name
    pub service_name: String,
    /// Service version
    pub version: String,
    /// Listen address
    pub listen_addr: String,
    /// Enable CORS
    pub enable_cors: bool,
    /// Request timeout (seconds)
    pub request_timeout_secs: u64,
    /// Max request body size (bytes)
    pub max_body_size: usize,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            service_name: "p3-api".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            listen_addr: "0.0.0.0:3000".to_string(),
            enable_cors: true,
            request_timeout_secs: 30,
            max_body_size: 1024 * 1024, // 1MB
        }
    }
}

/// Application state shared across handlers
pub struct AppState {
    /// Configuration
    pub config: ApiConfig,
    /// Authentication configuration
    pub auth_config: AuthConfig,
    /// P3 Executor
    pub executor: Arc<P3Executor>,
    /// P3 Database (optional - for direct queries)
    pub database: Option<Arc<P3Database>>,
    /// P3 Verifier
    pub verifier: Arc<Verifier>,
    /// Service start time
    pub started_at: DateTime<Utc>,
    /// Request counter
    request_counter: RwLock<u64>,
    /// Viewer contexts (in-memory cache, production would use database)
    viewer_contexts: RwLock<HashMap<String, ViewerContext>>,
    /// Query audit records (in-memory cache, production would use database)
    audit_records: RwLock<Vec<QueryAuditRecord>>,
    /// Export tickets (in-memory cache, production would use database)
    export_tickets: RwLock<HashMap<String, ExportTicket>>,
}

impl AppState {
    /// Create new application state with default config
    pub fn new(executor: P3Executor, verifier: Verifier) -> Self {
        Self {
            config: ApiConfig::default(),
            auth_config: AuthConfig::default(),
            executor: Arc::new(executor),
            database: None,
            verifier: Arc::new(verifier),
            started_at: Utc::now(),
            request_counter: RwLock::new(0),
            viewer_contexts: RwLock::new(HashMap::new()),
            audit_records: RwLock::new(Vec::new()),
            export_tickets: RwLock::new(HashMap::new()),
        }
    }

    /// Create with configuration
    pub fn with_config(config: ApiConfig, executor: P3Executor, verifier: Verifier) -> Self {
        Self {
            config,
            auth_config: AuthConfig::default(),
            executor: Arc::new(executor),
            database: None,
            verifier: Arc::new(verifier),
            started_at: Utc::now(),
            request_counter: RwLock::new(0),
            viewer_contexts: RwLock::new(HashMap::new()),
            audit_records: RwLock::new(Vec::new()),
            export_tickets: RwLock::new(HashMap::new()),
        }
    }

    /// Set authentication configuration
    pub fn with_auth(mut self, auth_config: AuthConfig) -> Self {
        self.auth_config = auth_config;
        self
    }

    /// Set the database
    pub fn with_database(mut self, database: P3Database) -> Self {
        self.database = Some(Arc::new(database));
        self
    }

    /// Create application state with database connection
    ///
    /// This factory method connects to SurrealDB, initializes the schema,
    /// and creates all required services.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use soulbase_storage::surreal::SurrealConfig;
    ///
    /// let state = AppState::with_surreal(
    ///     SurrealConfig::default(),  // uses mem://
    ///     TenantId("default".to_string()),
    ///     ApiConfig::default(),
    /// ).await?;
    /// ```
    pub async fn with_surreal(
        surreal_config: SurrealConfig,
        tenant_id: TenantId,
        config: ApiConfig,
    ) -> Result<Self, ApiError> {
        // Connect to SurrealDB
        let datastore = Arc::new(
            SurrealDatastore::connect(surreal_config)
                .await
                .map_err(|e| ApiError::Internal {
                    message: format!("Database connection failed: {}", e),
                })?
        );

        // Create database and initialize schema
        let database = P3Database::new(datastore, tenant_id);
        database.init_schema().await?;

        tracing::info!("P3 database schema initialized successfully");

        // Create executor and verifier
        let executor = P3Executor::default_config();
        let verifier = Verifier::l1();

        Ok(Self {
            config,
            auth_config: AuthConfig::from_env(),
            executor: Arc::new(executor),
            database: Some(Arc::new(database)),
            verifier: Arc::new(verifier),
            started_at: Utc::now(),
            request_counter: RwLock::new(0),
            viewer_contexts: RwLock::new(HashMap::new()),
            audit_records: RwLock::new(Vec::new()),
            export_tickets: RwLock::new(HashMap::new()),
        })
    }

    /// Get service uptime in seconds
    pub fn uptime_secs(&self) -> u64 {
        let now = Utc::now();
        (now - self.started_at).num_seconds().max(0) as u64
    }

    /// Increment request counter
    pub async fn increment_requests(&self) -> u64 {
        let mut counter = self.request_counter.write().await;
        *counter += 1;
        *counter
    }

    /// Get request count
    pub async fn request_count(&self) -> u64 {
        *self.request_counter.read().await
    }

    // ============================================
    // Disclosure Context Management
    // ============================================

    /// Store a viewer context
    pub async fn store_viewer_context(&self, context_id: &str, context: ViewerContext) {
        let mut contexts = self.viewer_contexts.write().await;
        contexts.insert(context_id.to_string(), context);
    }

    /// Get a viewer context
    pub async fn get_viewer_context(&self, context_id: &str) -> Option<ViewerContext> {
        let contexts = self.viewer_contexts.read().await;
        contexts.get(context_id).cloned()
    }

    /// Remove expired viewer contexts
    pub async fn cleanup_expired_contexts(&self) {
        let now = Utc::now();
        let mut contexts = self.viewer_contexts.write().await;
        contexts.retain(|_, ctx| !ctx.is_expired(&now));
    }

    // ============================================
    // Audit Record Management
    // ============================================

    /// Store an audit record
    pub async fn store_audit_record(&self, record: QueryAuditRecord) {
        let mut records = self.audit_records.write().await;
        records.push(record);
    }

    /// Get audit records (with optional limit)
    pub async fn get_audit_records(&self, limit: Option<usize>) -> Vec<QueryAuditRecord> {
        let records = self.audit_records.read().await;
        match limit {
            Some(n) => records.iter().rev().take(n).cloned().collect(),
            None => records.clone(),
        }
    }

    /// Get audit records count
    pub async fn audit_records_count(&self) -> usize {
        self.audit_records.read().await.len()
    }

    // ============================================
    // Export Ticket Management
    // ============================================

    /// Store an export ticket
    pub async fn store_export_ticket(&self, ticket: ExportTicket) {
        let mut tickets = self.export_tickets.write().await;
        tickets.insert(ticket.ticket_id.as_str().to_string(), ticket);
    }

    /// Get an export ticket
    pub async fn get_export_ticket(&self, ticket_id: &str) -> Option<ExportTicket> {
        let tickets = self.export_tickets.read().await;
        tickets.get(ticket_id).cloned()
    }

    /// Update export ticket status
    pub async fn update_export_ticket<F>(&self, ticket_id: &str, update_fn: F) -> bool
    where
        F: FnOnce(&mut ExportTicket),
    {
        let mut tickets = self.export_tickets.write().await;
        if let Some(ticket) = tickets.get_mut(ticket_id) {
            update_fn(ticket);
            true
        } else {
            false
        }
    }

    /// Remove expired export tickets
    pub async fn cleanup_expired_tickets(&self) {
        let now = Utc::now();
        let mut tickets = self.export_tickets.write().await;
        tickets.retain(|_, ticket| !ticket.is_expired(&now));
    }
}

/// Health status of the service
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthStatus {
    /// Service is healthy
    Healthy,
    /// Service is degraded but functional
    Degraded,
    /// Service is unhealthy
    Unhealthy,
}

impl HealthStatus {
    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            HealthStatus::Healthy => "healthy",
            HealthStatus::Degraded => "degraded",
            HealthStatus::Unhealthy => "unhealthy",
        }
    }
}

/// Component health check result
#[derive(Debug, Clone)]
pub struct ComponentHealthCheck {
    /// Component name
    pub name: String,
    /// Health status
    pub status: HealthStatus,
    /// Optional message
    pub message: Option<String>,
}

impl ComponentHealthCheck {
    /// Create a healthy result
    pub fn healthy(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: HealthStatus::Healthy,
            message: None,
        }
    }

    /// Create a degraded result
    pub fn degraded(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: HealthStatus::Degraded,
            message: Some(message.into()),
        }
    }

    /// Create an unhealthy result
    pub fn unhealthy(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: HealthStatus::Unhealthy,
            message: Some(message.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_executor::{ExecutorConfig, P3Executor};
    use p3_verifier::Verifier;

    #[test]
    fn test_api_config_default() {
        let config = ApiConfig::default();
        assert_eq!(config.service_name, "p3-api");
        assert_eq!(config.listen_addr, "0.0.0.0:3000");
        assert!(config.enable_cors);
    }

    #[test]
    fn test_app_state_creation() {
        let executor = P3Executor::default_config();
        let verifier = Verifier::l1();

        let state = AppState::new(executor, verifier);
        assert!(state.uptime_secs() < 2); // Just created
    }

    #[tokio::test]
    async fn test_request_counter() {
        let executor = P3Executor::default_config();
        let verifier = Verifier::l1();

        let state = AppState::new(executor, verifier);
        assert_eq!(state.request_count().await, 0);

        let count = state.increment_requests().await;
        assert_eq!(count, 1);

        let count = state.increment_requests().await;
        assert_eq!(count, 2);

        assert_eq!(state.request_count().await, 2);
    }

    #[test]
    fn test_health_status() {
        assert_eq!(HealthStatus::Healthy.as_str(), "healthy");
        assert_eq!(HealthStatus::Degraded.as_str(), "degraded");
        assert_eq!(HealthStatus::Unhealthy.as_str(), "unhealthy");
    }

    #[test]
    fn test_component_health_check() {
        let healthy = ComponentHealthCheck::healthy("executor");
        assert_eq!(healthy.status, HealthStatus::Healthy);
        assert!(healthy.message.is_none());

        let degraded = ComponentHealthCheck::degraded("database", "High latency");
        assert_eq!(degraded.status, HealthStatus::Degraded);
        assert_eq!(degraded.message.as_deref(), Some("High latency"));

        let unhealthy = ComponentHealthCheck::unhealthy("verifier", "Connection failed");
        assert_eq!(unhealthy.status, HealthStatus::Unhealthy);
    }
}
