//! Org Proof Gateway
//!
//! The Org Proof Gateway is a service layer that handles organization-level
//! proof requests with proper authorization and mandatory audit logging.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                  Org Proof Gateway                       │
//! │  ┌─────────────────────────────────────────────────────┐ │
//! │  │              Authorization Layer                    │ │
//! │  │   ViewerContext + OrgScope + TTL validation        │ │
//! │  └─────────────────────────────────────────────────────┘ │
//! │                         │                                │
//! │                         ▼                                │
//! │  ┌─────────────────────────────────────────────────────┐ │
//! │  │              Query Execution Layer                  │ │
//! │  │   list / lookup / explain / export                 │ │
//! │  └─────────────────────────────────────────────────────┘ │
//! │                         │                                │
//! │                         ▼                                │
//! │  ┌─────────────────────────────────────────────────────┐ │
//! │  │              Mandatory Audit Layer                  │ │
//! │  │   QueryAuditRecord + QueryAuditDigest              │ │
//! │  └─────────────────────────────────────────────────────┘ │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! # Features
//!
//! - **Authorization**: Validates ViewerContext, OrgScope, and TTL
//! - **Query Scoping**: Enforces operation and data scope limits
//! - **Mandatory Audit**: All org-level queries are audited
//! - **Export Control**: DSN_DOWN forbids plaintext export
//! - **Conformance**: Provider operations gated by conformance level

use chrono::Utc;
use p3_core::types::disclosure::{
    ConformanceLevel, DisclosureLevel, ExportScope, ExportTicket, ExportTicketStatus,
    OrgScope, ProviderMaterialRequirements, ProviderOperation, ProviderRegistration,
    ProviderType, QueryAuditDigest, QueryAuditRecord, QueryOperation, QueryScope,
    ViewerContext,
};
use p3_core::P3Digest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;

/// Gateway configuration
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// Default context TTL in seconds
    pub default_context_ttl: i64,
    /// Maximum context TTL in seconds
    pub max_context_ttl: i64,
    /// Default result limit
    pub default_result_limit: u32,
    /// Maximum result limit
    pub max_result_limit: u32,
    /// DSN availability flag
    pub dsn_available: bool,
    /// Export ticket TTL in seconds
    pub export_ticket_ttl: i64,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            default_context_ttl: 3600,      // 1 hour
            max_context_ttl: 86400,         // 24 hours
            default_result_limit: 100,
            max_result_limit: 10000,
            dsn_available: true,
            export_ticket_ttl: 86400,       // 24 hours
        }
    }
}

/// Gateway error types
#[derive(Debug, Clone, thiserror::Error)]
pub enum GatewayError {
    /// Context expired
    #[error("Context expired")]
    ContextExpired,
    /// Context not found
    #[error("Context not found: {0}")]
    ContextNotFound(String),
    /// Operation not allowed
    #[error("Operation not allowed: {0}")]
    OperationNotAllowed(String),
    /// Scope violation
    #[error("Scope violation: {0}")]
    ScopeViolation(String),
    /// Export not allowed
    #[error("Export not allowed: {0}")]
    ExportNotAllowed(String),
    /// Provider not authorized
    #[error("Provider not authorized: {0}")]
    ProviderNotAuthorized(String),
    /// Audit required
    #[error("Audit required for this operation")]
    AuditRequired,
    /// Invalid request
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
}

pub type GatewayResult<T> = Result<T, GatewayError>;

/// Query request for the gateway
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayQueryRequest {
    /// Context ID
    pub context_id: String,
    /// Operation type
    pub operation: QueryOperation,
    /// Resource type
    pub resource_type: String,
    /// Resource ID (for lookup)
    pub resource_id: Option<String>,
    /// Filters
    pub filters: HashMap<String, String>,
    /// Page number
    pub page: u64,
    /// Page size
    pub page_size: u32,
}

/// Query response from the gateway
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayQueryResponse<T> {
    /// Query results
    pub data: T,
    /// Result count
    pub result_count: u32,
    /// Total available (for pagination)
    pub total: u64,
    /// Disclosure level used
    pub disclosure_level: DisclosureLevel,
    /// Audit digest (mandatory for org-level)
    pub audit_digest: QueryAuditDigest,
    /// Query duration in milliseconds
    pub duration_ms: u64,
}

/// Export request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayExportRequest {
    /// Context ID
    pub context_id: String,
    /// Export scope
    pub export_scope: ExportScope,
}

/// Org Proof Gateway service
pub struct OrgProofGateway {
    /// Configuration
    config: GatewayConfig,
    /// Active viewer contexts
    contexts: RwLock<HashMap<String, ViewerContext>>,
    /// Audit log
    audit_log: RwLock<Vec<QueryAuditRecord>>,
    /// Export tickets
    export_tickets: RwLock<HashMap<String, ExportTicket>>,
    /// Provider registrations
    providers: RwLock<HashMap<String, ProviderRegistration>>,
}

impl OrgProofGateway {
    /// Create a new gateway
    pub fn new(config: GatewayConfig) -> Self {
        Self {
            config,
            contexts: RwLock::new(HashMap::new()),
            audit_log: RwLock::new(Vec::new()),
            export_tickets: RwLock::new(HashMap::new()),
            providers: RwLock::new(HashMap::new()),
        }
    }

    /// Create with default configuration
    pub fn default_config() -> Self {
        Self::new(GatewayConfig::default())
    }

    // ============================================
    // Context Management
    // ============================================

    /// Create and store a new viewer context
    pub async fn create_context(
        &self,
        viewer_id: P3Digest,
        org_scope: Option<OrgScope>,
        query_scope: QueryScope,
        ttl_seconds: Option<i64>,
    ) -> String {
        let ttl = ttl_seconds
            .map(|t| t.min(self.config.max_context_ttl))
            .unwrap_or(self.config.default_context_ttl);

        let context = match org_scope {
            Some(scope) => ViewerContext::org(viewer_id, scope, query_scope, ttl),
            None => ViewerContext::new(viewer_id, query_scope, ttl),
        };

        let context_id = format!("ctx:{}", Utc::now().timestamp_nanos_opt().unwrap_or(0));

        self.contexts.write().await.insert(context_id.clone(), context);

        context_id
    }

    /// Validate a viewer context
    pub async fn validate_context(&self, context_id: &str) -> GatewayResult<ViewerContext> {
        let contexts = self.contexts.read().await;
        let context = contexts
            .get(context_id)
            .cloned()
            .ok_or_else(|| GatewayError::ContextNotFound(context_id.to_string()))?;

        if context.is_expired(&Utc::now()) {
            return Err(GatewayError::ContextExpired);
        }

        Ok(context)
    }

    /// Invalidate a context
    pub async fn invalidate_context(&self, context_id: &str) -> bool {
        self.contexts.write().await.remove(context_id).is_some()
    }

    /// Cleanup expired contexts
    pub async fn cleanup_contexts(&self) {
        let now = Utc::now();
        self.contexts.write().await.retain(|_, ctx| !ctx.is_expired(&now));
    }

    // ============================================
    // Query Execution
    // ============================================

    /// Execute a query through the gateway
    pub async fn execute_query<T, F>(
        &self,
        request: GatewayQueryRequest,
        query_fn: F,
    ) -> GatewayResult<GatewayQueryResponse<T>>
    where
        F: FnOnce(&GatewayQueryRequest) -> (T, u32, u64),
        T: Serialize,
    {
        let start = std::time::Instant::now();

        // Validate context
        let context = self.validate_context(&request.context_id).await?;

        // Check operation is allowed
        if !context.query_scope.allows(&request.operation) {
            return Err(GatewayError::OperationNotAllowed(
                format!("{:?}", request.operation)
            ));
        }

        // Validate page size
        let page_size = request.page_size.min(
            context.query_scope.result_limit.unwrap_or(self.config.max_result_limit)
        );

        let validated_request = GatewayQueryRequest {
            page_size,
            ..request.clone()
        };

        // Execute the actual query
        let (data, result_count, total) = query_fn(&validated_request);

        let duration_ms = start.elapsed().as_millis() as u64;
        let disclosure_level = context.disclosure_level();

        // Create audit record (mandatory for org-level)
        let audit_digest = self.create_audit_record(
            &context,
            &request,
            &data,
            result_count,
            duration_ms,
        ).await;

        Ok(GatewayQueryResponse {
            data,
            result_count,
            total,
            disclosure_level,
            audit_digest,
            duration_ms,
        })
    }

    /// Create audit record for a query
    async fn create_audit_record<T: Serialize>(
        &self,
        context: &ViewerContext,
        request: &GatewayQueryRequest,
        result: &T,
        result_count: u32,
        duration_ms: u64,
    ) -> QueryAuditDigest {
        let context_bytes = serde_json::to_vec(context).unwrap_or_default();
        let request_bytes = serde_json::to_vec(request).unwrap_or_default();
        let result_bytes = serde_json::to_vec(result).unwrap_or_default();

        let record = QueryAuditRecord::new(
            P3Digest::blake3(&context_bytes),
            P3Digest::blake3(&request_bytes),
            P3Digest::blake3(&result_bytes),
            result_count,
            context.disclosure_level(),
        ).with_duration(duration_ms);

        let digest = record.audit_digest();

        // Store audit record
        self.audit_log.write().await.push(record);

        digest
    }

    /// Get audit records
    pub async fn get_audit_records(&self, limit: Option<usize>) -> Vec<QueryAuditRecord> {
        let records = self.audit_log.read().await;
        match limit {
            Some(n) => records.iter().rev().take(n).cloned().collect(),
            None => records.clone(),
        }
    }

    // ============================================
    // Export Management
    // ============================================

    /// Request an export ticket
    pub async fn request_export(
        &self,
        request: GatewayExportRequest,
    ) -> GatewayResult<ExportTicket> {
        let context = self.validate_context(&request.context_id).await?;

        // Check export operation is allowed
        if !context.query_scope.allows(&QueryOperation::Export) {
            return Err(GatewayError::ExportNotAllowed(
                "Export operation not in scope".to_string()
            ));
        }

        // Check plaintext export during DSN_DOWN
        if request.export_scope.include_plaintext && !self.config.dsn_available {
            return Err(GatewayError::ExportNotAllowed(
                "Plaintext export not available during DSN_DOWN".to_string()
            ));
        }

        let context_bytes = serde_json::to_vec(&context).unwrap_or_default();
        let ticket = ExportTicket::new(
            P3Digest::blake3(&context_bytes),
            request.export_scope,
            self.config.export_ticket_ttl,
            self.config.dsn_available,
        );

        let ticket_id = ticket.ticket_id.as_str().to_string();
        self.export_tickets.write().await.insert(ticket_id, ticket.clone());

        Ok(ticket)
    }

    /// Approve an export ticket
    pub async fn approve_export(&self, ticket_id: &str) -> GatewayResult<()> {
        let mut tickets = self.export_tickets.write().await;
        let ticket = tickets
            .get_mut(ticket_id)
            .ok_or_else(|| GatewayError::InvalidRequest("Ticket not found".to_string()))?;

        if ticket.is_expired(&Utc::now()) {
            return Err(GatewayError::ContextExpired);
        }

        ticket.approve();
        Ok(())
    }

    /// Reject an export ticket
    pub async fn reject_export(&self, ticket_id: &str, reason: &str) -> GatewayResult<()> {
        let mut tickets = self.export_tickets.write().await;
        let ticket = tickets
            .get_mut(ticket_id)
            .ok_or_else(|| GatewayError::InvalidRequest("Ticket not found".to_string()))?;

        ticket.reject(reason);
        Ok(())
    }

    /// Use an export ticket
    pub async fn use_export(&self, ticket_id: &str) -> GatewayResult<ExportTicket> {
        let mut tickets = self.export_tickets.write().await;
        let ticket = tickets
            .get_mut(ticket_id)
            .ok_or_else(|| GatewayError::InvalidRequest("Ticket not found".to_string()))?;

        if !ticket.is_valid(&Utc::now()) {
            return Err(GatewayError::ExportNotAllowed(
                format!("Ticket status: {:?}", ticket.status)
            ));
        }

        ticket.mark_used();
        Ok(ticket.clone())
    }

    /// Get export ticket
    pub async fn get_export_ticket(&self, ticket_id: &str) -> Option<ExportTicket> {
        self.export_tickets.read().await.get(ticket_id).cloned()
    }

    // ============================================
    // Provider Conformance
    // ============================================

    /// Register a provider
    pub async fn register_provider(
        &self,
        provider_id: &str,
        provider_type: ProviderType,
        level: ConformanceLevel,
    ) -> ProviderRegistration {
        use p3_core::ProviderId;

        let registration = ProviderRegistration::new(
            ProviderId::new(provider_id),
            provider_type,
            level,
        );

        self.providers.write().await.insert(
            provider_id.to_string(),
            registration.clone()
        );

        registration
    }

    /// Check if provider can perform operation
    pub async fn check_provider_authorization(
        &self,
        provider_id: &str,
        operation: &ProviderOperation,
    ) -> GatewayResult<()> {
        let providers = self.providers.read().await;
        let registration = providers
            .get(provider_id)
            .ok_or_else(|| GatewayError::ProviderNotAuthorized(
                format!("Provider not found: {}", provider_id)
            ))?;

        if !registration.can_perform(operation) {
            return Err(GatewayError::ProviderNotAuthorized(
                format!(
                    "Provider {} (level {:?}) cannot perform {:?}",
                    provider_id, registration.conformance_level, operation
                )
            ));
        }

        Ok(())
    }

    /// Update provider conformance level
    pub async fn update_provider_conformance(
        &self,
        provider_id: &str,
        new_level: ConformanceLevel,
        check_digest: P3Digest,
    ) -> GatewayResult<()> {
        let mut providers = self.providers.write().await;
        let registration = providers
            .get_mut(provider_id)
            .ok_or_else(|| GatewayError::ProviderNotAuthorized(
                format!("Provider not found: {}", provider_id)
            ))?;

        registration.conformance_level = new_level;
        registration.last_conformance_check = Some(Utc::now());
        registration.conformance_digest = Some(check_digest);

        Ok(())
    }

    /// Get provider registration
    pub async fn get_provider(&self, provider_id: &str) -> Option<ProviderRegistration> {
        self.providers.read().await.get(provider_id).cloned()
    }

    /// Get required materials for a conformance level
    pub fn get_required_materials(level: &ConformanceLevel) -> ProviderMaterialRequirements {
        ProviderMaterialRequirements::for_level(level)
    }

    // ============================================
    // DSN Status
    // ============================================

    /// Set DSN availability status
    pub fn set_dsn_available(&mut self, available: bool) {
        self.config.dsn_available = available;
    }

    /// Check DSN availability
    pub fn is_dsn_available(&self) -> bool {
        self.config.dsn_available
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_core::types::disclosure::ExportDataType;

    #[tokio::test]
    async fn test_create_context() {
        let gateway = OrgProofGateway::default_config();

        let viewer_id = P3Digest::zero();
        let context_id = gateway.create_context(
            viewer_id,
            None,
            QueryScope::read_only(),
            Some(3600),
        ).await;

        assert!(context_id.starts_with("ctx:"));
    }

    #[tokio::test]
    async fn test_validate_context() {
        let gateway = OrgProofGateway::default_config();

        let context_id = gateway.create_context(
            P3Digest::zero(),
            None,
            QueryScope::read_only(),
            Some(3600),
        ).await;

        let result = gateway.validate_context(&context_id).await;
        assert!(result.is_ok());

        let invalid_result = gateway.validate_context("invalid_ctx").await;
        assert!(invalid_result.is_err());
    }

    #[tokio::test]
    async fn test_org_context() {
        let gateway = OrgProofGateway::default_config();

        let org_scope = OrgScope::new(P3Digest::zero())
            .with_actor_types(vec!["worker".to_string()])
            .with_max_depth(2);

        let context_id = gateway.create_context(
            P3Digest::zero(),
            Some(org_scope),
            QueryScope::full(),
            None,
        ).await;

        let context = gateway.validate_context(&context_id).await.unwrap();
        assert_eq!(context.disclosure_level(), DisclosureLevel::Org);
    }

    #[tokio::test]
    async fn test_execute_query() {
        let gateway = OrgProofGateway::default_config();

        let context_id = gateway.create_context(
            P3Digest::zero(),
            None,
            QueryScope::read_only(),
            Some(3600),
        ).await;

        let request = GatewayQueryRequest {
            context_id,
            operation: QueryOperation::List,
            resource_type: "epochs".to_string(),
            resource_id: None,
            filters: HashMap::new(),
            page: 0,
            page_size: 20,
        };

        let result = gateway.execute_query(request, |_req| {
            (vec!["epoch1", "epoch2"], 2, 100)
        }).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.result_count, 2);
        assert_eq!(response.total, 100);
    }

    #[tokio::test]
    async fn test_operation_not_allowed() {
        let gateway = OrgProofGateway::default_config();

        let context_id = gateway.create_context(
            P3Digest::zero(),
            None,
            QueryScope::read_only(), // Only list and lookup
            Some(3600),
        ).await;

        let request = GatewayQueryRequest {
            context_id,
            operation: QueryOperation::Export, // Not in scope
            resource_type: "epochs".to_string(),
            resource_id: None,
            filters: HashMap::new(),
            page: 0,
            page_size: 20,
        };

        let result = gateway.execute_query(request, |_req| {
            (vec!["epoch1"], 1, 1)
        }).await;

        assert!(matches!(result, Err(GatewayError::OperationNotAllowed(_))));
    }

    #[tokio::test]
    async fn test_export_ticket() {
        let gateway = OrgProofGateway::default_config();

        let context_id = gateway.create_context(
            P3Digest::zero(),
            None,
            QueryScope::full(), // Includes export
            Some(3600),
        ).await;

        let request = GatewayExportRequest {
            context_id,
            export_scope: ExportScope::new(vec![ExportDataType::EpochSummary]),
        };

        let ticket = gateway.request_export(request).await.unwrap();
        assert!(matches!(ticket.status, ExportTicketStatus::Pending));

        // Approve ticket
        gateway.approve_export(ticket.ticket_id.as_str()).await.unwrap();

        let updated_ticket = gateway.get_export_ticket(ticket.ticket_id.as_str()).await.unwrap();
        assert!(matches!(updated_ticket.status, ExportTicketStatus::Approved));
    }

    #[tokio::test]
    async fn test_dsn_down_blocks_plaintext() {
        let mut gateway = OrgProofGateway::default_config();
        gateway.set_dsn_available(false);

        let context_id = gateway.create_context(
            P3Digest::zero(),
            None,
            QueryScope::full(),
            Some(3600),
        ).await;

        let request = GatewayExportRequest {
            context_id,
            export_scope: ExportScope::new(vec![ExportDataType::EpochSummary])
                .with_plaintext(true),
        };

        let result = gateway.request_export(request).await;
        assert!(matches!(result, Err(GatewayError::ExportNotAllowed(_))));
    }

    #[tokio::test]
    async fn test_provider_conformance() {
        let gateway = OrgProofGateway::default_config();

        // Register L2 provider
        gateway.register_provider("provider:test", ProviderType::ThirdParty, ConformanceLevel::L2).await;

        // L2 can verify and weak execute
        assert!(gateway.check_provider_authorization(
            "provider:test",
            &ProviderOperation::Verify
        ).await.is_ok());

        assert!(gateway.check_provider_authorization(
            "provider:test",
            &ProviderOperation::WeakExecute
        ).await.is_ok());

        // L2 cannot strong execute
        assert!(gateway.check_provider_authorization(
            "provider:test",
            &ProviderOperation::StrongExecute
        ).await.is_err());
    }

    #[tokio::test]
    async fn test_audit_log() {
        let gateway = OrgProofGateway::default_config();

        let org_scope = OrgScope::new(P3Digest::zero());
        let context_id = gateway.create_context(
            P3Digest::zero(),
            Some(org_scope),
            QueryScope::full(),
            Some(3600),
        ).await;

        // Execute some queries
        for i in 0..5 {
            let request = GatewayQueryRequest {
                context_id: context_id.clone(),
                operation: QueryOperation::List,
                resource_type: format!("resource_{}", i),
                resource_id: None,
                filters: HashMap::new(),
                page: 0,
                page_size: 20,
            };

            let _ = gateway.execute_query(request, |_| (vec!["item"], 1, 1)).await;
        }

        let records = gateway.get_audit_records(Some(3)).await;
        assert_eq!(records.len(), 3);

        let all_records = gateway.get_audit_records(None).await;
        assert_eq!(all_records.len(), 5);
    }
}
