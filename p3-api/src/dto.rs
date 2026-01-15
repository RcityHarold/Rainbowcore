//! Data Transfer Objects
//!
//! Request and response DTOs for the P3 API layer.

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

// ============================================
// Execution DTOs
// ============================================

/// Request to execute an operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteOperationRequest {
    /// Operation type
    pub operation_type: String,
    /// Target digest (hex-encoded)
    pub target_digest: String,
    /// Optional amount
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<Decimal>,
    /// Epoch ID
    pub epoch_id: String,
    /// Initiator reference
    pub initiator_ref: String,
    /// Optional executor reference
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executor_ref: Option<String>,
}

/// Response from execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteOperationResponse {
    /// Execution ID
    pub execution_id: String,
    /// Final status
    pub status: String,
    /// Resolution type
    pub resolution_type: String,
    /// Result digest (hex-encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_digest: Option<String>,
    /// Proof reference
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_ref: Option<ProofRefDto>,
    /// Completed at
    pub completed_at: DateTime<Utc>,
}

/// Proof reference DTO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRefDto {
    /// Proof ID
    pub proof_id: String,
    /// Proof type
    pub proof_type: String,
    /// Executor reference
    pub executor_ref: String,
    /// Executed at
    pub executed_at: DateTime<Utc>,
    /// Proof digest (hex-encoded)
    pub proof_digest: String,
}

// ============================================
// Quote DTOs
// ============================================

/// Request for a quote
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteRequest {
    /// Operation type
    pub operation_type: String,
    /// Target digest (hex-encoded)
    pub target_ref: String,
    /// Optional amount
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<Decimal>,
    /// Epoch ID
    pub epoch_id: String,
    /// Initiator reference
    pub initiator_ref: String,
    /// Params digest (hex-encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params_digest: Option<String>,
}

/// Quote response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteResponse {
    /// Quote ID
    pub quote_id: String,
    /// Status
    pub status: String,
    /// Quoted amount
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quoted_amount: Option<Decimal>,
    /// Fee amount
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_amount: Option<Decimal>,
    /// Valid until
    pub valid_until: DateTime<Utc>,
    /// Quote digest (hex-encoded)
    pub quote_digest: String,
}

// ============================================
// Provider DTOs
// ============================================

/// Provider information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderDto {
    /// Provider ID
    pub provider_id: String,
    /// Provider name
    pub name: String,
    /// Status
    pub status: String,
    /// Service type
    pub service_type: String,
    /// Total credits
    pub total_credits: Decimal,
    /// Total debits
    pub total_debits: Decimal,
    /// Net balance
    pub net_balance: Decimal,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Last activity
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_activity: Option<DateTime<Utc>>,
}

/// Request to create a provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateProviderRequest {
    /// Provider name
    pub name: String,
    /// Service type
    pub service_type: String,
    /// Initial configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
}

/// Request to update provider status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateProviderStatusRequest {
    /// New status
    pub status: String,
    /// Reason for status change
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// ============================================
// Clearing DTOs
// ============================================

/// Clearing batch information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearingBatchDto {
    /// Batch ID
    pub batch_id: String,
    /// Epoch ID
    pub epoch_id: String,
    /// Status
    pub status: String,
    /// Entry count
    pub entry_count: u64,
    /// Total amount
    pub total_amount: Decimal,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Finalized at
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finalized_at: Option<DateTime<Utc>>,
}

/// Request to create clearing batch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateClearingBatchRequest {
    /// Epoch ID
    pub epoch_id: String,
}

/// Clearing entry DTO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearingEntryDto {
    /// Entry ID
    pub entry_id: String,
    /// Batch ID
    pub batch_id: String,
    /// From account
    pub from_account: String,
    /// To account
    pub to_account: String,
    /// Amount
    pub amount: Decimal,
    /// Entry type
    pub entry_type: String,
    /// Created at
    pub created_at: DateTime<Utc>,
}

/// Request to add clearing entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddClearingEntryRequest {
    /// From account
    pub from_account: String,
    /// To account
    pub to_account: String,
    /// Amount
    pub amount: Decimal,
    /// Entry type
    pub entry_type: String,
}

// ============================================
// Treasury DTOs
// ============================================

/// Treasury pool information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryPoolDto {
    /// Pool ID
    pub pool_id: String,
    /// Pool name
    pub name: String,
    /// Pool type
    pub pool_type: String,
    /// Current balance
    pub balance: Decimal,
    /// Minimum balance
    pub min_balance: Decimal,
    /// Maximum balance
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_balance: Option<Decimal>,
    /// Status
    pub status: String,
    /// Created at
    pub created_at: DateTime<Utc>,
}

/// Treasury transaction DTO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryTxDto {
    /// Transaction ID
    pub tx_id: String,
    /// Pool ID
    pub pool_id: String,
    /// Transaction type
    pub tx_type: String,
    /// Amount
    pub amount: Decimal,
    /// Balance after
    pub balance_after: Decimal,
    /// Reference
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// Created at
    pub created_at: DateTime<Utc>,
}

// ============================================
// Epoch DTOs
// ============================================

/// Epoch information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochDto {
    /// Epoch ID
    pub epoch_id: String,
    /// Status
    pub status: String,
    /// Start time
    pub start_time: DateTime<Utc>,
    /// End time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time: Option<DateTime<Utc>>,
    /// Operation count
    pub operation_count: u64,
    /// Total volume
    pub total_volume: Decimal,
}

// ============================================
// Verification DTOs
// ============================================

/// Verification request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRequest {
    /// Data to verify (hex-encoded)
    pub data: String,
    /// Verification type
    pub verification_type: String,
    /// Expected digest (hex-encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_digest: Option<String>,
}

/// Verification response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResponse {
    /// Is valid
    pub valid: bool,
    /// Computed digest (hex-encoded)
    pub digest: String,
    /// Verification details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

// ============================================
// Statistics DTOs
// ============================================

/// Executor statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorStatsDto {
    /// Active executions
    pub active_executions: usize,
    /// Active attempt chains
    pub active_attempt_chains: usize,
    /// Proofs generated
    pub proofs_generated: u64,
    /// Active proof batches
    pub active_batches: usize,
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Service status
    pub status: String,
    /// Version
    pub version: String,
    /// Uptime seconds
    pub uptime_secs: u64,
    /// Component health
    pub components: Vec<ComponentHealth>,
}

/// Component health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Component name
    pub name: String,
    /// Status
    pub status: String,
    /// Message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

// ============================================
// List/Pagination DTOs
// ============================================

/// Paginated list response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    /// Items
    pub items: Vec<T>,
    /// Total count
    pub total: u64,
    /// Page number (0-indexed)
    pub page: u64,
    /// Page size
    pub page_size: u64,
    /// Has more pages
    pub has_more: bool,
}

/// Query parameters for listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListQuery {
    /// Page number (0-indexed)
    #[serde(default)]
    pub page: u64,
    /// Page size
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    /// Sort field
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort_by: Option<String>,
    /// Sort order (asc/desc)
    #[serde(default = "default_sort_order")]
    pub sort_order: String,
    /// Filter by status
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

fn default_page_size() -> u64 {
    20
}

fn default_sort_order() -> String {
    "desc".to_string()
}

impl Default for ListQuery {
    fn default() -> Self {
        Self {
            page: 0,
            page_size: default_page_size(),
            sort_by: None,
            sort_order: default_sort_order(),
            status: None,
        }
    }
}

// ============================================
// Disclosure DTOs
// ============================================

/// Request to create a viewer context (authorization)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateViewerContextRequest {
    /// Viewer ID (hex-encoded digest)
    pub viewer_id: String,
    /// Organization ID (hex-encoded, optional for org-level access)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    /// Allowed actor types (for org scope)
    #[serde(default)]
    pub actor_types: Vec<String>,
    /// Allowed query operations
    #[serde(default)]
    pub operations: Vec<String>,
    /// TTL in seconds
    #[serde(default = "default_context_ttl")]
    pub ttl_seconds: i64,
    /// Epoch range (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch_start: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch_end: Option<String>,
    /// Result limit
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_limit: Option<u32>,
}

fn default_context_ttl() -> i64 {
    3600 // 1 hour
}

/// Viewer context response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewerContextDto {
    /// Context ID (for subsequent requests)
    pub context_id: String,
    /// Viewer ID
    pub viewer_id: String,
    /// Disclosure level
    pub disclosure_level: String,
    /// Query operations allowed
    pub operations: Vec<String>,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Expires at
    pub expires_at: DateTime<Utc>,
    /// Organization scope (if org-level)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_scope: Option<OrgScopeDto>,
}

/// Organization scope DTO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgScopeDto {
    /// Organization ID
    pub org_id: String,
    /// Allowed actor types
    pub actor_types: Vec<String>,
    /// Max depth for related data
    pub max_depth: u32,
}

/// Disclosure query request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisclosureQueryRequest {
    /// Context ID (from CreateViewerContextResponse)
    pub context_id: String,
    /// Query operation (list, lookup, explain, export)
    pub operation: String,
    /// Resource type to query
    pub resource_type: String,
    /// Resource ID (for lookup operations)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
    /// Page number
    #[serde(default)]
    pub page: u64,
    /// Page size
    #[serde(default = "default_page_size")]
    pub page_size: u64,
}

/// Disclosure query response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisclosureQueryResponse<T> {
    /// Query results
    pub data: T,
    /// Query audit digest (for org-level queries)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_digest: Option<String>,
    /// Disclosure level used
    pub disclosure_level: String,
    /// Result count
    pub result_count: u32,
}

/// Query audit record DTO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryAuditRecordDto {
    /// Audit ID
    pub audit_id: String,
    /// Viewer context digest
    pub viewer_context_digest: String,
    /// Query parameters digest
    pub query_params_digest: String,
    /// Result digest
    pub result_digest: String,
    /// Result count
    pub result_count: u32,
    /// Queried at
    pub queried_at: DateTime<Utc>,
    /// Duration in milliseconds
    pub duration_ms: u64,
    /// Disclosure level
    pub disclosure_level: String,
    /// Audit digest
    pub audit_digest: String,
}

/// Request to create export ticket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateExportTicketRequest {
    /// Viewer context ID
    pub context_id: String,
    /// Data types to export
    pub data_types: Vec<String>,
    /// Export format (json, csv, parquet)
    #[serde(default = "default_export_format")]
    pub format: String,
    /// Include plaintext (requires DSN available)
    #[serde(default)]
    pub include_plaintext: bool,
    /// Epoch range (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch_start: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch_end: Option<String>,
    /// TTL in seconds
    #[serde(default = "default_export_ttl")]
    pub ttl_seconds: i64,
}

fn default_export_format() -> String {
    "json".to_string()
}

fn default_export_ttl() -> i64 {
    86400 // 24 hours
}

/// Export ticket response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportTicketDto {
    /// Ticket ID
    pub ticket_id: String,
    /// Status
    pub status: String,
    /// Data types included
    pub data_types: Vec<String>,
    /// Export format
    pub format: String,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Expires at
    pub expires_at: DateTime<Utc>,
    /// Whether plaintext export is allowed
    pub plaintext_allowed: bool,
    /// Audit digest (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_digest: Option<String>,
}

/// Provider conformance DTO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConformanceDto {
    /// Provider ID
    pub provider_id: String,
    /// Provider type
    pub provider_type: String,
    /// Conformance level (L1, L2, L3)
    pub conformance_level: String,
    /// Is active
    pub is_active: bool,
    /// Registered at
    pub registered_at: DateTime<Utc>,
    /// Last conformance check
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_conformance_check: Option<DateTime<Utc>>,
    /// Conformance digest
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conformance_digest: Option<String>,
    /// Required materials for this level
    pub required_materials: Vec<RequiredMaterialDto>,
}

/// Required material DTO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequiredMaterialDto {
    /// Material name
    pub name: String,
    /// Material description
    pub description: String,
}

/// Conformance check request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceCheckRequest {
    /// Provider ID
    pub provider_id: String,
    /// Target conformance level
    pub target_level: String,
    /// Submitted materials
    pub materials: Vec<SubmittedMaterialDto>,
}

/// Submitted material DTO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmittedMaterialDto {
    /// Material name
    pub name: String,
    /// Material digest (hex-encoded)
    pub digest: String,
}

/// Conformance check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceCheckResponse {
    /// Provider ID
    pub provider_id: String,
    /// Check passed
    pub passed: bool,
    /// Achieved level
    pub achieved_level: String,
    /// Checked at
    pub checked_at: DateTime<Utc>,
    /// Check digest
    pub check_digest: String,
    /// Missing materials (if not passed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing_materials: Option<Vec<String>>,
}

/// Public aggregated stats (disclosure level: public)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicAggregatedStatsDto {
    /// Total epochs
    pub total_epochs: u64,
    /// Total operations (aggregated)
    pub total_operations: u64,
    /// Total volume (aggregated)
    pub total_volume: Decimal,
    /// Active providers count
    pub active_providers: u64,
    /// Last updated
    pub last_updated: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_operation_request_serialization() {
        let request = ExecuteOperationRequest {
            operation_type: "Distribution".to_string(),
            target_digest: "abc123".to_string(),
            amount: Some(Decimal::new(1000, 2)),
            epoch_id: "epoch:2024:001".to_string(),
            initiator_ref: "initiator:1".to_string(),
            executor_ref: Some("executor:1".to_string()),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("Distribution"));
        assert!(json.contains("10.00"));
    }

    #[test]
    fn test_paginated_response() {
        let response = PaginatedResponse {
            items: vec!["item1", "item2"],
            total: 100,
            page: 0,
            page_size: 20,
            has_more: true,
        };

        assert_eq!(response.items.len(), 2);
        assert!(response.has_more);
    }

    #[test]
    fn test_list_query_defaults() {
        let query = ListQuery::default();
        assert_eq!(query.page, 0);
        assert_eq!(query.page_size, 20);
        assert_eq!(query.sort_order, "desc");
    }

    #[test]
    fn test_viewer_context_dto_serialization() {
        let dto = ViewerContextDto {
            context_id: "ctx:123".to_string(),
            viewer_id: "viewer:abc".to_string(),
            disclosure_level: "org".to_string(),
            operations: vec!["list".to_string(), "lookup".to_string()],
            created_at: Utc::now(),
            expires_at: Utc::now(),
            org_scope: Some(OrgScopeDto {
                org_id: "org:123".to_string(),
                actor_types: vec!["worker".to_string()],
                max_depth: 2,
            }),
        };

        let json = serde_json::to_string(&dto).unwrap();
        assert!(json.contains("ctx:123"));
        assert!(json.contains("org"));
    }

    #[test]
    fn test_export_ticket_dto_serialization() {
        let dto = ExportTicketDto {
            ticket_id: "export:123".to_string(),
            status: "pending".to_string(),
            data_types: vec!["epoch_summary".to_string()],
            format: "json".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now(),
            plaintext_allowed: true,
            audit_digest: None,
        };

        let json = serde_json::to_string(&dto).unwrap();
        assert!(json.contains("export:123"));
        assert!(json.contains("pending"));
    }

    #[test]
    fn test_conformance_check_response() {
        let response = ConformanceCheckResponse {
            provider_id: "provider:test".to_string(),
            passed: true,
            achieved_level: "L2".to_string(),
            checked_at: Utc::now(),
            check_digest: "abc123".to_string(),
            missing_materials: None,
        };

        assert!(response.passed);
        assert_eq!(response.achieved_level, "L2");
    }

    #[test]
    fn test_public_aggregated_stats() {
        let stats = PublicAggregatedStatsDto {
            total_epochs: 100,
            total_operations: 10000,
            total_volume: Decimal::new(1000000, 2),
            active_providers: 5,
            last_updated: Utc::now(),
        };

        assert_eq!(stats.total_epochs, 100);
        assert_eq!(stats.active_providers, 5);
    }
}
