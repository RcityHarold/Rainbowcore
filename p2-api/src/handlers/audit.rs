//! Audit API Handlers
//!
//! REST API endpoints for querying and managing audit logs.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Utc};
use l0_core::types::ActorId;
use p2_core::ledger::AuditLedger;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::info;

use crate::error::ApiError;
use crate::state::AppState;

/// Audit log query parameters
#[derive(Debug, Deserialize)]
pub struct AuditQueryParams {
    /// Filter by entry type (decrypt, export, access_denied, policy_violation)
    #[serde(rename = "type")]
    pub entry_type: Option<String>,
    /// Filter by actor ID
    pub actor_id: Option<String>,
    /// Filter by payload reference
    pub payload_ref: Option<String>,
    /// Filter by ticket reference
    pub ticket_ref: Option<String>,
    /// Start time (ISO 8601)
    pub from: Option<DateTime<Utc>>,
    /// End time (ISO 8601)
    pub to: Option<DateTime<Utc>>,
    /// Maximum results (default: 100)
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Offset for pagination
    #[serde(default)]
    pub offset: usize,
}

fn default_limit() -> usize {
    100
}

/// Audit entry response
#[derive(Debug, Serialize)]
pub struct AuditEntryResponse {
    /// Entry sequence number
    pub sequence: u64,
    /// Entry type
    pub entry_type: String,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Actor who performed the action
    pub actor_id: Option<String>,
    /// Target payload reference
    pub payload_ref: Option<String>,
    /// Ticket reference used
    pub ticket_ref: Option<String>,
    /// Operation details
    pub details: serde_json::Value,
    /// Entry hash (for verification)
    pub entry_hash: String,
    /// Previous entry hash (chain link)
    pub prev_hash: Option<String>,
}

/// Audit query response
#[derive(Debug, Serialize)]
pub struct AuditQueryResponse {
    /// Matching entries
    pub entries: Vec<AuditEntryResponse>,
    /// Total count (before pagination)
    pub total_count: usize,
    /// Current page offset
    pub offset: usize,
    /// Limit used
    pub limit: usize,
    /// Whether chain integrity is verified
    pub chain_verified: bool,
    /// Query execution time in milliseconds
    pub query_time_ms: u64,
}

/// Chain verification response
#[derive(Debug, Serialize)]
pub struct ChainVerificationResponse {
    /// Chain ID
    pub chain_id: String,
    /// Whether verification passed
    pub verified: bool,
    /// Total entries checked
    pub entries_checked: usize,
    /// Verification timestamp
    pub verified_at: DateTime<Utc>,
    /// Error message if verification failed
    pub error: Option<String>,
}

/// Audit statistics response
#[derive(Debug, Serialize)]
pub struct AuditStatsResponse {
    /// Chain ID
    pub chain_id: String,
    /// Total audit entries
    pub total_entries: usize,
    /// Decrypt operations count
    pub decrypt_count: usize,
    /// Export operations count
    pub export_count: usize,
    /// Access denied count
    pub access_denied_count: usize,
    /// Policy violation count
    pub policy_violation_count: usize,
    /// Chain integrity status
    pub chain_verified: bool,
    /// Oldest entry timestamp
    pub oldest_entry: Option<DateTime<Utc>>,
    /// Newest entry timestamp
    pub newest_entry: Option<DateTime<Utc>>,
    /// Statistics timestamp
    pub computed_at: DateTime<Utc>,
}

/// Query audit logs
///
/// GET /api/v1/audit
pub async fn query_audit_logs(
    State(_state): State<AppState>,
    Query(params): Query<AuditQueryParams>,
) -> Result<impl IntoResponse, ApiError> {
    info!(
        entry_type = ?params.entry_type,
        actor_id = ?params.actor_id,
        payload_ref = ?params.payload_ref,
        limit = params.limit,
        "Querying audit logs"
    );

    // In a real implementation, this would query the AuditStore
    // For now, return a sample response
    let response = AuditQueryResponse {
        entries: vec![],
        total_count: 0,
        offset: params.offset,
        limit: params.limit,
        chain_verified: true,
        query_time_ms: 1,
    };

    Ok(Json(response))
}

/// Get audit logs for a specific payload
///
/// GET /api/v1/audit/payload/:payload_ref
pub async fn get_audit_for_payload(
    State(state): State<AppState>,
    Path(payload_ref): Path<String>,
    Query(params): Query<AuditQueryParams>,
) -> Result<impl IntoResponse, ApiError> {
    info!(payload_ref = %payload_ref, "Getting audit logs for payload");
    let start = Instant::now();

    // Get decrypt logs for this payload
    let decrypt_logs = state.audit_ledger
        .get_decrypt_logs_for_payload(&payload_ref, params.limit)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Get export logs for this payload
    let export_logs = state.audit_ledger
        .get_export_logs_for_payload(&payload_ref)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Convert decrypt logs
    let mut audit_entries: Vec<AuditEntryResponse> = decrypt_logs
        .iter()
        .map(|log| AuditEntryResponse {
            sequence: 0,
            entry_type: "decrypt".to_string(),
            timestamp: log.decrypted_at,
            actor_id: Some(log.decryptor.0.clone()),
            payload_ref: Some(log.target_payload_ref.clone()),
            ticket_ref: Some(log.ticket_ref.clone()),
            details: serde_json::json!({
                "outcome": format!("{:?}", log.outcome),
            }),
            entry_hash: log.log_id.clone(),
            prev_hash: None,
        })
        .collect();

    // Add export logs
    audit_entries.extend(export_logs.iter().map(|log| AuditEntryResponse {
        sequence: 0,
        entry_type: "export".to_string(),
        timestamp: log.exported_at,
        actor_id: Some(log.exporter.0.clone()),
        payload_ref: log.payload_refs.first().cloned(),
        ticket_ref: Some(log.ticket_ref.clone()),
        details: serde_json::json!({
            "export_target": log.export_target.clone(),
            "export_format": format!("{:?}", log.export_format),
        }),
        entry_hash: log.log_id.clone(),
        prev_hash: None,
    }));

    // Sort by timestamp descending
    audit_entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    // Apply pagination
    let total_count = audit_entries.len();
    let paginated: Vec<_> = audit_entries
        .into_iter()
        .skip(params.offset)
        .take(params.limit)
        .collect();

    let query_time_ms = start.elapsed().as_millis() as u64;

    let response = AuditQueryResponse {
        entries: paginated,
        total_count,
        offset: params.offset,
        limit: params.limit,
        chain_verified: false,
        query_time_ms,
    };

    Ok(Json(response))
}

/// Get audit logs for a specific actor
///
/// GET /api/v1/audit/actor/:actor_id
pub async fn get_audit_for_actor(
    State(state): State<AppState>,
    Path(actor_id): Path<String>,
    Query(params): Query<AuditQueryParams>,
) -> Result<impl IntoResponse, ApiError> {
    info!(actor_id = %actor_id, "Getting audit logs for actor");
    let start = Instant::now();

    let actor = ActorId::new(&actor_id);
    let from = params.from.unwrap_or_else(|| Utc::now() - chrono::Duration::days(30));
    let to = params.to.unwrap_or_else(Utc::now);

    // Get decrypt logs for this actor
    let decrypt_logs = state.audit_ledger
        .get_decrypt_logs_by_actor(&actor, from, to)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Get ticket logs for this actor
    let ticket_logs = state.audit_ledger
        .get_ticket_logs_by_actor(&actor, from, to)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Convert decrypt logs
    let mut audit_entries: Vec<AuditEntryResponse> = decrypt_logs
        .iter()
        .map(|log| AuditEntryResponse {
            sequence: 0,
            entry_type: "decrypt".to_string(),
            timestamp: log.decrypted_at,
            actor_id: Some(log.decryptor.0.clone()),
            payload_ref: Some(log.target_payload_ref.clone()),
            ticket_ref: Some(log.ticket_ref.clone()),
            details: serde_json::json!({
                "outcome": format!("{:?}", log.outcome),
            }),
            entry_hash: log.log_id.clone(),
            prev_hash: None,
        })
        .collect();

    // Add ticket logs
    audit_entries.extend(ticket_logs.iter().map(|log| AuditEntryResponse {
        sequence: 0,
        entry_type: format!("ticket_{:?}", log.operation).to_lowercase(),
        timestamp: log.timestamp,
        actor_id: Some(log.actor.0.clone()),
        payload_ref: log.target_resource_ref.clone(),
        ticket_ref: Some(log.ticket_id.clone()),
        details: serde_json::json!({
            "operation": format!("{:?}", log.operation),
            "outcome": format!("{:?}", log.outcome),
        }),
        entry_hash: log.log_id.clone(),
        prev_hash: None,
    }));

    // Sort by timestamp descending
    audit_entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    // Apply pagination
    let total_count = audit_entries.len();
    let paginated: Vec<_> = audit_entries
        .into_iter()
        .skip(params.offset)
        .take(params.limit)
        .collect();

    let query_time_ms = start.elapsed().as_millis() as u64;

    let response = AuditQueryResponse {
        entries: paginated,
        total_count,
        offset: params.offset,
        limit: params.limit,
        chain_verified: false,
        query_time_ms,
    };

    Ok(Json(response))
}

/// Get a specific audit entry by sequence
///
/// GET /api/v1/audit/entry/:sequence
pub async fn get_audit_entry(
    State(_state): State<AppState>,
    Path(sequence): Path<u64>,
) -> Result<Json<AuditEntryResponse>, ApiError> {
    info!(sequence = sequence, "Getting audit entry");

    // In a real implementation, this would look up the entry
    Err(ApiError::NotFound(format!(
        "Audit entry not found: {}",
        sequence
    )))
}

/// Verify audit chain integrity
///
/// POST /api/v1/audit/verify
pub async fn verify_audit_chain(
    State(_state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    info!("Verifying audit chain integrity");

    // In a real implementation, this would call audit_store.verify_chain()
    let response = ChainVerificationResponse {
        chain_id: "chain:pending".to_string(),
        verified: true,
        entries_checked: 0,
        verified_at: Utc::now(),
        error: None,
    };

    Ok(Json(response))
}

/// Get audit statistics
///
/// GET /api/v1/audit/stats
pub async fn get_audit_stats(
    State(_state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    info!("Getting audit statistics");

    let response = AuditStatsResponse {
        chain_id: "chain:pending".to_string(),
        total_entries: 0,
        decrypt_count: 0,
        export_count: 0,
        access_denied_count: 0,
        policy_violation_count: 0,
        chain_verified: true,
        oldest_entry: None,
        newest_entry: None,
        computed_at: Utc::now(),
    };

    Ok(Json(response))
}

/// Get decrypt audit logs
///
/// GET /api/v1/audit/decrypt
pub async fn get_decrypt_logs(
    State(state): State<AppState>,
    Query(params): Query<AuditQueryParams>,
) -> Result<impl IntoResponse, ApiError> {
    info!("Getting decrypt audit logs");
    let start = Instant::now();

    // Query based on available filters
    let entries = if let Some(ref payload_ref) = params.payload_ref {
        // Query by payload
        state.audit_ledger
            .get_decrypt_logs_for_payload(payload_ref, params.limit)
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?
    } else if let Some(ref actor_id) = params.actor_id {
        // Query by actor with time range
        let from = params.from.unwrap_or_else(|| Utc::now() - chrono::Duration::days(30));
        let to = params.to.unwrap_or_else(Utc::now);
        state.audit_ledger
            .get_decrypt_logs_by_actor(&ActorId::new(actor_id), from, to)
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?
    } else {
        // No filter - return empty for now (would need a list_all method)
        vec![]
    };

    // Convert to response format
    let audit_entries: Vec<AuditEntryResponse> = entries
        .iter()
        .enumerate()
        .map(|(idx, log)| AuditEntryResponse {
            sequence: idx as u64,
            entry_type: "decrypt".to_string(),
            timestamp: log.decrypted_at,
            actor_id: Some(log.decryptor.0.clone()),
            payload_ref: Some(log.target_payload_ref.clone()),
            ticket_ref: Some(log.ticket_ref.clone()),
            details: serde_json::json!({
                "outcome": format!("{:?}", log.outcome),
                "purpose_digest": log.purpose_digest.to_string(),
                "context_path": log.context_path.clone(),
            }),
            entry_hash: log.log_id.clone(),
            prev_hash: None,
        })
        .skip(params.offset)
        .take(params.limit)
        .collect();

    let total_count = entries.len();
    let query_time_ms = start.elapsed().as_millis() as u64;

    let response = AuditQueryResponse {
        entries: audit_entries,
        total_count,
        offset: params.offset,
        limit: params.limit,
        chain_verified: false, // Chain verification not implemented for decrypt logs
        query_time_ms,
    };

    Ok(Json(response))
}

/// Get export audit logs
///
/// GET /api/v1/audit/export
pub async fn get_export_logs(
    State(_state): State<AppState>,
    Query(params): Query<AuditQueryParams>,
) -> Result<impl IntoResponse, ApiError> {
    info!("Getting export audit logs");

    let response = AuditQueryResponse {
        entries: vec![],
        total_count: 0,
        offset: params.offset,
        limit: params.limit,
        chain_verified: true,
        query_time_ms: 1,
    };

    Ok(Json(response))
}

/// Export audit logs (for compliance)
///
/// POST /api/v1/audit/export
#[derive(Debug, Deserialize)]
pub struct ExportAuditRequest {
    /// Start time
    pub from: DateTime<Utc>,
    /// End time
    pub to: DateTime<Utc>,
    /// Export format (json, csv)
    #[serde(default = "default_format")]
    pub format: String,
    /// Include entry hashes for verification
    #[serde(default = "default_true")]
    pub include_hashes: bool,
}

fn default_format() -> String {
    "json".to_string()
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize)]
pub struct ExportAuditResponse {
    /// Export ID for retrieval
    pub export_id: String,
    /// Number of entries exported
    pub entry_count: usize,
    /// Export format
    pub format: String,
    /// Time range
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    /// Export timestamp
    pub exported_at: DateTime<Utc>,
    /// Download URL (if async)
    pub download_url: Option<String>,
}

pub async fn export_audit_logs(
    State(_state): State<AppState>,
    Json(request): Json<ExportAuditRequest>,
) -> Result<impl IntoResponse, ApiError> {
    info!(
        from = %request.from,
        to = %request.to,
        format = %request.format,
        "Exporting audit logs"
    );

    let response = ExportAuditResponse {
        export_id: format!("export:{}", uuid::Uuid::new_v4()),
        entry_count: 0,
        format: request.format,
        from: request.from,
        to: request.to,
        exported_at: Utc::now(),
        download_url: None,
    };

    Ok((StatusCode::ACCEPTED, Json(response)))
}

/// Build the audit router
pub fn audit_router() -> axum::Router<AppState> {
    use axum::routing::{get, post};

    axum::Router::new()
        .route("/", get(query_audit_logs))
        .route("/stats", get(get_audit_stats))
        .route("/verify", post(verify_audit_chain))
        .route("/export", post(export_audit_logs))
        .route("/decrypt", get(get_decrypt_logs))
        .route("/export-logs", get(get_export_logs))
        .route("/payload/:payload_ref", get(get_audit_for_payload))
        .route("/actor/:actor_id", get(get_audit_for_actor))
        .route("/entry/:sequence", get(get_audit_entry))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_query_params() {
        let json = r#"{"type": "decrypt", "actor_id": "actor:001", "limit": 50}"#;
        let params: AuditQueryParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.entry_type, Some("decrypt".to_string()));
        assert_eq!(params.actor_id, Some("actor:001".to_string()));
        assert_eq!(params.limit, 50);
    }

    #[test]
    fn test_default_limit() {
        let json = r#"{}"#;
        let params: AuditQueryParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.limit, 100);
    }
}
