//! API Handlers
//!
//! HTTP handler implementations for P3 API endpoints.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use p3_core::{EpochId, OperationType, P3Digest};
use std::sync::Arc;

use crate::dto::*;
use crate::error::{ApiError, ApiResult};
use crate::state::{AppState, ComponentHealthCheck, HealthStatus};

/// Health check handler
pub async fn health_check(State(state): State<Arc<AppState>>) -> ApiResult<Json<HealthResponse>> {
    let mut components = vec![];

    // Check executor
    let _executor_stats = state.executor.stats().await;
    components.push(ComponentHealthCheck::healthy("executor"));

    // Check verifier (always healthy if initialized)
    components.push(ComponentHealthCheck::healthy("verifier"));

    // Check database if available
    if state.database.is_some() {
        components.push(ComponentHealthCheck::healthy("database"));
    }

    let overall_status = if components.iter().all(|c| c.status == HealthStatus::Healthy) {
        "healthy"
    } else if components.iter().any(|c| c.status == HealthStatus::Unhealthy) {
        "unhealthy"
    } else {
        "degraded"
    };

    Ok(Json(HealthResponse {
        status: overall_status.to_string(),
        version: state.config.version.clone(),
        uptime_secs: state.uptime_secs(),
        components: components
            .into_iter()
            .map(|c| ComponentHealth {
                name: c.name,
                status: c.status.as_str().to_string(),
                message: c.message,
            })
            .collect(),
    }))
}

/// Get executor statistics
pub async fn get_stats(State(state): State<Arc<AppState>>) -> ApiResult<Json<ExecutorStatsDto>> {
    let stats = state.executor.stats().await;

    Ok(Json(ExecutorStatsDto {
        active_executions: stats.active_executions,
        active_attempt_chains: stats.active_attempt_chains,
        proofs_generated: stats.proofs_generated,
        active_batches: stats.active_batches,
    }))
}

/// Execute an operation
pub async fn execute_operation(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ExecuteOperationRequest>,
) -> ApiResult<Json<ExecuteOperationResponse>> {
    state.increment_requests().await;

    // Parse operation type
    let operation_type = parse_operation_type(&request.operation_type)?;

    // Parse target digest
    let target_digest = P3Digest::from_hex(&request.target_digest)
        .map_err(|_| ApiError::validation("Invalid target digest"))?;

    // Create execution context
    let epoch_id = EpochId::new(&request.epoch_id);
    let mut context =
        p3_executor::ExecutionContext::new(epoch_id, &request.initiator_ref);

    if let Some(executor_ref) = &request.executor_ref {
        context = context.with_executor(executor_ref);
    }

    // Execute operation
    let result = state
        .executor
        .execute_operation(operation_type, target_digest, request.amount, context)
        .await?;

    // Build proof reference if available
    let proof_ref = result.proof.map(|p| ProofRefDto {
        proof_id: p.proof_id,
        proof_type: format!("{:?}", p.proof_type),
        executor_ref: p.executor_ref,
        executed_at: p.executed_at,
        proof_digest: p.proof_digest.to_hex(),
    });

    Ok(Json(ExecuteOperationResponse {
        execution_id: result.execution_id,
        status: format!("{:?}", result.status),
        resolution_type: "Automatic".to_string(),
        result_digest: result.result_digest.map(|d| d.to_hex()),
        proof_ref,
        completed_at: chrono::Utc::now(),
    }))
}

/// Verify data
pub async fn verify(
    State(state): State<Arc<AppState>>,
    Json(request): Json<VerificationRequest>,
) -> ApiResult<Json<VerificationResponse>> {
    state.increment_requests().await;

    // Decode data
    let data = hex::decode(&request.data)
        .map_err(|_| ApiError::validation("Invalid hex data"))?;

    // Compute digest
    let computed_digest = P3Digest::blake3(&data);

    // Check against expected if provided
    let valid = if let Some(expected) = &request.expected_digest {
        let expected_digest = P3Digest::from_hex(expected)
            .map_err(|_| ApiError::validation("Invalid expected digest"))?;
        computed_digest == expected_digest
    } else {
        true
    };

    Ok(Json(VerificationResponse {
        valid,
        digest: computed_digest.to_hex(),
        details: None,
    }))
}

// ============================================
// Provider Handlers
// ============================================

/// List providers
pub async fn list_providers(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<PaginatedResponse<ProviderDto>>> {
    state.increment_requests().await;

    // For now, return empty list since we don't have database access in basic setup
    Ok(Json(PaginatedResponse {
        items: vec![],
        total: 0,
        page: query.page,
        page_size: query.page_size,
        has_more: false,
    }))
}

/// Get provider by ID
pub async fn get_provider(
    State(state): State<Arc<AppState>>,
    Path(provider_id): Path<String>,
) -> ApiResult<Json<ProviderDto>> {
    state.increment_requests().await;

    // Would fetch from database
    Err(ApiError::not_found("Provider", provider_id))
}

// ============================================
// Clearing Handlers
// ============================================

/// List clearing batches
pub async fn list_clearing_batches(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<PaginatedResponse<ClearingBatchDto>>> {
    state.increment_requests().await;

    Ok(Json(PaginatedResponse {
        items: vec![],
        total: 0,
        page: query.page,
        page_size: query.page_size,
        has_more: false,
    }))
}

/// Get clearing batch by ID
pub async fn get_clearing_batch(
    State(state): State<Arc<AppState>>,
    Path(batch_id): Path<String>,
) -> ApiResult<Json<ClearingBatchDto>> {
    state.increment_requests().await;

    Err(ApiError::not_found("ClearingBatch", batch_id))
}

// ============================================
// Treasury Handlers
// ============================================

/// List treasury pools
pub async fn list_treasury_pools(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<PaginatedResponse<TreasuryPoolDto>>> {
    state.increment_requests().await;

    Ok(Json(PaginatedResponse {
        items: vec![],
        total: 0,
        page: query.page,
        page_size: query.page_size,
        has_more: false,
    }))
}

/// Get treasury pool by ID
pub async fn get_treasury_pool(
    State(state): State<Arc<AppState>>,
    Path(pool_id): Path<String>,
) -> ApiResult<Json<TreasuryPoolDto>> {
    state.increment_requests().await;

    Err(ApiError::not_found("TreasuryPool", pool_id))
}

// ============================================
// Proof Batch Handlers
// ============================================

/// Create proof batch
pub async fn create_proof_batch(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CreateClearingBatchRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    state.increment_requests().await;

    let epoch_id = EpochId::new(&request.epoch_id);
    let batch_id = format!(
        "batch:{}:{}",
        request.epoch_id,
        chrono::Utc::now().timestamp_millis()
    );

    state
        .executor
        .create_proof_batch(&batch_id, epoch_id)
        .await?;

    Ok(Json(serde_json::json!({
        "batch_id": batch_id,
        "status": "created"
    })))
}

/// Seal proof batch
pub async fn seal_proof_batch(
    State(state): State<Arc<AppState>>,
    Path(batch_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    state.increment_requests().await;

    let batch = state.executor.seal_proof_batch(&batch_id).await?;

    Ok(Json(serde_json::json!({
        "batch_id": batch.batch_id,
        "proof_count": batch.len(),
        "batch_digest": batch.batch_digest.to_hex(),
        "is_sealed": batch.is_sealed()
    })))
}

// ============================================
// Disclosure Handlers
// ============================================

/// Create a viewer context (authorization)
pub async fn create_viewer_context(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CreateViewerContextRequest>,
) -> ApiResult<Json<ViewerContextDto>> {
    state.increment_requests().await;

    // Parse viewer ID
    let viewer_id = P3Digest::from_hex(&request.viewer_id)
        .map_err(|_| ApiError::validation("Invalid viewer_id digest"))?;

    // Build query scope
    let operations: Vec<p3_core::types::disclosure::QueryOperation> = request
        .operations
        .iter()
        .filter_map(|op| parse_query_operation(op).ok())
        .collect();

    let mut query_scope = p3_core::types::disclosure::QueryScope::new()
        .with_operations(if operations.is_empty() {
            vec![
                p3_core::types::disclosure::QueryOperation::List,
                p3_core::types::disclosure::QueryOperation::Lookup,
            ]
        } else {
            operations
        });

    if let Some(limit) = request.result_limit {
        query_scope = query_scope.with_result_limit(limit);
    }

    // Build epoch range if provided
    if request.epoch_start.is_some() || request.epoch_end.is_some() {
        let epoch_range = p3_core::types::disclosure::EpochRange {
            start: request.epoch_start.map(EpochId::new),
            end: request.epoch_end.map(EpochId::new),
            max_count: None,
        };
        query_scope = query_scope.with_epoch_range(epoch_range);
    }

    // Create viewer context
    let (viewer_context, disclosure_level, org_scope_dto) = if let Some(org_id_hex) = &request.org_id {
        // Org-level access
        let org_id = P3Digest::from_hex(org_id_hex)
            .map_err(|_| ApiError::validation("Invalid org_id digest"))?;

        let org_scope = p3_core::types::disclosure::OrgScope::new(org_id)
            .with_actor_types(request.actor_types.clone())
            .with_max_depth(2);

        let org_scope_dto = OrgScopeDto {
            org_id: org_id_hex.clone(),
            actor_types: request.actor_types.clone(),
            max_depth: 2,
        };

        let ctx = p3_core::types::disclosure::ViewerContext::org(
            viewer_id,
            org_scope,
            query_scope,
            request.ttl_seconds,
        );

        (ctx, "org", Some(org_scope_dto))
    } else {
        // Private access
        let ctx = p3_core::types::disclosure::ViewerContext::new(
            viewer_id,
            query_scope,
            request.ttl_seconds,
        );

        (ctx, "private", None)
    };

    // Generate context ID
    let context_id = format!("ctx:{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0));
    let expires_at = viewer_context.created_at + chrono::Duration::seconds(request.ttl_seconds);

    // Store context in state (in production, would use database)
    state.store_viewer_context(&context_id, viewer_context.clone()).await;

    Ok(Json(ViewerContextDto {
        context_id,
        viewer_id: request.viewer_id,
        disclosure_level: disclosure_level.to_string(),
        operations: request.operations.clone(),
        created_at: viewer_context.created_at,
        expires_at,
        org_scope: org_scope_dto,
    }))
}

/// Get public aggregated statistics (disclosure: public)
pub async fn get_public_stats(
    State(state): State<Arc<AppState>>,
) -> ApiResult<Json<PublicAggregatedStatsDto>> {
    state.increment_requests().await;

    // Return aggregated stats (no individual detail enumeration)
    let stats = state.executor.stats().await;

    Ok(Json(PublicAggregatedStatsDto {
        total_epochs: 0, // Would query from database
        total_operations: stats.proofs_generated,
        total_volume: rust_decimal::Decimal::ZERO, // Would aggregate from database
        active_providers: 0, // Would query from database
        last_updated: chrono::Utc::now(),
    }))
}

/// Query with disclosure level
pub async fn disclosure_query(
    State(state): State<Arc<AppState>>,
    Json(request): Json<DisclosureQueryRequest>,
) -> ApiResult<Json<DisclosureQueryResponse<serde_json::Value>>> {
    state.increment_requests().await;
    let start_time = std::time::Instant::now();

    // Retrieve viewer context
    let viewer_context = state.get_viewer_context(&request.context_id).await
        .ok_or_else(|| ApiError::unauthorized("Invalid or expired context"))?;

    // Check if context is expired
    if viewer_context.is_expired(&chrono::Utc::now()) {
        return Err(ApiError::unauthorized("Context has expired"));
    }

    // Parse and validate operation
    let operation = parse_query_operation(&request.operation)?;
    if !viewer_context.query_scope.allows(&operation) {
        return Err(ApiError::forbidden("Operation not allowed in this context"));
    }

    let disclosure_level = viewer_context.disclosure_level();

    // Execute query based on resource type and operation
    let (data, result_count) = match request.resource_type.as_str() {
        "epochs" => {
            // Would query epochs from database
            (serde_json::json!({ "items": [], "total": 0 }), 0)
        }
        "providers" => {
            (serde_json::json!({ "items": [], "total": 0 }), 0)
        }
        "distributions" => {
            (serde_json::json!({ "items": [], "total": 0 }), 0)
        }
        _ => {
            return Err(ApiError::validation(format!("Unknown resource type: {}", request.resource_type)));
        }
    };

    // Create audit record for org-level queries
    let audit_digest = if disclosure_level.requires_audit() {
        let viewer_context_bytes = serde_json::to_vec(&viewer_context).unwrap_or_default();
        let query_params_bytes = serde_json::to_vec(&request).unwrap_or_default();
        let result_bytes = serde_json::to_vec(&data).unwrap_or_default();

        let audit_record = p3_core::types::disclosure::QueryAuditRecord::new(
            P3Digest::blake3(&viewer_context_bytes),
            P3Digest::blake3(&query_params_bytes),
            P3Digest::blake3(&result_bytes),
            result_count,
            disclosure_level.clone(),
        ).with_duration(start_time.elapsed().as_millis() as u64);

        // Store audit record (in production, would persist to database)
        state.store_audit_record(audit_record.clone()).await;

        Some(audit_record.audit_digest().as_digest().to_hex())
    } else {
        None
    };

    Ok(Json(DisclosureQueryResponse {
        data,
        audit_digest,
        disclosure_level: disclosure_level.name().to_string(),
        result_count,
    }))
}

/// List query audit records
pub async fn list_audit_records(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<PaginatedResponse<QueryAuditRecordDto>>> {
    state.increment_requests().await;

    // Would query audit records from database
    // For now, return empty list
    Ok(Json(PaginatedResponse {
        items: vec![],
        total: 0,
        page: query.page,
        page_size: query.page_size,
        has_more: false,
    }))
}

/// Create export ticket
pub async fn create_export_ticket(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CreateExportTicketRequest>,
) -> ApiResult<Json<ExportTicketDto>> {
    state.increment_requests().await;

    // Verify viewer context
    let viewer_context = state.get_viewer_context(&request.context_id).await
        .ok_or_else(|| ApiError::unauthorized("Invalid or expired context"))?;

    if viewer_context.is_expired(&chrono::Utc::now()) {
        return Err(ApiError::unauthorized("Context has expired"));
    }

    // Check if export operation is allowed
    if !viewer_context.query_scope.allows(&p3_core::types::disclosure::QueryOperation::Export) {
        return Err(ApiError::forbidden("Export operation not allowed in this context"));
    }

    // Parse data types
    let data_types: Vec<p3_core::types::disclosure::ExportDataType> = request
        .data_types
        .iter()
        .filter_map(|dt| parse_export_data_type(dt).ok())
        .collect();

    if data_types.is_empty() {
        return Err(ApiError::validation("No valid data types specified"));
    }

    // Parse export format
    let format = parse_export_format(&request.format)?;

    // Check DSN availability (simplified - would check actual DSN status)
    let dsn_available = true;

    // Validate plaintext export
    if request.include_plaintext && !dsn_available {
        return Err(ApiError::validation("Plaintext export not available during DSN_DOWN"));
    }

    // Create export scope
    let mut export_scope = p3_core::types::disclosure::ExportScope::new(data_types.clone())
        .with_format(format.clone())
        .with_plaintext(request.include_plaintext);

    if request.epoch_start.is_some() || request.epoch_end.is_some() {
        export_scope = export_scope.with_epoch_range(p3_core::types::disclosure::EpochRange {
            start: request.epoch_start.map(EpochId::new),
            end: request.epoch_end.map(EpochId::new),
            max_count: None,
        });
    }

    // Create export ticket
    let viewer_context_bytes = serde_json::to_vec(&viewer_context).unwrap_or_default();
    let ticket = p3_core::types::disclosure::ExportTicket::new(
        P3Digest::blake3(&viewer_context_bytes),
        export_scope,
        request.ttl_seconds,
        dsn_available,
    );

    let ticket_id = ticket.ticket_id.as_str().to_string();

    // Store ticket (in production, would persist to database)
    state.store_export_ticket(ticket.clone()).await;

    Ok(Json(ExportTicketDto {
        ticket_id,
        status: format!("{:?}", ticket.status),
        data_types: request.data_types.clone(),
        format: request.format.clone(),
        created_at: ticket.created_at,
        expires_at: ticket.expires_at,
        plaintext_allowed: ticket.allows_plaintext_export(),
        audit_digest: ticket.audit_digest.map(|d| d.as_digest().to_hex()),
    }))
}

/// Get export ticket status
pub async fn get_export_ticket(
    State(state): State<Arc<AppState>>,
    Path(ticket_id): Path<String>,
) -> ApiResult<Json<ExportTicketDto>> {
    state.increment_requests().await;

    let ticket = state.get_export_ticket(&ticket_id).await
        .ok_or_else(|| ApiError::not_found("ExportTicket", &ticket_id))?;

    Ok(Json(ExportTicketDto {
        ticket_id: ticket.ticket_id.as_str().to_string(),
        status: format!("{:?}", ticket.status),
        data_types: ticket.export_scope.data_types.iter().map(|dt| format!("{:?}", dt)).collect(),
        format: format!("{:?}", ticket.export_scope.format),
        created_at: ticket.created_at,
        expires_at: ticket.expires_at,
        plaintext_allowed: ticket.allows_plaintext_export(),
        audit_digest: ticket.audit_digest.map(|d| d.as_digest().to_hex()),
    }))
}

/// Check provider conformance level
pub async fn check_provider_conformance(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ConformanceCheckRequest>,
) -> ApiResult<Json<ConformanceCheckResponse>> {
    state.increment_requests().await;

    // Parse target level
    let target_level = parse_conformance_level(&request.target_level)?;

    // Get required materials for target level
    let requirements = p3_core::types::disclosure::ProviderMaterialRequirements::for_level(&target_level);

    // Check submitted materials
    let submitted_names: std::collections::HashSet<_> = request.materials.iter().map(|m| m.name.clone()).collect();
    let required_names: std::collections::HashSet<_> = requirements.required_materials.iter().map(|m| m.name.clone()).collect();

    let missing: Vec<_> = required_names.difference(&submitted_names).cloned().collect();

    let passed = missing.is_empty();
    let achieved_level = if passed {
        target_level.name().to_string()
    } else {
        // Determine what level was actually achieved
        match target_level {
            p3_core::types::disclosure::ConformanceLevel::L3 => {
                // Check if L2 materials are present
                let l2_reqs = p3_core::types::disclosure::ProviderMaterialRequirements::l2();
                let l2_names: std::collections::HashSet<_> = l2_reqs.required_materials.iter().map(|m| m.name.clone()).collect();
                if l2_names.is_subset(&submitted_names) {
                    "L2".to_string()
                } else {
                    "L1".to_string()
                }
            }
            p3_core::types::disclosure::ConformanceLevel::L2 => "L1".to_string(),
            p3_core::types::disclosure::ConformanceLevel::L1 => "None".to_string(),
        }
    };

    // Generate check digest
    let check_data = serde_json::to_vec(&request).unwrap_or_default();
    let check_digest = P3Digest::blake3(&check_data);

    Ok(Json(ConformanceCheckResponse {
        provider_id: request.provider_id,
        passed,
        achieved_level,
        checked_at: chrono::Utc::now(),
        check_digest: check_digest.to_hex(),
        missing_materials: if passed { None } else { Some(missing) },
    }))
}

/// Get provider conformance details
pub async fn get_provider_conformance(
    State(state): State<Arc<AppState>>,
    Path(provider_id): Path<String>,
) -> ApiResult<Json<ProviderConformanceDto>> {
    state.increment_requests().await;

    // Would fetch from database
    Err(ApiError::not_found("Provider", provider_id))
}

// ============================================
// Helper Functions
// ============================================

/// Parse query operation from string
fn parse_query_operation(s: &str) -> ApiResult<p3_core::types::disclosure::QueryOperation> {
    match s.to_lowercase().as_str() {
        "list" => Ok(p3_core::types::disclosure::QueryOperation::List),
        "lookup" => Ok(p3_core::types::disclosure::QueryOperation::Lookup),
        "explain" => Ok(p3_core::types::disclosure::QueryOperation::Explain),
        "export" => Ok(p3_core::types::disclosure::QueryOperation::Export),
        "aggregate" => Ok(p3_core::types::disclosure::QueryOperation::Aggregate),
        _ => Err(ApiError::validation(format!("Unknown query operation: {}", s))),
    }
}

/// Parse export data type from string
fn parse_export_data_type(s: &str) -> ApiResult<p3_core::types::disclosure::ExportDataType> {
    match s.to_lowercase().as_str() {
        "epoch_summary" | "epochsummary" => Ok(p3_core::types::disclosure::ExportDataType::EpochSummary),
        "points" => Ok(p3_core::types::disclosure::ExportDataType::Points),
        "attribution" => Ok(p3_core::types::disclosure::ExportDataType::Attribution),
        "distribution" => Ok(p3_core::types::disclosure::ExportDataType::Distribution),
        "clearing" => Ok(p3_core::types::disclosure::ExportDataType::Clearing),
        "audit_logs" | "auditlogs" => Ok(p3_core::types::disclosure::ExportDataType::AuditLogs),
        _ => Err(ApiError::validation(format!("Unknown export data type: {}", s))),
    }
}

/// Parse export format from string
fn parse_export_format(s: &str) -> ApiResult<p3_core::types::disclosure::ExportFormat> {
    match s.to_lowercase().as_str() {
        "json" => Ok(p3_core::types::disclosure::ExportFormat::Json),
        "csv" => Ok(p3_core::types::disclosure::ExportFormat::Csv),
        "parquet" => Ok(p3_core::types::disclosure::ExportFormat::Parquet),
        _ => Err(ApiError::validation(format!("Unknown export format: {}", s))),
    }
}

/// Parse conformance level from string
fn parse_conformance_level(s: &str) -> ApiResult<p3_core::types::disclosure::ConformanceLevel> {
    match s.to_uppercase().as_str() {
        "L1" => Ok(p3_core::types::disclosure::ConformanceLevel::L1),
        "L2" => Ok(p3_core::types::disclosure::ConformanceLevel::L2),
        "L3" => Ok(p3_core::types::disclosure::ConformanceLevel::L3),
        _ => Err(ApiError::validation(format!("Unknown conformance level: {}", s))),
    }
}

/// Parse operation type from string
fn parse_operation_type(s: &str) -> ApiResult<OperationType> {
    match s.to_lowercase().as_str() {
        "pointscalculation" | "points_calculation" | "points" => {
            Ok(OperationType::PointsCalculation)
        }
        "attribution" => Ok(OperationType::Attribution),
        "distribution" => Ok(OperationType::Distribution),
        "clawback" => Ok(OperationType::Clawback),
        "depositoperation" | "deposit_operation" | "deposit" => {
            Ok(OperationType::DepositOperation)
        }
        "fine" => Ok(OperationType::Fine),
        "subsidy" => Ok(OperationType::Subsidy),
        "budgetspend" | "budget_spend" | "budget" => Ok(OperationType::BudgetSpend),
        _ => Err(ApiError::validation(format!("Unknown operation type: {}", s))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_operation_type() {
        assert_eq!(
            parse_operation_type("distribution").unwrap(),
            OperationType::Distribution
        );
        assert_eq!(
            parse_operation_type("CLAWBACK").unwrap(),
            OperationType::Clawback
        );
        assert_eq!(
            parse_operation_type("Fine").unwrap(),
            OperationType::Fine
        );
        assert_eq!(
            parse_operation_type("points_calculation").unwrap(),
            OperationType::PointsCalculation
        );
        assert_eq!(
            parse_operation_type("deposit").unwrap(),
            OperationType::DepositOperation
        );

        assert!(parse_operation_type("invalid").is_err());
    }

    #[test]
    fn test_parse_operation_type_case_insensitive() {
        assert_eq!(
            parse_operation_type("DiStRiBuTiOn").unwrap(),
            OperationType::Distribution
        );
    }
}
