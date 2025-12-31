//! Receipt and Fee management endpoints

use axum::{
    extract::{Path, Query, State},
    Json,
};
use l0_core::ledger::{ChargeFeeRequest as CoreChargeFeeRequest, CreateReceiptRequest as CoreCreateReceiptRequest, QueryOptions, ReceiptLedger};
use l0_core::types::{ActorId, Digest, FeeReceiptStatus, FeeUnits, RootKind, ScopeType};

use crate::dto::{
    ChargeFeeRequest, CreateReceiptRequest, FeeReceiptResponse, ListQueryParams,
    PaginatedResponse, ReceiptResponse, RejectReceiptRequest, SubmitTipWitnessRequest,
    TipWitnessChainResponse, TipWitnessGapResponse, TipWitnessResponse, UpdateFeeStatusRequest,
    VerifyReceiptResponse,
};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Create a new L0 receipt
pub async fn create_receipt(
    State(state): State<AppState>,
    Json(req): Json<CreateReceiptRequest>,
) -> ApiResult<Json<ReceiptResponse>> {
    let scope_type = parse_scope_type(&req.scope_type)?;
    let root_kind = parse_root_kind(&req.root_kind)?;
    let root = Digest::from_hex(&req.root)
        .map_err(|_| ApiError::Validation("Invalid root digest hex".to_string()))?;

    let core_req = CoreCreateReceiptRequest {
        scope_type,
        root_kind,
        root,
        time_window_start: req.time_window_start,
        time_window_end: req.time_window_end,
        batch_sequence_no: req.batch_sequence_no,
        signer_set_version: req.signer_set_version,
        canonicalization_version: req.canonicalization_version,
        anchor_policy_version: req.anchor_policy_version,
        fee_schedule_version: req.fee_schedule_version,
        signed_snapshot_ref: req.signed_snapshot_ref,
    };

    let receipt = state
        .receipt
        .create_receipt(core_req, req.fee_receipt_id)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(receipt_to_response(&receipt)))
}

/// Get receipt by ID
pub async fn get_receipt(
    State(state): State<AppState>,
    Path(receipt_id): Path<String>,
) -> ApiResult<Json<ReceiptResponse>> {
    let receipt = state
        .receipt
        .get_receipt(&receipt_id)
        .await
        .map_err(ApiError::Ledger)?
        .ok_or_else(|| ApiError::NotFound(format!("Receipt {} not found", receipt_id)))?;

    Ok(Json(receipt_to_response(&receipt)))
}

/// Verify a receipt
pub async fn verify_receipt(
    State(state): State<AppState>,
    Path(receipt_id): Path<String>,
) -> ApiResult<Json<VerifyReceiptResponse>> {
    let result = state
        .receipt
        .verify_receipt(&receipt_id)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(VerifyReceiptResponse {
        valid: result.valid,
        evidence_level: format!("{:?}", result.evidence_level).to_lowercase(),
        chain_anchored: result.chain_anchored,
        errors: result.errors,
    }))
}

/// Reject a receipt
pub async fn reject_receipt(
    State(state): State<AppState>,
    Path(receipt_id): Path<String>,
    Json(req): Json<RejectReceiptRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let observer_digest = req
        .observer_reports_digest
        .map(|d| Digest::from_hex(&d))
        .transpose()
        .map_err(|_| ApiError::Validation("Invalid observer digest hex".to_string()))?;

    state
        .receipt
        .reject_receipt(&receipt_id, req.reason_code, observer_digest)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(serde_json::json!({ "status": "rejected" })))
}

/// List receipts
pub async fn list_receipts(
    State(state): State<AppState>,
    Query(params): Query<ListQueryParams>,
) -> ApiResult<Json<PaginatedResponse<ReceiptResponse>>> {
    let scope_type = params
        .scope_type
        .as_ref()
        .map(|s| parse_scope_type(s))
        .transpose()?;

    let options = QueryOptions {
        limit: Some(params.limit),
        offset: Some(params.offset),
        ..Default::default()
    };

    let receipts = state
        .receipt
        .list_receipts(scope_type, options)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(PaginatedResponse {
        total: receipts.len() as u64,
        items: receipts.iter().map(receipt_to_response).collect(),
        limit: params.limit,
        offset: params.offset,
    }))
}

/// Get receipts by batch sequence
pub async fn get_receipts_by_batch(
    State(state): State<AppState>,
    Path(batch_sequence): Path<u64>,
) -> ApiResult<Json<Vec<ReceiptResponse>>> {
    let receipts = state
        .receipt
        .get_receipts_by_batch(batch_sequence)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(receipts.iter().map(receipt_to_response).collect()))
}

// ============ Fee Receipt Endpoints ============

/// Charge a fee
pub async fn charge_fee(
    State(state): State<AppState>,
    Json(req): Json<ChargeFeeRequest>,
) -> ApiResult<Json<FeeReceiptResponse>> {
    let units = parse_fee_units(&req.units)?;
    let discount_digest = req
        .discount_digest
        .map(|d| Digest::from_hex(&d))
        .transpose()
        .map_err(|_| ApiError::Validation("Invalid discount digest".to_string()))?;
    let subsidy_digest = req
        .subsidy_digest
        .map(|d| Digest::from_hex(&d))
        .transpose()
        .map_err(|_| ApiError::Validation("Invalid subsidy digest".to_string()))?;

    let core_req = CoreChargeFeeRequest {
        payer_actor_id: ActorId(req.payer_actor_id),
        anchor_type: req.anchor_type,
        units,
        units_count: req.units_count,
        fee_schedule_version: req.fee_schedule_version,
        linked_anchor_id: req.linked_anchor_id,
        risk_multiplier: req.risk_multiplier,
        deposit_amount: req.deposit_amount,
        discount_digest,
        subsidy_digest,
    };

    let fee = state
        .receipt
        .charge_fee(core_req)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(fee_to_response(&fee)))
}

/// Get fee receipt by ID
pub async fn get_fee_receipt(
    State(state): State<AppState>,
    Path(fee_receipt_id): Path<String>,
) -> ApiResult<Json<FeeReceiptResponse>> {
    let fee = state
        .receipt
        .get_fee_receipt(&fee_receipt_id)
        .await
        .map_err(ApiError::Ledger)?
        .ok_or_else(|| ApiError::NotFound(format!("Fee receipt {} not found", fee_receipt_id)))?;

    Ok(Json(fee_to_response(&fee)))
}

/// Update fee status
pub async fn update_fee_status(
    State(state): State<AppState>,
    Path(fee_receipt_id): Path<String>,
    Json(req): Json<UpdateFeeStatusRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let status = parse_fee_status(&req.status)?;

    state
        .receipt
        .update_fee_status(&fee_receipt_id, status)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(serde_json::json!({ "status": "updated" })))
}

/// Get pending fees for an actor
pub async fn get_pending_fees(
    State(state): State<AppState>,
    Path(actor_id): Path<String>,
) -> ApiResult<Json<Vec<FeeReceiptResponse>>> {
    let fees = state
        .receipt
        .get_pending_fees(&ActorId(actor_id))
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(fees.iter().map(fee_to_response).collect()))
}

/// Get fee history for an actor
pub async fn get_fee_history(
    State(state): State<AppState>,
    Path(actor_id): Path<String>,
    Query(params): Query<ListQueryParams>,
) -> ApiResult<Json<PaginatedResponse<FeeReceiptResponse>>> {
    let options = QueryOptions {
        limit: Some(params.limit),
        offset: Some(params.offset),
        ..Default::default()
    };

    let fees = state
        .receipt
        .get_fee_history(&ActorId(actor_id), options)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(PaginatedResponse {
        total: fees.len() as u64,
        items: fees.iter().map(fee_to_response).collect(),
        limit: params.limit,
        offset: params.offset,
    }))
}

/// Refund a fee
pub async fn refund_fee(
    State(state): State<AppState>,
    Path(fee_receipt_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    state
        .receipt
        .refund_fee(&fee_receipt_id, None)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(serde_json::json!({ "status": "refunded" })))
}

// ============ TipWitness Endpoints ============

/// Submit a TipWitness
pub async fn submit_tip_witness(
    State(state): State<AppState>,
    Json(req): Json<SubmitTipWitnessRequest>,
) -> ApiResult<Json<TipWitnessResponse>> {
    let digest = Digest::from_hex(&req.local_tip_digest)
        .map_err(|_| ApiError::Validation("Invalid tip digest hex".to_string()))?;

    let result = state
        .tipwitness
        .submit_tip_witness(
            &ActorId(req.actor_id),
            digest,
            req.local_sequence_no,
            req.last_known_receipt_ref,
        )
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(TipWitnessResponse {
        tip_witness_id: result.tip_witness.tip_witness_id,
        actor_id: result.tip_witness.actor_id.0,
        local_tip_digest: result.tip_witness.local_tip_digest.to_hex(),
        local_sequence_no: result.tip_witness.local_sequence_no,
        last_known_receipt_ref: result.tip_witness.last_known_receipt_ref,
        witnessed_at: result.tip_witness.witnessed_at,
        receipt_id: result.tip_witness.receipt_id.map(|r| r.0),
    }))
}

/// Get latest TipWitness for an actor
pub async fn get_latest_tip_witness(
    State(state): State<AppState>,
    Path(actor_id): Path<String>,
) -> ApiResult<Json<TipWitnessResponse>> {
    let entity = state
        .tipwitness
        .get_latest_tip_witness(&ActorId(actor_id.clone()))
        .await
        .map_err(ApiError::Ledger)?
        .ok_or_else(|| ApiError::NotFound(format!("No TipWitness for actor {}", actor_id)))?;

    Ok(Json(TipWitnessResponse {
        tip_witness_id: entity.tip_witness_id,
        actor_id: entity.actor_id,
        local_tip_digest: entity.local_tip_digest,
        local_sequence_no: entity.local_sequence_no,
        last_known_receipt_ref: entity.last_known_receipt_ref,
        witnessed_at: entity.witnessed_at,
        receipt_id: entity.receipt_id,
    }))
}

/// Get TipWitness history for an actor
pub async fn get_tip_witness_history(
    State(state): State<AppState>,
    Path(actor_id): Path<String>,
    Query(params): Query<ListQueryParams>,
) -> ApiResult<Json<Vec<TipWitnessResponse>>> {
    let history = state
        .tipwitness
        .get_tip_witness_history(&ActorId(actor_id), params.limit)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(
        history
            .into_iter()
            .map(|tw| TipWitnessResponse {
                tip_witness_id: tw.tip_witness_id,
                actor_id: tw.actor_id.0,
                local_tip_digest: tw.local_tip_digest.to_hex(),
                local_sequence_no: tw.local_sequence_no,
                last_known_receipt_ref: tw.last_known_receipt_ref,
                witnessed_at: tw.witnessed_at,
                receipt_id: tw.receipt_id.map(|r| r.0),
            })
            .collect(),
    ))
}

/// Verify TipWitness chain for an actor
pub async fn verify_tip_witness_chain(
    State(state): State<AppState>,
    Path(actor_id): Path<String>,
) -> ApiResult<Json<TipWitnessChainResponse>> {
    let result = state
        .tipwitness
        .verify_tip_witness_chain(&ActorId(actor_id))
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(TipWitnessChainResponse {
        is_valid: result.is_valid,
        witness_count: result.witness_count,
        earliest_sequence: result.earliest_sequence,
        latest_sequence: result.latest_sequence,
        gaps: result
            .gaps
            .into_iter()
            .map(|g| TipWitnessGapResponse {
                from_sequence: g.from_sequence,
                to_sequence: g.to_sequence,
                gap_type: g.gap_type,
            })
            .collect(),
    }))
}

// ============ Helper Functions ============

fn receipt_to_response(receipt: &l0_core::types::L0Receipt) -> ReceiptResponse {
    ReceiptResponse {
        receipt_id: receipt.receipt_id.0.clone(),
        scope_type: format!("{:?}", receipt.scope_type).to_lowercase(),
        root_kind: format!("{:?}", receipt.root_kind).to_lowercase(),
        root: receipt.root.to_hex(),
        time_window_start: receipt.time_window_start,
        time_window_end: receipt.time_window_end,
        batch_sequence_no: receipt.batch_sequence_no,
        signer_set_version: receipt.signer_set_version.clone(),
        created_at: receipt.created_at,
        rejected: receipt.rejected,
        reject_reason_code: receipt.reject_reason_code.clone(),
    }
}

fn fee_to_response(fee: &l0_core::types::FeeReceipt) -> FeeReceiptResponse {
    FeeReceiptResponse {
        fee_receipt_id: fee.fee_receipt_id.clone(),
        fee_schedule_version: fee.fee_schedule_version.clone(),
        payer_actor_id: fee.payer_actor_id.clone(),
        anchor_type: fee.anchor_type.clone(),
        units: format!("{:?}", fee.units).to_lowercase(),
        units_count: fee.units_count,
        amount: fee.amount.clone(),
        status: format!("{:?}", fee.status).to_lowercase(),
        timestamp: fee.timestamp,
        linked_receipt_id: fee.linked_receipt_id.clone(),
    }
}

fn parse_scope_type(s: &str) -> Result<ScopeType, ApiError> {
    match s {
        "akn_batch" => Ok(ScopeType::AknBatch),
        "consent_batch" => Ok(ScopeType::ConsentBatch),
        "verdict_batch" => Ok(ScopeType::VerdictBatch),
        "dispute_batch" => Ok(ScopeType::DisputeBatch),
        "repair_batch" => Ok(ScopeType::RepairBatch),
        "clawback_batch" => Ok(ScopeType::ClawbackBatch),
        "log_batch" => Ok(ScopeType::LogBatch),
        "trace_batch" => Ok(ScopeType::TraceBatch),
        "backfill_batch" => Ok(ScopeType::BackfillBatch),
        "identity_batch" => Ok(ScopeType::IdentityBatch),
        "covenant_status_batch" => Ok(ScopeType::CovenantStatusBatch),
        _ => Err(ApiError::Validation(format!("Invalid scope type: {}", s))),
    }
}

fn parse_root_kind(s: &str) -> Result<RootKind, ApiError> {
    match s {
        "batch_root" => Ok(RootKind::BatchRoot),
        "epoch_root" => Ok(RootKind::EpochRoot),
        _ => Err(ApiError::Validation(format!("Invalid root kind: {}", s))),
    }
}

fn parse_fee_units(s: &str) -> Result<FeeUnits, ApiError> {
    match s {
        "batch_root" => Ok(FeeUnits::BatchRoot),
        "entry_count" => Ok(FeeUnits::EntryCount),
        "size_tier" => Ok(FeeUnits::SizeTier),
        _ => Err(ApiError::Validation(format!("Invalid fee units: {}", s))),
    }
}

fn parse_fee_status(s: &str) -> Result<FeeReceiptStatus, ApiError> {
    match s {
        "charged_pending_receipt" => Ok(FeeReceiptStatus::ChargedPendingReceipt),
        "charged" => Ok(FeeReceiptStatus::Charged),
        "refunded" => Ok(FeeReceiptStatus::Refunded),
        "forfeited" => Ok(FeeReceiptStatus::Forfeited),
        "charged_no_receipt" => Ok(FeeReceiptStatus::ChargedNoReceipt),
        _ => Err(ApiError::Validation(format!("Invalid fee status: {}", s))),
    }
}
