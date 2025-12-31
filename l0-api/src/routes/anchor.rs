//! Chain Anchor Ledger endpoints
//!
//! Endpoints for managing chain anchoring operations.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use l0_core::ledger::{AnchorLedger, CreateAnchorRequest};
use l0_core::types::{AnchorChainType, AnchorStatus, Digest};

use crate::dto::ListQueryParams;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ============ DTOs ============

/// Create anchor request
#[derive(Debug, Deserialize)]
pub struct CreateAnchorRequestDto {
    /// Target chain
    pub chain_type: String,
    /// Epoch root to anchor
    pub epoch_root: String,
    /// Epoch sequence number
    pub epoch_sequence: u64,
    /// Epoch start timestamp
    pub epoch_start: DateTime<Utc>,
    /// Epoch end timestamp
    pub epoch_end: DateTime<Utc>,
    /// Number of batches in epoch
    pub batch_count: u64,
}

/// Anchor transaction response
#[derive(Debug, Serialize)]
pub struct AnchorResponse {
    pub anchor_id: String,
    pub chain_type: String,
    pub epoch_root: String,
    pub epoch_sequence: u64,
    pub epoch_start: DateTime<Utc>,
    pub epoch_end: DateTime<Utc>,
    pub batch_count: u64,
    pub status: String,
    pub tx_hash: Option<String>,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub confirmations: u32,
    pub required_confirmations: u32,
    pub gas_price: Option<String>,
    pub gas_used: Option<u64>,
    pub fee_paid: Option<String>,
    pub submitted_at: Option<DateTime<Utc>>,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Anchor verification response
#[derive(Debug, Serialize)]
pub struct AnchorVerificationResponse {
    pub valid: bool,
    pub chain_type: String,
    pub tx_hash: Option<String>,
    pub block_number: Option<u64>,
    pub confirmations: u32,
    pub epoch_root_matches: bool,
    pub proof_verified: bool,
    pub errors: Vec<String>,
    pub verified_at: DateTime<Utc>,
}

/// Anchor policy response
#[derive(Debug, Serialize)]
pub struct AnchorPolicyResponse {
    pub version: String,
    pub enabled_chains: Vec<String>,
    pub primary_chain: String,
    pub epoch_interval: u64,
    pub max_anchor_delay: u64,
    pub retry_count: u32,
    pub gas_strategy: String,
}

/// Update anchor policy request
#[derive(Debug, Deserialize)]
pub struct UpdateAnchorPolicyRequest {
    pub enabled_chains: Vec<String>,
    pub primary_chain: String,
    pub epoch_interval: u64,
    pub max_anchor_delay: u64,
    pub retry_count: u32,
    pub gas_strategy: String,
}

/// Update anchor status request
#[derive(Debug, Deserialize)]
pub struct UpdateAnchorStatusRequest {
    pub status: String,
    pub tx_hash: Option<String>,
    pub block_number: Option<u64>,
    pub confirmations: u32,
}

// ============ Endpoints ============

/// Create anchor transaction
pub async fn create_anchor(
    State(state): State<AppState>,
    Json(req): Json<CreateAnchorRequestDto>,
) -> ApiResult<Json<AnchorResponse>> {
    let epoch_root = Digest::from_hex(&req.epoch_root)
        .map_err(|_| ApiError::Validation("Invalid epoch root hex".to_string()))?;

    let chain_type = str_to_chain_type(&req.chain_type);

    let create_req = CreateAnchorRequest {
        chain_type,
        epoch_root,
        epoch_sequence: req.epoch_sequence,
        epoch_start: req.epoch_start,
        epoch_end: req.epoch_end,
        batch_count: req.batch_count,
        epoch_proof: None,
    };

    let anchor = state
        .anchor
        .create_anchor(create_req)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(anchor_to_response(&anchor)))
}

/// Get anchor by ID
pub async fn get_anchor(
    State(state): State<AppState>,
    Path(anchor_id): Path<String>,
) -> ApiResult<Json<AnchorResponse>> {
    let anchor = state
        .anchor
        .get_anchor(&anchor_id)
        .await
        .map_err(ApiError::Ledger)?
        .ok_or_else(|| ApiError::NotFound(format!("Anchor {} not found", anchor_id)))?;

    Ok(Json(anchor_to_response(&anchor)))
}

/// Get anchor by epoch sequence
pub async fn get_anchor_by_epoch(
    State(state): State<AppState>,
    Path((chain_type, epoch_sequence)): Path<(String, u64)>,
) -> ApiResult<Json<AnchorResponse>> {
    let chain = str_to_chain_type(&chain_type);

    let anchor = state
        .anchor
        .get_anchor_by_epoch(chain, epoch_sequence)
        .await
        .map_err(ApiError::Ledger)?
        .ok_or_else(|| {
            ApiError::NotFound(format!(
                "Anchor for epoch {} on {} not found",
                epoch_sequence, chain_type
            ))
        })?;

    Ok(Json(anchor_to_response(&anchor)))
}

/// Submit anchor transaction to chain
pub async fn submit_anchor(
    State(state): State<AppState>,
    Path(anchor_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let tx_hash = state
        .anchor
        .submit_anchor(&anchor_id)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(serde_json::json!({
        "success": true,
        "anchor_id": anchor_id,
        "tx_hash": tx_hash
    })))
}

/// Check anchor status on chain
pub async fn check_status(
    State(state): State<AppState>,
    Path(anchor_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let status = state
        .anchor
        .check_anchor_status(&anchor_id)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(serde_json::json!({
        "anchor_id": anchor_id,
        "status": status_to_str(&status)
    })))
}

/// Update anchor status
pub async fn update_status(
    State(state): State<AppState>,
    Path(anchor_id): Path<String>,
    Json(req): Json<UpdateAnchorStatusRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let status = str_to_status(&req.status);

    state
        .anchor
        .update_anchor_status(&anchor_id, status, req.tx_hash, req.block_number, req.confirmations)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(serde_json::json!({
        "success": true,
        "anchor_id": anchor_id,
        "status": req.status
    })))
}

/// Verify anchor on chain
pub async fn verify_anchor(
    State(state): State<AppState>,
    Path(anchor_id): Path<String>,
) -> ApiResult<Json<AnchorVerificationResponse>> {
    let verification = state
        .anchor
        .verify_anchor(&anchor_id)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(AnchorVerificationResponse {
        valid: verification.valid,
        chain_type: chain_type_to_str(&verification.chain_type).to_string(),
        tx_hash: verification.tx_hash,
        block_number: verification.block_number,
        confirmations: verification.confirmations,
        epoch_root_matches: verification.epoch_root_matches,
        proof_verified: verification.proof_verified,
        errors: verification.errors,
        verified_at: verification.verified_at,
    }))
}

/// Get pending anchors
pub async fn get_pending_anchors(
    State(state): State<AppState>,
    Query(params): Query<ChainTypeParams>,
) -> ApiResult<Json<Vec<AnchorResponse>>> {
    let chain_type = params.chain_type.as_ref().map(|s| str_to_chain_type(s));

    let anchors = state
        .anchor
        .get_pending_anchors(chain_type)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(anchors.iter().map(anchor_to_response).collect()))
}

/// Get finalized anchors
pub async fn get_finalized_anchors(
    State(state): State<AppState>,
    Path(chain_type): Path<String>,
    Query(params): Query<ListQueryParams>,
) -> ApiResult<Json<Vec<AnchorResponse>>> {
    let chain = str_to_chain_type(&chain_type);

    let anchors = state
        .anchor
        .get_finalized_anchors(chain, params.limit)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(anchors.iter().map(anchor_to_response).collect()))
}

/// Get anchor history for epoch range
pub async fn get_anchor_history(
    State(state): State<AppState>,
    Path(chain_type): Path<String>,
    Query(params): Query<EpochRangeParams>,
) -> ApiResult<Json<Vec<AnchorResponse>>> {
    let chain = str_to_chain_type(&chain_type);

    let anchors = state
        .anchor
        .get_anchor_history(chain, params.from_epoch, params.to_epoch)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(anchors.iter().map(anchor_to_response).collect()))
}

/// Get anchor policy
pub async fn get_policy(State(state): State<AppState>) -> ApiResult<Json<AnchorPolicyResponse>> {
    let policy = state.anchor.get_anchor_policy().await.map_err(ApiError::Ledger)?;

    Ok(Json(AnchorPolicyResponse {
        version: policy.version,
        enabled_chains: policy
            .enabled_chains
            .iter()
            .map(|c| chain_type_to_str(c).to_string())
            .collect(),
        primary_chain: chain_type_to_str(&policy.primary_chain).to_string(),
        epoch_interval: policy.epoch_interval,
        max_anchor_delay: policy.max_anchor_delay,
        retry_count: policy.retry_count,
        gas_strategy: gas_strategy_to_str(&policy.gas_strategy).to_string(),
    }))
}

/// Update anchor policy
pub async fn update_policy(
    State(state): State<AppState>,
    Json(req): Json<UpdateAnchorPolicyRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    use l0_core::types::{AnchorPolicy, GasStrategy};
    use std::collections::HashMap;

    let mut min_confirmations = HashMap::new();
    min_confirmations.insert("ethereum".to_string(), 12u32);
    min_confirmations.insert("bitcoin".to_string(), 6u32);
    min_confirmations.insert("polygon".to_string(), 256u32);
    min_confirmations.insert("solana".to_string(), 32u32);

    let policy = AnchorPolicy {
        version: "v1.0.0".to_string(),
        enabled_chains: req
            .enabled_chains
            .iter()
            .map(|s| str_to_chain_type(s))
            .collect(),
        primary_chain: str_to_chain_type(&req.primary_chain),
        epoch_interval: req.epoch_interval,
        max_anchor_delay: req.max_anchor_delay,
        retry_count: req.retry_count,
        gas_strategy: str_to_gas_strategy(&req.gas_strategy),
        min_confirmations,
    };

    state
        .anchor
        .update_anchor_policy(policy)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(serde_json::json!({
        "success": true
    })))
}

/// Retry failed anchor
pub async fn retry_anchor(
    State(state): State<AppState>,
    Path(anchor_id): Path<String>,
) -> ApiResult<Json<AnchorResponse>> {
    let anchor = state
        .anchor
        .retry_anchor(&anchor_id)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(anchor_to_response(&anchor)))
}

/// Get latest finalized epoch
pub async fn get_latest_finalized_epoch(
    State(state): State<AppState>,
    Path(chain_type): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let chain = str_to_chain_type(&chain_type);

    let epoch = state
        .anchor
        .get_latest_finalized_epoch(chain)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(serde_json::json!({
        "chain_type": chain_type,
        "latest_finalized_epoch": epoch
    })))
}

// ============ Query Params ============

#[derive(Debug, Deserialize)]
pub struct ChainTypeParams {
    pub chain_type: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EpochRangeParams {
    pub from_epoch: u64,
    pub to_epoch: u64,
}

// ============ Helpers ============

fn anchor_to_response(anchor: &l0_core::types::AnchorTransaction) -> AnchorResponse {
    AnchorResponse {
        anchor_id: anchor.anchor_id.clone(),
        chain_type: chain_type_to_str(&anchor.chain_type).to_string(),
        epoch_root: anchor.epoch_root.to_hex(),
        epoch_sequence: anchor.epoch_sequence,
        epoch_start: anchor.epoch_start,
        epoch_end: anchor.epoch_end,
        batch_count: anchor.batch_count,
        status: status_to_str(&anchor.status).to_string(),
        tx_hash: anchor.tx_hash.clone(),
        block_number: anchor.block_number,
        block_hash: anchor.block_hash.clone(),
        confirmations: anchor.confirmations,
        required_confirmations: anchor.required_confirmations,
        gas_price: anchor.gas_price.clone(),
        gas_used: anchor.gas_used,
        fee_paid: anchor.fee_paid.clone(),
        submitted_at: anchor.submitted_at,
        confirmed_at: anchor.confirmed_at,
        created_at: anchor.created_at,
    }
}

fn chain_type_to_str(chain_type: &AnchorChainType) -> &'static str {
    match chain_type {
        AnchorChainType::Ethereum => "ethereum",
        AnchorChainType::Bitcoin => "bitcoin",
        AnchorChainType::Polygon => "polygon",
        AnchorChainType::Solana => "solana",
        AnchorChainType::Internal => "internal",
    }
}

fn str_to_chain_type(s: &str) -> AnchorChainType {
    match s.to_lowercase().as_str() {
        "ethereum" => AnchorChainType::Ethereum,
        "bitcoin" => AnchorChainType::Bitcoin,
        "polygon" => AnchorChainType::Polygon,
        "solana" => AnchorChainType::Solana,
        _ => AnchorChainType::Internal,
    }
}

fn status_to_str(status: &AnchorStatus) -> &'static str {
    match status {
        AnchorStatus::Pending => "pending",
        AnchorStatus::Submitted => "submitted",
        AnchorStatus::Confirmed => "confirmed",
        AnchorStatus::Finalized => "finalized",
        AnchorStatus::Failed => "failed",
        AnchorStatus::Expired => "expired",
    }
}

fn str_to_status(s: &str) -> AnchorStatus {
    match s {
        "pending" => AnchorStatus::Pending,
        "submitted" => AnchorStatus::Submitted,
        "confirmed" => AnchorStatus::Confirmed,
        "finalized" => AnchorStatus::Finalized,
        "failed" => AnchorStatus::Failed,
        "expired" => AnchorStatus::Expired,
        _ => AnchorStatus::Pending,
    }
}

fn gas_strategy_to_str(strategy: &l0_core::types::GasStrategy) -> &'static str {
    use l0_core::types::GasStrategy;
    match strategy {
        GasStrategy::Standard => "standard",
        GasStrategy::Fast => "fast",
        GasStrategy::Slow => "slow",
        GasStrategy::Custom => "custom",
    }
}

fn str_to_gas_strategy(s: &str) -> l0_core::types::GasStrategy {
    use l0_core::types::GasStrategy;
    match s {
        "standard" => GasStrategy::Standard,
        "fast" => GasStrategy::Fast,
        "slow" => GasStrategy::Slow,
        "custom" => GasStrategy::Custom,
        _ => GasStrategy::Standard,
    }
}
