//! Actor management endpoints

use axum::{
    extract::{Path, State},
    Json,
};
use l0_core::ledger::IdentityLedger;
use l0_core::types::{ActorId, ActorStatus, ActorType, Digest};

use crate::dto::{ActorResponse, RegisterActorRequest, UpdateActorStatusRequest};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Register a new actor
pub async fn register_actor(
    State(state): State<AppState>,
    Json(req): Json<RegisterActorRequest>,
) -> ApiResult<Json<ActorResponse>> {
    // Parse actor type
    let actor_type = parse_actor_type(&req.actor_type)?;

    // Register the actor
    let record = state
        .identity
        .register_actor(actor_type, req.public_key, req.node_actor_id)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(actor_to_response(&record)))
}

/// Get actor by ID
pub async fn get_actor(
    State(state): State<AppState>,
    Path(actor_id): Path<String>,
) -> ApiResult<Json<ActorResponse>> {
    let actor = state
        .identity
        .get_actor(&ActorId(actor_id.clone()))
        .await
        .map_err(ApiError::Ledger)?
        .ok_or_else(|| ApiError::NotFound(format!("Actor {} not found", actor_id)))?;

    Ok(Json(actor_to_response(&actor)))
}

/// Get actor by public key
pub async fn get_actor_by_pubkey(
    State(state): State<AppState>,
    Path(pubkey): Path<String>,
) -> ApiResult<Json<ActorResponse>> {
    let actor = state
        .identity
        .get_actor_by_pubkey(&pubkey)
        .await
        .map_err(ApiError::Ledger)?
        .ok_or_else(|| ApiError::NotFound(format!("Actor with pubkey {} not found", pubkey)))?;

    Ok(Json(actor_to_response(&actor)))
}

/// Update actor status
pub async fn update_status(
    State(state): State<AppState>,
    Path(actor_id): Path<String>,
    Json(req): Json<UpdateActorStatusRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let new_status = parse_actor_status(&req.status)?;

    let reason_digest = req
        .reason_digest
        .as_ref()
        .map(|d| Digest::from_hex(d))
        .transpose()
        .map_err(|_| ApiError::Validation("Invalid reason digest hex".to_string()))?;

    let receipt_id = state
        .identity
        .update_status(&ActorId(actor_id), new_status, reason_digest)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(serde_json::json!({
        "receipt_id": receipt_id.0,
        "status": req.status
    })))
}

// Helper functions

fn parse_actor_type(s: &str) -> ApiResult<ActorType> {
    match s {
        "human_actor" => Ok(ActorType::HumanActor),
        "ai_actor" => Ok(ActorType::AiActor),
        "node_actor" => Ok(ActorType::NodeActor),
        "group_actor" => Ok(ActorType::GroupActor),
        _ => Err(ApiError::Validation(format!("Invalid actor type: {}", s))),
    }
}

fn parse_actor_status(s: &str) -> ApiResult<ActorStatus> {
    match s {
        "active" => Ok(ActorStatus::Active),
        "suspended" => Ok(ActorStatus::Suspended),
        "in_repair" => Ok(ActorStatus::InRepair),
        "terminated" => Ok(ActorStatus::Terminated),
        _ => Err(ApiError::Validation(format!("Invalid actor status: {}", s))),
    }
}

fn actor_to_response(record: &l0_core::types::ActorRecord) -> ActorResponse {
    ActorResponse {
        actor_id: record.actor_id.0.clone(),
        actor_type: match record.actor_type {
            ActorType::HumanActor => "human_actor",
            ActorType::AiActor => "ai_actor",
            ActorType::NodeActor => "node_actor",
            ActorType::GroupActor => "group_actor",
        }
        .to_string(),
        node_actor_id: record.node_actor_id.0.clone(),
        public_key: record.public_key.clone(),
        status: match record.status {
            ActorStatus::Active => "active",
            ActorStatus::Suspended => "suspended",
            ActorStatus::InRepair => "in_repair",
            ActorStatus::Terminated => "terminated",
        }
        .to_string(),
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}
