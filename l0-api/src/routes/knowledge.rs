//! Knowledge-Index Ledger endpoints

use axum::{
    extract::{Path, Query, State},
    Json,
};
use l0_core::ledger::{KnowledgeLedger, QueryOptions};
use l0_core::types::{ActorId, Digest, SpaceId};

use crate::dto::{
    CreateCrossRefRequest, CrossReferenceResponse, IndexContentRequest, KnowledgeEntryResponse,
    ListQueryParams, PaginatedResponse,
};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Index new content
pub async fn index_content(
    State(state): State<AppState>,
    Json(req): Json<IndexContentRequest>,
) -> ApiResult<Json<KnowledgeEntryResponse>> {
    let content_digest = Digest::from_hex(&req.content_digest)
        .map_err(|_| ApiError::Validation("Invalid content digest hex".to_string()))?;

    let parent_digest = req
        .parent_digest
        .as_ref()
        .map(|d| Digest::from_hex(d))
        .transpose()
        .map_err(|_| ApiError::Validation("Invalid parent digest hex".to_string()))?;

    let space_id = req.space_id.as_ref().map(|s| SpaceId(s.clone()));

    let entry = state
        .knowledge
        .index_content(
            content_digest,
            &ActorId(req.owner_actor_id),
            space_id.as_ref(),
            parent_digest,
        )
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(entry_to_response(&entry)))
}

/// Get entry by ID
pub async fn get_entry(
    State(state): State<AppState>,
    Path(entry_id): Path<String>,
) -> ApiResult<Json<KnowledgeEntryResponse>> {
    let entry = state
        .knowledge
        .get_entry(&entry_id)
        .await
        .map_err(ApiError::Ledger)?
        .ok_or_else(|| ApiError::NotFound(format!("Entry {} not found", entry_id)))?;

    Ok(Json(entry_to_response(&entry)))
}

/// Get entries by digest
pub async fn get_entries_by_digest(
    State(state): State<AppState>,
    Path(digest): Path<String>,
) -> ApiResult<Json<Vec<KnowledgeEntryResponse>>> {
    let content_digest = Digest::from_hex(&digest)
        .map_err(|_| ApiError::Validation("Invalid digest hex".to_string()))?;

    let entries = state
        .knowledge
        .get_entries_by_digest(&content_digest)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(entries.iter().map(entry_to_response).collect()))
}

/// Get entries by space
pub async fn get_entries_by_space(
    State(state): State<AppState>,
    Path(space_id): Path<String>,
    Query(params): Query<ListQueryParams>,
) -> ApiResult<Json<PaginatedResponse<KnowledgeEntryResponse>>> {
    let options = QueryOptions {
        limit: Some(params.limit),
        offset: Some(params.offset),
        ..Default::default()
    };

    let entries = state
        .knowledge
        .get_entries_by_space(&SpaceId(space_id), options)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(PaginatedResponse {
        total: entries.len() as u64,
        items: entries.iter().map(entry_to_response).collect(),
        limit: params.limit,
        offset: params.offset,
    }))
}

/// Get entries by actor
pub async fn get_entries_by_actor(
    State(state): State<AppState>,
    Path(actor_id): Path<String>,
    Query(params): Query<ListQueryParams>,
) -> ApiResult<Json<PaginatedResponse<KnowledgeEntryResponse>>> {
    let options = QueryOptions {
        limit: Some(params.limit),
        offset: Some(params.offset),
        ..Default::default()
    };

    let entries = state
        .knowledge
        .get_entries_by_actor(&ActorId(actor_id), options)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(PaginatedResponse {
        total: entries.len() as u64,
        items: entries.iter().map(entry_to_response).collect(),
        limit: params.limit,
        offset: params.offset,
    }))
}

/// Create cross-reference
pub async fn create_cross_reference(
    State(state): State<AppState>,
    Json(req): Json<CreateCrossRefRequest>,
) -> ApiResult<Json<CrossReferenceResponse>> {
    let source_digest = Digest::from_hex(&req.source_digest)
        .map_err(|_| ApiError::Validation("Invalid source digest hex".to_string()))?;

    let target_digest = Digest::from_hex(&req.target_digest)
        .map_err(|_| ApiError::Validation("Invalid target digest hex".to_string()))?;

    let xref = state
        .knowledge
        .create_cross_reference(source_digest, target_digest, req.ref_type)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(crossref_to_response(&xref)))
}

/// Get cross-references by digest
pub async fn get_cross_references(
    State(state): State<AppState>,
    Path((digest, direction)): Path<(String, String)>,
) -> ApiResult<Json<Vec<CrossReferenceResponse>>> {
    let content_digest = Digest::from_hex(&digest)
        .map_err(|_| ApiError::Validation("Invalid digest hex".to_string()))?;

    let as_source = direction == "outgoing";

    let xrefs = state
        .knowledge
        .get_cross_references(&content_digest, as_source)
        .await
        .map_err(ApiError::Ledger)?;

    Ok(Json(xrefs.iter().map(crossref_to_response).collect()))
}

// Helper functions

fn entry_to_response(entry: &l0_core::ledger::KnowledgeIndexEntry) -> KnowledgeEntryResponse {
    use l0_core::ledger::IndexEntryType;
    use l0_core::types::{AnchoringState, EvidenceLevel};

    KnowledgeEntryResponse {
        entry_id: entry.entry_id.clone(),
        entry_type: match entry.entry_type {
            IndexEntryType::ContentDigest => "content_digest",
            IndexEntryType::RelationDigest => "relation_digest",
            IndexEntryType::AggregateDigest => "aggregate_digest",
            IndexEntryType::SceneDigest => "scene_digest",
        }
        .to_string(),
        content_digest: entry.content_digest.to_hex(),
        parent_digest: entry.parent_digest.as_ref().map(|d| d.to_hex()),
        space_id: entry.space_id.as_ref().map(|s| s.0.clone()),
        owner_actor_id: entry.owner_actor_id.0.clone(),
        created_at: entry.created_at,
        evidence_level: match entry.evidence_level {
            EvidenceLevel::A => "a",
            EvidenceLevel::B => "b",
        }
        .to_string(),
        anchoring_state: match entry.anchoring_state {
            AnchoringState::LocalUnconfirmed => "local_unconfirmed",
            AnchoringState::Anchored => "anchored",
        }
        .to_string(),
        receipt_id: entry.receipt_id.as_ref().map(|r| r.0.clone()),
    }
}

fn crossref_to_response(xref: &l0_core::ledger::CrossReference) -> CrossReferenceResponse {
    CrossReferenceResponse {
        ref_id: xref.ref_id.clone(),
        source_digest: xref.source_digest.to_hex(),
        target_digest: xref.target_digest.to_hex(),
        ref_type: xref.ref_type.clone(),
        created_at: xref.created_at,
        receipt_id: xref.receipt_id.as_ref().map(|r| r.0.clone()),
    }
}
