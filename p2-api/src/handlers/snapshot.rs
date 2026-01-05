//! Snapshot API Handlers
//!
//! REST API endpoints for resurrection snapshot operations (R0/R1).

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::error::ApiError;
use crate::state::AppState;

/// Create R0 snapshot request
#[derive(Debug, Deserialize)]
pub struct CreateR0Request {
    /// Actor ID to snapshot
    pub actor_id: String,
    /// Trigger reason for the snapshot
    pub trigger: R0TriggerType,
    /// Custom policy version (optional)
    pub policy_version: Option<String>,
}

/// R0 trigger type for API
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum R0TriggerType {
    /// Subject onset event
    SubjectOnset,
    /// Scheduled backup
    Scheduled,
    /// Manual trigger
    Manual,
    /// Pre-migration checkpoint
    PreMigration,
}

impl std::fmt::Display for R0TriggerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            R0TriggerType::SubjectOnset => write!(f, "subject_onset"),
            R0TriggerType::Scheduled => write!(f, "scheduled"),
            R0TriggerType::Manual => write!(f, "manual"),
            R0TriggerType::PreMigration => write!(f, "pre_migration"),
        }
    }
}

/// Create R1 snapshot request
#[derive(Debug, Deserialize)]
pub struct CreateR1Request {
    /// Actor ID to snapshot
    pub actor_id: String,
    /// R0 snapshot ID to base R1 on
    pub r0_snapshot_id: String,
    /// Guardian consent reference (required for R1)
    pub guardian_consent_ref: String,
    /// Authority that approved the resurrection
    pub approving_authority: String,
}

/// Snapshot list query parameters
#[derive(Debug, Deserialize)]
pub struct SnapshotListQuery {
    /// Actor ID filter
    pub actor_id: Option<String>,
    /// Snapshot type filter (r0 or r1)
    #[serde(rename = "type")]
    pub snapshot_type: Option<String>,
    /// Maximum number of results
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Offset for pagination
    #[serde(default)]
    pub offset: usize,
}

fn default_limit() -> usize {
    50
}

/// R0 snapshot summary response
#[derive(Debug, Serialize)]
pub struct R0SnapshotSummary {
    /// Snapshot ID
    pub snapshot_id: String,
    /// Actor ID
    pub actor_id: String,
    /// Package digest
    pub package_digest: String,
    /// Trigger reason
    pub trigger: String,
    /// Generation timestamp
    pub generated_at: DateTime<Utc>,
    /// Policy version
    pub policy_version: String,
    /// Number of payload refs
    pub payload_count: usize,
}

/// R1 snapshot summary response
#[derive(Debug, Serialize)]
pub struct R1SnapshotSummary {
    /// Snapshot ID
    pub snapshot_id: String,
    /// Actor ID
    pub actor_id: String,
    /// Source R0 snapshot ID
    pub source_r0_id: String,
    /// Generation timestamp
    pub generated_at: DateTime<Utc>,
    /// Whether resurrection was authorized
    pub authorized: bool,
    /// Authorizing entity
    pub authorized_by: Option<String>,
}

/// Create snapshot response
#[derive(Debug, Serialize)]
pub struct CreateSnapshotResponse {
    /// Created snapshot ID
    pub snapshot_id: String,
    /// Snapshot type (r0 or r1)
    pub snapshot_type: String,
    /// Actor ID
    pub actor_id: String,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
}

/// Snapshot list response
#[derive(Debug, Serialize)]
pub struct SnapshotListResponse {
    /// R0 snapshots
    pub r0_snapshots: Vec<R0SnapshotSummary>,
    /// R1 snapshots
    pub r1_snapshots: Vec<R1SnapshotSummary>,
    /// Total count (for pagination)
    pub total: usize,
}

/// Snapshot verification response
#[derive(Debug, Serialize)]
pub struct VerifySnapshotResponse {
    /// Snapshot ID
    pub snapshot_id: String,
    /// Whether snapshot exists and is valid
    pub valid: bool,
    /// Snapshot type if found
    pub snapshot_type: Option<String>,
    /// Verification timestamp
    pub verified_at: DateTime<Utc>,
    /// Any verification errors
    pub errors: Vec<String>,
}

/// Create an R0 (skeleton) snapshot
///
/// POST /api/v1/snapshots/r0
pub async fn create_r0_snapshot(
    State(_state): State<AppState>,
    Json(request): Json<CreateR0Request>,
) -> Result<impl IntoResponse, ApiError> {
    info!(
        actor_id = %request.actor_id,
        trigger = %request.trigger,
        "Creating R0 snapshot"
    );

    // Validate actor exists
    if request.actor_id.is_empty() {
        return Err(ApiError::BadRequest("actor_id is required".to_string()));
    }

    // In a real implementation, this would:
    // 1. Load actor state from the ledger
    // 2. Generate the skeleton snapshot
    // 3. Store it in the snapshot ledger
    // For now, we generate a snapshot ID
    let snapshot_id = format!("r0:{}", uuid::Uuid::new_v4());
    let now = Utc::now();

    // Here would be the actual snapshot creation logic using:
    // state.snapshot_ledger.store_r0(snapshot).await?

    let response = CreateSnapshotResponse {
        snapshot_id,
        snapshot_type: "r0".to_string(),
        actor_id: request.actor_id,
        created_at: now,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// Create an R1 (full resurrection) snapshot
///
/// POST /api/v1/snapshots/r1
pub async fn create_r1_snapshot(
    State(_state): State<AppState>,
    Json(request): Json<CreateR1Request>,
) -> Result<impl IntoResponse, ApiError> {
    info!(
        actor_id = %request.actor_id,
        r0_id = %request.r0_snapshot_id,
        "Creating R1 snapshot"
    );

    // Validate request
    if request.actor_id.is_empty() {
        return Err(ApiError::BadRequest("actor_id is required".to_string()));
    }
    if request.r0_snapshot_id.is_empty() {
        return Err(ApiError::BadRequest(
            "r0_snapshot_id is required".to_string(),
        ));
    }
    if request.guardian_consent_ref.is_empty() {
        return Err(ApiError::BadRequest(
            "guardian_consent_ref is required for R1 snapshots".to_string(),
        ));
    }

    // In a real implementation:
    // 1. Verify the R0 snapshot exists
    // 2. Verify guardian consent
    // 3. Collect full payload data
    // 4. Generate R1 snapshot
    // 5. Store it

    let snapshot_id = format!("r1:{}", uuid::Uuid::new_v4());
    let now = Utc::now();

    let response = CreateSnapshotResponse {
        snapshot_id,
        snapshot_type: "r1".to_string(),
        actor_id: request.actor_id,
        created_at: now,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// Get a specific snapshot by ID
///
/// GET /api/v1/snapshots/:snapshot_id
pub async fn get_snapshot(
    State(_state): State<AppState>,
    Path(snapshot_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    info!(snapshot_id = %snapshot_id, "Getting snapshot");

    // Determine type from ID prefix
    if snapshot_id.starts_with("r0:") {
        // Return R0 summary
        let summary = R0SnapshotSummary {
            snapshot_id: snapshot_id.clone(),
            actor_id: "actor:unknown".to_string(),
            package_digest: "0x...".to_string(),
            trigger: "manual".to_string(),
            generated_at: Utc::now(),
            policy_version: "v1".to_string(),
            payload_count: 0,
        };
        Ok(Json(serde_json::json!({
            "type": "r0",
            "snapshot": summary
        })))
    } else if snapshot_id.starts_with("r1:") {
        // Return R1 summary
        let summary = R1SnapshotSummary {
            snapshot_id: snapshot_id.clone(),
            actor_id: "actor:unknown".to_string(),
            source_r0_id: "r0:unknown".to_string(),
            generated_at: Utc::now(),
            authorized: true,
            authorized_by: Some("system".to_string()),
        };
        Ok(Json(serde_json::json!({
            "type": "r1",
            "snapshot": summary
        })))
    } else {
        Err(ApiError::NotFound(format!(
            "Snapshot not found: {}",
            snapshot_id
        )))
    }
}

/// List snapshots with filtering
///
/// GET /api/v1/snapshots
pub async fn list_snapshots(
    State(_state): State<AppState>,
    Query(query): Query<SnapshotListQuery>,
) -> Result<impl IntoResponse, ApiError> {
    info!(
        actor_id = ?query.actor_id,
        snapshot_type = ?query.snapshot_type,
        limit = query.limit,
        "Listing snapshots"
    );

    // In a real implementation, this would query the snapshot ledger
    // For now, return an empty response
    let response = SnapshotListResponse {
        r0_snapshots: vec![],
        r1_snapshots: vec![],
        total: 0,
    };

    Ok(Json(response))
}

/// Get latest R0 snapshot for an actor
///
/// GET /api/v1/snapshots/r0/latest/:actor_id
pub async fn get_latest_r0(
    State(_state): State<AppState>,
    Path(actor_id): Path<String>,
) -> Result<Json<R0SnapshotSummary>, ApiError> {
    info!(actor_id = %actor_id, "Getting latest R0 snapshot");

    // In a real implementation:
    // let actor = ActorId::new(&actor_id);
    // let snapshot = state.snapshot_ledger.get_latest_r0(&actor).await?;

    Err(ApiError::NotFound(format!(
        "No R0 snapshot found for actor: {}",
        actor_id
    )))
}

/// Get latest R1 snapshot for an actor
///
/// GET /api/v1/snapshots/r1/latest/:actor_id
pub async fn get_latest_r1(
    State(_state): State<AppState>,
    Path(actor_id): Path<String>,
) -> Result<Json<R1SnapshotSummary>, ApiError> {
    info!(actor_id = %actor_id, "Getting latest R1 snapshot");

    Err(ApiError::NotFound(format!(
        "No R1 snapshot found for actor: {}",
        actor_id
    )))
}

/// Verify a snapshot's integrity
///
/// POST /api/v1/snapshots/:snapshot_id/verify
pub async fn verify_snapshot(
    State(_state): State<AppState>,
    Path(snapshot_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    info!(snapshot_id = %snapshot_id, "Verifying snapshot");

    // In a real implementation:
    // let valid = state.snapshot_ledger.verify_snapshot(&snapshot_id).await?;

    let response = VerifySnapshotResponse {
        snapshot_id,
        valid: false, // Would be real verification result
        snapshot_type: None,
        verified_at: Utc::now(),
        errors: vec!["Snapshot not found".to_string()],
    };

    Ok(Json(response))
}

/// Delete a snapshot (if allowed by retention policy)
///
/// DELETE /api/v1/snapshots/:snapshot_id
pub async fn delete_snapshot(
    State(_state): State<AppState>,
    Path(snapshot_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    info!(snapshot_id = %snapshot_id, "Delete snapshot request");

    // Snapshots typically cannot be deleted due to retention requirements
    // This would check the retention policy first
    Err(ApiError::Forbidden(
        "Snapshots cannot be deleted within retention period".to_string(),
    ))
}

/// Compare two snapshots
///
/// POST /api/v1/snapshots/compare
#[derive(Debug, Deserialize)]
pub struct CompareSnapshotsRequest {
    /// First snapshot ID
    pub snapshot_a: String,
    /// Second snapshot ID
    pub snapshot_b: String,
}

#[derive(Debug, Serialize)]
pub struct CompareSnapshotsResponse {
    /// First snapshot ID
    pub snapshot_a: String,
    /// Second snapshot ID
    pub snapshot_b: String,
    /// Whether snapshots are identical
    pub identical: bool,
    /// Differences found
    pub differences: Vec<SnapshotDifference>,
    /// Comparison timestamp
    pub compared_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct SnapshotDifference {
    /// Field that differs
    pub field: String,
    /// Value in snapshot A
    pub value_a: String,
    /// Value in snapshot B
    pub value_b: String,
}

pub async fn compare_snapshots(
    State(_state): State<AppState>,
    Json(request): Json<CompareSnapshotsRequest>,
) -> Result<impl IntoResponse, ApiError> {
    info!(
        snapshot_a = %request.snapshot_a,
        snapshot_b = %request.snapshot_b,
        "Comparing snapshots"
    );

    // In a real implementation, load both snapshots and compare
    let response = CompareSnapshotsResponse {
        snapshot_a: request.snapshot_a,
        snapshot_b: request.snapshot_b,
        identical: false,
        differences: vec![],
        compared_at: Utc::now(),
    };

    Ok(Json(response))
}

/// Get snapshot statistics
///
/// GET /api/v1/snapshots/stats
#[derive(Debug, Serialize)]
pub struct SnapshotStats {
    /// Total R0 snapshots
    pub total_r0: usize,
    /// Total R1 snapshots
    pub total_r1: usize,
    /// Unique actors with R0 snapshots
    pub actors_with_r0: usize,
    /// Unique actors with R1 snapshots
    pub actors_with_r1: usize,
    /// Storage used (bytes)
    pub storage_bytes: u64,
    /// Oldest snapshot timestamp
    pub oldest_snapshot: Option<DateTime<Utc>>,
    /// Newest snapshot timestamp
    pub newest_snapshot: Option<DateTime<Utc>>,
    /// Statistics timestamp
    pub computed_at: DateTime<Utc>,
}

pub async fn get_snapshot_stats(
    State(_state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    info!("Getting snapshot statistics");

    let stats = SnapshotStats {
        total_r0: 0,
        total_r1: 0,
        actors_with_r0: 0,
        actors_with_r1: 0,
        storage_bytes: 0,
        oldest_snapshot: None,
        newest_snapshot: None,
        computed_at: Utc::now(),
    };

    Ok(Json(stats))
}

/// Build the snapshot router
pub fn snapshot_router() -> axum::Router<AppState> {
    use axum::routing::{delete, get, post};

    axum::Router::new()
        // R0 operations
        .route("/r0", post(create_r0_snapshot))
        .route("/r0/latest/:actor_id", get(get_latest_r0))
        // R1 operations
        .route("/r1", post(create_r1_snapshot))
        .route("/r1/latest/:actor_id", get(get_latest_r1))
        // General operations
        .route("/", get(list_snapshots))
        .route("/stats", get(get_snapshot_stats))
        .route("/compare", post(compare_snapshots))
        .route("/:snapshot_id", get(get_snapshot))
        .route("/:snapshot_id", delete(delete_snapshot))
        .route("/:snapshot_id/verify", post(verify_snapshot))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_r0_trigger_display() {
        assert_eq!(R0TriggerType::SubjectOnset.to_string(), "subject_onset");
        assert_eq!(R0TriggerType::Manual.to_string(), "manual");
    }

    #[test]
    fn test_deserialize_create_r0_request() {
        let json = r#"{"actor_id": "actor:test", "trigger": "manual"}"#;
        let request: CreateR0Request = serde_json::from_str(json).unwrap();
        assert_eq!(request.actor_id, "actor:test");
    }

    #[test]
    fn test_deserialize_create_r1_request() {
        let json = r#"{
            "actor_id": "actor:test",
            "r0_snapshot_id": "r0:123",
            "guardian_consent_ref": "consent:456",
            "approving_authority": "guardian:001"
        }"#;
        let request: CreateR1Request = serde_json::from_str(json).unwrap();
        assert_eq!(request.actor_id, "actor:test");
        assert_eq!(request.r0_snapshot_id, "r0:123");
    }
}
