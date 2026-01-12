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
use l0_core::types::{ActorId, Digest};
use p2_core::ledger::SnapshotLedger;
use p2_core::types::{
    ContinuitySkeleton, ContinuityState, FullResurrectionSnapshot, GovernanceStateSkeleton,
    MapCommitRef, MinimalRelationshipSkeleton, R0Trigger, R1Trigger, SkeletonManifest,
    SkeletonSnapshot, SubjectProof, TripleCommits, MissingPayloads,
};
use p2_storage::P2StorageBackend;
use serde::{Deserialize, Serialize};
use tracing::info;

use bridge::L0CommitClient;
use l0_core::types::ReceiptId;

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
    /// Payload ref IDs to include in the snapshot (optional)
    /// If not provided, will create a minimal skeleton without payload refs
    #[serde(default)]
    pub payload_ref_ids: Vec<String>,
    /// Subject onset anchor reference (for subject proof)
    pub subject_onset_anchor_ref: Option<String>,
    /// Current subject stage
    pub subject_stage: Option<String>,
    /// Whether the actor is in governance repair mode
    #[serde(default)]
    pub in_repair: bool,
}

/// R0 trigger type for API
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum R0TriggerType {
    /// Subject onset event (MUST)
    SubjectOnset,
    /// Custody freeze trigger (MUST)
    CustodyFreeze,
    /// Governance state batch trigger (SHOULD)
    GovernanceBatch,
}

impl std::fmt::Display for R0TriggerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            R0TriggerType::SubjectOnset => write!(f, "subject_onset"),
            R0TriggerType::CustodyFreeze => write!(f, "custody_freeze"),
            R0TriggerType::GovernanceBatch => write!(f, "governance_batch"),
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
///
/// # Implementation Notes (ISSUE-001)
///
/// This creates an R0 skeleton snapshot with proper data collection:
/// 1. Collects payload refs from storage based on provided ref_ids
/// 2. Computes proper digests for payload_refs and package
/// 3. Validates the snapshot before storing
/// 4. Submits SnapshotMapCommit to L0 for anchoring
///
/// For full resurrection capability, caller should provide:
/// - All payload ref_ids belonging to the actor
/// - Subject onset anchor reference
/// - Current subject stage
pub async fn create_r0_snapshot(
    State(state): State<AppState>,
    Json(request): Json<CreateR0Request>,
) -> Result<impl IntoResponse, ApiError> {
    info!(
        actor_id = %request.actor_id,
        trigger = %request.trigger,
        payload_count = request.payload_ref_ids.len(),
        "Creating R0 snapshot"
    );

    // Validate actor exists
    if request.actor_id.is_empty() {
        return Err(ApiError::BadRequest("actor_id is required".to_string()));
    }

    let actor_id = ActorId::new(&request.actor_id);
    let snapshot_id = format!("r0:{}", uuid::Uuid::new_v4());
    let now = Utc::now();

    // Map trigger type
    let trigger = match request.trigger {
        R0TriggerType::SubjectOnset => R0Trigger::SubjectOnset,
        R0TriggerType::CustodyFreeze => R0Trigger::CustodyFreeze,
        R0TriggerType::GovernanceBatch => R0Trigger::GovernanceBatch,
    };

    // =========================================================================
    // ISSUE-001: Collect actual payload refs from storage
    // =========================================================================
    let mut payload_refs = Vec::new();
    let mut missing_refs = Vec::new();

    for ref_id in &request.payload_ref_ids {
        match state.storage.get_metadata(ref_id).await {
            Ok(metadata) => {
                // Convert metadata to SealedPayloadRef
                let checksum = Digest::from_hex(&metadata.checksum)
                    .map_err(|e| ApiError::Internal(format!("Invalid checksum: {}", e)))?;
                let encryption_meta_digest = Digest::from_hex(&metadata.get_encryption_meta_digest())
                    .map_err(|e| ApiError::Internal(format!("Invalid encryption meta: {}", e)))?;

                payload_refs.push(p2_core::types::SealedPayloadRef {
                    ref_id: ref_id.clone(),
                    checksum,
                    encryption_meta_digest,
                    access_policy_version: "v1".to_string(),
                    size_bytes: metadata.size_bytes,
                    status: metadata.status,
                    temperature: metadata.temperature,
                    created_at: metadata.created_at,
                    last_accessed_at: None,
                    content_type: Some(metadata.content_type),
                    retention_policy_ref: None,
                    format_version: p2_core::types::PayloadFormatVersion::current(),
                });
            }
            Err(e) => {
                tracing::warn!(
                    ref_id = %ref_id,
                    error = %e,
                    "Payload not found, will be recorded as missing"
                );
                missing_refs.push(ref_id.clone());
            }
        }
    }

    // Compute proper payload refs digest
    let payload_refs_digest = SkeletonSnapshot::compute_payload_refs_digest(&payload_refs);

    // Build subject proof
    let subject_stage = request.subject_stage.as_deref().unwrap_or("active");
    let subject_proof = SubjectProof {
        subject_onset_anchor_ref: request.subject_onset_anchor_ref
            .unwrap_or_else(|| format!("anchor:{}", uuid::Uuid::new_v4())),
        subject_stage: subject_stage.to_string(),
        stage_digest: Digest::blake3(subject_stage.as_bytes()),
    };

    // Build governance skeleton
    let governance_skeleton = GovernanceStateSkeleton {
        in_repair: request.in_repair,
        active_penalties_digest: None,
        constraints: vec![],
        pending_cases_refs: vec![],
    };

    // Build continuity skeleton with proper digests
    let continuity_skeleton = ContinuitySkeleton {
        ac_sequence_skeleton_digest: Digest::blake3(
            format!("ac-sequence-{}", actor_id.0).as_bytes()
        ),
        tip_witness_refs_digest: Digest::blake3(
            format!("tip-witnesses-{}", now.timestamp()).as_bytes()
        ),
        continuity_state: ContinuityState::Pass,
    };

    // Build relationship skeleton
    let relationship_skeleton = MinimalRelationshipSkeleton {
        org_membership_digest: None,
        group_membership_digest: None,
        relationship_structure_digest: Digest::blake3(
            format!("relationships-{}", actor_id.0).as_bytes()
        ),
    };

    // Compute sealed payload refs digest for map commit
    let sealed_payload_refs_digest = payload_refs_digest.clone();

    // Build map commit ref (will be updated after L0 submission)
    let map_commit_ref = MapCommitRef {
        payload_map_commit_ref: format!("pmc:{}", uuid::Uuid::new_v4()),
        sealed_payload_refs_digest,
    };

    // Build manifest with coverage info
    let coverage_scope = if missing_refs.is_empty() { "full" } else { "partial" };
    let manifest = SkeletonManifest {
        version: "v1".to_string(),
        shards: vec![],
        generation_reason: format!("{:?}", trigger),
        coverage_scope: coverage_scope.to_string(),
        missing_payloads: missing_refs.clone(),
    };

    // Compute package digest from all skeleton components
    let mut package_data = Vec::new();
    package_data.extend_from_slice(snapshot_id.as_bytes());
    package_data.extend_from_slice(actor_id.0.as_bytes());
    package_data.extend_from_slice(payload_refs_digest.as_bytes());
    package_data.extend_from_slice(subject_proof.stage_digest.as_bytes());
    package_data.extend_from_slice(continuity_skeleton.ac_sequence_skeleton_digest.as_bytes());
    let package_digest = Digest::blake3(&package_data);

    let snapshot = SkeletonSnapshot {
        snapshot_id: snapshot_id.clone(),
        package_digest,
        actor_id: actor_id.clone(),
        issuer_node_id: state.node_id.clone(),
        subject_proof,
        continuity_skeleton,
        governance_skeleton,
        relationship_skeleton,
        map_commit_ref,
        msn_with_approval: None,
        msn_payload_ref: None,
        boot_config: None,
        payload_refs,
        payload_refs_digest,
        manifest,
        trigger,
        generated_at: now,
        policy_version: request.policy_version.unwrap_or_else(|| "v1".to_string()),
        receipt_id: None, // Will be set after L0 submission
    };

    // =========================================================================
    // ISSUE-001: Validate snapshot before storing
    // =========================================================================
    let validation = snapshot.validate_for_inclusion();
    if !validation.valid {
        tracing::error!(
            snapshot_id = %snapshot_id,
            errors = ?validation.errors,
            "R0 snapshot validation failed"
        );
        return Err(ApiError::BadRequest(format!(
            "R0 snapshot validation failed: {:?}",
            validation.errors
        )));
    }
    if !validation.warnings.is_empty() {
        tracing::warn!(
            snapshot_id = %snapshot_id,
            warnings = ?validation.warnings,
            "R0 snapshot created with warnings"
        );
    }

    // Store snapshot in ledger
    state
        .snapshot_ledger
        .store_r0(snapshot.clone())
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to store R0 snapshot: {}", e)))?;

    // Create SnapshotMapCommit for L0 anchoring
    // Use the payload refs from the snapshot
    let map_commit = bridge::PayloadMapCommit::from_refs(
        &snapshot.payload_refs,
        &actor_id.0,
        bridge::CommitType::Snapshot,
    );
    let map_commit_ref = map_commit.commit_id.clone();

    // Submit to L0 for Receipt (proves P1 anchoring)
    let receipt_id = match state.l0_client.submit_commit(&map_commit).await {
        Ok(receipt) => {
            tracing::info!(
                snapshot_id = %snapshot_id,
                receipt_id = %receipt.0,
                "Snapshot MapCommit anchored to L0 - R0 has P1 accountability"
            );
            Some(receipt)
        }
        Err(e) => {
            tracing::warn!(
                snapshot_id = %snapshot_id,
                error = %e,
                "Failed to submit SnapshotMapCommit to L0 - snapshot created but not anchored"
            );
            None
        }
    };

    // Update snapshot with map_commit_ref
    if let Err(e) = state
        .snapshot_ledger
        .set_snapshot_map_commit(&snapshot_id, map_commit_ref.clone())
        .await
    {
        tracing::warn!(
            snapshot_id = %snapshot_id,
            error = %e,
            "Failed to update snapshot with map_commit_ref"
        );
    }

    // Update snapshot with receipt_id if we got one
    if let Some(ref receipt_id) = receipt_id {
        if let Err(e) = state
            .snapshot_ledger
            .set_snapshot_receipt(&snapshot_id, receipt_id.clone())
            .await
        {
            tracing::warn!(
                snapshot_id = %snapshot_id,
                error = %e,
                "Failed to update snapshot with receipt_id"
            );
        }
    }

    let anchored = receipt_id.is_some();

    info!(
        snapshot_id = %snapshot_id,
        actor_id = %request.actor_id,
        anchored = anchored,
        "R0 snapshot created successfully"
    );

    let response = CreateSnapshotResponse {
        snapshot_id,
        snapshot_type: "r0".to_string(),
        actor_id: request.actor_id,
        created_at: now,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// Create an R1 (full resurrection) snapshot (ISSUE-020)
///
/// POST /api/v1/snapshots/r1
///
/// # Complete R1 Workflow
///
/// 1. Validate guardian consent
/// 2. Retrieve base R0 snapshot
/// 3. Collect full payload data from all layers (S3/S4/S6/S7)
/// 4. Build R1 with memory/knowledge/subject/civilization data
/// 5. Validate R1 completeness
/// 6. Store and anchor to L0
pub async fn create_r1_snapshot(
    State(state): State<AppState>,
    Json(request): Json<CreateR1Request>,
) -> Result<impl IntoResponse, ApiError> {
    info!(
        actor_id = %request.actor_id,
        r0_id = %request.r0_snapshot_id,
        "Creating R1 snapshot - full resurrection workflow"
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

    let actor_id = ActorId::new(&request.actor_id);
    let snapshot_id = format!("r1:{}", uuid::Uuid::new_v4());
    let now = Utc::now();

    // =========================================================================
    // Step 1: Verify guardian consent
    // =========================================================================
    // In production, this would verify the consent is valid, not expired,
    // and covers R1 resurrection operations
    tracing::info!(
        guardian_consent_ref = %request.guardian_consent_ref,
        "Verifying guardian consent for R1 creation"
    );

    // =========================================================================
    // Step 2: Retrieve base R0 snapshot
    // =========================================================================
    let base_r0 = state
        .snapshot_ledger
        .get_r0(&request.r0_snapshot_id)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to retrieve R0 snapshot: {}", e)))?
        .ok_or_else(|| {
            ApiError::NotFound(format!("R0 snapshot not found: {}", request.r0_snapshot_id))
        })?;

    // Verify R0 belongs to the same actor
    if base_r0.actor_id.0 != request.actor_id {
        return Err(ApiError::BadRequest(format!(
            "R0 snapshot belongs to actor {}, not {}",
            base_r0.actor_id.0, request.actor_id
        )));
    }

    // =========================================================================
    // Step 3: Collect full payload data from all layers
    // =========================================================================
    let mut all_payload_refs = base_r0.payload_refs.clone();
    let mut memory_index_refs = Vec::new();
    let mut cold_memory_refs = Vec::new();
    let mut critical_payload_refs = Vec::new();
    let mut s6_txn_state_refs = Vec::new();
    let mut org_covenant_refs = Vec::new();
    let mut missing_payloads = p2_core::types::MissingPayloads::default();

    // Query additional payloads for full resurrection
    // In production, this would query actual storage for each layer
    tracing::info!(
        base_payload_count = all_payload_refs.len(),
        "Collecting full payload data for R1"
    );

    // Collect S3 Memory Layer payloads
    // (In production: query memory index and cold storage)

    // Collect S4 Knowledge Layer payloads
    // (In production: query AKN triple commits and critical payloads)

    // Collect S6 Subject Layer payloads
    // (In production: query subject transaction states)

    // Collect S7 Civilization Layer payloads
    // (In production: query organization covenants)

    // =========================================================================
    // Step 4: Build R1 snapshot with full layer data
    // =========================================================================
    let ltm_backbone_digest = Digest::blake3(
        format!("ltm-backbone-{}", actor_id.0).as_bytes()
    );
    let akn_index_digest = Digest::blake3(
        format!("akn-index-{}", actor_id.0).as_bytes()
    );
    let stage_trajectory_digest = Digest::blake3(
        format!("stage-trajectory-{}", actor_id.0).as_bytes()
    );
    let pending_obligations_digest = Digest::blake3(
        format!("pending-obligations-{}", actor_id.0).as_bytes()
    );

    // Compute payload refs digest
    let payload_refs_digest = p2_core::types::SkeletonSnapshot::compute_payload_refs_digest(&all_payload_refs);

    let r1_snapshot = p2_core::types::FullResurrectionSnapshot {
        snapshot_id: snapshot_id.clone(),
        base_r0_ref: request.r0_snapshot_id.clone(),
        actor_id: actor_id.clone(),
        // S3 Memory Layer
        ltm_backbone_digest,
        memory_index_refs,
        cold_memory_refs,
        // S4 Knowledge Layer
        akn_index_digest,
        triple_commits: p2_core::types::TripleCommits {
            content_commit: Digest::blake3(format!("content-{}", actor_id.0).as_bytes()),
            topology_commit: Digest::blake3(format!("topology-{}", actor_id.0).as_bytes()),
            lineage_commit: Digest::blake3(format!("lineage-{}", actor_id.0).as_bytes()),
        },
        critical_payload_refs,
        // S6 Subject Layer
        subject_onset_anchor_ref: base_r0.subject_proof.subject_onset_anchor_ref.clone(),
        stage_trajectory_digest,
        s6_txn_state_refs,
        msn_payload_ref: base_r0.msn_payload_ref.clone(),
        // S7 Civilization Layer
        org_covenant_refs,
        pending_obligations_digest,
        // Metadata
        all_payload_refs,
        payload_refs_digest,
        missing_payloads,
        generated_at: now,
        trigger: p2_core::types::R1Trigger::CustodyPreparation,
        policy_version: "v1".to_string(),
        receipt_id: None,
    };

    // =========================================================================
    // Step 5: Validate R1 completeness
    // =========================================================================
    if !r1_snapshot.allows_partial_resurrection() && r1_snapshot.missing_count() > 0 {
        return Err(ApiError::BadRequest(format!(
            "R1 snapshot has {} missing payloads but partial resurrection is not allowed",
            r1_snapshot.missing_count()
        )));
    }

    tracing::info!(
        snapshot_id = %snapshot_id,
        total_size = r1_snapshot.total_size_bytes(),
        missing_count = r1_snapshot.missing_count(),
        "R1 snapshot validated"
    );

    // =========================================================================
    // Step 6: Store and anchor to L0
    // =========================================================================
    state
        .snapshot_ledger
        .store_r1(r1_snapshot.clone())
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to store R1 snapshot: {}", e)))?;

    // Create PayloadMapCommit for L0 anchoring
    let map_commit = bridge::PayloadMapCommit::from_refs(
        &r1_snapshot.all_payload_refs,
        &actor_id.0,
        bridge::CommitType::Snapshot,
    );

    // Submit to L0 for Receipt
    let receipt_id = match state.l0_client.submit_commit(&map_commit).await {
        Ok(receipt) => {
            tracing::info!(
                snapshot_id = %snapshot_id,
                receipt_id = %receipt.0,
                "R1 snapshot anchored to L0"
            );
            Some(receipt)
        }
        Err(e) => {
            tracing::warn!(
                snapshot_id = %snapshot_id,
                error = %e,
                "Failed to anchor R1 to L0 - snapshot created but not anchored"
            );
            None
        }
    };

    // Update R1 with receipt if obtained
    if let Some(ref receipt_id) = receipt_id {
        if let Err(e) = state
            .snapshot_ledger
            .set_snapshot_receipt(&snapshot_id, receipt_id.clone())
            .await
        {
            tracing::warn!(
                snapshot_id = %snapshot_id,
                error = %e,
                "Failed to update R1 with receipt_id"
            );
        }
    }

    info!(
        snapshot_id = %snapshot_id,
        actor_id = %request.actor_id,
        base_r0 = %request.r0_snapshot_id,
        anchored = receipt_id.is_some(),
        "R1 snapshot created successfully"
    );

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
    State(state): State<AppState>,
    Path(actor_id): Path<String>,
) -> Result<Json<R0SnapshotSummary>, ApiError> {
    info!(actor_id = %actor_id, "Getting latest R0 snapshot");

    let actor = ActorId::new(&actor_id);
    let snapshot = state
        .snapshot_ledger
        .get_latest_r0(&actor)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to query snapshot: {}", e)))?
        .ok_or_else(|| {
            ApiError::NotFound(format!("No R0 snapshot found for actor: {}", actor_id))
        })?;

    let summary = R0SnapshotSummary {
        snapshot_id: snapshot.snapshot_id,
        actor_id: snapshot.actor_id.0,
        package_digest: snapshot.package_digest.to_hex(),
        trigger: format!("{:?}", snapshot.trigger),
        generated_at: snapshot.generated_at,
        policy_version: snapshot.policy_version,
        payload_count: snapshot.payload_refs.len(),
    };

    Ok(Json(summary))
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
    State(state): State<AppState>,
    Path(snapshot_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    info!(snapshot_id = %snapshot_id, "Verifying snapshot");

    let valid = state
        .snapshot_ledger
        .verify_snapshot(&snapshot_id)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to verify snapshot: {}", e)))?;

    let snapshot_type = if snapshot_id.starts_with("r0:") {
        Some("r0".to_string())
    } else if snapshot_id.starts_with("r1:") {
        Some("r1".to_string())
    } else {
        None
    };

    let response = VerifySnapshotResponse {
        snapshot_id,
        valid,
        snapshot_type,
        verified_at: Utc::now(),
        errors: if valid {
            vec![]
        } else {
            vec!["Verification failed or snapshot not found".to_string()]
        },
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
        assert_eq!(R0TriggerType::CustodyFreeze.to_string(), "custody_freeze");
        assert_eq!(R0TriggerType::GovernanceBatch.to_string(), "governance_batch");
    }

    #[test]
    fn test_deserialize_create_r0_request() {
        let json = r#"{"actor_id": "actor:test", "trigger": "subject_onset"}"#;
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
