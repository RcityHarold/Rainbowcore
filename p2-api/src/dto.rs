//! Data Transfer Objects for P2 API

use chrono::{DateTime, Utc};
use p2_core::types::{EvidenceLevel, SealedPayloadStatus, StorageTemperature};
use serde::{Deserialize, Serialize};
use validator::Validate;

/// Write payload request
#[derive(Debug, Deserialize, Validate)]
pub struct WritePayloadRequest {
    /// Content type
    #[validate(length(min = 1, max = 256))]
    pub content_type: String,

    /// Storage temperature hint
    pub temperature: Option<StorageTemperature>,

    /// Tags for organization
    #[validate(length(max = 10))]
    pub tags: Option<Vec<String>>,

    /// Committer identifier
    #[validate(length(min = 1, max = 256))]
    pub committer: Option<String>,
}

/// Write payload response
#[derive(Debug, Serialize)]
pub struct WritePayloadResponse {
    /// Payload reference ID
    pub ref_id: String,
    /// Checksum digest
    pub checksum: String,
    /// Size in bytes
    pub size_bytes: u64,
    /// Storage temperature
    pub temperature: StorageTemperature,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
}

/// Read payload response metadata
#[derive(Debug, Serialize)]
pub struct PayloadMetadataResponse {
    /// Reference ID
    pub ref_id: String,
    /// Checksum
    pub checksum: String,
    /// Size in bytes
    pub size_bytes: u64,
    /// Status
    pub status: SealedPayloadStatus,
    /// Temperature tier
    pub temperature: StorageTemperature,
    /// Content type
    pub content_type: String,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Tags
    pub tags: Vec<String>,
}

/// Sync request
#[derive(Debug, Deserialize, Validate)]
pub struct SyncRequest {
    /// Content type
    #[validate(length(min = 1, max = 256))]
    pub content_type: String,

    /// Local path identifier
    #[validate(length(max = 1024))]
    pub local_path: Option<String>,

    /// Committer
    #[validate(length(min = 1, max = 256))]
    pub committer: String,
}

/// Sync response
#[derive(Debug, Serialize)]
pub struct SyncResponse {
    /// Sync ID
    pub sync_id: String,
    /// Phase
    pub phase: String,
    /// Payload ref ID
    pub ref_id: Option<String>,
    /// Commit ID
    pub commit_id: Option<String>,
    /// Receipt ID
    pub receipt_id: Option<String>,
    /// Duration in milliseconds
    pub duration_ms: Option<i64>,
    /// Is complete
    pub is_complete: bool,
}

/// Verify commit request
#[derive(Debug, Deserialize, Validate)]
pub struct VerifyCommitRequest {
    /// Commit ID
    #[validate(length(min = 1, max = 256))]
    pub commit_id: String,

    /// Payload ref IDs to verify
    #[validate(length(min = 1, max = 1000))]
    pub ref_ids: Vec<String>,
}

/// Verify commit response
#[derive(Debug, Serialize)]
pub struct VerifyCommitResponse {
    /// Is valid
    pub is_valid: bool,
    /// Evidence level
    pub evidence_level: EvidenceLevel,
    /// Mismatch details (if any)
    pub mismatch: Option<VerifyMismatch>,
}

/// Verification mismatch details
#[derive(Debug, Serialize)]
pub struct VerifyMismatch {
    /// Mismatch type
    pub mismatch_type: String,
    /// Expected value
    pub expected: String,
    /// Actual value
    pub actual: String,
}

/// Create evidence bundle request
#[derive(Debug, Deserialize, Validate)]
pub struct CreateEvidenceBundleRequest {
    /// Case ID
    #[validate(length(min = 1, max = 256))]
    pub case_id: String,

    /// Payload ref IDs
    #[validate(length(min = 1, max = 100))]
    pub ref_ids: Vec<String>,

    /// Requester
    #[validate(length(min = 1, max = 256))]
    pub requester: String,

    /// Purpose
    #[validate(length(min = 1, max = 1024))]
    pub purpose: String,
}

/// Evidence bundle response
#[derive(Debug, Serialize)]
pub struct EvidenceBundleResponse {
    /// Bundle ID
    pub bundle_id: String,
    /// Evidence level
    pub evidence_level: EvidenceLevel,
    /// Payload count
    pub payload_count: u64,
    /// Total size
    pub total_size_bytes: u64,
    /// Map commit reference
    pub map_commit_ref: Option<String>,
    /// Receipt ID
    pub receipt_id: Option<String>,
    /// Created at
    pub created_at: DateTime<Utc>,
}

/// Access ticket request
#[derive(Debug, Deserialize, Validate)]
pub struct CreateAccessTicketRequest {
    /// Holder actor ID
    #[validate(length(min = 1, max = 256))]
    pub holder_id: String,

    /// Payload ref IDs
    #[validate(length(min = 1, max = 100))]
    pub ref_ids: Vec<String>,

    /// Permissions
    #[validate(length(min = 1, max = 10))]
    pub permissions: Vec<String>,

    /// Validity duration in seconds
    #[validate(range(min = 60, max = 86400))]
    pub validity_seconds: u64,

    /// Purpose
    #[validate(length(min = 1, max = 1024))]
    pub purpose: String,
}

/// Access ticket response
#[derive(Debug, Serialize)]
pub struct AccessTicketResponse {
    /// Ticket ID
    pub ticket_id: String,
    /// Holder
    pub holder_id: String,
    /// Expires at
    pub expires_at: DateTime<Utc>,
    /// Permissions
    pub permissions: Vec<String>,
    /// Payload count
    pub payload_count: usize,
}

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// Service status
    pub status: String,
    /// Version
    pub version: String,
    /// Storage health
    pub storage_healthy: bool,
    /// Bridge health
    pub bridge_healthy: bool,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Storage stats response
#[derive(Debug, Serialize)]
pub struct StorageStatsResponse {
    /// Total payloads
    pub total_payloads: u64,
    /// Total size in bytes
    pub total_size_bytes: u64,
    /// Hot tier count
    pub hot_count: u64,
    /// Warm tier count
    pub warm_count: u64,
    /// Cold tier count
    pub cold_count: u64,
    /// Backend type
    pub backend_type: String,
}

/// Migrate temperature request
#[derive(Debug, Deserialize, Validate)]
pub struct MigrateTemperatureRequest {
    /// Target temperature
    pub target_temperature: StorageTemperature,
}

/// Tombstone request
#[derive(Debug, Deserialize)]
pub struct TombstoneRequest {
    /// Reason for tombstoning
    pub reason: Option<String>,
}
