//! P2 Ledger Traits
//!
//! Trait definitions for P2 ledger operations.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use l0_core::types::{ActorId, Digest, ReceiptId};

use crate::error::P2Result;
use crate::types::{
    AccessTicket, DecryptAuditLog, EvidenceBundle, ExportAuditLog, FullResurrectionSnapshot,
    PayloadSelector, SamplingArtifact, SealedPayloadRef, SkeletonSnapshot, TicketPermission,
    TicketRequest,
};

/// Snapshot Ledger - manages R0/R1 resurrection snapshots
#[async_trait]
pub trait SnapshotLedger: Send + Sync {
    /// Store an R0 skeleton snapshot
    async fn store_r0(&self, snapshot: SkeletonSnapshot) -> P2Result<String>;

    /// Store an R1 full resurrection snapshot
    async fn store_r1(&self, snapshot: FullResurrectionSnapshot) -> P2Result<String>;

    /// Get R0 snapshot by ID
    async fn get_r0(&self, snapshot_id: &str) -> P2Result<Option<SkeletonSnapshot>>;

    /// Get R1 snapshot by ID
    async fn get_r1(&self, snapshot_id: &str) -> P2Result<Option<FullResurrectionSnapshot>>;

    /// List R0 snapshots for an actor
    async fn list_r0_for_actor(
        &self,
        actor_id: &ActorId,
        limit: usize,
    ) -> P2Result<Vec<SkeletonSnapshot>>;

    /// List R1 snapshots for an actor
    async fn list_r1_for_actor(
        &self,
        actor_id: &ActorId,
        limit: usize,
    ) -> P2Result<Vec<FullResurrectionSnapshot>>;

    /// Get the latest R0 for an actor
    async fn get_latest_r0(&self, actor_id: &ActorId) -> P2Result<Option<SkeletonSnapshot>>;

    /// Get the latest R1 for an actor
    async fn get_latest_r1(&self, actor_id: &ActorId) -> P2Result<Option<FullResurrectionSnapshot>>;

    /// Verify snapshot integrity
    async fn verify_snapshot(&self, snapshot_id: &str) -> P2Result<bool>;
}

/// Evidence Ledger - manages evidence bundles
#[async_trait]
pub trait EvidenceLedger: Send + Sync {
    /// Create an evidence bundle
    async fn create_bundle(&self, bundle: EvidenceBundle) -> P2Result<String>;

    /// Get evidence bundle by ID
    async fn get_bundle(&self, bundle_id: &str) -> P2Result<Option<EvidenceBundle>>;

    /// List bundles for a case
    async fn list_bundles_for_case(
        &self,
        case_ref: &str,
        limit: usize,
    ) -> P2Result<Vec<EvidenceBundle>>;

    /// List bundles by submitter
    async fn list_bundles_by_submitter(
        &self,
        submitter: &ActorId,
        limit: usize,
    ) -> P2Result<Vec<EvidenceBundle>>;

    /// Update bundle with receipt (after P1 commitment)
    async fn set_bundle_receipt(
        &self,
        bundle_id: &str,
        receipt_id: ReceiptId,
    ) -> P2Result<()>;

    /// Update bundle with map commit reference
    async fn set_bundle_map_commit(
        &self,
        bundle_id: &str,
        map_commit_ref: String,
    ) -> P2Result<()>;

    /// Verify bundle against P1 commitment
    async fn verify_bundle(&self, bundle_id: &str, expected_digest: &Digest) -> P2Result<bool>;
}

/// Ticket Ledger - manages access tickets
#[async_trait]
pub trait TicketLedger: Send + Sync {
    /// Issue a new access ticket
    async fn issue_ticket(&self, request: TicketRequest, issuer: &ActorId) -> P2Result<AccessTicket>;

    /// Get ticket by ID
    async fn get_ticket(&self, ticket_id: &str) -> P2Result<Option<AccessTicket>>;

    /// Validate and use a ticket
    async fn use_ticket(&self, ticket_id: &str) -> P2Result<AccessTicket>;

    /// Revoke a ticket
    async fn revoke_ticket(&self, ticket_id: &str, reason: &str) -> P2Result<()>;

    /// List tickets by holder
    async fn list_tickets_by_holder(
        &self,
        holder: &ActorId,
        include_expired: bool,
    ) -> P2Result<Vec<AccessTicket>>;

    /// List tickets for a resource
    async fn list_tickets_for_resource(
        &self,
        resource_ref: &str,
    ) -> P2Result<Vec<AccessTicket>>;

    /// Check if a ticket allows a specific operation
    async fn check_permission(
        &self,
        ticket_id: &str,
        permission: TicketPermission,
        selector: &PayloadSelector,
    ) -> P2Result<bool>;
}

/// Audit Ledger - manages audit logs
#[async_trait]
pub trait AuditLedger: Send + Sync {
    /// Record a decrypt audit log (MUST for every decrypt)
    async fn record_decrypt(&self, log: DecryptAuditLog) -> P2Result<String>;

    /// Record an export audit log
    async fn record_export(&self, log: ExportAuditLog) -> P2Result<String>;

    /// Record a sampling artifact
    async fn record_sampling(&self, artifact: SamplingArtifact) -> P2Result<String>;

    /// Get decrypt logs for a payload
    async fn get_decrypt_logs_for_payload(
        &self,
        payload_ref: &str,
        limit: usize,
    ) -> P2Result<Vec<DecryptAuditLog>>;

    /// Get decrypt logs by decryptor
    async fn get_decrypt_logs_by_actor(
        &self,
        actor_id: &ActorId,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> P2Result<Vec<DecryptAuditLog>>;

    /// Get export logs for a payload
    async fn get_export_logs_for_payload(
        &self,
        payload_ref: &str,
    ) -> P2Result<Vec<ExportAuditLog>>;

    /// Get sampling artifacts for a batch
    async fn get_sampling_batch(&self, batch_id: &str) -> P2Result<Vec<SamplingArtifact>>;

    /// Get failed samplings (for escalation)
    async fn get_failed_samplings(&self, limit: usize) -> P2Result<Vec<SamplingArtifact>>;

    /// Check if decrypt was audited (for verification)
    async fn verify_decrypt_audited(
        &self,
        ticket_ref: &str,
        payload_ref: &str,
        at: DateTime<Utc>,
    ) -> P2Result<bool>;
}

/// Payload Store - manages sealed payload storage
#[async_trait]
pub trait PayloadStore: Send + Sync {
    /// Store a sealed payload
    async fn store(&self, data: &[u8], metadata: PayloadMetadata) -> P2Result<SealedPayloadRef>;

    /// Retrieve a sealed payload
    async fn retrieve(&self, ref_id: &str) -> P2Result<Vec<u8>>;

    /// Check if a payload exists
    async fn exists(&self, ref_id: &str) -> P2Result<bool>;

    /// Get payload metadata
    async fn get_metadata(&self, ref_id: &str) -> P2Result<SealedPayloadRef>;

    /// Tombstone a payload (right to be forgotten)
    async fn tombstone(&self, ref_id: &str) -> P2Result<()>;

    /// Verify payload integrity
    async fn verify_integrity(&self, ref_id: &str) -> P2Result<bool>;

    /// Update payload temperature
    async fn update_temperature(
        &self,
        ref_id: &str,
        temperature: crate::types::StorageTemperature,
    ) -> P2Result<()>;
}

/// Payload metadata for storage
#[derive(Debug, Clone)]
pub struct PayloadMetadata {
    /// Content type
    pub content_type: String,
    /// Encryption key version
    pub encryption_key_version: String,
    /// Storage temperature
    pub temperature: crate::types::StorageTemperature,
    /// Retention policy reference
    pub retention_policy_ref: Option<String>,
    /// Tags
    pub tags: Vec<String>,
}

impl Default for PayloadMetadata {
    fn default() -> Self {
        Self {
            content_type: "application/octet-stream".to_string(),
            encryption_key_version: "v1".to_string(),
            temperature: crate::types::StorageTemperature::Hot,
            retention_policy_ref: None,
            tags: Vec::new(),
        }
    }
}
