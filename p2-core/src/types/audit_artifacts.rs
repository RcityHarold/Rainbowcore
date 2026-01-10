//! Audit Artifacts Types
//!
//! Audit logging for P2 operations - decrypt, export, and sampling.
//! All payload access MUST generate an audit log entry.
//!
//! # HARD RULE: Mandatory Audit Logging
//!
//! Per DSN documentation, audit logging is **NOT optional**:
//!
//! 1. **Decrypt operations**: MUST write `DecryptAuditLog` BEFORE decryption
//! 2. **Export operations**: MUST write `ExportAuditLog` BEFORE export
//! 3. **Ticket operations**: MUST write `TicketAuditLog` for all lifecycle events
//!
//! If audit log write fails, the operation MUST be blocked. This is enforced
//! by the `MandatoryAuditGuard` which wraps all sensitive operations.
//!
//! # Error Handling
//!
//! When audit write fails:
//! - `DecryptOutcome::AuditWriteFailed` is returned
//! - The actual decrypt/export operation is NOT performed
//! - The failure is logged at ERROR level

use super::selector::PayloadSelector;
use chrono::{DateTime, Utc};
use l0_core::types::{ActorId, Digest, ReceiptId};
use serde::{Deserialize, Serialize};

/// Decrypt Audit Log - MUST be written for every decrypt/expand operation
///
/// This is a mandatory audit record. Any decrypt operation without
/// a corresponding audit log is a protocol violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptAuditLog {
    /// Log ID
    pub log_id: String,

    /// Used ticket reference
    pub ticket_ref: String,

    /// Decryptor actor ID
    pub decryptor: ActorId,

    /// Target payload reference
    pub target_payload_ref: String,

    /// Selector actually used
    pub selector_used: PayloadSelector,

    /// Purpose digest (privacy protected, no plaintext)
    pub purpose_digest: Digest,

    /// Result digest (proves what was decrypted)
    pub result_digest: Digest,

    /// Decryption timestamp
    pub decrypted_at: DateTime<Utc>,

    /// Decryption context (call chain path)
    pub context_path: String,

    /// High-risk operation flag
    pub high_risk: bool,

    /// Associated receipt (MUST for high-risk)
    pub receipt_id: Option<ReceiptId>,

    /// Operation outcome
    pub outcome: DecryptOutcome,

    /// Client information
    pub client_info: Option<ClientInfo>,

    /// Consent chain reference
    pub consent_chain_ref: Option<String>,
}

impl DecryptAuditLog {
    /// Create a new decrypt audit log
    pub fn new(
        log_id: String,
        ticket_ref: String,
        decryptor: ActorId,
        target_payload_ref: String,
        selector_used: PayloadSelector,
        purpose_digest: Digest,
        result_digest: Digest,
        context_path: String,
    ) -> Self {
        Self {
            log_id,
            ticket_ref,
            decryptor,
            target_payload_ref,
            selector_used,
            purpose_digest,
            result_digest,
            decrypted_at: Utc::now(),
            context_path,
            high_risk: false,
            receipt_id: None,
            outcome: DecryptOutcome::Success,
            client_info: None,
            consent_chain_ref: None,
        }
    }

    /// Mark as high-risk operation
    pub fn set_high_risk(&mut self, receipt_id: ReceiptId) {
        self.high_risk = true;
        self.receipt_id = Some(receipt_id);
    }

    /// Check if this operation needs P1 anchoring
    pub fn needs_anchoring(&self) -> bool {
        self.high_risk && self.receipt_id.is_none()
    }
}

/// Decrypt operation outcome
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecryptOutcome {
    /// Successful decryption
    Success,
    /// Failed - ticket invalid
    TicketInvalid,
    /// Failed - payload not found
    PayloadNotFound,
    /// Failed - decryption error
    DecryptionError,
    /// Failed - selector out of scope
    SelectorOutOfScope,
    /// Failed - audit write failed
    AuditWriteFailed,
}

/// Client information for audit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    /// Client identifier
    pub client_id: String,
    /// IP address or node ID
    pub source_address: Option<String>,
    /// User agent or SDK version
    pub user_agent: Option<String>,
}

/// Export Audit Log - MUST be written for external exports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportAuditLog {
    /// Log ID
    pub log_id: String,

    /// Used ticket reference
    pub ticket_ref: String,

    /// Exporter actor ID
    pub exporter: ActorId,

    /// Export target (external system identifier)
    pub export_target: String,

    /// Exported payload references
    pub payload_refs: Vec<String>,

    /// Export format
    pub export_format: ExportFormat,

    /// Export content digest
    pub content_digest: Digest,

    /// Export timestamp
    pub exported_at: DateTime<Utc>,

    /// Associated receipt
    pub receipt_id: Option<ReceiptId>,

    /// Export destination type
    pub destination_type: ExportDestinationType,

    /// Redaction applied
    pub redaction_applied: bool,

    /// Redaction policy reference
    pub redaction_policy_ref: Option<String>,
}

impl ExportAuditLog {
    /// Create a new export audit log
    pub fn new(
        log_id: String,
        ticket_ref: String,
        exporter: ActorId,
        export_target: String,
        payload_refs: Vec<String>,
        export_format: ExportFormat,
        content_digest: Digest,
    ) -> Self {
        Self {
            log_id,
            ticket_ref,
            exporter,
            export_target,
            payload_refs,
            export_format,
            content_digest,
            exported_at: Utc::now(),
            receipt_id: None,
            destination_type: ExportDestinationType::External,
            redaction_applied: false,
            redaction_policy_ref: None,
        }
    }

    /// Get export payload count
    pub fn payload_count(&self) -> usize {
        self.payload_refs.len()
    }
}

/// Export format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    /// JSON format
    Json,
    /// CBOR format
    Cbor,
    /// Encrypted bundle
    EncryptedBundle,
    /// CSV format
    Csv,
    /// Raw binary
    Raw,
    /// Other format
    Other,
}

/// Export destination type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportDestinationType {
    /// External system
    External,
    /// Legal/compliance system
    Legal,
    /// Backup system
    Backup,
    /// Migration target
    Migration,
    /// Archive system
    Archive,
}

/// Sampling Artifact - Periodic sampling for integrity verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingArtifact {
    /// Artifact ID
    pub artifact_id: String,

    /// Sampling batch ID
    pub sampling_batch: String,

    /// Sampled payload reference
    pub sampled_payload_ref: String,

    /// Recomputed checksum
    pub recomputed_checksum: Digest,

    /// Original checksum (from sealed_payload_ref)
    pub original_checksum: Digest,

    /// Checksum match result
    pub checksum_match: bool,

    /// Reachability status
    pub reachability: ReachabilityStatus,

    /// Sampling timestamp
    pub sampled_at: DateTime<Utc>,

    /// Sampler node ID
    pub sampler_node_id: String,

    /// Sampling duration (ms)
    pub sampling_duration_ms: u64,

    /// Storage backend type
    pub backend_type: String,

    /// Additional verification results
    pub additional_checks: Vec<AdditionalCheck>,
}

impl SamplingArtifact {
    /// Create a new sampling artifact
    pub fn new(
        artifact_id: String,
        sampling_batch: String,
        sampled_payload_ref: String,
        recomputed_checksum: Digest,
        original_checksum: Digest,
        sampler_node_id: String,
    ) -> Self {
        let checksum_match = recomputed_checksum == original_checksum;
        Self {
            artifact_id,
            sampling_batch,
            sampled_payload_ref,
            recomputed_checksum,
            original_checksum,
            checksum_match,
            reachability: ReachabilityStatus::Reachable,
            sampled_at: Utc::now(),
            sampler_node_id,
            sampling_duration_ms: 0,
            backend_type: "unknown".to_string(),
            additional_checks: Vec::new(),
        }
    }

    /// Check if sampling passed
    pub fn is_pass(&self) -> bool {
        self.checksum_match && matches!(self.reachability, ReachabilityStatus::Reachable)
    }

    /// Check if this needs escalation
    pub fn needs_escalation(&self) -> bool {
        !self.checksum_match || matches!(self.reachability, ReachabilityStatus::Unreachable)
    }
}

/// Reachability status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReachabilityStatus {
    /// Fully reachable
    Reachable,
    /// Unreachable
    Unreachable,
    /// Timeout during access
    Timeout,
    /// Partially reachable (some shards missing)
    PartiallyReachable,
    /// Degraded (accessible but slow)
    Degraded,
}

/// Additional check in sampling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdditionalCheck {
    /// Check name
    pub check_name: String,
    /// Check passed
    pub passed: bool,
    /// Details
    pub details: Option<String>,
}

/// Sampling policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingPolicy {
    /// Policy version
    pub version: String,

    /// Sampling rate (0.0 - 1.0)
    pub sampling_rate: f64,

    /// Minimum samples per batch
    pub min_samples_per_batch: u32,

    /// Maximum samples per batch
    pub max_samples_per_batch: u32,

    /// Batch interval (seconds)
    pub batch_interval_seconds: u64,

    /// Temperature tiers to sample
    pub sample_temperatures: Vec<String>,

    /// Whether to verify checksums
    pub verify_checksums: bool,

    /// Whether to verify reachability
    pub verify_reachability: bool,

    /// Escalation threshold (consecutive failures)
    pub escalation_threshold: u32,
}

impl Default for SamplingPolicy {
    fn default() -> Self {
        Self {
            version: "v1".to_string(),
            sampling_rate: 0.01,  // 1% sampling
            min_samples_per_batch: 10,
            max_samples_per_batch: 1000,
            batch_interval_seconds: 3600,  // Hourly
            sample_temperatures: vec!["hot".to_string(), "warm".to_string(), "cold".to_string()],
            verify_checksums: true,
            verify_reachability: true,
            escalation_threshold: 3,
        }
    }
}

/// Ticket Audit Log - Records all ticket lifecycle events
///
/// This is a mandatory audit record for ticket operations.
/// All ticket issuance, use, and revocation MUST be logged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketAuditLog {
    /// Log ID
    pub log_id: String,

    /// Ticket ID being operated on
    pub ticket_id: String,

    /// Operation type
    pub operation: TicketOperation,

    /// Actor performing the operation
    pub actor: ActorId,

    /// Target resource reference (for issue/use operations)
    pub target_resource_ref: Option<String>,

    /// Ticket holder (for issue operations)
    pub holder: Option<ActorId>,

    /// Operation timestamp
    pub timestamp: DateTime<Utc>,

    /// Operation outcome
    pub outcome: TicketOperationOutcome,

    /// Reason (for revocation or failure)
    pub reason: Option<String>,

    /// Ticket permissions (for issue operations)
    pub permissions: Vec<String>,

    /// Ticket validity duration (seconds, for issue operations)
    pub validity_seconds: Option<u32>,

    /// Usage count after operation (for use operations)
    pub usage_count: Option<u32>,

    /// Remaining uses (for use operations)
    pub remaining_uses: Option<u32>,

    /// Consent reference (for issue operations)
    pub consent_ref: Option<String>,

    /// Client information
    pub client_info: Option<ClientInfo>,
}

impl TicketAuditLog {
    /// Create a new ticket audit log for issuance
    pub fn issue(
        log_id: String,
        ticket_id: String,
        issuer: ActorId,
        holder: ActorId,
        target_resource_ref: String,
        permissions: Vec<String>,
        validity_seconds: u32,
        consent_ref: Option<String>,
    ) -> Self {
        Self {
            log_id,
            ticket_id,
            operation: TicketOperation::Issue,
            actor: issuer,
            target_resource_ref: Some(target_resource_ref),
            holder: Some(holder),
            timestamp: Utc::now(),
            outcome: TicketOperationOutcome::Success,
            reason: None,
            permissions,
            validity_seconds: Some(validity_seconds),
            usage_count: None,
            remaining_uses: None,
            consent_ref,
            client_info: None,
        }
    }

    /// Create a new ticket audit log for usage
    pub fn use_ticket(
        log_id: String,
        ticket_id: String,
        user: ActorId,
        target_resource_ref: String,
        usage_count: u32,
        remaining_uses: Option<u32>,
    ) -> Self {
        Self {
            log_id,
            ticket_id,
            operation: TicketOperation::Use,
            actor: user,
            target_resource_ref: Some(target_resource_ref),
            holder: None,
            timestamp: Utc::now(),
            outcome: TicketOperationOutcome::Success,
            reason: None,
            permissions: Vec::new(),
            validity_seconds: None,
            usage_count: Some(usage_count),
            remaining_uses,
            consent_ref: None,
            client_info: None,
        }
    }

    /// Create a new ticket audit log for revocation
    pub fn revoke(
        log_id: String,
        ticket_id: String,
        revoker: ActorId,
        reason: String,
    ) -> Self {
        Self {
            log_id,
            ticket_id,
            operation: TicketOperation::Revoke,
            actor: revoker,
            target_resource_ref: None,
            holder: None,
            timestamp: Utc::now(),
            outcome: TicketOperationOutcome::Success,
            reason: Some(reason),
            permissions: Vec::new(),
            validity_seconds: None,
            usage_count: None,
            remaining_uses: None,
            consent_ref: None,
            client_info: None,
        }
    }

    /// Create a failed operation log
    pub fn failed(
        log_id: String,
        ticket_id: String,
        operation: TicketOperation,
        actor: ActorId,
        outcome: TicketOperationOutcome,
        reason: String,
    ) -> Self {
        Self {
            log_id,
            ticket_id,
            operation,
            actor,
            target_resource_ref: None,
            holder: None,
            timestamp: Utc::now(),
            outcome,
            reason: Some(reason),
            permissions: Vec::new(),
            validity_seconds: None,
            usage_count: None,
            remaining_uses: None,
            consent_ref: None,
            client_info: None,
        }
    }

    /// Set client information
    pub fn with_client_info(mut self, client_info: ClientInfo) -> Self {
        self.client_info = Some(client_info);
        self
    }

    /// Check if operation was successful
    pub fn is_success(&self) -> bool {
        matches!(self.outcome, TicketOperationOutcome::Success)
    }
}

/// Ticket operation type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketOperation {
    /// Ticket issuance
    Issue,
    /// Ticket usage (access)
    Use,
    /// Ticket revocation
    Revoke,
    /// Permission check
    PermissionCheck,
    /// Ticket refresh
    Refresh,
}

/// Ticket operation outcome
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketOperationOutcome {
    /// Operation successful
    Success,
    /// Ticket not found
    NotFound,
    /// Ticket expired
    Expired,
    /// Ticket already revoked
    AlreadyRevoked,
    /// Ticket exhausted (max uses reached)
    Exhausted,
    /// Permission denied
    PermissionDenied,
    /// Invalid request
    InvalidRequest,
    /// Internal error
    InternalError,
}

/// Audit summary for a time period
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSummary {
    /// Summary ID
    pub summary_id: String,

    /// Period start
    pub period_start: DateTime<Utc>,

    /// Period end
    pub period_end: DateTime<Utc>,

    /// Total decrypt operations
    pub total_decrypts: u64,

    /// Successful decrypts
    pub successful_decrypts: u64,

    /// Failed decrypts
    pub failed_decrypts: u64,

    /// High-risk operations
    pub high_risk_operations: u64,

    /// Total exports
    pub total_exports: u64,

    /// Sampling results
    pub sampling_pass_rate: f64,

    /// Unique accessors
    pub unique_accessors: u64,

    /// Most accessed payloads (top N)
    pub top_accessed_payloads: Vec<(String, u64)>,
}

// ============================================================================
// Mandatory Audit Enforcement
// ============================================================================

/// Audit write result
#[derive(Debug, Clone)]
pub enum AuditWriteResult {
    /// Audit log written successfully
    Success { log_id: String },
    /// Audit write failed
    Failed { error: AuditWriteError },
}

impl AuditWriteResult {
    /// Check if write was successful
    pub fn is_success(&self) -> bool {
        matches!(self, AuditWriteResult::Success { .. })
    }

    /// Get log ID if successful
    pub fn log_id(&self) -> Option<&str> {
        match self {
            AuditWriteResult::Success { log_id } => Some(log_id),
            _ => None,
        }
    }
}

/// Audit write error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditWriteError {
    /// Error code
    pub code: AuditErrorCode,
    /// Error message
    pub message: String,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Retry allowed
    pub retry_allowed: bool,
}

impl AuditWriteError {
    /// Create a new audit write error
    pub fn new(code: AuditErrorCode, message: &str) -> Self {
        Self {
            code,
            message: message.to_string(),
            timestamp: Utc::now(),
            retry_allowed: matches!(code, AuditErrorCode::StorageUnavailable | AuditErrorCode::Timeout),
        }
    }
}

impl std::fmt::Display for AuditWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AuditWriteError({:?}): {}", self.code, self.message)
    }
}

impl std::error::Error for AuditWriteError {}

/// Audit error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditErrorCode {
    /// Storage backend unavailable
    StorageUnavailable,
    /// Write timeout
    Timeout,
    /// Invalid audit data
    InvalidData,
    /// Duplicate log ID
    DuplicateLogId,
    /// Quota exceeded
    QuotaExceeded,
    /// Internal error
    InternalError,
}

/// Mandatory Audit Guard - Ensures audit is written before operation
///
/// # HARD RULE
///
/// This guard enforces that audit logs are written BEFORE any sensitive
/// operation is performed. The operation cannot proceed without a successful
/// audit write.
///
/// # Usage
///
/// ```rust,ignore
/// // Create guard - this writes the audit log
/// let guard = MandatoryAuditGuard::new_decrypt(audit_log, writer).await?;
///
/// // Only after guard is successfully created can you perform the operation
/// let result = perform_decrypt(...);
///
/// // Update the guard with the result
/// guard.complete_with_result(result).await?;
/// ```
#[derive(Debug)]
pub struct MandatoryAuditGuard {
    /// Audit log ID
    log_id: String,
    /// Operation type
    operation_type: MandatoryAuditOperation,
    /// Guard state
    state: AuditGuardState,
    /// Created timestamp
    created_at: DateTime<Utc>,
}

/// Audit guard state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditGuardState {
    /// Audit written, operation pending
    Pending,
    /// Operation completed successfully
    Completed,
    /// Operation failed
    Failed,
    /// Guard abandoned (operation not completed)
    Abandoned,
}

/// Mandatory audit operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MandatoryAuditOperation {
    /// Decrypt operation
    Decrypt,
    /// Export operation
    Export,
    /// Ticket issuance
    TicketIssue,
    /// Ticket usage
    TicketUse,
    /// Ticket revocation
    TicketRevoke,
}

impl MandatoryAuditGuard {
    /// Create a new audit guard with pre-written log
    ///
    /// The audit log MUST already be written successfully before calling this.
    /// This function just wraps the log ID and tracks completion.
    pub fn from_written_log(log_id: String, operation_type: MandatoryAuditOperation) -> Self {
        Self {
            log_id,
            operation_type,
            state: AuditGuardState::Pending,
            created_at: Utc::now(),
        }
    }

    /// Get the log ID
    pub fn log_id(&self) -> &str {
        &self.log_id
    }

    /// Get the operation type
    pub fn operation_type(&self) -> MandatoryAuditOperation {
        self.operation_type
    }

    /// Get the guard state
    pub fn state(&self) -> AuditGuardState {
        self.state
    }

    /// Mark operation as completed successfully
    pub fn mark_completed(&mut self) {
        if self.state == AuditGuardState::Pending {
            self.state = AuditGuardState::Completed;
        }
    }

    /// Mark operation as failed
    pub fn mark_failed(&mut self) {
        if self.state == AuditGuardState::Pending {
            self.state = AuditGuardState::Failed;
        }
    }

    /// Check if operation can proceed
    ///
    /// Returns true only if the audit was written and operation is pending
    pub fn can_proceed(&self) -> bool {
        self.state == AuditGuardState::Pending
    }

    /// Get duration since guard creation
    pub fn duration_ms(&self) -> i64 {
        (Utc::now() - self.created_at).num_milliseconds()
    }
}

impl Drop for MandatoryAuditGuard {
    fn drop(&mut self) {
        // If guard is dropped while still pending, log a warning
        if self.state == AuditGuardState::Pending {
            self.state = AuditGuardState::Abandoned;
            tracing::warn!(
                log_id = %self.log_id,
                operation_type = ?self.operation_type,
                "MandatoryAuditGuard dropped while operation still pending - audit may be incomplete"
            );
        }
    }
}

/// Trait for audit log writers
///
/// Implementations MUST ensure durability before returning success.
/// A successful write means the log is guaranteed to be persisted.
#[async_trait::async_trait]
pub trait AuditLogWriter: Send + Sync {
    /// Write a decrypt audit log
    ///
    /// MUST be called BEFORE the actual decrypt operation.
    async fn write_decrypt_log(&self, log: &DecryptAuditLog) -> AuditWriteResult;

    /// Write an export audit log
    ///
    /// MUST be called BEFORE the actual export operation.
    async fn write_export_log(&self, log: &ExportAuditLog) -> AuditWriteResult;

    /// Write a ticket audit log
    ///
    /// MUST be called for all ticket lifecycle events.
    async fn write_ticket_log(&self, log: &TicketAuditLog) -> AuditWriteResult;

    /// Write a sampling artifact
    async fn write_sampling_artifact(&self, artifact: &SamplingArtifact) -> AuditWriteResult;

    /// Update an existing log (e.g., to add outcome after operation)
    async fn update_log_outcome(&self, log_id: &str, outcome: &str) -> AuditWriteResult;
}

/// Helper function to create a mandatory audit guard for decrypt operations
///
/// This is the recommended way to ensure audit compliance:
///
/// ```rust,ignore
/// let guard = create_decrypt_audit_guard(
///     audit_log,
///     &audit_writer,
/// ).await?;
///
/// // Audit is now written - safe to proceed
/// let result = decrypt_payload(...);
///
/// guard.mark_completed(); // or mark_failed()
/// ```
pub async fn create_decrypt_audit_guard<W: AuditLogWriter>(
    log: &DecryptAuditLog,
    writer: &W,
) -> Result<MandatoryAuditGuard, AuditWriteError> {
    match writer.write_decrypt_log(log).await {
        AuditWriteResult::Success { log_id } => {
            Ok(MandatoryAuditGuard::from_written_log(log_id, MandatoryAuditOperation::Decrypt))
        }
        AuditWriteResult::Failed { error } => {
            tracing::error!(
                ticket_ref = %log.ticket_ref,
                target_payload = %log.target_payload_ref,
                error = %error,
                "MANDATORY AUDIT WRITE FAILED - blocking decrypt operation"
            );
            Err(error)
        }
    }
}

/// Helper function to create a mandatory audit guard for export operations
pub async fn create_export_audit_guard<W: AuditLogWriter>(
    log: &ExportAuditLog,
    writer: &W,
) -> Result<MandatoryAuditGuard, AuditWriteError> {
    match writer.write_export_log(log).await {
        AuditWriteResult::Success { log_id } => {
            Ok(MandatoryAuditGuard::from_written_log(log_id, MandatoryAuditOperation::Export))
        }
        AuditWriteResult::Failed { error } => {
            tracing::error!(
                ticket_ref = %log.ticket_ref,
                export_target = %log.export_target,
                error = %error,
                "MANDATORY AUDIT WRITE FAILED - blocking export operation"
            );
            Err(error)
        }
    }
}

/// Helper function to create a mandatory audit guard for ticket operations
pub async fn create_ticket_audit_guard<W: AuditLogWriter>(
    log: &TicketAuditLog,
    writer: &W,
) -> Result<MandatoryAuditGuard, AuditWriteError> {
    let operation_type = match log.operation {
        TicketOperation::Issue => MandatoryAuditOperation::TicketIssue,
        TicketOperation::Use => MandatoryAuditOperation::TicketUse,
        TicketOperation::Revoke => MandatoryAuditOperation::TicketRevoke,
        _ => MandatoryAuditOperation::TicketUse, // Default for other operations
    };

    match writer.write_ticket_log(log).await {
        AuditWriteResult::Success { log_id } => {
            Ok(MandatoryAuditGuard::from_written_log(log_id, operation_type))
        }
        AuditWriteResult::Failed { error } => {
            tracing::error!(
                ticket_id = %log.ticket_id,
                operation = ?log.operation,
                error = %error,
                "MANDATORY AUDIT WRITE FAILED - blocking ticket operation"
            );
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypt_audit_log() {
        let log = DecryptAuditLog::new(
            "log:001".to_string(),
            "ticket:001".to_string(),
            ActorId::new("actor:decryptor"),
            "payload:001".to_string(),
            PayloadSelector::span(0, 100),
            Digest::zero(),
            Digest::zero(),
            "/api/v1/decrypt".to_string(),
        );

        assert!(!log.high_risk);
        assert!(!log.needs_anchoring());
        assert_eq!(log.outcome, DecryptOutcome::Success);
    }

    #[test]
    fn test_high_risk_audit() {
        let mut log = DecryptAuditLog::new(
            "log:002".to_string(),
            "ticket:001".to_string(),
            ActorId::new("actor:decryptor"),
            "payload:001".to_string(),
            PayloadSelector::full(),
            Digest::zero(),
            Digest::zero(),
            "/api/v1/decrypt".to_string(),
        );

        log.set_high_risk(ReceiptId("receipt:001".to_string()));
        assert!(log.high_risk);
        assert!(!log.needs_anchoring()); // Has receipt now
    }

    #[test]
    fn test_sampling_artifact() {
        let checksum = Digest::blake3(b"test data");
        let artifact = SamplingArtifact::new(
            "sample:001".to_string(),
            "batch:001".to_string(),
            "payload:001".to_string(),
            checksum.clone(),
            checksum,
            "node:sampler".to_string(),
        );

        assert!(artifact.is_pass());
        assert!(artifact.checksum_match);
        assert!(!artifact.needs_escalation());
    }

    #[test]
    fn test_sampling_failure() {
        let artifact = SamplingArtifact::new(
            "sample:002".to_string(),
            "batch:001".to_string(),
            "payload:001".to_string(),
            Digest::blake3(b"data1"),
            Digest::blake3(b"data2"),
            "node:sampler".to_string(),
        );

        assert!(!artifact.is_pass());
        assert!(!artifact.checksum_match);
        assert!(artifact.needs_escalation());
    }

    #[test]
    fn test_export_format() {
        let format = ExportFormat::Json;
        let json = serde_json::to_string(&format).unwrap();
        assert_eq!(json, "\"json\"");
    }

    #[test]
    fn test_default_sampling_policy() {
        let policy = SamplingPolicy::default();
        assert_eq!(policy.sampling_rate, 0.01);
        assert!(policy.verify_checksums);
    }

    #[test]
    fn test_audit_write_result() {
        let success = AuditWriteResult::Success {
            log_id: "log:001".to_string(),
        };
        assert!(success.is_success());
        assert_eq!(success.log_id(), Some("log:001"));

        let error = AuditWriteError::new(AuditErrorCode::StorageUnavailable, "Storage down");
        let failed = AuditWriteResult::Failed { error };
        assert!(!failed.is_success());
        assert_eq!(failed.log_id(), None);
    }

    #[test]
    fn test_audit_write_error() {
        let error = AuditWriteError::new(AuditErrorCode::StorageUnavailable, "Backend unavailable");
        assert!(error.retry_allowed);
        assert_eq!(error.code, AuditErrorCode::StorageUnavailable);

        let error2 = AuditWriteError::new(AuditErrorCode::InvalidData, "Bad format");
        assert!(!error2.retry_allowed);
    }

    #[test]
    fn test_mandatory_audit_guard() {
        let mut guard = MandatoryAuditGuard::from_written_log(
            "log:001".to_string(),
            MandatoryAuditOperation::Decrypt,
        );

        assert_eq!(guard.log_id(), "log:001");
        assert_eq!(guard.operation_type(), MandatoryAuditOperation::Decrypt);
        assert_eq!(guard.state(), AuditGuardState::Pending);
        assert!(guard.can_proceed());

        guard.mark_completed();
        assert_eq!(guard.state(), AuditGuardState::Completed);
        assert!(!guard.can_proceed());
    }

    #[test]
    fn test_mandatory_audit_guard_failed() {
        let mut guard = MandatoryAuditGuard::from_written_log(
            "log:002".to_string(),
            MandatoryAuditOperation::Export,
        );

        guard.mark_failed();
        assert_eq!(guard.state(), AuditGuardState::Failed);
        assert!(!guard.can_proceed());
    }

    #[test]
    fn test_ticket_audit_log_issue() {
        let log = TicketAuditLog::issue(
            "log:001".to_string(),
            "ticket:001".to_string(),
            ActorId::new("issuer:001"),
            ActorId::new("holder:001"),
            "payload:001".to_string(),
            vec!["read".to_string()],
            3600,
            Some("consent:001".to_string()),
        );

        assert_eq!(log.operation, TicketOperation::Issue);
        assert!(log.is_success());
        assert_eq!(log.validity_seconds, Some(3600));
    }

    #[test]
    fn test_ticket_audit_log_use() {
        let log = TicketAuditLog::use_ticket(
            "log:002".to_string(),
            "ticket:001".to_string(),
            ActorId::new("user:001"),
            "payload:001".to_string(),
            1,
            Some(4),
        );

        assert_eq!(log.operation, TicketOperation::Use);
        assert_eq!(log.usage_count, Some(1));
        assert_eq!(log.remaining_uses, Some(4));
    }

    #[test]
    fn test_ticket_audit_log_revoke() {
        let log = TicketAuditLog::revoke(
            "log:003".to_string(),
            "ticket:001".to_string(),
            ActorId::new("admin:001"),
            "Policy violation".to_string(),
        );

        assert_eq!(log.operation, TicketOperation::Revoke);
        assert_eq!(log.reason, Some("Policy violation".to_string()));
    }
}
