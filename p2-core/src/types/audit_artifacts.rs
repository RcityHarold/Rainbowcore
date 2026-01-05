//! Audit Artifacts Types
//!
//! Audit logging for P2 operations - decrypt, export, and sampling.
//! All payload access MUST generate an audit log entry.

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
}
