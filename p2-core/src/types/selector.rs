//! Payload Selector Types
//!
//! Minimal disclosure selectors for ticketed forensic access.
//! Selectors determine what portion of a sealed payload can be accessed.

use serde::{Deserialize, Serialize};

/// Payload Selector - Minimal disclosure unit
///
/// Determines what portion of a sealed payload the ticket holder can access.
/// Default is Span (fragment-level), which provides good balance between
/// privacy and utility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadSelector {
    /// Selector type
    pub selector_type: SelectorType,

    /// Selector expression
    pub selector_expr: String,

    /// Selector version
    pub version: String,
}

impl Default for PayloadSelector {
    fn default() -> Self {
        Self::digest_only()
    }
}

impl PayloadSelector {
    /// Create a full selector (use with caution)
    pub fn full() -> Self {
        Self {
            selector_type: SelectorType::Full,
            selector_expr: "*".to_string(),
            version: "v1".to_string(),
        }
    }

    /// Create a span (fragment) selector - recommended default
    pub fn span(start: usize, end: usize) -> Self {
        Self {
            selector_type: SelectorType::Span,
            selector_expr: format!("{}:{}", start, end),
            version: "v1".to_string(),
        }
    }

    /// Create a byte range selector
    pub fn byte_range(start_byte: u64, end_byte: u64) -> Self {
        Self {
            selector_type: SelectorType::ByteRange,
            selector_expr: format!("{}-{}", start_byte, end_byte),
            version: "v1".to_string(),
        }
    }

    /// Create a field selector for structured payloads
    pub fn fields(field_paths: Vec<&str>) -> Self {
        Self {
            selector_type: SelectorType::Field,
            selector_expr: field_paths.join(","),
            version: "v1".to_string(),
        }
    }

    /// Create a digest-only selector (most restrictive)
    pub fn digest_only() -> Self {
        Self {
            selector_type: SelectorType::DigestOnly,
            selector_expr: "digest".to_string(),
            version: "v1".to_string(),
        }
    }

    /// Create a redacted selector (returns structure with sensitive data removed)
    pub fn redacted(redaction_policy: &str) -> Self {
        Self {
            selector_type: SelectorType::Redacted,
            selector_expr: redaction_policy.to_string(),
            version: "v1".to_string(),
        }
    }

    /// Check if this selector is a subset of another
    pub fn is_subset_of(&self, other: &PayloadSelector) -> bool {
        match (&self.selector_type, &other.selector_type) {
            // Full contains everything
            (_, SelectorType::Full) => true,
            // DigestOnly is subset of everything
            (SelectorType::DigestOnly, _) => true,
            // Full is not subset of anything except Full
            (SelectorType::Full, _) => false,
            // Same type requires expression comparison
            (SelectorType::Span, SelectorType::Span) => self.span_is_subset(other),
            (SelectorType::ByteRange, SelectorType::ByteRange) => self.range_is_subset(other),
            (a, b) if a == b => self.expr_is_subset(&self.selector_expr, &other.selector_expr),
            // Different types - need specific logic
            _ => false,
        }
    }

    /// Check if this span is a subset of another span
    fn span_is_subset(&self, other: &PayloadSelector) -> bool {
        match (self.parse_span(), other.parse_span()) {
            (Some((a_start, a_end)), Some((b_start, b_end))) => {
                a_start >= b_start && a_end <= b_end
            }
            _ => false,
        }
    }

    /// Check if this byte range is a subset of another byte range
    fn range_is_subset(&self, other: &PayloadSelector) -> bool {
        match (self.parse_byte_range(), other.parse_byte_range()) {
            (Some((a_start, a_end)), Some((b_start, b_end))) => {
                a_start >= b_start && a_end <= b_end
            }
            _ => false,
        }
    }

    /// Check if expression a is subset of expression b (for non-range types)
    fn expr_is_subset(&self, a: &str, b: &str) -> bool {
        a == b || b == "*"
    }

    /// Get the disclosure level (0-100, higher = more disclosure)
    pub fn disclosure_level(&self) -> u8 {
        match self.selector_type {
            SelectorType::DigestOnly => 0,
            SelectorType::Redacted => 20,
            SelectorType::Field => 40,
            SelectorType::Span => 60,
            SelectorType::ByteRange => 70,
            SelectorType::Full => 100,
        }
    }

    /// Check if this selector requires full decryption
    pub fn requires_full_decryption(&self) -> bool {
        matches!(self.selector_type, SelectorType::Full)
    }

    /// Parse span expression into (start, end)
    pub fn parse_span(&self) -> Option<(usize, usize)> {
        if self.selector_type != SelectorType::Span {
            return None;
        }
        let parts: Vec<&str> = self.selector_expr.split(':').collect();
        if parts.len() != 2 {
            return None;
        }
        let start = parts[0].parse().ok()?;
        let end = parts[1].parse().ok()?;
        Some((start, end))
    }

    /// Parse byte range expression into (start, end)
    pub fn parse_byte_range(&self) -> Option<(u64, u64)> {
        if self.selector_type != SelectorType::ByteRange {
            return None;
        }
        let parts: Vec<&str> = self.selector_expr.split('-').collect();
        if parts.len() != 2 {
            return None;
        }
        let start = parts[0].parse().ok()?;
        let end = parts[1].parse().ok()?;
        Some((start, end))
    }

    /// Parse field paths
    pub fn parse_fields(&self) -> Option<Vec<String>> {
        if self.selector_type != SelectorType::Field {
            return None;
        }
        Some(self.selector_expr.split(',').map(|s| s.to_string()).collect())
    }
}

/// Selector type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectorType {
    /// Full payload (use with caution)
    Full,
    /// Fragment/span level (v1 default, recommended)
    Span,
    /// Byte range access
    ByteRange,
    /// Field-level for structured payloads (optional enhancement)
    Field,
    /// Digest only - no content, only verification (most restrictive)
    DigestOnly,
    /// Redacted - structure preserved, sensitive data removed
    Redacted,
}

/// Selector validation result
#[derive(Debug, Clone)]
pub enum SelectorValidation {
    /// Selector is valid
    Valid,
    /// Selector is invalid - expression error
    InvalidExpression(String),
    /// Selector exceeds allowed scope
    ExceedsScope(String),
    /// Selector type not supported for this payload
    TypeNotSupported(String),
}

impl SelectorValidation {
    pub fn is_valid(&self) -> bool {
        matches!(self, SelectorValidation::Valid)
    }
}

// ============================================================================
// Selector Audit Replay (问题13)
// ============================================================================

use chrono::{DateTime, Utc};
use l0_core::types::{ActorId, Digest};

/// Selector operation record for audit replay
///
/// Every selector operation is recorded for potential audit replay.
/// This supports forensic investigation and compliance verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectorOperationRecord {
    /// Record ID
    pub record_id: String,
    /// Ticket ID that authorized this operation
    pub ticket_id: String,
    /// Selector used
    pub selector: PayloadSelector,
    /// Target payload reference
    pub target_payload_ref: String,
    /// Actor who performed the operation
    pub actor: ActorId,
    /// Operation timestamp
    pub timestamp: DateTime<Utc>,
    /// Input digest (before selection)
    pub input_digest: Digest,
    /// Output digest (after selection)
    pub output_digest: Digest,
    /// Bytes accessed
    pub bytes_accessed: u64,
    /// Operation result
    pub result: SelectorOperationResult,
    /// Additional metadata digest
    pub metadata_digest: Option<Digest>,
}

impl SelectorOperationRecord {
    /// Create a new operation record
    pub fn new(
        record_id: String,
        ticket_id: String,
        selector: PayloadSelector,
        target_payload_ref: String,
        actor: ActorId,
        input_digest: Digest,
        output_digest: Digest,
        bytes_accessed: u64,
    ) -> Self {
        Self {
            record_id,
            ticket_id,
            selector,
            target_payload_ref,
            actor,
            timestamp: Utc::now(),
            input_digest,
            output_digest,
            bytes_accessed,
            result: SelectorOperationResult::Success,
            metadata_digest: None,
        }
    }

    /// Create record for failed operation
    pub fn failed(
        record_id: String,
        ticket_id: String,
        selector: PayloadSelector,
        target_payload_ref: String,
        actor: ActorId,
        error: SelectorOperationError,
    ) -> Self {
        Self {
            record_id,
            ticket_id,
            selector,
            target_payload_ref,
            actor,
            timestamp: Utc::now(),
            input_digest: Digest::zero(),
            output_digest: Digest::zero(),
            bytes_accessed: 0,
            result: SelectorOperationResult::Failed(error),
            metadata_digest: None,
        }
    }

    /// Compute verification digest for this record
    pub fn compute_verification_digest(&self) -> Digest {
        let mut data = Vec::new();
        data.extend_from_slice(self.record_id.as_bytes());
        data.extend_from_slice(self.ticket_id.as_bytes());
        data.extend_from_slice(self.target_payload_ref.as_bytes());
        data.extend_from_slice(self.input_digest.as_bytes());
        data.extend_from_slice(self.output_digest.as_bytes());
        data.extend_from_slice(&self.timestamp.timestamp().to_le_bytes());
        Digest::blake3(&data)
    }
}

/// Selector operation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SelectorOperationResult {
    /// Operation succeeded
    Success,
    /// Operation failed
    Failed(SelectorOperationError),
}

/// Selector operation error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SelectorOperationError {
    /// Selector expression invalid
    InvalidSelector(String),
    /// Selector exceeds ticket scope
    ExceedsScope,
    /// Payload not found
    PayloadNotFound,
    /// Payload inaccessible
    PayloadInaccessible,
    /// Decryption failed
    DecryptionFailed,
    /// Ticket invalid
    TicketInvalid,
    /// Internal error
    InternalError(String),
}

/// Selector audit replay request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectorReplayRequest {
    /// Replay request ID
    pub request_id: String,
    /// Original operation record ID
    pub original_record_id: String,
    /// Requestor
    pub requestor: ActorId,
    /// Replay purpose
    pub purpose: ReplayPurpose,
    /// Request timestamp
    pub requested_at: DateTime<Utc>,
    /// Authorization reference (audit mandate, court order, etc.)
    pub authorization_ref: String,
}

/// Purpose of audit replay
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayPurpose {
    /// Forensic investigation
    ForensicInvestigation,
    /// Compliance verification
    ComplianceVerification,
    /// Dispute resolution
    DisputeResolution,
    /// Security audit
    SecurityAudit,
    /// Data integrity check
    DataIntegrityCheck,
}

/// Selector replay result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectorReplayResult {
    /// Replay result ID
    pub result_id: String,
    /// Original record ID
    pub original_record_id: String,
    /// Replay request ID
    pub request_id: String,
    /// Replay status
    pub status: ReplayStatus,
    /// Output matches original
    pub output_matches: bool,
    /// Original output digest
    pub original_output_digest: Digest,
    /// Replayed output digest
    pub replayed_output_digest: Digest,
    /// Replay timestamp
    pub replayed_at: DateTime<Utc>,
    /// Discrepancies found (if any)
    pub discrepancies: Vec<ReplayDiscrepancy>,
    /// Verifier signature
    pub verifier_id: String,
}

impl SelectorReplayResult {
    /// Check if replay was successful and output matches
    pub fn is_verified(&self) -> bool {
        matches!(self.status, ReplayStatus::Completed) && self.output_matches
    }
}

/// Replay status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayStatus {
    /// Replay pending
    Pending,
    /// Replay in progress
    InProgress,
    /// Replay completed
    Completed,
    /// Replay failed
    Failed,
    /// Replay not possible (data unavailable)
    DataUnavailable,
}

/// Discrepancy found during replay
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayDiscrepancy {
    /// Discrepancy type
    pub discrepancy_type: DiscrepancyType,
    /// Description
    pub description: String,
    /// Severity
    pub severity: DiscrepancySeverity,
}

/// Types of discrepancies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscrepancyType {
    /// Output digest mismatch
    OutputMismatch,
    /// Bytes accessed differs
    ByteCountDiffers,
    /// Selector interpretation differs
    SelectorInterpretation,
    /// Timestamp anomaly
    TimestampAnomaly,
    /// Missing metadata
    MissingMetadata,
}

/// Discrepancy severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscrepancySeverity {
    /// Low - minor difference, likely acceptable
    Low,
    /// Medium - notable difference, requires review
    Medium,
    /// High - significant difference, likely issue
    High,
    /// Critical - major discrepancy, integrity concern
    Critical,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_selector_creation() {
        let full = PayloadSelector::full();
        assert_eq!(full.selector_type, SelectorType::Full);
        assert_eq!(full.selector_expr, "*");

        let span = PayloadSelector::span(0, 100);
        assert_eq!(span.selector_type, SelectorType::Span);
        assert_eq!(span.selector_expr, "0:100");

        let digest = PayloadSelector::digest_only();
        assert_eq!(digest.selector_type, SelectorType::DigestOnly);
    }

    #[test]
    fn test_selector_subset() {
        let full = PayloadSelector::full();
        let span = PayloadSelector::span(0, 100);
        let digest = PayloadSelector::digest_only();

        // DigestOnly is subset of everything
        assert!(digest.is_subset_of(&full));
        assert!(digest.is_subset_of(&span));
        assert!(digest.is_subset_of(&digest));

        // Everything is subset of Full
        assert!(span.is_subset_of(&full));
        assert!(full.is_subset_of(&full));

        // Full is not subset of Span
        assert!(!full.is_subset_of(&span));
    }

    #[test]
    fn test_disclosure_level() {
        assert_eq!(PayloadSelector::digest_only().disclosure_level(), 0);
        assert_eq!(PayloadSelector::full().disclosure_level(), 100);
        assert!(PayloadSelector::span(0, 100).disclosure_level() > PayloadSelector::digest_only().disclosure_level());
    }

    #[test]
    fn test_parse_span() {
        let span = PayloadSelector::span(10, 50);
        let (start, end) = span.parse_span().unwrap();
        assert_eq!(start, 10);
        assert_eq!(end, 50);

        let full = PayloadSelector::full();
        assert!(full.parse_span().is_none());
    }

    #[test]
    fn test_parse_fields() {
        let fields = PayloadSelector::fields(vec!["name", "email", "id"]);
        let parsed = fields.parse_fields().unwrap();
        assert_eq!(parsed, vec!["name", "email", "id"]);
    }
}
