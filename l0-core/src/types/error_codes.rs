//! Unified Error Codes for L0/P2 Protocol
//!
//! This module defines standard error codes that must be used consistently
//! across all modules for API responses and error handling.
//!
//! # Error Code Format
//!
//! Error codes follow the pattern: `{CATEGORY}_{SUBCATEGORY}_{SPECIFIC}`
//! - Category: Major error category (VERSION, MAP, TICKET, AUDIT, etc.)
//! - Subcategory: Specific area within category
//! - Specific: Detailed error type

use serde::{Deserialize, Serialize};
use std::fmt;

/// Standard error code for protocol operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    // ========== Version Errors (1xxx) ==========
    /// Version drift detected between components
    VersionDrift,
    /// Unknown or unsupported version
    UnknownVersion,
    /// Version mismatch in request
    VersionMismatch,
    /// Version upgrade required
    VersionUpgradeRequired,
    /// Canonicalization version incompatible
    CanonicalizationIncompatible,
    /// Signer set version expired
    SignerSetExpired,

    // ========== Map Commit Errors (2xxx) ==========
    /// Map commit reference not found
    MapCommitNotFound,
    /// Map commit mismatch (hash doesn't match)
    MapCommitMismatch,
    /// Map commit verification failed
    MapCommitVerificationFailed,
    /// Payload map entry missing
    PayloadMapEntryMissing,
    /// Duplicate map commit
    MapCommitDuplicate,
    /// Map commit expired
    MapCommitExpired,

    // ========== Ticket Errors (3xxx) ==========
    /// Ticket not found
    TicketNotFound,
    /// Ticket scope invalid
    TicketScopeInvalid,
    /// Ticket expired
    TicketExpired,
    /// Ticket already used (max uses exceeded)
    TicketExhausted,
    /// Ticket revoked
    TicketRevoked,
    /// Ticket permission denied
    TicketPermissionDenied,
    /// Ticket delegation chain invalid
    TicketDelegationInvalid,

    // ========== Audit Errors (4xxx) ==========
    /// Decrypt audit log missing
    DecryptAuditMissing,
    /// Export audit log missing
    ExportAuditMissing,
    /// Sampling audit failed
    SamplingAuditFailed,
    /// Audit chain broken
    AuditChainBroken,
    /// Audit verification failed
    AuditVerificationFailed,
    /// Mandatory audit not recorded
    MandatoryAuditMissing,

    // ========== Evidence Errors (5xxx) ==========
    /// Evidence level insufficient
    EvidenceLevelInsufficient,
    /// Evidence bundle not found
    EvidenceBundleNotFound,
    /// Evidence corrupted
    EvidenceCorrupted,
    /// Evidence expired
    EvidenceExpired,
    /// Receipt missing for A-level
    ReceiptMissing,

    // ========== Storage Errors (6xxx) ==========
    /// Payload not found
    PayloadNotFound,
    /// Payload corrupted
    PayloadCorrupted,
    /// Storage unavailable
    StorageUnavailable,
    /// Append-only violation
    AppendOnlyViolation,
    /// Zero-plaintext violation (attempted to store unencrypted data)
    PlaintextViolation,
    /// Tombstone required
    TombstoneRequired,

    // ========== Consent Errors (7xxx) ==========
    /// Consent not found
    ConsentNotFound,
    /// Consent expired
    ConsentExpired,
    /// Consent revoked
    ConsentRevoked,
    /// Consent scope exceeded
    ConsentScopeExceeded,
    /// Delegation chain too deep
    DelegationChainTooDeep,
    /// Emergency override expired
    EmergencyOverrideExpired,

    // ========== Actor Errors (8xxx) ==========
    /// Actor not found
    ActorNotFound,
    /// Actor suspended
    ActorSuspended,
    /// Actor not authorized
    ActorNotAuthorized,
    /// TipWitness missing
    TipWitnessMissing,
    /// TipWitness stale
    TipWitnessStale,

    // ========== Backfill Errors (9xxx) ==========
    /// Backfill in progress
    BackfillInProgress,
    /// Backfill failed
    BackfillFailed,
    /// Backfill window expired
    BackfillWindowExpired,
    /// Continuity check failed
    ContinuityCheckFailed,
    /// Gap unacceptable
    GapUnacceptable,

    // ========== Snapshot Errors (10xxx) ==========
    /// Snapshot not found
    SnapshotNotFound,
    /// Snapshot corrupted
    SnapshotCorrupted,
    /// R0 snapshot missing (local-only mode)
    R0SnapshotMissing,
    /// R1 snapshot incomplete
    R1SnapshotIncomplete,
    /// Snapshot verification failed
    SnapshotVerificationFailed,

    // ========== Node Errors (11xxx) ==========
    /// Node not registered
    NodeNotRegistered,
    /// Node banned
    NodeBanned,
    /// Node trust insufficient
    NodeTrustInsufficient,
    /// Node admission denied
    NodeAdmissionDenied,

    // ========== General Errors (0xxx) ==========
    /// Unknown error
    Unknown,
    /// Internal error
    Internal,
    /// Invalid request
    InvalidRequest,
    /// Rate limited
    RateLimited,
    /// Service unavailable
    ServiceUnavailable,
    /// Timeout
    Timeout,
}

impl ErrorCode {
    /// Get numeric code for this error
    pub fn numeric_code(&self) -> u32 {
        match self {
            // Version Errors (1xxx)
            ErrorCode::VersionDrift => 1001,
            ErrorCode::UnknownVersion => 1002,
            ErrorCode::VersionMismatch => 1003,
            ErrorCode::VersionUpgradeRequired => 1004,
            ErrorCode::CanonicalizationIncompatible => 1005,
            ErrorCode::SignerSetExpired => 1006,

            // Map Commit Errors (2xxx)
            ErrorCode::MapCommitNotFound => 2001,
            ErrorCode::MapCommitMismatch => 2002,
            ErrorCode::MapCommitVerificationFailed => 2003,
            ErrorCode::PayloadMapEntryMissing => 2004,
            ErrorCode::MapCommitDuplicate => 2005,
            ErrorCode::MapCommitExpired => 2006,

            // Ticket Errors (3xxx)
            ErrorCode::TicketNotFound => 3001,
            ErrorCode::TicketScopeInvalid => 3002,
            ErrorCode::TicketExpired => 3003,
            ErrorCode::TicketExhausted => 3004,
            ErrorCode::TicketRevoked => 3005,
            ErrorCode::TicketPermissionDenied => 3006,
            ErrorCode::TicketDelegationInvalid => 3007,

            // Audit Errors (4xxx)
            ErrorCode::DecryptAuditMissing => 4001,
            ErrorCode::ExportAuditMissing => 4002,
            ErrorCode::SamplingAuditFailed => 4003,
            ErrorCode::AuditChainBroken => 4004,
            ErrorCode::AuditVerificationFailed => 4005,
            ErrorCode::MandatoryAuditMissing => 4006,

            // Evidence Errors (5xxx)
            ErrorCode::EvidenceLevelInsufficient => 5001,
            ErrorCode::EvidenceBundleNotFound => 5002,
            ErrorCode::EvidenceCorrupted => 5003,
            ErrorCode::EvidenceExpired => 5004,
            ErrorCode::ReceiptMissing => 5005,

            // Storage Errors (6xxx)
            ErrorCode::PayloadNotFound => 6001,
            ErrorCode::PayloadCorrupted => 6002,
            ErrorCode::StorageUnavailable => 6003,
            ErrorCode::AppendOnlyViolation => 6004,
            ErrorCode::PlaintextViolation => 6005,
            ErrorCode::TombstoneRequired => 6006,

            // Consent Errors (7xxx)
            ErrorCode::ConsentNotFound => 7001,
            ErrorCode::ConsentExpired => 7002,
            ErrorCode::ConsentRevoked => 7003,
            ErrorCode::ConsentScopeExceeded => 7004,
            ErrorCode::DelegationChainTooDeep => 7005,
            ErrorCode::EmergencyOverrideExpired => 7006,

            // Actor Errors (8xxx)
            ErrorCode::ActorNotFound => 8001,
            ErrorCode::ActorSuspended => 8002,
            ErrorCode::ActorNotAuthorized => 8003,
            ErrorCode::TipWitnessMissing => 8004,
            ErrorCode::TipWitnessStale => 8005,

            // Backfill Errors (9xxx)
            ErrorCode::BackfillInProgress => 9001,
            ErrorCode::BackfillFailed => 9002,
            ErrorCode::BackfillWindowExpired => 9003,
            ErrorCode::ContinuityCheckFailed => 9004,
            ErrorCode::GapUnacceptable => 9005,

            // Snapshot Errors (10xxx)
            ErrorCode::SnapshotNotFound => 10001,
            ErrorCode::SnapshotCorrupted => 10002,
            ErrorCode::R0SnapshotMissing => 10003,
            ErrorCode::R1SnapshotIncomplete => 10004,
            ErrorCode::SnapshotVerificationFailed => 10005,

            // Node Errors (11xxx)
            ErrorCode::NodeNotRegistered => 11001,
            ErrorCode::NodeBanned => 11002,
            ErrorCode::NodeTrustInsufficient => 11003,
            ErrorCode::NodeAdmissionDenied => 11004,

            // General Errors (0xxx)
            ErrorCode::Unknown => 1,
            ErrorCode::Internal => 2,
            ErrorCode::InvalidRequest => 3,
            ErrorCode::RateLimited => 4,
            ErrorCode::ServiceUnavailable => 5,
            ErrorCode::Timeout => 6,
        }
    }

    /// Get error category
    pub fn category(&self) -> ErrorCategory {
        match self.numeric_code() / 1000 {
            0 => ErrorCategory::General,
            1 => ErrorCategory::Version,
            2 => ErrorCategory::MapCommit,
            3 => ErrorCategory::Ticket,
            4 => ErrorCategory::Audit,
            5 => ErrorCategory::Evidence,
            6 => ErrorCategory::Storage,
            7 => ErrorCategory::Consent,
            8 => ErrorCategory::Actor,
            9 => ErrorCategory::Backfill,
            10 => ErrorCategory::Snapshot,
            11 => ErrorCategory::Node,
            _ => ErrorCategory::General,
        }
    }

    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            ErrorCode::StorageUnavailable
                | ErrorCode::ServiceUnavailable
                | ErrorCode::Timeout
                | ErrorCode::RateLimited
                | ErrorCode::BackfillInProgress
        )
    }

    /// Get default HTTP status code for this error
    pub fn http_status(&self) -> u16 {
        match self.category() {
            ErrorCategory::General => match self {
                ErrorCode::InvalidRequest => 400,
                ErrorCode::RateLimited => 429,
                ErrorCode::ServiceUnavailable => 503,
                ErrorCode::Timeout => 504,
                _ => 500,
            },
            ErrorCategory::Version => 409,  // Conflict
            ErrorCategory::MapCommit => 422, // Unprocessable Entity
            ErrorCategory::Ticket => 403,   // Forbidden
            ErrorCategory::Audit => 500,
            ErrorCategory::Evidence => 422,
            ErrorCategory::Storage => 503,
            ErrorCategory::Consent => 403,
            ErrorCategory::Actor => 403,
            ErrorCategory::Backfill => 409,
            ErrorCategory::Snapshot => 404,
            ErrorCategory::Node => 403,
        }
    }

    /// Get human-readable message for this error
    pub fn message(&self) -> &'static str {
        match self {
            ErrorCode::VersionDrift => "Version drift detected between components",
            ErrorCode::UnknownVersion => "Unknown or unsupported version",
            ErrorCode::VersionMismatch => "Version mismatch in request",
            ErrorCode::VersionUpgradeRequired => "Protocol version upgrade required",
            ErrorCode::CanonicalizationIncompatible => "Canonicalization version incompatible",
            ErrorCode::SignerSetExpired => "Signer set version has expired",

            ErrorCode::MapCommitNotFound => "Map commit reference not found",
            ErrorCode::MapCommitMismatch => "Map commit hash mismatch",
            ErrorCode::MapCommitVerificationFailed => "Map commit verification failed",
            ErrorCode::PayloadMapEntryMissing => "Payload map entry missing",
            ErrorCode::MapCommitDuplicate => "Duplicate map commit",
            ErrorCode::MapCommitExpired => "Map commit has expired",

            ErrorCode::TicketNotFound => "Access ticket not found",
            ErrorCode::TicketScopeInvalid => "Ticket scope is invalid for this operation",
            ErrorCode::TicketExpired => "Access ticket has expired",
            ErrorCode::TicketExhausted => "Access ticket usage limit exceeded",
            ErrorCode::TicketRevoked => "Access ticket has been revoked",
            ErrorCode::TicketPermissionDenied => "Ticket does not grant required permission",
            ErrorCode::TicketDelegationInvalid => "Ticket delegation chain is invalid",

            ErrorCode::DecryptAuditMissing => "Required decrypt audit log is missing",
            ErrorCode::ExportAuditMissing => "Required export audit log is missing",
            ErrorCode::SamplingAuditFailed => "Sampling audit check failed",
            ErrorCode::AuditChainBroken => "Audit chain integrity broken",
            ErrorCode::AuditVerificationFailed => "Audit verification failed",
            ErrorCode::MandatoryAuditMissing => "Mandatory audit record not found",

            ErrorCode::EvidenceLevelInsufficient => "Evidence level insufficient for operation",
            ErrorCode::EvidenceBundleNotFound => "Evidence bundle not found",
            ErrorCode::EvidenceCorrupted => "Evidence data is corrupted",
            ErrorCode::EvidenceExpired => "Evidence has expired",
            ErrorCode::ReceiptMissing => "Receipt required for A-level evidence is missing",

            ErrorCode::PayloadNotFound => "Payload not found in storage",
            ErrorCode::PayloadCorrupted => "Payload data is corrupted",
            ErrorCode::StorageUnavailable => "Storage backend is unavailable",
            ErrorCode::AppendOnlyViolation => "Append-only invariant violated",
            ErrorCode::PlaintextViolation => "Zero-plaintext invariant violated",
            ErrorCode::TombstoneRequired => "Direct deletion not allowed, use tombstone",

            ErrorCode::ConsentNotFound => "Consent record not found",
            ErrorCode::ConsentExpired => "Consent has expired",
            ErrorCode::ConsentRevoked => "Consent has been revoked",
            ErrorCode::ConsentScopeExceeded => "Operation exceeds consent scope",
            ErrorCode::DelegationChainTooDeep => "Delegation chain exceeds maximum depth",
            ErrorCode::EmergencyOverrideExpired => "Emergency override has expired",

            ErrorCode::ActorNotFound => "Actor not found",
            ErrorCode::ActorSuspended => "Actor is suspended",
            ErrorCode::ActorNotAuthorized => "Actor not authorized for this operation",
            ErrorCode::TipWitnessMissing => "TipWitness required but not provided",
            ErrorCode::TipWitnessStale => "TipWitness is stale",

            ErrorCode::BackfillInProgress => "Backfill operation already in progress",
            ErrorCode::BackfillFailed => "Backfill operation failed",
            ErrorCode::BackfillWindowExpired => "Backfill time window has expired",
            ErrorCode::ContinuityCheckFailed => "Continuity check failed",
            ErrorCode::GapUnacceptable => "Data gap is not acceptable",

            ErrorCode::SnapshotNotFound => "Snapshot not found",
            ErrorCode::SnapshotCorrupted => "Snapshot data is corrupted",
            ErrorCode::R0SnapshotMissing => "R0 (skeleton) snapshot is missing",
            ErrorCode::R1SnapshotIncomplete => "R1 (full) snapshot is incomplete",
            ErrorCode::SnapshotVerificationFailed => "Snapshot verification failed",

            ErrorCode::NodeNotRegistered => "Node is not registered",
            ErrorCode::NodeBanned => "Node has been banned",
            ErrorCode::NodeTrustInsufficient => "Node trust score is insufficient",
            ErrorCode::NodeAdmissionDenied => "Node admission denied",

            ErrorCode::Unknown => "Unknown error",
            ErrorCode::Internal => "Internal server error",
            ErrorCode::InvalidRequest => "Invalid request",
            ErrorCode::RateLimited => "Rate limit exceeded",
            ErrorCode::ServiceUnavailable => "Service temporarily unavailable",
            ErrorCode::Timeout => "Operation timed out",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}({})", self, self.numeric_code())
    }
}

/// Error category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCategory {
    General,
    Version,
    MapCommit,
    Ticket,
    Audit,
    Evidence,
    Storage,
    Consent,
    Actor,
    Backfill,
    Snapshot,
    Node,
}

/// Structured error response for API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// Error code
    pub code: ErrorCode,
    /// Numeric code
    pub numeric_code: u32,
    /// Human-readable message
    pub message: String,
    /// Additional details
    pub details: Option<String>,
    /// Request ID for tracing
    pub request_id: Option<String>,
    /// Retry-After header value (seconds)
    pub retry_after: Option<u64>,
}

impl ErrorResponse {
    /// Create a new error response
    pub fn new(code: ErrorCode) -> Self {
        Self {
            code,
            numeric_code: code.numeric_code(),
            message: code.message().to_string(),
            details: None,
            request_id: None,
            retry_after: None,
        }
    }

    /// Add details to the error
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    /// Add request ID for tracing
    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    /// Add retry-after for retryable errors
    pub fn with_retry_after(mut self, seconds: u64) -> Self {
        self.retry_after = Some(seconds);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_numeric() {
        assert_eq!(ErrorCode::VersionDrift.numeric_code(), 1001);
        assert_eq!(ErrorCode::MapCommitMismatch.numeric_code(), 2002);
        assert_eq!(ErrorCode::TicketScopeInvalid.numeric_code(), 3002);
        assert_eq!(ErrorCode::DecryptAuditMissing.numeric_code(), 4001);
    }

    #[test]
    fn test_error_code_category() {
        assert_eq!(ErrorCode::VersionDrift.category(), ErrorCategory::Version);
        assert_eq!(ErrorCode::TicketExpired.category(), ErrorCategory::Ticket);
        assert_eq!(ErrorCode::PayloadNotFound.category(), ErrorCategory::Storage);
    }

    #[test]
    fn test_error_code_retryable() {
        assert!(ErrorCode::StorageUnavailable.is_retryable());
        assert!(ErrorCode::Timeout.is_retryable());
        assert!(!ErrorCode::TicketExpired.is_retryable());
        assert!(!ErrorCode::VersionMismatch.is_retryable());
    }

    #[test]
    fn test_error_response() {
        let response = ErrorResponse::new(ErrorCode::TicketScopeInvalid)
            .with_details("Ticket does not cover payload:123")
            .with_request_id("req-456");

        assert_eq!(response.code, ErrorCode::TicketScopeInvalid);
        assert_eq!(response.numeric_code, 3002);
        assert!(response.details.is_some());
        assert!(response.request_id.is_some());
    }
}
