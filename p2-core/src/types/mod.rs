//! P2/DSN Core Types
//!
//! This module contains all the core type definitions for the P2 layer:
//! - Sealed payload references (the basic storage unit)
//! - Resurrection snapshots (R0/R1)
//! - Evidence bundles (for judicial discovery)
//! - Access tickets (ticketed forensic access)
//! - Selectors (minimal disclosure)
//! - Audit artifacts (mandatory audit logging)
//! - Payload map commits (P1-P2 mapping commitment system)

pub mod access_ticket;
pub mod audit_artifacts;
pub mod evidence_bundle;
pub mod payload_map;
pub mod resurrection;
pub mod sealed_payload;
pub mod selector;

// Re-exports for convenience
pub use access_ticket::{
    AccessTicket, DelegationEntry, TicketError, TicketPermission, TicketRequest, TicketStatus,
    TicketValidation,
};
pub use audit_artifacts::{
    AdditionalCheck, AuditErrorCode, AuditGuardState, AuditLogWriter, AuditSummary,
    AuditWriteError, AuditWriteResult, ClientInfo, DecryptAuditLog, DecryptOutcome,
    ExportAuditLog, ExportDestinationType, ExportFormat, MandatoryAuditGuard,
    MandatoryAuditOperation, ReachabilityStatus, SamplingArtifact, SamplingPolicy,
    TicketAuditLog, TicketOperation, TicketOperationOutcome,
    create_decrypt_audit_guard, create_export_audit_guard, create_ticket_audit_guard,
};
pub use evidence_bundle::{
    AvailabilityStatus, EvidenceAvailability, EvidenceBundle, EvidenceBundleStatus,
    EvidenceLevelDetails, EvidenceLevelDowngradeReason, EvidenceSubmission,
    EvidenceType, EvidenceVerificationState, PayloadSubmission, TemperatureImpact,
};
pub use resurrection::{
    ContinuitySkeleton, ContinuityState, FullResurrectionSnapshot, GovernanceStateSkeleton,
    MSNApprovalDecision, MSNApprovalDetails, MSNApprovalStatus, MSNRejectionReason,
    MSNValidationError, MSNValidationResult, MSNWithApproval, ManifestShard, MapCommitRef,
    MinimalBootConfig, MinimalRelationshipSkeleton, MissingPayloads, MissingReason,
    R0Trigger, R0ValidationError, R0ValidationResult, R1Trigger, SkeletonManifest,
    SkeletonSnapshot, SubjectProof, TripleCommits,
};
pub use sealed_payload::{
    EncryptionMetadata, PayloadFormatVersion, SealedPayloadRef, SealedPayloadStatus, StorageTemperature,
    ThresholdEncryptionInfo,
};
pub use selector::{PayloadSelector, SelectorType, SelectorValidation};
pub use payload_map::{
    ACMapCommit, BatchMapCommit, MapCommit, MapCommitStatus, MapCommitVerifyResult,
    MapCommitVersionInfo, PayloadMap, PayloadMapEntry, PayloadMapEntryStatus,
    SnapshotMapCommit, SnapshotType,
};
