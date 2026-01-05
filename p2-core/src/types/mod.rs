//! P2/DSN Core Types
//!
//! This module contains all the core type definitions for the P2 layer:
//! - Sealed payload references (the basic storage unit)
//! - Resurrection snapshots (R0/R1)
//! - Evidence bundles (for judicial discovery)
//! - Access tickets (ticketed forensic access)
//! - Selectors (minimal disclosure)
//! - Audit artifacts (mandatory audit logging)

pub mod access_ticket;
pub mod audit_artifacts;
pub mod evidence_bundle;
pub mod resurrection;
pub mod sealed_payload;
pub mod selector;

// Re-exports for convenience
pub use access_ticket::{
    AccessTicket, DelegationEntry, TicketError, TicketPermission, TicketRequest, TicketStatus,
    TicketValidation,
};
pub use audit_artifacts::{
    AdditionalCheck, AuditSummary, ClientInfo, DecryptAuditLog, DecryptOutcome,
    ExportAuditLog, ExportDestinationType, ExportFormat, ReachabilityStatus, SamplingArtifact,
    SamplingPolicy,
};
pub use evidence_bundle::{
    EvidenceBundle, EvidenceBundleStatus, EvidenceLevel, EvidenceSubmission, EvidenceType,
    PayloadSubmission,
};
pub use resurrection::{
    ContinuitySkeleton, ContinuityState, FullResurrectionSnapshot, GovernanceStateSkeleton,
    ManifestShard, MapCommitRef, MinimalBootConfig, MinimalRelationshipSkeleton, MissingPayloads,
    MissingReason, R0Trigger, R1Trigger, SkeletonManifest, SkeletonSnapshot, SubjectProof,
    TripleCommits,
};
pub use sealed_payload::{
    EncryptionMetadata, SealedPayloadRef, SealedPayloadStatus, StorageTemperature,
    ThresholdEncryptionInfo,
};
pub use selector::{PayloadSelector, SelectorType, SelectorValidation};
