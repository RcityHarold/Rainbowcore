//! P3 Core Type Definitions
//!
//! All types follow these naming conventions:
//! - snake_case for field names
//! - *_id suffix for primary keys
//! - *_ref suffix for references
//! - *_digest suffix for digests

pub mod attribution;
pub mod clearing;
pub mod common;
pub mod disclosure;
pub mod epoch;
pub mod execution;
pub mod manifest;
pub mod points;
pub mod treasury;
pub mod version;

// Re-export common types
pub use common::{
    // Digest types
    P3Digest, SetDigest, RefDigest, MoneyDigest, PointsDigest, EMPTY_SET_DIGEST,
    // ID types
    EpochId, EventId, PendingId, AttemptChainId, ProviderId, DistributionId, IdempotencyKey, VersionId,
    // Version types
    CanonVersion, ErrorCodeVersion,
    // Enums
    EvidenceLevel, StrongEconomicAction, PendingKind, DegradedFlag,
    DepositStatus, ExecutionStatus,
};

// Re-export L0 types directly
pub use l0_core::types::{ActorId, NodeActorId, GroupActorId, ReceiptId};

// Re-export epoch types
pub use epoch::{
    ChainAnchorLink, CutoffRef, EconomyEpoch, EconomyEpochBundle, EpochHeader, EpochWindow,
    EventSet, ManifestDigest, ManifestFourSets, WeightsVersionRef,
};

// Re-export manifest types
pub use manifest::{
    // Events
    AbuseSignalEvent, AbuseSignalType,
    AnchorRef, AppealFiledEvent,
    AuditResult, AuditSamplingResultEvent, AuditSamplingTriggeredEvent,
    BackfillEventStatus, BackfillStatusEvent,
    ClawbackOrderEvent, CovenantStatus, CovenantStatusChangeEvent,
    DisputeFiledEvent, DsnDownEvent, DsnDownSeverity,
    EconomyEventRef, EscalationLevel,
    EvalBucket, EvalEvent, EvalType,
    EventType, FraudSuspectedEvent,
    MintEvent, MintKind, MissingAuditEvent,
    MustOpenCandidateEvent, MustOpenReason,
    PolicyVersionPublicationEvent, RepairCheckpointEvent, RepairCheckpointStatus,
    RevocationRecordEvent, RevocationType,
    SamplingTriggerType, SuspicionType,
    UseEvent, UseKind, VerdictIssuedEvent, VerdictOutcome,
};

// Re-export points types
pub use points::{
    BucketMultiplier, CapFunctions, CompatibilityVector, DiscountEntry, DiscountTable,
    HoldbackRules, MintBaseConfig, MultiplierTable, PenaltyEntry, PenaltyTable,
    PointsInputRefs, PointsOutput, ReasonCode, ReasonsDigest, RoundingMode,
    SemanticVersion, UseBaseConfig, WeightsContent, WeightsVersion,
};

// Re-export attribution types
pub use attribution::{
    AttributionMapDigest, ConnectedLevel, ConnectedWeight, ContributionType,
    ContributorShare, ContributorType, DecayCurve, LineageNode, LineagePolicyVersion,
    LineageTree, MergeRule, PoolAttribution, TargetKind,
};

// Re-export treasury types
pub use treasury::{
    BudgetSpendEntry, DistributionEntry, DsnStorageColumn, IncomeCapturedEntry,
    IncomeStatus, PayoutMethod, PoolBalanceSnapshot, PoolId, PoolRatios, PoolRatioVersion,
    ProtocolTaxColumn, RewardDistributionEntry, RewardPoints, ServiceFeeColumn, SpendReasonType,
    SubsidyEntry, SubsidyReasonType, ThreeColumnBill, TreasuryPool,
};

// Re-export clearing types
pub use clearing::{
    AncestorProtectionParams, Bond, ClawbackExecutionEntry, ClawbackStatus, Deposit,
    DepositReasonType, Fine, RecoveryEntry, RecoveryEntryStatus, RecoveryPlan,
    SettlementBatch, SettlementBatchStatus, ClearingSummary,
};

// Re-export execution types
pub use execution::{
    Attempt, AttemptChain, AttemptChainStatus, AttemptResult, BackoffPolicy,
    ExecutionContext, ExecutionProofRef, ExecutionProofType, ExecutionResult,
    ExecutionState, IdempotencyRecord, IdempotencyStatus, OperationType,
    PendingEntry, PendingResolution, ResolutionType,
};

// Re-export version types
pub use version::{
    BreakingChange, CompatibilityInfo, IncompatibilityInfo, KnownVersionSet,
    VersionCheckItem, VersionCheckStatus, VersionDependency, VersionGateResult,
    VersionMetadata, VersionObject, VersionRegistryEntry, VersionStatus,
    VersionTransition, VersionType,
};

// Re-export disclosure types (Phase 6)
pub use disclosure::{
    // Disclosure levels
    DisclosureLevel,
    // Viewer context and authorization
    ViewerContext, OrgScope, ContextTTL,
    // Query scope
    QueryScope, QueryOperation, EpochRange, ActorFilter,
    // Query audit
    QueryAuditRecord, QueryAuditId, QueryAuditDigest,
    // Export ticket
    ExportTicket, ExportTicketId, ExportScope, ExportDataType, ExportFormat, ExportTicketStatus,
    // Conformance
    ConformanceLevel, ProviderOperation,
    // Provider types
    ProviderType, ProviderRegistration, ProviderMaterialRequirements, RequiredMaterial,
};
