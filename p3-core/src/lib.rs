//! P3 Economy Layer - Settlement, Distribution and Clearing
//!
//! P3 is the "Economy & Settlement Layer" in the Rainbow Public Reality Stack.
//! It provides:
//! - **Measurement**: Provable events -> Recalculable inputs (manifest four sets)
//! - **Distribution**: Three pool tax split and reward allocation
//! - **Clearing**: Deposit/Fine/Clawback/Pending closed loop
//! - **Anti-speculation & Recalculation**: Version-controlled/Challengeable/Third-party verifiable
//!
//! # Five Constitutional Invariants
//!
//! | Invariant | Core Requirement |
//! |-----------|------------------|
//! | **Zero Plaintext** | P3 calculation/verification only consumes digests and references |
//! | **Epoch Atomic** | EconomyEpoch is the sole settlement atom, all consequences bind to epoch_id |
//! | **Append-Only** | Historical epochs/results cannot be overwritten, corrections via superseded chain |
//! | **No Tax Mixing** | Mandatory three-column split (Protocol Tax / DSN Storage / Service Fee) |
//! | **No Official Privilege** | No hidden interfaces, same API/validation/error codes/penalties for all |
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     EEL Implementation Layer                 │
//! │            (Execution Orchestration, Market Contracts)       │
//! ├─────────────────────────────────────────────────────────────┤
//! │                     P3 Economy Layer (This Crate)            │
//! │    (Settlement, Distribution, Clearing, Treasury, Gates)    │
//! ├─────────────────────────────────────────────────────────────┤
//! │    L0 Consensus Layer     │      P2 DSN Layer               │
//! │   (Identity, Causality,   │   (Encrypted Storage,           │
//! │    Receipts, Knowledge)   │    Tickets, Evidence)           │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Core Types
//!
//! - [`EconomyEpoch`]: Settlement atom and sealing point
//! - [`ManifestFourSets`]: Four sets (knowledge_events, court_events, policy_state, sampling_audit)
//! - [`PointsOutput`]: Points calculation result (gross/risk_adjusted/eligible/withheld)
//! - [`TreasuryPool`]: Three pools (InfraPool, CivilizationPool, RewardPool)
//! - [`ClawbackExecutionEntry`]: Clawback execution with ancestor protection
//! - [`AttemptChain`]: Retry chain management
//!
//! # Hard Gates
//!
//! All strong economic actions must pass through hard gates:
//! - `require_A`: Evidence level A required
//! - `require_not_degraded`: Degraded mode blocks strong actions
//! - `require_known_versions`: Unknown versions block strong actions
//! - `require_execution_proof`: Execution proof required for final payouts
//! - `require_verdict_ref`: Verdict reference required for forfeit/fine

pub mod error;
pub mod types;
pub mod gates;
pub mod canon;
pub mod merkle;
pub mod bundle;
pub mod points;
pub mod attribution;
pub mod treasury;
pub mod clearing;
pub mod execution;
pub mod pending;
pub mod degraded;
pub mod governance;

// Re-export error types
pub use error::{EvidenceLevelThreshold, P3Error, P3Result};

// Re-export all types
pub use types::*;

// Re-export gates
pub use gates::{GateChecker, GateContext, GateCheckResult};

// Re-export canon
pub use canon::{Canonicalizer, CanonSpec};

// Re-export merkle
pub use merkle::{MerkleTreeBuilder, MerkleRoot, MerkleProof};

// Re-export bundle
pub use bundle::{BundleVerifier, SealedBundle, BundleVerificationResult};

// Re-export points
pub use points::{PointsCalculator, PointsContext, PointsResult, WeightsRegistry};

// Re-export attribution
pub use attribution::{
    AttributionContext, AttributionEngine, AttributionResult, DistributionMode,
    LineageProcessor, ShareInput,
};

// Re-export treasury
pub use treasury::{
    DistributionEngine, DistributionResult, IncomeSplit, PoolState, SpendRecord,
    TreasuryContext, TreasuryManager,
};

// Re-export clearing
pub use clearing::{
    ClearingContext, ClearingEngine, ClawbackRecord, DepositRecord, FineRecord,
    SettlementProcessor, SettlementReport,
};

// Re-export execution
pub use execution::{
    ExecutionEngine, ExecutionPhase, ExecutionRecord,
    QuoteRequest, QuoteResponse, CommitRequest, CommitResponse,
    ExecuteRequest, ExecuteResponse, ResolveRequest, ResolveResponse,
    IdempotencyManager, IdempotencyCheck, IdempotencyGuard,
    AttemptChainManager, AttemptOutcome,
};

// Re-export pending
pub use pending::{
    PendingManager, PendingResolver, PendingCategory, PendingPriority,
    EnhancedPendingEntry, PendingResolutionRequest, PendingQueueStats,
    RecoverySequence, RecoveryOrder, RecoveryStatus, ResolutionStrategy,
};

// Re-export degraded (renamed RecoveryPlan to avoid conflict with types::clearing::RecoveryPlan)
pub use degraded::{
    DegradedModeDetector, DegradedSeverity, DegradedSource, DegradedModeStatus,
    ExtendedDegradedFlag, RecoveryManager, RecoveryPlanStatus,
    RecoveryCondition, RecoveryConditionType, RecoveryAction, RecoveryActionType,
    DetectionRule, DetectionCheck, DetectionMetrics,
};
pub use degraded::RecoveryPlan as DegradedRecoveryPlan;

// Re-export governance (renamed types to avoid conflicts with types::version::*)
pub use governance::{
    VersionRegistry, VersionManager, VersionObjectType, VersionNumber, TransitionType,
    ChallengeManager, Challenge, ChallengeReason, ChallengeStatus,
    ChallengeResolution, ChallengeAction, Dispute, DisputeStatus,
    DisputeVote, DisputeOutcome, UnknownVersionRef, UnknownVersionResolution,
};
pub use governance::VersionObject as GovVersionObject;
pub use governance::VersionStatus as GovVersionStatus;
pub use governance::VersionTransition as GovVersionTransition;

// Re-export disclosure types (Phase 6)
pub use types::{
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

// Re-export L0 types for convenience
pub use l0_core::types::{ActorId, ActorType, Digest as L0Digest, NodeActorId, GroupActorId, ReceiptId};

/// P3 version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// P3 protocol version
pub const PROTOCOL_VERSION: &str = "v1";

/// Default canon version
pub const DEFAULT_CANON_VERSION: &str = "v1";

/// Default error code version
pub const DEFAULT_ERROR_CODE_VERSION: &str = "v1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
        assert_eq!(PROTOCOL_VERSION, "v1");
    }

    #[test]
    fn test_epoch_id_creation() {
        let id = EpochId::new("epoch:2024:001");
        assert_eq!(id.as_str(), "epoch:2024:001");
    }

    #[test]
    fn test_p3_digest_creation() {
        let digest = P3Digest::blake3(b"test data");
        assert!(!digest.is_zero());
    }

    #[test]
    fn test_evidence_level_default() {
        let level = EvidenceLevel::default();
        assert_eq!(level, EvidenceLevel::B);
    }

    #[test]
    fn test_pool_ratios_default() {
        let ratios = PoolRatios::default();
        assert!(ratios.validate());
    }

    #[test]
    fn test_strong_action_name() {
        let action = StrongEconomicAction::FinalClawbackExecute;
        assert_eq!(action.name(), "FinalClawbackExecute");
    }
}
