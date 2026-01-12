//! P2/DSN Storage Layer
//!
//! Storage backend implementations for the P2 encrypted permanence domain.
//!
//! # Features
//!
//! - **Local filesystem**: Default backend for development and single-node deployments
//! - **IPFS**: Content-addressed distributed storage (optional, with `ipfs` feature)
//! - **S3-compatible**: Object storage for cloud deployments (optional, with `s3` feature)
//!
//! # Temperature Tiers
//!
//! P2 supports three storage temperature tiers:
//! - **Hot**: Low latency, high cost, for frequently accessed data
//! - **Warm**: Medium latency/cost, for moderately accessed data
//! - **Cold**: High latency, low cost, for archival data
//!
//! # Usage
//!
//! ```ignore
//! use p2_storage::backend::{LocalStorageBackend, P2StorageBackend, WriteMetadata};
//!
//! async fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     let backend = LocalStorageBackend::new("/path/to/storage").await?;
//!
//!     let data = b"encrypted payload data";
//!     let metadata = WriteMetadata::hot("application/octet-stream");
//!
//!     let payload_ref = backend.write(data, metadata).await?;
//!     println!("Stored payload: {}", payload_ref.ref_id);
//!
//!     let read_data = backend.read(&payload_ref.ref_id).await?;
//!     assert_eq!(read_data, data);
//!
//!     Ok(())
//! }
//! ```

pub mod backend;
pub mod backend_migration;
pub mod compliance;
pub mod config;
pub mod error;
pub mod failover;
pub mod health_monitor;
pub mod invariants;
pub mod ops;
pub mod performance;
pub mod replication;
pub mod retention;
pub mod router;
pub mod routing_policy;
pub mod services;
pub mod telemetry;
pub mod temperature;

pub use backend::{
    BackendCapabilities, BackendType, HealthStatus, IntegrityResult, LocalStorageBackend,
    P2StorageBackend, PayloadMetadata, WriteMetadata,
};
pub use error::{StorageError, StorageResult};
pub use retention::{
    LegalHold, LegalHoldManager, LegalHoldStatus, RetentionChecker, RetentionGC,
    RetentionPolicy, RetentionPolicyConfig, RetentionRule,
};
pub use services::{
    Alert, AlertConfig, AlertHandler, AlertManager, AlertSeverity, AlertType, AuditChain,
    AuditChainEntry, AuditQuery, AuditQueryResult, AuditStore, AuditStoreConfig, FailureDetail,
    FailureSeverity, HealthStatus as SamplingHealthStatus, InMemoryMetadataProvider,
    IntegrityCheckResult, IntegrityCheckType, IntegrityChecker, IntegrityCheckerConfig,
    IntegrityStats, PayloadMetadataProvider, PayloadSampleInfo, PayloadSampler, SamplingReport,
    SamplingReportBuilder, SamplingRunStatus, SamplingScheduler, SamplingSchedulerConfig,
    SamplingSchedulerState, SamplingStrategy, SamplingSummary, SelectedSample, TemperatureTier,
};
pub use replication::{
    AsyncReplicator, BatchConsistencyResult, ConsistencyCheckConfig, ConsistencyCheckResult,
    ConsistencyChecker, ConsistencyLevel, MockReplicaClient, NodeHealthStatus, QueueStatus,
    RepairAction, ReplicaClient, ReplicaNodeConfig, ReplicaStatus, ReplicationConfig,
    ReplicationFactorConfig, ReplicationManager, ReplicationManagerState, ReplicationMode,
    ReplicationTask, ReplicationWriteOptions, RetryConfig, SyncReplicationResult, SyncReplicator,
};
pub use telemetry::{
    Counter, Gauge, Histogram, LogConfig, LogFormat, LogLevel, MetricsConfig, MetricsRegistry,
    ReplicationMetrics, SamplingMetrics, StorageMetrics, TraceContext, TracingConfig,
};
pub use temperature::{
    MigrationBatch, MigrationCandidate, MigrationProgress, MigrationResult, MigrationStatus,
    TemperaturePolicy, TemperaturePolicyConfig, TemperaturePolicyExecutor,
};
pub use failover::{FailoverConfig, FailoverEvent, FailoverManager, FailoverState, FailoverStats};
pub use health_monitor::{
    BackendHealth, BackendHealthSummary, HealthCheckResult, HealthMonitor, HealthMonitorConfig,
    HealthSummary,
};
pub use router::{BackendRouter, BackendStats, RouterConfig, RouterStats};
pub use routing_policy::{
    CompositePolicy, ContentTypePolicy, ContentTypeRule, PrimaryBackupPolicy, RoundRobinPolicy,
    RoutingDecision, RoutingPolicy, SizeBasedPolicy, TemperatureBasedPolicy,
};
pub use config::{
    BackendSelection, ConfigError, ConfigReloader, ConfigValidator, EnvOverride,
    GeneralConfig, LocalStorageConfig, MetricsServerConfig, P2StorageConfig, SecurityConfig,
    StorageConfig, TelemetryConfig, ValidationError, ValidationResult,
};
pub use ops::{
    BackendStats as OpsBackendStats, ConfigUpdate, ControlStatus, DiagnosticItem,
    DiagnosticLevel, DiagnosticReport, DiagnosticResult, HealthCheck,
    HealthCheckResult as OpsHealthCheckResult, HealthEndpoint, HealthResponse,
    HealthStatus as OpsHealthStatus, MaintenanceMode, OperationControl, OperationStats,
    PerformanceStats, ShutdownRequest, StatsCollector, StatsResponse, StorageStats,
    SystemDiagnostics, SystemHealth, ThroughputStats,
};
pub use compliance::{
    AuditEventType, ComplianceAuditEntry, ComplianceAuditLog, ComplianceCheckResult,
    ComplianceChecker, ComplianceContext, CompliancePolicy, ComplianceRule, ComplianceRuleSet,
    ComplianceStatus, PolicyAction, PolicyCondition, PolicyEnforcer, PolicyViolation,
    RuleCategory, RuleSeverity, RuleViolation,
};
pub use invariants::{
    AppendOnlyError, AppendOnlyGuard, AppendOnlyResult, AuditSeverity, CiphertextError,
    CiphertextValidation, CiphertextValidator, DeletionError, DeletionGuard, DeletionRequest,
    DeletionResult, EncryptionFormat, ExistenceProof, InvariantAuditEntry, InvariantAuditLogger,
    InvariantCheck, InvariantCheckResult, InvariantConfig, InvariantEnforcedStorage,
    InvariantViolationType, TombstoneRecord, WriteCheckResult, WriteOperation,
};
pub use performance::{
    AcceptanceCriterion, AcceptanceReport, DailySampler, DailySamplingConfig, DailySamplingResult,
    LatencyStats, PerformanceCollector,
    // Testing infrastructure (ISSUE-028, ISSUE-029)
    testing::{
        PerformanceTestConfig, PerformanceTestResult, PerformanceTestHarness,
        LatencyPercentiles, CurrentMetrics,
        FaultType, FaultConfig, FaultTestResult, FaultInjector, FaultTestHarness,
        DataIntegrityResult,
    },
};
// Backend Migration Protocol (ISSUE-012)
pub use backend_migration::{
    BackendMigrationExecutor, DualWriteManager, DualWriteStats, MigrationAuditEntry,
    MigrationConfig, MigrationError, MigrationEvent, MigrationPhase,
    MigrationResult as BackendMigrationResult,
    MigrationState, ReEncryptionHandler, RefRemappingRegistry,
};

/// Storage version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
