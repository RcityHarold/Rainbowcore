//! Operations API Module
//!
//! Provides operational management APIs for the P2 storage layer.
//!
//! # Features
//!
//! - **Health checks**: Backend health monitoring
//! - **Statistics**: Storage usage and performance stats
//! - **Management**: Operational control endpoints
//! - **Diagnostics**: System diagnostics and debugging

pub mod health;
pub mod stats;
pub mod management;
pub mod diagnostics;

pub use health::{
    HealthCheck, HealthCheckResult, HealthEndpoint, HealthResponse, HealthStatus,
    SystemHealth,
};
pub use stats::{
    BackendStats, OperationStats, StorageStats, StatsCollector, StatsResponse,
    PerformanceStats, ThroughputStats,
};
pub use management::{
    ControlStatus, MaintenanceMode, OperationControl, ShutdownRequest, ConfigUpdate,
};
pub use diagnostics::{
    DiagnosticItem, DiagnosticLevel, DiagnosticReport, DiagnosticResult, SystemDiagnostics,
};
