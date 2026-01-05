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
pub mod error;
pub mod retention;
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
pub use temperature::{
    MigrationBatch, MigrationCandidate, MigrationProgress, MigrationResult, MigrationStatus,
    TemperaturePolicy, TemperaturePolicyConfig, TemperaturePolicyExecutor,
};

/// Storage version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
