//! P2 Storage Backends
//!
//! This module contains storage backend implementations.

pub mod local;
pub mod traits;

// IPFS backend modules
pub mod ipfs;
pub mod ipfs_pin;
pub mod ipfs_cluster;

// S3 backend modules
pub mod s3;
pub mod s3_lifecycle;

pub use local::LocalStorageBackend;
pub use traits::{
    BackendCapabilities, BackendType, HealthStatus, IntegrityResult, P2StorageBackend,
    PayloadMetadata, WriteMetadata,
};

// IPFS exports
pub use ipfs::{IpfsBackend, IpfsConfig, CidMapping};
pub use ipfs_pin::{PinManager, PinPriority, PinStatus, PinStrategy, PinRecord, PinManagerConfig, PinStats};
pub use ipfs_cluster::{ClusterClient, HttpClusterClient, ClusterConfig, ClusterPinInfo};

// S3 exports
pub use s3::{S3Backend, S3Config, S3StorageClass, ServerSideEncryption, S3ObjectMeta};
pub use s3_lifecycle::{
    LifecycleConfiguration, LifecycleManager, LifecycleRule, LifecycleTransition,
    LifecycleExpiration, LifecycleFilter, LifecycleRuleStatus,
};
