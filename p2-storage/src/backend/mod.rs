//! P2 Storage Backends
//!
//! This module contains storage backend implementations.

pub mod local;
pub mod traits;

pub use local::LocalStorageBackend;
pub use traits::{
    BackendCapabilities, BackendType, HealthStatus, IntegrityResult, P2StorageBackend,
    PayloadMetadata, WriteMetadata,
};
