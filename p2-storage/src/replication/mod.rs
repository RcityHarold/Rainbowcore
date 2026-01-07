//! Replication Module
//!
//! Provides data replication across multiple storage backends for high availability.
//!
//! # Features
//!
//! - **Synchronous Replication**: Waits for all replicas before confirming write
//! - **Asynchronous Replication**: Confirms write after primary, replicates in background
//! - **Semi-synchronous**: Waits for one replica, then async for the rest
//! - **Consistency Checking**: Verifies data consistency across replicas
//! - **Auto-repair**: Automatically repairs inconsistent replicas from majority
//!
//! # Example
//!
//! ```ignore
//! use p2_storage::replication::{
//!     ReplicationManager, ReplicationConfig, ReplicationMode,
//!     ReplicationWriteOptions,
//! };
//!
//! let config = ReplicationConfig::synchronous();
//! let manager = ReplicationManager::new(config, client);
//!
//! manager.start().await?;
//!
//! let options = ReplicationWriteOptions::default();
//! manager.replicate("payload:001", &data, options).await?;
//! ```

pub mod async_repl;
pub mod config;
pub mod consistency;
pub mod manager;
pub mod sync;

pub use async_repl::{AsyncReplicator, QueueStatus, ReplicationTask};
pub use config::{
    AsyncReplicationConfig, ConsistencyLevel, ReplicaNodeConfig, ReplicationConfig,
    ReplicationFactorConfig, ReplicationMode, RetryConfig,
};
pub use consistency::{
    BatchConsistencyResult, ConsistencyCheckConfig, ConsistencyCheckResult, ConsistencyChecker,
    RepairAction, ReplicaStatus,
};
pub use manager::{ReplicationManager, ReplicationManagerState, ReplicationWriteOptions};
pub use sync::{
    MockReplicaClient, NodeHealthStatus, NodeReplicationResult, ReplicaClient,
    SyncReplicationResult, SyncReplicator,
};
