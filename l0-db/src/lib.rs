//! L0 Database Layer
//!
//! Provides storage integration for L0 ledgers using soulbase-storage.
//!
//! This crate implements the ledger storage for L0 consensus layer
//! using SurrealDB (via soulbase-storage) as the persistence layer.
//!
//! # 架构说明
//!
//! 复用 soulbase-storage 的能力：
//! - `SurrealDatastore` - SurrealDB 连接管理
//! - `Repository<E>` - 通用 CRUD 操作
//! - `Session` / `Transaction` - 事务支持
//! - `HealthCheck` - 健康检查
//!
//! # 使用示例
//!
//! ```ignore
//! use l0_db::{L0Database, ActorEntity};
//! use soulbase_storage::surreal::SurrealDatastore;
//! use std::sync::Arc;
//!
//! async fn example() {
//!     let datastore = Arc::new(SurrealDatastore::connect("mem://").await.unwrap());
//!     let db = L0Database::new(datastore);
//!     db.init_schema().await.unwrap();
//! }
//! ```

pub mod entities;
pub mod error;
pub mod repos;
pub mod schema;
pub mod sequence;
pub mod services;
pub mod validation;

// Re-export main types
pub use entities::*;
pub use error::*;
pub use repos::*;
pub use schema::L0_SCHEMA;
pub use sequence::{PersistentSequence, SequenceManager};
pub use services::{
    AnchorService, BackfillService, CausalityService, ConsentService, DisputeService,
    IdentityService, KnowledgeService, ReceiptService, TipWitnessChainVerification,
    TipWitnessService, TipWitnessSubmission,
};

// Re-export soulbase-storage for convenience
pub use soulbase_storage::model::{Entity, Page, QueryParams};
pub use soulbase_storage::spi::{Datastore, Session};
pub use soulbase_storage::surreal::SurrealDatastore;
