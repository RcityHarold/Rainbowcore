//! L0 API Server
//!
//! Provides REST and GraphQL APIs for L0 operations.
//!
//! Endpoints:
//! - POST /commit - Submit commitment
//! - GET /receipt/{id} - Get receipt
//! - GET /verify/{id} - Verify receipt
//! - POST /backfill - Request backfill
//! - GET /actor/{id} - Get actor info

pub mod dto;
pub mod error;
pub mod routes;
pub mod server;
pub mod state;

pub use dto::*;
pub use error::*;
pub use routes::*;
pub use server::*;
pub use state::*;
