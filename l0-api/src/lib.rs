//! L0 API Server
//!
//! Provides REST APIs for L0 Public Reality Ledger operations.
//!
//! ## API Versioning
//!
//! All business endpoints are served under `/api/v1/` prefix.
//! Health endpoints remain at root level for infrastructure compatibility.
//!
//! ### Version Information
//! - GET /api/version - Get API version info
//!
//! ### Health (Unversioned)
//! - GET /health - Health check
//! - GET /ready - Readiness check
//!
//! ## Endpoints (v1)
//!
//! ### Actor Management
//! - POST /api/v1/actors - Register actor
//! - GET /api/v1/actors/:actor_id - Get actor info
//! - POST /api/v1/actors/:actor_id/status - Update actor status
//!
//! ### Commitment Management
//! - POST /api/v1/commitments - Submit commitment
//! - GET /api/v1/commitments/:commitment_id - Get commitment
//! - GET /api/v1/commitments/:commitment_id/verify - Verify chain
//!
//! ### Knowledge-Index Ledger
//! - POST /api/v1/knowledge - Index content
//! - GET /api/v1/knowledge/:entry_id - Get entry
//! - GET /api/v1/knowledge/digest/:digest - Get entries by digest
//! - GET /api/v1/knowledge/space/:space_id - Get entries by space
//! - GET /api/v1/knowledge/actor/:actor_id - Get entries by actor
//! - POST /api/v1/knowledge/crossrefs - Create cross-reference
//!
//! ### Policy-Consent Ledger
//! - POST /api/v1/consents - Grant consent
//! - GET /api/v1/consents/:consent_id - Get consent
//! - POST /api/v1/consents/:consent_id/revoke - Revoke consent
//! - POST /api/v1/consents/verify - Verify consent
//! - POST /api/v1/tickets - Issue access ticket
//! - GET /api/v1/tickets/:ticket_id - Get ticket
//! - POST /api/v1/tickets/:ticket_id/use - Use ticket
//!
//! ### Dispute-Resolution Ledger
//! - POST /api/v1/disputes - File dispute
//! - GET /api/v1/disputes/:dispute_id - Get dispute
//! - POST /api/v1/disputes/:dispute_id/verdict - Issue verdict
//! - POST /api/v1/clawbacks - Initiate clawback
//! - POST /api/v1/clawbacks/:clawback_id/execute - Execute clawback

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
