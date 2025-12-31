//! L0 API Server
//!
//! Provides REST APIs for L0 Public Reality Ledger operations.
//!
//! ## Endpoints
//!
//! ### Actor Management
//! - POST /actors - Register actor
//! - GET /actors/:actor_id - Get actor info
//! - POST /actors/:actor_id/status - Update actor status
//!
//! ### Commitment Management
//! - POST /commitments - Submit commitment
//! - GET /commitments/:commitment_id - Get commitment
//! - GET /commitments/:commitment_id/verify - Verify chain
//!
//! ### Knowledge-Index Ledger
//! - POST /knowledge - Index content
//! - GET /knowledge/:entry_id - Get entry
//! - GET /knowledge/digest/:digest - Get entries by digest
//! - GET /knowledge/space/:space_id - Get entries by space
//! - GET /knowledge/actor/:actor_id - Get entries by actor
//! - POST /knowledge/crossrefs - Create cross-reference
//!
//! ### Policy-Consent Ledger
//! - POST /consents - Grant consent
//! - GET /consents/:consent_id - Get consent
//! - POST /consents/:consent_id/revoke - Revoke consent
//! - POST /consents/verify - Verify consent
//! - POST /tickets - Issue access ticket
//! - GET /tickets/:ticket_id - Get ticket
//! - POST /tickets/:ticket_id/use - Use ticket
//!
//! ### Dispute-Resolution Ledger
//! - POST /disputes - File dispute
//! - GET /disputes/:dispute_id - Get dispute
//! - POST /disputes/:dispute_id/verdict - Issue verdict
//! - POST /clawbacks - Initiate clawback
//! - POST /clawbacks/:clawback_id/execute - Execute clawback

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
