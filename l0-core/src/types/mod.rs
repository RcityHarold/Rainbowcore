//! Core type definitions for L0 Protocol
//!
//! All types follow these naming conventions:
//! - snake_case for field names
//! - *_id suffix for primary keys
//! - *_ref suffix for references
//! - *_digest suffix for digests

mod actor;
mod receipt;
mod snapshot;
mod version;
mod dispute;
mod consent;
mod backfill;
mod common;

pub use actor::*;
pub use receipt::*;
pub use snapshot::*;
pub use version::*;
pub use dispute::*;
pub use consent::*;
pub use backfill::*;
pub use common::*;
