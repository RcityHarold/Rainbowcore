//! Core type definitions for L0 Protocol
//!
//! All types follow these naming conventions:
//! - snake_case for field names
//! - *_id suffix for primary keys
//! - *_ref suffix for references
//! - *_digest suffix for digests

mod actor;
mod anchor;
mod backfill;
mod common;
mod consent;
mod dispute;
mod receipt;
mod snapshot;
mod version;

pub use actor::*;
pub use anchor::*;
pub use backfill::*;
pub use common::*;
pub use consent::*;
pub use dispute::*;
pub use receipt::*;
pub use snapshot::*;
pub use version::*;
