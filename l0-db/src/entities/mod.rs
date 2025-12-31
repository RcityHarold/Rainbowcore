//! L0 Entity definitions for SurrealDB storage
//!
//! Each entity implements the `Entity` trait from soulbase-storage.

mod actor;
mod anchor;
mod backfill;
mod commitment;
mod consent;
mod dispute;
mod knowledge;
mod receipt;

pub use actor::*;
pub use anchor::*;
pub use backfill::*;
pub use commitment::*;
pub use consent::*;
pub use dispute::*;
pub use knowledge::*;
pub use receipt::*;
