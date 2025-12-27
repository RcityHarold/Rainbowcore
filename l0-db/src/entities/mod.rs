//! L0 Entity definitions for SurrealDB storage
//!
//! Each entity implements the `Entity` trait from soulbase-storage.

mod actor;
mod commitment;
mod receipt;
mod consent;
mod dispute;

pub use actor::*;
pub use commitment::*;
pub use receipt::*;
pub use consent::*;
pub use dispute::*;
