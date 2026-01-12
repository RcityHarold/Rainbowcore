//! L0 Core - RainbowCore Public Reality Ledger
//!
//! This crate provides the core types and interfaces for the L0 consensus layer.
//! L0 is the public reality layer that provides:
//! - Zero plaintext storage (only commitments/indexes/receipts)
//! - Verifiability by any node
//! - Non-repudiability through threshold signatures
//! - Recalculability of all roots and digests
//!
//! # 架构说明
//!
//! 本 crate 复用 soul-base 基础设施：
//! - `soulbase-crypto` - 摘要、签名、规范化
//! - `soulbase-types` - 基础类型 (Envelope, Id, Subject)
//! - `soulbase-errors` - 错误处理
//!
//! L0 特有的类型和接口定义在本 crate 中。

pub mod canon;
pub mod constants;
pub mod crypto;
pub mod epoch_proof;
pub mod error;
pub mod ledger;
pub mod logging;
pub mod types;
pub mod version;

// Re-export soul-base primitives for convenience
pub use soulbase_crypto::{Digest, Digester, DefaultDigester};
pub use soulbase_crypto::{Canonicalizer, JsonCanonicalizer};
pub use soulbase_types::envelope::Envelope;
pub use soulbase_types::id::Id;
pub use soulbase_types::subject::Subject;

pub use constants::*;
pub use epoch_proof::*;
pub use error::*;
pub use types::*;
