//! Ledger interfaces for L0
//!
//! L0 maintains five distinct ledgers:
//! - Identity Ledger: Actor registration and key management
//! - Causality Ledger: Commitment ordering and parent chains
//! - Knowledge-Index Ledger: Zero-plaintext content indexes
//! - Policy-Consent Ledger: Consent records and access control
//! - Dispute-Resolution Ledger: Verdicts, repairs, and clawbacks

mod identity;
mod causality;
mod knowledge;
mod consent;
mod dispute;

pub use identity::*;
pub use causality::*;
pub use knowledge::*;
pub use consent::*;
pub use dispute::*;

use crate::error::LedgerError;
use crate::types::{Digest, ReceiptId};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

/// Common result type for ledger operations
pub type LedgerResult<T> = Result<T, LedgerError>;

/// Ledger query options
#[derive(Debug, Clone, Default)]
pub struct QueryOptions {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub order_desc: bool,
    pub time_start: Option<DateTime<Utc>>,
    pub time_end: Option<DateTime<Utc>>,
}

/// Ledger entry metadata common to all ledgers
#[derive(Debug, Clone)]
pub struct LedgerEntryMeta {
    pub created_at: DateTime<Utc>,
    pub receipt_id: Option<ReceiptId>,
    pub entry_digest: Digest,
    pub sequence_no: u64,
}

/// Base trait for all ledger implementations
#[async_trait]
pub trait Ledger: Send + Sync {
    /// Get the ledger name
    fn name(&self) -> &'static str;

    /// Get the current sequence number
    async fn current_sequence(&self) -> LedgerResult<u64>;

    /// Get the current root digest
    async fn current_root(&self) -> LedgerResult<Digest>;

    /// Verify the integrity of the ledger
    async fn verify_integrity(&self) -> LedgerResult<bool>;
}
