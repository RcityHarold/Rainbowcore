//! P2 Ledger Module
//!
//! This module provides ledger traits and implementations for P2 operations.
//! Includes file-based implementations for:
//! - Snapshot Ledger (R0/R1 resurrection snapshots)
//! - Evidence Ledger (evidence bundles with P1 commitment tracking)
//! - Audit Ledger (decrypt, export, and sampling audit logs)
//! - Ticket Ledger (access tickets for forensic access)
//! - Ledger Index (efficient indexing for queries)
//!
//! # Security
//!
//! All ledger data is encrypted at rest using the `encrypted_storage` module.
//! This ensures zero-plaintext compliance for the P2 layer.

pub mod traits;
pub mod audit_ledger;
pub mod encrypted_storage;
pub mod evidence_ledger;
pub mod index;
pub mod snapshot_ledger;
pub mod sync_ledger;
pub mod ticket_ledger;
pub mod wal;

pub use traits::{
    AuditLedger, AuditStats, EvidenceLedger, PayloadMetadata, PayloadStore, SnapshotLedger, TicketLedger,
};

pub use audit_ledger::FileAuditLedger;
pub use evidence_ledger::FileEvidenceLedger;
pub use index::{
    CompositeIndex, IndexBuilder, IndexEntry, IndexEntryType, IndexStats, LedgerIndex,
    SecondaryIndex, SecondaryKey, TimeIndex,
};
pub use snapshot_ledger::FileSnapshotLedger;
pub use ticket_ledger::FileTicketLedger;
pub use sync_ledger::{FileSyncLedger, SyncLedger, SyncStateEntry, SyncPhase};
pub use wal::{
    RecoveryResult, SyncMode, WalConfig, WalEntry, WalEntryStatus, WalOperation, WalStats,
    WalTarget, WriteAheadLog, LSN,
};
