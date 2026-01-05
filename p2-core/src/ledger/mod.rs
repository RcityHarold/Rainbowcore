//! P2 Ledger Module
//!
//! This module provides ledger traits and implementations for P2 operations.
//! Includes file-based implementations for:
//! - Snapshot Ledger (R0/R1 resurrection snapshots)
//! - Evidence Ledger (evidence bundles with P1 commitment tracking)
//! - Audit Ledger (decrypt, export, and sampling audit logs)
//! - Ticket Ledger (access tickets for forensic access)

pub mod traits;
pub mod audit_ledger;
pub mod evidence_ledger;
pub mod snapshot_ledger;
pub mod ticket_ledger;

pub use traits::{
    AuditLedger, EvidenceLedger, PayloadMetadata, PayloadStore, SnapshotLedger, TicketLedger,
};

pub use audit_ledger::FileAuditLedger;
pub use evidence_ledger::FileEvidenceLedger;
pub use snapshot_ledger::FileSnapshotLedger;
pub use ticket_ledger::FileTicketLedger;
