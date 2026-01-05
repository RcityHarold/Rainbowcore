//! P2/DSN Core - Encrypted Permanence Domain
//!
//! P2 is the "Encrypted Permanence Domain" in the Rainbow Public Reality Stack.
//! It stores encrypted payloads for:
//! - Life entity data: S6 subject AI resurrection snapshots (R0/R1)
//! - Evidence payloads: Encrypted evidence bundles for judicial discovery
//! - Audit materials: Decrypt/export/sampling audit artifacts
//!
//! # Key Principles (Hard Invariants)
//!
//! 1. **Append-only**: Only add, never modify or delete (corrections via append)
//! 2. **Zero plaintext**: P2 stores ciphertext, decryption requires ticketed access
//! 3. **Non-platform**: Any critical assertion is third-party verifiable
//! 4. **payload_map_commit reconciliation**: Missing map commit = B-level evidence
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    P1 (L0 Consensus Layer)                   │
//! │         Zero plaintext · Only commits/indices/receipts       │
//! │                                                              │
//! │   payload_map_commit ←────────────────┐                      │
//! │   snapshot_commit                     │                      │
//! │   receipt                             │                      │
//! └───────────────────────────────────────│──────────────────────┘
//!                                         │ Reconciliation
//! ┌───────────────────────────────────────│──────────────────────┐
//! │                    P2 (DSN Layer)      │                      │
//! │         Encrypted permanence · Ticketed access               │
//! │                                        │                      │
//! │   sealed_payload_ref ─────────────────┘                      │
//! │   EvidenceBundle                                             │
//! │   ResurrectionSnapshot                                       │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Core Types
//!
//! - [`SealedPayloadRef`]: Reference to an encrypted payload
//! - [`SkeletonSnapshot`]: R0 minimal resurrection snapshot (MUST)
//! - [`FullResurrectionSnapshot`]: R1 full resurrection snapshot (SHOULD)
//! - [`EvidenceBundle`]: Encrypted evidence package
//! - [`AccessTicket`]: Ticketed forensic access
//! - [`PayloadSelector`]: Minimal disclosure selector
//! - [`DecryptAuditLog`]: Mandatory decrypt audit log
//!
//! # Evidence Levels
//!
//! - **Level A**: Receipt-backed + payload_map_commit reconciled
//! - **Level B**: Missing receipt or map_commit (can upgrade via backfill)
//!
//! Hard rule: Missing payload_map_commit MUST be level B.

pub mod crypto;
pub mod error;
pub mod ledger;
pub mod types;

// Re-export commonly used types
pub use error::{P2Error, P2Result};

pub use types::{
    // Sealed Payload
    SealedPayloadRef, SealedPayloadStatus, StorageTemperature, EncryptionMetadata,
    // Resurrection
    SkeletonSnapshot, FullResurrectionSnapshot, R0Trigger, R1Trigger,
    ContinuityState, MapCommitRef, MissingPayloads, MissingReason,
    // Evidence
    EvidenceBundle, EvidenceLevel, EvidenceType, EvidenceBundleStatus,
    // Tickets
    AccessTicket, TicketPermission, TicketStatus, TicketValidation, TicketError, TicketRequest,
    // Selectors
    PayloadSelector, SelectorType,
    // Audit
    DecryptAuditLog, ExportAuditLog, SamplingArtifact, DecryptOutcome,
    ReachabilityStatus, SamplingPolicy,
};

pub use ledger::{
    AuditLedger, EvidenceLedger, PayloadMetadata, PayloadStore, SnapshotLedger, TicketLedger,
};

pub use crypto::{EnvelopeEncryption, SealedEnvelope};

/// P2 version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// P2 protocol version
pub const PROTOCOL_VERSION: &str = "v1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
        assert_eq!(PROTOCOL_VERSION, "v1");
    }

    #[test]
    fn test_evidence_level_rule() {
        // Verify the hard rule: missing map_commit = level B
        use types::evidence_bundle::EvidenceBundle;
        use l0_core::types::ActorId;

        let bundle = EvidenceBundle::new(
            "bundle:test".to_string(),
            "case:test".to_string(),
            ActorId::new("actor:submitter"),
            Vec::new(),
        );

        // No receipt, no map_commit -> must be B
        assert_eq!(bundle.evidence_level(), EvidenceLevel::B);
    }
}
