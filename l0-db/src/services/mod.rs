//! L0 Ledger Service Implementations
//!
//! This module provides concrete implementations of the ledger traits
//! defined in l0-core using the l0-db storage layer.

pub mod access_ticket_service;
pub mod anchor_service;
pub mod backfill_service;
pub mod causality_service;
pub mod civilization_tax_service;
pub mod consent_service;
pub mod decrypt_audit_service;
pub mod degraded_mode_service;
pub mod dispute_service;
pub mod guardian_consent_service;
pub mod identity_service;
pub mod knowledge_service;
pub mod observer_report_service;
pub mod p4_integration;
pub mod receipt_service;
pub mod signer_set_service;
pub mod tipwitness_service;

pub use access_ticket_service::{ForensicAccessTicketLedger, ForensicAccessTicketService, TicketAuditEntry, TicketUsageResult};
pub use guardian_consent_service::{GuardianConsentLedger, GuardianConsentService, PendingApprovals};
pub use anchor_service::AnchorService;
pub use backfill_service::BackfillService;
pub use causality_service::CausalityService;
pub use civilization_tax_service::{CivilizationTaxLedger, CivilizationTaxService};
pub use consent_service::ConsentService;
pub use decrypt_audit_service::{DecryptAuditLedger, DecryptAuditService};
pub use degraded_mode_service::{DegradedModeLedger, DegradedModeService};
pub use dispute_service::DisputeService;
pub use identity_service::IdentityService;
pub use knowledge_service::KnowledgeService;
pub use p4_integration::{AnchorProvider, MockAnchorProvider};
pub use observer_report_service::{ObserverReportLedger, ObserverReportService};
pub use receipt_service::ReceiptService;
pub use signer_set_service::{SignerSetLedger, SignerSetService};
pub use tipwitness_service::{TipWitnessChainVerification, TipWitnessService, TipWitnessSubmission};

#[cfg(feature = "p4")]
pub use p4_integration::P4AnchorProvider;
