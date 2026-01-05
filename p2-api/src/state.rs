//! Application State
//!
//! Shared state for the P2 API service.

use std::sync::Arc;

use p2_core::ledger::{FileAuditLedger, FileEvidenceLedger, FileTicketLedger};
use p2_storage::LocalStorageBackend;

/// Application state
#[derive(Clone)]
pub struct AppState {
    /// Storage backend
    pub storage: Arc<LocalStorageBackend>,
    /// Evidence ledger
    pub evidence_ledger: Arc<FileEvidenceLedger>,
    /// Ticket ledger
    pub ticket_ledger: Arc<FileTicketLedger>,
    /// Audit ledger
    pub audit_ledger: Arc<FileAuditLedger>,
}

impl AppState {
    /// Create new application state
    pub async fn new(storage_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let storage = Arc::new(LocalStorageBackend::new(storage_path).await?);

        // Initialize ledgers in ledger subdirectory
        let ledger_path = format!("{}/ledgers", storage_path);
        let evidence_ledger = Arc::new(
            FileEvidenceLedger::new(format!("{}/evidence", ledger_path)).await?,
        );
        let ticket_ledger = Arc::new(
            FileTicketLedger::new(format!("{}/tickets", ledger_path)).await?,
        );
        let audit_ledger = Arc::new(
            FileAuditLedger::new(format!("{}/audit", ledger_path)).await?,
        );

        Ok(Self {
            storage,
            evidence_ledger,
            ticket_ledger,
            audit_ledger,
        })
    }

    /// Create with custom storage backend (ledgers will be at default location)
    pub fn with_storage(storage: Arc<LocalStorageBackend>) -> Self {
        // For backwards compatibility, use blocking runtime to create ledgers
        // In production, prefer using new() which is async
        let rt = tokio::runtime::Handle::current();
        let evidence_ledger = rt
            .block_on(FileEvidenceLedger::new("/tmp/p2-ledgers/evidence"))
            .expect("Failed to create evidence ledger");
        let ticket_ledger = rt
            .block_on(FileTicketLedger::new("/tmp/p2-ledgers/tickets"))
            .expect("Failed to create ticket ledger");
        let audit_ledger = rt
            .block_on(FileAuditLedger::new("/tmp/p2-ledgers/audit"))
            .expect("Failed to create audit ledger");

        Self {
            storage,
            evidence_ledger: Arc::new(evidence_ledger),
            ticket_ledger: Arc::new(ticket_ledger),
            audit_ledger: Arc::new(audit_ledger),
        }
    }

    /// Create with all components
    pub fn with_components(
        storage: Arc<LocalStorageBackend>,
        evidence_ledger: Arc<FileEvidenceLedger>,
        ticket_ledger: Arc<FileTicketLedger>,
        audit_ledger: Arc<FileAuditLedger>,
    ) -> Self {
        Self {
            storage,
            evidence_ledger,
            ticket_ledger,
            audit_ledger,
        }
    }
}
