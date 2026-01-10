//! Application State
//!
//! Shared state for the P2 API service.
//!
//! # Production Usage
//!
//! In production, always use `AppState::new()` with an L0 URL:
//! ```ignore
//! let state = AppState::new(storage_path, l0_url).await?;
//! ```
//!
//! For testing, use `AppState::for_testing()`.

use std::sync::Arc;

use bridge::L0CommitClient;
#[cfg(test)]
use bridge::MockL0Client;
use p2_core::ledger::{FileAuditLedger, FileEvidenceLedger, FileSnapshotLedger, FileSyncLedger, FileTicketLedger};
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
    /// Sync state ledger
    pub sync_ledger: Arc<FileSyncLedger>,
    /// Snapshot ledger (R0/R1 resurrection snapshots)
    pub snapshot_ledger: Arc<FileSnapshotLedger>,
    /// L0 commit client
    pub l0_client: Arc<dyn L0CommitClient>,
}

impl AppState {
    /// Create new application state with L0 URL (RECOMMENDED FOR PRODUCTION)
    ///
    /// This connects to a real L0 instance for commitment anchoring.
    ///
    /// # Arguments
    /// * `storage_path` - Path for local storage
    /// * `l0_url` - URL of the L0 API (e.g., "http://localhost:8080")
    pub async fn new(
        storage_path: &str,
        l0_url: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let l0_client = Arc::new(bridge::HttpL0Client::new(l0_url));
        Self::with_l0_client(storage_path, l0_client).await
    }

    /// Create application state for testing with mock L0 client
    ///
    /// # Security Warning
    /// This uses a mock L0 client that doesn't provide real commitment anchoring.
    /// Only use in tests and development.
    #[cfg(test)]
    pub async fn for_testing(storage_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_l0_client(storage_path, Arc::new(MockL0Client::new())).await
    }

    /// Create application state with mock L0 client (TESTING ONLY)
    ///
    /// # Security Warning
    /// **NOT FOR PRODUCTION!** This uses a mock L0 client that doesn't
    /// provide real commitment anchoring. Use `new()` with an L0 URL instead.
    ///
    /// This method is only available in test builds.
    #[cfg(test)]
    pub async fn new_mock(storage_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_l0_client(storage_path, Arc::new(MockL0Client::new())).await
    }

    /// Create new application state with custom L0 client
    pub async fn with_l0_client(
        storage_path: &str,
        l0_client: Arc<dyn L0CommitClient>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
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
        let sync_ledger = Arc::new(
            FileSyncLedger::new(format!("{}/sync", ledger_path)).await?,
        );
        let snapshot_ledger = Arc::new(
            FileSnapshotLedger::new(format!("{}/snapshots", ledger_path)).await?,
        );

        Ok(Self {
            storage,
            evidence_ledger,
            ticket_ledger,
            audit_ledger,
            sync_ledger,
            snapshot_ledger,
            l0_client,
        })
    }

    /// Create with custom storage backend, L0 client, and ledger path
    ///
    /// # Arguments
    /// * `storage` - Storage backend for payload data
    /// * `l0_client` - L0 commitment client for anchoring
    /// * `ledger_path` - Base path for ledger storage (must be persistent and secure)
    ///
    /// # Panics
    /// Panics if ledger initialization fails. Use `try_with_storage_and_l0` for
    /// fallible initialization.
    pub fn with_storage_and_l0(
        storage: Arc<LocalStorageBackend>,
        l0_client: Arc<dyn L0CommitClient>,
        ledger_path: &str,
    ) -> Self {
        Self::try_with_storage_and_l0(storage, l0_client, ledger_path)
            .expect("Failed to initialize ledgers")
    }

    /// Create with custom storage backend, L0 client, and ledger path (fallible)
    ///
    /// # Arguments
    /// * `storage` - Storage backend for payload data
    /// * `l0_client` - L0 commitment client for anchoring
    /// * `ledger_path` - Base path for ledger storage (must be persistent and secure)
    ///
    /// # Returns
    /// Error if ledger initialization fails
    pub fn try_with_storage_and_l0(
        storage: Arc<LocalStorageBackend>,
        l0_client: Arc<dyn L0CommitClient>,
        ledger_path: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Validate ledger path is not /tmp (unreliable for production)
        if ledger_path.starts_with("/tmp") {
            tracing::warn!(
                path = ledger_path,
                "Using /tmp for ledger storage is NOT recommended for production. \
                 Data may be lost on system restart."
            );
        }

        // Use blocking runtime to create ledgers
        let rt = tokio::runtime::Handle::current();
        let evidence_ledger = rt
            .block_on(FileEvidenceLedger::new(format!("{}/evidence", ledger_path)))?;
        let ticket_ledger = rt
            .block_on(FileTicketLedger::new(format!("{}/tickets", ledger_path)))?;
        let audit_ledger = rt
            .block_on(FileAuditLedger::new(format!("{}/audit", ledger_path)))?;
        let sync_ledger = rt
            .block_on(FileSyncLedger::new(format!("{}/sync", ledger_path)))?;
        let snapshot_ledger = rt
            .block_on(FileSnapshotLedger::new(format!("{}/snapshots", ledger_path)))?;

        Ok(Self {
            storage,
            evidence_ledger: Arc::new(evidence_ledger),
            ticket_ledger: Arc::new(ticket_ledger),
            audit_ledger: Arc::new(audit_ledger),
            sync_ledger: Arc::new(sync_ledger),
            snapshot_ledger: Arc::new(snapshot_ledger),
            l0_client,
        })
    }

    /// Create with custom storage backend (TESTING ONLY)
    ///
    /// # Security Warning
    /// **NOT FOR PRODUCTION!**
    /// - Uses mock L0 client (no real commitment anchoring)
    /// - Uses /tmp for ledger storage (data loss risk on restart)
    ///
    /// This method is only available in test builds.
    /// Use `with_storage_and_l0(storage, l0_client, ledger_path)` instead.
    #[cfg(test)]
    pub fn with_storage(storage: Arc<LocalStorageBackend>) -> Self {
        Self::with_storage_and_l0(storage, Arc::new(MockL0Client::new()), "/tmp/p2-ledgers")
    }

    /// Create with all components
    pub fn with_components(
        storage: Arc<LocalStorageBackend>,
        evidence_ledger: Arc<FileEvidenceLedger>,
        ticket_ledger: Arc<FileTicketLedger>,
        audit_ledger: Arc<FileAuditLedger>,
        sync_ledger: Arc<FileSyncLedger>,
        snapshot_ledger: Arc<FileSnapshotLedger>,
        l0_client: Arc<dyn L0CommitClient>,
    ) -> Self {
        Self {
            storage,
            evidence_ledger,
            ticket_ledger,
            audit_ledger,
            sync_ledger,
            snapshot_ledger,
            l0_client,
        }
    }
}
