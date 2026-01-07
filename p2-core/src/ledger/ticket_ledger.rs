//! Ticket Ledger Implementation
//!
//! Persistent storage for access tickets.
//! All payload access MUST go through a valid ticket.
//! All data is encrypted at rest using the encrypted_storage module.

use async_trait::async_trait;
use chrono::Utc;
use l0_core::types::ActorId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::fs;
use tokio::sync::RwLock;

use super::encrypted_storage::{EncryptedStorage, EncryptedStorageConfig};
use super::traits::TicketLedger;
use crate::error::{P2Error, P2Result};
use crate::types::{
    AccessTicket, PayloadSelector, TicketPermission, TicketRequest, TicketStatus,
};
use l0_core::types::Digest;

/// Index entry for ticket lookup
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TicketIndexEntry {
    ticket_id: String,
    holder: String,
    issuer: String,
    target_resource_ref: String,
    issued_at: chrono::DateTime<Utc>,
    valid_until: chrono::DateTime<Utc>,
    status: TicketStatus,
}

/// File-based ticket ledger implementation with encryption at rest
pub struct FileTicketLedger {
    /// Base path for ticket storage
    base_path: PathBuf,
    /// Tickets directory
    tickets_path: PathBuf,
    /// Index path
    index_path: PathBuf,
    /// In-memory index cache
    index_cache: RwLock<HashMap<String, TicketIndexEntry>>,
    /// Encrypted storage handler
    storage: EncryptedStorage,
}

impl FileTicketLedger {
    /// Create a new file-based ticket ledger with default encryption
    pub async fn new(base_path: impl Into<PathBuf>) -> P2Result<Self> {
        Self::with_config(base_path, EncryptedStorageConfig::default()).await
    }

    /// Create with custom encryption config
    pub async fn with_config(
        base_path: impl Into<PathBuf>,
        encryption_config: EncryptedStorageConfig,
    ) -> P2Result<Self> {
        let base_path = base_path.into();
        let tickets_path = base_path.join("tickets");
        let index_path = base_path.join("ticket_index.enc");

        // Create directories
        for path in [&base_path, &tickets_path] {
            fs::create_dir_all(path).await.map_err(|e| {
                P2Error::Storage(format!("Failed to create directory {:?}: {}", path, e))
            })?;
        }

        let storage = EncryptedStorage::new(encryption_config);

        // Load or create index
        let index_cache = if index_path.exists() {
            let entries: Vec<TicketIndexEntry> = storage
                .read(&index_path, "ticket-ledger-index")
                .await
                .unwrap_or_default();
            let mut map = HashMap::new();
            for entry in entries {
                map.insert(entry.ticket_id.clone(), entry);
            }
            RwLock::new(map)
        } else {
            RwLock::new(HashMap::new())
        };

        Ok(Self {
            base_path,
            tickets_path,
            index_path,
            index_cache,
            storage,
        })
    }

    /// Create with encryption disabled (for testing only)
    #[cfg(test)]
    pub async fn unencrypted(base_path: impl Into<PathBuf>) -> P2Result<Self> {
        Self::with_config(base_path, EncryptedStorageConfig::unencrypted()).await
    }

    /// Save the index to disk (encrypted)
    async fn save_index(&self) -> P2Result<()> {
        let entries: Vec<_> = self
            .index_cache
            .read()
            .await
            .values()
            .cloned()
            .collect();

        self.storage
            .write(&self.index_path, &entries, "ticket-ledger-index")
            .await
    }

    /// Get the file path for a ticket
    fn ticket_file_path(&self, ticket_id: &str) -> PathBuf {
        self.tickets_path.join(format!("{}.enc", ticket_id))
    }

    /// Write ticket to disk (encrypted)
    async fn write_ticket(&self, ticket: &AccessTicket) -> P2Result<()> {
        let path = self.ticket_file_path(&ticket.ticket_id);
        self.storage.write(&path, ticket, &ticket.ticket_id).await
    }

    /// Read ticket from disk (encrypted)
    async fn read_ticket(&self, ticket_id: &str) -> P2Result<Option<AccessTicket>> {
        let path = self.ticket_file_path(ticket_id);
        if !path.exists() {
            return Ok(None);
        }

        let ticket: AccessTicket = self.storage.read(&path, ticket_id).await?;
        Ok(Some(ticket))
    }
}

#[async_trait]
impl TicketLedger for FileTicketLedger {
    async fn issue_ticket(
        &self,
        request: TicketRequest,
        issuer: &ActorId,
    ) -> P2Result<AccessTicket> {
        let ticket_id = format!("ticket:{}", uuid::Uuid::new_v4());
        let valid_until = Utc::now() + chrono::Duration::seconds(request.validity_seconds as i64);
        let purpose_digest = Digest::blake3(request.purpose.as_bytes());

        let mut ticket = AccessTicket::new(
            ticket_id.clone(),
            request.consent_ref,
            request.holder,
            issuer.clone(),
            request.target_resource_ref,
            request.permissions,
            request.selector,
            valid_until,
            purpose_digest,
        );

        if request.one_time {
            ticket.set_one_time();
        }

        // Write ticket to disk
        self.write_ticket(&ticket).await?;

        // Update index
        {
            let mut cache = self.index_cache.write().await;
            cache.insert(
                ticket_id.clone(),
                TicketIndexEntry {
                    ticket_id: ticket_id.clone(),
                    holder: ticket.holder.0.clone(),
                    issuer: ticket.issuer.0.clone(),
                    target_resource_ref: ticket.target_resource_ref.clone(),
                    issued_at: ticket.issued_at,
                    valid_until: ticket.valid_until,
                    status: ticket.status,
                },
            );
        }

        self.save_index().await?;

        Ok(ticket)
    }

    async fn get_ticket(&self, ticket_id: &str) -> P2Result<Option<AccessTicket>> {
        self.read_ticket(ticket_id).await
    }

    async fn use_ticket(&self, ticket_id: &str) -> P2Result<AccessTicket> {
        // Read current ticket
        let mut ticket = self.read_ticket(ticket_id).await?.ok_or_else(|| {
            P2Error::Storage(format!("Ticket not found: {}", ticket_id))
        })?;

        // Use the ticket (this validates and increments counter)
        ticket.use_ticket().map_err(|e| {
            P2Error::Storage(format!("Failed to use ticket: {}", e))
        })?;

        // Write back
        self.write_ticket(&ticket).await?;

        // Update index status if needed
        if ticket.one_time || ticket.remaining_uses() == Some(0) {
            let mut cache = self.index_cache.write().await;
            if let Some(entry) = cache.get_mut(ticket_id) {
                entry.status = TicketStatus::Used;
            }
            drop(cache);
            self.save_index().await?;
        }

        Ok(ticket)
    }

    async fn revoke_ticket(&self, ticket_id: &str, reason: &str) -> P2Result<()> {
        // Read current ticket
        let mut ticket = self.read_ticket(ticket_id).await?.ok_or_else(|| {
            P2Error::Storage(format!("Ticket not found: {}", ticket_id))
        })?;

        // Revoke
        ticket.revoke(reason);

        // Write back
        self.write_ticket(&ticket).await?;

        // Update index
        {
            let mut cache = self.index_cache.write().await;
            if let Some(entry) = cache.get_mut(ticket_id) {
                entry.status = TicketStatus::Revoked;
            }
        }

        self.save_index().await?;

        Ok(())
    }

    async fn list_tickets_by_holder(
        &self,
        holder: &ActorId,
        include_expired: bool,
    ) -> P2Result<Vec<AccessTicket>> {
        let now = Utc::now();
        let entries = {
            let cache = self.index_cache.read().await;
            cache
                .values()
                .filter(|e| {
                    e.holder == holder.0
                        && (include_expired || e.valid_until > now)
                })
                .cloned()
                .collect::<Vec<_>>()
        };

        let mut tickets = Vec::new();
        for entry in entries {
            if let Some(ticket) = self.read_ticket(&entry.ticket_id).await? {
                tickets.push(ticket);
            }
        }

        // Sort by issued_at descending
        tickets.sort_by(|a, b| b.issued_at.cmp(&a.issued_at));

        Ok(tickets)
    }

    async fn list_tickets_for_resource(&self, resource_ref: &str) -> P2Result<Vec<AccessTicket>> {
        let entries = {
            let cache = self.index_cache.read().await;
            cache
                .values()
                .filter(|e| e.target_resource_ref == resource_ref)
                .cloned()
                .collect::<Vec<_>>()
        };

        let mut tickets = Vec::new();
        for entry in entries {
            if let Some(ticket) = self.read_ticket(&entry.ticket_id).await? {
                tickets.push(ticket);
            }
        }

        // Sort by issued_at descending
        tickets.sort_by(|a, b| b.issued_at.cmp(&a.issued_at));

        Ok(tickets)
    }

    async fn check_permission(
        &self,
        ticket_id: &str,
        permission: TicketPermission,
        selector: &PayloadSelector,
    ) -> P2Result<bool> {
        let ticket = match self.read_ticket(ticket_id).await? {
            Some(t) => t,
            None => return Ok(false),
        };

        // Check if ticket is valid
        if !ticket.is_valid() {
            return Ok(false);
        }

        // Check permission
        if !ticket.has_permission(permission) {
            return Ok(false);
        }

        // Check selector scope
        if !ticket.selector_within_scope(selector) {
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_request() -> TicketRequest {
        TicketRequest {
            consent_ref: "consent:test".to_string(),
            holder: ActorId::new("actor:holder"),
            target_resource_ref: "payload:001".to_string(),
            permissions: vec![TicketPermission::Read],
            selector: PayloadSelector::full(),
            validity_seconds: 3600,
            purpose: "test purpose".to_string(),
            one_time: false,
        }
    }

    #[tokio::test]
    async fn test_issue_and_get_ticket() {
        let temp_dir = TempDir::new().unwrap();
        let ledger = FileTicketLedger::unencrypted(temp_dir.path()).await.unwrap();

        let issuer = ActorId::new("actor:issuer");
        let request = create_test_request();

        let ticket = ledger.issue_ticket(request, &issuer).await.unwrap();
        assert!(ticket.is_valid());

        let retrieved = ledger.get_ticket(&ticket.ticket_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().ticket_id, ticket.ticket_id);
    }

    #[tokio::test]
    async fn test_use_ticket() {
        let temp_dir = TempDir::new().unwrap();
        let ledger = FileTicketLedger::unencrypted(temp_dir.path()).await.unwrap();

        let issuer = ActorId::new("actor:issuer");
        let request = create_test_request();

        let ticket = ledger.issue_ticket(request, &issuer).await.unwrap();
        let ticket_id = ticket.ticket_id.clone();

        // Use the ticket
        let used = ledger.use_ticket(&ticket_id).await.unwrap();
        assert_eq!(used.used_count, 1);

        // Use again
        let used = ledger.use_ticket(&ticket_id).await.unwrap();
        assert_eq!(used.used_count, 2);
    }

    #[tokio::test]
    async fn test_one_time_ticket() {
        let temp_dir = TempDir::new().unwrap();
        let ledger = FileTicketLedger::unencrypted(temp_dir.path()).await.unwrap();

        let issuer = ActorId::new("actor:issuer");
        let mut request = create_test_request();
        request.one_time = true;

        let ticket = ledger.issue_ticket(request, &issuer).await.unwrap();
        let ticket_id = ticket.ticket_id.clone();

        // First use succeeds
        ledger.use_ticket(&ticket_id).await.unwrap();

        // Second use fails
        let result = ledger.use_ticket(&ticket_id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_revoke_ticket() {
        let temp_dir = TempDir::new().unwrap();
        let ledger = FileTicketLedger::unencrypted(temp_dir.path()).await.unwrap();

        let issuer = ActorId::new("actor:issuer");
        let request = create_test_request();

        let ticket = ledger.issue_ticket(request, &issuer).await.unwrap();
        let ticket_id = ticket.ticket_id.clone();

        // Revoke
        ledger.revoke_ticket(&ticket_id, "test revocation").await.unwrap();

        // Check status
        let revoked = ledger.get_ticket(&ticket_id).await.unwrap().unwrap();
        assert_eq!(revoked.status, TicketStatus::Revoked);

        // Cannot use revoked ticket
        let result = ledger.use_ticket(&ticket_id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_tickets_by_holder() {
        let temp_dir = TempDir::new().unwrap();
        let ledger = FileTicketLedger::unencrypted(temp_dir.path()).await.unwrap();

        let issuer = ActorId::new("actor:issuer");
        let holder = ActorId::new("actor:holder");

        // Issue 3 tickets
        for _ in 0..3 {
            let request = create_test_request();
            ledger.issue_ticket(request, &issuer).await.unwrap();
        }

        let tickets = ledger.list_tickets_by_holder(&holder, false).await.unwrap();
        assert_eq!(tickets.len(), 3);
    }

    #[tokio::test]
    async fn test_check_permission() {
        let temp_dir = TempDir::new().unwrap();
        let ledger = FileTicketLedger::unencrypted(temp_dir.path()).await.unwrap();

        let issuer = ActorId::new("actor:issuer");
        let request = create_test_request();

        let ticket = ledger.issue_ticket(request, &issuer).await.unwrap();

        // Has Read permission
        assert!(ledger
            .check_permission(&ticket.ticket_id, TicketPermission::Read, &PayloadSelector::full())
            .await
            .unwrap());

        // Does not have Export permission
        assert!(!ledger
            .check_permission(&ticket.ticket_id, TicketPermission::Export, &PayloadSelector::full())
            .await
            .unwrap());
    }
}
