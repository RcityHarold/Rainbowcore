//! Access Ticket Service
//!
//! Manages access tickets for forensic data access with audit logging.

use async_trait::async_trait;
use chrono::{Duration, Utc};
use l0_core::error::LedgerError;
use l0_core::ledger::LedgerResult;
use l0_core::types::{
    AccessPurpose, AccessScope, Digest, ForensicAccessTicket, ForensicTicketStatus,
    TicketApproval, TicketRequest, TicketVerification,
};
use l0_core::types::ActorId;
use soulbase_storage::surreal::SurrealDatastore;
use soulbase_storage::Datastore;
use soulbase_types::prelude::TenantId;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Access Ticket Ledger trait
#[async_trait]
pub trait ForensicAccessTicketLedger: Send + Sync {
    /// Request a new access ticket
    async fn request_ticket(&self, request: TicketRequest) -> LedgerResult<ForensicAccessTicket>;

    /// Approve a pending ticket
    async fn approve_ticket(
        &self,
        ticket_id: &str,
        approver_id: &ActorId,
        signature: &str,
        notes: Option<&str>,
    ) -> LedgerResult<ForensicAccessTicket>;

    /// Verify a ticket is valid for use
    async fn verify_ticket(&self, ticket_id: &str) -> LedgerResult<TicketVerification>;

    /// Use a ticket (records usage and returns decryption key reference)
    async fn use_ticket(&self, ticket_id: &str) -> LedgerResult<TicketUsageResult>;

    /// Revoke a ticket
    async fn revoke_ticket(&self, ticket_id: &str, reason: &str) -> LedgerResult<()>;

    /// Get ticket by ID
    async fn get_ticket(&self, ticket_id: &str) -> LedgerResult<Option<ForensicAccessTicket>>;

    /// List tickets by requester
    async fn list_by_requester(
        &self,
        requester_id: &ActorId,
        limit: usize,
    ) -> LedgerResult<Vec<ForensicAccessTicket>>;

    /// List pending tickets requiring approval
    async fn list_pending_tickets(&self, limit: usize) -> LedgerResult<Vec<ForensicAccessTicket>>;

    /// Get audit log for a ticket
    async fn get_ticket_audit_log(&self, ticket_id: &str) -> LedgerResult<Vec<TicketAuditEntry>>;
}

/// Result of using a ticket
#[derive(Debug, Clone)]
pub struct TicketUsageResult {
    /// Ticket ID
    pub ticket_id: String,
    /// Decryption key reference (to be fetched from key service)
    pub key_ref: String,
    /// Scope of access granted
    pub scope: AccessScope,
    /// Usage recorded at
    pub used_at: chrono::DateTime<Utc>,
    /// Remaining uses (if limited)
    pub remaining_uses: Option<u32>,
}

/// Audit log entry for ticket operations
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TicketAuditEntry {
    /// Entry ID
    pub entry_id: String,
    /// Ticket ID
    pub ticket_id: String,
    /// Action performed
    pub action: TicketAction,
    /// Actor who performed the action
    pub actor_id: ActorId,
    /// Timestamp
    pub timestamp: chrono::DateTime<Utc>,
    /// Additional details
    pub details: Option<String>,
    /// IP address (if available)
    pub ip_address: Option<String>,
}

/// Ticket action types for audit log
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketAction {
    Requested,
    Approved,
    Rejected,
    Used,
    Revoked,
    Expired,
    Verified,
}

/// Access Ticket Service implementation
pub struct ForensicAccessTicketService {
    datastore: Arc<SurrealDatastore>,
    tenant_id: TenantId,
    /// In-memory ticket storage (would be persisted in production)
    tickets: RwLock<HashMap<String, ForensicAccessTicket>>,
    /// Audit log entries
    audit_log: RwLock<Vec<TicketAuditEntry>>,
    sequence: std::sync::atomic::AtomicU64,
}

impl ForensicAccessTicketService {
    /// Create a new Access Ticket Service
    pub fn new(datastore: Arc<SurrealDatastore>, tenant_id: TenantId) -> Self {
        Self {
            datastore,
            tenant_id,
            tickets: RwLock::new(HashMap::new()),
            audit_log: RwLock::new(Vec::new()),
            sequence: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Generate a new ticket ID
    fn generate_ticket_id(&self) -> String {
        let seq = self.sequence.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let timestamp = Utc::now().timestamp_micros();
        format!("ticket_{:016x}_{:08x}", timestamp, seq)
    }

    /// Generate an audit entry ID
    fn generate_audit_id(&self) -> String {
        let seq = self.sequence.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let timestamp = Utc::now().timestamp_micros();
        format!("audit_{:016x}_{:08x}", timestamp, seq)
    }

    /// Log an audit entry
    fn log_audit(
        &self,
        ticket_id: &str,
        action: TicketAction,
        actor_id: &ActorId,
        details: Option<String>,
    ) {
        let entry = TicketAuditEntry {
            entry_id: self.generate_audit_id(),
            ticket_id: ticket_id.to_string(),
            action,
            actor_id: actor_id.clone(),
            timestamp: Utc::now(),
            details,
            ip_address: None,
        };

        let mut log = self.audit_log.write().unwrap();
        log.push(entry);
    }

    /// Save ticket to database
    async fn save_ticket_to_db(&self, ticket: &ForensicAccessTicket) -> LedgerResult<()> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let id = format!("access_tickets:{}:{}", self.tenant_id.0, ticket.ticket_id);
        let ticket_id = ticket.ticket_id.clone();
        let sealed_payload_ref = ticket.sealed_payload_ref.clone();
        let requester_id = ticket.requester_id.0.clone();
        let purpose = serde_json::to_string(&ticket.purpose).unwrap_or_default();
        let status = format!("{:?}", ticket.status).to_lowercase();
        let created_at = ticket.created_at;
        let expires_at = ticket.expires_at;
        let use_count = ticket.use_count;
        let max_uses = ticket.max_uses;

        session
            .client()
            .query("UPSERT $id SET tenant_id = $tenant, ticket_id = $ticket_id, sealed_payload_ref = $sealed_payload_ref, requester_id = $requester_id, purpose = $purpose, status = $status, created_at = $created_at, expires_at = $expires_at, use_count = $use_count, max_uses = $max_uses")
            .bind(("id", id))
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("ticket_id", ticket_id))
            .bind(("sealed_payload_ref", sealed_payload_ref))
            .bind(("requester_id", requester_id))
            .bind(("purpose", purpose))
            .bind(("status", status))
            .bind(("created_at", created_at))
            .bind(("expires_at", expires_at))
            .bind(("use_count", use_count))
            .bind(("max_uses", max_uses))
            .await
            .map_err(|e| LedgerError::Storage(format!("Save ticket failed: {}", e)))?;

        Ok(())
    }

    /// Save audit entry to database
    async fn save_audit_to_db(&self, entry: &TicketAuditEntry) -> LedgerResult<()> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let id = format!("ticket_audit:{}:{}", self.tenant_id.0, entry.entry_id);
        let entry_id = entry.entry_id.clone();
        let ticket_id = entry.ticket_id.clone();
        let action = format!("{:?}", entry.action).to_lowercase();
        let actor_id = entry.actor_id.0.clone();
        let timestamp = entry.timestamp;
        let details = entry.details.clone();

        session
            .client()
            .query("CREATE $id SET tenant_id = $tenant, entry_id = $entry_id, ticket_id = $ticket_id, action = $action, actor_id = $actor_id, timestamp = $timestamp, details = $details")
            .bind(("id", id))
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("entry_id", entry_id))
            .bind(("ticket_id", ticket_id))
            .bind(("action", action))
            .bind(("actor_id", actor_id))
            .bind(("timestamp", timestamp))
            .bind(("details", details))
            .await
            .map_err(|e| LedgerError::Storage(format!("Save audit failed: {}", e)))?;

        Ok(())
    }
}

#[async_trait]
impl ForensicAccessTicketLedger for ForensicAccessTicketService {
    async fn request_ticket(&self, request: TicketRequest) -> LedgerResult<ForensicAccessTicket> {
        let ticket_id = self.generate_ticket_id();
        let now = Utc::now();

        // Determine initial status based on purpose
        let initial_status = if request.purpose.requires_multi_approval() {
            ForensicTicketStatus::Pending
        } else {
            ForensicTicketStatus::Active
        };

        // Calculate payload digest (in production, would verify payload exists)
        let payload_digest = Digest::blake3(request.sealed_payload_ref.as_bytes());

        let ticket = ForensicAccessTicket {
            ticket_id: ticket_id.clone(),
            sealed_payload_ref: request.sealed_payload_ref,
            payload_digest,
            requester_id: request.requester_id.clone(),
            purpose: request.purpose,
            status: initial_status,
            created_at: now,
            expires_at: now + request.duration,
            used_at: None,
            revoked_at: None,
            revocation_reason: None,
            approvals: Vec::new(),
            max_uses: Some(10), // Default max uses
            use_count: 0,
            scope: request.scope,
            audit_log_ref: None,
        };

        // Store ticket
        {
            let mut tickets = self.tickets.write().unwrap();
            tickets.insert(ticket_id.clone(), ticket.clone());
        }

        // Log audit entry
        self.log_audit(
            &ticket_id,
            TicketAction::Requested,
            &request.requester_id,
            Some(request.justification),
        );

        // Persist to database
        self.save_ticket_to_db(&ticket).await?;

        Ok(ticket)
    }

    async fn approve_ticket(
        &self,
        ticket_id: &str,
        approver_id: &ActorId,
        signature: &str,
        notes: Option<&str>,
    ) -> LedgerResult<ForensicAccessTicket> {
        let result = {
            let mut tickets = self.tickets.write().unwrap();

            let ticket = tickets.get_mut(ticket_id).ok_or_else(|| {
                LedgerError::NotFound(format!("Ticket {} not found", ticket_id))
            })?;

            if ticket.status != ForensicTicketStatus::Pending && ticket.status != ForensicTicketStatus::Active {
                return Err(LedgerError::InvalidStateTransition(
                    format!("Cannot approve ticket in status {:?}", ticket.status)
                ));
            }

            // Add approval
            let approval = TicketApproval {
                approver_id: approver_id.clone(),
                approved_at: Utc::now(),
                signature: signature.to_string(),
                notes: notes.map(|s| s.to_string()),
            };

            ticket.add_approval(approval);
            ticket.clone()
        };

        // Log audit entry
        self.log_audit(
            ticket_id,
            TicketAction::Approved,
            approver_id,
            notes.map(|s| s.to_string()),
        );

        // Persist to database
        self.save_ticket_to_db(&result).await?;

        Ok(result)
    }

    async fn verify_ticket(&self, ticket_id: &str) -> LedgerResult<TicketVerification> {
        let mut tickets = self.tickets.write().unwrap();

        let ticket = tickets.get_mut(ticket_id).ok_or_else(|| {
            LedgerError::NotFound(format!("Ticket {} not found", ticket_id))
        })?;

        // Check and update expiration
        ticket.check_expiration();

        let verification = if ticket.is_valid() {
            TicketVerification::valid(ticket)
        } else {
            let mut errors = Vec::new();
            if ticket.status == ForensicTicketStatus::Expired {
                errors.push("Ticket has expired".to_string());
            }
            if ticket.status == ForensicTicketStatus::Revoked {
                errors.push(format!(
                    "Ticket was revoked: {}",
                    ticket.revocation_reason.as_deref().unwrap_or("no reason")
                ));
            }
            if ticket.status == ForensicTicketStatus::Used {
                errors.push("Ticket has been fully used".to_string());
            }
            if ticket.status == ForensicTicketStatus::Pending {
                errors.push("Ticket is pending approval".to_string());
            }
            TicketVerification::invalid(ticket.status, errors)
        };

        Ok(verification)
    }

    async fn use_ticket(&self, ticket_id: &str) -> LedgerResult<TicketUsageResult> {
        let (result, requester_id) = {
            let mut tickets = self.tickets.write().unwrap();

            let ticket = tickets.get_mut(ticket_id).ok_or_else(|| {
                LedgerError::NotFound(format!("Ticket {} not found", ticket_id))
            })?;

            // Check expiration first
            ticket.check_expiration();

            if !ticket.is_valid() {
                return Err(LedgerError::Validation(format!(
                    "Ticket is not valid: {:?}",
                    ticket.status
                )));
            }

            if !ticket.has_required_approvals() {
                return Err(LedgerError::Validation(
                    "Ticket does not have required approvals".to_string()
                ));
            }

            // Mark as used
            ticket.mark_used();

            let remaining = ticket.max_uses.map(|max| max.saturating_sub(ticket.use_count));

            let result = TicketUsageResult {
                ticket_id: ticket_id.to_string(),
                key_ref: format!("key:{}", ticket.sealed_payload_ref),
                scope: ticket.scope.clone(),
                used_at: Utc::now(),
                remaining_uses: remaining,
            };

            (result, ticket.requester_id.clone())
        };

        // Log audit entry
        self.log_audit(
            ticket_id,
            TicketAction::Used,
            &requester_id,
            Some(format!("Remaining uses: {:?}", result.remaining_uses)),
        );

        // Get ticket for persistence
        let ticket = {
            let tickets = self.tickets.read().unwrap();
            tickets.get(ticket_id).cloned()
        };

        if let Some(t) = ticket {
            self.save_ticket_to_db(&t).await?;
        }

        Ok(result)
    }

    async fn revoke_ticket(&self, ticket_id: &str, reason: &str) -> LedgerResult<()> {
        let requester_id = {
            let mut tickets = self.tickets.write().unwrap();

            let ticket = tickets.get_mut(ticket_id).ok_or_else(|| {
                LedgerError::NotFound(format!("Ticket {} not found", ticket_id))
            })?;

            ticket.revoke(reason);
            ticket.requester_id.clone()
        };

        // Log audit entry
        self.log_audit(
            ticket_id,
            TicketAction::Revoked,
            &requester_id,
            Some(reason.to_string()),
        );

        // Get ticket for persistence
        let ticket = {
            let tickets = self.tickets.read().unwrap();
            tickets.get(ticket_id).cloned()
        };

        if let Some(t) = ticket {
            self.save_ticket_to_db(&t).await?;
        }

        Ok(())
    }

    async fn get_ticket(&self, ticket_id: &str) -> LedgerResult<Option<ForensicAccessTicket>> {
        let tickets = self.tickets.read().unwrap();
        Ok(tickets.get(ticket_id).cloned())
    }

    async fn list_by_requester(
        &self,
        requester_id: &ActorId,
        limit: usize,
    ) -> LedgerResult<Vec<ForensicAccessTicket>> {
        let tickets = self.tickets.read().unwrap();

        let result: Vec<_> = tickets
            .values()
            .filter(|t| &t.requester_id == requester_id)
            .take(limit)
            .cloned()
            .collect();

        Ok(result)
    }

    async fn list_pending_tickets(&self, limit: usize) -> LedgerResult<Vec<ForensicAccessTicket>> {
        let tickets = self.tickets.read().unwrap();

        let result: Vec<_> = tickets
            .values()
            .filter(|t| t.status == ForensicTicketStatus::Pending)
            .take(limit)
            .cloned()
            .collect();

        Ok(result)
    }

    async fn get_ticket_audit_log(&self, ticket_id: &str) -> LedgerResult<Vec<TicketAuditEntry>> {
        let log = self.audit_log.read().unwrap();

        let entries: Vec<_> = log
            .iter()
            .filter(|e| e.ticket_id == ticket_id)
            .cloned()
            .collect();

        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ticket_action_serialization() {
        let action = TicketAction::Requested;
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(json, "\"requested\"");
    }
}
