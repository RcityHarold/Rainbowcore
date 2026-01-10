//! Audit Ledger Implementation
//!
//! Persistent storage for audit logs - decrypt, export, and sampling artifacts.
//! All payload access MUST generate an audit log entry.
//! All data is encrypted at rest using the encrypted_storage module.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use l0_core::types::ActorId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::fs;
use tokio::sync::RwLock;

use super::encrypted_storage::{EncryptedStorage, EncryptedStorageConfig};
use super::traits::AuditLedger;
use crate::error::{P2Error, P2Result};
use crate::types::{DecryptAuditLog, ExportAuditLog, SamplingArtifact, TicketAuditLog};

/// Index entry types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum AuditLogType {
    Decrypt,
    Export,
    Sampling,
    Ticket,
}

/// Audit log index entry
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditIndexEntry {
    log_id: String,
    log_type: AuditLogType,
    actor_id: Option<String>,
    payload_ref: Option<String>,
    batch_id: Option<String>,
    timestamp: DateTime<Utc>,
    is_failed: bool,
    /// For ticket logs: the ticket ID
    ticket_id: Option<String>,
    /// For ticket logs: the resource reference
    resource_ref: Option<String>,
}

/// File-based audit ledger implementation with encryption at rest
pub struct FileAuditLedger {
    /// Base path for audit storage
    base_path: PathBuf,
    /// Decrypt logs directory
    decrypt_path: PathBuf,
    /// Export logs directory
    export_path: PathBuf,
    /// Sampling artifacts directory
    sampling_path: PathBuf,
    /// Ticket logs directory
    ticket_path: PathBuf,
    /// Index path
    index_path: PathBuf,
    /// In-memory index cache
    index_cache: RwLock<HashMap<String, AuditIndexEntry>>,
    /// Encrypted storage handler
    storage: EncryptedStorage,
}

impl FileAuditLedger {
    /// Create a new file-based audit ledger with default encryption
    pub async fn new(base_path: impl Into<PathBuf>) -> P2Result<Self> {
        Self::with_config(base_path, EncryptedStorageConfig::default()).await
    }

    /// Create with custom encryption config
    pub async fn with_config(
        base_path: impl Into<PathBuf>,
        encryption_config: EncryptedStorageConfig,
    ) -> P2Result<Self> {
        let base_path = base_path.into();
        let decrypt_path = base_path.join("decrypt");
        let export_path = base_path.join("export");
        let sampling_path = base_path.join("sampling");
        let ticket_path = base_path.join("ticket");
        let index_path = base_path.join("audit_index.enc");

        // Create directories
        for path in [&base_path, &decrypt_path, &export_path, &sampling_path, &ticket_path] {
            fs::create_dir_all(path).await.map_err(|e| {
                P2Error::Storage(format!("Failed to create directory {:?}: {}", path, e))
            })?;
        }

        let storage = EncryptedStorage::new(encryption_config);

        // Load or create index
        let index_cache = if index_path.exists() {
            let entries: Vec<AuditIndexEntry> = storage
                .read(&index_path, "audit-ledger-index")
                .await
                .unwrap_or_default();
            let mut map = HashMap::new();
            for entry in entries {
                map.insert(entry.log_id.clone(), entry);
            }
            RwLock::new(map)
        } else {
            RwLock::new(HashMap::new())
        };

        Ok(Self {
            base_path,
            decrypt_path,
            export_path,
            sampling_path,
            ticket_path,
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
            .write(&self.index_path, &entries, "audit-ledger-index")
            .await
    }

    /// Get file path for decrypt log
    fn decrypt_file_path(&self, log_id: &str) -> PathBuf {
        self.decrypt_path.join(format!("{}.enc", log_id))
    }

    /// Get file path for export log
    fn export_file_path(&self, log_id: &str) -> PathBuf {
        self.export_path.join(format!("{}.enc", log_id))
    }

    /// Get file path for sampling artifact
    fn sampling_file_path(&self, artifact_id: &str) -> PathBuf {
        self.sampling_path.join(format!("{}.enc", artifact_id))
    }

    /// Get file path for ticket log
    fn ticket_file_path(&self, log_id: &str) -> PathBuf {
        self.ticket_path.join(format!("{}.enc", log_id))
    }

    /// Read decrypt log from disk (encrypted)
    async fn read_decrypt_log(&self, log_id: &str) -> P2Result<Option<DecryptAuditLog>> {
        let path = self.decrypt_file_path(log_id);
        if !path.exists() {
            return Ok(None);
        }

        let log: DecryptAuditLog = self.storage.read(&path, log_id).await?;
        Ok(Some(log))
    }

    /// Read export log from disk (encrypted)
    async fn read_export_log(&self, log_id: &str) -> P2Result<Option<ExportAuditLog>> {
        let path = self.export_file_path(log_id);
        if !path.exists() {
            return Ok(None);
        }

        let log: ExportAuditLog = self.storage.read(&path, log_id).await?;
        Ok(Some(log))
    }

    /// Read sampling artifact from disk (encrypted)
    async fn read_sampling_artifact(&self, artifact_id: &str) -> P2Result<Option<SamplingArtifact>> {
        let path = self.sampling_file_path(artifact_id);
        if !path.exists() {
            return Ok(None);
        }

        let artifact: SamplingArtifact = self.storage.read(&path, artifact_id).await?;
        Ok(Some(artifact))
    }

    /// Read ticket log from disk (encrypted)
    async fn read_ticket_log(&self, log_id: &str) -> P2Result<Option<TicketAuditLog>> {
        let path = self.ticket_file_path(log_id);
        if !path.exists() {
            return Ok(None);
        }

        let log: TicketAuditLog = self.storage.read(&path, log_id).await?;
        Ok(Some(log))
    }
}

#[async_trait]
impl AuditLedger for FileAuditLedger {
    async fn record_decrypt(&self, log: DecryptAuditLog) -> P2Result<String> {
        let log_id = log.log_id.clone();

        // Write encrypted log
        let path = self.decrypt_file_path(&log_id);
        self.storage.write(&path, &log, &log_id).await?;

        // Update index
        {
            let mut cache = self.index_cache.write().await;
            cache.insert(
                log_id.clone(),
                AuditIndexEntry {
                    log_id: log_id.clone(),
                    log_type: AuditLogType::Decrypt,
                    actor_id: Some(log.decryptor.0.clone()),
                    payload_ref: Some(log.target_payload_ref.clone()),
                    batch_id: None,
                    timestamp: log.decrypted_at,
                    is_failed: !matches!(log.outcome, crate::types::DecryptOutcome::Success),
                    ticket_id: None,
                    resource_ref: None,
                },
            );
        }

        self.save_index().await?;

        Ok(log_id)
    }

    async fn record_export(&self, log: ExportAuditLog) -> P2Result<String> {
        let log_id = log.log_id.clone();

        // Write encrypted log
        let path = self.export_file_path(&log_id);
        self.storage.write(&path, &log, &log_id).await?;

        // Update index
        {
            let mut cache = self.index_cache.write().await;
            cache.insert(
                log_id.clone(),
                AuditIndexEntry {
                    log_id: log_id.clone(),
                    log_type: AuditLogType::Export,
                    actor_id: Some(log.exporter.0.clone()),
                    payload_ref: log.payload_refs.first().cloned(),
                    batch_id: None,
                    timestamp: log.exported_at,
                    is_failed: false,
                    ticket_id: None,
                    resource_ref: None,
                },
            );
        }

        self.save_index().await?;

        Ok(log_id)
    }

    async fn record_sampling(&self, artifact: SamplingArtifact) -> P2Result<String> {
        let artifact_id = artifact.artifact_id.clone();

        // Write encrypted artifact
        let path = self.sampling_file_path(&artifact_id);
        self.storage.write(&path, &artifact, &artifact_id).await?;

        // Update index
        {
            let mut cache = self.index_cache.write().await;
            cache.insert(
                artifact_id.clone(),
                AuditIndexEntry {
                    log_id: artifact_id.clone(),
                    log_type: AuditLogType::Sampling,
                    actor_id: None,
                    payload_ref: Some(artifact.sampled_payload_ref.clone()),
                    batch_id: Some(artifact.sampling_batch.clone()),
                    timestamp: artifact.sampled_at,
                    is_failed: artifact.needs_escalation(),
                    ticket_id: None,
                    resource_ref: None,
                },
            );
        }

        self.save_index().await?;

        Ok(artifact_id)
    }

    async fn get_decrypt_logs_for_payload(
        &self,
        payload_ref: &str,
        limit: usize,
    ) -> P2Result<Vec<DecryptAuditLog>> {
        let entries = {
            let cache = self.index_cache.read().await;

            let mut entries: Vec<_> = cache
                .values()
                .filter(|e| {
                    matches!(e.log_type, AuditLogType::Decrypt)
                        && e.payload_ref.as_deref() == Some(payload_ref)
                })
                .cloned()
                .collect();

            // Sort by timestamp descending
            entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
            entries.truncate(limit);
            entries
        };

        let mut logs = Vec::new();
        for entry in entries {
            if let Some(log) = self.read_decrypt_log(&entry.log_id).await? {
                logs.push(log);
            }
        }

        Ok(logs)
    }

    async fn get_decrypt_logs_by_actor(
        &self,
        actor_id: &ActorId,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> P2Result<Vec<DecryptAuditLog>> {
        let entries = {
            let cache = self.index_cache.read().await;

            cache
                .values()
                .filter(|e| {
                    matches!(e.log_type, AuditLogType::Decrypt)
                        && e.actor_id.as_deref() == Some(&actor_id.0)
                        && e.timestamp >= from
                        && e.timestamp <= to
                })
                .cloned()
                .collect::<Vec<_>>()
        };

        let mut logs = Vec::new();
        for entry in entries {
            if let Some(log) = self.read_decrypt_log(&entry.log_id).await? {
                logs.push(log);
            }
        }

        // Sort by timestamp
        logs.sort_by(|a, b| a.decrypted_at.cmp(&b.decrypted_at));

        Ok(logs)
    }

    async fn get_export_logs_for_payload(
        &self,
        payload_ref: &str,
    ) -> P2Result<Vec<ExportAuditLog>> {
        let entries = {
            let cache = self.index_cache.read().await;

            cache
                .values()
                .filter(|e| {
                    matches!(e.log_type, AuditLogType::Export)
                        && e.payload_ref.as_deref() == Some(payload_ref)
                })
                .cloned()
                .collect::<Vec<_>>()
        };

        let mut logs = Vec::new();
        for entry in entries {
            if let Some(log) = self.read_export_log(&entry.log_id).await? {
                // Check if this export actually contains the payload
                if log.payload_refs.contains(&payload_ref.to_string()) {
                    logs.push(log);
                }
            }
        }

        // Sort by timestamp
        logs.sort_by(|a, b| a.exported_at.cmp(&b.exported_at));

        Ok(logs)
    }

    async fn get_sampling_batch(&self, batch_id: &str) -> P2Result<Vec<SamplingArtifact>> {
        let entries = {
            let cache = self.index_cache.read().await;

            cache
                .values()
                .filter(|e| {
                    matches!(e.log_type, AuditLogType::Sampling)
                        && e.batch_id.as_deref() == Some(batch_id)
                })
                .cloned()
                .collect::<Vec<_>>()
        };

        let mut artifacts = Vec::new();
        for entry in entries {
            if let Some(artifact) = self.read_sampling_artifact(&entry.log_id).await? {
                artifacts.push(artifact);
            }
        }

        // Sort by timestamp
        artifacts.sort_by(|a, b| a.sampled_at.cmp(&b.sampled_at));

        Ok(artifacts)
    }

    async fn get_failed_samplings(&self, limit: usize) -> P2Result<Vec<SamplingArtifact>> {
        let entries = {
            let cache = self.index_cache.read().await;

            let mut entries: Vec<_> = cache
                .values()
                .filter(|e| {
                    matches!(e.log_type, AuditLogType::Sampling) && e.is_failed
                })
                .cloned()
                .collect();

            // Sort by timestamp descending (most recent failures first)
            entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
            entries.truncate(limit);
            entries
        };

        let mut artifacts = Vec::new();
        for entry in entries {
            if let Some(artifact) = self.read_sampling_artifact(&entry.log_id).await? {
                artifacts.push(artifact);
            }
        }

        Ok(artifacts)
    }

    async fn verify_decrypt_audited(
        &self,
        ticket_ref: &str,
        payload_ref: &str,
        at: DateTime<Utc>,
    ) -> P2Result<bool> {
        // Get all decrypt logs for this payload
        let logs = self.get_decrypt_logs_for_payload(payload_ref, 1000).await?;

        // Check if any log matches the ticket and time (within a reasonable window)
        let time_window = chrono::Duration::seconds(60); // 1 minute window

        for log in logs {
            if log.ticket_ref == ticket_ref {
                let diff = if log.decrypted_at > at {
                    log.decrypted_at - at
                } else {
                    at - log.decrypted_at
                };
                if diff <= time_window {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    async fn record_ticket(&self, log: TicketAuditLog) -> P2Result<String> {
        let log_id = log.log_id.clone();

        // Write encrypted log
        let path = self.ticket_file_path(&log_id);
        self.storage.write(&path, &log, &log_id).await?;

        // Update index
        {
            let mut cache = self.index_cache.write().await;
            cache.insert(
                log_id.clone(),
                AuditIndexEntry {
                    log_id: log_id.clone(),
                    log_type: AuditLogType::Ticket,
                    actor_id: Some(log.actor.0.clone()),
                    payload_ref: None,
                    batch_id: None,
                    timestamp: log.timestamp,
                    is_failed: !log.is_success(),
                    ticket_id: Some(log.ticket_id.clone()),
                    resource_ref: log.target_resource_ref.clone(),
                },
            );
        }

        self.save_index().await?;

        Ok(log_id)
    }

    async fn get_ticket_logs(&self, ticket_id: &str, limit: usize) -> P2Result<Vec<TicketAuditLog>> {
        let entries = {
            let cache = self.index_cache.read().await;

            let mut entries: Vec<_> = cache
                .values()
                .filter(|e| {
                    matches!(e.log_type, AuditLogType::Ticket)
                        && e.ticket_id.as_deref() == Some(ticket_id)
                })
                .cloned()
                .collect();

            // Sort by timestamp descending
            entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
            entries.truncate(limit);
            entries
        };

        let mut logs = Vec::new();
        for entry in entries {
            if let Some(log) = self.read_ticket_log(&entry.log_id).await? {
                logs.push(log);
            }
        }

        Ok(logs)
    }

    async fn get_ticket_logs_by_actor(
        &self,
        actor_id: &ActorId,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> P2Result<Vec<TicketAuditLog>> {
        let entries = {
            let cache = self.index_cache.read().await;

            cache
                .values()
                .filter(|e| {
                    matches!(e.log_type, AuditLogType::Ticket)
                        && e.actor_id.as_deref() == Some(&actor_id.0)
                        && e.timestamp >= from
                        && e.timestamp <= to
                })
                .cloned()
                .collect::<Vec<_>>()
        };

        let mut logs = Vec::new();
        for entry in entries {
            if let Some(log) = self.read_ticket_log(&entry.log_id).await? {
                logs.push(log);
            }
        }

        // Sort by timestamp
        logs.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        Ok(logs)
    }

    async fn get_ticket_logs_for_resource(
        &self,
        resource_ref: &str,
        limit: usize,
    ) -> P2Result<Vec<TicketAuditLog>> {
        let entries = {
            let cache = self.index_cache.read().await;

            let mut entries: Vec<_> = cache
                .values()
                .filter(|e| {
                    matches!(e.log_type, AuditLogType::Ticket)
                        && e.resource_ref.as_deref() == Some(resource_ref)
                })
                .cloned()
                .collect();

            // Sort by timestamp descending
            entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
            entries.truncate(limit);
            entries
        };

        let mut logs = Vec::new();
        for entry in entries {
            if let Some(log) = self.read_ticket_log(&entry.log_id).await? {
                logs.push(log);
            }
        }

        Ok(logs)
    }

    async fn get_stats(&self) -> P2Result<super::traits::AuditStats> {
        let cache = self.index_cache.read().await;

        let mut stats = super::traits::AuditStats {
            total_entries: cache.len(),
            decrypt_count: 0,
            export_count: 0,
            sampling_count: 0,
            ticket_count: 0,
            failed_count: 0,
            oldest_timestamp: None,
            newest_timestamp: None,
        };

        for entry in cache.values() {
            // Count by type
            match entry.log_type {
                AuditLogType::Decrypt => stats.decrypt_count += 1,
                AuditLogType::Export => stats.export_count += 1,
                AuditLogType::Sampling => stats.sampling_count += 1,
                AuditLogType::Ticket => stats.ticket_count += 1,
            }

            // Count failures
            if entry.is_failed {
                stats.failed_count += 1;
            }

            // Track oldest and newest timestamps
            if stats.oldest_timestamp.is_none() || entry.timestamp < stats.oldest_timestamp.unwrap() {
                stats.oldest_timestamp = Some(entry.timestamp);
            }
            if stats.newest_timestamp.is_none() || entry.timestamp > stats.newest_timestamp.unwrap() {
                stats.newest_timestamp = Some(entry.timestamp);
            }
        }

        Ok(stats)
    }

    async fn get_export_logs_by_actor(
        &self,
        actor_id: &ActorId,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> P2Result<Vec<ExportAuditLog>> {
        let entries = {
            let cache = self.index_cache.read().await;

            cache
                .values()
                .filter(|e| {
                    matches!(e.log_type, AuditLogType::Export)
                        && e.actor_id.as_deref() == Some(&actor_id.0)
                        && e.timestamp >= from
                        && e.timestamp <= to
                })
                .cloned()
                .collect::<Vec<_>>()
        };

        let mut logs = Vec::new();
        for entry in entries {
            if let Some(log) = self.read_export_log(&entry.log_id).await? {
                logs.push(log);
            }
        }

        // Sort by timestamp
        logs.sort_by(|a, b| a.exported_at.cmp(&b.exported_at));

        Ok(logs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DecryptOutcome, ExportFormat, PayloadSelector};
    use l0_core::types::Digest;
    use tempfile::TempDir;

    fn create_test_decrypt_log() -> DecryptAuditLog {
        DecryptAuditLog::new(
            format!("log:{}", uuid::Uuid::new_v4()),
            "ticket:001".to_string(),
            ActorId::new("actor:decryptor"),
            "payload:001".to_string(),
            PayloadSelector::full(),
            Digest::blake3(b"purpose"),
            Digest::blake3(b"result"),
            "/api/v1/decrypt".to_string(),
        )
    }

    fn create_test_export_log() -> ExportAuditLog {
        ExportAuditLog::new(
            format!("export:{}", uuid::Uuid::new_v4()),
            "ticket:001".to_string(),
            ActorId::new("actor:exporter"),
            "external-system".to_string(),
            vec!["payload:001".to_string()],
            ExportFormat::Json,
            Digest::blake3(b"content"),
        )
    }

    fn create_test_sampling_artifact(batch: &str, failed: bool) -> SamplingArtifact {
        let checksum1 = Digest::blake3(b"data1");
        let checksum2 = if failed {
            Digest::blake3(b"data2")
        } else {
            checksum1.clone()
        };

        SamplingArtifact::new(
            format!("sample:{}", uuid::Uuid::new_v4()),
            batch.to_string(),
            "payload:001".to_string(),
            checksum1,
            checksum2,
            "node:sampler".to_string(),
        )
    }

    #[tokio::test]
    async fn test_record_and_get_decrypt_log() {
        let temp_dir = TempDir::new().unwrap();
        let ledger = FileAuditLedger::unencrypted(temp_dir.path()).await.unwrap();

        let log = create_test_decrypt_log();
        let log_id = log.log_id.clone();
        let payload_ref = log.target_payload_ref.clone();

        ledger.record_decrypt(log).await.unwrap();

        let logs = ledger.get_decrypt_logs_for_payload(&payload_ref, 10).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].log_id, log_id);
    }

    #[tokio::test]
    async fn test_record_and_get_export_log() {
        let temp_dir = TempDir::new().unwrap();
        let ledger = FileAuditLedger::unencrypted(temp_dir.path()).await.unwrap();

        let log = create_test_export_log();

        ledger.record_export(log.clone()).await.unwrap();

        let logs = ledger.get_export_logs_for_payload("payload:001").await.unwrap();
        assert_eq!(logs.len(), 1);
    }

    #[tokio::test]
    async fn test_record_and_get_sampling() {
        let temp_dir = TempDir::new().unwrap();
        let ledger = FileAuditLedger::unencrypted(temp_dir.path()).await.unwrap();

        // Record successful and failed samplings
        let artifact1 = create_test_sampling_artifact("batch:001", false);
        let artifact2 = create_test_sampling_artifact("batch:001", true);

        ledger.record_sampling(artifact1).await.unwrap();
        ledger.record_sampling(artifact2).await.unwrap();

        // Get batch
        let batch = ledger.get_sampling_batch("batch:001").await.unwrap();
        assert_eq!(batch.len(), 2);

        // Get failed samplings
        let failed = ledger.get_failed_samplings(10).await.unwrap();
        assert_eq!(failed.len(), 1);
        assert!(failed[0].needs_escalation());
    }

    #[tokio::test]
    async fn test_get_decrypt_logs_by_actor() {
        let temp_dir = TempDir::new().unwrap();
        let ledger = FileAuditLedger::unencrypted(temp_dir.path()).await.unwrap();

        let log = create_test_decrypt_log();
        let actor_id = log.decryptor.clone();

        ledger.record_decrypt(log).await.unwrap();

        let from = Utc::now() - chrono::Duration::hours(1);
        let to = Utc::now() + chrono::Duration::hours(1);

        let logs = ledger.get_decrypt_logs_by_actor(&actor_id, from, to).await.unwrap();
        assert_eq!(logs.len(), 1);
    }

    #[tokio::test]
    async fn test_verify_decrypt_audited() {
        let temp_dir = TempDir::new().unwrap();
        let ledger = FileAuditLedger::unencrypted(temp_dir.path()).await.unwrap();

        let log = create_test_decrypt_log();
        let ticket_ref = log.ticket_ref.clone();
        let payload_ref = log.target_payload_ref.clone();
        let at = log.decrypted_at;

        ledger.record_decrypt(log).await.unwrap();

        // Should find the audit log
        assert!(ledger.verify_decrypt_audited(&ticket_ref, &payload_ref, at).await.unwrap());

        // Should not find with wrong ticket
        assert!(!ledger.verify_decrypt_audited("wrong:ticket", &payload_ref, at).await.unwrap());
    }

    #[tokio::test]
    async fn test_record_and_get_ticket_log() {
        use crate::types::TicketAuditLog;

        let temp_dir = TempDir::new().unwrap();
        let ledger = FileAuditLedger::unencrypted(temp_dir.path()).await.unwrap();

        let log = TicketAuditLog::issue(
            format!("ticketlog:{}", uuid::Uuid::new_v4()),
            "ticket:001".to_string(),
            ActorId::new("actor:issuer"),
            ActorId::new("actor:holder"),
            "payload:001".to_string(),
            vec!["read".to_string(), "export".to_string()],
            3600,
            Some("consent:001".to_string()),
        );
        let log_id = log.log_id.clone();
        let ticket_id = log.ticket_id.clone();

        ledger.record_ticket(log).await.unwrap();

        let logs = ledger.get_ticket_logs(&ticket_id, 10).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].log_id, log_id);
    }

    #[tokio::test]
    async fn test_ticket_use_log() {
        use crate::types::TicketAuditLog;

        let temp_dir = TempDir::new().unwrap();
        let ledger = FileAuditLedger::unencrypted(temp_dir.path()).await.unwrap();

        // Issue log
        let issue_log = TicketAuditLog::issue(
            format!("ticketlog:{}", uuid::Uuid::new_v4()),
            "ticket:002".to_string(),
            ActorId::new("actor:issuer"),
            ActorId::new("actor:holder"),
            "payload:002".to_string(),
            vec!["read".to_string()],
            3600,
            None,
        );
        ledger.record_ticket(issue_log).await.unwrap();

        // Use log
        let use_log = TicketAuditLog::use_ticket(
            format!("ticketlog:{}", uuid::Uuid::new_v4()),
            "ticket:002".to_string(),
            ActorId::new("actor:holder"),
            "payload:002".to_string(),
            1,
            Some(4),
        );
        ledger.record_ticket(use_log).await.unwrap();

        // Get all logs for the ticket
        let logs = ledger.get_ticket_logs("ticket:002", 10).await.unwrap();
        assert_eq!(logs.len(), 2);
    }

    #[tokio::test]
    async fn test_ticket_logs_by_actor() {
        use crate::types::TicketAuditLog;

        let temp_dir = TempDir::new().unwrap();
        let ledger = FileAuditLedger::unencrypted(temp_dir.path()).await.unwrap();

        let issuer = ActorId::new("actor:issuer");

        // Create a few ticket logs
        for i in 0..3 {
            let log = TicketAuditLog::issue(
                format!("ticketlog:{}", uuid::Uuid::new_v4()),
                format!("ticket:{:03}", i),
                issuer.clone(),
                ActorId::new("actor:holder"),
                format!("payload:{:03}", i),
                vec!["read".to_string()],
                3600,
                None,
            );
            ledger.record_ticket(log).await.unwrap();
        }

        let from = Utc::now() - chrono::Duration::hours(1);
        let to = Utc::now() + chrono::Duration::hours(1);

        let logs = ledger.get_ticket_logs_by_actor(&issuer, from, to).await.unwrap();
        assert_eq!(logs.len(), 3);
    }

    #[tokio::test]
    async fn test_ticket_logs_for_resource() {
        use crate::types::TicketAuditLog;

        let temp_dir = TempDir::new().unwrap();
        let ledger = FileAuditLedger::unencrypted(temp_dir.path()).await.unwrap();

        let resource_ref = "payload:resource-001";

        // Issue and use tickets for the same resource
        let issue_log = TicketAuditLog::issue(
            format!("ticketlog:{}", uuid::Uuid::new_v4()),
            "ticket:res-001".to_string(),
            ActorId::new("actor:issuer"),
            ActorId::new("actor:holder"),
            resource_ref.to_string(),
            vec!["read".to_string()],
            3600,
            None,
        );
        ledger.record_ticket(issue_log).await.unwrap();

        let use_log = TicketAuditLog::use_ticket(
            format!("ticketlog:{}", uuid::Uuid::new_v4()),
            "ticket:res-001".to_string(),
            ActorId::new("actor:holder"),
            resource_ref.to_string(),
            1,
            None,
        );
        ledger.record_ticket(use_log).await.unwrap();

        let logs = ledger.get_ticket_logs_for_resource(resource_ref, 10).await.unwrap();
        assert_eq!(logs.len(), 2);
    }

    #[tokio::test]
    async fn test_ticket_revoke_log() {
        use crate::types::TicketAuditLog;

        let temp_dir = TempDir::new().unwrap();
        let ledger = FileAuditLedger::unencrypted(temp_dir.path()).await.unwrap();

        let revoke_log = TicketAuditLog::revoke(
            format!("ticketlog:{}", uuid::Uuid::new_v4()),
            "ticket:revoked".to_string(),
            ActorId::new("actor:admin"),
            "Security policy violation".to_string(),
        );
        let log_id = revoke_log.log_id.clone();

        ledger.record_ticket(revoke_log).await.unwrap();

        let logs = ledger.get_ticket_logs("ticket:revoked", 10).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].log_id, log_id);
        assert_eq!(logs[0].reason, Some("Security policy violation".to_string()));
    }
}
