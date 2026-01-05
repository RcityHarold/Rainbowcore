//! Decrypt Audit Log Service
//!
//! Manages audit logs for decryption operations and sealed data access.

use async_trait::async_trait;
use chrono::Utc;
use l0_core::error::LedgerError;
use l0_core::ledger::LedgerResult;
use l0_core::types::{
    ActorId, AuditRetentionPolicy, CustodyAction, CustodyEntry, DecryptAuditEntry,
    DecryptAuditStatus, DecryptAuditSummary, DecryptAuthorizationSource,
    DecryptOperationType, Digest, ThresholdParticipant,
};
use soulbase_storage::surreal::SurrealDatastore;
use soulbase_storage::Datastore;
use soulbase_types::prelude::TenantId;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Decrypt Audit Ledger trait
#[async_trait]
pub trait DecryptAuditLedger: Send + Sync {
    /// Log a decryption access
    async fn log_decrypt_access(
        &self,
        sealed_payload_ref: &str,
        data_subject_id: &ActorId,
        accessor_id: &ActorId,
        operation_type: DecryptOperationType,
        authorization_source: DecryptAuthorizationSource,
        authorization_ref: &str,
        access_purpose: &str,
        data_digest: Digest,
        access_epoch: u64,
    ) -> LedgerResult<DecryptAuditEntry>;

    /// Update entry status
    async fn update_status(
        &self,
        entry_id: &str,
        status: DecryptAuditStatus,
    ) -> LedgerResult<DecryptAuditEntry>;

    /// Add custody chain entry
    async fn add_custody_entry(
        &self,
        entry_id: &str,
        actor_id: &ActorId,
        action: CustodyAction,
        signature: &str,
        notes: Option<&str>,
    ) -> LedgerResult<DecryptAuditEntry>;

    /// Add threshold participant
    async fn add_threshold_participant(
        &self,
        entry_id: &str,
        participant_id: &ActorId,
        share_index: u32,
        signature: &str,
    ) -> LedgerResult<DecryptAuditEntry>;

    /// Get audit entry by ID
    async fn get_entry(&self, entry_id: &str) -> LedgerResult<Option<DecryptAuditEntry>>;

    /// Get entries for a sealed payload
    async fn get_entries_for_payload(
        &self,
        sealed_payload_ref: &str,
    ) -> LedgerResult<Vec<DecryptAuditEntry>>;

    /// Get entries for a data subject
    async fn get_entries_for_subject(
        &self,
        data_subject_id: &ActorId,
    ) -> LedgerResult<Vec<DecryptAuditEntry>>;

    /// Get entries by accessor
    async fn get_entries_by_accessor(
        &self,
        accessor_id: &ActorId,
    ) -> LedgerResult<Vec<DecryptAuditEntry>>;

    /// Get entries for epoch range
    async fn get_entries_for_epoch_range(
        &self,
        start_epoch: u64,
        end_epoch: u64,
    ) -> LedgerResult<Vec<DecryptAuditEntry>>;

    /// Get summary for period
    async fn get_summary(
        &self,
        start_epoch: u64,
        end_epoch: u64,
    ) -> LedgerResult<DecryptAuditSummary>;

    /// Update retention policy
    async fn update_retention_policy(&self, policy: AuditRetentionPolicy) -> LedgerResult<()>;

    /// Get current retention policy
    async fn get_retention_policy(&self) -> LedgerResult<AuditRetentionPolicy>;
}

/// Decrypt Audit Service implementation
pub struct DecryptAuditService {
    datastore: Arc<SurrealDatastore>,
    tenant_id: TenantId,
    entries: RwLock<HashMap<String, DecryptAuditEntry>>,
    retention_policy: RwLock<AuditRetentionPolicy>,
    sequence: std::sync::atomic::AtomicU64,
}

impl DecryptAuditService {
    pub fn new(datastore: Arc<SurrealDatastore>, tenant_id: TenantId) -> Self {
        Self {
            datastore,
            tenant_id,
            entries: RwLock::new(HashMap::new()),
            retention_policy: RwLock::new(AuditRetentionPolicy::default()),
            sequence: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn generate_entry_id(&self) -> String {
        let seq = self.sequence.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let timestamp = Utc::now().timestamp_micros();
        format!("daud_{:016x}_{:08x}", timestamp, seq)
    }

    async fn save_entry_to_db(&self, entry: &DecryptAuditEntry) -> LedgerResult<()> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let entry_id = entry.entry_id.clone();
        let sealed_payload_ref = entry.sealed_payload_ref.clone();
        let data_subject_id = entry.data_subject_id.0.clone();
        let accessor_id = entry.accessor_id.0.clone();
        let operation_type = serde_json::to_string(&entry.operation_type).unwrap_or_default();
        let authorization_source = serde_json::to_string(&entry.authorization_source).unwrap_or_default();
        let authorization_ref = entry.authorization_ref.clone();
        let status = serde_json::to_string(&entry.status).unwrap_or_default();
        let access_purpose = entry.access_purpose.clone();
        let data_digest = entry.data_digest.to_hex();
        let access_epoch = entry.access_epoch;
        let requested_at = entry.requested_at.to_rfc3339();
        let completed_at = entry.completed_at.map(|d| d.to_rfc3339());
        let access_context = entry.access_context.clone();
        let accessor_location = entry.accessor_location.clone();
        let custody_chain = serde_json::to_string(&entry.custody_chain).unwrap_or_default();
        let threshold_participants = serde_json::to_string(&entry.threshold_participants).unwrap_or_default();
        let access_expires_at = entry.access_expires_at.map(|d| d.to_rfc3339());

        let _: Option<DecryptAuditEntry> = session
            .client()
            .query(
                "UPSERT decrypt_audit_entries SET
                    tenant_id = $tenant,
                    entry_id = $entry_id,
                    sealed_payload_ref = $sealed_payload_ref,
                    data_subject_id = $data_subject_id,
                    accessor_id = $accessor_id,
                    operation_type = $operation_type,
                    authorization_source = $authorization_source,
                    authorization_ref = $authorization_ref,
                    status = $status,
                    access_purpose = $access_purpose,
                    data_digest = $data_digest,
                    access_epoch = $access_epoch,
                    requested_at = $requested_at,
                    completed_at = $completed_at,
                    access_context = $access_context,
                    accessor_location = $accessor_location,
                    custody_chain = $custody_chain,
                    threshold_participants = $threshold_participants,
                    access_expires_at = $access_expires_at
                WHERE tenant_id = $tenant AND entry_id = $entry_id",
            )
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("entry_id", entry_id))
            .bind(("sealed_payload_ref", sealed_payload_ref))
            .bind(("data_subject_id", data_subject_id))
            .bind(("accessor_id", accessor_id))
            .bind(("operation_type", operation_type))
            .bind(("authorization_source", authorization_source))
            .bind(("authorization_ref", authorization_ref))
            .bind(("status", status))
            .bind(("access_purpose", access_purpose))
            .bind(("data_digest", data_digest))
            .bind(("access_epoch", access_epoch))
            .bind(("requested_at", requested_at))
            .bind(("completed_at", completed_at))
            .bind(("access_context", access_context))
            .bind(("accessor_location", accessor_location))
            .bind(("custody_chain", custody_chain))
            .bind(("threshold_participants", threshold_participants))
            .bind(("access_expires_at", access_expires_at))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        Ok(())
    }
}

#[async_trait]
impl DecryptAuditLedger for DecryptAuditService {
    async fn log_decrypt_access(
        &self,
        sealed_payload_ref: &str,
        data_subject_id: &ActorId,
        accessor_id: &ActorId,
        operation_type: DecryptOperationType,
        authorization_source: DecryptAuthorizationSource,
        authorization_ref: &str,
        access_purpose: &str,
        data_digest: Digest,
        access_epoch: u64,
    ) -> LedgerResult<DecryptAuditEntry> {
        let now = Utc::now();
        let entry = DecryptAuditEntry {
            entry_id: self.generate_entry_id(),
            sealed_payload_ref: sealed_payload_ref.to_string(),
            data_subject_id: data_subject_id.clone(),
            accessor_id: accessor_id.clone(),
            operation_type,
            authorization_source,
            authorization_ref: authorization_ref.to_string(),
            status: DecryptAuditStatus::Pending,
            access_purpose: access_purpose.to_string(),
            data_digest,
            access_epoch,
            requested_at: now,
            completed_at: None,
            access_context: None,
            accessor_location: None,
            custody_chain: Vec::new(),
            threshold_participants: Vec::new(),
            access_expires_at: None,
        };

        {
            let mut entries = self.entries.write().unwrap();
            entries.insert(entry.entry_id.clone(), entry.clone());
        }

        self.save_entry_to_db(&entry).await?;
        Ok(entry)
    }

    async fn update_status(
        &self,
        entry_id: &str,
        status: DecryptAuditStatus,
    ) -> LedgerResult<DecryptAuditEntry> {
        let entry = {
            let mut entries = self.entries.write().unwrap();
            let entry = entries
                .get_mut(entry_id)
                .ok_or_else(|| LedgerError::NotFound(format!("Entry {}", entry_id)))?;

            entry.status = status;
            if status == DecryptAuditStatus::Success {
                entry.completed_at = Some(Utc::now());
            }

            entry.clone()
        };

        self.save_entry_to_db(&entry).await?;
        Ok(entry)
    }

    async fn add_custody_entry(
        &self,
        entry_id: &str,
        actor_id: &ActorId,
        action: CustodyAction,
        signature: &str,
        notes: Option<&str>,
    ) -> LedgerResult<DecryptAuditEntry> {
        let entry = {
            let mut entries = self.entries.write().unwrap();
            let entry = entries
                .get_mut(entry_id)
                .ok_or_else(|| LedgerError::NotFound(format!("Entry {}", entry_id)))?;

            entry.custody_chain.push(CustodyEntry {
                actor_id: actor_id.clone(),
                action,
                timestamp: Utc::now(),
                signature: signature.to_string(),
                notes: notes.map(|s| s.to_string()),
            });

            entry.clone()
        };

        self.save_entry_to_db(&entry).await?;
        Ok(entry)
    }

    async fn add_threshold_participant(
        &self,
        entry_id: &str,
        participant_id: &ActorId,
        share_index: u32,
        signature: &str,
    ) -> LedgerResult<DecryptAuditEntry> {
        let entry = {
            let mut entries = self.entries.write().unwrap();
            let entry = entries
                .get_mut(entry_id)
                .ok_or_else(|| LedgerError::NotFound(format!("Entry {}", entry_id)))?;

            // Check not already added
            if entry.threshold_participants.iter().any(|p| p.share_index == share_index) {
                return Err(LedgerError::Validation(
                    "Share index already contributed".to_string(),
                ));
            }

            entry.threshold_participants.push(ThresholdParticipant {
                participant_id: participant_id.clone(),
                share_index,
                contributed_at: Utc::now(),
                signature: signature.to_string(),
            });

            entry.clone()
        };

        self.save_entry_to_db(&entry).await?;
        Ok(entry)
    }

    async fn get_entry(&self, entry_id: &str) -> LedgerResult<Option<DecryptAuditEntry>> {
        let entries = self.entries.read().unwrap();
        Ok(entries.get(entry_id).cloned())
    }

    async fn get_entries_for_payload(
        &self,
        sealed_payload_ref: &str,
    ) -> LedgerResult<Vec<DecryptAuditEntry>> {
        let entries = self.entries.read().unwrap();
        Ok(entries
            .values()
            .filter(|e| e.sealed_payload_ref == sealed_payload_ref)
            .cloned()
            .collect())
    }

    async fn get_entries_for_subject(
        &self,
        data_subject_id: &ActorId,
    ) -> LedgerResult<Vec<DecryptAuditEntry>> {
        let entries = self.entries.read().unwrap();
        Ok(entries
            .values()
            .filter(|e| &e.data_subject_id == data_subject_id)
            .cloned()
            .collect())
    }

    async fn get_entries_by_accessor(
        &self,
        accessor_id: &ActorId,
    ) -> LedgerResult<Vec<DecryptAuditEntry>> {
        let entries = self.entries.read().unwrap();
        Ok(entries
            .values()
            .filter(|e| &e.accessor_id == accessor_id)
            .cloned()
            .collect())
    }

    async fn get_entries_for_epoch_range(
        &self,
        start_epoch: u64,
        end_epoch: u64,
    ) -> LedgerResult<Vec<DecryptAuditEntry>> {
        let entries = self.entries.read().unwrap();
        Ok(entries
            .values()
            .filter(|e| e.access_epoch >= start_epoch && e.access_epoch <= end_epoch)
            .cloned()
            .collect())
    }

    async fn get_summary(
        &self,
        start_epoch: u64,
        end_epoch: u64,
    ) -> LedgerResult<DecryptAuditSummary> {
        let entries = self.entries.read().unwrap();
        let range_entries: Vec<_> = entries
            .values()
            .filter(|e| e.access_epoch >= start_epoch && e.access_epoch <= end_epoch)
            .collect();

        let total = range_entries.len() as u64;
        let successful = range_entries
            .iter()
            .filter(|e| e.status == DecryptAuditStatus::Success)
            .count() as u64;
        let failed = range_entries
            .iter()
            .filter(|e| e.status == DecryptAuditStatus::Failed)
            .count() as u64;
        let denied = range_entries
            .iter()
            .filter(|e| e.status == DecryptAuditStatus::Denied)
            .count() as u64;

        // Count by operation type
        let mut by_op_type: HashMap<DecryptOperationType, u64> = HashMap::new();
        for e in &range_entries {
            *by_op_type.entry(e.operation_type).or_insert(0) += 1;
        }

        // Count by authorization source
        let mut by_auth_source: HashMap<DecryptAuthorizationSource, u64> = HashMap::new();
        for e in &range_entries {
            *by_auth_source.entry(e.authorization_source).or_insert(0) += 1;
        }

        Ok(DecryptAuditSummary {
            total_entries: total,
            successful_decryptions: successful,
            failed_decryptions: failed,
            denied_attempts: denied,
            by_operation_type: by_op_type.into_iter().collect(),
            by_authorization_source: by_auth_source.into_iter().collect(),
            period_start: Utc::now(), // TODO: Calculate from epoch
            period_end: Utc::now(),
        })
    }

    async fn update_retention_policy(&self, policy: AuditRetentionPolicy) -> LedgerResult<()> {
        let mut current = self.retention_policy.write().unwrap();
        *current = policy;
        Ok(())
    }

    async fn get_retention_policy(&self) -> LedgerResult<AuditRetentionPolicy> {
        let policy = self.retention_policy.read().unwrap();
        Ok(policy.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_retention() {
        let policy = AuditRetentionPolicy::default();
        assert_eq!(policy.standard_retention_days, 365);
        assert!(policy.archive_before_delete);
    }
}
