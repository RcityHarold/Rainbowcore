//! Evidence Backfill Mechanism
//!
//! Upgrades B-level evidence to A-level when P1 receipts and map_commits
//! become available. This ensures eventual consistency between P1 and P2.
//!
//! # Hard Rules
//!
//! Evidence level MUST be upgraded from B to A when:
//! 1. A valid P1 receipt exists
//! 2. A valid payload_map_commit exists
//! 3. The map_commit digest matches the payload refs digest
//!
//! # Anti-History-Washing (防洗史) Rules
//!
//! **CRITICAL**: The order of commit vs upload determines upgrade eligibility:
//!
//! - **Commit-Then-Upload**: P1 commitment exists BEFORE P2 upload
//!   - This is a valid backfill scenario
//!   - Evidence CAN be upgraded from B to A
//!   - The commitment proves intent existed before content was stored
//!
//! - **Upload-Then-Commit**: P2 upload happened BEFORE P1 commitment
//!   - This is NOT a valid backfill for A-level
//!   - Evidence remains at B-level (storage only, not evidence-grade)
//!   - Marked as `history_wash_risk: true`
//!   - This prevents backdating evidence after the fact
//!
//! The `commit_cutoff_time` is used to determine which case applies.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use l0_core::types::{Digest, ReceiptId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::error::{BridgeError, BridgeResult};
use crate::l0_client::L0CommitClient;
use crate::payload_map_commit::PayloadMapCommit;
use l0_core::types::EvidenceLevel;
use p2_core::types::EvidenceBundle;

/// Upload-Commit order for anti-history-washing verification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UploadCommitOrder {
    /// Commit was made BEFORE upload - valid for A-level upgrade
    CommitThenUpload,
    /// Upload was made BEFORE commit - NOT valid for A-level (storage only)
    UploadThenCommit,
    /// Order cannot be determined (missing timestamps)
    Undetermined,
}

impl UploadCommitOrder {
    /// Check if this order allows A-level upgrade
    pub fn allows_a_level_upgrade(&self) -> bool {
        matches!(self, Self::CommitThenUpload)
    }

    /// Determine order from timestamps
    pub fn from_timestamps(
        commit_time: Option<DateTime<Utc>>,
        upload_time: Option<DateTime<Utc>>,
        grace_window: Duration,
    ) -> Self {
        match (commit_time, upload_time) {
            (Some(commit), Some(upload)) => {
                // Allow grace window for near-simultaneous operations
                if commit <= upload + grace_window {
                    Self::CommitThenUpload
                } else {
                    Self::UploadThenCommit
                }
            }
            _ => Self::Undetermined,
        }
    }
}

/// Backfill ledger trait for tracking pending evidence upgrades
#[async_trait]
pub trait BackfillLedger: Send + Sync {
    /// Add a bundle to the backfill queue
    async fn queue_for_backfill(&self, bundle_id: &str, payload_refs_digest: Digest) -> BridgeResult<()>;

    /// Get all pending backfill entries
    async fn get_pending(&self, limit: usize) -> BridgeResult<Vec<BackfillEntry>>;

    /// Mark a bundle as backfilled
    async fn mark_complete(&self, bundle_id: &str, result: BackfillResult) -> BridgeResult<()>;

    /// Get backfill status for a bundle
    async fn get_status(&self, bundle_id: &str) -> BridgeResult<Option<BackfillStatus>>;

    /// Get backfill statistics
    async fn get_stats(&self) -> BridgeResult<BackfillStats>;
}

/// Backfill entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackfillEntry {
    /// Bundle ID
    pub bundle_id: String,
    /// Payload refs digest to match
    pub payload_refs_digest: Digest,
    /// When queued
    pub queued_at: DateTime<Utc>,
    /// Retry count
    pub retry_count: u32,
    /// Last attempt
    pub last_attempt_at: Option<DateTime<Utc>>,
    /// Status
    pub status: BackfillStatus,
    /// P2 upload timestamp (for anti-history-washing verification)
    pub p2_upload_time: Option<DateTime<Utc>>,
    /// Commit cutoff time - commitments after this time are Upload-Then-Commit
    pub commit_cutoff_time: Option<DateTime<Utc>>,
}

/// Backfill status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackfillStatus {
    /// Pending - waiting for P1 data
    Pending,
    /// In progress
    InProgress,
    /// Completed successfully
    Complete,
    /// Failed (will retry)
    Failed,
    /// Permanently failed (won't retry)
    PermanentlyFailed,
}

/// Backfill result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackfillResult {
    /// Whether upgrade succeeded
    pub success: bool,
    /// New evidence level
    pub new_level: Option<EvidenceLevel>,
    /// Receipt ID if found
    pub receipt_id: Option<ReceiptId>,
    /// Map commit reference if found
    pub map_commit_ref: Option<String>,
    /// Error message if failed
    pub error: Option<String>,
    /// Completed at
    pub completed_at: DateTime<Utc>,
    /// Upload-Commit order determination
    pub upload_commit_order: UploadCommitOrder,
    /// History wash risk flag
    /// True if Upload-Then-Commit pattern detected (cannot upgrade to A-level)
    pub history_wash_risk: bool,
    /// Commit timestamp from P1 (if found)
    pub commit_time: Option<DateTime<Utc>>,
    /// Reason for not upgrading (if applicable)
    pub no_upgrade_reason: Option<BackfillNoUpgradeReason>,
}

/// Reason why backfill did not upgrade to A-level
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackfillNoUpgradeReason {
    /// Missing P1 receipt
    MissingReceipt,
    /// Missing payload_map_commit
    MissingMapCommit,
    /// Upload-Then-Commit pattern detected (防洗史 violation)
    UploadThenCommit {
        upload_time: DateTime<Utc>,
        commit_time: DateTime<Utc>,
    },
    /// Digest mismatch between P1 commit and P2 payloads
    DigestMismatch {
        expected: String,
        actual: String,
    },
    /// Commit time unknown (cannot verify order)
    CommitTimeUnknown,
    /// Other error
    Other { details: String },
}

/// Backfill statistics
#[derive(Debug, Clone, Default)]
pub struct BackfillStats {
    /// Total pending
    pub pending_count: usize,
    /// Total in progress
    pub in_progress_count: usize,
    /// Total completed
    pub completed_count: usize,
    /// Total failed
    pub failed_count: usize,
    /// Success rate (0.0-1.0)
    pub success_rate: f64,
}

/// Evidence backfill executor
pub struct BackfillExecutor<L: L0CommitClient, B: BackfillLedger> {
    /// L0 client for fetching receipts
    l0_client: Arc<L>,
    /// Backfill ledger
    backfill_ledger: Arc<B>,
    /// Evidence ledger for updating bundles
    evidence_updater: Arc<dyn EvidenceUpdater>,
    /// Max retries before permanent failure
    max_retries: u32,
    /// Batch size for processing
    batch_size: usize,
    /// Grace window for commit-upload timing (for network latency etc.)
    grace_window: Duration,
    /// Number of batches to search for receipts
    receipt_search_batches: u64,
}

/// Evidence updater trait (abstracts EvidenceLedger for this module)
#[async_trait]
pub trait EvidenceUpdater: Send + Sync {
    /// Get evidence bundle
    async fn get_bundle(&self, bundle_id: &str) -> BridgeResult<Option<EvidenceBundle>>;
    /// Set receipt on bundle
    async fn set_receipt(&self, bundle_id: &str, receipt_id: ReceiptId) -> BridgeResult<()>;
    /// Set map commit on bundle
    async fn set_map_commit(&self, bundle_id: &str, map_commit_ref: String) -> BridgeResult<()>;
    /// Set history wash risk flag on bundle
    async fn set_history_wash_risk(&self, bundle_id: &str, risk: bool, reason: Option<String>) -> BridgeResult<()>;
}

/// Found map commit with metadata
#[derive(Debug, Clone)]
pub struct FoundMapCommit {
    /// Map commit reference ID
    pub ref_id: String,
    /// Map commit digest
    pub digest: Digest,
    /// Commit timestamp from L0
    pub commit_time: DateTime<Utc>,
    /// The actual PayloadMapCommit (if available)
    pub commit: Option<PayloadMapCommit>,
}

impl<L: L0CommitClient, B: BackfillLedger> BackfillExecutor<L, B> {
    /// Create a new backfill executor
    pub fn new(
        l0_client: Arc<L>,
        backfill_ledger: Arc<B>,
        evidence_updater: Arc<dyn EvidenceUpdater>,
    ) -> Self {
        Self {
            l0_client,
            backfill_ledger,
            evidence_updater,
            max_retries: 5,
            batch_size: 100,
            // Default 5 minute grace window for commit-upload timing
            grace_window: Duration::minutes(5),
            // Search last 100 batches for receipts
            receipt_search_batches: 100,
        }
    }

    /// Set max retries
    pub fn with_max_retries(mut self, max: u32) -> Self {
        self.max_retries = max;
        self
    }

    /// Set batch size
    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    /// Set grace window for commit-upload timing
    pub fn with_grace_window(mut self, window: Duration) -> Self {
        self.grace_window = window;
        self
    }

    /// Set receipt search batch count
    pub fn with_receipt_search_batches(mut self, count: u64) -> Self {
        self.receipt_search_batches = count;
        self
    }

    /// Process pending backfills
    pub async fn process_pending(&self) -> BridgeResult<BackfillBatchResult> {
        let pending = self.backfill_ledger.get_pending(self.batch_size).await?;

        info!("Processing {} pending backfill entries", pending.len());

        let mut results = Vec::new();
        let mut success_count = 0;
        let mut failure_count = 0;

        for entry in pending {
            let result = self.process_entry(&entry).await;

            match &result {
                Ok(r) if r.success => success_count += 1,
                _ => failure_count += 1,
            }

            let backfill_result = result.unwrap_or_else(|e| BackfillResult {
                success: false,
                new_level: None,
                receipt_id: None,
                map_commit_ref: None,
                error: Some(e.to_string()),
                completed_at: Utc::now(),
                upload_commit_order: UploadCommitOrder::Undetermined,
                history_wash_risk: false,
                commit_time: None,
                no_upgrade_reason: Some(BackfillNoUpgradeReason::Other {
                    details: e.to_string(),
                }),
            });

            // Mark complete or failed in ledger
            if backfill_result.success || entry.retry_count >= self.max_retries {
                self.backfill_ledger
                    .mark_complete(&entry.bundle_id, backfill_result.clone())
                    .await?;
            }

            // If history wash risk detected, mark on bundle
            if backfill_result.history_wash_risk {
                let reason = match &backfill_result.no_upgrade_reason {
                    Some(BackfillNoUpgradeReason::UploadThenCommit { upload_time, commit_time }) => {
                        Some(format!(
                            "Upload-Then-Commit detected: upload={}, commit={}",
                            upload_time, commit_time
                        ))
                    }
                    _ => Some("History wash risk detected".to_string()),
                };
                let _ = self.evidence_updater
                    .set_history_wash_risk(&entry.bundle_id, true, reason)
                    .await;
            }

            results.push((entry.bundle_id.clone(), backfill_result));
        }

        Ok(BackfillBatchResult {
            processed_count: results.len(),
            success_count,
            failure_count,
            results,
        })
    }

    /// Process a single backfill entry with anti-history-washing verification
    async fn process_entry(&self, entry: &BackfillEntry) -> BridgeResult<BackfillResult> {
        debug!("Processing backfill for bundle: {}", entry.bundle_id);

        // Get current bundle state
        let bundle = self
            .evidence_updater
            .get_bundle(&entry.bundle_id)
            .await?
            .ok_or_else(|| BridgeError::NotFound(entry.bundle_id.clone()))?;

        // Check if already at level A
        if bundle.evidence_level() == EvidenceLevel::A {
            return Ok(BackfillResult {
                success: true,
                new_level: Some(EvidenceLevel::A),
                receipt_id: bundle.receipt_id.clone(),
                map_commit_ref: bundle.map_commit_ref.clone(),
                error: None,
                completed_at: Utc::now(),
                upload_commit_order: UploadCommitOrder::CommitThenUpload, // Assume valid if already A
                history_wash_risk: false,
                commit_time: None,
                no_upgrade_reason: None,
            });
        }

        // Try to find receipt and map_commit
        let mut receipt_id = bundle.receipt_id.clone();
        let mut map_commit_ref = bundle.map_commit_ref.clone();
        let mut commit_time: Option<DateTime<Utc>> = None;
        let mut found_map_commit: Option<FoundMapCommit> = None;

        // Search for matching receipt if not already present
        if receipt_id.is_none() {
            match self.find_receipt_for_digest(&entry.payload_refs_digest).await {
                Ok(Some(rid)) => {
                    self.evidence_updater
                        .set_receipt(&entry.bundle_id, rid.clone())
                        .await?;
                    receipt_id = Some(rid);
                }
                Ok(None) => {
                    debug!("No receipt found for bundle: {}", entry.bundle_id);
                }
                Err(e) => {
                    warn!("Error finding receipt: {}", e);
                }
            }
        }

        // Search for matching map_commit if not already present
        if map_commit_ref.is_none() {
            match self.find_map_commit_for_digest(&entry.payload_refs_digest).await {
                Ok(Some(found)) => {
                    commit_time = Some(found.commit_time);
                    self.evidence_updater
                        .set_map_commit(&entry.bundle_id, found.ref_id.clone())
                        .await?;
                    map_commit_ref = Some(found.ref_id.clone());
                    found_map_commit = Some(found);
                }
                Ok(None) => {
                    debug!("No map_commit found for bundle: {}", entry.bundle_id);
                }
                Err(e) => {
                    warn!("Error finding map_commit: {}", e);
                }
            }
        }

        // ==== ANTI-HISTORY-WASHING VERIFICATION ====
        //
        // Determine if this is Commit-Then-Upload or Upload-Then-Commit
        let upload_time = entry.p2_upload_time;
        let cutoff_time = entry.commit_cutoff_time;

        let upload_commit_order = if let (Some(commit_t), Some(upload_t)) = (commit_time, upload_time) {
            UploadCommitOrder::from_timestamps(Some(commit_t), Some(upload_t), self.grace_window)
        } else if let Some(cutoff) = cutoff_time {
            // Use cutoff time as proxy for commit time
            if let Some(upload_t) = upload_time {
                if cutoff <= upload_t + self.grace_window {
                    UploadCommitOrder::CommitThenUpload
                } else {
                    UploadCommitOrder::UploadThenCommit
                }
            } else {
                UploadCommitOrder::Undetermined
            }
        } else {
            UploadCommitOrder::Undetermined
        };

        // Determine if history wash risk exists
        let history_wash_risk = matches!(upload_commit_order, UploadCommitOrder::UploadThenCommit);

        // Determine final evidence level with anti-history-washing rules
        let (new_level, no_upgrade_reason) = self.determine_final_level(
            receipt_id.is_some(),
            map_commit_ref.is_some(),
            upload_commit_order,
            upload_time,
            commit_time,
        );

        let success = new_level == EvidenceLevel::A;

        Ok(BackfillResult {
            success,
            new_level: Some(new_level),
            receipt_id,
            map_commit_ref,
            error: if !success {
                no_upgrade_reason.as_ref().map(|r| format!("{:?}", r))
            } else {
                None
            },
            completed_at: Utc::now(),
            upload_commit_order,
            history_wash_risk,
            commit_time,
            no_upgrade_reason,
        })
    }

    /// Determine final evidence level with anti-history-washing rules
    fn determine_final_level(
        &self,
        has_receipt: bool,
        has_map_commit: bool,
        order: UploadCommitOrder,
        upload_time: Option<DateTime<Utc>>,
        commit_time: Option<DateTime<Utc>>,
    ) -> (EvidenceLevel, Option<BackfillNoUpgradeReason>) {
        // Rule 1: Missing receipt = B level
        if !has_receipt {
            return (EvidenceLevel::B, Some(BackfillNoUpgradeReason::MissingReceipt));
        }

        // Rule 2: Missing map_commit = B level
        if !has_map_commit {
            return (EvidenceLevel::B, Some(BackfillNoUpgradeReason::MissingMapCommit));
        }

        // Rule 3 (CRITICAL): Upload-Then-Commit = B level (防洗史)
        // Even if receipt and map_commit exist, if the commit was made AFTER
        // the upload, this is potentially backdating evidence.
        match order {
            UploadCommitOrder::UploadThenCommit => {
                if let (Some(upload_t), Some(commit_t)) = (upload_time, commit_time) {
                    return (
                        EvidenceLevel::B,
                        Some(BackfillNoUpgradeReason::UploadThenCommit {
                            upload_time: upload_t,
                            commit_time: commit_t,
                        }),
                    );
                }
                // Even without exact times, mark as B if order detected
                return (
                    EvidenceLevel::B,
                    Some(BackfillNoUpgradeReason::Other {
                        details: "Upload-Then-Commit order detected".to_string(),
                    }),
                );
            }
            UploadCommitOrder::Undetermined => {
                // If we can't determine the order, we CANNOT upgrade to A
                // This is a conservative approach to prevent history washing
                return (
                    EvidenceLevel::B,
                    Some(BackfillNoUpgradeReason::CommitTimeUnknown),
                );
            }
            UploadCommitOrder::CommitThenUpload => {
                // Valid order - can upgrade to A
            }
        }

        // All checks passed - upgrade to A
        (EvidenceLevel::A, None)
    }

    /// Find receipt for a given digest
    async fn find_receipt_for_digest(&self, digest: &Digest) -> BridgeResult<Option<ReceiptId>> {
        // Query L0 for receipts matching this digest
        let current_batch = self.l0_client.current_batch_sequence().await?;

        // Check recent batches (configurable)
        let start_batch = current_batch.saturating_sub(self.receipt_search_batches);
        for batch_seq in (start_batch..=current_batch).rev() {
            let receipts = self.l0_client.get_receipts_by_batch(batch_seq).await?;
            for receipt in receipts {
                // Check if receipt's root matches our digest
                if receipt.root == *digest {
                    return Ok(Some(receipt.receipt_id));
                }
            }
        }

        Ok(None)
    }

    /// Find map_commit for a given digest with timestamp information
    ///
    /// This method queries L0 for PayloadMapCommits that match the given digest.
    /// Returns the commit with its timestamp for anti-history-washing verification.
    async fn find_map_commit_for_digest(&self, digest: &Digest) -> BridgeResult<Option<FoundMapCommit>> {
        // Query L0 for PayloadMapCommits matching this digest
        let current_batch = self.l0_client.current_batch_sequence().await?;

        // Search recent batches for map_commits
        let start_batch = current_batch.saturating_sub(self.receipt_search_batches);
        for batch_seq in (start_batch..=current_batch).rev() {
            // Query L0 for map_commits in this batch
            match self.l0_client.get_map_commits_by_batch(batch_seq).await {
                Ok(map_commits) => {
                    for (ref_id, commit_info) in map_commits {
                        // Check if this commit's digest matches our target
                        if commit_info.refs_set_digest == *digest {
                            return Ok(Some(FoundMapCommit {
                                ref_id,
                                digest: commit_info.refs_set_digest.clone(),
                                commit_time: commit_info.committed_at,
                                commit: Some(commit_info),
                            }));
                        }
                    }
                }
                Err(e) => {
                    debug!("Error fetching map_commits for batch {}: {}", batch_seq, e);
                    continue;
                }
            }
        }

        Ok(None)
    }

    /// Verify digest match between P1 commit and P2 payloads
    /// This is used for reconciliation verification
    pub fn verify_digest_match(
        &self,
        map_commit: &PayloadMapCommit,
        p2_digest: &Digest,
    ) -> bool {
        map_commit.refs_set_digest == *p2_digest
    }
}

/// Backfill batch result
#[derive(Debug, Clone)]
pub struct BackfillBatchResult {
    /// Number processed
    pub processed_count: usize,
    /// Number succeeded
    pub success_count: usize,
    /// Number failed
    pub failure_count: usize,
    /// Individual results
    pub results: Vec<(String, BackfillResult)>,
}

impl BackfillBatchResult {
    /// Get success rate
    pub fn success_rate(&self) -> f64 {
        if self.processed_count == 0 {
            1.0
        } else {
            self.success_count as f64 / self.processed_count as f64
        }
    }
}

/// In-memory backfill ledger (for testing/development)
pub struct InMemoryBackfillLedger {
    entries: RwLock<HashMap<String, BackfillEntry>>,
    completed: RwLock<HashMap<String, BackfillResult>>,
}

impl InMemoryBackfillLedger {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            completed: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryBackfillLedger {
    fn default() -> Self {
        Self::new()
    }
}

/// Extended backfill ledger trait with timestamp support
#[async_trait]
pub trait BackfillLedgerExt: BackfillLedger {
    /// Add a bundle to the backfill queue with upload timestamp
    async fn queue_for_backfill_with_timestamps(
        &self,
        bundle_id: &str,
        payload_refs_digest: Digest,
        p2_upload_time: Option<DateTime<Utc>>,
        commit_cutoff_time: Option<DateTime<Utc>>,
    ) -> BridgeResult<()>;
}

#[async_trait]
impl BackfillLedger for InMemoryBackfillLedger {
    async fn queue_for_backfill(&self, bundle_id: &str, payload_refs_digest: Digest) -> BridgeResult<()> {
        let mut entries = self.entries.write().await;
        entries.insert(
            bundle_id.to_string(),
            BackfillEntry {
                bundle_id: bundle_id.to_string(),
                payload_refs_digest,
                queued_at: Utc::now(),
                retry_count: 0,
                last_attempt_at: None,
                status: BackfillStatus::Pending,
                p2_upload_time: None,
                commit_cutoff_time: None,
            },
        );
        Ok(())
    }

    async fn get_pending(&self, limit: usize) -> BridgeResult<Vec<BackfillEntry>> {
        let entries = self.entries.read().await;
        let pending: Vec<_> = entries
            .values()
            .filter(|e| matches!(e.status, BackfillStatus::Pending | BackfillStatus::Failed))
            .take(limit)
            .cloned()
            .collect();
        Ok(pending)
    }

    async fn mark_complete(&self, bundle_id: &str, result: BackfillResult) -> BridgeResult<()> {
        let mut entries = self.entries.write().await;
        if let Some(entry) = entries.get_mut(bundle_id) {
            entry.status = if result.success {
                BackfillStatus::Complete
            } else if entry.retry_count >= 5 {
                BackfillStatus::PermanentlyFailed
            } else {
                entry.retry_count += 1;
                BackfillStatus::Failed
            };
            entry.last_attempt_at = Some(Utc::now());
        }

        let mut completed = self.completed.write().await;
        completed.insert(bundle_id.to_string(), result);

        Ok(())
    }

    async fn get_status(&self, bundle_id: &str) -> BridgeResult<Option<BackfillStatus>> {
        let entries = self.entries.read().await;
        Ok(entries.get(bundle_id).map(|e| e.status))
    }

    async fn get_stats(&self) -> BridgeResult<BackfillStats> {
        let entries = self.entries.read().await;
        let completed = self.completed.read().await;

        let mut stats = BackfillStats::default();

        for entry in entries.values() {
            match entry.status {
                BackfillStatus::Pending => stats.pending_count += 1,
                BackfillStatus::InProgress => stats.in_progress_count += 1,
                BackfillStatus::Complete => stats.completed_count += 1,
                BackfillStatus::Failed | BackfillStatus::PermanentlyFailed => {
                    stats.failed_count += 1
                }
            }
        }

        let total_finished = stats.completed_count + stats.failed_count;
        stats.success_rate = if total_finished > 0 {
            stats.completed_count as f64 / total_finished as f64
        } else {
            1.0
        };

        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a complete BackfillResult for testing
    fn make_backfill_result(success: bool, level: EvidenceLevel) -> BackfillResult {
        BackfillResult {
            success,
            new_level: Some(level),
            receipt_id: if success { Some(ReceiptId("receipt:001".to_string())) } else { None },
            map_commit_ref: if success { Some("pmc:001".to_string()) } else { None },
            error: if !success { Some("Test error".to_string()) } else { None },
            completed_at: Utc::now(),
            upload_commit_order: if success { UploadCommitOrder::CommitThenUpload } else { UploadCommitOrder::Undetermined },
            history_wash_risk: false,
            commit_time: None,
            no_upgrade_reason: if !success { Some(BackfillNoUpgradeReason::MissingReceipt) } else { None },
        }
    }

    #[tokio::test]
    async fn test_in_memory_backfill_ledger() {
        let ledger = InMemoryBackfillLedger::new();

        // Queue an entry
        ledger
            .queue_for_backfill("bundle:001", Digest::blake3(b"test"))
            .await
            .unwrap();

        // Check pending
        let pending = ledger.get_pending(10).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].bundle_id, "bundle:001");

        // Check status
        let status = ledger.get_status("bundle:001").await.unwrap();
        assert_eq!(status, Some(BackfillStatus::Pending));
    }

    #[tokio::test]
    async fn test_mark_complete_success() {
        let ledger = InMemoryBackfillLedger::new();

        ledger
            .queue_for_backfill("bundle:001", Digest::blake3(b"test"))
            .await
            .unwrap();

        let result = make_backfill_result(true, EvidenceLevel::A);

        ledger.mark_complete("bundle:001", result).await.unwrap();

        let status = ledger.get_status("bundle:001").await.unwrap();
        assert_eq!(status, Some(BackfillStatus::Complete));
    }

    #[tokio::test]
    async fn test_backfill_stats() {
        let ledger = InMemoryBackfillLedger::new();

        // Queue multiple entries
        for i in 0..5 {
            ledger
                .queue_for_backfill(&format!("bundle:{}", i), Digest::blake3(format!("test{}", i).as_bytes()))
                .await
                .unwrap();
        }

        // Complete some
        for i in 0..3 {
            let result = make_backfill_result(true, EvidenceLevel::A);
            ledger
                .mark_complete(&format!("bundle:{}", i), result)
                .await
                .unwrap();
        }

        let stats = ledger.get_stats().await.unwrap();
        assert_eq!(stats.completed_count, 3);
        assert_eq!(stats.pending_count, 2);
    }

    // ========== Anti-History-Washing Tests (防洗史测试) ==========

    #[test]
    fn test_upload_commit_order_commit_then_upload() {
        // Commit at time T, upload at time T+10min
        let commit_time = Utc::now();
        let upload_time = commit_time + Duration::minutes(10);
        let grace = Duration::minutes(5);

        let order = UploadCommitOrder::from_timestamps(
            Some(commit_time),
            Some(upload_time),
            grace,
        );

        assert_eq!(order, UploadCommitOrder::CommitThenUpload);
        assert!(order.allows_a_level_upgrade());
    }

    #[test]
    fn test_upload_commit_order_upload_then_commit() {
        // Upload at time T, commit at time T+10min (history washing attempt)
        let upload_time = Utc::now();
        let commit_time = upload_time + Duration::minutes(10);
        let grace = Duration::minutes(5);

        let order = UploadCommitOrder::from_timestamps(
            Some(commit_time),
            Some(upload_time),
            grace,
        );

        assert_eq!(order, UploadCommitOrder::UploadThenCommit);
        assert!(!order.allows_a_level_upgrade());
    }

    #[test]
    fn test_upload_commit_order_within_grace_window() {
        // Commit at time T, upload at time T-3min (within 5min grace window)
        let commit_time = Utc::now();
        let upload_time = commit_time - Duration::minutes(3);
        let grace = Duration::minutes(5);

        let order = UploadCommitOrder::from_timestamps(
            Some(commit_time),
            Some(upload_time),
            grace,
        );

        // Within grace window, should be treated as Commit-Then-Upload
        assert_eq!(order, UploadCommitOrder::CommitThenUpload);
    }

    #[test]
    fn test_upload_commit_order_undetermined() {
        let grace = Duration::minutes(5);

        // Missing commit time
        let order1 = UploadCommitOrder::from_timestamps(
            None,
            Some(Utc::now()),
            grace,
        );
        assert_eq!(order1, UploadCommitOrder::Undetermined);

        // Missing upload time
        let order2 = UploadCommitOrder::from_timestamps(
            Some(Utc::now()),
            None,
            grace,
        );
        assert_eq!(order2, UploadCommitOrder::Undetermined);

        // Both missing
        let order3 = UploadCommitOrder::from_timestamps(None, None, grace);
        assert_eq!(order3, UploadCommitOrder::Undetermined);
    }

    #[test]
    fn test_history_wash_risk_detection() {
        // Create a result with Upload-Then-Commit
        let upload_time = Utc::now();
        let commit_time = upload_time + Duration::hours(1);

        let result = BackfillResult {
            success: false,
            new_level: Some(EvidenceLevel::B),
            receipt_id: Some(ReceiptId("receipt:001".to_string())),
            map_commit_ref: Some("pmc:001".to_string()),
            error: Some("Upload-Then-Commit detected".to_string()),
            completed_at: Utc::now(),
            upload_commit_order: UploadCommitOrder::UploadThenCommit,
            history_wash_risk: true,
            commit_time: Some(commit_time),
            no_upgrade_reason: Some(BackfillNoUpgradeReason::UploadThenCommit {
                upload_time,
                commit_time,
            }),
        };

        assert!(result.history_wash_risk);
        assert_eq!(result.new_level, Some(EvidenceLevel::B));
        assert!(!result.success);
    }

    #[test]
    fn test_no_upgrade_reasons() {
        // Test all no-upgrade reasons
        let reasons = vec![
            BackfillNoUpgradeReason::MissingReceipt,
            BackfillNoUpgradeReason::MissingMapCommit,
            BackfillNoUpgradeReason::UploadThenCommit {
                upload_time: Utc::now(),
                commit_time: Utc::now() + Duration::hours(1),
            },
            BackfillNoUpgradeReason::DigestMismatch {
                expected: "abc123".to_string(),
                actual: "def456".to_string(),
            },
            BackfillNoUpgradeReason::CommitTimeUnknown,
            BackfillNoUpgradeReason::Other {
                details: "Test error".to_string(),
            },
        ];

        // All reasons should serialize/deserialize correctly
        for reason in reasons {
            let json = serde_json::to_string(&reason).unwrap();
            let _: BackfillNoUpgradeReason = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_backfill_entry_with_timestamps() {
        let entry = BackfillEntry {
            bundle_id: "bundle:001".to_string(),
            payload_refs_digest: Digest::blake3(b"test"),
            queued_at: Utc::now(),
            retry_count: 0,
            last_attempt_at: None,
            status: BackfillStatus::Pending,
            p2_upload_time: Some(Utc::now()),
            commit_cutoff_time: Some(Utc::now() - Duration::minutes(10)),
        };

        assert!(entry.p2_upload_time.is_some());
        assert!(entry.commit_cutoff_time.is_some());
    }
}
