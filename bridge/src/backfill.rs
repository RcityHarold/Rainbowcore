//! Evidence Backfill Mechanism
//!
//! Upgrades B-level evidence to A-level when P1 receipts and map_commits
//! become available. This ensures eventual consistency between P1 and P2.
//!
//! # Hard Rule
//!
//! Evidence level MUST be upgraded from B to A when:
//! 1. A valid P1 receipt exists
//! 2. A valid payload_map_commit exists
//! 3. The map_commit digest matches the payload refs digest

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use l0_core::types::{Digest, ReceiptId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::error::{BridgeError, BridgeResult};
use crate::l0_client::L0CommitClient;
use crate::payload_map_commit::PayloadMapCommit;
use p2_core::types::{EvidenceBundle, EvidenceLevel};

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
            });

            // Mark complete or failed in ledger
            if backfill_result.success || entry.retry_count >= self.max_retries {
                self.backfill_ledger
                    .mark_complete(&entry.bundle_id, backfill_result.clone())
                    .await?;
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

    /// Process a single backfill entry
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
            });
        }

        // Try to find receipt and map_commit
        let mut receipt_id = bundle.receipt_id.clone();
        let mut map_commit_ref = bundle.map_commit_ref.clone();

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
                Ok(Some(ref_id)) => {
                    self.evidence_updater
                        .set_map_commit(&entry.bundle_id, ref_id.clone())
                        .await?;
                    map_commit_ref = Some(ref_id);
                }
                Ok(None) => {
                    debug!("No map_commit found for bundle: {}", entry.bundle_id);
                }
                Err(e) => {
                    warn!("Error finding map_commit: {}", e);
                }
            }
        }

        // Determine new level
        let new_level = if receipt_id.is_some() && map_commit_ref.is_some() {
            EvidenceLevel::A
        } else {
            EvidenceLevel::B
        };

        let success = new_level == EvidenceLevel::A;

        Ok(BackfillResult {
            success,
            new_level: Some(new_level),
            receipt_id,
            map_commit_ref,
            error: if !success {
                Some("Missing receipt or map_commit".to_string())
            } else {
                None
            },
            completed_at: Utc::now(),
        })
    }

    /// Find receipt for a given digest
    async fn find_receipt_for_digest(&self, digest: &Digest) -> BridgeResult<Option<ReceiptId>> {
        // Query L0 for receipts matching this digest
        // This is a simplified implementation - in production, would need
        // to query L0 API for map_commits containing this digest

        // For now, we check recent batches
        let current_batch = self.l0_client.current_batch_sequence().await?;

        // Check last 10 batches
        for batch_seq in (current_batch.saturating_sub(10)..=current_batch).rev() {
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

    /// Find map_commit for a given digest
    async fn find_map_commit_for_digest(&self, digest: &Digest) -> BridgeResult<Option<String>> {
        // In production, would query L0 for PayloadMapCommits
        // For now, return None - the actual implementation depends on L0 API
        Ok(None)
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

        let result = BackfillResult {
            success: true,
            new_level: Some(EvidenceLevel::A),
            receipt_id: Some(ReceiptId("receipt:001".to_string())),
            map_commit_ref: Some("pmc:001".to_string()),
            error: None,
            completed_at: Utc::now(),
        };

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
            let result = BackfillResult {
                success: true,
                new_level: Some(EvidenceLevel::A),
                receipt_id: None,
                map_commit_ref: None,
                error: None,
                completed_at: Utc::now(),
            };
            ledger
                .mark_complete(&format!("bundle:{}", i), result)
                .await
                .unwrap();
        }

        let stats = ledger.get_stats().await.unwrap();
        assert_eq!(stats.completed_count, 3);
        assert_eq!(stats.pending_count, 2);
    }
}
