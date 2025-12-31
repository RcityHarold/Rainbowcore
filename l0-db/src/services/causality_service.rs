//! Causality Ledger Service Implementation
//!
//! Implements the CausalityLedger trait using l0-db repositories.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use l0_core::error::LedgerError;
use l0_core::ledger::{CausalityLedger, CommitmentRecord, Ledger, LedgerResult, QueryOptions};
use l0_core::types::{
    ActorId, Digest, EpochSnapshot, L0Receipt, ReceiptId, RootKind, ScopeType, SignedBatchSnapshot,
};
use l0_core::crypto::IncrementalMerkleTree;
use soulbase_types::prelude::TenantId;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::entities::{BatchSnapshotEntity, CommitmentEntity, EpochSnapshotEntity};
use crate::error::L0DbError;
use crate::repos::L0Database;

/// Causality Ledger Service
pub struct CausalityService {
    database: Arc<L0Database>,
    tenant_id: TenantId,
    /// Current batch accumulator
    batch_tree: RwLock<IncrementalMerkleTree>,
    /// Current batch sequence number
    batch_sequence: std::sync::atomic::AtomicU64,
}

impl CausalityService {
    /// Create a new Causality Service
    pub fn new(database: Arc<L0Database>, tenant_id: TenantId) -> Self {
        Self {
            database,
            tenant_id,
            batch_tree: RwLock::new(IncrementalMerkleTree::new()),
            batch_sequence: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Initialize from database (load latest batch sequence)
    pub async fn init(&self) -> LedgerResult<()> {
        let latest = self
            .database
            .commitments
            .get_latest_batch(&self.tenant_id)
            .await
            .map_err(Self::map_db_error)?;

        if let Some(batch) = latest {
            self.batch_sequence.store(
                batch.batch_sequence_no + 1,
                std::sync::atomic::Ordering::SeqCst,
            );
        }

        Ok(())
    }

    /// Generate a new commitment ID
    fn generate_commitment_id(&self) -> String {
        let timestamp = Utc::now().timestamp_micros();
        let random: u32 = rand::random();
        format!("commit_{:016x}_{:08x}", timestamp, random)
    }

    /// Convert database error to ledger error
    fn map_db_error(e: L0DbError) -> LedgerError {
        LedgerError::Storage(e.to_string())
    }

    /// Convert ScopeType to string
    fn scope_type_to_str(scope_type: ScopeType) -> &'static str {
        match scope_type {
            ScopeType::AknBatch => "akn_batch",
            ScopeType::ConsentBatch => "consent_batch",
            ScopeType::VerdictBatch => "verdict_batch",
            ScopeType::DisputeBatch => "dispute_batch",
            ScopeType::RepairBatch => "repair_batch",
            ScopeType::ClawbackBatch => "clawback_batch",
            ScopeType::LogBatch => "log_batch",
            ScopeType::TraceBatch => "trace_batch",
            ScopeType::BackfillBatch => "backfill_batch",
            ScopeType::IdentityBatch => "identity_batch",
            ScopeType::CovenantStatusBatch => "covenant_status_batch",
        }
    }

    /// Convert string to ScopeType
    fn str_to_scope_type(s: &str) -> Result<ScopeType, LedgerError> {
        match s {
            "akn_batch" => Ok(ScopeType::AknBatch),
            "consent_batch" => Ok(ScopeType::ConsentBatch),
            "verdict_batch" => Ok(ScopeType::VerdictBatch),
            "dispute_batch" => Ok(ScopeType::DisputeBatch),
            "repair_batch" => Ok(ScopeType::RepairBatch),
            "clawback_batch" => Ok(ScopeType::ClawbackBatch),
            "log_batch" => Ok(ScopeType::LogBatch),
            "trace_batch" => Ok(ScopeType::TraceBatch),
            "backfill_batch" => Ok(ScopeType::BackfillBatch),
            "identity_batch" => Ok(ScopeType::IdentityBatch),
            "covenant_status_batch" => Ok(ScopeType::CovenantStatusBatch),
            _ => Err(LedgerError::Validation(format!(
                "Unknown scope type: {}",
                s
            ))),
        }
    }

    /// Convert CommitmentEntity to CommitmentRecord
    fn entity_to_record(entity: &CommitmentEntity) -> LedgerResult<CommitmentRecord> {
        let scope_type = Self::str_to_scope_type(&entity.scope_type)?;

        Ok(CommitmentRecord {
            commitment_id: entity.commitment_id.clone(),
            actor_id: ActorId(entity.actor_id.clone()),
            scope_type,
            commitment_digest: Digest::from_hex(&entity.commitment_digest).unwrap_or_default(),
            parent_commitment_ref: entity.parent_commitment_ref.clone(),
            sequence_no: entity.sequence_no,
            created_at: entity.created_at,
            receipt_id: entity.receipt_id.as_ref().map(|id| ReceiptId(id.clone())),
        })
    }

    /// Get the latest epoch sequence number
    pub async fn get_epoch_sequence(&self) -> LedgerResult<u64> {
        self.database
            .commitments
            .get_latest_epoch_sequence(&self.tenant_id)
            .await
            .map_err(Self::map_db_error)
    }

    /// Seal current batch and create snapshot (internal method)
    pub async fn seal_batch(&self) -> LedgerResult<BatchSnapshotEntity> {
        let mut tree = self.batch_tree.write().await;
        let batch_root = tree.root();
        let count = tree.count();

        if count == 0 {
            return Err(LedgerError::Validation(
                "No commitments in batch".to_string(),
            ));
        }

        let batch_seq = self
            .batch_sequence
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let now = Utc::now();

        // Get previous batch root
        let prev_batch = self
            .database
            .commitments
            .get_batch_snapshot(&self.tenant_id, batch_seq.saturating_sub(1))
            .await
            .map_err(Self::map_db_error)?;

        let parent_root = prev_batch.map(|b| b.batch_root);

        let snapshot = BatchSnapshotEntity {
            id: format!("l0_batch_snapshot:{}:{}", self.tenant_id.0, batch_seq),
            tenant_id: self.tenant_id.clone(),
            batch_sequence_no: batch_seq,
            batch_root: batch_root.to_hex(),
            time_window_start: now,
            time_window_end: now,
            parent_batch_root: parent_root,
            commitment_count: count as u64,
            signer_set_version: "v1".to_string(),
            threshold_rule: "5/9".to_string(),
            signature_bitmap: String::new(),
            threshold_proof: String::new(),
            created_at: now,
        };

        let created = self
            .database
            .commitments
            .create_batch_snapshot(&snapshot)
            .await
            .map_err(Self::map_db_error)?;

        // Reset tree for next batch
        *tree = IncrementalMerkleTree::new();

        Ok(created)
    }
}

#[async_trait]
impl Ledger for CausalityService {
    fn name(&self) -> &'static str {
        "causality"
    }

    async fn current_sequence(&self) -> LedgerResult<u64> {
        Ok(self
            .batch_sequence
            .load(std::sync::atomic::Ordering::SeqCst))
    }

    async fn current_root(&self) -> LedgerResult<Digest> {
        let tree = self.batch_tree.read().await;
        Ok(tree.root())
    }

    async fn verify_integrity(&self) -> LedgerResult<bool> {
        // Verify batch chain continuity
        let batches = self
            .database
            .commitments
            .list_batch_snapshots(&self.tenant_id, 10000) // Get all batches
            .await
            .map_err(Self::map_db_error)?;

        if batches.is_empty() {
            return Ok(true);
        }

        // Verify batch sequence continuity and parent chain
        let mut prev_root: Option<String> = None;
        let mut prev_seq: Option<u64> = None;

        for batch in &batches {
            // Check sequence continuity
            if let Some(expected_seq) = prev_seq {
                if batch.batch_sequence_no != expected_seq + 1 {
                    return Ok(false); // Sequence gap detected
                }
            } else if batch.batch_sequence_no != 0 {
                // First batch should start at 0
                return Ok(false);
            }

            // Check parent root chain
            if let Some(expected_parent) = &prev_root {
                match &batch.parent_batch_root {
                    Some(actual_parent) if actual_parent == expected_parent => {}
                    _ => return Ok(false), // Parent chain broken
                }
            }

            // Required fields check
            if batch.batch_root.is_empty() {
                return Ok(false);
            }

            prev_root = Some(batch.batch_root.clone());
            prev_seq = Some(batch.batch_sequence_no);
        }

        Ok(true)
    }
}

#[async_trait]
impl CausalityLedger for CausalityService {
    async fn submit_commitment(
        &self,
        actor_id: &ActorId,
        scope_type: ScopeType,
        commitment_digest: Digest,
        parent_ref: Option<String>,
    ) -> LedgerResult<CommitmentRecord> {
        // Get the actor's latest commitment for sequence number
        let latest = self
            .database
            .commitments
            .get_latest(&self.tenant_id, &actor_id.0)
            .await
            .map_err(Self::map_db_error)?;

        let sequence_no = latest.as_ref().map(|c| c.sequence_no + 1).unwrap_or(0);

        // Validate parent reference
        let parent_commitment_ref = match parent_ref {
            Some(ref p) => {
                // Verify parent exists
                let parent = self
                    .database
                    .commitments
                    .get_by_id(&self.tenant_id, p)
                    .await
                    .map_err(Self::map_db_error)?;
                if parent.is_none() {
                    return Err(LedgerError::NotFound(format!(
                        "Parent commitment {} not found",
                        p
                    )));
                }
                Some(p.clone())
            }
            None => latest.map(|c| c.commitment_id),
        };

        let scope_str = Self::scope_type_to_str(scope_type);
        let commitment_id = self.generate_commitment_id();

        let entity = CommitmentEntity::new(
            self.tenant_id.clone(),
            commitment_id.clone(),
            actor_id.0.clone(),
            scope_str.to_string(),
            commitment_digest.to_hex(),
            parent_commitment_ref,
            sequence_no,
        );

        let created = self
            .database
            .commitments
            .create(&entity)
            .await
            .map_err(Self::map_db_error)?;

        // Add to current batch tree
        {
            let mut tree = self.batch_tree.write().await;
            tree.add(commitment_digest.clone());
        }

        Self::entity_to_record(&created)
    }

    async fn get_commitment(&self, commitment_id: &str) -> LedgerResult<Option<CommitmentRecord>> {
        let result = self
            .database
            .commitments
            .get_by_id(&self.tenant_id, commitment_id)
            .await
            .map_err(Self::map_db_error)?;

        match result {
            Some(entity) => Ok(Some(Self::entity_to_record(&entity)?)),
            None => Ok(None),
        }
    }

    async fn get_commitment_chain(
        &self,
        actor_id: &ActorId,
        scope_type: Option<ScopeType>,
        options: QueryOptions,
    ) -> LedgerResult<Vec<CommitmentRecord>> {
        let limit = options.limit.unwrap_or(100);
        let scope_str = scope_type.map(Self::scope_type_to_str);

        let entities = self
            .database
            .commitments
            .get_chain_with_scope(&self.tenant_id, &actor_id.0, scope_str, limit)
            .await
            .map_err(Self::map_db_error)?;

        entities.iter().map(Self::entity_to_record).collect()
    }

    async fn verify_chain(&self, commitment_id: &str, depth: Option<u32>) -> LedgerResult<bool> {
        // Get the starting commitment
        let commitment = self
            .get_commitment(commitment_id)
            .await?
            .ok_or_else(|| LedgerError::NotFound(format!("Commitment {} not found", commitment_id)))?;

        let max_depth = depth.unwrap_or(1000) as usize;
        let mut current = commitment;
        let mut count = 0;

        // Walk the parent chain
        while let Some(ref parent_ref) = current.parent_commitment_ref {
            if count >= max_depth {
                break;
            }

            let parent = self
                .get_commitment(parent_ref)
                .await?
                .ok_or_else(|| {
                    LedgerError::ContinuityFailed(format!("Parent {} not found", parent_ref))
                })?;

            // Verify sequence continuity
            if parent.sequence_no + 1 != current.sequence_no {
                return Ok(false);
            }

            // Verify actor continuity
            if parent.actor_id.0 != current.actor_id.0 {
                return Ok(false);
            }

            current = parent;
            count += 1;
        }

        Ok(true)
    }

    async fn submit_batch_root(&self, snapshot: SignedBatchSnapshot) -> LedgerResult<L0Receipt> {
        // Create batch snapshot entity
        let entity = BatchSnapshotEntity {
            id: format!(
                "l0_batch_snapshot:{}:{}",
                self.tenant_id.0, snapshot.batch_sequence_no
            ),
            tenant_id: self.tenant_id.clone(),
            batch_sequence_no: snapshot.batch_sequence_no,
            batch_root: snapshot.batch_root.to_hex(),
            time_window_start: snapshot.time_window_start,
            time_window_end: snapshot.time_window_end,
            parent_batch_root: snapshot.parent_batch_root.map(|d| d.to_hex()),
            commitment_count: 0, // Not tracked in SignedBatchSnapshot
            signer_set_version: snapshot.signer_set_version.clone(),
            threshold_rule: snapshot.threshold_rule.clone(),
            signature_bitmap: snapshot.signature_bitmap.clone(),
            threshold_proof: snapshot.threshold_proof.clone(),
            created_at: Utc::now(),
        };

        self.database
            .commitments
            .create_batch_snapshot(&entity)
            .await
            .map_err(Self::map_db_error)?;

        // Generate receipt
        let receipt_id = ReceiptId(format!(
            "receipt_batch_{}",
            snapshot.batch_sequence_no
        ));

        Ok(L0Receipt {
            receipt_id: receipt_id.clone(),
            scope_type: ScopeType::AknBatch,
            root_kind: RootKind::BatchRoot,
            root: snapshot.batch_root,
            time_window_start: snapshot.time_window_start,
            time_window_end: snapshot.time_window_end,
            batch_sequence_no: Some(snapshot.batch_sequence_no),
            signer_set_version: snapshot.signer_set_version,
            canonicalization_version: snapshot.canonicalization_version,
            anchor_policy_version: snapshot.anchor_policy_version,
            fee_schedule_version: snapshot.fee_schedule_version,
            fee_receipt_id: String::new(),
            signed_snapshot_ref: snapshot.snapshot_id,
            created_at: Utc::now(),
            rejected: None,
            reject_reason_code: None,
            observer_reports_digest: snapshot.observer_reports_digest,
        })
    }

    async fn get_batch_snapshot(
        &self,
        sequence_no: u64,
    ) -> LedgerResult<Option<SignedBatchSnapshot>> {
        let entity = self
            .database
            .commitments
            .get_batch_snapshot(&self.tenant_id, sequence_no)
            .await
            .map_err(Self::map_db_error)?;

        match entity {
            Some(e) => {
                let snapshot = SignedBatchSnapshot {
                    snapshot_id: e.id,
                    batch_root: Digest::from_hex(&e.batch_root).unwrap_or_default(),
                    time_window_start: e.time_window_start,
                    time_window_end: e.time_window_end,
                    batch_sequence_no: e.batch_sequence_no,
                    parent_batch_root: e.parent_batch_root.and_then(|s| Digest::from_hex(&s).ok()),
                    signer_set_version: e.signer_set_version,
                    canonicalization_version: "v1".to_string(),
                    anchor_policy_version: "v1".to_string(),
                    fee_schedule_version: "v1".to_string(),
                    threshold_rule: e.threshold_rule,
                    signature_bitmap: e.signature_bitmap,
                    threshold_proof: e.threshold_proof,
                    observer_reports_digest: None,
                };
                Ok(Some(snapshot))
            }
            None => Ok(None),
        }
    }

    async fn submit_epoch_root(&self, snapshot: EpochSnapshot) -> LedgerResult<L0Receipt> {
        let entity = EpochSnapshotEntity {
            id: format!(
                "l0_epoch_snapshot:{}:{}",
                self.tenant_id.0, snapshot.epoch_sequence_no
            ),
            tenant_id: self.tenant_id.clone(),
            epoch_sequence_no: snapshot.epoch_sequence_no,
            epoch_root: snapshot.epoch_root.to_hex(),
            time_window_start: snapshot.epoch_window_start,
            time_window_end: snapshot.epoch_window_end,
            batch_start: 0, // Not tracked in EpochSnapshot directly
            batch_end: 0,
            parent_epoch_root: snapshot.parent_epoch_root.map(|d| d.to_hex()),
            chain_anchor_tx: None,
            anchor_status: "pending".to_string(),
            created_at: Utc::now(),
        };

        self.database
            .commitments
            .create_epoch_snapshot(&entity)
            .await
            .map_err(Self::map_db_error)?;

        let receipt_id = ReceiptId(format!(
            "receipt_epoch_{}",
            snapshot.epoch_sequence_no
        ));

        Ok(L0Receipt {
            receipt_id: receipt_id.clone(),
            scope_type: ScopeType::AknBatch,
            root_kind: RootKind::EpochRoot,
            root: snapshot.epoch_root,
            time_window_start: snapshot.epoch_window_start,
            time_window_end: snapshot.epoch_window_end,
            batch_sequence_no: None,
            signer_set_version: snapshot.signer_set_version,
            canonicalization_version: snapshot.canonicalization_version,
            anchor_policy_version: snapshot.chain_anchor_policy_version,
            fee_schedule_version: "v1".to_string(),
            fee_receipt_id: String::new(),
            signed_snapshot_ref: snapshot.epoch_id,
            created_at: Utc::now(),
            rejected: None,
            reject_reason_code: None,
            observer_reports_digest: snapshot.gaps_digest,
        })
    }

    async fn get_epoch_snapshot(&self, sequence_no: u64) -> LedgerResult<Option<EpochSnapshot>> {
        let entity = self
            .database
            .commitments
            .get_epoch_snapshot(&self.tenant_id, sequence_no)
            .await
            .map_err(Self::map_db_error)?;

        match entity {
            Some(e) => {
                let snapshot = EpochSnapshot {
                    epoch_id: e.id,
                    epoch_root: Digest::from_hex(&e.epoch_root).unwrap_or_default(),
                    epoch_window_start: e.time_window_start,
                    epoch_window_end: e.time_window_end,
                    epoch_sequence_no: e.epoch_sequence_no,
                    parent_epoch_root: e.parent_epoch_root.and_then(|s| Digest::from_hex(&s).ok()),
                    signer_set_version: "v1".to_string(),
                    canonicalization_version: "v1".to_string(),
                    chain_anchor_policy_version: "v1".to_string(),
                    threshold_rule: "5/9".to_string(),
                    signature_bitmap: None,
                    threshold_proof: None,
                    gaps_digest: None,
                    batch_receipts_digest: Digest::zero(),
                };
                Ok(Some(snapshot))
            }
            None => Ok(None),
        }
    }

    async fn get_commitments_in_window(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        scope_type: Option<ScopeType>,
    ) -> LedgerResult<Vec<CommitmentRecord>> {
        let scope_str = scope_type.map(Self::scope_type_to_str);

        let entities = self
            .database
            .commitments
            .get_in_time_window(&self.tenant_id, start, end, scope_str)
            .await
            .map_err(Self::map_db_error)?;

        entities.iter().map(Self::entity_to_record).collect()
    }

    async fn calculate_batch_root(&self, commitment_ids: &[String]) -> LedgerResult<Digest> {
        let mut tree = IncrementalMerkleTree::new();

        for id in commitment_ids {
            let commitment = self.get_commitment(id).await?.ok_or_else(|| {
                LedgerError::NotFound(format!("Commitment {} not found", id))
            })?;
            tree.add(commitment.commitment_digest);
        }

        Ok(tree.root())
    }
}
