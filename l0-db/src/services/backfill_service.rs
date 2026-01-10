//! Backfill Service Implementation
//!
//! Implements the BackfillLedger trait for managing B-to-A level evidence upgrades.
//! This service manages the process of upgrading B-level (local-only) evidence
//! to A-level (receipt-backed) evidence through anchoring.

use async_trait::async_trait;
use chrono::{Duration, Utc};
use l0_core::crypto::IncrementalMerkleTree;
use l0_core::error::LedgerError;
use l0_core::ledger::{
    BackfillLedger, CreateBackfillRequest, Ledger, LedgerResult,
};
use l0_core::types::{
    ActorId, BackfillItem, BackfillPlan, BackfillReceipt, BackfillRequest, BackfillStatus,
    ContinuityCheckResult, Digest, EvidenceLevel, GapRecord, GapType, ReceiptId,
};
use soulbase_storage::model::Entity;
use soulbase_storage::surreal::SurrealDatastore;
use soulbase_storage::Datastore;
use soulbase_types::prelude::TenantId;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::entities::BackfillRequestEntity;

/// In-memory plan cache (would be stored in DB in production)
type PlanCache = Arc<RwLock<HashMap<String, BackfillPlan>>>;

/// In-memory receipt cache (would be stored in DB in production)
type ReceiptCache = Arc<RwLock<HashMap<String, BackfillReceipt>>>;

/// Backfill Service
///
/// Manages backfill operations for upgrading B-level evidence to A-level.
pub struct BackfillService {
    datastore: Arc<SurrealDatastore>,
    tenant_id: TenantId,
    sequence: std::sync::atomic::AtomicU64,
    /// Cached plans for quick retrieval
    plans: PlanCache,
    /// Cached receipts for quick retrieval
    receipts: ReceiptCache,
}

impl BackfillService {
    /// Create a new Backfill Service
    pub fn new(datastore: Arc<SurrealDatastore>, tenant_id: TenantId) -> Self {
        Self {
            datastore,
            tenant_id,
            sequence: std::sync::atomic::AtomicU64::new(0),
            plans: Arc::new(RwLock::new(HashMap::new())),
            receipts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new Backfill Service with persistent sequence
    pub async fn new_with_persistence(
        datastore: Arc<SurrealDatastore>,
        tenant_id: TenantId,
    ) -> Result<Self, LedgerError> {
        let service = Self::new(datastore.clone(), tenant_id.clone());
        let max_seq = service.load_max_sequence().await?;
        service
            .sequence
            .store(max_seq + 1, std::sync::atomic::Ordering::SeqCst);
        Ok(service)
    }

    /// Load the maximum sequence number from existing records
    async fn load_max_sequence(&self) -> Result<u64, LedgerError> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant ORDER BY created_at DESC LIMIT 1",
            BackfillRequestEntity::TABLE
        );

        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let result: Option<BackfillRequestEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        if let Some(request) = result {
            if let Some(seq) = crate::sequence::extract_sequence_from_id(&request.request_id) {
                return Ok(seq);
            }
        }

        Ok(0)
    }

    /// Generate a new ID
    fn generate_id(&self, prefix: &str) -> String {
        let seq = self
            .sequence
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let timestamp = Utc::now().timestamp_micros();
        format!("{}_{:016x}_{:08x}", prefix, timestamp, seq)
    }

    /// Convert status to string
    fn status_to_str(status: BackfillStatus) -> &'static str {
        match status {
            BackfillStatus::Requested => "requested",
            BackfillStatus::PlanGenerated => "plan_generated",
            BackfillStatus::InProgress => "in_progress",
            BackfillStatus::Completed => "completed",
            BackfillStatus::Failed => "failed",
            BackfillStatus::Cancelled => "cancelled",
        }
    }

    /// Convert string to status
    fn str_to_status(s: &str) -> BackfillStatus {
        match s {
            "requested" => BackfillStatus::Requested,
            "plan_generated" => BackfillStatus::PlanGenerated,
            "in_progress" => BackfillStatus::InProgress,
            "completed" => BackfillStatus::Completed,
            "failed" => BackfillStatus::Failed,
            "cancelled" => BackfillStatus::Cancelled,
            _ => BackfillStatus::Requested,
        }
    }

    /// Convert entity to BackfillRequest
    fn entity_to_request(entity: &BackfillRequestEntity) -> BackfillRequest {
        BackfillRequest {
            request_id: entity.request_id.clone(),
            actor_id: ActorId(entity.actor_id.clone()),
            status: Self::str_to_status(&entity.status),
            backfill_type: l0_core::types::BackfillType::P1Initiated, // Default type
            start_digest: Digest::from_hex(&entity.start_digest).unwrap_or_default(),
            start_sequence_no: entity.start_sequence_no,
            end_digest: Digest::from_hex(&entity.end_digest).unwrap_or_default(),
            end_sequence_no: entity.end_sequence_no,
            tip_witness_ref: entity.tip_witness_ref.clone(),
            scope_filter: None, // Simplified for now
            time_window: None,
            coordination_state: None,
            original_window_ref: None,
            requested_at: entity.requested_at,
            completed_at: entity.completed_at,
            receipt_id: entity.receipt_id.clone().map(ReceiptId),
        }
    }
}

#[async_trait]
impl Ledger for BackfillService {
    fn name(&self) -> &'static str {
        "backfill"
    }

    async fn current_sequence(&self) -> LedgerResult<u64> {
        Ok(self.sequence.load(std::sync::atomic::Ordering::SeqCst))
    }

    async fn current_root(&self) -> LedgerResult<Digest> {
        // Compute Merkle root from all backfill requests
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant ORDER BY requested_at ASC",
            BackfillRequestEntity::TABLE
        );

        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let requests: Vec<BackfillRequestEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        if requests.is_empty() {
            return Ok(Digest::zero());
        }

        // Build Merkle tree from request digests
        let mut tree = IncrementalMerkleTree::new();
        for req in &requests {
            // Compute digest from request data
            let req_data = format!(
                "{}:{}:{}:{}",
                req.request_id, req.actor_id, req.start_sequence_no, req.end_sequence_no
            );
            let digest = Digest::blake3(req_data.as_bytes());
            tree.add(digest);
        }

        Ok(tree.root())
    }

    async fn verify_integrity(&self) -> LedgerResult<bool> {
        // Verify integrity by checking:
        // 1. All requests have valid status values
        // 2. Completed requests have completion timestamps
        // 3. No duplicate request IDs

        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant",
            BackfillRequestEntity::TABLE
        );

        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let requests: Vec<BackfillRequestEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        let mut seen_ids = std::collections::HashSet::new();
        let valid_statuses = ["requested", "plan_generated", "in_progress", "completed", "failed", "cancelled"];

        for req in &requests {
            // Check for duplicate IDs
            if !seen_ids.insert(&req.request_id) {
                return Ok(false);
            }

            // Check valid status
            if !valid_statuses.contains(&req.status.as_str()) {
                return Ok(false);
            }

            // Check completed requests have completion time
            if (req.status == "completed" || req.status == "failed" || req.status == "cancelled")
                && req.completed_at.is_none()
            {
                return Ok(false);
            }

            // Check sequence ordering
            if req.end_sequence_no < req.start_sequence_no {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

#[async_trait]
impl BackfillLedger for BackfillService {
    async fn create_request(&self, request: CreateBackfillRequest) -> LedgerResult<BackfillRequest> {
        let request_id = self.generate_id("backfill");
        let now = Utc::now();

        let entity = BackfillRequestEntity {
            id: format!("l0_backfill:{}:{}", self.tenant_id.0, request_id),
            tenant_id: self.tenant_id.clone(),
            request_id: request_id.clone(),
            actor_id: request.actor_id.0.clone(),
            status: "requested".to_string(),
            start_digest: request.start_digest.to_hex(),
            start_sequence_no: request.start_sequence_no,
            end_digest: request.end_digest.to_hex(),
            end_sequence_no: request.end_sequence_no,
            tip_witness_ref: request.tip_witness_ref,
            requested_at: now,
            completed_at: None,
            receipt_id: None,
            plan_id: None,
        };

        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!("CREATE {} CONTENT $data RETURN AFTER", BackfillRequestEntity::TABLE);

        let mut response = session
            .client()
            .query(&query)
            .bind(("data", entity))
            .await
            .map_err(|e| LedgerError::Storage(format!("Create failed: {}", e)))?;

        let result: Option<BackfillRequestEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        let created = result.ok_or_else(|| LedgerError::Storage("Create returned no result".to_string()))?;
        Ok(Self::entity_to_request(&created))
    }

    async fn get_request(&self, request_id: &str) -> LedgerResult<Option<BackfillRequest>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND request_id = $request_id LIMIT 1",
            BackfillRequestEntity::TABLE
        );

        let request_id_owned = request_id.to_string();
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("request_id", request_id_owned))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let result: Option<BackfillRequestEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        Ok(result.map(|e| Self::entity_to_request(&e)))
    }

    async fn list_requests(
        &self,
        actor_id: &ActorId,
        status: Option<BackfillStatus>,
    ) -> LedgerResult<Vec<BackfillRequest>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let status_clause = status
            .map(|s| format!("AND status = '{}'", Self::status_to_str(s)))
            .unwrap_or_default();

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND actor_id = $actor {} ORDER BY requested_at DESC LIMIT 100",
            BackfillRequestEntity::TABLE,
            status_clause
        );

        let actor_owned = actor_id.0.clone();
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("actor", actor_owned))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let results: Vec<BackfillRequestEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        Ok(results.iter().map(Self::entity_to_request).collect())
    }

    async fn update_request_status(
        &self,
        request_id: &str,
        status: BackfillStatus,
    ) -> LedgerResult<()> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let completed_at = if matches!(status, BackfillStatus::Completed | BackfillStatus::Failed | BackfillStatus::Cancelled) {
            Some(Utc::now())
        } else {
            None
        };

        let query = format!(
            "UPDATE {} SET status = $status, completed_at = $completed WHERE tenant_id = $tenant AND request_id = $request_id",
            BackfillRequestEntity::TABLE
        );

        let request_id_owned = request_id.to_string();
        session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("request_id", request_id_owned))
            .bind(("status", Self::status_to_str(status)))
            .bind(("completed", completed_at))
            .await
            .map_err(|e| LedgerError::Storage(format!("Update failed: {}", e)))?;

        Ok(())
    }

    async fn generate_plan(&self, request_id: &str) -> LedgerResult<BackfillPlan> {
        let request = self
            .get_request(request_id)
            .await?
            .ok_or_else(|| LedgerError::NotFound(format!("Request {} not found", request_id)))?;

        // Detect gaps
        let gaps = self
            .detect_gaps(
                &request.actor_id,
                request.start_sequence_no,
                request.end_sequence_no,
            )
            .await?;

        // Calculate continuity result
        let continuity = if gaps.is_empty() {
            ContinuityCheckResult::Pass
        } else if gaps.iter().all(|g| g.acceptable) {
            ContinuityCheckResult::PassWithGaps
        } else {
            ContinuityCheckResult::Fail
        };

        // Generate anchor sequence with computed digests
        let item_count = (request.end_sequence_no - request.start_sequence_no + 1) as usize;
        let mut prev_digest: Option<Digest> = None;

        let anchor_sequence: Vec<BackfillItem> = (request.start_sequence_no..=request.end_sequence_no)
            .map(|seq| {
                // Compute a deterministic digest for this item
                // In production, this would fetch actual object digests from storage
                let item_data = format!(
                    "{}:{}:{}",
                    request.actor_id.0, seq, request.start_digest.to_hex()
                );
                let object_digest = Digest::blake3(item_data.as_bytes());

                let item = BackfillItem {
                    sequence_no: seq,
                    object_type: "commitment".to_string(),
                    object_digest: object_digest.clone(),
                    parent_digest: prev_digest.clone(),
                    current_level: EvidenceLevel::B,
                    target_level: EvidenceLevel::A,
                    anchored: false,
                    receipt_ref: None,
                };

                prev_digest = Some(object_digest);
                item
            })
            .collect();

        // Calculate estimated fee based on item count
        let base_fee_per_item = 10u64;
        let estimated_fee = format!("{}", item_count as u64 * base_fee_per_item);

        let plan_id = self.generate_id("plan");
        let now = Utc::now();

        // Compute plan digest from all items
        let mut tree = IncrementalMerkleTree::new();
        for item in &anchor_sequence {
            tree.add(item.object_digest.clone());
        }
        let plan_digest = tree.root();

        let plan = BackfillPlan {
            plan_id: plan_id.clone(),
            request_ref: request_id.to_string(),
            anchor_sequence,
            estimated_fee,
            gaps,
            continuity_result: continuity,
            created_at: now,
            expires_at: now + Duration::hours(24),
            plan_digest,
        };

        // Store the plan in cache
        {
            let mut plans = self.plans.write().await;
            plans.insert(plan_id.clone(), plan.clone());
        }

        // Update request status
        self.update_request_status(request_id, BackfillStatus::PlanGenerated)
            .await?;

        Ok(plan)
    }

    async fn get_plan(&self, plan_id: &str) -> LedgerResult<Option<BackfillPlan>> {
        let plans = self.plans.read().await;
        Ok(plans.get(plan_id).cloned())
    }

    async fn execute_plan(&self, plan_id: &str) -> LedgerResult<BackfillReceipt> {
        // Get the plan
        let plan = self.get_plan(plan_id).await?.ok_or_else(|| {
            LedgerError::NotFound(format!("Plan {} not found", plan_id))
        })?;

        // Get the original request
        let request = self.get_request(&plan.request_ref).await?.ok_or_else(|| {
            LedgerError::NotFound(format!("Request {} not found", plan.request_ref))
        })?;

        // Update request status to in-progress
        self.update_request_status(&plan.request_ref, BackfillStatus::InProgress).await?;

        let started_at = Utc::now();

        // Process each item in the anchor sequence
        // In production, this would:
        // 1. Create batches of items
        // 2. Submit each batch for anchoring
        // 3. Wait for confirmation
        // 4. Update each item's receipt_ref

        let objects_anchored = plan.anchor_sequence.len() as u64;

        // Compute digest of all anchored objects
        let mut tree = IncrementalMerkleTree::new();
        for item in &plan.anchor_sequence {
            tree.add(item.object_digest.clone());
        }
        let anchored_objects_digest = tree.root();

        // Compute gaps digest if any
        let gaps_acknowledged_digest = if !plan.gaps.is_empty() {
            let gaps_data: String = plan.gaps.iter()
                .map(|g| format!("{}:{}", g.start_sequence, g.end_sequence))
                .collect::<Vec<_>>()
                .join(",");
            Some(Digest::blake3(gaps_data.as_bytes()))
        } else {
            None
        };

        let receipt_id = self.generate_id("backfill_receipt");
        let completed_at = Utc::now();

        let receipt = BackfillReceipt {
            backfill_receipt_id: receipt_id.clone(),
            request_ref: plan.request_ref.clone(),
            plan_ref: plan_id.to_string(),
            actor_id: request.actor_id.clone(),
            objects_anchored,
            anchored_objects_digest,
            gaps_acknowledged_digest,
            total_fee_paid: plan.estimated_fee.clone(),
            continuity_result: plan.continuity_result,
            started_at,
            completed_at,
            receipt_id: ReceiptId(receipt_id.clone()),
        };

        // Store the receipt in cache
        {
            let mut receipts = self.receipts.write().await;
            receipts.insert(receipt_id.clone(), receipt.clone());
        }

        // Update request status to completed
        self.update_request_status(&plan.request_ref, BackfillStatus::Completed).await?;

        Ok(receipt)
    }

    async fn get_receipt(&self, receipt_id: &str) -> LedgerResult<Option<BackfillReceipt>> {
        let receipts = self.receipts.read().await;
        Ok(receipts.get(receipt_id).cloned())
    }

    async fn cancel_request(&self, request_id: &str, _reason: String) -> LedgerResult<()> {
        self.update_request_status(request_id, BackfillStatus::Cancelled)
            .await
    }

    async fn detect_gaps(
        &self,
        actor_id: &ActorId,
        start_sequence: u64,
        end_sequence: u64,
    ) -> LedgerResult<Vec<GapRecord>> {
        // Analyze the actor's commitment chain to identify gaps
        // In a full implementation, this would query the commitment ledger

        let mut gaps = Vec::new();

        // For now, we detect gaps based on heuristics
        // A gap is detected when there's a significant jump in sequence numbers
        // or when expected hash chain links are missing

        let sequence_range = end_sequence.saturating_sub(start_sequence);

        // Define gap detection thresholds
        const SMALL_GAP_THRESHOLD: u64 = 10;
        const LARGE_GAP_THRESHOLD: u64 = 100;
        const MAX_ACCEPTABLE_GAP: u64 = 1000;

        // Check for sequence discontinuities
        // In production, this would query the actual sequence data
        if sequence_range > LARGE_GAP_THRESHOLD {
            // For large ranges, sample points to detect gaps
            let sample_points = [
                start_sequence + sequence_range / 4,
                start_sequence + sequence_range / 2,
                start_sequence + 3 * sequence_range / 4,
            ];

            for (i, &point) in sample_points.iter().enumerate() {
                // Simulate checking if this sequence exists
                // In production, query the database
                let sequence_exists = point % 100 != 0; // Simulate some missing sequences

                if !sequence_exists && i > 0 {
                    let gap_start = sample_points.get(i.saturating_sub(1)).copied().unwrap_or(start_sequence);
                    let gap_size = point - gap_start;

                    gaps.push(GapRecord {
                        gap_id: format!("gap:{}:{}:{}", actor_id.0, gap_start, point),
                        start_sequence: gap_start,
                        end_sequence: point,
                        gap_type: if gap_size > SMALL_GAP_THRESHOLD {
                            GapType::SequenceGap
                        } else {
                            GapType::HashChainBreak
                        },
                        acceptable: gap_size < MAX_ACCEPTABLE_GAP,
                        reason_digest: Some(Digest::blake3(
                            format!("gap:{}:{}:{}", actor_id.0, gap_start, point).as_bytes()
                        )),
                    });
                }
            }
        }

        Ok(gaps)
    }

    async fn verify_continuity(
        &self,
        actor_id: &ActorId,
        start_sequence: u64,
        end_sequence: u64,
    ) -> LedgerResult<ContinuityCheckResult> {
        let gaps = self.detect_gaps(actor_id, start_sequence, end_sequence).await?;

        if gaps.is_empty() {
            Ok(ContinuityCheckResult::Pass)
        } else if gaps.iter().all(|g| g.acceptable) {
            Ok(ContinuityCheckResult::PassWithGaps)
        } else {
            Ok(ContinuityCheckResult::Fail)
        }
    }

    async fn get_backfill_history(
        &self,
        actor_id: &ActorId,
        limit: u32,
    ) -> LedgerResult<Vec<BackfillReceipt>> {
        // Get receipts from cache that match this actor
        let receipts = self.receipts.read().await;

        let mut history: Vec<BackfillReceipt> = receipts
            .values()
            .filter(|r| r.actor_id == *actor_id)
            .cloned()
            .collect();

        // Sort by completion time (most recent first)
        history.sort_by(|a, b| b.completed_at.cmp(&a.completed_at));

        // Apply limit
        history.truncate(limit as usize);

        Ok(history)
    }
}
