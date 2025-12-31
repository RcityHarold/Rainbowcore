//! Backfill Service Implementation
//!
//! Implements the BackfillLedger trait for managing B-to-A level evidence upgrades.

use async_trait::async_trait;
use chrono::{Duration, Utc};
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
use std::sync::Arc;

use crate::entities::BackfillRequestEntity;

/// Backfill Service
///
/// Manages backfill operations for upgrading B-level evidence to A-level.
pub struct BackfillService {
    datastore: Arc<SurrealDatastore>,
    tenant_id: TenantId,
    sequence: std::sync::atomic::AtomicU64,
}

impl BackfillService {
    /// Create a new Backfill Service
    pub fn new(datastore: Arc<SurrealDatastore>, tenant_id: TenantId) -> Self {
        Self {
            datastore,
            tenant_id,
            sequence: std::sync::atomic::AtomicU64::new(0),
        }
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
            start_digest: Digest::from_hex(&entity.start_digest).unwrap_or_default(),
            start_sequence_no: entity.start_sequence_no,
            end_digest: Digest::from_hex(&entity.end_digest).unwrap_or_default(),
            end_sequence_no: entity.end_sequence_no,
            tip_witness_ref: entity.tip_witness_ref.clone(),
            scope_filter: None, // Simplified for now
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
        Ok(Digest::zero())
    }

    async fn verify_integrity(&self) -> LedgerResult<bool> {
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

        // Generate anchor sequence
        let item_count = (request.end_sequence_no - request.start_sequence_no + 1) as usize;
        let anchor_sequence: Vec<BackfillItem> = (request.start_sequence_no..=request.end_sequence_no)
            .map(|seq| BackfillItem {
                sequence_no: seq,
                object_type: "commitment".to_string(),
                object_digest: Digest::zero(), // Would be fetched from actual data
                parent_digest: None,
                current_level: EvidenceLevel::B,
                target_level: EvidenceLevel::A,
                anchored: false,
                receipt_ref: None,
            })
            .collect();

        // Calculate estimated fee (simplified)
        let estimated_fee = format!("{}", item_count * 10);

        let plan_id = self.generate_id("plan");
        let now = Utc::now();

        let plan = BackfillPlan {
            plan_id: plan_id.clone(),
            request_ref: request_id.to_string(),
            anchor_sequence,
            estimated_fee,
            gaps,
            continuity_result: continuity,
            created_at: now,
            expires_at: now + Duration::hours(24),
            plan_digest: Digest::zero(), // Would be computed from plan contents
        };

        // Update request status
        self.update_request_status(request_id, BackfillStatus::PlanGenerated)
            .await?;

        Ok(plan)
    }

    async fn get_plan(&self, _plan_id: &str) -> LedgerResult<Option<BackfillPlan>> {
        // In a full implementation, plans would be stored separately
        Ok(None)
    }

    async fn execute_plan(&self, plan_id: &str) -> LedgerResult<BackfillReceipt> {
        // In a full implementation, this would:
        // 1. Get the plan
        // 2. Process each item in the anchor sequence
        // 3. Generate receipts for each batch
        // 4. Create the final backfill receipt

        let receipt_id = self.generate_id("backfill_receipt");
        let now = Utc::now();

        let receipt = BackfillReceipt {
            backfill_receipt_id: receipt_id.clone(),
            request_ref: "req:placeholder".to_string(),
            plan_ref: plan_id.to_string(),
            actor_id: ActorId::new("actor:placeholder"),
            objects_anchored: 0,
            anchored_objects_digest: Digest::zero(),
            gaps_acknowledged_digest: None,
            total_fee_paid: "0".to_string(),
            continuity_result: ContinuityCheckResult::Pass,
            started_at: now,
            completed_at: now,
            receipt_id: ReceiptId(receipt_id),
        };

        Ok(receipt)
    }

    async fn get_receipt(&self, _receipt_id: &str) -> LedgerResult<Option<BackfillReceipt>> {
        // In a full implementation, receipts would be stored and retrieved
        Ok(None)
    }

    async fn cancel_request(&self, request_id: &str, _reason: String) -> LedgerResult<()> {
        self.update_request_status(request_id, BackfillStatus::Cancelled)
            .await
    }

    async fn detect_gaps(
        &self,
        _actor_id: &ActorId,
        start_sequence: u64,
        end_sequence: u64,
    ) -> LedgerResult<Vec<GapRecord>> {
        // In a full implementation, this would analyze the actor's commitment chain
        // and identify any missing sequences or hash chain breaks.

        let mut gaps = Vec::new();

        // Simulate gap detection (placeholder logic)
        if end_sequence - start_sequence > 1000 {
            gaps.push(GapRecord {
                gap_id: format!("gap:{}:{}", start_sequence, end_sequence),
                start_sequence,
                end_sequence,
                gap_type: GapType::SequenceGap,
                acceptable: true,
                reason_digest: None,
            });
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
        _actor_id: &ActorId,
        _limit: u32,
    ) -> LedgerResult<Vec<BackfillReceipt>> {
        // In a full implementation, this would retrieve historical backfill receipts
        Ok(vec![])
    }
}
