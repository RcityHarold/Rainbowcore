//! Dispute-Resolution Ledger Service Implementation
//!
//! Implements the DisputeLedger trait for managing disputes,
//! verdicts, repairs, and clawbacks.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use l0_core::crypto::IncrementalMerkleTree;
use l0_core::error::LedgerError;
use l0_core::ledger::{DisputeLedger, Ledger, LedgerResult, QueryOptions};
use l0_core::types::{
    ActorId, AppealOutcome, AppealRecord, AppealStatus, ClawbackRecord, ClawbackStatus, ClawbackType,
    Digest, DisputePriority, DisputeRecord, DisputeStatus, DisputeType, ReceiptId, RepairCheckpoint,
    RepairCheckpointType, VerdictRecord, VerdictType,
};
use soulbase_storage::model::Entity;
use soulbase_storage::surreal::SurrealDatastore;
use soulbase_storage::Datastore;
use soulbase_types::prelude::TenantId;
use std::collections::HashSet;
use std::sync::Arc;

use crate::entities::{AppealEntity, ClawbackEntity, DisputeEntity, RepairCheckpointEntity, VerdictEntity};
use crate::validation::{validate_not_space, validate_parties_not_space};

/// Dispute-Resolution Ledger Service
pub struct DisputeService {
    datastore: Arc<SurrealDatastore>,
    tenant_id: TenantId,
    sequence: std::sync::atomic::AtomicU64,
}

impl DisputeService {
    /// Create a new Dispute Service
    pub fn new(datastore: Arc<SurrealDatastore>, tenant_id: TenantId) -> Self {
        Self {
            datastore,
            tenant_id,
            sequence: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Create a new Dispute Service with persistent sequence
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
            DisputeEntity::TABLE
        );

        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let result: Option<DisputeEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        if let Some(dispute) = result {
            if let Some(seq) = crate::sequence::extract_sequence_from_id(&dispute.dispute_id) {
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

    /// Convert DisputePriority to string
    fn priority_to_str(p: DisputePriority) -> &'static str {
        match p {
            DisputePriority::Normal => "normal",
            DisputePriority::Urgent => "urgent",
            DisputePriority::Critical => "critical",
        }
    }

    /// Convert string to DisputePriority with validation
    fn str_to_priority(s: &str) -> LedgerResult<DisputePriority> {
        match s {
            "normal" => Ok(DisputePriority::Normal),
            "urgent" => Ok(DisputePriority::Urgent),
            "critical" => Ok(DisputePriority::Critical),
            other => Err(LedgerError::Validation(format!(
                "Invalid dispute priority: '{}'. Expected one of: normal, urgent, critical",
                other
            ))),
        }
    }

    /// Convert DisputeStatus to string
    fn status_to_str(s: DisputeStatus) -> &'static str {
        match s {
            DisputeStatus::Filed => "filed",
            DisputeStatus::UnderReview => "under_review",
            DisputeStatus::VerdictIssued => "verdict_issued",
            DisputeStatus::RepairInProgress => "repair_in_progress",
            DisputeStatus::Resolved => "resolved",
            DisputeStatus::Dismissed => "dismissed",
        }
    }

    /// Convert string to DisputeStatus with validation
    fn str_to_status(s: &str) -> LedgerResult<DisputeStatus> {
        match s {
            "filed" => Ok(DisputeStatus::Filed),
            "under_review" => Ok(DisputeStatus::UnderReview),
            "verdict_issued" => Ok(DisputeStatus::VerdictIssued),
            "repair_in_progress" => Ok(DisputeStatus::RepairInProgress),
            "resolved" => Ok(DisputeStatus::Resolved),
            "dismissed" => Ok(DisputeStatus::Dismissed),
            other => Err(LedgerError::Validation(format!(
                "Invalid dispute status: '{}'. Expected one of: filed, under_review, verdict_issued, repair_in_progress, resolved, dismissed",
                other
            ))),
        }
    }

    /// Convert VerdictType to string
    fn verdict_type_to_str(t: VerdictType) -> &'static str {
        match t {
            VerdictType::InFavor => "in_favor",
            VerdictType::Against => "against",
            VerdictType::Mixed => "mixed",
            VerdictType::Dismissed => "dismissed",
            VerdictType::Inconclusive => "inconclusive",
        }
    }

    /// Convert string to VerdictType with validation
    fn str_to_verdict_type(s: &str) -> LedgerResult<VerdictType> {
        match s {
            "in_favor" => Ok(VerdictType::InFavor),
            "against" => Ok(VerdictType::Against),
            "mixed" => Ok(VerdictType::Mixed),
            "dismissed" => Ok(VerdictType::Dismissed),
            "inconclusive" => Ok(VerdictType::Inconclusive),
            other => Err(LedgerError::Validation(format!(
                "Invalid verdict type: '{}'. Expected one of: in_favor, against, mixed, dismissed, inconclusive",
                other
            ))),
        }
    }

    /// Convert ClawbackType to string
    fn clawback_type_to_str(t: ClawbackType) -> &'static str {
        match t {
            ClawbackType::FullReverse => "full_reverse",
            ClawbackType::PartialReverse => "partial_reverse",
            ClawbackType::Compensation => "compensation",
            ClawbackType::Penalty => "penalty",
        }
    }

    /// Convert string to ClawbackType with validation
    fn str_to_clawback_type(s: &str) -> LedgerResult<ClawbackType> {
        match s {
            "full_reverse" => Ok(ClawbackType::FullReverse),
            "partial_reverse" => Ok(ClawbackType::PartialReverse),
            "compensation" => Ok(ClawbackType::Compensation),
            "penalty" => Ok(ClawbackType::Penalty),
            other => Err(LedgerError::Validation(format!(
                "Invalid clawback type: '{}'. Expected one of: full_reverse, partial_reverse, compensation, penalty",
                other
            ))),
        }
    }

    /// Convert ClawbackStatus to string
    fn clawback_status_to_str(s: ClawbackStatus) -> &'static str {
        match s {
            ClawbackStatus::Pending => "pending",
            ClawbackStatus::Approved => "approved",
            ClawbackStatus::Executed => "executed",
            ClawbackStatus::Failed => "failed",
            ClawbackStatus::Cancelled => "cancelled",
        }
    }

    /// Convert string to ClawbackStatus with validation
    fn str_to_clawback_status(s: &str) -> LedgerResult<ClawbackStatus> {
        match s {
            "pending" => Ok(ClawbackStatus::Pending),
            "approved" => Ok(ClawbackStatus::Approved),
            "executed" => Ok(ClawbackStatus::Executed),
            "failed" => Ok(ClawbackStatus::Failed),
            "cancelled" => Ok(ClawbackStatus::Cancelled),
            other => Err(LedgerError::Validation(format!(
                "Invalid clawback status: '{}'. Expected one of: pending, approved, executed, failed, cancelled",
                other
            ))),
        }
    }

    /// Convert string to AppealStatus with validation
    fn str_to_appeal_status(s: &str) -> LedgerResult<AppealStatus> {
        match s {
            "pending" => Ok(AppealStatus::Pending),
            "under_review" => Ok(AppealStatus::UnderReview),
            "accepted" => Ok(AppealStatus::Accepted),
            "rejected" => Ok(AppealStatus::Rejected),
            "dismissed" => Ok(AppealStatus::Dismissed),
            "expired" => Ok(AppealStatus::Expired),
            // Map legacy DisputeStatus values to closest AppealStatus
            "filed" => Ok(AppealStatus::Pending),
            "verdict_issued" | "resolved" => Ok(AppealStatus::Accepted),
            other => Err(LedgerError::Validation(format!(
                "Invalid appeal status: '{}'. Expected one of: pending, under_review, accepted, rejected, dismissed, expired",
                other
            ))),
        }
    }

    /// Parse Digest from hex string with proper error handling
    fn parse_digest(hex_str: &str, field_name: &str) -> LedgerResult<Digest> {
        Digest::from_hex(hex_str).map_err(|e| {
            LedgerError::Validation(format!(
                "Invalid {} digest '{}': {}",
                field_name, hex_str, e
            ))
        })
    }

    /// Convert entity to DisputeRecord with validation
    fn entity_to_dispute(entity: &DisputeEntity) -> LedgerResult<DisputeRecord> {
        let priority = Self::str_to_priority(&entity.priority)?;
        let status = Self::str_to_status(&entity.status)?;
        let evidence_digest = Self::parse_digest(&entity.evidence_digest, "evidence")?;

        Ok(DisputeRecord {
            dispute_id: entity.dispute_id.clone(),
            filed_by: ActorId(entity.filed_by.clone()),
            filed_against: entity.filed_against.iter().map(|s| ActorId(s.clone())).collect(),
            dispute_type: DisputeType::Other, // Default for legacy records
            priority,
            status,
            subject_commitment_ref: entity.subject_commitment_ref.clone(),
            evidence_digest,
            reason_digest: None, // Not stored in legacy entity
            filed_at: entity.filed_at,
            last_updated: entity.last_updated,
            receipt_id: entity.receipt_id.as_ref().map(|r| ReceiptId(r.clone())),
        })
    }

    /// Convert entity to VerdictRecord with validation
    fn entity_to_verdict(entity: &VerdictEntity) -> LedgerResult<VerdictRecord> {
        let verdict_type = Self::str_to_verdict_type(&entity.verdict_type)?;
        let verdict_digest = Self::parse_digest(&entity.verdict_digest, "verdict")?;
        let rationale_digest = Self::parse_digest(&entity.rationale_digest, "rationale")?;

        let remedies_digest = match &entity.remedies_digest {
            Some(d) => Some(Self::parse_digest(d, "remedies")?),
            None => None,
        };

        Ok(VerdictRecord {
            verdict_id: entity.verdict_id.clone(),
            dispute_id: entity.dispute_id.clone(),
            verdict_type,
            verdict_digest,
            rationale_digest,
            remedies_digest,
            responsibility_shares_digest: None, // Not stored in legacy entity
            violation_findings_digest: None,    // Not stored in legacy entity
            sanctions_digest: None,             // Not stored in legacy entity
            issued_by: entity.issued_by.clone(),
            issued_at: entity.issued_at,
            effective_at: entity.effective_at,
            appeal_deadline: entity.appeal_deadline,
            receipt_id: entity.receipt_id.as_ref().map(|r| ReceiptId(r.clone())),
        })
    }

    /// Convert entity to ClawbackRecord with validation
    fn entity_to_clawback(entity: &ClawbackEntity) -> LedgerResult<ClawbackRecord> {
        let clawback_type = Self::str_to_clawback_type(&entity.clawback_type)?;
        let status = Self::str_to_clawback_status(&entity.status)?;
        let clawback_digest = Self::parse_digest(&entity.clawback_digest, "clawback")?;

        let compensation_digest = match &entity.compensation_digest {
            Some(d) => Some(Self::parse_digest(d, "compensation")?),
            None => None,
        };

        Ok(ClawbackRecord {
            clawback_id: entity.clawback_id.clone(),
            verdict_id: entity.verdict_id.clone(),
            clawback_type,
            status,
            clawback_digest,
            target_commitment_refs: entity.target_commitment_refs.clone(),
            affected_actors: entity.affected_actors.iter().map(|s| ActorId(s.clone())).collect(),
            compensation_digest,
            initiated_at: entity.initiated_at,
            executed_at: entity.executed_at,
            receipt_id: entity.receipt_id.as_ref().map(|r| ReceiptId(r.clone())),
        })
    }

    /// Convert entity to RepairCheckpoint with validation
    fn entity_to_checkpoint(entity: &RepairCheckpointEntity) -> LedgerResult<RepairCheckpoint> {
        let checkpoint_digest = Self::parse_digest(&entity.checkpoint_digest, "checkpoint")?;
        let repair_plan_digest = Self::parse_digest(&entity.repair_plan_digest, "repair_plan")?;

        Ok(RepairCheckpoint {
            checkpoint_id: entity.checkpoint_id.clone(),
            dispute_id: entity.dispute_id.clone(),
            verdict_id: entity.verdict_id.clone(),
            checkpoint_type: RepairCheckpointType::InRepairStart, // Default for legacy records
            checkpoint_digest,
            affected_actors: entity.affected_actors.iter().map(|s| ActorId(s.clone())).collect(),
            repair_plan_digest,
            expected_outcome_digest: None, // Not stored in legacy entity
            current_status_digest: None,   // Not stored in legacy entity
            progress_percent: entity.progress_percent,
            created_at: entity.created_at,
            completed_at: entity.completed_at,
            receipt_id: entity.receipt_id.as_ref().map(|r| ReceiptId(r.clone())),
        })
    }

    /// Convert entity to AppealRecord with validation
    fn entity_to_appeal(entity: &AppealEntity) -> LedgerResult<AppealRecord> {
        let grounds_digest = Self::parse_digest(&entity.grounds_digest, "grounds")?;
        let status = Self::str_to_appeal_status(&entity.status)?;

        let new_evidence_digest = match &entity.new_evidence_digest {
            Some(d) => Some(Self::parse_digest(d, "new_evidence")?),
            None => None,
        };

        Ok(AppealRecord {
            appeal_id: entity.appeal_id.clone(),
            verdict_id: entity.verdict_id.clone(),
            filed_by: ActorId(entity.filed_by.clone()),
            grounds_digest,
            new_evidence_digest,
            filed_at: entity.filed_at,
            status,
            appeal_outcome: None,              // Not stored in legacy entity
            appellate_decision_digest: None,   // Not stored in legacy entity
            receipt_id: entity.receipt_id.as_ref().map(|r| ReceiptId(r.clone())),
        })
    }
}

#[async_trait]
impl Ledger for DisputeService {
    fn name(&self) -> &'static str {
        "dispute"
    }

    async fn current_sequence(&self) -> LedgerResult<u64> {
        Ok(self.sequence.load(std::sync::atomic::Ordering::SeqCst))
    }

    async fn current_root(&self) -> LedgerResult<Digest> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        // Query all disputes
        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant ORDER BY created_at ASC",
            DisputeEntity::TABLE
        );
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;
        let disputes: Vec<DisputeEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        // Query all verdicts
        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant ORDER BY created_at ASC",
            VerdictEntity::TABLE
        );
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;
        let verdicts: Vec<VerdictEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        // Query all clawbacks
        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant ORDER BY created_at ASC",
            ClawbackEntity::TABLE
        );
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;
        let clawbacks: Vec<ClawbackEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        // Query all appeals
        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant ORDER BY created_at ASC",
            AppealEntity::TABLE
        );
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;
        let appeals: Vec<AppealEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        if disputes.is_empty() && verdicts.is_empty() && clawbacks.is_empty() && appeals.is_empty() {
            return Ok(Digest::zero());
        }

        let mut tree = IncrementalMerkleTree::new();

        // Add disputes to tree
        for dispute in &disputes {
            let data = format!(
                "dispute:{}:{}:{}:{}:{}",
                dispute.dispute_id,
                dispute.filed_by,
                dispute.status,
                dispute.priority,
                dispute.evidence_digest
            );
            tree.add(Digest::blake3(data.as_bytes()));
        }

        // Add verdicts to tree
        for verdict in &verdicts {
            let data = format!(
                "verdict:{}:{}:{}:{}",
                verdict.verdict_id,
                verdict.dispute_id,
                verdict.verdict_type,
                verdict.verdict_digest
            );
            tree.add(Digest::blake3(data.as_bytes()));
        }

        // Add clawbacks to tree
        for clawback in &clawbacks {
            let data = format!(
                "clawback:{}:{}:{}:{}",
                clawback.clawback_id,
                clawback.verdict_id,
                clawback.clawback_type,
                clawback.status
            );
            tree.add(Digest::blake3(data.as_bytes()));
        }

        // Add appeals to tree
        for appeal in &appeals {
            let data = format!(
                "appeal:{}:{}:{}:{}",
                appeal.appeal_id,
                appeal.verdict_id,
                appeal.filed_by,
                appeal.grounds_digest
            );
            tree.add(Digest::blake3(data.as_bytes()));
        }

        Ok(tree.root())
    }

    async fn verify_integrity(&self) -> LedgerResult<bool> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        // Verify disputes
        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant",
            DisputeEntity::TABLE
        );
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;
        let disputes: Vec<DisputeEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        let mut seen_dispute_ids = HashSet::new();
        for dispute in &disputes {
            // Check for duplicate dispute_ids
            if !seen_dispute_ids.insert(&dispute.dispute_id) {
                return Ok(false);
            }
            // Check required fields
            if dispute.dispute_id.is_empty() || dispute.filed_by.is_empty() {
                return Ok(false);
            }
            // Validate status
            if Self::str_to_status(&dispute.status).is_err() {
                return Ok(false);
            }
            // Validate priority
            if Self::str_to_priority(&dispute.priority).is_err() {
                return Ok(false);
            }
        }

        // Verify verdicts
        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant",
            VerdictEntity::TABLE
        );
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;
        let verdicts: Vec<VerdictEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        let mut seen_verdict_ids = HashSet::new();
        for verdict in &verdicts {
            // Check for duplicate verdict_ids
            if !seen_verdict_ids.insert(&verdict.verdict_id) {
                return Ok(false);
            }
            // Check required fields
            if verdict.verdict_id.is_empty() || verdict.dispute_id.is_empty() {
                return Ok(false);
            }
            // Validate verdict_type
            if Self::str_to_verdict_type(&verdict.verdict_type).is_err() {
                return Ok(false);
            }
            // Verify verdict references existing dispute
            if !seen_dispute_ids.contains(&verdict.dispute_id) {
                // Dispute might have been filed before we started tracking
                // Just log but don't fail integrity check
            }
        }

        // Verify clawbacks
        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant",
            ClawbackEntity::TABLE
        );
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;
        let clawbacks: Vec<ClawbackEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        let mut seen_clawback_ids = HashSet::new();
        for clawback in &clawbacks {
            // Check for duplicate clawback_ids
            if !seen_clawback_ids.insert(&clawback.clawback_id) {
                return Ok(false);
            }
            // Check required fields
            if clawback.clawback_id.is_empty() || clawback.verdict_id.is_empty() {
                return Ok(false);
            }
            // Validate clawback_type
            if Self::str_to_clawback_type(&clawback.clawback_type).is_err() {
                return Ok(false);
            }
            // Validate status
            if Self::str_to_clawback_status(&clawback.status).is_err() {
                return Ok(false);
            }
        }

        // Verify appeals
        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant",
            AppealEntity::TABLE
        );
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;
        let appeals: Vec<AppealEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        let mut seen_appeal_ids = HashSet::new();
        for appeal in &appeals {
            // Check for duplicate appeal_ids
            if !seen_appeal_ids.insert(&appeal.appeal_id) {
                return Ok(false);
            }
            // Check required fields
            if appeal.appeal_id.is_empty() || appeal.verdict_id.is_empty() || appeal.filed_by.is_empty() {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

#[async_trait]
impl DisputeLedger for DisputeService {
    async fn file_dispute(
        &self,
        filed_by: &ActorId,
        filed_against: Vec<ActorId>,
        priority: DisputePriority,
        subject_commitment_ref: String,
        evidence_digest: Digest,
    ) -> LedgerResult<DisputeRecord> {
        // Validate: Space cannot file disputes or be filed against
        validate_not_space(&filed_by.0, "filed_by").map_err(|e| {
            LedgerError::Validation(e.to_string())
        })?;
        let filed_against_strs: Vec<String> = filed_against.iter().map(|a| a.0.clone()).collect();
        validate_parties_not_space(&filed_against_strs, "filed_against").map_err(|e| {
            LedgerError::Validation(e.to_string())
        })?;

        let dispute_id = self.generate_id("dispute");
        let now = Utc::now();

        let entity = DisputeEntity {
            id: format!("l0_dispute:{}:{}", self.tenant_id.0, dispute_id),
            tenant_id: self.tenant_id.clone(),
            dispute_id: dispute_id.clone(),
            filed_by: filed_by.0.clone(),
            filed_against: filed_against.iter().map(|a| a.0.clone()).collect(),
            priority: Self::priority_to_str(priority).to_string(),
            status: "filed".to_string(),
            subject_commitment_ref,
            evidence_digest: evidence_digest.to_hex(),
            filed_at: now,
            last_updated: now,
            receipt_id: None,
        };

        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!("CREATE {} CONTENT $data RETURN AFTER", DisputeEntity::TABLE);

        let mut response = session
            .client()
            .query(&query)
            .bind(("data", entity))
            .await
            .map_err(|e| LedgerError::Storage(format!("Create failed: {}", e)))?;

        let result: Option<DisputeEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        let created = result.ok_or_else(|| LedgerError::Storage("Create returned no result".to_string()))?;
        Self::entity_to_dispute(&created)
    }

    async fn get_dispute(&self, dispute_id: &str) -> LedgerResult<Option<DisputeRecord>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND dispute_id = $dispute_id LIMIT 1",
            DisputeEntity::TABLE
        );

        let dispute_id_owned = dispute_id.to_string();
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("dispute_id", dispute_id_owned))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let result: Option<DisputeEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        match result {
            Some(e) => Ok(Some(Self::entity_to_dispute(&e)?)),
            None => Ok(None),
        }
    }

    async fn update_dispute_status(
        &self,
        dispute_id: &str,
        new_status: DisputeStatus,
    ) -> LedgerResult<ReceiptId> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "UPDATE {} SET status = $status, last_updated = $now WHERE tenant_id = $tenant AND dispute_id = $dispute_id",
            DisputeEntity::TABLE
        );

        let dispute_id_owned = dispute_id.to_string();
        session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("dispute_id", dispute_id_owned))
            .bind(("status", Self::status_to_str(new_status)))
            .bind(("now", Utc::now()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Update failed: {}", e)))?;

        Ok(ReceiptId(format!("receipt:dispute_status:{}", dispute_id)))
    }

    async fn list_disputes(
        &self,
        status: Option<DisputeStatus>,
        priority: Option<DisputePriority>,
        options: QueryOptions,
    ) -> LedgerResult<Vec<DisputeRecord>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let mut where_clauses = vec!["tenant_id = $tenant".to_string()];
        if let Some(s) = status {
            where_clauses.push(format!("status = '{}'", Self::status_to_str(s)));
        }
        if let Some(p) = priority {
            where_clauses.push(format!("priority = '{}'", Self::priority_to_str(p)));
        }

        let limit = options.limit.unwrap_or(100);

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE {} ORDER BY filed_at DESC LIMIT {}",
            DisputeEntity::TABLE,
            where_clauses.join(" AND "),
            limit
        );

        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let results: Vec<DisputeEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        results.iter().map(Self::entity_to_dispute).collect()
    }

    async fn list_disputes_for_actor(
        &self,
        actor_id: &ActorId,
        as_filer: bool,
        options: QueryOptions,
    ) -> LedgerResult<Vec<DisputeRecord>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let field = if as_filer { "filed_by" } else { "filed_against" };
        let limit = options.limit.unwrap_or(100);

        let actor_id_owned = actor_id.0.clone();
        let query = if as_filer {
            format!(
                "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND {} = $actor ORDER BY filed_at DESC LIMIT {}",
                DisputeEntity::TABLE,
                field,
                limit
            )
        } else {
            format!(
                "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND $actor IN {} ORDER BY filed_at DESC LIMIT {}",
                DisputeEntity::TABLE,
                field,
                limit
            )
        };

        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("actor", actor_id_owned))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let results: Vec<DisputeEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        results.iter().map(Self::entity_to_dispute).collect()
    }

    async fn issue_verdict(
        &self,
        dispute_id: &str,
        verdict_type: VerdictType,
        verdict_digest: Digest,
        rationale_digest: Digest,
        remedies_digest: Option<Digest>,
        issued_by: String,
        appeal_deadline: Option<DateTime<Utc>>,
    ) -> LedgerResult<VerdictRecord> {
        let verdict_id = self.generate_id("verdict");
        let now = Utc::now();

        let entity = VerdictEntity {
            id: format!("l0_verdict:{}:{}", self.tenant_id.0, verdict_id),
            tenant_id: self.tenant_id.clone(),
            verdict_id: verdict_id.clone(),
            dispute_id: dispute_id.to_string(),
            verdict_type: Self::verdict_type_to_str(verdict_type).to_string(),
            verdict_digest: verdict_digest.to_hex(),
            rationale_digest: rationale_digest.to_hex(),
            remedies_digest: remedies_digest.map(|d| d.to_hex()),
            issued_by,
            issued_at: now,
            effective_at: now,
            appeal_deadline,
            receipt_id: None,
        };

        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!("CREATE {} CONTENT $data RETURN AFTER", VerdictEntity::TABLE);

        let mut response = session
            .client()
            .query(&query)
            .bind(("data", entity))
            .await
            .map_err(|e| LedgerError::Storage(format!("Create failed: {}", e)))?;

        let result: Option<VerdictEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        let created = result.ok_or_else(|| LedgerError::Storage("Create returned no result".to_string()))?;

        // Update dispute status
        self.update_dispute_status(dispute_id, DisputeStatus::VerdictIssued).await?;

        Self::entity_to_verdict(&created)
    }

    async fn get_verdict(&self, verdict_id: &str) -> LedgerResult<Option<VerdictRecord>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND verdict_id = $verdict_id LIMIT 1",
            VerdictEntity::TABLE
        );

        let verdict_id_owned = verdict_id.to_string();
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("verdict_id", verdict_id_owned))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let result: Option<VerdictEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        match result {
            Some(e) => Ok(Some(Self::entity_to_verdict(&e)?)),
            None => Ok(None),
        }
    }

    async fn get_verdict_for_dispute(&self, dispute_id: &str) -> LedgerResult<Option<VerdictRecord>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND dispute_id = $dispute_id LIMIT 1",
            VerdictEntity::TABLE
        );

        let dispute_id_owned = dispute_id.to_string();
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("dispute_id", dispute_id_owned))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let result: Option<VerdictEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        match result {
            Some(e) => Ok(Some(Self::entity_to_verdict(&e)?)),
            None => Ok(None),
        }
    }

    async fn create_repair_checkpoint(
        &self,
        dispute_id: &str,
        verdict_id: &str,
        affected_actors: Vec<ActorId>,
        repair_plan_digest: Digest,
    ) -> LedgerResult<RepairCheckpoint> {
        let checkpoint_id = self.generate_id("repair");
        let now = Utc::now();

        let entity = RepairCheckpointEntity {
            id: format!("l0_repair_checkpoint:{}:{}", self.tenant_id.0, checkpoint_id),
            tenant_id: self.tenant_id.clone(),
            checkpoint_id: checkpoint_id.clone(),
            dispute_id: dispute_id.to_string(),
            verdict_id: verdict_id.to_string(),
            checkpoint_digest: Digest::zero().to_hex(),
            affected_actors: affected_actors.iter().map(|a| a.0.clone()).collect(),
            repair_plan_digest: repair_plan_digest.to_hex(),
            progress_percent: 0,
            created_at: now,
            completed_at: None,
            receipt_id: None,
        };

        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!("CREATE {} CONTENT $data RETURN AFTER", RepairCheckpointEntity::TABLE);

        let mut response = session
            .client()
            .query(&query)
            .bind(("data", entity))
            .await
            .map_err(|e| LedgerError::Storage(format!("Create failed: {}", e)))?;

        let result: Option<RepairCheckpointEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        let created = result.ok_or_else(|| LedgerError::Storage("Create returned no result".to_string()))?;

        // Update dispute status
        self.update_dispute_status(dispute_id, DisputeStatus::RepairInProgress).await?;

        Self::entity_to_checkpoint(&created)
    }

    async fn update_repair_progress(
        &self,
        checkpoint_id: &str,
        progress_percent: u8,
        checkpoint_digest: Digest,
    ) -> LedgerResult<ReceiptId> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "UPDATE {} SET progress_percent = $progress, checkpoint_digest = $digest WHERE tenant_id = $tenant AND checkpoint_id = $checkpoint_id",
            RepairCheckpointEntity::TABLE
        );

        let checkpoint_id_owned = checkpoint_id.to_string();
        session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("checkpoint_id", checkpoint_id_owned))
            .bind(("progress", progress_percent))
            .bind(("digest", checkpoint_digest.to_hex()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Update failed: {}", e)))?;

        Ok(ReceiptId(format!("receipt:repair_progress:{}", checkpoint_id)))
    }

    async fn complete_repair(&self, checkpoint_id: &str, final_digest: Digest) -> LedgerResult<ReceiptId> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "UPDATE {} SET progress_percent = 100, checkpoint_digest = $digest, completed_at = $now WHERE tenant_id = $tenant AND checkpoint_id = $checkpoint_id",
            RepairCheckpointEntity::TABLE
        );

        let checkpoint_id_owned = checkpoint_id.to_string();
        session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("checkpoint_id", checkpoint_id_owned))
            .bind(("digest", final_digest.to_hex()))
            .bind(("now", Utc::now()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Update failed: {}", e)))?;

        Ok(ReceiptId(format!("receipt:repair_complete:{}", checkpoint_id)))
    }

    async fn get_repair_checkpoint(&self, checkpoint_id: &str) -> LedgerResult<Option<RepairCheckpoint>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND checkpoint_id = $checkpoint_id LIMIT 1",
            RepairCheckpointEntity::TABLE
        );

        let checkpoint_id_owned = checkpoint_id.to_string();
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("checkpoint_id", checkpoint_id_owned))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let result: Option<RepairCheckpointEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        match result {
            Some(e) => Ok(Some(Self::entity_to_checkpoint(&e)?)),
            None => Ok(None),
        }
    }

    async fn initiate_clawback(
        &self,
        verdict_id: &str,
        clawback_type: ClawbackType,
        target_commitment_refs: Vec<String>,
        affected_actors: Vec<ActorId>,
        compensation_digest: Option<Digest>,
    ) -> LedgerResult<ClawbackRecord> {
        let clawback_id = self.generate_id("clawback");
        let now = Utc::now();

        // Compute clawback digest
        let mut digest_input = Vec::new();
        digest_input.extend_from_slice(clawback_id.as_bytes());
        digest_input.extend_from_slice(verdict_id.as_bytes());
        for r in &target_commitment_refs {
            digest_input.extend_from_slice(r.as_bytes());
        }
        let clawback_digest = Digest::blake3(&digest_input);

        let entity = ClawbackEntity {
            id: format!("l0_clawback:{}:{}", self.tenant_id.0, clawback_id),
            tenant_id: self.tenant_id.clone(),
            clawback_id: clawback_id.clone(),
            verdict_id: verdict_id.to_string(),
            clawback_type: Self::clawback_type_to_str(clawback_type).to_string(),
            status: "pending".to_string(),
            clawback_digest: clawback_digest.to_hex(),
            target_commitment_refs,
            affected_actors: affected_actors.iter().map(|a| a.0.clone()).collect(),
            compensation_digest: compensation_digest.map(|d| d.to_hex()),
            initiated_at: now,
            executed_at: None,
            receipt_id: None,
        };

        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!("CREATE {} CONTENT $data RETURN AFTER", ClawbackEntity::TABLE);

        let mut response = session
            .client()
            .query(&query)
            .bind(("data", entity))
            .await
            .map_err(|e| LedgerError::Storage(format!("Create failed: {}", e)))?;

        let result: Option<ClawbackEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        let created = result.ok_or_else(|| LedgerError::Storage("Create returned no result".to_string()))?;
        Self::entity_to_clawback(&created)
    }

    async fn execute_clawback(&self, clawback_id: &str, execution_digest: Digest) -> LedgerResult<ReceiptId> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "UPDATE {} SET status = 'executed', executed_at = $now, clawback_digest = $digest WHERE tenant_id = $tenant AND clawback_id = $clawback_id",
            ClawbackEntity::TABLE
        );

        let clawback_id_owned = clawback_id.to_string();
        session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("clawback_id", clawback_id_owned))
            .bind(("now", Utc::now()))
            .bind(("digest", execution_digest.to_hex()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Update failed: {}", e)))?;

        Ok(ReceiptId(format!("receipt:clawback_execute:{}", clawback_id)))
    }

    async fn update_clawback_status(&self, clawback_id: &str, new_status: ClawbackStatus) -> LedgerResult<ReceiptId> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "UPDATE {} SET status = $status WHERE tenant_id = $tenant AND clawback_id = $clawback_id",
            ClawbackEntity::TABLE
        );

        let clawback_id_owned = clawback_id.to_string();
        session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("clawback_id", clawback_id_owned))
            .bind(("status", Self::clawback_status_to_str(new_status)))
            .await
            .map_err(|e| LedgerError::Storage(format!("Update failed: {}", e)))?;

        Ok(ReceiptId(format!("receipt:clawback_status:{}", clawback_id)))
    }

    async fn get_clawback(&self, clawback_id: &str) -> LedgerResult<Option<ClawbackRecord>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND clawback_id = $clawback_id LIMIT 1",
            ClawbackEntity::TABLE
        );

        let clawback_id_owned = clawback_id.to_string();
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("clawback_id", clawback_id_owned))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let result: Option<ClawbackEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        match result {
            Some(e) => Ok(Some(Self::entity_to_clawback(&e)?)),
            None => Ok(None),
        }
    }

    async fn list_clawbacks(&self, status: Option<ClawbackStatus>, options: QueryOptions) -> LedgerResult<Vec<ClawbackRecord>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let status_clause = status
            .map(|s| format!("AND status = '{}'", Self::clawback_status_to_str(s)))
            .unwrap_or_default();

        let limit = options.limit.unwrap_or(100);

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant {} ORDER BY initiated_at DESC LIMIT {}",
            ClawbackEntity::TABLE,
            status_clause,
            limit
        );

        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let results: Vec<ClawbackEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        results.iter().map(Self::entity_to_clawback).collect()
    }

    async fn file_appeal(
        &self,
        verdict_id: &str,
        filed_by: &ActorId,
        grounds_digest: Digest,
        new_evidence_digest: Option<Digest>,
    ) -> LedgerResult<AppealRecord> {
        // First verify the verdict exists
        let verdict = self.get_verdict(verdict_id).await?;
        if verdict.is_none() {
            return Err(LedgerError::NotFound(format!("Verdict {} not found", verdict_id)));
        }

        // Check if appeal deadline has passed
        if let Some(v) = verdict {
            if let Some(deadline) = v.appeal_deadline {
                if Utc::now() > deadline {
                    return Err(LedgerError::Validation("Appeal deadline has passed".to_string()));
                }
            }
        }

        // Check if an appeal already exists for this verdict
        let existing = self.get_appeal_for_verdict(verdict_id).await?;
        if existing.is_some() {
            return Err(LedgerError::Validation("An appeal already exists for this verdict".to_string()));
        }

        let appeal_id = self.generate_id("appeal");
        let now = Utc::now();

        let entity = AppealEntity {
            id: format!("l0_appeal:{}:{}", self.tenant_id.0, appeal_id),
            tenant_id: self.tenant_id.clone(),
            appeal_id: appeal_id.clone(),
            verdict_id: verdict_id.to_string(),
            filed_by: filed_by.0.clone(),
            grounds_digest: grounds_digest.to_hex(),
            new_evidence_digest: new_evidence_digest.map(|d| d.to_hex()),
            filed_at: now,
            status: "filed".to_string(),
            receipt_id: None,
        };

        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!("CREATE {} CONTENT $data RETURN AFTER", AppealEntity::TABLE);

        let mut response = session
            .client()
            .query(&query)
            .bind(("data", entity))
            .await
            .map_err(|e| LedgerError::Storage(format!("Create failed: {}", e)))?;

        let result: Option<AppealEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        let created = result.ok_or_else(|| LedgerError::Storage("Create returned no result".to_string()))?;
        Self::entity_to_appeal(&created)
    }

    async fn get_appeal_for_verdict(&self, verdict_id: &str) -> LedgerResult<Option<AppealRecord>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND verdict_id = $verdict_id LIMIT 1",
            AppealEntity::TABLE
        );

        let verdict_id_owned = verdict_id.to_string();
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("verdict_id", verdict_id_owned))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let result: Option<AppealEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        match result {
            Some(e) => Ok(Some(Self::entity_to_appeal(&e)?)),
            None => Ok(None),
        }
    }
}
