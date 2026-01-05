//! Guardian Consent and Human Consent Protocol Service
//!
//! Manages GCR (Guardian Consent Receipt) and HCP (Human Consent Protocol) workflows.

use async_trait::async_trait;
use chrono::{Duration, Utc};
use l0_core::error::LedgerError;
use l0_core::ledger::LedgerResult;
use l0_core::types::{
    ActorId, Digest, EmergencyJustificationType, EmergencyOverrideWorkflow,
    GcrStatus, GuardianApproval, GuardianConsentReceipt, GuardianType,
    HcpApprovalLevel, HcpRequest, HcpStatus, HumanApproval, HumanRejection,
    OverrideAuditEntry, OverrideStage, VerificationMethod,
};
use soulbase_storage::surreal::SurrealDatastore;
use soulbase_storage::Datastore;
use soulbase_types::prelude::TenantId;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Guardian Consent Ledger trait
#[async_trait]
pub trait GuardianConsentLedger: Send + Sync {
    /// Create a new GCR request
    async fn create_gcr(
        &self,
        ward_id: &ActorId,
        guardian_id: &ActorId,
        guardian_type: GuardianType,
        guardianship_proof_digest: &Digest,
        consent_scope_digest: &Digest,
        justification: &str,
        justification_type: EmergencyJustificationType,
    ) -> LedgerResult<GuardianConsentReceipt>;

    /// Approve a GCR (by additional guardian if multi-guardian)
    async fn approve_gcr(
        &self,
        gcr_id: &str,
        guardian_id: &ActorId,
        guardian_type: GuardianType,
        signature: &str,
    ) -> LedgerResult<GuardianConsentReceipt>;

    /// Reject a GCR
    async fn reject_gcr(&self, gcr_id: &str, reason: &str) -> LedgerResult<()>;

    /// Get GCR by ID
    async fn get_gcr(&self, gcr_id: &str) -> LedgerResult<Option<GuardianConsentReceipt>>;

    /// Create HCP request
    async fn create_hcp(
        &self,
        ai_actor_id: &ActorId,
        action_digest: &Digest,
        action_description: &str,
        reason: &str,
        approval_level: HcpApprovalLevel,
    ) -> LedgerResult<HcpRequest>;

    /// Approve HCP request
    async fn approve_hcp(
        &self,
        request_id: &str,
        human_id: &ActorId,
        signature: &str,
        verification_method: VerificationMethod,
        conditions: Option<&str>,
    ) -> LedgerResult<HcpRequest>;

    /// Reject HCP request
    async fn reject_hcp(
        &self,
        request_id: &str,
        human_id: &ActorId,
        reason: &str,
        signature: &str,
    ) -> LedgerResult<HcpRequest>;

    /// Get HCP request by ID
    async fn get_hcp(&self, request_id: &str) -> LedgerResult<Option<HcpRequest>>;

    /// Start emergency override workflow
    async fn start_override_workflow(
        &self,
        emergency_type: EmergencyJustificationType,
        initiated_by: &ActorId,
        requires_gcr: bool,
        requires_hcp: bool,
    ) -> LedgerResult<EmergencyOverrideWorkflow>;

    /// Get pending approvals for an actor
    async fn get_pending_approvals(&self, actor_id: &ActorId) -> LedgerResult<PendingApprovals>;
}

/// Pending approvals for an actor
#[derive(Debug, Clone, Default)]
pub struct PendingApprovals {
    pub gcrs: Vec<GuardianConsentReceipt>,
    pub hcps: Vec<HcpRequest>,
    pub workflows: Vec<EmergencyOverrideWorkflow>,
}

/// Guardian Consent Service implementation
pub struct GuardianConsentService {
    datastore: Arc<SurrealDatastore>,
    tenant_id: TenantId,
    gcrs: RwLock<HashMap<String, GuardianConsentReceipt>>,
    hcps: RwLock<HashMap<String, HcpRequest>>,
    workflows: RwLock<HashMap<String, EmergencyOverrideWorkflow>>,
    sequence: std::sync::atomic::AtomicU64,
}

impl GuardianConsentService {
    /// Create a new Guardian Consent Service
    pub fn new(datastore: Arc<SurrealDatastore>, tenant_id: TenantId) -> Self {
        Self {
            datastore,
            tenant_id,
            gcrs: RwLock::new(HashMap::new()),
            hcps: RwLock::new(HashMap::new()),
            workflows: RwLock::new(HashMap::new()),
            sequence: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn generate_id(&self, prefix: &str) -> String {
        let seq = self.sequence.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let timestamp = Utc::now().timestamp_micros();
        format!("{}_{:016x}_{:08x}", prefix, timestamp, seq)
    }

    async fn save_gcr_to_db(&self, gcr: &GuardianConsentReceipt) -> LedgerResult<()> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let id = format!("gcrs:{}:{}", self.tenant_id.0, gcr.gcr_id);
        let gcr_id = gcr.gcr_id.clone();
        let ward_id = gcr.ward_id.0.clone();
        let guardian_id = gcr.guardian_id.0.clone();
        let status = format!("{:?}", gcr.status).to_lowercase();
        let created_at = gcr.created_at;
        let expires_at = gcr.expires_at;

        session
            .client()
            .query("UPSERT $id SET tenant_id = $tenant, gcr_id = $gcr_id, ward_id = $ward_id, guardian_id = $guardian_id, status = $status, created_at = $created_at, expires_at = $expires_at")
            .bind(("id", id))
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("gcr_id", gcr_id))
            .bind(("ward_id", ward_id))
            .bind(("guardian_id", guardian_id))
            .bind(("status", status))
            .bind(("created_at", created_at))
            .bind(("expires_at", expires_at))
            .await
            .map_err(|e| LedgerError::Storage(format!("Save GCR failed: {}", e)))?;

        Ok(())
    }

    async fn save_hcp_to_db(&self, hcp: &HcpRequest) -> LedgerResult<()> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let id = format!("hcps:{}:{}", self.tenant_id.0, hcp.request_id);
        let request_id = hcp.request_id.clone();
        let ai_actor_id = hcp.ai_actor_id.0.clone();
        let status = format!("{:?}", hcp.status).to_lowercase();
        let requested_at = hcp.requested_at;
        let expires_at = hcp.expires_at;

        session
            .client()
            .query("UPSERT $id SET tenant_id = $tenant, request_id = $request_id, ai_actor_id = $ai_actor_id, status = $status, requested_at = $requested_at, expires_at = $expires_at")
            .bind(("id", id))
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("request_id", request_id))
            .bind(("ai_actor_id", ai_actor_id))
            .bind(("status", status))
            .bind(("requested_at", requested_at))
            .bind(("expires_at", expires_at))
            .await
            .map_err(|e| LedgerError::Storage(format!("Save HCP failed: {}", e)))?;

        Ok(())
    }
}

#[async_trait]
impl GuardianConsentLedger for GuardianConsentService {
    async fn create_gcr(
        &self,
        ward_id: &ActorId,
        guardian_id: &ActorId,
        guardian_type: GuardianType,
        guardianship_proof_digest: &Digest,
        consent_scope_digest: &Digest,
        justification: &str,
        justification_type: EmergencyJustificationType,
    ) -> LedgerResult<GuardianConsentReceipt> {
        let now = Utc::now();
        let gcr = GuardianConsentReceipt {
            gcr_id: self.generate_id("gcr"),
            ward_id: ward_id.clone(),
            guardian_id: guardian_id.clone(),
            guardian_type,
            guardianship_proof_digest: guardianship_proof_digest.clone(),
            consent_scope_digest: consent_scope_digest.clone(),
            justification: justification.to_string(),
            justification_type,
            status: GcrStatus::Pending,
            created_at: now,
            expires_at: now + Duration::hours(24),
            decided_at: None,
            additional_approvers: Vec::new(),
            min_approvers: 1,
            emergency_override_ref: None,
            audit_log_ref: None,
        };

        {
            let mut gcrs = self.gcrs.write().unwrap();
            gcrs.insert(gcr.gcr_id.clone(), gcr.clone());
        }

        self.save_gcr_to_db(&gcr).await?;
        Ok(gcr)
    }

    async fn approve_gcr(
        &self,
        gcr_id: &str,
        guardian_id: &ActorId,
        guardian_type: GuardianType,
        signature: &str,
    ) -> LedgerResult<GuardianConsentReceipt> {
        let gcr = {
            let mut gcrs = self.gcrs.write().unwrap();
            let gcr = gcrs.get_mut(gcr_id).ok_or_else(|| {
                LedgerError::NotFound(format!("GCR {} not found", gcr_id))
            })?;

            if !gcr.can_approve() {
                return Err(LedgerError::InvalidStateTransition(
                    format!("GCR cannot be approved in status {:?}", gcr.status)
                ));
            }

            // Add approval
            let approval = GuardianApproval {
                guardian_id: guardian_id.clone(),
                guardian_type,
                approved_at: Utc::now(),
                signature: signature.to_string(),
                notes: None,
            };
            gcr.additional_approvers.push(approval);

            // Check if we have enough approvals
            if gcr.has_required_approvals() {
                gcr.status = GcrStatus::Approved;
                gcr.decided_at = Some(Utc::now());
            }

            gcr.clone()
        };

        self.save_gcr_to_db(&gcr).await?;
        Ok(gcr)
    }

    async fn reject_gcr(&self, gcr_id: &str, reason: &str) -> LedgerResult<()> {
        let gcr = {
            let mut gcrs = self.gcrs.write().unwrap();
            let gcr = gcrs.get_mut(gcr_id).ok_or_else(|| {
                LedgerError::NotFound(format!("GCR {} not found", gcr_id))
            })?;

            gcr.status = GcrStatus::Rejected;
            gcr.decided_at = Some(Utc::now());
            gcr.clone()
        };

        let _ = reason; // Would be logged in audit
        self.save_gcr_to_db(&gcr).await?;
        Ok(())
    }

    async fn get_gcr(&self, gcr_id: &str) -> LedgerResult<Option<GuardianConsentReceipt>> {
        let gcrs = self.gcrs.read().unwrap();
        Ok(gcrs.get(gcr_id).cloned())
    }

    async fn create_hcp(
        &self,
        ai_actor_id: &ActorId,
        action_digest: &Digest,
        action_description: &str,
        reason: &str,
        approval_level: HcpApprovalLevel,
    ) -> LedgerResult<HcpRequest> {
        let now = Utc::now();
        let hcp = HcpRequest {
            request_id: self.generate_id("hcp"),
            ai_actor_id: ai_actor_id.clone(),
            action_digest: action_digest.clone(),
            action_description: action_description.to_string(),
            reason: reason.to_string(),
            approval_level,
            status: HcpStatus::Pending,
            requested_at: now,
            expires_at: now + Duration::hours(4), // Shorter timeout for AI actions
            approvals: Vec::new(),
            rejections: Vec::new(),
            decided_at: None,
            escalation_chain: Vec::new(),
        };

        {
            let mut hcps = self.hcps.write().unwrap();
            hcps.insert(hcp.request_id.clone(), hcp.clone());
        }

        self.save_hcp_to_db(&hcp).await?;
        Ok(hcp)
    }

    async fn approve_hcp(
        &self,
        request_id: &str,
        human_id: &ActorId,
        signature: &str,
        verification_method: VerificationMethod,
        conditions: Option<&str>,
    ) -> LedgerResult<HcpRequest> {
        let hcp = {
            let mut hcps = self.hcps.write().unwrap();
            let hcp = hcps.get_mut(request_id).ok_or_else(|| {
                LedgerError::NotFound(format!("HCP {} not found", request_id))
            })?;

            if hcp.status != HcpStatus::Pending {
                return Err(LedgerError::InvalidStateTransition(
                    format!("HCP cannot be approved in status {:?}", hcp.status)
                ));
            }

            let approval = HumanApproval {
                human_id: human_id.clone(),
                approved_at: Utc::now(),
                signature: signature.to_string(),
                conditions: conditions.map(|s| s.to_string()),
                verification_method,
            };
            hcp.approvals.push(approval);
            hcp.update_status();

            hcp.clone()
        };

        self.save_hcp_to_db(&hcp).await?;
        Ok(hcp)
    }

    async fn reject_hcp(
        &self,
        request_id: &str,
        human_id: &ActorId,
        reason: &str,
        signature: &str,
    ) -> LedgerResult<HcpRequest> {
        let hcp = {
            let mut hcps = self.hcps.write().unwrap();
            let hcp = hcps.get_mut(request_id).ok_or_else(|| {
                LedgerError::NotFound(format!("HCP {} not found", request_id))
            })?;

            if hcp.status != HcpStatus::Pending {
                return Err(LedgerError::InvalidStateTransition(
                    format!("HCP cannot be rejected in status {:?}", hcp.status)
                ));
            }

            let rejection = HumanRejection {
                human_id: human_id.clone(),
                rejected_at: Utc::now(),
                reason: reason.to_string(),
                signature: signature.to_string(),
            };
            hcp.rejections.push(rejection);
            hcp.update_status();

            hcp.clone()
        };

        self.save_hcp_to_db(&hcp).await?;
        Ok(hcp)
    }

    async fn get_hcp(&self, request_id: &str) -> LedgerResult<Option<HcpRequest>> {
        let hcps = self.hcps.read().unwrap();
        Ok(hcps.get(request_id).cloned())
    }

    async fn start_override_workflow(
        &self,
        emergency_type: EmergencyJustificationType,
        initiated_by: &ActorId,
        requires_gcr: bool,
        requires_hcp: bool,
    ) -> LedgerResult<EmergencyOverrideWorkflow> {
        let now = Utc::now();
        let stage = if requires_gcr {
            OverrideStage::AwaitingGcr
        } else if requires_hcp {
            OverrideStage::AwaitingHcp
        } else {
            OverrideStage::Executing
        };

        let workflow = EmergencyOverrideWorkflow {
            workflow_id: self.generate_id("workflow"),
            emergency_type,
            initiated_by: initiated_by.clone(),
            stage,
            gcr: None,
            hcp: None,
            started_at: now,
            deadline: now + Duration::hours(24),
            audit_entries: vec![OverrideAuditEntry {
                timestamp: now,
                actor_id: initiated_by.clone(),
                action: "workflow_initiated".to_string(),
                details: Some(format!("Emergency type: {:?}", emergency_type)),
            }],
        };

        {
            let mut workflows = self.workflows.write().unwrap();
            workflows.insert(workflow.workflow_id.clone(), workflow.clone());
        }

        Ok(workflow)
    }

    async fn get_pending_approvals(&self, actor_id: &ActorId) -> LedgerResult<PendingApprovals> {
        let gcrs = self.gcrs.read().unwrap();
        let hcps = self.hcps.read().unwrap();
        let workflows = self.workflows.read().unwrap();

        let pending_gcrs: Vec<_> = gcrs
            .values()
            .filter(|g| g.status == GcrStatus::Pending && &g.guardian_id == actor_id)
            .cloned()
            .collect();

        let pending_hcps: Vec<_> = hcps
            .values()
            .filter(|h| h.status == HcpStatus::Pending)
            .cloned()
            .collect();

        let pending_workflows: Vec<_> = workflows
            .values()
            .filter(|w| matches!(w.stage, OverrideStage::AwaitingGcr | OverrideStage::AwaitingHcp))
            .cloned()
            .collect();

        Ok(PendingApprovals {
            gcrs: pending_gcrs,
            hcps: pending_hcps,
            workflows: pending_workflows,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pending_approvals_default() {
        let pending = PendingApprovals::default();
        assert!(pending.gcrs.is_empty());
        assert!(pending.hcps.is_empty());
        assert!(pending.workflows.is_empty());
    }
}
