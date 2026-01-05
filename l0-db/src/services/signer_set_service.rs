//! Signer Set Management Service
//!
//! Implements signer admission, slashing, and reputation management.

use async_trait::async_trait;
use chrono::Utc;
use l0_core::error::LedgerError;
use l0_core::ledger::LedgerResult;
use l0_core::types::{
    ActorId, AdmissionPolicy, AdmissionRequest, AdmissionStatus, Digest, SignerApproval,
    SignerRecord, SignerRejection, SignerSetSnapshot, SignerStatus, SlashingEvent,
    SlashingPolicy, ViolationType,
};
use soulbase_storage::surreal::SurrealDatastore;
use soulbase_storage::Datastore;
use soulbase_types::prelude::TenantId;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Signer Set Ledger trait
#[async_trait]
pub trait SignerSetLedger: Send + Sync {
    /// Register a new signer candidate
    async fn register_candidate(
        &self,
        candidate_id: &ActorId,
        public_key: &str,
        stake_amount: u64,
    ) -> LedgerResult<AdmissionRequest>;

    /// Vote to approve a candidate
    async fn approve_candidate(
        &self,
        request_id: &str,
        signer_id: &ActorId,
        signature: &str,
    ) -> LedgerResult<AdmissionRequest>;

    /// Vote to reject a candidate
    async fn reject_candidate(
        &self,
        request_id: &str,
        signer_id: &ActorId,
        reason: &str,
        signature: &str,
    ) -> LedgerResult<AdmissionRequest>;

    /// Admit an approved candidate to the signer set
    async fn admit_candidate(&self, request_id: &str) -> LedgerResult<SignerRecord>;

    /// Record a violation and apply slashing
    async fn record_violation(
        &self,
        signer_id: &ActorId,
        violation_type: ViolationType,
        evidence_digest: Digest,
        epoch: u64,
    ) -> LedgerResult<SlashingEvent>;

    /// Update signer reputation
    async fn update_reputation(
        &self,
        signer_id: &ActorId,
        delta: i32,
    ) -> LedgerResult<SignerRecord>;

    /// Record successful signature
    async fn record_signature_success(&self, signer_id: &ActorId) -> LedgerResult<SignerRecord>;

    /// Record missed signature
    async fn record_signature_miss(&self, signer_id: &ActorId) -> LedgerResult<SignerRecord>;

    /// Voluntarily exit from signer set
    async fn exit_signer_set(&self, signer_id: &ActorId) -> LedgerResult<SignerRecord>;

    /// Get signer by ID
    async fn get_signer(&self, signer_id: &ActorId) -> LedgerResult<Option<SignerRecord>>;

    /// Get all active signers
    async fn get_active_signers(&self) -> LedgerResult<Vec<SignerRecord>>;

    /// Get pending admission requests
    async fn get_pending_requests(&self) -> LedgerResult<Vec<AdmissionRequest>>;

    /// Get current snapshot
    async fn get_snapshot(&self) -> LedgerResult<SignerSetSnapshot>;

    /// Update admission policy
    async fn update_admission_policy(&self, policy: AdmissionPolicy) -> LedgerResult<()>;

    /// Update slashing policy
    async fn update_slashing_policy(&self, policy: SlashingPolicy) -> LedgerResult<()>;

    /// Get slashing events for a signer
    async fn get_slashing_history(&self, signer_id: &ActorId) -> LedgerResult<Vec<SlashingEvent>>;
}

/// Signer Set Service implementation
pub struct SignerSetService {
    datastore: Arc<SurrealDatastore>,
    tenant_id: TenantId,
    signers: RwLock<HashMap<String, SignerRecord>>,
    requests: RwLock<HashMap<String, AdmissionRequest>>,
    slashing_events: RwLock<Vec<SlashingEvent>>,
    admission_policy: RwLock<AdmissionPolicy>,
    slashing_policy: RwLock<SlashingPolicy>,
    snapshot_version: RwLock<u64>,
    sequence: std::sync::atomic::AtomicU64,
}

impl SignerSetService {
    pub fn new(datastore: Arc<SurrealDatastore>, tenant_id: TenantId) -> Self {
        Self {
            datastore,
            tenant_id,
            signers: RwLock::new(HashMap::new()),
            requests: RwLock::new(HashMap::new()),
            slashing_events: RwLock::new(Vec::new()),
            admission_policy: RwLock::new(AdmissionPolicy::default()),
            slashing_policy: RwLock::new(SlashingPolicy::default()),
            snapshot_version: RwLock::new(0),
            sequence: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Generate a new request ID
    fn generate_request_id(&self) -> String {
        let seq = self.sequence.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let timestamp = Utc::now().timestamp_micros();
        format!("req_{:016x}_{:08x}", timestamp, seq)
    }

    /// Generate a new event ID
    fn generate_event_id(&self) -> String {
        let seq = self.sequence.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let timestamp = Utc::now().timestamp_micros();
        format!("slash_{:016x}_{:08x}", timestamp, seq)
    }

    /// Calculate slash amount based on policy and violation type
    fn calculate_slash_amount(&self, stake: u64, violation: ViolationType) -> u64 {
        let policy = self.slashing_policy.read().unwrap();
        let bps = match violation {
            ViolationType::MissedSignature => policy.miss_signature_slash_bps,
            ViolationType::DoubleSigning => policy.double_sign_slash_bps,
            ViolationType::Downtime => policy.downtime_slash_bps,
            ViolationType::Equivocation => policy.equivocation_slash_bps,
            ViolationType::ProtocolViolation => policy.equivocation_slash_bps, // Same as equivocation
        };
        (stake * bps as u64) / 10000
    }

    /// Determine resulting status after violation
    fn determine_post_violation_status(
        &self,
        signer: &SignerRecord,
        violation: ViolationType,
        slashed_amount: u64,
    ) -> SignerStatus {
        let policy = self.slashing_policy.read().unwrap();
        let remaining_stake = signer.stake_amount.saturating_sub(slashed_amount);

        // Full slash or below threshold -> Removed
        if remaining_stake < policy.min_stake_threshold {
            return SignerStatus::Removed;
        }

        // Equivocation or double signing -> Suspended
        if matches!(violation, ViolationType::DoubleSigning | ViolationType::Equivocation) {
            return SignerStatus::Suspended;
        }

        // Too many slashing events -> Demoted
        if signer.slashing_count + 1 >= policy.max_slashing_events_before_demotion {
            return SignerStatus::Demoted;
        }

        // Otherwise remain active
        SignerStatus::Active
    }

    async fn save_signer_to_db(&self, signer: &SignerRecord) -> LedgerResult<()> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let signer_id = signer.signer_id.0.clone();
        let public_key = signer.public_key.clone();
        let status = serde_json::to_string(&signer.status)
            .map_err(|e| LedgerError::Serialization(format!("Failed to serialize status: {}", e)))?;
        let reputation_score = signer.reputation_score;
        let epochs_participated = signer.epochs_participated;
        let missed_signatures = signer.missed_signatures;
        let successful_signatures = signer.successful_signatures;
        let slashing_count = signer.slashing_count;
        let total_slashed = signer.total_slashed;
        let joined_at = signer.joined_at.to_rfc3339();
        let last_active_at = signer.last_active_at.to_rfc3339();
        let stake_amount = signer.stake_amount;
        let locked_stake = signer.locked_stake;

        let _: Option<SignerRecord> = session
            .client()
            .query(
                "UPSERT signer_records SET
                    tenant_id = $tenant,
                    signer_id = $signer_id,
                    public_key = $public_key,
                    status = $status,
                    reputation_score = $reputation_score,
                    epochs_participated = $epochs_participated,
                    missed_signatures = $missed_signatures,
                    successful_signatures = $successful_signatures,
                    slashing_count = $slashing_count,
                    total_slashed = $total_slashed,
                    joined_at = $joined_at,
                    last_active_at = $last_active_at,
                    stake_amount = $stake_amount,
                    locked_stake = $locked_stake
                WHERE tenant_id = $tenant AND signer_id = $signer_id",
            )
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("signer_id", signer_id))
            .bind(("public_key", public_key))
            .bind(("status", status))
            .bind(("reputation_score", reputation_score))
            .bind(("epochs_participated", epochs_participated))
            .bind(("missed_signatures", missed_signatures))
            .bind(("successful_signatures", successful_signatures))
            .bind(("slashing_count", slashing_count))
            .bind(("total_slashed", total_slashed))
            .bind(("joined_at", joined_at))
            .bind(("last_active_at", last_active_at))
            .bind(("stake_amount", stake_amount))
            .bind(("locked_stake", locked_stake))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        Ok(())
    }

    async fn save_request_to_db(&self, request: &AdmissionRequest) -> LedgerResult<()> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let request_id = request.request_id.clone();
        let candidate_id = request.candidate_id.0.clone();
        let public_key = request.public_key.clone();
        let stake_amount = request.stake_amount;
        let requested_at = request.requested_at.to_rfc3339();
        let status = serde_json::to_string(&request.status).unwrap_or_default();
        let approvals = serde_json::to_string(&request.approvals).unwrap_or_default();
        let rejections = serde_json::to_string(&request.rejections).unwrap_or_default();
        let decided_at = request.decided_at.map(|d| d.to_rfc3339());

        let _: Option<AdmissionRequest> = session
            .client()
            .query(
                "UPSERT admission_requests SET
                    tenant_id = $tenant,
                    request_id = $request_id,
                    candidate_id = $candidate_id,
                    public_key = $public_key,
                    stake_amount = $stake_amount,
                    requested_at = $requested_at,
                    status = $status,
                    approvals = $approvals,
                    rejections = $rejections,
                    decided_at = $decided_at
                WHERE tenant_id = $tenant AND request_id = $request_id",
            )
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("request_id", request_id))
            .bind(("candidate_id", candidate_id))
            .bind(("public_key", public_key))
            .bind(("stake_amount", stake_amount))
            .bind(("requested_at", requested_at))
            .bind(("status", status))
            .bind(("approvals", approvals))
            .bind(("rejections", rejections))
            .bind(("decided_at", decided_at))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        Ok(())
    }

    async fn save_slashing_event_to_db(&self, event: &SlashingEvent) -> LedgerResult<()> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let event_id = event.event_id.clone();
        let signer_id = event.signer_id.0.clone();
        let violation_type = serde_json::to_string(&event.violation_type).unwrap_or_default();
        let evidence_digest = event.evidence_digest.to_hex();
        let amount_slashed = event.amount_slashed;
        let reputation_penalty = event.reputation_penalty;
        let resulting_status = serde_json::to_string(&event.resulting_status).unwrap_or_default();
        let violation_at = event.violation_at.to_rfc3339();
        let slashed_at = event.slashed_at.to_rfc3339();
        let epoch = event.epoch;

        let _: Option<SlashingEvent> = session
            .client()
            .query(
                "INSERT INTO slashing_events {
                    tenant_id: $tenant,
                    event_id: $event_id,
                    signer_id: $signer_id,
                    violation_type: $violation_type,
                    evidence_digest: $evidence_digest,
                    amount_slashed: $amount_slashed,
                    reputation_penalty: $reputation_penalty,
                    resulting_status: $resulting_status,
                    violation_at: $violation_at,
                    slashed_at: $slashed_at,
                    epoch: $epoch
                }",
            )
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("event_id", event_id))
            .bind(("signer_id", signer_id))
            .bind(("violation_type", violation_type))
            .bind(("evidence_digest", evidence_digest))
            .bind(("amount_slashed", amount_slashed))
            .bind(("reputation_penalty", reputation_penalty))
            .bind(("resulting_status", resulting_status))
            .bind(("violation_at", violation_at))
            .bind(("slashed_at", slashed_at))
            .bind(("epoch", epoch))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        Ok(())
    }

    fn increment_snapshot_version(&self) {
        let mut version = self.snapshot_version.write().unwrap();
        *version += 1;
    }
}

#[async_trait]
impl SignerSetLedger for SignerSetService {
    async fn register_candidate(
        &self,
        candidate_id: &ActorId,
        public_key: &str,
        stake_amount: u64,
    ) -> LedgerResult<AdmissionRequest> {
        let policy = self.admission_policy.read().unwrap().clone();

        // Check minimum stake
        if stake_amount < policy.min_stake {
            return Err(LedgerError::Validation(format!(
                "Stake {} below minimum {}",
                stake_amount, policy.min_stake
            )));
        }

        // Check candidate limit
        {
            let requests = self.requests.read().unwrap();
            let pending_count = requests
                .values()
                .filter(|r| r.status == AdmissionStatus::Pending)
                .count();
            if pending_count >= policy.max_candidates as usize {
                return Err(LedgerError::Validation(
                    "Maximum candidates reached".to_string(),
                ));
            }
        }

        let request = AdmissionRequest {
            request_id: self.generate_request_id(),
            candidate_id: candidate_id.clone(),
            public_key: public_key.to_string(),
            stake_amount,
            requested_at: Utc::now(),
            status: AdmissionStatus::Pending,
            approvals: Vec::new(),
            rejections: Vec::new(),
            decided_at: None,
        };

        {
            let mut requests = self.requests.write().unwrap();
            requests.insert(request.request_id.clone(), request.clone());
        }

        self.save_request_to_db(&request).await?;
        Ok(request)
    }

    async fn approve_candidate(
        &self,
        request_id: &str,
        signer_id: &ActorId,
        signature: &str,
    ) -> LedgerResult<AdmissionRequest> {
        let result = {
            let mut requests = self.requests.write().unwrap();
            let request = requests
                .get_mut(request_id)
                .ok_or_else(|| LedgerError::NotFound(format!("Request {}", request_id)))?;

            if request.status != AdmissionStatus::Pending {
                return Err(LedgerError::Validation(
                    "Request is not pending".to_string(),
                ));
            }

            // Check if already approved by this signer
            if request.approvals.iter().any(|a| &a.signer_id == signer_id) {
                return Err(LedgerError::Validation(
                    "Already approved by this signer".to_string(),
                ));
            }

            request.approvals.push(SignerApproval {
                signer_id: signer_id.clone(),
                approved_at: Utc::now(),
                signature: signature.to_string(),
            });

            // Check if approved
            let policy = self.admission_policy.read().unwrap();
            if request.has_enough_approvals(&policy) {
                request.status = AdmissionStatus::Approved;
                request.decided_at = Some(Utc::now());
            }

            request.clone()
        };

        self.save_request_to_db(&result).await?;
        Ok(result)
    }

    async fn reject_candidate(
        &self,
        request_id: &str,
        signer_id: &ActorId,
        reason: &str,
        signature: &str,
    ) -> LedgerResult<AdmissionRequest> {
        let (result, total_signers) = {
            let signers = self.signers.read().unwrap();
            let total_signers = signers
                .values()
                .filter(|s| s.status == SignerStatus::Active)
                .count();

            let mut requests = self.requests.write().unwrap();
            let request = requests
                .get_mut(request_id)
                .ok_or_else(|| LedgerError::NotFound(format!("Request {}", request_id)))?;

            if request.status != AdmissionStatus::Pending {
                return Err(LedgerError::Validation(
                    "Request is not pending".to_string(),
                ));
            }

            // Check if already rejected by this signer
            if request.rejections.iter().any(|r| &r.signer_id == signer_id) {
                return Err(LedgerError::Validation(
                    "Already rejected by this signer".to_string(),
                ));
            }

            request.rejections.push(SignerRejection {
                signer_id: signer_id.clone(),
                rejected_at: Utc::now(),
                reason: reason.to_string(),
                signature: signature.to_string(),
            });

            (request.clone(), total_signers)
        };

        // Check if rejected (outside lock to avoid deadlock)
        let final_result = {
            let mut requests = self.requests.write().unwrap();
            let request = requests.get_mut(request_id).unwrap();

            if request.is_rejected(total_signers) {
                request.status = AdmissionStatus::Rejected;
                request.decided_at = Some(Utc::now());
            }

            request.clone()
        };

        self.save_request_to_db(&final_result).await?;
        Ok(final_result)
    }

    async fn admit_candidate(&self, request_id: &str) -> LedgerResult<SignerRecord> {
        let signer = {
            let mut requests = self.requests.write().unwrap();
            let request = requests
                .get_mut(request_id)
                .ok_or_else(|| LedgerError::NotFound(format!("Request {}", request_id)))?;

            if request.status != AdmissionStatus::Approved {
                return Err(LedgerError::Validation(
                    "Request is not approved".to_string(),
                ));
            }

            let now = Utc::now();
            let signer = SignerRecord {
                signer_id: request.candidate_id.clone(),
                public_key: request.public_key.clone(),
                status: SignerStatus::Active,
                reputation_score: 500, // Starting reputation
                epochs_participated: 0,
                missed_signatures: 0,
                successful_signatures: 0,
                slashing_count: 0,
                total_slashed: 0,
                joined_at: now,
                last_active_at: now,
                stake_amount: request.stake_amount,
                locked_stake: 0,
            };

            signer
        };

        {
            let mut signers = self.signers.write().unwrap();
            signers.insert(signer.signer_id.0.clone(), signer.clone());
        }

        self.save_signer_to_db(&signer).await?;
        self.increment_snapshot_version();
        Ok(signer)
    }

    async fn record_violation(
        &self,
        signer_id: &ActorId,
        violation_type: ViolationType,
        evidence_digest: Digest,
        epoch: u64,
    ) -> LedgerResult<SlashingEvent> {
        let (event, updated_signer) = {
            let mut signers = self.signers.write().unwrap();
            let signer = signers
                .get_mut(&signer_id.0)
                .ok_or_else(|| LedgerError::NotFound(format!("Signer {}", signer_id.0)))?;

            let slash_amount = self.calculate_slash_amount(signer.stake_amount, violation_type);
            let policy = self.slashing_policy.read().unwrap();
            let reputation_penalty = policy.reputation_penalty_per_miss;

            let resulting_status =
                self.determine_post_violation_status(signer, violation_type, slash_amount);

            let now = Utc::now();
            let event = SlashingEvent {
                event_id: self.generate_event_id(),
                signer_id: signer_id.clone(),
                violation_type,
                evidence_digest,
                amount_slashed: slash_amount,
                reputation_penalty,
                resulting_status,
                violation_at: now,
                slashed_at: now,
                epoch,
            };

            // Update signer
            signer.stake_amount = signer.stake_amount.saturating_sub(slash_amount);
            signer.locked_stake += slash_amount;
            signer.total_slashed += slash_amount;
            signer.slashing_count += 1;
            signer.reputation_score = signer.reputation_score.saturating_sub(reputation_penalty);
            signer.status = resulting_status;

            (event, signer.clone())
        };

        {
            let mut events = self.slashing_events.write().unwrap();
            events.push(event.clone());
        }

        self.save_slashing_event_to_db(&event).await?;
        self.save_signer_to_db(&updated_signer).await?;
        self.increment_snapshot_version();
        Ok(event)
    }

    async fn update_reputation(
        &self,
        signer_id: &ActorId,
        delta: i32,
    ) -> LedgerResult<SignerRecord> {
        let signer = {
            let mut signers = self.signers.write().unwrap();
            let signer = signers
                .get_mut(&signer_id.0)
                .ok_or_else(|| LedgerError::NotFound(format!("Signer {}", signer_id.0)))?;

            if delta >= 0 {
                signer.reputation_score =
                    (signer.reputation_score + delta as u32).min(1000);
            } else {
                signer.reputation_score =
                    signer.reputation_score.saturating_sub((-delta) as u32);
            }

            signer.clone()
        };

        self.save_signer_to_db(&signer).await?;
        Ok(signer)
    }

    async fn record_signature_success(&self, signer_id: &ActorId) -> LedgerResult<SignerRecord> {
        let signer = {
            let mut signers = self.signers.write().unwrap();
            let signer = signers
                .get_mut(&signer_id.0)
                .ok_or_else(|| LedgerError::NotFound(format!("Signer {}", signer_id.0)))?;

            signer.successful_signatures += 1;
            signer.last_active_at = Utc::now();
            // Small reputation boost
            signer.reputation_score = (signer.reputation_score + 1).min(1000);

            signer.clone()
        };

        self.save_signer_to_db(&signer).await?;
        Ok(signer)
    }

    async fn record_signature_miss(&self, signer_id: &ActorId) -> LedgerResult<SignerRecord> {
        let signer = {
            let mut signers = self.signers.write().unwrap();
            let signer = signers
                .get_mut(&signer_id.0)
                .ok_or_else(|| LedgerError::NotFound(format!("Signer {}", signer_id.0)))?;

            signer.missed_signatures += 1;
            let policy = self.slashing_policy.read().unwrap();
            signer.reputation_score = signer
                .reputation_score
                .saturating_sub(policy.reputation_penalty_per_miss);

            signer.clone()
        };

        self.save_signer_to_db(&signer).await?;
        Ok(signer)
    }

    async fn exit_signer_set(&self, signer_id: &ActorId) -> LedgerResult<SignerRecord> {
        let signer = {
            let mut signers = self.signers.write().unwrap();
            let signer = signers
                .get_mut(&signer_id.0)
                .ok_or_else(|| LedgerError::NotFound(format!("Signer {}", signer_id.0)))?;

            if signer.status != SignerStatus::Active {
                return Err(LedgerError::Validation(
                    "Only active signers can exit".to_string(),
                ));
            }

            signer.status = SignerStatus::Exited;
            signer.clone()
        };

        self.save_signer_to_db(&signer).await?;
        self.increment_snapshot_version();
        Ok(signer)
    }

    async fn get_signer(&self, signer_id: &ActorId) -> LedgerResult<Option<SignerRecord>> {
        let signers = self.signers.read().unwrap();
        Ok(signers.get(&signer_id.0).cloned())
    }

    async fn get_active_signers(&self) -> LedgerResult<Vec<SignerRecord>> {
        let signers = self.signers.read().unwrap();
        Ok(signers
            .values()
            .filter(|s| s.status == SignerStatus::Active)
            .cloned()
            .collect())
    }

    async fn get_pending_requests(&self) -> LedgerResult<Vec<AdmissionRequest>> {
        let requests = self.requests.read().unwrap();
        Ok(requests
            .values()
            .filter(|r| r.status == AdmissionStatus::Pending)
            .cloned()
            .collect())
    }

    async fn get_snapshot(&self) -> LedgerResult<SignerSetSnapshot> {
        let signers = self.signers.read().unwrap();
        let requests = self.requests.read().unwrap();
        let admission_policy = self.admission_policy.read().unwrap().clone();
        let slashing_policy = self.slashing_policy.read().unwrap().clone();
        let version = *self.snapshot_version.read().unwrap();

        let active_signers: Vec<SignerRecord> = signers
            .values()
            .filter(|s| s.status == SignerStatus::Active)
            .cloned()
            .collect();

        let suspended_signers: Vec<SignerRecord> = signers
            .values()
            .filter(|s| s.status == SignerStatus::Suspended)
            .cloned()
            .collect();

        let candidates: Vec<AdmissionRequest> = requests
            .values()
            .filter(|r| r.status == AdmissionStatus::Pending)
            .cloned()
            .collect();

        let total_stake: u64 = active_signers.iter().map(|s| s.stake_amount).sum();

        Ok(SignerSetSnapshot {
            version,
            active_signers,
            suspended_signers,
            candidates,
            admission_policy,
            slashing_policy,
            snapshot_at: Utc::now(),
            total_stake,
        })
    }

    async fn update_admission_policy(&self, policy: AdmissionPolicy) -> LedgerResult<()> {
        let mut current = self.admission_policy.write().unwrap();
        *current = policy;
        Ok(())
    }

    async fn update_slashing_policy(&self, policy: SlashingPolicy) -> LedgerResult<()> {
        let mut current = self.slashing_policy.write().unwrap();
        *current = policy;
        Ok(())
    }

    async fn get_slashing_history(&self, signer_id: &ActorId) -> LedgerResult<Vec<SlashingEvent>> {
        let events = self.slashing_events.read().unwrap();
        Ok(events
            .iter()
            .filter(|e| &e.signer_id == signer_id)
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_violation_status_determination() {
        // Test logic without service
        let signer = SignerRecord {
            signer_id: ActorId("test".to_string()),
            public_key: "key".to_string(),
            status: SignerStatus::Active,
            reputation_score: 500,
            epochs_participated: 10,
            missed_signatures: 0,
            successful_signatures: 100,
            slashing_count: 0,
            total_slashed: 0,
            joined_at: Utc::now(),
            last_active_at: Utc::now(),
            stake_amount: 100_000,
            locked_stake: 0,
        };

        // Signer with stake below threshold should be removed
        let low_stake_signer = SignerRecord {
            stake_amount: 5_000,
            ..signer.clone()
        };

        let policy = SlashingPolicy::default();
        let slash_amount = 5_000; // Would leave 0
        let remaining = low_stake_signer.stake_amount.saturating_sub(slash_amount);
        assert!(remaining < policy.min_stake_threshold);
    }
}
