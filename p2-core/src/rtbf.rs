//! Right To Be Forgotten (RTBF) Implementation
//!
//! This module implements the "被遗忘权" (Right to be Forgotten) coordination
//! between P1 (ledger) and P2 (storage) layers as specified in DSN documentation.
//!
//! # Key Requirements
//!
//! 1. **Legal Hold Check**: RTBF cannot proceed if subject has active legal holds
//! 2. **Evidence Retention**: Evidence bundles may be exempt from RTBF
//! 3. **Tombstone Creation**: Data is tombstoned, not hard-deleted
//! 4. **Cross-Layer Coordination**: P1 index updates + P2 storage tombstones
//! 5. **Audit Trail**: All RTBF operations must be audit-logged
//!
//! # Workflow
//!
//! ```text
//! RTBF Request → Legal Hold Check → Evidence Check →
//! Payload Enumeration → P2 Tombstone → P1 Index Update → Audit Log
//! ```

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use l0_core::types::{ActorId, Digest};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// RTBF error types
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
pub enum RtbfError {
    #[error("Legal hold active: {hold_id}")]
    LegalHoldActive { hold_id: String },

    #[error("Evidence retention prevents deletion: {reason}")]
    EvidenceRetention { reason: String },

    #[error("Subject not found: {subject_id}")]
    SubjectNotFound { subject_id: String },

    #[error("Request already in progress: {request_id}")]
    RequestInProgress { request_id: String },

    #[error("P2 storage operation failed: {0}")]
    StorageError(String),

    #[error("P1 ledger operation failed: {0}")]
    LedgerError(String),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Request expired: {request_id}")]
    RequestExpired { request_id: String },

    #[error("Insufficient authorization: {0}")]
    InsufficientAuthorization(String),
}

pub type RtbfResult<T> = Result<T, RtbfError>;

/// RTBF request status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RtbfStatus {
    /// Request received, pending processing
    Pending,
    /// Legal hold check in progress
    CheckingLegalHold,
    /// Evidence retention check in progress
    CheckingEvidence,
    /// Payload enumeration in progress
    EnumeratingPayloads,
    /// P2 tombstoning in progress
    TombstoningPayloads,
    /// P1 index update in progress
    UpdatingIndex,
    /// Request completed successfully
    Completed,
    /// Request failed
    Failed,
    /// Request blocked by legal hold
    BlockedByLegalHold,
    /// Request partially completed (some evidence retained)
    PartiallyCompleted,
}

/// RTBF request representing a subject's deletion request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RtbfRequest {
    /// Unique request ID
    pub request_id: String,
    /// Subject ID requesting deletion
    pub subject_id: ActorId,
    /// Request timestamp
    pub requested_at: DateTime<Utc>,
    /// Request expiration (must be processed within this window)
    pub expires_at: DateTime<Utc>,
    /// Scope of deletion
    pub scope: RtbfScope,
    /// Requestor identity (may differ from subject)
    pub requestor: ActorId,
    /// Authorization proof
    pub authorization_proof: Option<String>,
    /// Request reason
    pub reason: RtbfReason,
    /// Current status
    pub status: RtbfStatus,
    /// Processing metadata
    pub processing_metadata: HashMap<String, String>,
}

impl RtbfRequest {
    /// Create a new RTBF request
    pub fn new(subject_id: ActorId, requestor: ActorId, scope: RtbfScope, reason: RtbfReason) -> Self {
        let request_id = format!("rtbf:{}", Uuid::new_v4());
        let now = Utc::now();

        Self {
            request_id,
            subject_id,
            requested_at: now,
            expires_at: now + Duration::days(30), // 30-day processing window
            scope,
            requestor,
            authorization_proof: None,
            reason,
            status: RtbfStatus::Pending,
            processing_metadata: HashMap::new(),
        }
    }

    /// Check if request has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if request is in a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            RtbfStatus::Completed | RtbfStatus::Failed | RtbfStatus::BlockedByLegalHold
        )
    }
}

/// Scope of RTBF deletion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RtbfScope {
    /// Delete all data for the subject
    Full,
    /// Delete only specific data types
    Selective {
        /// Include resurrection snapshots
        include_resurrection: bool,
        /// Include evidence bundles
        include_evidence: bool,
        /// Include audit logs
        include_audit: bool,
        /// Specific payload ref_ids to delete
        specific_payloads: Vec<String>,
    },
    /// Delete data before a specific date
    Temporal {
        /// Delete data before this timestamp
        before: DateTime<Utc>,
    },
}

/// Reason for RTBF request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RtbfReason {
    /// Subject exercising GDPR rights
    GdprRequest,
    /// Subject exercising CCPA rights
    CcpaRequest,
    /// Subject withdrawing consent
    ConsentWithdrawal,
    /// Data no longer necessary
    DataUnnecessary,
    /// Subject objection to processing
    ObjectionToProcessing,
    /// Unlawful processing
    UnlawfulProcessing,
    /// Legal obligation to delete
    LegalObligation,
    /// Other reason
    Other(String),
}

/// Result of RTBF processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RtbfResult_ {
    /// Request ID
    pub request_id: String,
    /// Final status
    pub status: RtbfStatus,
    /// Payloads tombstoned
    pub tombstoned_count: usize,
    /// Payloads retained (due to legal hold or evidence)
    pub retained_count: usize,
    /// Retained payload reasons
    pub retained_reasons: HashMap<String, RetentionReason>,
    /// Processing duration
    pub processing_duration_ms: u64,
    /// Completion timestamp
    pub completed_at: DateTime<Utc>,
    /// Audit log entry ID
    pub audit_log_id: String,
}

/// Reason for retaining a payload despite RTBF
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RetentionReason {
    /// Active legal hold
    LegalHold { hold_id: String, case_id: String },
    /// Evidence in active case
    ActiveEvidence { case_id: String },
    /// Regulatory retention requirement
    RegulatoryRetention { regulation: String, until: DateTime<Utc> },
    /// Third-party rights
    ThirdPartyRights { party_id: String },
}

/// Legal hold status for a subject
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegalHoldStatus {
    /// Subject ID
    pub subject_id: ActorId,
    /// Active holds
    pub active_holds: Vec<LegalHoldInfo>,
    /// Whether RTBF can proceed
    pub rtbf_allowed: bool,
    /// Check timestamp
    pub checked_at: DateTime<Utc>,
}

/// Legal hold information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegalHoldInfo {
    /// Hold ID
    pub hold_id: String,
    /// Associated case ID
    pub case_id: String,
    /// Hold start time
    pub started_at: DateTime<Utc>,
    /// Expected duration
    pub expected_until: Option<DateTime<Utc>>,
    /// Hold reason
    pub reason: String,
}

/// Subject's payload inventory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadInventory {
    /// Subject ID
    pub subject_id: ActorId,
    /// Resurrection snapshots
    pub resurrection_refs: Vec<String>,
    /// Evidence bundles
    pub evidence_refs: Vec<String>,
    /// Audit logs
    pub audit_refs: Vec<String>,
    /// Other payloads
    pub other_refs: Vec<String>,
    /// Inventory timestamp
    pub enumerated_at: DateTime<Utc>,
}

impl PayloadInventory {
    /// Get total payload count
    pub fn total_count(&self) -> usize {
        self.resurrection_refs.len()
            + self.evidence_refs.len()
            + self.audit_refs.len()
            + self.other_refs.len()
    }

    /// Get all ref_ids
    pub fn all_refs(&self) -> Vec<&String> {
        self.resurrection_refs
            .iter()
            .chain(self.evidence_refs.iter())
            .chain(self.audit_refs.iter())
            .chain(self.other_refs.iter())
            .collect()
    }
}

/// P1 Ledger interface for RTBF operations
#[async_trait]
pub trait RtbfLedgerInterface: Send + Sync {
    /// Check legal hold status for a subject
    async fn check_legal_hold(&self, subject_id: &ActorId) -> RtbfResult<LegalHoldStatus>;

    /// Enumerate all payloads for a subject
    async fn enumerate_payloads(&self, subject_id: &ActorId) -> RtbfResult<PayloadInventory>;

    /// Mark payloads as deleted in P1 index
    async fn mark_deleted(&self, ref_ids: &[String], request_id: &str) -> RtbfResult<()>;

    /// Record RTBF completion in P1
    async fn record_rtbf_completion(&self, result: &RtbfResult_) -> RtbfResult<String>;
}

/// P2 Storage interface for RTBF operations
#[async_trait]
pub trait RtbfStorageInterface: Send + Sync {
    /// Tombstone a payload
    async fn tombstone_payload(&self, ref_id: &str, request_id: &str) -> RtbfResult<()>;

    /// Batch tombstone payloads
    async fn batch_tombstone(&self, ref_ids: &[String], request_id: &str) -> RtbfResult<BatchTombstoneResult>;

    /// Check if payload exists
    async fn payload_exists(&self, ref_id: &str) -> RtbfResult<bool>;

    /// Get payload metadata (without decryption)
    async fn get_metadata(&self, ref_id: &str) -> RtbfResult<PayloadMetadataInfo>;
}

/// Result of batch tombstone operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchTombstoneResult {
    /// Successfully tombstoned
    pub tombstoned: Vec<String>,
    /// Failed to tombstone
    pub failed: Vec<TombstoneFailure>,
    /// Skipped (already tombstoned)
    pub skipped: Vec<String>,
}

/// Tombstone failure details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TombstoneFailure {
    /// Payload ref_id
    pub ref_id: String,
    /// Failure reason
    pub reason: String,
}

/// Payload metadata info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadMetadataInfo {
    /// Payload ref_id
    pub ref_id: String,
    /// Payload type
    pub payload_type: PayloadType,
    /// Associated subject
    pub subject_id: Option<ActorId>,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Is tombstoned
    pub is_tombstoned: bool,
}

/// Payload type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PayloadType {
    /// Resurrection snapshot
    Resurrection,
    /// Evidence bundle
    Evidence,
    /// Audit artifact
    Audit,
    /// Generic payload
    Generic,
}

/// RTBF Coordinator - orchestrates the RTBF workflow
pub struct RtbfCoordinator<L: RtbfLedgerInterface, S: RtbfStorageInterface> {
    /// P1 ledger interface
    ledger: Arc<L>,
    /// P2 storage interface
    storage: Arc<S>,
    /// Active requests
    active_requests: RwLock<HashMap<String, RtbfRequest>>,
    /// Configuration
    config: RtbfConfig,
    /// Audit callback
    audit_callback: Option<Arc<dyn Fn(&RtbfAuditEntry) + Send + Sync>>,
}

/// RTBF configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RtbfConfig {
    /// Maximum concurrent requests
    pub max_concurrent_requests: usize,
    /// Batch size for tombstoning
    pub tombstone_batch_size: usize,
    /// Enable dry run mode
    pub dry_run_mode: bool,
    /// Require explicit authorization
    pub require_authorization: bool,
    /// Evidence retention check enabled
    pub check_evidence_retention: bool,
    /// Request timeout (seconds)
    pub request_timeout_secs: u64,
}

impl Default for RtbfConfig {
    fn default() -> Self {
        Self {
            max_concurrent_requests: 10,
            tombstone_batch_size: 100,
            dry_run_mode: false,
            require_authorization: true,
            check_evidence_retention: true,
            request_timeout_secs: 3600, // 1 hour
        }
    }
}

/// RTBF audit entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RtbfAuditEntry {
    /// Entry ID
    pub entry_id: String,
    /// Request ID
    pub request_id: String,
    /// Subject ID
    pub subject_id: ActorId,
    /// Operation type
    pub operation: RtbfAuditOperation,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Details
    pub details: HashMap<String, String>,
    /// Entry hash (for chaining)
    pub entry_hash: Digest,
}

/// RTBF audit operation types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RtbfAuditOperation {
    /// Request received
    RequestReceived,
    /// Legal hold checked
    LegalHoldChecked { allowed: bool },
    /// Evidence retention checked
    EvidenceChecked { retained_count: usize },
    /// Payloads enumerated
    PayloadsEnumerated { count: usize },
    /// Tombstone started
    TombstoneStarted { batch_size: usize },
    /// Tombstone completed
    TombstoneCompleted { success_count: usize, failure_count: usize },
    /// Index updated
    IndexUpdated { count: usize },
    /// Request completed
    RequestCompleted { status: RtbfStatus },
    /// Request failed
    RequestFailed { error: String },
}

impl<L: RtbfLedgerInterface, S: RtbfStorageInterface> RtbfCoordinator<L, S> {
    /// Create a new RTBF coordinator
    pub fn new(ledger: Arc<L>, storage: Arc<S>, config: RtbfConfig) -> Self {
        Self {
            ledger,
            storage,
            active_requests: RwLock::new(HashMap::new()),
            config,
            audit_callback: None,
        }
    }

    /// Set audit callback
    pub fn with_audit_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(&RtbfAuditEntry) + Send + Sync + 'static,
    {
        self.audit_callback = Some(Arc::new(callback));
        self
    }

    /// Submit an RTBF request
    pub async fn submit_request(&self, mut request: RtbfRequest) -> RtbfResult<String> {
        // Check if request already exists
        let requests = self.active_requests.read().await;
        if requests.contains_key(&request.request_id) {
            return Err(RtbfError::RequestInProgress {
                request_id: request.request_id.clone(),
            });
        }
        drop(requests);

        // Check concurrent request limit
        let requests = self.active_requests.read().await;
        if requests.len() >= self.config.max_concurrent_requests {
            return Err(RtbfError::StorageError(
                "Maximum concurrent requests reached".to_string(),
            ));
        }
        drop(requests);

        // Log request received
        self.audit_log(RtbfAuditEntry {
            entry_id: format!("audit:{}", Uuid::new_v4()),
            request_id: request.request_id.clone(),
            subject_id: request.subject_id.clone(),
            operation: RtbfAuditOperation::RequestReceived,
            timestamp: Utc::now(),
            details: HashMap::new(),
            entry_hash: Digest::zero(),
        });

        request.status = RtbfStatus::Pending;
        let request_id = request.request_id.clone();

        // Store request
        let mut requests = self.active_requests.write().await;
        requests.insert(request_id.clone(), request);

        Ok(request_id)
    }

    /// Process an RTBF request
    pub async fn process_request(&self, request_id: &str) -> RtbfResult<RtbfResult_> {
        let start_time = std::time::Instant::now();

        // Get request
        let mut request = {
            let requests = self.active_requests.read().await;
            requests.get(request_id).cloned().ok_or_else(|| {
                RtbfError::SubjectNotFound {
                    subject_id: request_id.to_string(),
                }
            })?
        };

        // Check expiration
        if request.is_expired() {
            return Err(RtbfError::RequestExpired {
                request_id: request_id.to_string(),
            });
        }

        // Step 1: Check legal hold
        request.status = RtbfStatus::CheckingLegalHold;
        self.update_request(&request).await;

        let legal_hold_status = self.ledger.check_legal_hold(&request.subject_id).await?;

        self.audit_log(RtbfAuditEntry {
            entry_id: format!("audit:{}", Uuid::new_v4()),
            request_id: request_id.to_string(),
            subject_id: request.subject_id.clone(),
            operation: RtbfAuditOperation::LegalHoldChecked {
                allowed: legal_hold_status.rtbf_allowed,
            },
            timestamp: Utc::now(),
            details: HashMap::new(),
            entry_hash: Digest::zero(),
        });

        if !legal_hold_status.rtbf_allowed {
            request.status = RtbfStatus::BlockedByLegalHold;
            self.update_request(&request).await;

            return Ok(RtbfResult_ {
                request_id: request_id.to_string(),
                status: RtbfStatus::BlockedByLegalHold,
                tombstoned_count: 0,
                retained_count: 0,
                retained_reasons: legal_hold_status
                    .active_holds
                    .iter()
                    .map(|h| {
                        (
                            h.hold_id.clone(),
                            RetentionReason::LegalHold {
                                hold_id: h.hold_id.clone(),
                                case_id: h.case_id.clone(),
                            },
                        )
                    })
                    .collect(),
                processing_duration_ms: start_time.elapsed().as_millis() as u64,
                completed_at: Utc::now(),
                audit_log_id: format!("audit:{}", Uuid::new_v4()),
            });
        }

        // Step 2: Enumerate payloads
        request.status = RtbfStatus::EnumeratingPayloads;
        self.update_request(&request).await;

        let inventory = self.ledger.enumerate_payloads(&request.subject_id).await?;

        self.audit_log(RtbfAuditEntry {
            entry_id: format!("audit:{}", Uuid::new_v4()),
            request_id: request_id.to_string(),
            subject_id: request.subject_id.clone(),
            operation: RtbfAuditOperation::PayloadsEnumerated {
                count: inventory.total_count(),
            },
            timestamp: Utc::now(),
            details: HashMap::new(),
            entry_hash: Digest::zero(),
        });

        // Step 3: Filter based on scope and evidence retention
        request.status = RtbfStatus::CheckingEvidence;
        self.update_request(&request).await;

        let (refs_to_delete, retained_reasons) = self.filter_payloads(&request, &inventory).await?;

        self.audit_log(RtbfAuditEntry {
            entry_id: format!("audit:{}", Uuid::new_v4()),
            request_id: request_id.to_string(),
            subject_id: request.subject_id.clone(),
            operation: RtbfAuditOperation::EvidenceChecked {
                retained_count: retained_reasons.len(),
            },
            timestamp: Utc::now(),
            details: HashMap::new(),
            entry_hash: Digest::zero(),
        });

        // Step 4: Tombstone payloads (if not dry run)
        request.status = RtbfStatus::TombstoningPayloads;
        self.update_request(&request).await;

        let mut tombstoned_count = 0;
        let mut failures = Vec::new();

        if !self.config.dry_run_mode {
            // Process in batches
            for chunk in refs_to_delete.chunks(self.config.tombstone_batch_size) {
                let batch_result = self
                    .storage
                    .batch_tombstone(chunk, request_id)
                    .await?;

                tombstoned_count += batch_result.tombstoned.len();
                failures.extend(batch_result.failed);
            }
        } else {
            tombstoned_count = refs_to_delete.len();
        }

        self.audit_log(RtbfAuditEntry {
            entry_id: format!("audit:{}", Uuid::new_v4()),
            request_id: request_id.to_string(),
            subject_id: request.subject_id.clone(),
            operation: RtbfAuditOperation::TombstoneCompleted {
                success_count: tombstoned_count,
                failure_count: failures.len(),
            },
            timestamp: Utc::now(),
            details: HashMap::new(),
            entry_hash: Digest::zero(),
        });

        // Step 5: Update P1 index
        request.status = RtbfStatus::UpdatingIndex;
        self.update_request(&request).await;

        if !self.config.dry_run_mode {
            self.ledger.mark_deleted(&refs_to_delete, request_id).await?;
        }

        self.audit_log(RtbfAuditEntry {
            entry_id: format!("audit:{}", Uuid::new_v4()),
            request_id: request_id.to_string(),
            subject_id: request.subject_id.clone(),
            operation: RtbfAuditOperation::IndexUpdated {
                count: refs_to_delete.len(),
            },
            timestamp: Utc::now(),
            details: HashMap::new(),
            entry_hash: Digest::zero(),
        });

        // Determine final status
        let final_status = if retained_reasons.is_empty() && failures.is_empty() {
            RtbfStatus::Completed
        } else {
            RtbfStatus::PartiallyCompleted
        };

        request.status = final_status;
        self.update_request(&request).await;

        let result = RtbfResult_ {
            request_id: request_id.to_string(),
            status: final_status,
            tombstoned_count,
            retained_count: retained_reasons.len(),
            retained_reasons,
            processing_duration_ms: start_time.elapsed().as_millis() as u64,
            completed_at: Utc::now(),
            audit_log_id: format!("audit:{}", Uuid::new_v4()),
        };

        // Record completion
        if !self.config.dry_run_mode {
            self.ledger.record_rtbf_completion(&result).await?;
        }

        self.audit_log(RtbfAuditEntry {
            entry_id: format!("audit:{}", Uuid::new_v4()),
            request_id: request_id.to_string(),
            subject_id: request.subject_id.clone(),
            operation: RtbfAuditOperation::RequestCompleted { status: final_status },
            timestamp: Utc::now(),
            details: HashMap::new(),
            entry_hash: Digest::zero(),
        });

        // Remove from active requests
        let mut requests = self.active_requests.write().await;
        requests.remove(request_id);

        Ok(result)
    }

    /// Filter payloads based on scope and retention rules
    async fn filter_payloads(
        &self,
        request: &RtbfRequest,
        inventory: &PayloadInventory,
    ) -> RtbfResult<(Vec<String>, HashMap<String, RetentionReason>)> {
        let mut to_delete = Vec::new();
        let mut retained = HashMap::new();

        // Process based on scope
        match &request.scope {
            RtbfScope::Full => {
                // Include all payloads
                to_delete.extend(inventory.resurrection_refs.clone());
                to_delete.extend(inventory.other_refs.clone());

                // Evidence may be retained
                if self.config.check_evidence_retention {
                    for ref_id in &inventory.evidence_refs {
                        // Check if evidence is in active case
                        // For now, retain all evidence as potentially active
                        retained.insert(
                            ref_id.clone(),
                            RetentionReason::ActiveEvidence {
                                case_id: "pending_check".to_string(),
                            },
                        );
                    }
                } else {
                    to_delete.extend(inventory.evidence_refs.clone());
                }

                // Audit logs are typically retained for compliance
                for ref_id in &inventory.audit_refs {
                    retained.insert(
                        ref_id.clone(),
                        RetentionReason::RegulatoryRetention {
                            regulation: "audit_retention".to_string(),
                            until: Utc::now() + Duration::days(365 * 7), // 7-year retention
                        },
                    );
                }
            }
            RtbfScope::Selective {
                include_resurrection,
                include_evidence,
                include_audit,
                specific_payloads,
            } => {
                if *include_resurrection {
                    to_delete.extend(inventory.resurrection_refs.clone());
                }
                if *include_evidence {
                    to_delete.extend(inventory.evidence_refs.clone());
                }
                if *include_audit {
                    to_delete.extend(inventory.audit_refs.clone());
                }
                to_delete.extend(specific_payloads.clone());
            }
            RtbfScope::Temporal { before } => {
                // Would need to check timestamps - simplified for now
                for ref_id in inventory.all_refs() {
                    if let Ok(metadata) = self.storage.get_metadata(ref_id).await {
                        if metadata.created_at < *before {
                            to_delete.push(ref_id.clone());
                        }
                    }
                }
            }
        }

        // Remove retained items from delete list
        let retained_set: HashSet<_> = retained.keys().cloned().collect();
        to_delete.retain(|ref_id| !retained_set.contains(ref_id));

        Ok((to_delete, retained))
    }

    /// Update request in storage
    async fn update_request(&self, request: &RtbfRequest) {
        let mut requests = self.active_requests.write().await;
        requests.insert(request.request_id.clone(), request.clone());
    }

    /// Log audit entry
    fn audit_log(&self, entry: RtbfAuditEntry) {
        if let Some(callback) = &self.audit_callback {
            callback(&entry);
        }
        tracing::info!(
            request_id = %entry.request_id,
            operation = ?entry.operation,
            "RTBF audit log"
        );
    }

    /// Get request status
    pub async fn get_request_status(&self, request_id: &str) -> Option<RtbfStatus> {
        let requests = self.active_requests.read().await;
        requests.get(request_id).map(|r| r.status)
    }

    /// List active requests for a subject
    pub async fn list_requests_for_subject(&self, subject_id: &ActorId) -> Vec<RtbfRequest> {
        let requests = self.active_requests.read().await;
        requests
            .values()
            .filter(|r| &r.subject_id == subject_id)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtbf_request_creation() {
        let subject = ActorId::new("subject:alice");
        let requestor = ActorId::new("requestor:alice");

        let request = RtbfRequest::new(
            subject.clone(),
            requestor,
            RtbfScope::Full,
            RtbfReason::GdprRequest,
        );

        assert!(request.request_id.starts_with("rtbf:"));
        assert_eq!(request.subject_id, subject);
        assert_eq!(request.status, RtbfStatus::Pending);
        assert!(!request.is_expired());
        assert!(!request.is_terminal());
    }

    #[test]
    fn test_rtbf_scope_selective() {
        let scope = RtbfScope::Selective {
            include_resurrection: true,
            include_evidence: false,
            include_audit: false,
            specific_payloads: vec!["payload:123".to_string()],
        };

        if let RtbfScope::Selective { include_resurrection, .. } = scope {
            assert!(include_resurrection);
        }
    }

    #[test]
    fn test_payload_inventory() {
        let inventory = PayloadInventory {
            subject_id: ActorId::new("subject:test"),
            resurrection_refs: vec!["r0:1".to_string(), "r1:1".to_string()],
            evidence_refs: vec!["ev:1".to_string()],
            audit_refs: vec!["audit:1".to_string()],
            other_refs: vec![],
            enumerated_at: Utc::now(),
        };

        assert_eq!(inventory.total_count(), 4);
        assert_eq!(inventory.all_refs().len(), 4);
    }

    #[test]
    fn test_rtbf_config_default() {
        let config = RtbfConfig::default();
        assert_eq!(config.max_concurrent_requests, 10);
        assert_eq!(config.tombstone_batch_size, 100);
        assert!(!config.dry_run_mode);
        assert!(config.require_authorization);
    }
}
