//! TipWitness Service Implementation
//!
//! Implements the TipWitness functionality for anti-history-rewrite protection.
//! Every actor MUST submit a TipWitness when going online.
//! TipWitness is mandatory and free (no fee).

use chrono::Utc;
use l0_core::error::LedgerError;
use l0_core::ledger::LedgerResult;
use l0_core::types::{ActorId, Digest, ReceiptId, RootKind, ScopeType, L0Receipt, TipWitness};
use soulbase_types::prelude::TenantId;
use std::sync::Arc;

use crate::entities::TipWitnessEntity;
use crate::error::L0DbError;
use crate::repos::L0Database;

/// TipWitness Service
///
/// Manages TipWitness operations for anti-history-rewrite protection.
/// Key properties:
/// - Mandatory: Every actor must submit when going online
/// - Free: No fee charged for TipWitness
/// - Immutable: Once submitted, cannot be modified
pub struct TipWitnessService {
    database: Arc<L0Database>,
    tenant_id: TenantId,
}

impl TipWitnessService {
    /// Create a new TipWitness Service
    pub fn new(database: Arc<L0Database>, tenant_id: TenantId) -> Self {
        Self { database, tenant_id }
    }

    /// Convert database error to ledger error
    fn map_db_error(e: L0DbError) -> LedgerError {
        LedgerError::Storage(e.to_string())
    }

    /// Submit a TipWitness for an actor (mandatory, free)
    ///
    /// This creates an immutable reference point that prevents later claims
    /// of different history. Should be called when actor goes online.
    pub async fn submit_tip_witness(
        &self,
        actor_id: &ActorId,
        local_tip_digest: Digest,
        local_sequence_no: u64,
        last_known_receipt_ref: Option<String>,
    ) -> LedgerResult<TipWitnessSubmission> {
        // Validate sequence continuity
        let latest = self
            .get_latest_tip_witness(actor_id)
            .await?;

        if let Some(ref prev) = latest {
            // Sequence must be greater than or equal to previous
            if local_sequence_no < prev.local_sequence_no {
                return Err(LedgerError::Validation(format!(
                    "TipWitness sequence {} is less than previous {}",
                    local_sequence_no, prev.local_sequence_no
                )));
            }

            // If sequence is equal, digest must match (no rewrite allowed)
            if local_sequence_no == prev.local_sequence_no
                && prev.local_tip_digest != local_tip_digest.to_hex()
            {
                return Err(LedgerError::Validation(
                    "TipWitness with same sequence has different digest (history rewrite detected)"
                        .to_string(),
                ));
            }
        }

        // Generate TipWitness ID
        let tip_witness_id = format!(
            "tip:{}:{}:{}",
            actor_id.0,
            local_sequence_no,
            Utc::now().timestamp_micros()
        );

        // Create entity
        let entity = TipWitnessEntity {
            id: format!("l0_tip_witness:{}:{}", self.tenant_id.0, tip_witness_id),
            tenant_id: self.tenant_id.clone(),
            tip_witness_id: tip_witness_id.clone(),
            actor_id: actor_id.0.clone(),
            local_tip_digest: local_tip_digest.to_hex(),
            local_sequence_no,
            last_known_receipt_ref: last_known_receipt_ref.clone(),
            witnessed_at: Utc::now(),
            receipt_id: None, // Will be set after receipt generation
        };

        // Store TipWitness
        let created = self
            .database
            .receipts
            .create_tip_witness(&entity)
            .await
            .map_err(Self::map_db_error)?;

        // Generate receipt (TipWitness always gets a receipt, free of charge)
        let receipt = self.generate_tip_witness_receipt(&created).await?;

        // Update TipWitness with receipt ID
        // Note: In a full implementation, we would update the entity here

        Ok(TipWitnessSubmission {
            tip_witness: TipWitness {
                tip_witness_id: created.tip_witness_id,
                actor_id: actor_id.clone(),
                local_tip_digest,
                local_sequence_no,
                last_known_receipt_ref,
                witnessed_at: created.witnessed_at,
                receipt_id: Some(receipt.receipt_id.clone()),
            },
            receipt,
            is_first_witness: latest.is_none(),
        })
    }

    /// Get latest TipWitness for an actor
    pub async fn get_latest_tip_witness(
        &self,
        actor_id: &ActorId,
    ) -> LedgerResult<Option<TipWitnessEntity>> {
        self.database
            .receipts
            .get_latest_tip_witness(&self.tenant_id, &actor_id.0)
            .await
            .map_err(Self::map_db_error)
    }

    /// Get TipWitness history for an actor
    pub async fn get_tip_witness_history(
        &self,
        actor_id: &ActorId,
        limit: u32,
    ) -> LedgerResult<Vec<TipWitness>> {
        let entities = self
            .database
            .receipts
            .get_tip_witness_history(&self.tenant_id, &actor_id.0, limit)
            .await
            .map_err(Self::map_db_error)?;

        Ok(entities
            .into_iter()
            .map(|e| TipWitness {
                tip_witness_id: e.tip_witness_id,
                actor_id: ActorId(e.actor_id),
                local_tip_digest: Digest::from_hex(&e.local_tip_digest).unwrap_or_default(),
                local_sequence_no: e.local_sequence_no,
                last_known_receipt_ref: e.last_known_receipt_ref,
                witnessed_at: e.witnessed_at,
                receipt_id: e.receipt_id.map(ReceiptId),
            })
            .collect())
    }

    /// Verify TipWitness chain continuity for an actor
    pub async fn verify_tip_witness_chain(
        &self,
        actor_id: &ActorId,
    ) -> LedgerResult<TipWitnessChainVerification> {
        let history = self.get_tip_witness_history(actor_id, 1000).await?;

        if history.is_empty() {
            return Ok(TipWitnessChainVerification {
                is_valid: true,
                witness_count: 0,
                earliest_sequence: None,
                latest_sequence: None,
                gaps: vec![],
            });
        }

        let mut gaps = Vec::new();
        let mut is_valid = true;

        // Check for gaps in sequence
        for i in 1..history.len() {
            let prev = &history[i]; // Note: history is in reverse order (newest first)
            let curr = &history[i - 1];

            if prev.local_sequence_no > curr.local_sequence_no {
                is_valid = false;
                gaps.push(TipWitnessGap {
                    from_sequence: curr.local_sequence_no,
                    to_sequence: prev.local_sequence_no,
                    gap_type: "sequence_violation".to_string(),
                });
            }
        }

        let earliest = history.last().map(|w| w.local_sequence_no);
        let latest = history.first().map(|w| w.local_sequence_no);

        Ok(TipWitnessChainVerification {
            is_valid,
            witness_count: history.len() as u64,
            earliest_sequence: earliest,
            latest_sequence: latest,
            gaps,
        })
    }

    /// Generate a receipt for a TipWitness (always free)
    async fn generate_tip_witness_receipt(
        &self,
        tip_witness: &TipWitnessEntity,
    ) -> LedgerResult<L0Receipt> {
        let receipt_id = ReceiptId(format!(
            "receipt:tip:{}",
            tip_witness.tip_witness_id
        ));

        let digest = Digest::from_hex(&tip_witness.local_tip_digest)
            .unwrap_or_default();

        Ok(L0Receipt {
            receipt_id: receipt_id.clone(),
            scope_type: ScopeType::IdentityBatch, // TipWitness is an identity operation
            root_kind: RootKind::BatchRoot, // TipWitness uses batch root
            root: digest,
            time_window_start: tip_witness.witnessed_at,
            time_window_end: tip_witness.witnessed_at,
            batch_sequence_no: Some(tip_witness.local_sequence_no),
            signer_set_version: "v1".to_string(),
            canonicalization_version: "v1".to_string(),
            anchor_policy_version: "v1".to_string(),
            fee_schedule_version: "v1".to_string(),
            fee_receipt_id: "free:tipwitness".to_string(), // TipWitness is free
            signed_snapshot_ref: tip_witness.tip_witness_id.clone(),
            created_at: Utc::now(),
            rejected: None,
            reject_reason_code: None,
            observer_reports_digest: None,
        })
    }
}

/// Result of submitting a TipWitness
#[derive(Debug, Clone)]
pub struct TipWitnessSubmission {
    /// The created TipWitness
    pub tip_witness: TipWitness,
    /// The receipt for this TipWitness (always issued, free)
    pub receipt: L0Receipt,
    /// Whether this is the actor's first TipWitness
    pub is_first_witness: bool,
}

/// Result of TipWitness chain verification
#[derive(Debug, Clone)]
pub struct TipWitnessChainVerification {
    /// Is the chain valid?
    pub is_valid: bool,
    /// Number of witnesses in the chain
    pub witness_count: u64,
    /// Earliest sequence number
    pub earliest_sequence: Option<u64>,
    /// Latest sequence number
    pub latest_sequence: Option<u64>,
    /// Any gaps found
    pub gaps: Vec<TipWitnessGap>,
}

/// A gap in the TipWitness chain
#[derive(Debug, Clone)]
pub struct TipWitnessGap {
    pub from_sequence: u64,
    pub to_sequence: u64,
    pub gap_type: String,
}

/// History rewrite alert
#[derive(Debug, Clone)]
pub struct HistoryRewriteAlert {
    /// Actor ID that attempted rewrite
    pub actor_id: ActorId,
    /// Alert type
    pub alert_type: HistoryRewriteAlertType,
    /// The conflicting TipWitness
    pub conflicting_witness: Option<TipWitness>,
    /// Expected value
    pub expected: String,
    /// Actual value received
    pub actual: String,
    /// Timestamp of detection
    pub detected_at: chrono::DateTime<Utc>,
    /// Severity level (1-5, 5 being most severe)
    pub severity: u8,
}

/// Type of history rewrite alert
#[derive(Debug, Clone, PartialEq)]
pub enum HistoryRewriteAlertType {
    /// Same sequence but different digest
    DigestMismatch,
    /// Sequence went backwards
    SequenceRegression,
    /// Gap in sequence chain
    SequenceGap,
    /// L1/L2 cross-layer mismatch
    CrossLayerMismatch,
    /// Receipt reference mismatch
    ReceiptReferenceMismatch,
}

impl std::fmt::Display for HistoryRewriteAlertType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DigestMismatch => write!(f, "DIGEST_MISMATCH"),
            Self::SequenceRegression => write!(f, "SEQUENCE_REGRESSION"),
            Self::SequenceGap => write!(f, "SEQUENCE_GAP"),
            Self::CrossLayerMismatch => write!(f, "CROSS_LAYER_MISMATCH"),
            Self::ReceiptReferenceMismatch => write!(f, "RECEIPT_REFERENCE_MISMATCH"),
        }
    }
}

/// L1/L2 witness reference for cross-layer verification
#[derive(Debug, Clone)]
pub struct CrossLayerWitnessRef {
    /// Layer identifier (L1 or L2)
    pub layer: String,
    /// Witness ID from that layer
    pub witness_id: String,
    /// Digest at that layer
    pub layer_digest: Digest,
    /// Sequence number at that layer
    pub layer_sequence: u64,
    /// Timestamp when witnessed
    pub witnessed_at: chrono::DateTime<Utc>,
}

impl TipWitnessService {
    /// Detect history rewrite attempts with enhanced validation
    ///
    /// This performs comprehensive anti-history-rewrite checks including:
    /// 1. Sequence number validation
    /// 2. Digest consistency check
    /// 3. Receipt reference validation
    /// 4. Cross-layer verification (if L1/L2 refs provided)
    pub async fn detect_history_rewrite(
        &self,
        actor_id: &ActorId,
        claimed_digest: Digest,
        claimed_sequence: u64,
        claimed_receipt_ref: Option<String>,
        l1_witness_ref: Option<CrossLayerWitnessRef>,
        l2_witness_ref: Option<CrossLayerWitnessRef>,
    ) -> LedgerResult<Vec<HistoryRewriteAlert>> {
        let mut alerts = Vec::new();
        let now = Utc::now();

        // Get latest known TipWitness
        let latest = self.get_latest_tip_witness(actor_id).await?;

        if let Some(ref prev) = latest {
            // Check 1: Sequence regression
            if claimed_sequence < prev.local_sequence_no {
                alerts.push(HistoryRewriteAlert {
                    actor_id: actor_id.clone(),
                    alert_type: HistoryRewriteAlertType::SequenceRegression,
                    conflicting_witness: Some(self.entity_to_tip_witness(prev)),
                    expected: format!("sequence >= {}", prev.local_sequence_no),
                    actual: format!("sequence = {}", claimed_sequence),
                    detected_at: now,
                    severity: 5, // Most severe - definite rewrite attempt
                });
            }

            // Check 2: Same sequence, different digest (history rewrite)
            if claimed_sequence == prev.local_sequence_no {
                let prev_digest = Digest::from_hex(&prev.local_tip_digest).unwrap_or_default();
                if prev_digest != claimed_digest {
                    alerts.push(HistoryRewriteAlert {
                        actor_id: actor_id.clone(),
                        alert_type: HistoryRewriteAlertType::DigestMismatch,
                        conflicting_witness: Some(self.entity_to_tip_witness(prev)),
                        expected: prev.local_tip_digest.clone(),
                        actual: claimed_digest.to_hex(),
                        detected_at: now,
                        severity: 5, // Most severe - definite rewrite attempt
                    });
                }
            }

            // Check 3: Large sequence gap (suspicious)
            if claimed_sequence > prev.local_sequence_no + 1000 {
                alerts.push(HistoryRewriteAlert {
                    actor_id: actor_id.clone(),
                    alert_type: HistoryRewriteAlertType::SequenceGap,
                    conflicting_witness: Some(self.entity_to_tip_witness(prev)),
                    expected: format!("sequence close to {}", prev.local_sequence_no),
                    actual: format!("sequence = {} (gap of {})",
                        claimed_sequence,
                        claimed_sequence - prev.local_sequence_no),
                    detected_at: now,
                    severity: 3, // Medium - suspicious but not definite
                });
            }

            // Check 4: Receipt reference mismatch
            if let (Some(ref claimed_ref), Some(ref prev_ref)) =
                (&claimed_receipt_ref, &prev.last_known_receipt_ref)
            {
                // If claiming an earlier receipt than previously known, suspicious
                if claimed_ref < prev_ref {
                    alerts.push(HistoryRewriteAlert {
                        actor_id: actor_id.clone(),
                        alert_type: HistoryRewriteAlertType::ReceiptReferenceMismatch,
                        conflicting_witness: Some(self.entity_to_tip_witness(prev)),
                        expected: format!("receipt_ref >= {}", prev_ref),
                        actual: claimed_ref.clone(),
                        detected_at: now,
                        severity: 4,
                    });
                }
            }
        }

        // Check 5: L1/L2 cross-layer verification
        if let Some(l1_ref) = l1_witness_ref {
            let l1_alerts = self.verify_cross_layer_witness(
                actor_id,
                &claimed_digest,
                claimed_sequence,
                &l1_ref,
            ).await?;
            alerts.extend(l1_alerts);
        }

        if let Some(l2_ref) = l2_witness_ref {
            let l2_alerts = self.verify_cross_layer_witness(
                actor_id,
                &claimed_digest,
                claimed_sequence,
                &l2_ref,
            ).await?;
            alerts.extend(l2_alerts);
        }

        // Sort by severity (highest first)
        alerts.sort_by(|a, b| b.severity.cmp(&a.severity));

        Ok(alerts)
    }

    /// Verify cross-layer witness consistency
    async fn verify_cross_layer_witness(
        &self,
        actor_id: &ActorId,
        claimed_digest: &Digest,
        claimed_sequence: u64,
        layer_ref: &CrossLayerWitnessRef,
    ) -> LedgerResult<Vec<HistoryRewriteAlert>> {
        let mut alerts = Vec::new();
        let now = Utc::now();

        // The L0 sequence should be >= the layer's witnessed sequence
        // (L0 is the source of truth, layers witness L0 state)
        if claimed_sequence < layer_ref.layer_sequence {
            alerts.push(HistoryRewriteAlert {
                actor_id: actor_id.clone(),
                alert_type: HistoryRewriteAlertType::CrossLayerMismatch,
                conflicting_witness: None,
                expected: format!(
                    "{} witnessed sequence {} at {}",
                    layer_ref.layer,
                    layer_ref.layer_sequence,
                    layer_ref.witnessed_at
                ),
                actual: format!("L0 claiming sequence {}", claimed_sequence),
                detected_at: now,
                severity: 5, // Severe - cross-layer inconsistency
            });
        }

        // If same sequence, digest must match what layer witnessed
        if claimed_sequence == layer_ref.layer_sequence
            && *claimed_digest != layer_ref.layer_digest
        {
            alerts.push(HistoryRewriteAlert {
                actor_id: actor_id.clone(),
                alert_type: HistoryRewriteAlertType::CrossLayerMismatch,
                conflicting_witness: None,
                expected: format!(
                    "{} witnessed digest {} for sequence {}",
                    layer_ref.layer,
                    layer_ref.layer_digest.to_hex(),
                    layer_ref.layer_sequence
                ),
                actual: format!("L0 claiming digest {}", claimed_digest.to_hex()),
                detected_at: now,
                severity: 5,
            });
        }

        Ok(alerts)
    }

    /// Convert entity to TipWitness
    fn entity_to_tip_witness(&self, entity: &TipWitnessEntity) -> TipWitness {
        TipWitness {
            tip_witness_id: entity.tip_witness_id.clone(),
            actor_id: ActorId(entity.actor_id.clone()),
            local_tip_digest: Digest::from_hex(&entity.local_tip_digest).unwrap_or_default(),
            local_sequence_no: entity.local_sequence_no,
            last_known_receipt_ref: entity.last_known_receipt_ref.clone(),
            witnessed_at: entity.witnessed_at,
            receipt_id: entity.receipt_id.clone().map(ReceiptId),
        }
    }

    /// Verify the complete TipWitness chain including L1/L2 references
    pub async fn verify_complete_witness_chain(
        &self,
        actor_id: &ActorId,
        l1_witnesses: Vec<CrossLayerWitnessRef>,
        l2_witnesses: Vec<CrossLayerWitnessRef>,
    ) -> LedgerResult<CompleteChainVerification> {
        // First verify local chain
        let local_verification = self.verify_tip_witness_chain(actor_id).await?;

        // Get full history for cross-layer checks
        let history = self.get_tip_witness_history(actor_id, 10000).await?;

        let mut cross_layer_issues = Vec::new();

        // Verify L1 witnesses against L0 history
        for l1_ref in &l1_witnesses {
            // Find corresponding L0 witness
            let matching_l0 = history.iter().find(|w|
                w.local_sequence_no == l1_ref.layer_sequence
            );

            if let Some(l0_witness) = matching_l0 {
                if l0_witness.local_tip_digest != l1_ref.layer_digest {
                    cross_layer_issues.push(format!(
                        "L1 witness {} has digest {} but L0 has {} for sequence {}",
                        l1_ref.witness_id,
                        l1_ref.layer_digest.to_hex(),
                        l0_witness.local_tip_digest.to_hex(),
                        l1_ref.layer_sequence
                    ));
                }
            } else {
                cross_layer_issues.push(format!(
                    "L1 witnessed sequence {} not found in L0 history",
                    l1_ref.layer_sequence
                ));
            }
        }

        // Verify L2 witnesses against L0 history
        for l2_ref in &l2_witnesses {
            let matching_l0 = history.iter().find(|w|
                w.local_sequence_no == l2_ref.layer_sequence
            );

            if let Some(l0_witness) = matching_l0 {
                if l0_witness.local_tip_digest != l2_ref.layer_digest {
                    cross_layer_issues.push(format!(
                        "L2 witness {} has digest {} but L0 has {} for sequence {}",
                        l2_ref.witness_id,
                        l2_ref.layer_digest.to_hex(),
                        l0_witness.local_tip_digest.to_hex(),
                        l2_ref.layer_sequence
                    ));
                }
            } else {
                cross_layer_issues.push(format!(
                    "L2 witnessed sequence {} not found in L0 history",
                    l2_ref.layer_sequence
                ));
            }
        }

        let is_fully_valid = local_verification.is_valid && cross_layer_issues.is_empty();

        Ok(CompleteChainVerification {
            local_chain: local_verification,
            l1_witness_count: l1_witnesses.len() as u64,
            l2_witness_count: l2_witnesses.len() as u64,
            cross_layer_issues,
            is_fully_valid,
        })
    }
}

/// Complete chain verification result including cross-layer checks
#[derive(Debug, Clone)]
pub struct CompleteChainVerification {
    /// Local L0 chain verification
    pub local_chain: TipWitnessChainVerification,
    /// Number of L1 witnesses verified
    pub l1_witness_count: u64,
    /// Number of L2 witnesses verified
    pub l2_witness_count: u64,
    /// Any cross-layer consistency issues found
    pub cross_layer_issues: Vec<String>,
    /// Is the complete chain (L0 + L1 + L2) valid?
    pub is_fully_valid: bool,
}
