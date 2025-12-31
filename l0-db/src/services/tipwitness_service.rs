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
