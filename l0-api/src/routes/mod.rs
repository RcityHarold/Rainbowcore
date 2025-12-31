//! API route handlers

pub mod actor;
pub mod anchor;
pub mod backfill;
pub mod commitment;
pub mod consent;
pub mod dispute;
pub mod health;
pub mod knowledge;
pub mod receipt;

use axum::{routing::get, routing::post, Router};

use crate::state::AppState;

/// Create the API router
pub fn create_router(state: AppState) -> Router {
    Router::new()
        // Health endpoints
        .route("/health", get(health::health_check))
        .route("/ready", get(health::ready_check))
        // Actor endpoints
        .route("/actors", post(actor::register_actor))
        .route("/actors/:actor_id", get(actor::get_actor))
        .route("/actors/:actor_id/status", post(actor::update_status))
        .route("/actors/by-pubkey/:pubkey", get(actor::get_actor_by_pubkey))
        // Commitment endpoints
        .route("/commitments", post(commitment::submit_commitment))
        .route("/commitments/:commitment_id", get(commitment::get_commitment))
        .route("/commitments/actor/:actor_id", get(commitment::get_commitment_chain))
        .route("/commitments/:commitment_id/verify", get(commitment::verify_chain))
        // Batch endpoints
        .route("/batches/:sequence", get(commitment::get_batch_snapshot))
        // Knowledge endpoints
        .route("/knowledge", post(knowledge::index_content))
        .route("/knowledge/:entry_id", get(knowledge::get_entry))
        .route("/knowledge/digest/:digest", get(knowledge::get_entries_by_digest))
        .route("/knowledge/space/:space_id", get(knowledge::get_entries_by_space))
        .route("/knowledge/actor/:actor_id", get(knowledge::get_entries_by_actor))
        .route("/knowledge/crossrefs", post(knowledge::create_cross_reference))
        .route("/knowledge/crossrefs/:digest/:direction", get(knowledge::get_cross_references))
        // Consent endpoints
        .route("/consents", post(consent::grant_consent))
        .route("/consents/verify", post(consent::verify_consent))
        .route("/consents/:consent_id", get(consent::get_consent))
        .route("/consents/:consent_id/revoke", post(consent::revoke_consent))
        .route("/consents/grantor/:grantor_id", get(consent::list_granted_consents))
        .route("/consents/grantee/:grantee_id", get(consent::list_received_consents))
        .route("/tickets", post(consent::issue_ticket))
        .route("/tickets/:ticket_id", get(consent::get_ticket))
        .route("/tickets/:ticket_id/use", post(consent::use_ticket))
        // Dispute endpoints
        .route("/disputes", post(dispute::file_dispute))
        .route("/disputes", get(dispute::list_disputes))
        .route("/disputes/:dispute_id", get(dispute::get_dispute))
        .route("/disputes/:dispute_id/status", post(dispute::update_dispute_status))
        .route("/disputes/:dispute_id/verdict", post(dispute::issue_verdict))
        .route("/disputes/:dispute_id/verdict", get(dispute::get_verdict_for_dispute))
        .route("/disputes/actor/:actor_id/:role", get(dispute::list_disputes_for_actor))
        .route("/verdicts/:verdict_id", get(dispute::get_verdict))
        .route("/clawbacks", post(dispute::initiate_clawback))
        .route("/clawbacks", get(dispute::list_clawbacks))
        .route("/clawbacks/:clawback_id", get(dispute::get_clawback))
        .route("/clawbacks/:clawback_id/execute", post(dispute::execute_clawback))
        // Receipt endpoints
        .route("/receipts", post(receipt::create_receipt))
        .route("/receipts", get(receipt::list_receipts))
        .route("/receipts/:receipt_id", get(receipt::get_receipt))
        .route("/receipts/:receipt_id/verify", get(receipt::verify_receipt))
        .route("/receipts/:receipt_id/reject", post(receipt::reject_receipt))
        .route("/receipts/batch/:batch_sequence", get(receipt::get_receipts_by_batch))
        // Fee endpoints
        .route("/fees", post(receipt::charge_fee))
        .route("/fees/:fee_receipt_id", get(receipt::get_fee_receipt))
        .route("/fees/:fee_receipt_id/status", post(receipt::update_fee_status))
        .route("/fees/:fee_receipt_id/refund", post(receipt::refund_fee))
        .route("/fees/actor/:actor_id/pending", get(receipt::get_pending_fees))
        .route("/fees/actor/:actor_id/history", get(receipt::get_fee_history))
        // TipWitness endpoints
        .route("/tipwitness", post(receipt::submit_tip_witness))
        .route("/tipwitness/:actor_id", get(receipt::get_latest_tip_witness))
        .route("/tipwitness/:actor_id/history", get(receipt::get_tip_witness_history))
        .route("/tipwitness/:actor_id/verify", get(receipt::verify_tip_witness_chain))
        // Backfill endpoints
        .route("/backfill", post(backfill::create_request))
        .route("/backfill/:request_id", get(backfill::get_request))
        .route("/backfill/actor/:actor_id", get(backfill::list_requests))
        .route("/backfill/:request_id/plan", post(backfill::generate_plan))
        .route("/backfill/plan/:plan_id/execute", post(backfill::execute_plan))
        .route("/backfill/:request_id/cancel", post(backfill::cancel_request))
        .route("/backfill/actor/:actor_id/gaps", get(backfill::detect_gaps))
        .route("/backfill/actor/:actor_id/continuity", get(backfill::verify_continuity))
        .route("/backfill/actor/:actor_id/history", get(backfill::get_history))
        // Anchor endpoints
        .route("/anchors", post(anchor::create_anchor))
        .route("/anchors/pending", get(anchor::get_pending_anchors))
        .route("/anchors/policy", get(anchor::get_policy))
        .route("/anchors/policy", post(anchor::update_policy))
        .route("/anchors/:anchor_id", get(anchor::get_anchor))
        .route("/anchors/:anchor_id/submit", post(anchor::submit_anchor))
        .route("/anchors/:anchor_id/status", get(anchor::check_status))
        .route("/anchors/:anchor_id/status", post(anchor::update_status))
        .route("/anchors/:anchor_id/verify", get(anchor::verify_anchor))
        .route("/anchors/:anchor_id/retry", post(anchor::retry_anchor))
        .route("/anchors/chain/:chain_type/epoch/:epoch_sequence", get(anchor::get_anchor_by_epoch))
        .route("/anchors/chain/:chain_type/finalized", get(anchor::get_finalized_anchors))
        .route("/anchors/chain/:chain_type/history", get(anchor::get_anchor_history))
        .route("/anchors/chain/:chain_type/latest-epoch", get(anchor::get_latest_finalized_epoch))
        // State
        .with_state(state)
}
