# L0 Public Reality Ledger API Documentation

## Overview

The L0 API provides a RESTful interface for interacting with the L0 Public Reality Ledger (零明文公信层). This document describes all available endpoints, their request/response formats, and usage examples.

**Base URL**: `http://localhost:3000` (default)

**Content-Type**: `application/json`

---

## Table of Contents

1. [Health & Status](#health--status)
2. [Actor Management](#actor-management)
3. [Commitment Management](#commitment-management)
4. [Knowledge-Index Ledger](#knowledge-index-ledger)
5. [Policy-Consent Ledger](#policy-consent-ledger)
6. [Dispute-Resolution Ledger](#dispute-resolution-ledger)
7. [Receipt Management](#receipt-management)
8. [Fee Management](#fee-management)
9. [TipWitness Management](#tipwitness-management)
10. [Backfill Management](#backfill-management)
11. [Chain Anchoring](#chain-anchoring)

---

## Health & Status

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "node_id": "node_abc123",
  "current_batch_sequence": 1234,
  "current_epoch_sequence": 12
}
```

### GET /ready

Readiness check endpoint.

**Response:**
```json
{
  "status": "ready"
}
```

---

## Actor Management

### POST /actors

Register a new actor in the Identity Ledger.

**Request:**
```json
{
  "actor_type": "human_actor",
  "public_key": "ed25519_public_key_hex",
  "node_actor_id": "node_actor_id"
}
```

**Actor Types:**
- `human_actor` - Human user
- `ai_actor` - AI agent
- `node_actor` - Network node
- `group_actor` - Group/organization

**Response:**
```json
{
  "actor_id": "actor_abc123",
  "actor_type": "human_actor",
  "node_actor_id": "node_xyz",
  "public_key": "ed25519_public_key_hex",
  "status": "active",
  "created_at": "2025-01-01T00:00:00Z",
  "updated_at": "2025-01-01T00:00:00Z"
}
```

### GET /actors/:actor_id

Get actor by ID.

**Response:** Same as POST /actors response.

### GET /actors/by-pubkey/:pubkey

Get actor by public key.

**Response:** Same as POST /actors response.

### POST /actors/:actor_id/status

Update actor status.

**Request:**
```json
{
  "status": "suspended",
  "reason_digest": "optional_hex_digest"
}
```

**Status Values:**
- `active` - Actor is active
- `suspended` - Temporarily suspended
- `in_repair` - Under dispute repair
- `terminated` - Permanently terminated

**Response:**
```json
{
  "receipt_id": "receipt_abc123",
  "status": "suspended"
}
```

---

## Commitment Management

### POST /commitments

Submit a new commitment to the Causality Ledger.

**Request:**
```json
{
  "actor_id": "actor_abc123",
  "scope_type": "akn_batch",
  "commitment_digest": "blake3_digest_hex",
  "parent_ref": "optional_parent_commitment_id"
}
```

**Scope Types:**
- `akn_batch` - AKN (Acknowledged Knowledge Network) batch
- `consent_batch` - Consent operations batch
- `verdict_batch` - Verdict records batch
- `dispute_batch` - Dispute filings batch
- `repair_batch` - Repair operations batch
- `clawback_batch` - Clawback operations batch
- `log_batch` - Log entries batch
- `trace_batch` - Trace records batch
- `backfill_batch` - Backfill operations batch
- `identity_batch` - Identity operations batch
- `covenant_status_batch` - Covenant status batch

**Response:**
```json
{
  "commitment_id": "commit_abc123",
  "actor_id": "actor_abc123",
  "scope_type": "akn_batch",
  "commitment_digest": "blake3_digest_hex",
  "parent_commitment_ref": null,
  "sequence_no": 42,
  "created_at": "2025-01-01T00:00:00Z",
  "receipt_id": "receipt_abc123"
}
```

### GET /commitments/:commitment_id

Get commitment by ID.

**Response:** Same as POST /commitments response.

### GET /commitments/actor/:actor_id

Get commitment chain for an actor.

**Query Parameters:**
- `limit` (default: 100) - Number of items to return
- `offset` (default: 0) - Offset for pagination
- `scope_type` (optional) - Filter by scope type

**Response:**
```json
{
  "items": [...],
  "total": 100,
  "limit": 100,
  "offset": 0
}
```

### GET /commitments/:commitment_id/verify

Verify commitment chain integrity.

**Query Parameters:**
- `depth` (optional) - Depth to verify (default: 1000)

**Response:**
```json
{
  "commitment_id": "commit_abc123",
  "valid": true,
  "depth_checked": 1000
}
```

### GET /batches/:sequence

Get batch snapshot by sequence number.

**Response:**
```json
{
  "snapshot_id": "snapshot_abc123",
  "batch_root": "merkle_root_hex",
  "batch_sequence_no": 42,
  "time_window_start": "2025-01-01T00:00:00Z",
  "time_window_end": "2025-01-01T00:05:00Z",
  "parent_batch_root": "parent_root_hex",
  "signer_set_version": "v1",
  "signature_bitmap": "0xff",
  "threshold_proof": "aggregated_signature_hex"
}
```

---

## Knowledge-Index Ledger

### POST /knowledge

Index new content in the Knowledge-Index Ledger.

**Request:**
```json
{
  "content_digest": "blake3_digest_hex",
  "owner_actor_id": "actor_abc123",
  "space_id": "optional_space_id",
  "parent_digest": "optional_parent_digest"
}
```

**Response:**
```json
{
  "entry_id": "entry_abc123",
  "entry_type": "content",
  "content_digest": "blake3_digest_hex",
  "parent_digest": null,
  "space_id": null,
  "owner_actor_id": "actor_abc123",
  "created_at": "2025-01-01T00:00:00Z",
  "evidence_level": "b_level",
  "anchoring_state": "pending",
  "receipt_id": "receipt_abc123"
}
```

### GET /knowledge/:entry_id

Get knowledge entry by ID.

### GET /knowledge/digest/:digest

Get knowledge entries by content digest.

### GET /knowledge/space/:space_id

Get knowledge entries by space ID.

### GET /knowledge/actor/:actor_id

Get knowledge entries by actor ID.

### POST /knowledge/crossrefs

Create a cross-reference between two entries.

**Request:**
```json
{
  "source_digest": "source_blake3_hex",
  "target_digest": "target_blake3_hex",
  "ref_type": "citation"
}
```

**Response:**
```json
{
  "ref_id": "ref_abc123",
  "source_digest": "source_blake3_hex",
  "target_digest": "target_blake3_hex",
  "ref_type": "citation",
  "created_at": "2025-01-01T00:00:00Z",
  "receipt_id": "receipt_abc123"
}
```

### GET /knowledge/crossrefs/:digest/:direction

Get cross-references for a digest.

**Parameters:**
- `direction`: `outgoing` or `incoming`

---

## Policy-Consent Ledger

### POST /consents

Grant consent.

**Request:**
```json
{
  "consent_type": "explicit",
  "grantor": "actor_grantor_id",
  "grantee": "actor_grantee_id",
  "resource_type": "knowledge_entry",
  "resource_id": "optional_resource_id",
  "actions": ["read", "cite"],
  "terms_digest": "terms_blake3_hex",
  "expires_at": "2025-12-31T23:59:59Z"
}
```

**Consent Types:**
- `explicit` - Explicitly granted consent
- `implied` - Implied consent
- `delegated` - Delegated by another party
- `emergency` - Emergency override consent

**Response:**
```json
{
  "consent_id": "consent_abc123",
  "consent_type": "explicit",
  "grantor": "actor_grantor_id",
  "grantee": "actor_grantee_id",
  "resource_type": "knowledge_entry",
  "resource_id": null,
  "actions": ["read", "cite"],
  "status": "active",
  "terms_digest": "terms_blake3_hex",
  "granted_at": "2025-01-01T00:00:00Z",
  "expires_at": "2025-12-31T23:59:59Z",
  "revoked_at": null,
  "receipt_id": "receipt_abc123"
}
```

### GET /consents/:consent_id

Get consent by ID.

### POST /consents/:consent_id/revoke

Revoke consent.

**Request:**
```json
{
  "reason_digest": "optional_reason_blake3_hex"
}
```

### POST /consents/verify

Verify if consent exists for an action.

**Request:**
```json
{
  "grantor": "actor_grantor_id",
  "grantee": "actor_grantee_id",
  "action": "read",
  "resource_type": "knowledge_entry"
}
```

**Response:**
```json
{
  "valid": true,
  "consent_ref": "consent_abc123",
  "reason": null
}
```

### GET /consents/grantor/:grantor_id

List consents granted by an actor.

### GET /consents/grantee/:grantee_id

List consents received by an actor.

### POST /tickets

Issue an access ticket.

**Request:**
```json
{
  "consent_ref": "consent_abc123",
  "holder": "actor_holder_id",
  "target_resource": "resource_id",
  "permissions": ["read"],
  "valid_until": "2025-01-02T00:00:00Z",
  "one_time": true
}
```

**Response:**
```json
{
  "ticket_id": "ticket_abc123",
  "consent_ref": "consent_abc123",
  "holder": "actor_holder_id",
  "target_resource": "resource_id",
  "permissions": ["read"],
  "issued_at": "2025-01-01T00:00:00Z",
  "valid_from": "2025-01-01T00:00:00Z",
  "valid_until": "2025-01-02T00:00:00Z",
  "one_time": true,
  "used_at": null,
  "ticket_digest": "ticket_blake3_hex"
}
```

### GET /tickets/:ticket_id

Get ticket by ID.

### POST /tickets/:ticket_id/use

Use (consume) a one-time ticket.

**Response:**
```json
{
  "ticket_id": "ticket_abc123",
  "success": true
}
```

---

## Dispute-Resolution Ledger

### POST /disputes

File a new dispute.

**Request:**
```json
{
  "filed_by": "actor_filer_id",
  "filed_against": ["actor_defendant_id"],
  "priority": "normal",
  "subject_commitment_ref": "commitment_abc123",
  "evidence_digest": "evidence_blake3_hex"
}
```

**Priority Levels:**
- `normal` - Standard processing
- `urgent` - Expedited processing
- `critical` - Emergency processing

**Response:**
```json
{
  "dispute_id": "dispute_abc123",
  "filed_by": "actor_filer_id",
  "filed_against": ["actor_defendant_id"],
  "priority": "normal",
  "status": "filed",
  "subject_commitment_ref": "commitment_abc123",
  "evidence_digest": "evidence_blake3_hex",
  "filed_at": "2025-01-01T00:00:00Z",
  "last_updated": "2025-01-01T00:00:00Z",
  "receipt_id": "receipt_abc123"
}
```

### GET /disputes

List all disputes.

**Query Parameters:**
- `limit`, `offset` - Pagination
- `status` - Filter by status

**Dispute Status Values:**
- `filed` - Just filed
- `under_review` - Being reviewed
- `verdict_issued` - Verdict has been issued
- `repair_in_progress` - Repair process ongoing
- `resolved` - Fully resolved
- `dismissed` - Dismissed

### GET /disputes/:dispute_id

Get dispute by ID.

### POST /disputes/:dispute_id/status

Update dispute status.

**Request:**
```json
{
  "status": "under_review"
}
```

### GET /disputes/actor/:actor_id/:role

List disputes for an actor.

**Parameters:**
- `role`: `filed` (as filer) or `against` (as defendant)

### POST /disputes/:dispute_id/verdict

Issue verdict for a dispute.

**Request:**
```json
{
  "verdict_type": "in_favor",
  "verdict_digest": "verdict_blake3_hex",
  "rationale_digest": "rationale_blake3_hex",
  "remedies_digest": "optional_remedies_blake3_hex",
  "issued_by": "adjudicator_id",
  "appeal_deadline": "2025-01-15T00:00:00Z"
}
```

**Verdict Types:**
- `in_favor` - In favor of filer
- `against` - Against filer
- `mixed` - Mixed ruling
- `dismissed` - Case dismissed
- `inconclusive` - Insufficient evidence

**Response:**
```json
{
  "verdict_id": "verdict_abc123",
  "dispute_id": "dispute_abc123",
  "verdict_type": "in_favor",
  "verdict_digest": "verdict_blake3_hex",
  "rationale_digest": "rationale_blake3_hex",
  "remedies_digest": null,
  "issued_by": "adjudicator_id",
  "issued_at": "2025-01-01T00:00:00Z",
  "effective_at": "2025-01-01T00:00:00Z",
  "appeal_deadline": "2025-01-15T00:00:00Z",
  "receipt_id": "receipt_abc123"
}
```

### GET /verdicts/:verdict_id

Get verdict by ID.

### GET /disputes/:dispute_id/verdict

Get verdict for a dispute.

### POST /clawbacks

Initiate a clawback operation.

**Request:**
```json
{
  "verdict_id": "verdict_abc123",
  "clawback_type": "full_reverse",
  "target_commitment_refs": ["commit_1", "commit_2"],
  "affected_actors": ["actor_1", "actor_2"],
  "compensation_digest": "optional_compensation_blake3_hex"
}
```

**Clawback Types:**
- `full_reverse` - Full reversal of operations
- `partial_reverse` - Partial reversal
- `compensation` - Compensation payment
- `penalty` - Penalty assessment

**Response:**
```json
{
  "clawback_id": "clawback_abc123",
  "verdict_id": "verdict_abc123",
  "clawback_type": "full_reverse",
  "status": "pending",
  "clawback_digest": "clawback_blake3_hex",
  "target_commitment_refs": ["commit_1", "commit_2"],
  "affected_actors": ["actor_1", "actor_2"],
  "compensation_digest": null,
  "initiated_at": "2025-01-01T00:00:00Z",
  "executed_at": null,
  "receipt_id": "receipt_abc123"
}
```

### GET /clawbacks

List clawbacks.

### GET /clawbacks/:clawback_id

Get clawback by ID.

### POST /clawbacks/:clawback_id/execute

Execute a clawback.

**Request:**
```json
{
  "execution_digest": "execution_blake3_hex"
}
```

---

## Receipt Management

### POST /receipts

Create a new L0 receipt.

**Request:**
```json
{
  "scope_type": "akn_batch",
  "root_kind": "batch_root",
  "root": "merkle_root_hex",
  "time_window_start": "2025-01-01T00:00:00Z",
  "time_window_end": "2025-01-01T00:05:00Z",
  "batch_sequence_no": 42,
  "signer_set_version": "v1",
  "canonicalization_version": "v1",
  "anchor_policy_version": "v1",
  "fee_schedule_version": "v1",
  "signed_snapshot_ref": "snapshot_abc123",
  "fee_receipt_id": "fee_receipt_abc123"
}
```

**Root Kinds:**
- `batch_root` - Batch Merkle root
- `epoch_root` - Epoch Merkle root

**Response:**
```json
{
  "receipt_id": "receipt_abc123",
  "scope_type": "akn_batch",
  "root_kind": "batch_root",
  "root": "merkle_root_hex",
  "time_window_start": "2025-01-01T00:00:00Z",
  "time_window_end": "2025-01-01T00:05:00Z",
  "batch_sequence_no": 42,
  "signer_set_version": "v1",
  "created_at": "2025-01-01T00:00:00Z",
  "rejected": false,
  "reject_reason_code": null
}
```

### GET /receipts

List receipts.

### GET /receipts/:receipt_id

Get receipt by ID.

### GET /receipts/:receipt_id/verify

Verify a receipt.

**Response:**
```json
{
  "valid": true,
  "evidence_level": "a_level",
  "chain_anchored": true,
  "errors": []
}
```

### POST /receipts/:receipt_id/reject

Reject a receipt.

**Request:**
```json
{
  "reason_code": "INVALID_SIGNATURE",
  "observer_reports_digest": "optional_reports_blake3_hex"
}
```

### GET /receipts/batch/:batch_sequence

Get receipts by batch sequence number.

---

## Fee Management

### POST /fees

Charge a fee.

**Request:**
```json
{
  "payer_actor_id": "actor_abc123",
  "anchor_type": "batch",
  "units": "batch_root",
  "units_count": 1,
  "fee_schedule_version": "v1",
  "linked_anchor_id": "anchor_abc123",
  "risk_multiplier": "1.0",
  "deposit_amount": "100",
  "discount_digest": null,
  "subsidy_digest": null
}
```

**Fee Units:**
- `batch_root` - Per batch root
- `entry_count` - Per entry count
- `size_tier` - Size-based tier

**Response:**
```json
{
  "fee_receipt_id": "fee_abc123",
  "fee_schedule_version": "v1",
  "payer_actor_id": "actor_abc123",
  "anchor_type": "batch",
  "units": "batch_root",
  "units_count": 1,
  "amount": "100",
  "status": "charged_pending_receipt",
  "timestamp": "2025-01-01T00:00:00Z",
  "linked_receipt_id": null
}
```

### GET /fees/:fee_receipt_id

Get fee receipt by ID.

### POST /fees/:fee_receipt_id/status

Update fee status.

**Request:**
```json
{
  "status": "charged"
}
```

**Fee Status Values:**
- `charged_pending_receipt` - Charged, waiting for L0 receipt
- `charged` - Fully charged
- `refunded` - Refunded
- `forfeited` - Forfeited deposit
- `charged_no_receipt` - Charged without receipt

### GET /fees/actor/:actor_id/pending

Get pending fees for an actor.

### GET /fees/actor/:actor_id/history

Get fee history for an actor.

### POST /fees/:fee_receipt_id/refund

Refund a fee.

---

## TipWitness Management

TipWitness provides anti-history-rewrite protection.

### POST /tipwitness

Submit a TipWitness.

**Request:**
```json
{
  "actor_id": "actor_abc123",
  "local_tip_digest": "tip_blake3_hex",
  "local_sequence_no": 42,
  "last_known_receipt_ref": "receipt_abc123"
}
```

**Response:**
```json
{
  "tip_witness_id": "tipwitness_abc123",
  "actor_id": "actor_abc123",
  "local_tip_digest": "tip_blake3_hex",
  "local_sequence_no": 42,
  "last_known_receipt_ref": "receipt_abc123",
  "witnessed_at": "2025-01-01T00:00:00Z",
  "receipt_id": "receipt_abc123"
}
```

### GET /tipwitness/:actor_id

Get latest TipWitness for an actor.

### GET /tipwitness/:actor_id/history

Get TipWitness history for an actor.

### GET /tipwitness/:actor_id/verify

Verify TipWitness chain for an actor.

**Response:**
```json
{
  "is_valid": true,
  "witness_count": 42,
  "earliest_sequence": 1,
  "latest_sequence": 42,
  "gaps": []
}
```

---

## Backfill Management

Backfill enables B-level to A-level evidence upgrade.

### POST /backfill

Create a backfill request.

**Request:**
```json
{
  "actor_id": "actor_abc123",
  "start_digest": "start_blake3_hex",
  "start_sequence_no": 1,
  "end_digest": "end_blake3_hex",
  "end_sequence_no": 100,
  "tip_witness_ref": "tipwitness_abc123"
}
```

**Response:**
```json
{
  "request_id": "backfill_req_abc123",
  "actor_id": "actor_abc123",
  "status": "requested",
  "start_digest": "start_blake3_hex",
  "start_sequence_no": 1,
  "end_digest": "end_blake3_hex",
  "end_sequence_no": 100,
  "tip_witness_ref": "tipwitness_abc123",
  "requested_at": "2025-01-01T00:00:00Z",
  "completed_at": null,
  "receipt_id": null
}
```

### GET /backfill/:request_id

Get backfill request by ID.

### GET /backfill/actor/:actor_id

List backfill requests for an actor.

### POST /backfill/:request_id/plan

Generate a backfill plan.

**Response:**
```json
{
  "plan_id": "plan_abc123",
  "request_ref": "backfill_req_abc123",
  "item_count": 100,
  "estimated_fee": "1000",
  "gap_count": 0,
  "continuity_result": "pass",
  "created_at": "2025-01-01T00:00:00Z",
  "expires_at": "2025-01-02T00:00:00Z"
}
```

### POST /backfill/plan/:plan_id/execute

Execute a backfill plan.

**Response:**
```json
{
  "backfill_receipt_id": "bf_receipt_abc123",
  "request_ref": "backfill_req_abc123",
  "plan_ref": "plan_abc123",
  "actor_id": "actor_abc123",
  "objects_anchored": 100,
  "total_fee_paid": "1000",
  "continuity_result": "pass",
  "started_at": "2025-01-01T00:00:00Z",
  "completed_at": "2025-01-01T00:01:00Z",
  "receipt_id": "receipt_abc123"
}
```

### POST /backfill/:request_id/cancel

Cancel a backfill request.

**Request:**
```json
{
  "reason": "User cancelled"
}
```

### GET /backfill/actor/:actor_id/gaps

Detect gaps in an actor's commitment chain.

**Query Parameters:**
- `start_sequence` - Start sequence number
- `end_sequence` - End sequence number

**Response:**
```json
[
  {
    "gap_id": "gap_abc123",
    "start_sequence": 10,
    "end_sequence": 15,
    "gap_type": "sequence_gap",
    "acceptable": false
  }
]
```

**Gap Types:**
- `sequence_gap` - Missing sequence numbers
- `hash_chain_break` - Hash chain discontinuity
- `time_gap` - Time continuity break
- `unknown` - Unknown gap type

### GET /backfill/actor/:actor_id/continuity

Verify continuity of an actor's chain.

**Response:**
```json
{
  "result": "pass",
  "gaps": []
}
```

**Continuity Results:**
- `pass` - Full continuity
- `pass_with_gaps` - Acceptable gaps
- `fail` - Unacceptable discontinuity

### GET /backfill/actor/:actor_id/history

Get backfill history for an actor.

---

## Chain Anchoring

Chain anchoring provides external blockchain anchoring for epoch roots.

### POST /anchors

Create an anchor transaction.

**Request:**
```json
{
  "chain_type": "ethereum",
  "epoch_root": "epoch_root_hex",
  "epoch_sequence": 12,
  "epoch_start": "2025-01-01T00:00:00Z",
  "epoch_end": "2025-01-01T01:00:00Z",
  "batch_count": 12
}
```

**Chain Types:**
- `ethereum` - Ethereum mainnet
- `bitcoin` - Bitcoin mainnet
- `polygon` - Polygon PoS
- `solana` - Solana mainnet
- `internal` - Internal L0 chain (for testing)

**Response:**
```json
{
  "anchor_id": "anchor_abc123",
  "chain_type": "ethereum",
  "epoch_root": "epoch_root_hex",
  "epoch_sequence": 12,
  "epoch_start": "2025-01-01T00:00:00Z",
  "epoch_end": "2025-01-01T01:00:00Z",
  "batch_count": 12,
  "status": "pending",
  "tx_hash": null,
  "block_number": null,
  "block_hash": null,
  "confirmations": 0,
  "required_confirmations": 12,
  "gas_price": null,
  "gas_used": null,
  "fee_paid": null,
  "submitted_at": null,
  "confirmed_at": null,
  "created_at": "2025-01-01T00:00:00Z"
}
```

### GET /anchors/:anchor_id

Get anchor by ID.

### GET /anchors/chain/:chain_type/epoch/:epoch_sequence

Get anchor by epoch sequence on a chain.

### POST /anchors/:anchor_id/submit

Submit anchor transaction to chain.

**Response:**
```json
{
  "success": true,
  "anchor_id": "anchor_abc123",
  "tx_hash": "0xabc123..."
}
```

### GET /anchors/:anchor_id/status

Check anchor status on chain.

### POST /anchors/:anchor_id/status

Update anchor status.

**Request:**
```json
{
  "status": "confirmed",
  "tx_hash": "0xabc123...",
  "block_number": 12345678,
  "confirmations": 12
}
```

**Anchor Status Values:**
- `pending` - Created, not submitted
- `submitted` - Submitted to chain
- `confirmed` - Has confirmations
- `finalized` - Fully finalized
- `failed` - Transaction failed
- `expired` - Anchor expired

### GET /anchors/:anchor_id/verify

Verify anchor on chain.

**Response:**
```json
{
  "valid": true,
  "chain_type": "ethereum",
  "tx_hash": "0xabc123...",
  "block_number": 12345678,
  "confirmations": 15,
  "epoch_root_matches": true,
  "proof_verified": true,
  "errors": [],
  "verified_at": "2025-01-01T00:05:00Z"
}
```

### POST /anchors/:anchor_id/retry

Retry a failed anchor.

### GET /anchors/pending

Get pending anchors.

**Query Parameters:**
- `chain_type` (optional) - Filter by chain type

### GET /anchors/chain/:chain_type/finalized

Get finalized anchors for a chain.

### GET /anchors/chain/:chain_type/history

Get anchor history for a chain.

**Query Parameters:**
- `from_epoch` - Start epoch
- `to_epoch` - End epoch

### GET /anchors/chain/:chain_type/latest-epoch

Get latest finalized epoch for a chain.

**Response:**
```json
{
  "chain_type": "ethereum",
  "latest_finalized_epoch": 12
}
```

### GET /anchors/policy

Get current anchor policy.

**Response:**
```json
{
  "version": "v1.0.0",
  "enabled_chains": ["ethereum", "polygon"],
  "primary_chain": "ethereum",
  "epoch_interval": 3600,
  "max_anchor_delay": 7200,
  "retry_count": 3,
  "gas_strategy": "standard"
}
```

**Gas Strategies:**
- `standard` - Normal gas price
- `fast` - Higher gas for faster confirmation
- `slow` - Lower gas, slower confirmation
- `custom` - Custom gas configuration

### POST /anchors/policy

Update anchor policy.

**Request:**
```json
{
  "enabled_chains": ["ethereum", "polygon"],
  "primary_chain": "ethereum",
  "epoch_interval": 3600,
  "max_anchor_delay": 7200,
  "retry_count": 3,
  "gas_strategy": "standard"
}
```

---

## Error Responses

All endpoints return consistent error responses:

```json
{
  "error": {
    "code": "NOT_FOUND",
    "message": "Actor actor_abc123 not found"
  }
}
```

**HTTP Status Codes:**
- `200 OK` - Success
- `201 Created` - Resource created
- `400 Bad Request` - Validation error
- `404 Not Found` - Resource not found
- `500 Internal Server Error` - Server error

---

## Pagination

List endpoints support pagination:

**Query Parameters:**
- `limit` (default: 100, max: 1000) - Items per page
- `offset` (default: 0) - Starting offset

**Response:**
```json
{
  "items": [...],
  "total": 1000,
  "limit": 100,
  "offset": 0
}
```

---

## Data Types

### Digest Format
All digests are BLAKE3 hashes, hex-encoded (64 characters).

### Timestamps
All timestamps are ISO 8601 format in UTC: `2025-01-01T00:00:00Z`

### IDs
IDs are ULIDs or prefixed identifiers:
- Actor: `actor_ULID`
- Commitment: `commit_ULID`
- Receipt: `receipt_ULID`
- etc.

---

## Evidence Levels

L0 provides two evidence levels:

- **B-Level (B级证据)**: Local chain with threshold signatures
- **A-Level (A级证据)**: Externally anchored on public blockchain

Backfill allows upgrading B-level evidence to A-level.
