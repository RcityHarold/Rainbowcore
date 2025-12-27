//! SurrealDB schema definitions for L0

/// Complete L0 schema for SurrealDB
pub const L0_SCHEMA: &str = r#"
-- ============================================
-- L0 Actor Table (Identity Ledger)
-- ============================================
DEFINE TABLE l0_actor SCHEMAFULL;
DEFINE FIELD id ON l0_actor TYPE string;
DEFINE FIELD tenant_id ON l0_actor TYPE object;
DEFINE FIELD actor_id ON l0_actor TYPE string;
DEFINE FIELD actor_type ON l0_actor TYPE string ASSERT $value IN ['human', 'ai_agent', 'node', 'group'];
DEFINE FIELD node_actor_id ON l0_actor TYPE string;
DEFINE FIELD public_key ON l0_actor TYPE string;
DEFINE FIELD payment_address_slot ON l0_actor TYPE option<string>;
DEFINE FIELD status ON l0_actor TYPE string ASSERT $value IN ['active', 'suspended', 'revoked'];
DEFINE FIELD created_at ON l0_actor TYPE datetime;
DEFINE FIELD updated_at ON l0_actor TYPE datetime;
DEFINE FIELD receipt_id ON l0_actor TYPE option<string>;
DEFINE FIELD metadata_digest ON l0_actor TYPE option<string>;
DEFINE INDEX idx_actor_id ON l0_actor FIELDS actor_id UNIQUE;
DEFINE INDEX idx_actor_pubkey ON l0_actor FIELDS public_key UNIQUE;
DEFINE INDEX idx_actor_tenant ON l0_actor FIELDS tenant_id;

-- ============================================
-- L0 Key Rotation Table
-- ============================================
DEFINE TABLE l0_key_rotation SCHEMAFULL;
DEFINE FIELD id ON l0_key_rotation TYPE string;
DEFINE FIELD tenant_id ON l0_key_rotation TYPE object;
DEFINE FIELD actor_id ON l0_key_rotation TYPE string;
DEFINE FIELD old_public_key ON l0_key_rotation TYPE string;
DEFINE FIELD new_public_key ON l0_key_rotation TYPE string;
DEFINE FIELD rotated_at ON l0_key_rotation TYPE datetime;
DEFINE FIELD reason_digest ON l0_key_rotation TYPE option<string>;
DEFINE FIELD receipt_id ON l0_key_rotation TYPE option<string>;
DEFINE INDEX idx_key_rotation_actor ON l0_key_rotation FIELDS actor_id;

-- ============================================
-- L0 Commitment Table (Causality Ledger)
-- ============================================
DEFINE TABLE l0_commitment SCHEMAFULL;
DEFINE FIELD id ON l0_commitment TYPE string;
DEFINE FIELD tenant_id ON l0_commitment TYPE object;
DEFINE FIELD commitment_id ON l0_commitment TYPE string;
DEFINE FIELD actor_id ON l0_commitment TYPE string;
DEFINE FIELD scope_type ON l0_commitment TYPE string;
DEFINE FIELD commitment_digest ON l0_commitment TYPE string;
DEFINE FIELD parent_commitment_ref ON l0_commitment TYPE option<string>;
DEFINE FIELD sequence_no ON l0_commitment TYPE int;
DEFINE FIELD created_at ON l0_commitment TYPE datetime;
DEFINE FIELD receipt_id ON l0_commitment TYPE option<string>;
DEFINE FIELD batch_sequence_no ON l0_commitment TYPE option<int>;
DEFINE INDEX idx_commitment_id ON l0_commitment FIELDS commitment_id UNIQUE;
DEFINE INDEX idx_commitment_actor ON l0_commitment FIELDS actor_id, sequence_no;
DEFINE INDEX idx_commitment_batch ON l0_commitment FIELDS batch_sequence_no;

-- ============================================
-- L0 Batch Snapshot Table
-- ============================================
DEFINE TABLE l0_batch_snapshot SCHEMAFULL;
DEFINE FIELD id ON l0_batch_snapshot TYPE string;
DEFINE FIELD tenant_id ON l0_batch_snapshot TYPE object;
DEFINE FIELD batch_sequence_no ON l0_batch_snapshot TYPE int;
DEFINE FIELD batch_root ON l0_batch_snapshot TYPE string;
DEFINE FIELD time_window_start ON l0_batch_snapshot TYPE datetime;
DEFINE FIELD time_window_end ON l0_batch_snapshot TYPE datetime;
DEFINE FIELD parent_batch_root ON l0_batch_snapshot TYPE option<string>;
DEFINE FIELD commitment_count ON l0_batch_snapshot TYPE int;
DEFINE FIELD signer_set_version ON l0_batch_snapshot TYPE string;
DEFINE FIELD threshold_rule ON l0_batch_snapshot TYPE string;
DEFINE FIELD signature_bitmap ON l0_batch_snapshot TYPE string;
DEFINE FIELD threshold_proof ON l0_batch_snapshot TYPE string;
DEFINE FIELD created_at ON l0_batch_snapshot TYPE datetime;
DEFINE INDEX idx_batch_seq ON l0_batch_snapshot FIELDS batch_sequence_no UNIQUE;

-- ============================================
-- L0 Epoch Snapshot Table (Chain Anchoring)
-- ============================================
DEFINE TABLE l0_epoch_snapshot SCHEMAFULL;
DEFINE FIELD id ON l0_epoch_snapshot TYPE string;
DEFINE FIELD tenant_id ON l0_epoch_snapshot TYPE object;
DEFINE FIELD epoch_sequence_no ON l0_epoch_snapshot TYPE int;
DEFINE FIELD epoch_root ON l0_epoch_snapshot TYPE string;
DEFINE FIELD time_window_start ON l0_epoch_snapshot TYPE datetime;
DEFINE FIELD time_window_end ON l0_epoch_snapshot TYPE datetime;
DEFINE FIELD batch_start ON l0_epoch_snapshot TYPE int;
DEFINE FIELD batch_end ON l0_epoch_snapshot TYPE int;
DEFINE FIELD parent_epoch_root ON l0_epoch_snapshot TYPE option<string>;
DEFINE FIELD chain_anchor_tx ON l0_epoch_snapshot TYPE option<string>;
DEFINE FIELD anchor_status ON l0_epoch_snapshot TYPE string;
DEFINE FIELD created_at ON l0_epoch_snapshot TYPE datetime;
DEFINE INDEX idx_epoch_seq ON l0_epoch_snapshot FIELDS epoch_sequence_no UNIQUE;

-- ============================================
-- L0 Receipt Table
-- ============================================
DEFINE TABLE l0_receipt SCHEMAFULL;
DEFINE FIELD id ON l0_receipt TYPE string;
DEFINE FIELD tenant_id ON l0_receipt TYPE object;
DEFINE FIELD receipt_id ON l0_receipt TYPE string;
DEFINE FIELD scope_type ON l0_receipt TYPE string;
DEFINE FIELD root_kind ON l0_receipt TYPE string;
DEFINE FIELD root ON l0_receipt TYPE string;
DEFINE FIELD time_window_start ON l0_receipt TYPE datetime;
DEFINE FIELD time_window_end ON l0_receipt TYPE datetime;
DEFINE FIELD batch_sequence_no ON l0_receipt TYPE option<int>;
DEFINE FIELD signer_set_version ON l0_receipt TYPE string;
DEFINE FIELD canonicalization_version ON l0_receipt TYPE string;
DEFINE FIELD anchor_policy_version ON l0_receipt TYPE string;
DEFINE FIELD fee_schedule_version ON l0_receipt TYPE string;
DEFINE FIELD fee_receipt_id ON l0_receipt TYPE string;
DEFINE FIELD signed_snapshot_ref ON l0_receipt TYPE string;
DEFINE FIELD created_at ON l0_receipt TYPE datetime;
DEFINE FIELD rejected ON l0_receipt TYPE bool DEFAULT false;
DEFINE FIELD reject_reason_code ON l0_receipt TYPE option<string>;
DEFINE INDEX idx_receipt_id ON l0_receipt FIELDS receipt_id UNIQUE;
DEFINE INDEX idx_receipt_batch ON l0_receipt FIELDS batch_sequence_no;

-- ============================================
-- L0 Fee Receipt Table
-- ============================================
DEFINE TABLE l0_fee_receipt SCHEMAFULL;
DEFINE FIELD id ON l0_fee_receipt TYPE string;
DEFINE FIELD tenant_id ON l0_fee_receipt TYPE object;
DEFINE FIELD fee_receipt_id ON l0_fee_receipt TYPE string;
DEFINE FIELD payer_actor_id ON l0_fee_receipt TYPE string;
DEFINE FIELD fee_units ON l0_fee_receipt TYPE int;
DEFINE FIELD fee_schedule_version ON l0_fee_receipt TYPE string;
DEFINE FIELD status ON l0_fee_receipt TYPE string;
DEFINE FIELD created_at ON l0_fee_receipt TYPE datetime;
DEFINE FIELD settled_at ON l0_fee_receipt TYPE option<datetime>;
DEFINE INDEX idx_fee_receipt_id ON l0_fee_receipt FIELDS fee_receipt_id UNIQUE;

-- ============================================
-- L0 TipWitness Table (Anti-History-Rewrite)
-- ============================================
DEFINE TABLE l0_tip_witness SCHEMAFULL;
DEFINE FIELD id ON l0_tip_witness TYPE string;
DEFINE FIELD tenant_id ON l0_tip_witness TYPE object;
DEFINE FIELD tip_witness_id ON l0_tip_witness TYPE string;
DEFINE FIELD actor_id ON l0_tip_witness TYPE string;
DEFINE FIELD local_tip_digest ON l0_tip_witness TYPE string;
DEFINE FIELD local_sequence_no ON l0_tip_witness TYPE int;
DEFINE FIELD last_known_receipt_ref ON l0_tip_witness TYPE option<string>;
DEFINE FIELD witnessed_at ON l0_tip_witness TYPE datetime;
DEFINE FIELD receipt_id ON l0_tip_witness TYPE option<string>;
DEFINE INDEX idx_tip_witness_id ON l0_tip_witness FIELDS tip_witness_id UNIQUE;
DEFINE INDEX idx_tip_witness_actor ON l0_tip_witness FIELDS actor_id;

-- ============================================
-- L0 Consent Table (Policy-Consent Ledger)
-- ============================================
DEFINE TABLE l0_consent SCHEMAFULL;
DEFINE FIELD id ON l0_consent TYPE string;
DEFINE FIELD tenant_id ON l0_consent TYPE object;
DEFINE FIELD consent_id ON l0_consent TYPE string;
DEFINE FIELD consent_type ON l0_consent TYPE string;
DEFINE FIELD grantor ON l0_consent TYPE string;
DEFINE FIELD grantee ON l0_consent TYPE string;
DEFINE FIELD resource_type ON l0_consent TYPE string;
DEFINE FIELD resource_id ON l0_consent TYPE option<string>;
DEFINE FIELD actions ON l0_consent TYPE array<string>;
DEFINE FIELD constraints_digest ON l0_consent TYPE option<string>;
DEFINE FIELD status ON l0_consent TYPE string;
DEFINE FIELD terms_digest ON l0_consent TYPE string;
DEFINE FIELD granted_at ON l0_consent TYPE datetime;
DEFINE FIELD expires_at ON l0_consent TYPE option<datetime>;
DEFINE FIELD revoked_at ON l0_consent TYPE option<datetime>;
DEFINE FIELD revocation_reason_digest ON l0_consent TYPE option<string>;
DEFINE FIELD superseded_by ON l0_consent TYPE option<string>;
DEFINE FIELD receipt_id ON l0_consent TYPE option<string>;
DEFINE INDEX idx_consent_id ON l0_consent FIELDS consent_id UNIQUE;
DEFINE INDEX idx_consent_grantor ON l0_consent FIELDS grantor;
DEFINE INDEX idx_consent_grantee ON l0_consent FIELDS grantee;

-- ============================================
-- L0 Access Ticket Table
-- ============================================
DEFINE TABLE l0_access_ticket SCHEMAFULL;
DEFINE FIELD id ON l0_access_ticket TYPE string;
DEFINE FIELD tenant_id ON l0_access_ticket TYPE object;
DEFINE FIELD ticket_id ON l0_access_ticket TYPE string;
DEFINE FIELD consent_ref ON l0_access_ticket TYPE string;
DEFINE FIELD holder ON l0_access_ticket TYPE string;
DEFINE FIELD target_resource ON l0_access_ticket TYPE string;
DEFINE FIELD permissions ON l0_access_ticket TYPE array<string>;
DEFINE FIELD issued_at ON l0_access_ticket TYPE datetime;
DEFINE FIELD valid_from ON l0_access_ticket TYPE datetime;
DEFINE FIELD valid_until ON l0_access_ticket TYPE datetime;
DEFINE FIELD one_time ON l0_access_ticket TYPE bool;
DEFINE FIELD used_at ON l0_access_ticket TYPE option<datetime>;
DEFINE FIELD ticket_digest ON l0_access_ticket TYPE string;
DEFINE FIELD receipt_id ON l0_access_ticket TYPE option<string>;
DEFINE INDEX idx_ticket_id ON l0_access_ticket FIELDS ticket_id UNIQUE;

-- ============================================
-- L0 Delegation Table
-- ============================================
DEFINE TABLE l0_delegation SCHEMAFULL;
DEFINE FIELD id ON l0_delegation TYPE string;
DEFINE FIELD tenant_id ON l0_delegation TYPE object;
DEFINE FIELD delegation_id ON l0_delegation TYPE string;
DEFINE FIELD delegator ON l0_delegation TYPE string;
DEFINE FIELD delegate ON l0_delegation TYPE string;
DEFINE FIELD resource_type ON l0_delegation TYPE string;
DEFINE FIELD actions ON l0_delegation TYPE array<string>;
DEFINE FIELD can_redelegate ON l0_delegation TYPE bool;
DEFINE FIELD max_depth ON l0_delegation TYPE int;
DEFINE FIELD current_depth ON l0_delegation TYPE int;
DEFINE FIELD parent_delegation_ref ON l0_delegation TYPE option<string>;
DEFINE FIELD valid_from ON l0_delegation TYPE datetime;
DEFINE FIELD valid_until ON l0_delegation TYPE option<datetime>;
DEFINE FIELD revoked_at ON l0_delegation TYPE option<datetime>;
DEFINE FIELD receipt_id ON l0_delegation TYPE option<string>;
DEFINE INDEX idx_delegation_id ON l0_delegation FIELDS delegation_id UNIQUE;

-- ============================================
-- L0 Dispute Table (Dispute-Resolution Ledger)
-- ============================================
DEFINE TABLE l0_dispute SCHEMAFULL;
DEFINE FIELD id ON l0_dispute TYPE string;
DEFINE FIELD tenant_id ON l0_dispute TYPE object;
DEFINE FIELD dispute_id ON l0_dispute TYPE string;
DEFINE FIELD filed_by ON l0_dispute TYPE string;
DEFINE FIELD filed_against ON l0_dispute TYPE array<string>;
DEFINE FIELD priority ON l0_dispute TYPE string;
DEFINE FIELD status ON l0_dispute TYPE string;
DEFINE FIELD subject_commitment_ref ON l0_dispute TYPE string;
DEFINE FIELD evidence_digest ON l0_dispute TYPE string;
DEFINE FIELD filed_at ON l0_dispute TYPE datetime;
DEFINE FIELD last_updated ON l0_dispute TYPE datetime;
DEFINE FIELD receipt_id ON l0_dispute TYPE option<string>;
DEFINE INDEX idx_dispute_id ON l0_dispute FIELDS dispute_id UNIQUE;
DEFINE INDEX idx_dispute_status ON l0_dispute FIELDS status;

-- ============================================
-- L0 Verdict Table
-- ============================================
DEFINE TABLE l0_verdict SCHEMAFULL;
DEFINE FIELD id ON l0_verdict TYPE string;
DEFINE FIELD tenant_id ON l0_verdict TYPE object;
DEFINE FIELD verdict_id ON l0_verdict TYPE string;
DEFINE FIELD dispute_id ON l0_verdict TYPE string;
DEFINE FIELD verdict_type ON l0_verdict TYPE string;
DEFINE FIELD verdict_digest ON l0_verdict TYPE string;
DEFINE FIELD rationale_digest ON l0_verdict TYPE string;
DEFINE FIELD remedies_digest ON l0_verdict TYPE option<string>;
DEFINE FIELD issued_by ON l0_verdict TYPE string;
DEFINE FIELD issued_at ON l0_verdict TYPE datetime;
DEFINE FIELD effective_at ON l0_verdict TYPE datetime;
DEFINE FIELD appeal_deadline ON l0_verdict TYPE option<datetime>;
DEFINE FIELD receipt_id ON l0_verdict TYPE option<string>;
DEFINE INDEX idx_verdict_id ON l0_verdict FIELDS verdict_id UNIQUE;
DEFINE INDEX idx_verdict_dispute ON l0_verdict FIELDS dispute_id;

-- ============================================
-- L0 Clawback Table
-- ============================================
DEFINE TABLE l0_clawback SCHEMAFULL;
DEFINE FIELD id ON l0_clawback TYPE string;
DEFINE FIELD tenant_id ON l0_clawback TYPE object;
DEFINE FIELD clawback_id ON l0_clawback TYPE string;
DEFINE FIELD verdict_id ON l0_clawback TYPE string;
DEFINE FIELD clawback_type ON l0_clawback TYPE string;
DEFINE FIELD status ON l0_clawback TYPE string;
DEFINE FIELD clawback_digest ON l0_clawback TYPE string;
DEFINE FIELD target_commitment_refs ON l0_clawback TYPE array<string>;
DEFINE FIELD affected_actors ON l0_clawback TYPE array<string>;
DEFINE FIELD compensation_digest ON l0_clawback TYPE option<string>;
DEFINE FIELD initiated_at ON l0_clawback TYPE datetime;
DEFINE FIELD executed_at ON l0_clawback TYPE option<datetime>;
DEFINE FIELD receipt_id ON l0_clawback TYPE option<string>;
DEFINE INDEX idx_clawback_id ON l0_clawback FIELDS clawback_id UNIQUE;

-- ============================================
-- L0 Repair Checkpoint Table
-- ============================================
DEFINE TABLE l0_repair_checkpoint SCHEMAFULL;
DEFINE FIELD id ON l0_repair_checkpoint TYPE string;
DEFINE FIELD tenant_id ON l0_repair_checkpoint TYPE object;
DEFINE FIELD checkpoint_id ON l0_repair_checkpoint TYPE string;
DEFINE FIELD dispute_id ON l0_repair_checkpoint TYPE string;
DEFINE FIELD verdict_id ON l0_repair_checkpoint TYPE string;
DEFINE FIELD checkpoint_digest ON l0_repair_checkpoint TYPE string;
DEFINE FIELD affected_actors ON l0_repair_checkpoint TYPE array<string>;
DEFINE FIELD repair_plan_digest ON l0_repair_checkpoint TYPE string;
DEFINE FIELD progress_percent ON l0_repair_checkpoint TYPE int;
DEFINE FIELD created_at ON l0_repair_checkpoint TYPE datetime;
DEFINE FIELD completed_at ON l0_repair_checkpoint TYPE option<datetime>;
DEFINE FIELD receipt_id ON l0_repair_checkpoint TYPE option<string>;
DEFINE INDEX idx_checkpoint_id ON l0_repair_checkpoint FIELDS checkpoint_id UNIQUE;

-- ============================================
-- L0 Signer Set Table
-- ============================================
DEFINE TABLE l0_signer_set SCHEMAFULL;
DEFINE FIELD id ON l0_signer_set TYPE string;
DEFINE FIELD tenant_id ON l0_signer_set TYPE object;
DEFINE FIELD signer_set_id ON l0_signer_set TYPE string;
DEFINE FIELD version ON l0_signer_set TYPE int;
DEFINE FIELD certified_signer_pubkeys ON l0_signer_set TYPE array<string>;
DEFINE FIELD observer_pubkeys ON l0_signer_set TYPE array<string>;
DEFINE FIELD threshold_rule ON l0_signer_set TYPE string;
DEFINE FIELD valid_from ON l0_signer_set TYPE datetime;
DEFINE FIELD supersedes ON l0_signer_set TYPE option<string>;
DEFINE FIELD admission_policy_version ON l0_signer_set TYPE string;
DEFINE INDEX idx_signer_set ON l0_signer_set FIELDS signer_set_id, version UNIQUE;
"#;
