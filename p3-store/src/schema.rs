//! SurrealDB schema definitions for P3 Economy Layer

/// Complete P3 schema for SurrealDB
pub const P3_SCHEMA: &str = r#"
-- ============================================
-- P3 Epoch Bundle Table
-- ============================================
DEFINE TABLE p3_epoch_bundle SCHEMAFULL;
DEFINE FIELD id ON p3_epoch_bundle TYPE string;
DEFINE FIELD tenant_id ON p3_epoch_bundle TYPE any;
DEFINE FIELD epoch_id ON p3_epoch_bundle TYPE string;
DEFINE FIELD epoch_window_start ON p3_epoch_bundle TYPE string;
DEFINE FIELD epoch_window_end ON p3_epoch_bundle TYPE string;
DEFINE FIELD cutoff_ref_digest ON p3_epoch_bundle TYPE option<string>;
DEFINE FIELD cutoff_ref_sequence ON p3_epoch_bundle TYPE option<int>;
DEFINE FIELD manifest_digest ON p3_epoch_bundle TYPE string;
DEFINE FIELD weights_version_id ON p3_epoch_bundle TYPE string;
DEFINE FIELD weights_version_digest ON p3_epoch_bundle TYPE string;
DEFINE FIELD policy_refs_digest ON p3_epoch_bundle TYPE string;
DEFINE FIELD canon_version ON p3_epoch_bundle TYPE string;
DEFINE FIELD receipt_refs_digest ON p3_epoch_bundle TYPE string;
DEFINE FIELD result_root_digest ON p3_epoch_bundle TYPE string;
DEFINE FIELD chain_anchor_tx_id ON p3_epoch_bundle TYPE option<string>;
DEFINE FIELD chain_anchor_chain_type ON p3_epoch_bundle TYPE option<string>;
DEFINE FIELD chain_anchor_block_height ON p3_epoch_bundle TYPE option<int>;
DEFINE FIELD chain_anchor_timestamp ON p3_epoch_bundle TYPE option<string>;
DEFINE FIELD status ON p3_epoch_bundle TYPE string ASSERT $value IN ['pending', 'committed', 'finalized', 'anchored'];
DEFINE FIELD created_at ON p3_epoch_bundle TYPE string;
DEFINE FIELD updated_at ON p3_epoch_bundle TYPE string;
DEFINE INDEX idx_epoch_id ON p3_epoch_bundle FIELDS epoch_id UNIQUE;
DEFINE INDEX idx_epoch_window ON p3_epoch_bundle FIELDS epoch_window_start, epoch_window_end;
DEFINE INDEX idx_epoch_status ON p3_epoch_bundle FIELDS status;

-- ============================================
-- P3 Manifest Event Set Table
-- ============================================
DEFINE TABLE p3_manifest_set SCHEMAFULL;
DEFINE FIELD id ON p3_manifest_set TYPE string;
DEFINE FIELD tenant_id ON p3_manifest_set TYPE any;
DEFINE FIELD epoch_id ON p3_manifest_set TYPE string;
DEFINE FIELD set_type ON p3_manifest_set TYPE string ASSERT $value IN ['knowledge_events', 'court_events', 'policy_state', 'sampling_audit'];
DEFINE FIELD set_digest ON p3_manifest_set TYPE string;
DEFINE FIELD event_count ON p3_manifest_set TYPE int;
DEFINE FIELD event_refs_json ON p3_manifest_set TYPE option<string>;
DEFINE FIELD created_at ON p3_manifest_set TYPE string;
DEFINE INDEX idx_manifest_epoch ON p3_manifest_set FIELDS epoch_id;
DEFINE INDEX idx_manifest_type ON p3_manifest_set FIELDS epoch_id, set_type UNIQUE;

-- ============================================
-- P3 Result Entry Table (for Result Root)
-- ============================================
DEFINE TABLE p3_result_entry SCHEMAFULL;
DEFINE FIELD id ON p3_result_entry TYPE string;
DEFINE FIELD tenant_id ON p3_result_entry TYPE any;
DEFINE FIELD epoch_id ON p3_result_entry TYPE string;
DEFINE FIELD entry_index ON p3_result_entry TYPE int;
DEFINE FIELD entry_type ON p3_result_entry TYPE string;
DEFINE FIELD entry_digest ON p3_result_entry TYPE string;
DEFINE FIELD actor_id ON p3_result_entry TYPE option<string>;
DEFINE FIELD amount_digest ON p3_result_entry TYPE option<string>;
DEFINE FIELD currency ON p3_result_entry TYPE option<string>;
DEFINE FIELD created_at ON p3_result_entry TYPE string;
DEFINE INDEX idx_result_epoch ON p3_result_entry FIELDS epoch_id;
DEFINE INDEX idx_result_actor ON p3_result_entry FIELDS actor_id;

-- ============================================
-- P3 Points Balance Table
-- ============================================
DEFINE TABLE p3_points_balance SCHEMAFULL;
DEFINE FIELD id ON p3_points_balance TYPE string;
DEFINE FIELD tenant_id ON p3_points_balance TYPE any;
DEFINE FIELD actor_id ON p3_points_balance TYPE string;
DEFINE FIELD point_type ON p3_points_balance TYPE string ASSERT $value IN ['ACP', 'CTP', 'GTP'];
DEFINE FIELD balance ON p3_points_balance TYPE string;
DEFINE FIELD last_updated_epoch ON p3_points_balance TYPE string;
DEFINE FIELD created_at ON p3_points_balance TYPE string;
DEFINE FIELD updated_at ON p3_points_balance TYPE string;
DEFINE INDEX idx_points_actor ON p3_points_balance FIELDS actor_id;
DEFINE INDEX idx_points_type ON p3_points_balance FIELDS actor_id, point_type UNIQUE;

-- ============================================
-- P3 Points History Table
-- ============================================
DEFINE TABLE p3_points_history SCHEMAFULL;
DEFINE FIELD id ON p3_points_history TYPE string;
DEFINE FIELD tenant_id ON p3_points_history TYPE any;
DEFINE FIELD actor_id ON p3_points_history TYPE string;
DEFINE FIELD point_type ON p3_points_history TYPE string;
DEFINE FIELD epoch_id ON p3_points_history TYPE string;
DEFINE FIELD delta ON p3_points_history TYPE string;
DEFINE FIELD reason_code ON p3_points_history TYPE string;
DEFINE FIELD reason_ref ON p3_points_history TYPE option<string>;
DEFINE FIELD balance_after ON p3_points_history TYPE string;
DEFINE FIELD created_at ON p3_points_history TYPE string;
DEFINE INDEX idx_history_actor ON p3_points_history FIELDS actor_id;
DEFINE INDEX idx_history_epoch ON p3_points_history FIELDS epoch_id;

-- ============================================
-- P3 Treasury Pool Table
-- ============================================
DEFINE TABLE p3_treasury_pool SCHEMAFULL;
DEFINE FIELD id ON p3_treasury_pool TYPE string;
DEFINE FIELD tenant_id ON p3_treasury_pool TYPE any;
DEFINE FIELD pool_type ON p3_treasury_pool TYPE string ASSERT $value IN ['infra', 'civilization', 'reward'];
DEFINE FIELD balance_digest ON p3_treasury_pool TYPE string;
DEFINE FIELD currency ON p3_treasury_pool TYPE string;
DEFINE FIELD last_updated_epoch ON p3_treasury_pool TYPE string;
DEFINE FIELD created_at ON p3_treasury_pool TYPE string;
DEFINE FIELD updated_at ON p3_treasury_pool TYPE string;
DEFINE INDEX idx_pool_type ON p3_treasury_pool FIELDS pool_type UNIQUE;

-- ============================================
-- P3 Treasury Transaction Table
-- ============================================
DEFINE TABLE p3_treasury_tx SCHEMAFULL;
DEFINE FIELD id ON p3_treasury_tx TYPE string;
DEFINE FIELD tenant_id ON p3_treasury_tx TYPE any;
DEFINE FIELD tx_id ON p3_treasury_tx TYPE string;
DEFINE FIELD epoch_id ON p3_treasury_tx TYPE string;
DEFINE FIELD pool_type ON p3_treasury_tx TYPE string;
DEFINE FIELD tx_type ON p3_treasury_tx TYPE string ASSERT $value IN ['deposit', 'withdraw', 'transfer', 'distribution'];
DEFINE FIELD amount_digest ON p3_treasury_tx TYPE string;
DEFINE FIELD currency ON p3_treasury_tx TYPE string;
DEFINE FIELD counterparty_ref ON p3_treasury_tx TYPE option<string>;
DEFINE FIELD reason_code ON p3_treasury_tx TYPE string;
DEFINE FIELD created_at ON p3_treasury_tx TYPE string;
DEFINE INDEX idx_treasury_tx_id ON p3_treasury_tx FIELDS tx_id UNIQUE;
DEFINE INDEX idx_treasury_tx_epoch ON p3_treasury_tx FIELDS epoch_id;
DEFINE INDEX idx_treasury_tx_pool ON p3_treasury_tx FIELDS pool_type;

-- ============================================
-- P3 Clearing Batch Table
-- ============================================
DEFINE TABLE p3_clearing_batch SCHEMAFULL;
DEFINE FIELD id ON p3_clearing_batch TYPE string;
DEFINE FIELD tenant_id ON p3_clearing_batch TYPE any;
DEFINE FIELD batch_id ON p3_clearing_batch TYPE string;
DEFINE FIELD epoch_id ON p3_clearing_batch TYPE string;
DEFINE FIELD batch_digest ON p3_clearing_batch TYPE string;
DEFINE FIELD entry_count ON p3_clearing_batch TYPE int;
DEFINE FIELD total_amount_digest ON p3_clearing_batch TYPE string;
DEFINE FIELD currency ON p3_clearing_batch TYPE string;
DEFINE FIELD status ON p3_clearing_batch TYPE string ASSERT $value IN ['pending', 'processing', 'settled', 'failed'];
DEFINE FIELD created_at ON p3_clearing_batch TYPE string;
DEFINE FIELD settled_at ON p3_clearing_batch TYPE option<string>;
DEFINE INDEX idx_clearing_batch_id ON p3_clearing_batch FIELDS batch_id UNIQUE;
DEFINE INDEX idx_clearing_batch_epoch ON p3_clearing_batch FIELDS epoch_id;
DEFINE INDEX idx_clearing_batch_status ON p3_clearing_batch FIELDS status;

-- ============================================
-- P3 Clearing Entry Table
-- ============================================
DEFINE TABLE p3_clearing_entry SCHEMAFULL;
DEFINE FIELD id ON p3_clearing_entry TYPE string;
DEFINE FIELD tenant_id ON p3_clearing_entry TYPE any;
DEFINE FIELD entry_id ON p3_clearing_entry TYPE string;
DEFINE FIELD batch_id ON p3_clearing_entry TYPE string;
DEFINE FIELD from_actor ON p3_clearing_entry TYPE string;
DEFINE FIELD to_actor ON p3_clearing_entry TYPE string;
DEFINE FIELD amount_digest ON p3_clearing_entry TYPE string;
DEFINE FIELD currency ON p3_clearing_entry TYPE string;
DEFINE FIELD entry_type ON p3_clearing_entry TYPE string;
DEFINE FIELD reference_digest ON p3_clearing_entry TYPE option<string>;
DEFINE FIELD created_at ON p3_clearing_entry TYPE string;
DEFINE INDEX idx_clearing_entry_id ON p3_clearing_entry FIELDS entry_id UNIQUE;
DEFINE INDEX idx_clearing_entry_batch ON p3_clearing_entry FIELDS batch_id;
DEFINE INDEX idx_clearing_entry_actors ON p3_clearing_entry FIELDS from_actor, to_actor;

-- ============================================
-- P3 Fee Schedule Table
-- ============================================
DEFINE TABLE p3_fee_schedule SCHEMAFULL;
DEFINE FIELD id ON p3_fee_schedule TYPE string;
DEFINE FIELD tenant_id ON p3_fee_schedule TYPE any;
DEFINE FIELD schedule_id ON p3_fee_schedule TYPE string;
DEFINE FIELD version ON p3_fee_schedule TYPE int;
DEFINE FIELD schedule_digest ON p3_fee_schedule TYPE string;
DEFINE FIELD effective_from ON p3_fee_schedule TYPE string;
DEFINE FIELD effective_until ON p3_fee_schedule TYPE option<string>;
DEFINE FIELD pool_ratios_json ON p3_fee_schedule TYPE string;
DEFINE FIELD created_at ON p3_fee_schedule TYPE string;
DEFINE INDEX idx_fee_schedule ON p3_fee_schedule FIELDS schedule_id, version UNIQUE;
DEFINE INDEX idx_fee_schedule_effective ON p3_fee_schedule FIELDS effective_from;

-- ============================================
-- P3 Execution Proof Table
-- ============================================
DEFINE TABLE p3_execution_proof SCHEMAFULL;
DEFINE FIELD id ON p3_execution_proof TYPE string;
DEFINE FIELD tenant_id ON p3_execution_proof TYPE any;
DEFINE FIELD proof_id ON p3_execution_proof TYPE string;
DEFINE FIELD epoch_id ON p3_execution_proof TYPE string;
DEFINE FIELD proof_type ON p3_execution_proof TYPE string ASSERT $value IN ['on_chain', 'off_chain', 'credit', 'multi_sig'];
DEFINE FIELD executor_ref ON p3_execution_proof TYPE string;
DEFINE FIELD executed_at ON p3_execution_proof TYPE string;
DEFINE FIELD receipt_ref ON p3_execution_proof TYPE option<string>;
DEFINE FIELD proof_digest ON p3_execution_proof TYPE string;
DEFINE FIELD created_at ON p3_execution_proof TYPE string;
DEFINE INDEX idx_proof_id ON p3_execution_proof FIELDS proof_id UNIQUE;
DEFINE INDEX idx_proof_epoch ON p3_execution_proof FIELDS epoch_id;

-- ============================================
-- P3 Idempotency Key Table
-- ============================================
DEFINE TABLE p3_idempotency_key SCHEMAFULL;
DEFINE FIELD id ON p3_idempotency_key TYPE string;
DEFINE FIELD tenant_id ON p3_idempotency_key TYPE any;
DEFINE FIELD key_value ON p3_idempotency_key TYPE string;
DEFINE FIELD key_digest ON p3_idempotency_key TYPE string;
DEFINE FIELD epoch_id ON p3_idempotency_key TYPE string;
DEFINE FIELD result_digest ON p3_idempotency_key TYPE string;
DEFINE FIELD created_at ON p3_idempotency_key TYPE string;
DEFINE FIELD expires_at ON p3_idempotency_key TYPE option<string>;
DEFINE INDEX idx_idempotency_key ON p3_idempotency_key FIELDS key_value UNIQUE;
DEFINE INDEX idx_idempotency_epoch ON p3_idempotency_key FIELDS epoch_id;

-- ============================================
-- P3 Provider Registration Table
-- ============================================
DEFINE TABLE p3_provider SCHEMAFULL;
DEFINE FIELD id ON p3_provider TYPE string;
DEFINE FIELD tenant_id ON p3_provider TYPE any;
DEFINE FIELD provider_id ON p3_provider TYPE string;
DEFINE FIELD actor_id ON p3_provider TYPE string;
DEFINE FIELD conformance_level ON p3_provider TYPE string ASSERT $value IN ['L1', 'L2', 'L3'];
DEFINE FIELD capabilities_digest ON p3_provider TYPE string;
DEFINE FIELD endpoint_url ON p3_provider TYPE option<string>;
DEFINE FIELD status ON p3_provider TYPE string ASSERT $value IN ['active', 'suspended', 'revoked'];
DEFINE FIELD registered_at ON p3_provider TYPE string;
DEFINE FIELD last_verified_at ON p3_provider TYPE option<string>;
DEFINE FIELD created_at ON p3_provider TYPE string;
DEFINE FIELD updated_at ON p3_provider TYPE string;
DEFINE INDEX idx_provider_id ON p3_provider FIELDS provider_id UNIQUE;
DEFINE INDEX idx_provider_actor ON p3_provider FIELDS actor_id;
DEFINE INDEX idx_provider_level ON p3_provider FIELDS conformance_level;

-- ============================================
-- P3 Version Registry Table
-- ============================================
DEFINE TABLE p3_version_registry SCHEMAFULL;
DEFINE FIELD id ON p3_version_registry TYPE string;
DEFINE FIELD tenant_id ON p3_version_registry TYPE any;
DEFINE FIELD object_type ON p3_version_registry TYPE string ASSERT $value IN ['weights', 'fee_schedule', 'policy', 'canon'];
DEFINE FIELD version_id ON p3_version_registry TYPE string;
DEFINE FIELD version_number ON p3_version_registry TYPE int;
DEFINE FIELD object_digest ON p3_version_registry TYPE string;
DEFINE FIELD status ON p3_version_registry TYPE string ASSERT $value IN ['draft', 'active', 'deprecated', 'superseded'];
DEFINE FIELD effective_from ON p3_version_registry TYPE option<string>;
DEFINE FIELD effective_until ON p3_version_registry TYPE option<string>;
DEFINE FIELD supersedes ON p3_version_registry TYPE option<string>;
DEFINE FIELD created_at ON p3_version_registry TYPE string;
DEFINE INDEX idx_version_id ON p3_version_registry FIELDS version_id UNIQUE;
DEFINE INDEX idx_version_type ON p3_version_registry FIELDS object_type, version_number;
"#;
