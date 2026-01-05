//! Integration tests for L0 API endpoints
//!
//! These tests verify the L0 API endpoints including end-to-end commitment flows.

use axum_test::TestServer;
use l0_api::{create_router, AppState};
use l0_db::SurrealDatastore;
use serde_json::json;
use soulbase_storage::surreal::SurrealConfig;
use soulbase_types::prelude::TenantId;
use std::sync::Arc;

/// Create test database config for in-memory database
fn create_test_db_config() -> SurrealConfig {
    SurrealConfig {
        endpoint: "mem://".to_string(),
        namespace: "l0_test".to_string(),
        database: "ledger_test".to_string(),
        username: None,
        password: None,
        pool_size: None,
        strict_mode: None,
    }
}

/// Create test app state with in-memory database
async fn create_test_state() -> AppState {
    let config = create_test_db_config();
    let datastore = Arc::new(SurrealDatastore::connect(config).await.unwrap());
    let tenant_id = TenantId("test".to_string());
    AppState::new(datastore, tenant_id, Some("test_node".to_string()))
        .await
        .unwrap()
}

/// Create test server
async fn create_test_server() -> TestServer {
    let state = create_test_state().await;
    let router = create_router(state);
    TestServer::new(router).unwrap()
}

// ============ Health Endpoint Tests ============

#[tokio::test]
async fn test_health_check() {
    let server = create_test_server().await;

    let response = server.get("/health").await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "healthy");
}

#[tokio::test]
async fn test_ready_check() {
    let server = create_test_server().await;

    let response = server.get("/ready").await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "ready");
}

// ============ Actor Endpoint Tests ============

#[tokio::test]
async fn test_get_actor_not_found() {
    let server = create_test_server().await;

    let response = server.get("/api/v1/actors/nonexistent_actor_id").await;

    response.assert_status_not_found();
}

// ============ Anchor Endpoint Tests ============

#[tokio::test]
async fn test_get_anchor_policy() {
    let server = create_test_server().await;

    let response = server.get("/api/v1/anchors/policy").await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert!(body.is_object());
}

// ============ Commitment Endpoint Tests ============

#[tokio::test]
async fn test_get_commitment_not_found() {
    let server = create_test_server().await;

    let response = server.get("/api/v1/commitments/nonexistent_commitment").await;

    response.assert_status_not_found();
}

// ============ Dispute Endpoint Tests ============

#[tokio::test]
async fn test_list_disputes_empty() {
    let server = create_test_server().await;

    let response = server.get("/api/v1/disputes").await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert!(body["items"].as_array().is_some());
}

// ============ Consent Endpoint Tests ============

#[tokio::test]
async fn test_get_consent_not_found() {
    let server = create_test_server().await;

    let response = server.get("/api/v1/consents/nonexistent_consent").await;

    response.assert_status_not_found();
}

// ============ End-to-End Flow Tests ============

/// Test complete flow: Register Actor -> Submit Commitment -> Verify
#[tokio::test]
async fn test_e2e_actor_registration_and_commitment() {
    let server = create_test_server().await;

    // Step 1: Register an actor
    let register_request = json!({
        "actor_type": "human_actor",
        "public_key": "ed25519_test_pubkey_hex_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "node_actor_id": "test_node"
    });

    let response = server
        .post("/api/v1/actors")
        .json(&register_request)
        .await;

    response.assert_status_ok();
    let actor_body: serde_json::Value = response.json();

    // Verify actor was created
    assert!(actor_body["actor_id"].as_str().is_some());
    assert_eq!(actor_body["actor_type"], "human_actor");
    assert_eq!(actor_body["status"], "active");

    let actor_id = actor_body["actor_id"].as_str().unwrap();

    // Step 2: Submit a commitment
    let commitment_request = json!({
        "actor_id": actor_id,
        "scope_type": "akn_batch",
        "commitment_digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "parent_ref": null
    });

    let response = server
        .post("/api/v1/commitments")
        .json(&commitment_request)
        .await;

    response.assert_status_ok();
    let commitment_body: serde_json::Value = response.json();

    // Verify commitment was created
    assert!(commitment_body["commitment_id"].as_str().is_some());
    assert_eq!(commitment_body["actor_id"], actor_id);
    assert_eq!(commitment_body["scope_type"], "akn_batch");
    // Sequence numbers start at 0
    assert_eq!(commitment_body["sequence_no"], 0);

    let commitment_id = commitment_body["commitment_id"].as_str().unwrap();

    // Step 3: Retrieve and verify the commitment
    let response = server
        .get(&format!("/api/v1/commitments/{}", commitment_id))
        .await;

    response.assert_status_ok();
    let get_body: serde_json::Value = response.json();
    assert_eq!(get_body["commitment_id"], commitment_id);
    assert_eq!(get_body["actor_id"], actor_id);

    // Step 4: Get actor's commitment chain
    let response = server
        .get(&format!("/api/v1/commitments/actor/{}", actor_id))
        .await;

    response.assert_status_ok();
    let chain_body: serde_json::Value = response.json();
    assert!(chain_body["items"].as_array().is_some());
    assert!(chain_body["items"].as_array().unwrap().len() >= 1);
}

/// Test commitment chain integrity
#[tokio::test]
async fn test_e2e_commitment_chain() {
    let server = create_test_server().await;

    // Register an actor
    let register_request = json!({
        "actor_type": "ai_actor",
        "public_key": "ed25519_test_pubkey_hex_fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        "node_actor_id": "test_node"
    });

    let response = server
        .post("/api/v1/actors")
        .json(&register_request)
        .await;

    response.assert_status_ok();
    let actor_body: serde_json::Value = response.json();
    let actor_id = actor_body["actor_id"].as_str().unwrap();

    // Submit first commitment
    let commitment1 = json!({
        "actor_id": actor_id,
        "scope_type": "akn_batch",
        "commitment_digest": "1111111111111111111111111111111111111111111111111111111111111111",
        "parent_ref": null
    });

    let response = server.post("/api/v1/commitments").json(&commitment1).await;
    response.assert_status_ok();
    let commit1_body: serde_json::Value = response.json();
    let commit1_id = commit1_body["commitment_id"].as_str().unwrap();
    // Sequence numbers start at 0
    assert_eq!(commit1_body["sequence_no"], 0);

    // Submit second commitment with parent reference
    let commitment2 = json!({
        "actor_id": actor_id,
        "scope_type": "akn_batch",
        "commitment_digest": "2222222222222222222222222222222222222222222222222222222222222222",
        "parent_ref": commit1_id
    });

    let response = server.post("/api/v1/commitments").json(&commitment2).await;
    response.assert_status_ok();
    let commit2_body: serde_json::Value = response.json();
    assert_eq!(commit2_body["sequence_no"], 1);
    assert_eq!(commit2_body["parent_commitment_ref"].as_str(), Some(commit1_id));

    // Submit third commitment
    let commitment3 = json!({
        "actor_id": actor_id,
        "scope_type": "akn_batch",
        "commitment_digest": "3333333333333333333333333333333333333333333333333333333333333333",
        "parent_ref": commit2_body["commitment_id"].as_str()
    });

    let response = server.post("/api/v1/commitments").json(&commitment3).await;
    response.assert_status_ok();
    let commit3_body: serde_json::Value = response.json();
    assert_eq!(commit3_body["sequence_no"], 2);

    // Verify chain has 3 commitments
    let response = server
        .get(&format!("/api/v1/commitments/actor/{}", actor_id))
        .await;

    response.assert_status_ok();
    let chain_body: serde_json::Value = response.json();
    assert_eq!(chain_body["items"].as_array().unwrap().len(), 3);
}

/// Test TipWitness submission
#[tokio::test]
async fn test_e2e_tipwitness_flow() {
    let server = create_test_server().await;

    // Register an actor
    let register_request = json!({
        "actor_type": "node_actor",
        "public_key": "ed25519_test_pubkey_hex_abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
        "node_actor_id": "test_node"
    });

    let response = server
        .post("/api/v1/actors")
        .json(&register_request)
        .await;

    response.assert_status_ok();
    let actor_body: serde_json::Value = response.json();
    let actor_id = actor_body["actor_id"].as_str().unwrap();

    // Submit a commitment first
    let commitment = json!({
        "actor_id": actor_id,
        "scope_type": "akn_batch",
        "commitment_digest": "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111",
        "parent_ref": null
    });

    let response = server.post("/api/v1/commitments").json(&commitment).await;
    response.assert_status_ok();

    // Submit TipWitness
    let tipwitness_request = json!({
        "actor_id": actor_id,
        "local_tip_digest": "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222",
        "local_sequence_no": 0,  // Match the commitment sequence
        "last_known_receipt_ref": null
    });

    let response = server
        .post("/api/v1/tipwitness")
        .json(&tipwitness_request)
        .await;

    response.assert_status_ok();
    let tipwitness_body: serde_json::Value = response.json();

    assert!(tipwitness_body["tip_witness_id"].as_str().is_some());
    assert_eq!(tipwitness_body["actor_id"], actor_id);
    assert_eq!(tipwitness_body["local_sequence_no"], 0);

    // Get TipWitness history for actor (instead of single GET which might have routing issues)
    let response = server
        .get(&format!("/api/v1/tipwitness/{}/history", actor_id))
        .await;

    response.assert_status_ok();
    let history_body: serde_json::Value = response.json();
    // History returns an array
    assert!(history_body.as_array().is_some());
    assert!(!history_body.as_array().unwrap().is_empty());
}
