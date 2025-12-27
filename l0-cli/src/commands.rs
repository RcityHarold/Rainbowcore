//! Command handlers for the CLI

use l0_core::ledger::{CausalityLedger, IdentityLedger, QueryOptions};
use l0_core::types::{ActorId, ActorType, Digest, ScopeType};
use l0_db::{CausalityService, IdentityService, L0Database, SurrealDatastore};
use soulbase_storage::surreal::SurrealConfig;
use soulbase_types::prelude::TenantId;
use std::path::PathBuf;
use std::sync::Arc;

use crate::ActorCommands;

type CmdResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// Create database config from URL
fn create_db_config(url: &str) -> SurrealConfig {
    SurrealConfig {
        endpoint: url.to_string(),
        namespace: "l0".to_string(),
        database: "ledger".to_string(),
        username: None,
        password: None,
        pool_size: None,
        strict_mode: None,
    }
}

/// Handle actor commands
pub async fn handle_actor_command(
    action: ActorCommands,
    db_url: &str,
    tenant: &str,
) -> CmdResult {
    let config = create_db_config(db_url);
    let datastore = Arc::new(SurrealDatastore::connect(config).await?);
    let database = Arc::new(L0Database::new(datastore));
    let tenant_id = TenantId(tenant.to_string());
    let identity = IdentityService::new(database, tenant_id);

    match action {
        ActorCommands::Register {
            actor_type,
            public_key,
            node_actor_id,
        } => {
            let actor_type = parse_actor_type(&actor_type)?;
            let record = identity
                .register_actor(actor_type, public_key, node_actor_id)
                .await?;

            println!("Actor registered successfully!");
            println!("  Actor ID: {}", record.actor_id.0);
            println!("  Type: {:?}", record.actor_type);
            println!("  Node: {}", record.node_actor_id.0);
            println!("  Created: {}", record.created_at);
        }

        ActorCommands::Get { actor_id } => {
            let actor = identity
                .get_actor(&ActorId(actor_id.clone()))
                .await?
                .ok_or_else(|| format!("Actor {} not found", actor_id))?;

            println!("Actor: {}", actor.actor_id.0);
            println!("  Type: {:?}", actor.actor_type);
            println!("  Node: {}", actor.node_actor_id.0);
            println!("  Status: {:?}", actor.status);
            println!("  Public Key: {}", actor.public_key);
            println!("  Created: {}", actor.created_at);
            println!("  Updated: {}", actor.updated_at);
        }

        ActorCommands::List { actor_type, limit } => {
            let actor_type_filter = actor_type.as_ref().map(|s| parse_actor_type(s)).transpose()?;

            let actors = identity
                .list_actors(
                    actor_type_filter,
                    None,
                    QueryOptions {
                        limit: Some(limit),
                        ..Default::default()
                    },
                )
                .await?;

            println!("Found {} actors:", actors.len());
            for actor in actors {
                println!(
                    "  {} ({:?}) - {:?}",
                    actor.actor_id.0, actor.actor_type, actor.status
                );
            }
        }
    }

    Ok(())
}

/// Handle commit command
pub async fn handle_commit_command(
    actor_id: String,
    scope_type: String,
    file: Option<PathBuf>,
    data: Option<String>,
    db_url: &str,
    tenant: &str,
) -> CmdResult {
    // Get data to commit
    let data_bytes = if let Some(path) = file {
        std::fs::read(&path)?
    } else if let Some(hex_data) = data {
        hex::decode(&hex_data)?
    } else {
        return Err("Either --file or --data must be provided".into());
    };

    // Compute digest
    let commitment_digest = Digest::blake3(&data_bytes);

    // Parse scope type
    let scope_type = parse_scope_type(&scope_type)?;

    // Connect to database
    let config = create_db_config(db_url);
    let datastore = Arc::new(SurrealDatastore::connect(config).await?);
    let database = Arc::new(L0Database::new(datastore));
    let tenant_id = TenantId(tenant.to_string());
    let causality = CausalityService::new(database, tenant_id);
    causality.init().await?;

    // Submit commitment
    let record = causality
        .submit_commitment(&ActorId(actor_id), scope_type, commitment_digest, None)
        .await?;

    println!("Commitment submitted successfully!");
    println!("  Commitment ID: {}", record.commitment_id);
    println!("  Digest: {}", record.commitment_digest.to_hex());
    println!("  Sequence: {}", record.sequence_no);
    println!("  Parent: {:?}", record.parent_commitment_ref);
    println!("  Created: {}", record.created_at);

    Ok(())
}

/// Handle verify command
pub async fn handle_verify_command(
    commitment_id: String,
    depth: Option<u32>,
    db_url: &str,
    tenant: &str,
) -> CmdResult {
    // Connect to database
    let config = create_db_config(db_url);
    let datastore = Arc::new(SurrealDatastore::connect(config).await?);
    let database = Arc::new(L0Database::new(datastore));
    let tenant_id = TenantId(tenant.to_string());
    let causality = CausalityService::new(database, tenant_id);
    causality.init().await?;

    // Get the commitment first
    let commitment = causality
        .get_commitment(&commitment_id)
        .await?
        .ok_or_else(|| format!("Commitment {} not found", commitment_id))?;

    println!("Commitment found:");
    println!("  ID: {}", commitment.commitment_id);
    println!("  Actor: {}", commitment.actor_id.0);
    println!("  Scope: {:?}", commitment.scope_type);
    println!("  Sequence: {}", commitment.sequence_no);

    // Verify the chain
    let valid = causality.verify_chain(&commitment_id, depth).await?;

    if valid {
        println!("\nChain verification: PASSED");
        println!(
            "  Depth checked: {}",
            depth.unwrap_or(1000)
        );
    } else {
        println!("\nChain verification: FAILED");
        println!("  The commitment chain has integrity issues.");
    }

    Ok(())
}

// Helper functions

fn parse_actor_type(s: &str) -> Result<ActorType, String> {
    match s {
        "human_actor" => Ok(ActorType::HumanActor),
        "ai_actor" => Ok(ActorType::AiActor),
        "node_actor" => Ok(ActorType::NodeActor),
        "group_actor" => Ok(ActorType::GroupActor),
        _ => Err(format!("Invalid actor type: {}", s)),
    }
}

fn parse_scope_type(s: &str) -> Result<ScopeType, String> {
    match s {
        "akn_batch" => Ok(ScopeType::AknBatch),
        "consent_batch" => Ok(ScopeType::ConsentBatch),
        "verdict_batch" => Ok(ScopeType::VerdictBatch),
        "dispute_batch" => Ok(ScopeType::DisputeBatch),
        "repair_batch" => Ok(ScopeType::RepairBatch),
        "clawback_batch" => Ok(ScopeType::ClawbackBatch),
        "log_batch" => Ok(ScopeType::LogBatch),
        "trace_batch" => Ok(ScopeType::TraceBatch),
        "backfill_batch" => Ok(ScopeType::BackfillBatch),
        "identity_batch" => Ok(ScopeType::IdentityBatch),
        "covenant_status_batch" => Ok(ScopeType::CovenantStatusBatch),
        _ => Err(format!("Invalid scope type: {}", s)),
    }
}
