//! Command handlers for the CLI

use chrono::{Duration, Utc};
use l0_core::ledger::{
    AnchorLedger, BackfillLedger, CausalityLedger, ChargeFeeRequest, ConsentLedger,
    CreateAnchorRequest, CreateBackfillRequest, DisputeLedger, IdentityLedger, KnowledgeLedger,
    QueryOptions, ReceiptLedger,
};
use l0_core::types::{
    ActorId, ActorType, AnchorChainType, BackfillStatus, ConsentScope, ConsentType, Digest,
    FeeUnits, ScopeType, SpaceId,
};
use l0_db::{
    AnchorService, BackfillService, CausalityService, ConsentService, DisputeService,
    IdentityService, KnowledgeService, L0Database, ReceiptService, SurrealDatastore,
    TipWitnessService,
};
use soulbase_storage::surreal::SurrealConfig;
use soulbase_types::prelude::TenantId;
use std::path::PathBuf;
use std::sync::Arc;

use crate::{
    ActorCommands, AnchorCommands, BackfillCommands, ConsentCommands, DisputeCommands,
    FeeCommands, KnowledgeCommands, ReceiptCommands, TipWitnessCommands,
};

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

/// Handle knowledge commands
pub async fn handle_knowledge_command(
    action: KnowledgeCommands,
    db_url: &str,
    tenant: &str,
) -> CmdResult {
    let config = create_db_config(db_url);
    let datastore = Arc::new(SurrealDatastore::connect(config).await?);
    let tenant_id = TenantId(tenant.to_string());
    let knowledge = KnowledgeService::new(datastore, tenant_id);

    match action {
        KnowledgeCommands::Index {
            digest,
            owner,
            space,
        } => {
            let content_digest =
                Digest::from_hex(&digest).map_err(|e| format!("Invalid digest hex: {}", e))?;
            let space_id = space.map(SpaceId);

            let entry = knowledge
                .index_content(content_digest, &ActorId(owner), space_id.as_ref(), None)
                .await?;

            println!("Content indexed successfully!");
            println!("  Entry ID: {}", entry.entry_id);
            println!("  Digest: {}", entry.content_digest.to_hex());
            println!("  Owner: {}", entry.owner_actor_id.0);
            println!("  Space: {:?}", entry.space_id.as_ref().map(|s| &s.0));
            println!("  Created: {}", entry.created_at);
        }

        KnowledgeCommands::Get { entry_id } => {
            let entry = knowledge
                .get_entry(&entry_id)
                .await?
                .ok_or_else(|| format!("Entry {} not found", entry_id))?;

            println!("Knowledge Entry: {}", entry.entry_id);
            println!("  Type: {:?}", entry.entry_type);
            println!("  Digest: {}", entry.content_digest.to_hex());
            println!("  Owner: {}", entry.owner_actor_id.0);
            println!("  Space: {:?}", entry.space_id.as_ref().map(|s| &s.0));
            println!("  Evidence Level: {:?}", entry.evidence_level);
            println!("  Anchoring State: {:?}", entry.anchoring_state);
            println!("  Created: {}", entry.created_at);
        }

        KnowledgeCommands::Find { digest } => {
            let content_digest =
                Digest::from_hex(&digest).map_err(|e| format!("Invalid digest hex: {}", e))?;

            let entries = knowledge.get_entries_by_digest(&content_digest).await?;

            println!("Found {} entries:", entries.len());
            for entry in entries {
                println!(
                    "  {} (owner: {}, space: {:?})",
                    entry.entry_id,
                    entry.owner_actor_id.0,
                    entry.space_id.as_ref().map(|s| &s.0)
                );
            }
        }

        KnowledgeCommands::Crossref {
            source,
            target,
            ref_type,
        } => {
            let source_digest =
                Digest::from_hex(&source).map_err(|e| format!("Invalid source digest: {}", e))?;
            let target_digest =
                Digest::from_hex(&target).map_err(|e| format!("Invalid target digest: {}", e))?;

            let xref = knowledge
                .create_cross_reference(source_digest, target_digest, ref_type.clone())
                .await?;

            println!("Cross-reference created!");
            println!("  Ref ID: {}", xref.ref_id);
            println!("  Source: {}", xref.source_digest.to_hex());
            println!("  Target: {}", xref.target_digest.to_hex());
            println!("  Type: {}", xref.ref_type);
            println!("  Created: {}", xref.created_at);
        }
    }

    Ok(())
}

/// Handle consent commands
pub async fn handle_consent_command(
    action: ConsentCommands,
    db_url: &str,
    tenant: &str,
) -> CmdResult {
    let config = create_db_config(db_url);
    let datastore = Arc::new(SurrealDatastore::connect(config).await?);
    let tenant_id = TenantId(tenant.to_string());
    let consent = ConsentService::new(datastore, tenant_id);

    match action {
        ConsentCommands::Grant {
            grantor,
            grantee,
            resource_type,
            actions,
            terms_digest,
        } => {
            let actions_vec: Vec<String> = actions.split(',').map(|s| s.trim().to_string()).collect();
            let terms =
                Digest::from_hex(&terms_digest).map_err(|e| format!("Invalid terms digest: {}", e))?;

            let scope = ConsentScope {
                resource_type: resource_type.clone(),
                resource_id: None,
                actions: actions_vec.clone(),
                constraints_digest: None,
            };

            let record = consent
                .grant_consent(
                    ConsentType::Explicit,
                    &ActorId(grantor),
                    &ActorId(grantee),
                    scope,
                    terms,
                    None,
                )
                .await?;

            println!("Consent granted!");
            println!("  Consent ID: {}", record.consent_id);
            println!("  Grantor: {}", record.grantor.0);
            println!("  Grantee: {}", record.grantee.0);
            println!("  Resource Type: {}", record.scope.resource_type);
            println!("  Actions: {:?}", record.scope.actions);
            println!("  Status: {:?}", record.status);
            println!("  Created: {}", record.granted_at);
        }

        ConsentCommands::Revoke { consent_id } => {
            let receipt = consent.revoke_consent(&consent_id, None).await?;

            println!("Consent revoked!");
            println!("  Consent ID: {}", consent_id);
            println!("  Receipt ID: {}", receipt.0);
        }

        ConsentCommands::Verify {
            grantor,
            grantee,
            action,
            resource_type,
        } => {
            let result = consent
                .verify_consent(&ActorId(grantor), &ActorId(grantee), &action, &resource_type)
                .await?;

            if result.valid {
                println!("Consent verification: VALID");
                if let Some(consent_ref) = result.consent_ref {
                    println!("  Consent Reference: {}", consent_ref);
                }
            } else {
                println!("Consent verification: INVALID or NOT FOUND");
                if !result.reason.is_empty() {
                    println!("  Reason: {}", result.reason);
                }
            }
        }

        ConsentCommands::Get { consent_id } => {
            let record = consent
                .get_consent(&consent_id)
                .await?
                .ok_or_else(|| format!("Consent {} not found", consent_id))?;

            println!("Consent: {}", record.consent_id);
            println!("  Grantor: {}", record.grantor.0);
            println!("  Grantee: {}", record.grantee.0);
            println!("  Resource Type: {}", record.scope.resource_type);
            println!("  Actions: {:?}", record.scope.actions);
            println!("  Status: {:?}", record.status);
            println!("  Terms Digest: {}", record.terms_digest.to_hex());
            println!("  Granted At: {}", record.granted_at);
            if let Some(revoked) = record.revoked_at {
                println!("  Revoked At: {}", revoked);
            }
        }

        ConsentCommands::Ticket {
            consent_ref,
            holder,
            target,
            permissions,
            one_time,
        } => {
            let perms: Vec<String> = permissions.split(',').map(|s| s.trim().to_string()).collect();
            let valid_until = Utc::now() + Duration::hours(24);

            let ticket = consent
                .issue_ticket(&consent_ref, &ActorId(holder), target, perms, valid_until, one_time)
                .await?;

            println!("Access ticket issued!");
            println!("  Ticket ID: {}", ticket.ticket_id);
            println!("  Holder: {}", ticket.holder.0);
            println!("  Target: {}", ticket.target_resource);
            println!("  Permissions: {:?}", ticket.permissions);
            println!("  One-time: {}", ticket.one_time);
            println!("  Valid Until: {}", ticket.valid_until);
            println!("  Issued At: {}", ticket.issued_at);
        }
    }

    Ok(())
}

/// Handle dispute commands
pub async fn handle_dispute_command(
    action: DisputeCommands,
    db_url: &str,
    tenant: &str,
) -> CmdResult {
    let config = create_db_config(db_url);
    let datastore = Arc::new(SurrealDatastore::connect(config).await?);
    let tenant_id = TenantId(tenant.to_string());
    let dispute = DisputeService::new(datastore, tenant_id);

    match action {
        DisputeCommands::File {
            filed_by,
            filed_against,
            priority,
            subject,
            evidence,
        } => {
            let against: Vec<ActorId> = filed_against
                .split(',')
                .map(|s| ActorId(s.trim().to_string()))
                .collect();
            let priority = parse_dispute_priority(&priority)?;
            let evidence_digest =
                Digest::from_hex(&evidence).map_err(|e| format!("Invalid evidence digest: {}", e))?;

            let record = dispute
                .file_dispute(&ActorId(filed_by), against, priority, subject, evidence_digest)
                .await?;

            println!("Dispute filed!");
            println!("  Dispute ID: {}", record.dispute_id);
            println!("  Filed By: {}", record.filed_by.0);
            println!("  Filed Against: {:?}", record.filed_against.iter().map(|a| &a.0).collect::<Vec<_>>());
            println!("  Priority: {:?}", record.priority);
            println!("  Status: {:?}", record.status);
            println!("  Filed At: {}", record.filed_at);
        }

        DisputeCommands::Get { dispute_id } => {
            let record = dispute
                .get_dispute(&dispute_id)
                .await?
                .ok_or_else(|| format!("Dispute {} not found", dispute_id))?;

            println!("Dispute: {}", record.dispute_id);
            println!("  Filed By: {}", record.filed_by.0);
            println!("  Filed Against: {:?}", record.filed_against.iter().map(|a| &a.0).collect::<Vec<_>>());
            println!("  Priority: {:?}", record.priority);
            println!("  Status: {:?}", record.status);
            println!("  Subject: {}", record.subject_commitment_ref);
            println!("  Evidence: {}", record.evidence_digest.to_hex());
            println!("  Filed At: {}", record.filed_at);
        }

        DisputeCommands::List { status, limit } => {
            let status_filter = status.as_ref().map(|s| parse_dispute_status(s)).transpose()?;

            let disputes = dispute
                .list_disputes(
                    status_filter,
                    None,
                    QueryOptions {
                        limit: Some(limit),
                        ..Default::default()
                    },
                )
                .await?;

            println!("Found {} disputes:", disputes.len());
            for d in disputes {
                println!(
                    "  {} - {:?} (by: {}, priority: {:?})",
                    d.dispute_id, d.status, d.filed_by.0, d.priority
                );
            }
        }

        DisputeCommands::Verdict {
            dispute_id,
            verdict_type,
            verdict_digest,
            rationale_digest,
            issued_by,
        } => {
            let vtype = parse_verdict_type(&verdict_type)?;
            let vdigest =
                Digest::from_hex(&verdict_digest).map_err(|e| format!("Invalid verdict digest: {}", e))?;
            let rdigest =
                Digest::from_hex(&rationale_digest).map_err(|e| format!("Invalid rationale digest: {}", e))?;

            let verdict = dispute
                .issue_verdict(&dispute_id, vtype, vdigest, rdigest, None, issued_by, None)
                .await?;

            println!("Verdict issued!");
            println!("  Verdict ID: {}", verdict.verdict_id);
            println!("  Dispute ID: {}", verdict.dispute_id);
            println!("  Type: {:?}", verdict.verdict_type);
            println!("  Issued By: {}", verdict.issued_by);
            println!("  Issued At: {}", verdict.issued_at);
        }

        DisputeCommands::Clawback {
            verdict_id,
            clawback_type,
            targets,
            affected,
        } => {
            let ctype = parse_clawback_type(&clawback_type)?;
            let target_refs: Vec<String> = targets.split(',').map(|s| s.trim().to_string()).collect();
            let affected_actors: Vec<ActorId> = affected
                .split(',')
                .map(|s| ActorId(s.trim().to_string()))
                .collect();

            let clawback = dispute
                .initiate_clawback(&verdict_id, ctype, target_refs, affected_actors, None)
                .await?;

            println!("Clawback initiated!");
            println!("  Clawback ID: {}", clawback.clawback_id);
            println!("  Verdict ID: {}", clawback.verdict_id);
            println!("  Type: {:?}", clawback.clawback_type);
            println!("  Status: {:?}", clawback.status);
            println!("  Initiated At: {}", clawback.initiated_at);
        }
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

fn parse_dispute_priority(s: &str) -> Result<l0_core::types::DisputePriority, String> {
    use l0_core::types::DisputePriority;
    match s {
        "normal" => Ok(DisputePriority::Normal),
        "urgent" => Ok(DisputePriority::Urgent),
        "critical" => Ok(DisputePriority::Critical),
        _ => Err(format!("Invalid priority: {}. Use: normal, urgent, critical", s)),
    }
}

fn parse_dispute_status(s: &str) -> Result<l0_core::types::DisputeStatus, String> {
    use l0_core::types::DisputeStatus;
    match s {
        "filed" => Ok(DisputeStatus::Filed),
        "under_review" => Ok(DisputeStatus::UnderReview),
        "verdict_issued" => Ok(DisputeStatus::VerdictIssued),
        "repair_in_progress" => Ok(DisputeStatus::RepairInProgress),
        "resolved" => Ok(DisputeStatus::Resolved),
        "dismissed" => Ok(DisputeStatus::Dismissed),
        _ => Err(format!("Invalid status: {}. Use: filed, under_review, verdict_issued, repair_in_progress, resolved, dismissed", s)),
    }
}

fn parse_verdict_type(s: &str) -> Result<l0_core::types::VerdictType, String> {
    use l0_core::types::VerdictType;
    match s {
        "in_favor" => Ok(VerdictType::InFavor),
        "against" => Ok(VerdictType::Against),
        "mixed" => Ok(VerdictType::Mixed),
        "dismissed" => Ok(VerdictType::Dismissed),
        "inconclusive" => Ok(VerdictType::Inconclusive),
        _ => Err(format!("Invalid verdict type: {}. Use: in_favor, against, mixed, dismissed, inconclusive", s)),
    }
}

fn parse_clawback_type(s: &str) -> Result<l0_core::types::ClawbackType, String> {
    use l0_core::types::ClawbackType;
    match s {
        "full_reverse" => Ok(ClawbackType::FullReverse),
        "partial_reverse" => Ok(ClawbackType::PartialReverse),
        "compensation" => Ok(ClawbackType::Compensation),
        "penalty" => Ok(ClawbackType::Penalty),
        _ => Err(format!("Invalid clawback type: {}. Use: full_reverse, partial_reverse, compensation, penalty", s)),
    }
}

/// Handle receipt commands
pub async fn handle_receipt_command(
    action: ReceiptCommands,
    db_url: &str,
    tenant: &str,
) -> CmdResult {
    let config = create_db_config(db_url);
    let datastore = Arc::new(SurrealDatastore::connect(config).await?);
    let tenant_id = TenantId(tenant.to_string());
    let receipt_service = ReceiptService::new(datastore, tenant_id);

    match action {
        ReceiptCommands::Get { receipt_id } => {
            let receipt = receipt_service
                .get_receipt(&receipt_id)
                .await?
                .ok_or_else(|| format!("Receipt {} not found", receipt_id))?;

            println!("Receipt: {}", receipt.receipt_id.0);
            println!("  Scope Type: {:?}", receipt.scope_type);
            println!("  Root Kind: {:?}", receipt.root_kind);
            println!("  Root: {}", receipt.root.to_hex());
            println!("  Time Window: {} to {}", receipt.time_window_start, receipt.time_window_end);
            println!("  Batch Sequence: {:?}", receipt.batch_sequence_no);
            println!("  Signer Set Version: {}", receipt.signer_set_version);
            println!("  Created: {}", receipt.created_at);
            if let Some(rejected) = receipt.rejected {
                println!("  Rejected: {}", rejected);
                if let Some(reason) = &receipt.reject_reason_code {
                    println!("  Reject Reason: {}", reason);
                }
            }
        }

        ReceiptCommands::Verify { receipt_id } => {
            let result = receipt_service.verify_receipt(&receipt_id).await?;

            if result.valid {
                println!("Receipt verification: VALID");
                println!("  Evidence Level: {:?}", result.evidence_level);
                println!("  Chain Anchored: {}", result.chain_anchored);
            } else {
                println!("Receipt verification: INVALID");
                for err in &result.errors {
                    println!("  Error: {}", err);
                }
            }
        }

        ReceiptCommands::List { scope_type, limit } => {
            let scope_filter = scope_type.as_ref().map(|s| parse_scope_type(s)).transpose()?;

            let receipts = receipt_service
                .list_receipts(
                    scope_filter,
                    QueryOptions {
                        limit: Some(limit),
                        ..Default::default()
                    },
                )
                .await?;

            println!("Found {} receipts:", receipts.len());
            for r in receipts {
                println!(
                    "  {} - {:?} (batch: {:?}, created: {})",
                    r.receipt_id.0, r.scope_type, r.batch_sequence_no, r.created_at
                );
            }
        }

        ReceiptCommands::Batch { batch_sequence } => {
            let receipts = receipt_service
                .get_receipts_by_batch(batch_sequence)
                .await?;

            println!("Found {} receipts in batch {}:", receipts.len(), batch_sequence);
            for r in receipts {
                println!(
                    "  {} - {:?} (root: {})",
                    r.receipt_id.0, r.scope_type, r.root.to_hex()
                );
            }
        }
    }

    Ok(())
}

/// Handle TipWitness commands
pub async fn handle_tipwitness_command(
    action: TipWitnessCommands,
    db_url: &str,
    tenant: &str,
) -> CmdResult {
    let config = create_db_config(db_url);
    let datastore = Arc::new(SurrealDatastore::connect(config).await?);
    let database = Arc::new(L0Database::new(datastore));
    database.init_schema().await?;
    let tenant_id = TenantId(tenant.to_string());
    let tipwitness = TipWitnessService::new(database, tenant_id);

    match action {
        TipWitnessCommands::Submit {
            actor_id,
            digest,
            sequence,
            receipt_ref,
        } => {
            let tip_digest =
                Digest::from_hex(&digest).map_err(|e| format!("Invalid digest hex: {}", e))?;

            let result = tipwitness
                .submit_tip_witness(&ActorId(actor_id), tip_digest, sequence, receipt_ref)
                .await?;

            println!("TipWitness submitted successfully!");
            println!("  TipWitness ID: {}", result.tip_witness.tip_witness_id);
            println!("  Actor: {}", result.tip_witness.actor_id.0);
            println!("  Local Tip Digest: {}", result.tip_witness.local_tip_digest.to_hex());
            println!("  Local Sequence: {}", result.tip_witness.local_sequence_no);
            println!("  Witnessed At: {}", result.tip_witness.witnessed_at);
            println!("  Is First Witness: {}", result.is_first_witness);
            println!("  Receipt ID: {}", result.receipt.receipt_id.0);
        }

        TipWitnessCommands::Get { actor_id } => {
            let entity = tipwitness
                .get_latest_tip_witness(&ActorId(actor_id.clone()))
                .await?
                .ok_or_else(|| format!("No TipWitness found for actor {}", actor_id))?;

            println!("Latest TipWitness for actor {}:", actor_id);
            println!("  TipWitness ID: {}", entity.tip_witness_id);
            println!("  Local Tip Digest: {}", entity.local_tip_digest);
            println!("  Local Sequence: {}", entity.local_sequence_no);
            println!("  Last Known Receipt: {:?}", entity.last_known_receipt_ref);
            println!("  Witnessed At: {}", entity.witnessed_at);
        }

        TipWitnessCommands::History { actor_id, limit } => {
            let history = tipwitness
                .get_tip_witness_history(&ActorId(actor_id.clone()), limit)
                .await?;

            println!("TipWitness history for actor {} ({} entries):", actor_id, history.len());
            for tw in history {
                println!(
                    "  {} - seq {} (digest: {}, at: {})",
                    tw.tip_witness_id, tw.local_sequence_no, tw.local_tip_digest.to_hex(), tw.witnessed_at
                );
            }
        }

        TipWitnessCommands::Verify { actor_id } => {
            let result = tipwitness
                .verify_tip_witness_chain(&ActorId(actor_id.clone()))
                .await?;

            if result.is_valid {
                println!("TipWitness chain verification: VALID");
            } else {
                println!("TipWitness chain verification: INVALID");
            }
            println!("  Witness Count: {}", result.witness_count);
            println!("  Earliest Sequence: {:?}", result.earliest_sequence);
            println!("  Latest Sequence: {:?}", result.latest_sequence);
            if !result.gaps.is_empty() {
                println!("  Gaps found:");
                for gap in &result.gaps {
                    println!(
                        "    {} - from {} to {}",
                        gap.gap_type, gap.from_sequence, gap.to_sequence
                    );
                }
            }
        }
    }

    Ok(())
}

/// Handle fee commands
pub async fn handle_fee_command(
    action: FeeCommands,
    db_url: &str,
    tenant: &str,
) -> CmdResult {
    let config = create_db_config(db_url);
    let datastore = Arc::new(SurrealDatastore::connect(config).await?);
    let tenant_id = TenantId(tenant.to_string());
    let receipt_service = ReceiptService::new(datastore, tenant_id);

    match action {
        FeeCommands::Charge {
            payer,
            units,
            anchor_id,
        } => {
            let request = ChargeFeeRequest {
                payer_actor_id: ActorId(payer),
                anchor_type: "batch".to_string(),
                units: FeeUnits::BatchRoot,
                units_count: units,
                fee_schedule_version: "v1".to_string(),
                linked_anchor_id: anchor_id,
                risk_multiplier: None,
                deposit_amount: None,
                discount_digest: None,
                subsidy_digest: None,
            };

            let fee = receipt_service.charge_fee(request).await?;

            println!("Fee charged successfully!");
            println!("  Fee Receipt ID: {}", fee.fee_receipt_id);
            println!("  Payer: {}", fee.payer_actor_id);
            println!("  Units: {:?} x {}", fee.units, fee.units_count);
            println!("  Amount: {}", fee.amount);
            println!("  Status: {:?}", fee.status);
            println!("  Timestamp: {}", fee.timestamp);
        }

        FeeCommands::Get { fee_receipt_id } => {
            let fee = receipt_service
                .get_fee_receipt(&fee_receipt_id)
                .await?
                .ok_or_else(|| format!("Fee receipt {} not found", fee_receipt_id))?;

            println!("Fee Receipt: {}", fee.fee_receipt_id);
            println!("  Payer: {}", fee.payer_actor_id);
            println!("  Units: {:?} x {}", fee.units, fee.units_count);
            println!("  Amount: {}", fee.amount);
            println!("  Status: {:?}", fee.status);
            println!("  Fee Schedule Version: {}", fee.fee_schedule_version);
            println!("  Timestamp: {}", fee.timestamp);
            if let Some(receipt_id) = &fee.linked_receipt_id {
                println!("  Linked Receipt: {}", receipt_id);
            }
        }

        FeeCommands::Pending { actor_id } => {
            let pending = receipt_service
                .get_pending_fees(&ActorId(actor_id.clone()))
                .await?;

            println!("Pending fees for actor {} ({} entries):", actor_id, pending.len());
            let mut total: u64 = 0;
            for fee in &pending {
                println!(
                    "  {} - {} units (amount: {})",
                    fee.fee_receipt_id, fee.units_count, fee.amount
                );
                total += fee.units_count as u64;
            }
            println!("Total pending units: {}", total);
        }

        FeeCommands::History { actor_id, limit } => {
            let history = receipt_service
                .get_fee_history(
                    &ActorId(actor_id.clone()),
                    QueryOptions {
                        limit: Some(limit),
                        ..Default::default()
                    },
                )
                .await?;

            println!("Fee history for actor {} ({} entries):", actor_id, history.len());
            for fee in history {
                println!(
                    "  {} - {:?} (units: {}, amount: {}, at: {})",
                    fee.fee_receipt_id, fee.status, fee.units_count, fee.amount, fee.timestamp
                );
            }
        }

        FeeCommands::Refund { fee_receipt_id } => {
            receipt_service
                .refund_fee(&fee_receipt_id, None)
                .await?;

            println!("Fee refunded successfully!");
            println!("  Fee Receipt ID: {}", fee_receipt_id);
        }
    }

    Ok(())
}

/// Handle backfill commands
pub async fn handle_backfill_command(
    action: BackfillCommands,
    db_url: &str,
    tenant: &str,
) -> CmdResult {
    let config = create_db_config(db_url);
    let datastore = Arc::new(SurrealDatastore::connect(config).await?);
    let tenant_id = TenantId(tenant.to_string());
    let backfill = BackfillService::new(datastore, tenant_id);

    match action {
        BackfillCommands::Create {
            actor_id,
            start_digest,
            start_seq,
            end_digest,
            end_seq,
            tip_witness_ref,
        } => {
            let start = Digest::from_hex(&start_digest)
                .map_err(|e| format!("Invalid start digest: {}", e))?;
            let end = Digest::from_hex(&end_digest)
                .map_err(|e| format!("Invalid end digest: {}", e))?;

            let request = CreateBackfillRequest {
                actor_id: ActorId(actor_id),
                start_digest: start,
                start_sequence_no: start_seq,
                end_digest: end,
                end_sequence_no: end_seq,
                tip_witness_ref,
                scope_filter: None,
            };

            let result = backfill.create_request(request).await?;

            println!("Backfill request created!");
            println!("  Request ID: {}", result.request_id);
            println!("  Actor: {}", result.actor_id.0);
            println!("  Status: {:?}", result.status);
            println!("  Range: {} to {}", result.start_sequence_no, result.end_sequence_no);
            println!("  Requested At: {}", result.requested_at);
        }

        BackfillCommands::Get { request_id } => {
            let request = backfill
                .get_request(&request_id)
                .await?
                .ok_or_else(|| format!("Backfill request {} not found", request_id))?;

            println!("Backfill Request: {}", request.request_id);
            println!("  Actor: {}", request.actor_id.0);
            println!("  Status: {:?}", request.status);
            println!("  Start: {} (digest: {})", request.start_sequence_no, request.start_digest.to_hex());
            println!("  End: {} (digest: {})", request.end_sequence_no, request.end_digest.to_hex());
            println!("  TipWitness: {}", request.tip_witness_ref);
            println!("  Requested At: {}", request.requested_at);
            if let Some(completed) = request.completed_at {
                println!("  Completed At: {}", completed);
            }
        }

        BackfillCommands::List { actor_id, status } => {
            let status_filter = status.as_ref().map(|s| parse_backfill_status(s)).transpose()?;

            let requests = backfill
                .list_requests(&ActorId(actor_id.clone()), status_filter)
                .await?;

            println!("Backfill requests for actor {} ({} entries):", actor_id, requests.len());
            for req in requests {
                println!(
                    "  {} - {:?} (range: {} to {})",
                    req.request_id, req.status, req.start_sequence_no, req.end_sequence_no
                );
            }
        }

        BackfillCommands::Plan { request_id } => {
            let plan = backfill.generate_plan(&request_id).await?;

            println!("Backfill plan generated!");
            println!("  Plan ID: {}", plan.plan_id);
            println!("  Request: {}", plan.request_ref);
            println!("  Items: {}", plan.anchor_sequence.len());
            println!("  Estimated Fee: {}", plan.estimated_fee);
            println!("  Gaps: {}", plan.gaps.len());
            println!("  Continuity: {:?}", plan.continuity_result);
            println!("  Created: {}", plan.created_at);
            println!("  Expires: {}", plan.expires_at);
        }

        BackfillCommands::Execute { plan_id } => {
            let receipt = backfill.execute_plan(&plan_id).await?;

            println!("Backfill executed!");
            println!("  Receipt ID: {}", receipt.backfill_receipt_id);
            println!("  Objects Anchored: {}", receipt.objects_anchored);
            println!("  Total Fee Paid: {}", receipt.total_fee_paid);
            println!("  Continuity: {:?}", receipt.continuity_result);
            println!("  Completed At: {}", receipt.completed_at);
        }

        BackfillCommands::Cancel { request_id, reason } => {
            backfill.cancel_request(&request_id, reason).await?;

            println!("Backfill request cancelled!");
            println!("  Request ID: {}", request_id);
        }

        BackfillCommands::Gaps { actor_id, start, end } => {
            let gaps = backfill
                .detect_gaps(&ActorId(actor_id.clone()), start, end)
                .await?;

            println!("Gaps detected for actor {} (range {} to {}):", actor_id, start, end);
            if gaps.is_empty() {
                println!("  No gaps found");
            } else {
                for gap in gaps {
                    println!(
                        "  {} - {:?} (from {} to {}, acceptable: {})",
                        gap.gap_id, gap.gap_type, gap.start_sequence, gap.end_sequence, gap.acceptable
                    );
                }
            }
        }

        BackfillCommands::Continuity { actor_id, start, end } => {
            let result = backfill
                .verify_continuity(&ActorId(actor_id.clone()), start, end)
                .await?;

            println!("Continuity check for actor {} (range {} to {}):", actor_id, start, end);
            println!("  Result: {:?}", result);
        }

        BackfillCommands::History { actor_id, limit } => {
            let history = backfill
                .get_backfill_history(&ActorId(actor_id.clone()), limit)
                .await?;

            println!("Backfill history for actor {} ({} entries):", actor_id, history.len());
            for receipt in history {
                println!(
                    "  {} - {} objects (fee: {}, at: {})",
                    receipt.backfill_receipt_id, receipt.objects_anchored, receipt.total_fee_paid, receipt.completed_at
                );
            }
        }
    }

    Ok(())
}

/// Handle anchor commands
pub async fn handle_anchor_command(
    action: AnchorCommands,
    db_url: &str,
    tenant: &str,
) -> CmdResult {
    let config = create_db_config(db_url);
    let datastore = Arc::new(SurrealDatastore::connect(config).await?);
    let tenant_id = TenantId(tenant.to_string());
    let anchor = AnchorService::new(datastore, tenant_id);

    match action {
        AnchorCommands::Create {
            chain,
            epoch_root,
            epoch_sequence,
            batch_count,
        } => {
            let root = Digest::from_hex(&epoch_root)
                .map_err(|e| format!("Invalid epoch root: {}", e))?;
            let chain_type = parse_chain_type(&chain)?;
            let now = Utc::now();

            let request = CreateAnchorRequest {
                chain_type,
                epoch_root: root,
                epoch_sequence,
                epoch_start: now - Duration::hours(1),
                epoch_end: now,
                batch_count,
                epoch_proof: None,
            };

            let result = anchor.create_anchor(request).await?;

            println!("Anchor created!");
            println!("  Anchor ID: {}", result.anchor_id);
            println!("  Chain: {:?}", result.chain_type);
            println!("  Epoch Sequence: {}", result.epoch_sequence);
            println!("  Status: {:?}", result.status);
            println!("  Required Confirmations: {}", result.required_confirmations);
            println!("  Created At: {}", result.created_at);
        }

        AnchorCommands::Get { anchor_id } => {
            let tx = anchor
                .get_anchor(&anchor_id)
                .await?
                .ok_or_else(|| format!("Anchor {} not found", anchor_id))?;

            println!("Anchor: {}", tx.anchor_id);
            println!("  Chain: {:?}", tx.chain_type);
            println!("  Epoch Root: {}", tx.epoch_root.to_hex());
            println!("  Epoch Sequence: {}", tx.epoch_sequence);
            println!("  Epoch Range: {} to {}", tx.epoch_start, tx.epoch_end);
            println!("  Batch Count: {}", tx.batch_count);
            println!("  Status: {:?}", tx.status);
            println!("  TX Hash: {:?}", tx.tx_hash);
            println!("  Block Number: {:?}", tx.block_number);
            println!("  Confirmations: {}/{}", tx.confirmations, tx.required_confirmations);
            println!("  Created At: {}", tx.created_at);
        }

        AnchorCommands::Epoch { chain, epoch_sequence } => {
            let chain_type = parse_chain_type(&chain)?;
            let tx = anchor
                .get_anchor_by_epoch(chain_type, epoch_sequence)
                .await?
                .ok_or_else(|| format!("No anchor for epoch {} on {}", epoch_sequence, chain))?;

            println!("Anchor for {} epoch {}:", chain, epoch_sequence);
            println!("  Anchor ID: {}", tx.anchor_id);
            println!("  Status: {:?}", tx.status);
            println!("  TX Hash: {:?}", tx.tx_hash);
            println!("  Confirmations: {}/{}", tx.confirmations, tx.required_confirmations);
        }

        AnchorCommands::Submit { anchor_id } => {
            let tx_hash = anchor.submit_anchor(&anchor_id).await?;

            println!("Anchor submitted!");
            println!("  Anchor ID: {}", anchor_id);
            println!("  TX Hash: {}", tx_hash);
        }

        AnchorCommands::Status { anchor_id } => {
            let status = anchor.check_anchor_status(&anchor_id).await?;

            println!("Anchor status for {}:", anchor_id);
            println!("  Status: {:?}", status);
        }

        AnchorCommands::Verify { anchor_id } => {
            let verification = anchor.verify_anchor(&anchor_id).await?;

            println!("Anchor verification for {}:", anchor_id);
            println!("  Valid: {}", verification.valid);
            println!("  Chain: {:?}", verification.chain_type);
            println!("  TX Hash: {:?}", verification.tx_hash);
            println!("  Block Number: {:?}", verification.block_number);
            println!("  Confirmations: {}", verification.confirmations);
            println!("  Epoch Root Matches: {}", verification.epoch_root_matches);
            println!("  Proof Verified: {}", verification.proof_verified);
            if !verification.errors.is_empty() {
                println!("  Errors:");
                for err in &verification.errors {
                    println!("    - {}", err);
                }
            }
        }

        AnchorCommands::Pending { chain } => {
            let chain_type = chain.as_ref().map(|s| parse_chain_type(s)).transpose()?;
            let pending = anchor.get_pending_anchors(chain_type).await?;

            println!("Pending anchors ({} entries):", pending.len());
            for tx in pending {
                println!(
                    "  {} - {:?} epoch {} ({:?})",
                    tx.anchor_id, tx.chain_type, tx.epoch_sequence, tx.status
                );
            }
        }

        AnchorCommands::Finalized { chain, limit } => {
            let chain_type = parse_chain_type(&chain)?;
            let finalized = anchor.get_finalized_anchors(chain_type, limit).await?;

            println!("Finalized anchors on {} ({} entries):", chain, finalized.len());
            for tx in finalized {
                println!(
                    "  {} - epoch {} (block: {:?}, confirmations: {})",
                    tx.anchor_id, tx.epoch_sequence, tx.block_number, tx.confirmations
                );
            }
        }

        AnchorCommands::History { chain, from, to } => {
            let chain_type = parse_chain_type(&chain)?;
            let history = anchor.get_anchor_history(chain_type, from, to).await?;

            println!("Anchor history for {} epochs {} to {} ({} entries):", chain, from, to, history.len());
            for tx in history {
                println!(
                    "  {} - epoch {} ({:?})",
                    tx.anchor_id, tx.epoch_sequence, tx.status
                );
            }
        }

        AnchorCommands::Retry { anchor_id } => {
            let tx = anchor.retry_anchor(&anchor_id).await?;

            println!("Anchor retry initiated!");
            println!("  Anchor ID: {}", tx.anchor_id);
            println!("  Status: {:?}", tx.status);
        }

        AnchorCommands::Latest { chain } => {
            let chain_type = parse_chain_type(&chain)?;
            let epoch = anchor.get_latest_finalized_epoch(chain_type).await?;

            println!("Latest finalized epoch on {}:", chain);
            match epoch {
                Some(e) => println!("  Epoch: {}", e),
                None => println!("  No finalized epochs yet"),
            }
        }

        AnchorCommands::Policy => {
            let policy = anchor.get_anchor_policy().await?;

            println!("Anchor Policy:");
            println!("  Version: {}", policy.version);
            println!("  Enabled Chains: {:?}", policy.enabled_chains);
            println!("  Primary Chain: {:?}", policy.primary_chain);
            println!("  Epoch Interval: {} batches", policy.epoch_interval);
            println!("  Max Anchor Delay: {} seconds", policy.max_anchor_delay);
            println!("  Retry Count: {}", policy.retry_count);
            println!("  Gas Strategy: {:?}", policy.gas_strategy);
        }

        AnchorCommands::UpdatePolicy {
            primary_chain,
            epoch_interval,
            max_delay,
        } => {
            use l0_core::types::{AnchorPolicy, GasStrategy};
            use std::collections::HashMap;

            let primary = parse_chain_type(&primary_chain)?;
            let mut min_confirmations = HashMap::new();
            min_confirmations.insert("ethereum".to_string(), 12u32);
            min_confirmations.insert("bitcoin".to_string(), 6u32);
            min_confirmations.insert("polygon".to_string(), 256u32);
            min_confirmations.insert("solana".to_string(), 32u32);

            let policy = AnchorPolicy {
                version: "v1.0.0".to_string(),
                enabled_chains: vec![primary],
                primary_chain: primary,
                epoch_interval,
                max_anchor_delay: max_delay,
                retry_count: 3,
                gas_strategy: GasStrategy::Standard,
                min_confirmations,
            };

            anchor.update_anchor_policy(policy).await?;

            println!("Anchor policy updated!");
            println!("  Primary Chain: {}", primary_chain);
            println!("  Epoch Interval: {} batches", epoch_interval);
            println!("  Max Anchor Delay: {} seconds", max_delay);
        }
    }

    Ok(())
}

// Additional helper functions

fn parse_backfill_status(s: &str) -> Result<BackfillStatus, String> {
    match s {
        "requested" => Ok(BackfillStatus::Requested),
        "plan_generated" => Ok(BackfillStatus::PlanGenerated),
        "in_progress" => Ok(BackfillStatus::InProgress),
        "completed" => Ok(BackfillStatus::Completed),
        "failed" => Ok(BackfillStatus::Failed),
        "cancelled" => Ok(BackfillStatus::Cancelled),
        _ => Err(format!("Invalid backfill status: {}. Use: requested, plan_generated, in_progress, completed, failed, cancelled", s)),
    }
}

fn parse_chain_type(s: &str) -> Result<AnchorChainType, String> {
    match s.to_lowercase().as_str() {
        "ethereum" => Ok(AnchorChainType::Ethereum),
        "bitcoin" => Ok(AnchorChainType::Bitcoin),
        "polygon" => Ok(AnchorChainType::Polygon),
        "solana" => Ok(AnchorChainType::Solana),
        "internal" => Ok(AnchorChainType::Internal),
        _ => Err(format!("Invalid chain type: {}. Use: ethereum, bitcoin, polygon, solana, internal", s)),
    }
}
