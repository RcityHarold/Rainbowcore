//! L0 Command Line Interface
//!
//! Configuration is loaded from environment variables (via .env file).
//! Command-line arguments override environment variables.
//!
//! Usage:
//!   l0 init           - Initialize L0 node
//!   l0 start          - Start L0 node
//!   l0 status         - Show node status
//!   l0 commit         - Submit a commitment
//!   l0 verify <id>    - Verify a receipt
//!   l0 backfill       - Request backfill
//!   l0 knowledge      - Knowledge-Index operations
//!   l0 consent        - Policy-Consent operations
//!   l0 dispute        - Dispute-Resolution operations
//!   l0 interactive    - Interactive REPL mode
//!   l0 batch          - Batch operations from file

use clap::{Parser, Subcommand};
use l0_api::{run_server, ApiConfig};
use l0_db::SurrealDatastore;
use soulbase_storage::surreal::SurrealConfig;
use std::path::PathBuf;
use std::sync::Arc;

mod batch;
mod commands;
mod interactive;

#[derive(Parser)]
#[command(name = "l0")]
#[command(about = "L0 Public Reality Ledger CLI")]
#[command(version)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, default_value = "l0.toml")]
    config: PathBuf,

    /// Database URL (env: L0_DB_URL)
    #[arg(long, env = "L0_DB_URL", default_value = "mem://")]
    db_url: String,

    /// Database namespace (env: L0_DB_NAMESPACE)
    #[arg(long, env = "L0_DB_NAMESPACE", default_value = "l0")]
    db_namespace: String,

    /// Database name (env: L0_DB_DATABASE)
    #[arg(long, env = "L0_DB_DATABASE", default_value = "ledger")]
    db_database: String,

    /// Database username (env: L0_DB_USERNAME)
    #[arg(long, env = "L0_DB_USERNAME")]
    db_username: Option<String>,

    /// Database password (env: L0_DB_PASSWORD)
    #[arg(long, env = "L0_DB_PASSWORD")]
    db_password: Option<String>,

    /// Tenant ID (env: L0_TENANT_ID)
    #[arg(long, env = "L0_TENANT_ID", default_value = "default")]
    tenant: String,

    /// Node ID (env: L0_NODE_ID)
    #[arg(long, env = "L0_NODE_ID")]
    node_id: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize L0 node database schema
    Init,

    /// Start L0 API server
    Start {
        /// Host to bind to (env: L0_API_HOST)
        #[arg(short = 'H', long, env = "L0_API_HOST", default_value = "0.0.0.0")]
        host: String,
        /// Port to listen on (env: L0_API_PORT)
        #[arg(short, long, env = "L0_API_PORT", default_value = "3000")]
        port: u16,
    },

    /// Show node status
    Status {
        /// API server URL
        #[arg(short, long, default_value = "http://localhost:3000")]
        api_url: String,
    },

    /// Register a new actor
    Actor {
        #[command(subcommand)]
        action: ActorCommands,
    },

    /// Submit a commitment
    Commit {
        /// Actor ID
        #[arg(short, long)]
        actor_id: String,
        /// Scope type
        #[arg(short, long)]
        scope_type: String,
        /// File containing data to commit
        #[arg(short, long)]
        file: Option<PathBuf>,
        /// Raw data to commit (hex encoded)
        #[arg(short, long)]
        data: Option<String>,
    },

    /// Verify a commitment chain
    Verify {
        /// Commitment ID
        #[arg(short, long)]
        commitment_id: String,
        /// Verification depth
        #[arg(short, long)]
        depth: Option<u32>,
    },

    /// Backfill operations (B-to-A evidence upgrade)
    Backfill {
        #[command(subcommand)]
        action: BackfillCommands,
    },

    /// Chain anchor operations
    Anchor {
        #[command(subcommand)]
        action: AnchorCommands,
    },

    /// Knowledge-Index operations
    Knowledge {
        #[command(subcommand)]
        action: KnowledgeCommands,
    },

    /// Policy-Consent operations
    Consent {
        #[command(subcommand)]
        action: ConsentCommands,
    },

    /// Dispute-Resolution operations
    Dispute {
        #[command(subcommand)]
        action: DisputeCommands,
    },

    /// Receipt operations
    Receipt {
        #[command(subcommand)]
        action: ReceiptCommands,
    },

    /// TipWitness operations
    TipWitness {
        #[command(subcommand)]
        action: TipWitnessCommands,
    },

    /// Fee operations
    Fee {
        #[command(subcommand)]
        action: FeeCommands,
    },

    /// Interactive mode
    Interactive,

    /// Batch operations from file
    Batch {
        /// Path to batch file
        #[arg(short, long)]
        file: PathBuf,
        /// Continue on error
        #[arg(short, long)]
        continue_on_error: bool,
        /// Dry run (parse only)
        #[arg(short = 'n', long)]
        dry_run: bool,
        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },

    /// Generate batch script
    GenerateScript {
        /// Output file
        #[arg(short, long)]
        output: PathBuf,
        /// Template type (actors, consents, commits)
        #[arg(short, long)]
        template: String,
    },
}

#[derive(Subcommand)]
enum ActorCommands {
    /// Register a new actor
    Register {
        /// Actor type (human_actor, ai_actor, node_actor, group_actor)
        #[arg(short = 't', long)]
        actor_type: String,
        /// Public key (hex encoded)
        #[arg(short, long)]
        public_key: String,
        /// Node actor ID
        #[arg(short, long)]
        node_actor_id: String,
    },
    /// Get actor info
    Get {
        /// Actor ID
        actor_id: String,
    },
    /// List actors
    List {
        /// Filter by actor type
        #[arg(short = 't', long)]
        actor_type: Option<String>,
        /// Limit results
        #[arg(short, long, default_value = "100")]
        limit: u32,
    },
}

#[derive(Subcommand)]
enum KnowledgeCommands {
    /// Index content digest
    Index {
        /// Content digest (hex encoded)
        #[arg(short, long)]
        digest: String,
        /// Owner actor ID
        #[arg(short, long)]
        owner: String,
        /// Optional space ID
        #[arg(short, long)]
        space: Option<String>,
    },
    /// Get entry by ID
    Get {
        /// Entry ID
        entry_id: String,
    },
    /// Find entries by digest
    Find {
        /// Content digest (hex encoded)
        #[arg(short, long)]
        digest: String,
    },
    /// Create cross-reference
    Crossref {
        /// Source digest (hex encoded)
        #[arg(short, long)]
        source: String,
        /// Target digest (hex encoded)
        #[arg(short, long)]
        target: String,
        /// Reference type
        #[arg(short, long)]
        ref_type: String,
    },
}

#[derive(Subcommand)]
enum ConsentCommands {
    /// Grant consent
    Grant {
        /// Grantor actor ID
        #[arg(short, long)]
        grantor: String,
        /// Grantee actor ID
        #[arg(short = 'e', long)]
        grantee: String,
        /// Resource type
        #[arg(short, long)]
        resource_type: String,
        /// Actions (comma-separated)
        #[arg(short, long)]
        actions: String,
        /// Terms digest (hex encoded)
        #[arg(short, long)]
        terms_digest: String,
    },
    /// Revoke consent
    Revoke {
        /// Consent ID
        consent_id: String,
    },
    /// Verify consent
    Verify {
        /// Grantor actor ID
        #[arg(short, long)]
        grantor: String,
        /// Grantee actor ID
        #[arg(short = 'e', long)]
        grantee: String,
        /// Action to verify
        #[arg(short, long)]
        action: String,
        /// Resource type
        #[arg(short, long)]
        resource_type: String,
    },
    /// Get consent by ID
    Get {
        /// Consent ID
        consent_id: String,
    },
    /// Issue access ticket
    Ticket {
        /// Consent reference
        #[arg(short, long)]
        consent_ref: String,
        /// Holder actor ID
        #[arg(short = 'H', long)]
        holder: String,
        /// Target resource
        #[arg(short, long)]
        target: String,
        /// Permissions (comma-separated)
        #[arg(short, long)]
        permissions: String,
        /// One-time use
        #[arg(short, long)]
        one_time: bool,
    },
}

#[derive(Subcommand)]
enum DisputeCommands {
    /// File a dispute
    File {
        /// Filing actor ID
        #[arg(short = 'b', long)]
        filed_by: String,
        /// Filed against (comma-separated actor IDs)
        #[arg(short = 'a', long)]
        filed_against: String,
        /// Priority (normal, urgent, critical)
        #[arg(short, long, default_value = "normal")]
        priority: String,
        /// Subject commitment reference
        #[arg(short, long)]
        subject: String,
        /// Evidence digest (hex encoded)
        #[arg(short, long)]
        evidence: String,
    },
    /// Get dispute by ID
    Get {
        /// Dispute ID
        dispute_id: String,
    },
    /// List disputes
    List {
        /// Filter by status
        #[arg(short, long)]
        status: Option<String>,
        /// Limit results
        #[arg(short, long, default_value = "100")]
        limit: u32,
    },
    /// Issue verdict
    Verdict {
        /// Dispute ID
        #[arg(short, long)]
        dispute_id: String,
        /// Verdict type (in_favor, against, mixed, dismissed, inconclusive)
        #[arg(short = 't', long)]
        verdict_type: String,
        /// Verdict digest (hex encoded)
        #[arg(short, long)]
        verdict_digest: String,
        /// Rationale digest (hex encoded)
        #[arg(short, long)]
        rationale_digest: String,
        /// Issued by
        #[arg(short, long)]
        issued_by: String,
    },
    /// Initiate clawback
    Clawback {
        /// Verdict ID
        #[arg(short, long)]
        verdict_id: String,
        /// Clawback type (full_reverse, partial_reverse, compensation, penalty)
        #[arg(short, long)]
        clawback_type: String,
        /// Target commitment refs (comma-separated)
        #[arg(short, long)]
        targets: String,
        /// Affected actors (comma-separated)
        #[arg(short, long)]
        affected: String,
    },
}

#[derive(Subcommand)]
enum ReceiptCommands {
    /// Get receipt by ID
    Get {
        /// Receipt ID
        receipt_id: String,
    },
    /// Verify a receipt
    Verify {
        /// Receipt ID
        receipt_id: String,
    },
    /// List receipts
    List {
        /// Scope type filter
        #[arg(short, long)]
        scope_type: Option<String>,
        /// Limit results
        #[arg(short, long, default_value = "100")]
        limit: u32,
    },
    /// Get receipts by batch
    Batch {
        /// Batch sequence number
        batch_sequence: u64,
    },
}

#[derive(Subcommand)]
enum TipWitnessCommands {
    /// Submit a TipWitness
    Submit {
        /// Actor ID
        #[arg(short, long)]
        actor_id: String,
        /// Local tip digest (hex encoded)
        #[arg(short, long)]
        digest: String,
        /// Local sequence number
        #[arg(short, long)]
        sequence: u64,
        /// Last known receipt reference
        #[arg(short, long)]
        receipt_ref: Option<String>,
    },
    /// Get latest TipWitness for an actor
    Get {
        /// Actor ID
        actor_id: String,
    },
    /// Get TipWitness history for an actor
    History {
        /// Actor ID
        actor_id: String,
        /// Limit results
        #[arg(short, long, default_value = "100")]
        limit: u32,
    },
    /// Verify TipWitness chain for an actor
    Verify {
        /// Actor ID
        actor_id: String,
    },
}

#[derive(Subcommand)]
enum FeeCommands {
    /// Charge a fee
    Charge {
        /// Payer actor ID
        #[arg(short, long)]
        payer: String,
        /// Units count
        #[arg(short, long)]
        units: u32,
        /// Linked anchor ID
        #[arg(short, long)]
        anchor_id: String,
    },
    /// Get fee receipt by ID
    Get {
        /// Fee receipt ID
        fee_receipt_id: String,
    },
    /// Get pending fees for an actor
    Pending {
        /// Actor ID
        actor_id: String,
    },
    /// Get fee history for an actor
    History {
        /// Actor ID
        actor_id: String,
        /// Limit results
        #[arg(short, long, default_value = "100")]
        limit: u32,
    },
    /// Refund a fee
    Refund {
        /// Fee receipt ID
        fee_receipt_id: String,
    },
}

#[derive(Subcommand)]
enum BackfillCommands {
    /// Create a backfill request
    Create {
        /// Actor ID
        #[arg(short, long)]
        actor_id: String,
        /// Start digest (hex encoded)
        #[arg(short, long)]
        start_digest: String,
        /// Start sequence number
        #[arg(short = 'S', long)]
        start_seq: u64,
        /// End digest (hex encoded)
        #[arg(short, long)]
        end_digest: String,
        /// End sequence number
        #[arg(short = 'E', long)]
        end_seq: u64,
        /// TipWitness reference
        #[arg(short, long)]
        tip_witness_ref: String,
    },
    /// Get backfill request by ID
    Get {
        /// Request ID
        request_id: String,
    },
    /// List backfill requests for an actor
    List {
        /// Actor ID
        actor_id: String,
        /// Filter by status
        #[arg(short, long)]
        status: Option<String>,
    },
    /// Generate backfill plan
    Plan {
        /// Request ID
        request_id: String,
    },
    /// Execute backfill plan
    Execute {
        /// Plan ID
        plan_id: String,
    },
    /// Cancel backfill request
    Cancel {
        /// Request ID
        request_id: String,
        /// Reason
        #[arg(short, long)]
        reason: String,
    },
    /// Detect gaps in actor's commitment chain
    Gaps {
        /// Actor ID
        actor_id: String,
        /// Start sequence number
        #[arg(short, long)]
        start: u64,
        /// End sequence number
        #[arg(short, long)]
        end: u64,
    },
    /// Verify continuity of actor's commitment chain
    Continuity {
        /// Actor ID
        actor_id: String,
        /// Start sequence number
        #[arg(short, long)]
        start: u64,
        /// End sequence number
        #[arg(short, long)]
        end: u64,
    },
    /// Get backfill history for an actor
    History {
        /// Actor ID
        actor_id: String,
        /// Limit results
        #[arg(short, long, default_value = "100")]
        limit: u32,
    },
}

#[derive(Subcommand)]
enum AnchorCommands {
    /// Create an anchor transaction
    Create {
        /// Target chain (ethereum, bitcoin, polygon, solana, internal)
        #[arg(short, long)]
        chain: String,
        /// Epoch root (hex encoded)
        #[arg(short, long)]
        epoch_root: String,
        /// Epoch sequence number
        #[arg(short = 'n', long)]
        epoch_sequence: u64,
        /// Batch count
        #[arg(short, long)]
        batch_count: u64,
    },
    /// Get anchor by ID
    Get {
        /// Anchor ID
        anchor_id: String,
    },
    /// Get anchor by epoch
    Epoch {
        /// Chain type
        #[arg(short, long)]
        chain: String,
        /// Epoch sequence
        epoch_sequence: u64,
    },
    /// Submit anchor to chain
    Submit {
        /// Anchor ID
        anchor_id: String,
    },
    /// Check anchor status
    Status {
        /// Anchor ID
        anchor_id: String,
    },
    /// Verify anchor on chain
    Verify {
        /// Anchor ID
        anchor_id: String,
    },
    /// List pending anchors
    Pending {
        /// Filter by chain type
        #[arg(short, long)]
        chain: Option<String>,
    },
    /// List finalized anchors
    Finalized {
        /// Chain type
        chain: String,
        /// Limit results
        #[arg(short, long, default_value = "100")]
        limit: u32,
    },
    /// Get anchor history for epoch range
    History {
        /// Chain type
        chain: String,
        /// From epoch
        #[arg(short, long)]
        from: u64,
        /// To epoch
        #[arg(short, long)]
        to: u64,
    },
    /// Retry a failed anchor
    Retry {
        /// Anchor ID
        anchor_id: String,
    },
    /// Get latest finalized epoch
    Latest {
        /// Chain type
        chain: String,
    },
    /// Get anchor policy
    Policy,
    /// Update anchor policy
    UpdatePolicy {
        /// Primary chain
        #[arg(short, long)]
        primary_chain: String,
        /// Epoch interval
        #[arg(short, long)]
        epoch_interval: u64,
        /// Max anchor delay (seconds)
        #[arg(short, long)]
        max_delay: u64,
    },
}

#[tokio::main]
async fn main() {
    // Load .env file (ignore if not found)
    dotenvy::dotenv().ok();

    // Initialize logging
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    if let Err(e) = run_command(cli).await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

async fn run_command(cli: Cli) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Create database config from CLI (which includes env vars)
    let db_config = DbConfig::from_cli(&cli);

    match cli.command {
        Commands::Init => {
            println!("Initializing L0 database...");
            println!("  URL: {}", db_config.url);
            println!("  Namespace: {}", db_config.namespace);
            println!("  Database: {}", db_config.database);

            let config = db_config.to_surreal_config();
            let datastore = Arc::new(SurrealDatastore::connect(config).await?);
            let database = l0_db::L0Database::new(datastore);
            database.init_schema().await?;

            println!("Database schema initialized successfully.");
            Ok(())
        }

        Commands::Start { host, port } => {
            println!("Starting L0 API server...");
            println!("  Host: {}:{}", host, port);
            println!("  Database: {}", db_config.url);
            println!("  Tenant: {}", cli.tenant);
            if let Some(ref node_id) = cli.node_id {
                println!("  Node ID: {}", node_id);
            }

            let config = db_config.to_surreal_config();
            let datastore = Arc::new(SurrealDatastore::connect(config).await?);

            // Initialize schema first
            let database = l0_db::L0Database::new(datastore.clone());
            database.init_schema().await?;

            let api_config = ApiConfig {
                host,
                port,
                enable_cors: true,
                tenant_id: cli.tenant,
                node_id: cli.node_id,
            };

            run_server(api_config, datastore).await?;
            Ok(())
        }

        Commands::Status { api_url } => {
            println!("Checking L0 node status at {}...", api_url);

            let client = reqwest::Client::new();
            let response = client
                .get(format!("{}/health", api_url))
                .send()
                .await?
                .json::<serde_json::Value>()
                .await?;

            println!("Status: {}", serde_json::to_string_pretty(&response)?);
            Ok(())
        }

        Commands::Actor { action } => {
            commands::handle_actor_command(action, &cli.db_url, &cli.tenant).await
        }

        Commands::Commit {
            actor_id,
            scope_type,
            file,
            data,
        } => {
            commands::handle_commit_command(
                actor_id,
                scope_type,
                file,
                data,
                &cli.db_url,
                &cli.tenant,
            )
            .await
        }

        Commands::Verify { commitment_id, depth } => {
            commands::handle_verify_command(commitment_id, depth, &cli.db_url, &cli.tenant).await
        }

        Commands::Backfill { action } => {
            commands::handle_backfill_command(action, &cli.db_url, &cli.tenant).await
        }

        Commands::Anchor { action } => {
            commands::handle_anchor_command(action, &cli.db_url, &cli.tenant).await
        }

        Commands::Knowledge { action } => {
            commands::handle_knowledge_command(action, &cli.db_url, &cli.tenant).await
        }

        Commands::Consent { action } => {
            commands::handle_consent_command(action, &cli.db_url, &cli.tenant).await
        }

        Commands::Dispute { action } => {
            commands::handle_dispute_command(action, &cli.db_url, &cli.tenant).await
        }

        Commands::Receipt { action } => {
            commands::handle_receipt_command(action, &cli.db_url, &cli.tenant).await
        }

        Commands::TipWitness { action } => {
            commands::handle_tipwitness_command(action, &cli.db_url, &cli.tenant).await
        }

        Commands::Fee { action } => {
            commands::handle_fee_command(action, &cli.db_url, &cli.tenant).await
        }

        Commands::Interactive => {
            println!("Starting L0 Interactive Mode...");
            println!("Type 'help' for available commands, 'exit' to quit.\n");

            let mut session = interactive::InteractiveSession::new(
                cli.db_url.clone(),
                cli.tenant.clone(),
            );

            while session.is_running() {
                match session.read_line() {
                    Ok(input) => {
                        if input.is_empty() {
                            continue;
                        }

                        session.history.add(input.clone());

                        // Try built-in commands first
                        if let Some(result) = session.execute_builtin(&input) {
                            match result {
                                interactive::BuiltinResult::Exit => break,
                                _ => continue,
                            }
                        }

                        // Parse and execute as L0 command
                        let args = interactive::parse_interactive_args(&input);
                        if !args.is_empty() {
                            // Build CLI args: l0 <command> <args...>
                            let mut cli_args = vec!["l0".to_string()];
                            cli_args.push("--db-url".to_string());
                            cli_args.push(session.db_url.clone());
                            cli_args.push("--tenant".to_string());
                            cli_args.push(session.tenant.clone());
                            cli_args.extend(args);

                            // Execute the command in a subprocess
                            match std::process::Command::new(&cli_args[0])
                                .args(&cli_args[1..])
                                .status()
                            {
                                Ok(status) => {
                                    if !status.success() {
                                        eprintln!("Command failed with status: {}", status);
                                    }
                                }
                                Err(e) => {
                                    eprintln!("Failed to execute command: {}", e);
                                    // Fall back to direct interpretation
                                    eprintln!("Try: {}", cli_args.join(" "));
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Error reading input: {}", e);
                        break;
                    }
                }
            }

            println!("Goodbye!");
            Ok(())
        }

        Commands::Batch {
            file,
            continue_on_error,
            dry_run,
            verbose,
        } => {
            println!("Loading batch file: {}", file.display());

            let operations = batch::parse_batch_file(&file)?;
            println!("Found {} operations", operations.len());

            if dry_run {
                println!("\nDry run - operations to execute:");
                for (i, op) in operations.iter().enumerate() {
                    println!("  [{}] l0 {}", i + 1, op.to_cli_string());
                }
                return Ok(());
            }

            let config = batch::BatchConfig {
                continue_on_error,
                verbose,
                dry_run,
                ..Default::default()
            };

            let mut result = batch::BatchResult::new();

            for (i, op) in operations.iter().enumerate() {
                if verbose {
                    println!("[{}/{}] Executing: l0 {}", i + 1, operations.len(), op.to_cli_string());
                }

                let start = std::time::Instant::now();

                // Build CLI args
                let mut cli_args = vec!["l0".to_string()];
                cli_args.push("--db-url".to_string());
                cli_args.push(cli.db_url.clone());
                cli_args.push("--tenant".to_string());
                cli_args.push(cli.tenant.clone());
                cli_args.push(op.command.clone());
                cli_args.extend(op.args.iter().cloned());

                let status = std::process::Command::new(&cli_args[0])
                    .args(&cli_args[1..])
                    .status();

                let duration = start.elapsed().as_millis() as u64;

                match status {
                    Ok(s) if s.success() => {
                        result.add(batch::BatchOperationResult {
                            index: i,
                            operation: op.clone(),
                            success: true,
                            output: None,
                            error: None,
                            duration_ms: duration,
                        });
                    }
                    Ok(s) => {
                        let err = format!("Exit code: {:?}", s.code());
                        result.add(batch::BatchOperationResult {
                            index: i,
                            operation: op.clone(),
                            success: false,
                            output: None,
                            error: Some(err.clone()),
                            duration_ms: duration,
                        });
                        if !config.continue_on_error {
                            eprintln!("Batch aborted: {}", err);
                            result.add_skipped(operations.len() - i - 1);
                            break;
                        }
                    }
                    Err(e) => {
                        let err = format!("{}", e);
                        result.add(batch::BatchOperationResult {
                            index: i,
                            operation: op.clone(),
                            success: false,
                            output: None,
                            error: Some(err.clone()),
                            duration_ms: duration,
                        });
                        if !config.continue_on_error {
                            eprintln!("Batch aborted: {}", err);
                            result.add_skipped(operations.len() - i - 1);
                            break;
                        }
                    }
                }
            }

            result.print_summary();
            Ok(())
        }

        Commands::GenerateScript { output, template } => {
            println!("Generating script template: {}", template);

            let operations = match template.as_str() {
                "actors" => {
                    // Sample actor registration template
                    batch::templates::actor_registration_template(&[
                        ("human_actor".to_string(), "pubkey_1".to_string(), "node_1".to_string()),
                        ("ai_actor".to_string(), "pubkey_2".to_string(), "node_1".to_string()),
                    ])
                }
                "consents" => {
                    // Sample consent grant template
                    batch::templates::consent_grant_template(&[
                        (
                            "actor_1".to_string(),
                            "actor_2".to_string(),
                            "resource_type".to_string(),
                            vec!["read".to_string(), "write".to_string()],
                            "terms_digest_hex".to_string(),
                        ),
                    ])
                }
                "commits" => {
                    // Sample commitment template
                    batch::templates::commitment_batch_template(&[
                        ("actor_1".to_string(), "akn_batch".to_string(), "data_hex_1".to_string()),
                        ("actor_1".to_string(), "akn_batch".to_string(), "data_hex_2".to_string()),
                    ])
                }
                _ => {
                    return Err(format!("Unknown template: {}. Use: actors, consents, commits", template).into());
                }
            };

            let script = batch::generate_script(&operations, &cli.db_url, &cli.tenant);

            std::fs::write(&output, &script)?;
            println!("Script written to: {}", output.display());
            println!("\nTo execute, run:");
            println!("  chmod +x {}", output.display());
            println!("  ./{}", output.display());

            Ok(())
        }
    }
}

/// Database configuration for CLI
#[derive(Clone)]
struct DbConfig {
    url: String,
    namespace: String,
    database: String,
    username: Option<String>,
    password: Option<String>,
}

impl DbConfig {
    fn from_cli(cli: &Cli) -> Self {
        Self {
            url: cli.db_url.clone(),
            namespace: cli.db_namespace.clone(),
            database: cli.db_database.clone(),
            username: cli.db_username.clone(),
            password: cli.db_password.clone(),
        }
    }

    fn to_surreal_config(&self) -> SurrealConfig {
        SurrealConfig {
            endpoint: self.url.clone(),
            namespace: self.namespace.clone(),
            database: self.database.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
            pool_size: None,
            strict_mode: None,
        }
    }
}

