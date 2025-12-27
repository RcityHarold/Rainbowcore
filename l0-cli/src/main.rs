//! L0 Command Line Interface
//!
//! Usage:
//!   l0 init          - Initialize L0 node
//!   l0 start         - Start L0 node
//!   l0 status        - Show node status
//!   l0 commit        - Submit a commitment
//!   l0 verify <id>   - Verify a receipt
//!   l0 backfill      - Request backfill

use clap::{Parser, Subcommand};
use l0_api::{run_server, ApiConfig};
use l0_db::SurrealDatastore;
use soulbase_storage::surreal::SurrealConfig;
use std::path::PathBuf;
use std::sync::Arc;

mod commands;

#[derive(Parser)]
#[command(name = "l0")]
#[command(about = "L0 Public Reality Ledger CLI")]
#[command(version)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, default_value = "l0.toml")]
    config: PathBuf,

    /// Database URL
    #[arg(long, default_value = "mem://")]
    db_url: String,

    /// Tenant ID
    #[arg(long, default_value = "default")]
    tenant: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize L0 node database schema
    Init,

    /// Start L0 API server
    Start {
        /// Host to bind to
        #[arg(short = 'H', long, default_value = "0.0.0.0")]
        host: String,
        /// Port to listen on
        #[arg(short, long, default_value = "3000")]
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

    /// Request backfill
    Backfill {
        /// Start batch sequence
        #[arg(short, long)]
        from: u64,
        /// End batch sequence
        #[arg(short, long)]
        to: u64,
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

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    if let Err(e) = run_command(cli).await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

async fn run_command(cli: Cli) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match cli.command {
        Commands::Init => {
            println!("Initializing L0 database...");

            let config = create_db_config(&cli.db_url);
            let datastore = Arc::new(SurrealDatastore::connect(config).await?);
            let database = l0_db::L0Database::new(datastore);
            database.init_schema().await?;

            println!("Database schema initialized successfully.");
            Ok(())
        }

        Commands::Start { host, port } => {
            println!("Starting L0 API server on {}:{}...", host, port);

            let config = create_db_config(&cli.db_url);
            let datastore = Arc::new(SurrealDatastore::connect(config).await?);

            // Initialize schema first
            let database = l0_db::L0Database::new(datastore.clone());
            database.init_schema().await?;

            let config = ApiConfig {
                host,
                port,
                enable_cors: true,
                tenant_id: cli.tenant,
                node_id: None,
            };

            run_server(config, datastore).await?;
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

        Commands::Backfill { from, to } => {
            println!("Backfill from {} to {} not yet implemented", from, to);
            Ok(())
        }
    }
}

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
