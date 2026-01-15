//! Command Handlers
//!
//! Handler functions for CLI commands.

use crate::client::{ExecuteRequest, P3Client, VerifyRequest};
use crate::commands::{
    execute::ExecuteCommands,
    query::{ClearingQueries, EpochQueries, ProofQueries, ProviderQueries, QueryCommands, TreasuryQueries},
    verify::VerifyCommands,
    config::ConfigCommands,
    Cli, Commands, OutputFormat,
};
use crate::error::{CliError, CliResult};
use crate::output;
use p3_core::P3Digest;
use p3_store::{P3Database, SurrealConfig, SurrealDatastore};
use soulbase_types::prelude::TenantId;
use std::sync::Arc;

/// Database configuration extracted from CLI
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

/// Run the CLI with parsed arguments
pub async fn run(cli: Cli) -> CliResult<()> {
    match &cli.command {
        Commands::Init => handle_init(&cli).await,
        Commands::Start { host, port } => handle_start(&cli, host.clone(), *port).await,
        _ => {
            let client = P3Client::new(&cli.api_url)?;
            match cli.command {
                Commands::Health => handle_health(&client, cli.format).await,
                Commands::Stats => handle_stats(&client, cli.format).await,
                Commands::Execute(cmd) => handle_execute(&client, cmd, cli.format).await,
                Commands::Query(cmd) => handle_query(&client, cmd, cli.format).await,
                Commands::Verify(cmd) => handle_verify(&client, cmd, cli.format).await,
                Commands::Config(cmd) => handle_config(cmd, cli.format).await,
                Commands::Init | Commands::Start { .. } => unreachable!(),
            }
        }
    }
}

/// Handle database initialization
async fn handle_init(cli: &Cli) -> CliResult<()> {
    let db_config = DbConfig::from_cli(cli);

    println!("Initializing P3 database...");
    println!("  URL: {}", db_config.url);
    println!("  Namespace: {}", db_config.namespace);
    println!("  Database: {}", db_config.database);
    println!("  Tenant: {}", cli.tenant);

    let config = db_config.to_surreal_config();
    let datastore = Arc::new(
        SurrealDatastore::connect(config)
            .await
            .map_err(|e| CliError::server(format!("Database connection failed: {}", e)))?
    );

    let tenant_id = TenantId(cli.tenant.clone());
    let database = P3Database::new(datastore, tenant_id);
    database
        .init_schema()
        .await
        .map_err(|e| CliError::server(format!("Schema initialization failed: {}", e)))?;

    println!("Database schema initialized successfully.");
    Ok(())
}

/// Handle starting the API server
async fn handle_start(cli: &Cli, host: String, port: u16) -> CliResult<()> {
    let db_config = DbConfig::from_cli(cli);

    println!("Starting P3 API server...");
    println!("  Host: {}:{}", host, port);
    println!("  Database: {}", db_config.url);
    println!("  Tenant: {}", cli.tenant);

    let config = db_config.to_surreal_config();
    let datastore = Arc::new(
        SurrealDatastore::connect(config)
            .await
            .map_err(|e| CliError::server(format!("Database connection failed: {}", e)))?
    );

    // Initialize schema first (auto-create tables on first run)
    let tenant_id = TenantId(cli.tenant.clone());
    let database = P3Database::new(datastore.clone(), tenant_id.clone());
    database
        .init_schema()
        .await
        .map_err(|e| CliError::server(format!("Schema initialization failed: {}", e)))?;

    println!("Database schema initialized.");

    // Create AppState and start server
    let api_config = p3_api::ApiConfig {
        service_name: "p3-api".to_string(),
        version: p3_api::VERSION.to_string(),
        listen_addr: format!("{}:{}", host, port),
        enable_cors: true,
        request_timeout_secs: 30,
        max_body_size: 1024 * 1024,
    };

    let executor = p3_executor::P3Executor::default_config();
    let verifier = p3_verifier::Verifier::l1();

    let state = p3_api::AppState::with_config(api_config, executor, verifier)
        .with_database(database);

    println!("Starting server on {}:{}...", host, port);

    p3_api::start_server(state)
        .await
        .map_err(|e| CliError::server(format!("Server error: {}", e)))?;

    Ok(())
}

/// Handle health check command
async fn handle_health(client: &P3Client, format: OutputFormat) -> CliResult<()> {
    let health = client.health().await?;
    output::print_health(&health, format);
    Ok(())
}

/// Handle stats command
async fn handle_stats(client: &P3Client, format: OutputFormat) -> CliResult<()> {
    let stats = client.stats().await?;
    output::print_stats(&stats, format);
    Ok(())
}

/// Handle execute commands
async fn handle_execute(
    client: &P3Client,
    cmd: ExecuteCommands,
    format: OutputFormat,
) -> CliResult<()> {
    let request = ExecuteRequest {
        operation_type: cmd.operation_type().to_string(),
        target_digest: cmd.target().to_string(),
        amount: cmd.amount(),
        epoch_id: cmd.epoch().to_string(),
        initiator_ref: cmd.initiator().to_string(),
        executor_ref: cmd.executor().map(String::from),
    };

    let result = client.execute(request).await?;
    output::print_execute_result(&result, format);
    Ok(())
}

/// Handle query commands
async fn handle_query(
    client: &P3Client,
    cmd: QueryCommands,
    format: OutputFormat,
) -> CliResult<()> {
    match cmd {
        QueryCommands::Provider(provider_cmd) => {
            handle_provider_query(client, provider_cmd, format).await
        }
        QueryCommands::Clearing(clearing_cmd) => {
            handle_clearing_query(client, clearing_cmd, format).await
        }
        QueryCommands::Treasury(treasury_cmd) => {
            handle_treasury_query(client, treasury_cmd, format).await
        }
        QueryCommands::Proofs(proofs_cmd) => {
            handle_proofs_query(client, proofs_cmd, format).await
        }
        QueryCommands::Epoch(epoch_cmd) => {
            handle_epoch_query(client, epoch_cmd, format).await
        }
    }
}

/// Handle provider queries
async fn handle_provider_query(
    client: &P3Client,
    cmd: ProviderQueries,
    format: OutputFormat,
) -> CliResult<()> {
    match cmd {
        ProviderQueries::List { page, page_size, status: _ } => {
            let result = client.list_providers(page, page_size).await?;
            output::print_output(&result, format);
        }
        ProviderQueries::Get { id } => {
            output::print_info(&format!("Get provider: {}", id));
            // TODO: Implement get provider endpoint
        }
        ProviderQueries::Balance { id } => {
            output::print_info(&format!("Get balance for provider: {}", id));
            // TODO: Implement balance endpoint
        }
    }
    Ok(())
}

/// Handle clearing queries
async fn handle_clearing_query(
    client: &P3Client,
    cmd: ClearingQueries,
    format: OutputFormat,
) -> CliResult<()> {
    match cmd {
        ClearingQueries::List { page, page_size, epoch: _, status: _ } => {
            let result = client.list_clearing_batches(page, page_size).await?;
            output::print_output(&result, format);
        }
        ClearingQueries::Get { id } => {
            output::print_info(&format!("Get clearing batch: {}", id));
            // TODO: Implement get batch endpoint
        }
        ClearingQueries::Entries { batch_id, page: _ } => {
            output::print_info(&format!("Get entries for batch: {}", batch_id));
            // TODO: Implement get entries endpoint
        }
    }
    Ok(())
}

/// Handle treasury queries
async fn handle_treasury_query(
    client: &P3Client,
    cmd: TreasuryQueries,
    format: OutputFormat,
) -> CliResult<()> {
    match cmd {
        TreasuryQueries::List { page, page_size } => {
            let result = client.list_treasury_pools(page, page_size).await?;
            output::print_output(&result, format);
        }
        TreasuryQueries::Get { id } => {
            output::print_info(&format!("Get treasury pool: {}", id));
            // TODO: Implement get pool endpoint
        }
        TreasuryQueries::Transactions { pool_id, page: _, limit: _ } => {
            output::print_info(&format!("Get transactions for pool: {}", pool_id));
            // TODO: Implement transactions endpoint
        }
        TreasuryQueries::TotalBalance => {
            output::print_info("Get total treasury balance");
            // TODO: Implement total balance endpoint
        }
    }
    Ok(())
}

/// Handle proofs queries
async fn handle_proofs_query(
    _client: &P3Client,
    cmd: ProofQueries,
    _format: OutputFormat,
) -> CliResult<()> {
    match cmd {
        ProofQueries::List { page: _, epoch: _ } => {
            output::print_info("List proof batches");
            // TODO: Implement list proof batches
        }
        ProofQueries::Get { id } => {
            output::print_info(&format!("Get proof batch: {}", id));
            // TODO: Implement get batch
        }
        ProofQueries::Proofs { batch_id } => {
            output::print_info(&format!("Get proofs for batch: {}", batch_id));
            // TODO: Implement get proofs
        }
    }
    let _ = format; // Suppress warning
    Ok(())
}

/// Handle epoch queries
async fn handle_epoch_query(
    _client: &P3Client,
    cmd: EpochQueries,
    format: OutputFormat,
) -> CliResult<()> {
    match cmd {
        EpochQueries::Current => {
            output::print_info("Get current epoch");
            // TODO: Implement current epoch
        }
        EpochQueries::Get { id } => {
            output::print_info(&format!("Get epoch: {}", id));
            // TODO: Implement get epoch
        }
        EpochQueries::List { limit: _ } => {
            output::print_info("List recent epochs");
            // TODO: Implement list epochs
        }
    }
    let _ = format; // Suppress warning
    Ok(())
}

/// Handle verify commands
async fn handle_verify(
    client: &P3Client,
    cmd: VerifyCommands,
    format: OutputFormat,
) -> CliResult<()> {
    match cmd {
        VerifyCommands::Digest { data, expected } => {
            let request = VerifyRequest {
                data,
                verification_type: "blake3".to_string(),
                expected_digest: expected,
            };
            let result = client.verify(request).await?;
            output::print_verify_result(&result, format);
        }
        VerifyCommands::Compute { data, hex } => {
            let bytes = if hex {
                hex::decode(&data).map_err(|_| CliError::digest("Invalid hex data"))?
            } else {
                data.as_bytes().to_vec()
            };
            let digest = P3Digest::blake3(&bytes);
            output::print_info(&format!("Digest: {}", digest.to_hex()));
        }
        VerifyCommands::File { path, expected } => {
            let data = std::fs::read(&path)?;
            let digest = P3Digest::blake3(&data);
            let valid = expected
                .as_ref()
                .map(|e| e == &digest.to_hex())
                .unwrap_or(true);
            output::print_info(&format!("File: {}", path));
            output::print_info(&format!("Digest: {}", digest.to_hex()));
            output::print_info(&format!("Valid: {}", valid));
        }
        VerifyCommands::Proof { proof_id } => {
            output::print_info(&format!("Verifying proof: {}", proof_id));
            // TODO: Implement proof verification
        }
        VerifyCommands::Batch { batch_id } => {
            output::print_info(&format!("Verifying batch: {}", batch_id));
            // TODO: Implement batch verification
        }
        VerifyCommands::Bundle { file, level } => {
            output::print_info(&format!("Verifying bundle: {} (level: {})", file, level));
            // TODO: Implement bundle verification
        }
    }
    Ok(())
}

/// Handle config commands
async fn handle_config(cmd: ConfigCommands, _format: OutputFormat) -> CliResult<()> {
    match cmd {
        ConfigCommands::Show => {
            output::print_info("Current Configuration:");
            output::print_row("API URL:", &crate::commands::config::defaults::API_URL);
            output::print_row("Output Format:", crate::commands::config::defaults::OUTPUT_FORMAT);
            output::print_row("Page Size:", &crate::commands::config::defaults::PAGE_SIZE.to_string());
            output::print_row("Timeout:", &format!("{}s", crate::commands::config::defaults::TIMEOUT));
        }
        ConfigCommands::Set { key, value } => {
            output::print_info(&format!("Setting {} = {}", key, value));
            // TODO: Implement config persistence
        }
        ConfigCommands::Get { key } => {
            output::print_info(&format!("Getting config key: {}", key));
            // TODO: Implement config retrieval
        }
        ConfigCommands::Reset { all } => {
            if all {
                output::print_info("Resetting all configuration to defaults");
            } else {
                output::print_info("Specify --all to reset all settings");
            }
        }
        ConfigCommands::Init { force } => {
            if force {
                output::print_info("Initializing configuration (force)");
            } else {
                output::print_info("Initializing configuration");
            }
            // TODO: Create config file
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_request_construction() {
        let cmd = ExecuteCommands::Distribution {
            target: "abc123".to_string(),
            amount: rust_decimal::Decimal::new(1000, 2),
            epoch: "epoch:2024:001".to_string(),
            initiator: "actor:1".to_string(),
            executor: None,
        };

        let request = ExecuteRequest {
            operation_type: cmd.operation_type().to_string(),
            target_digest: cmd.target().to_string(),
            amount: cmd.amount(),
            epoch_id: cmd.epoch().to_string(),
            initiator_ref: cmd.initiator().to_string(),
            executor_ref: cmd.executor().map(String::from),
        };

        assert_eq!(request.operation_type, "distribution");
        assert_eq!(request.target_digest, "abc123");
    }
}
