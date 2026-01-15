//! CLI Commands Module
//!
//! Command definitions and handlers for the P3 CLI.

pub mod execute;
pub mod query;
pub mod verify;
pub mod config;

use clap::{Parser, Subcommand};

/// P3 Economy Layer CLI
#[derive(Parser, Debug)]
#[command(name = "p3")]
#[command(author = "Rainbow City Foundation")]
#[command(version)]
#[command(about = "P3 Economy Layer Command Line Interface")]
#[command(long_about = "A command-line tool for interacting with the P3 Economy Layer.\n\n\
    Use this tool to execute operations, query state, verify data, and manage \
    the P3 economy system.")]
pub struct Cli {
    /// API endpoint URL
    #[arg(short, long, env = "P3_API_URL", default_value = "http://localhost:3000")]
    pub api_url: String,

    /// Database URL (env: P3_DB_URL)
    #[arg(long, env = "P3_DB_URL", default_value = "mem://")]
    pub db_url: String,

    /// Database namespace (env: P3_DB_NAMESPACE)
    #[arg(long, env = "P3_DB_NAMESPACE", default_value = "p3")]
    pub db_namespace: String,

    /// Database name (env: P3_DB_DATABASE)
    #[arg(long, env = "P3_DB_DATABASE", default_value = "economy")]
    pub db_database: String,

    /// Database username (env: P3_DB_USERNAME)
    #[arg(long, env = "P3_DB_USERNAME")]
    pub db_username: Option<String>,

    /// Database password (env: P3_DB_PASSWORD)
    #[arg(long, env = "P3_DB_PASSWORD")]
    pub db_password: Option<String>,

    /// Tenant ID (env: P3_TENANT_ID)
    #[arg(long, env = "P3_TENANT_ID", default_value = "default")]
    pub tenant: String,

    /// Output format (json, table, plain)
    #[arg(short, long, default_value = "table")]
    pub format: OutputFormat,

    /// Enable verbose output
    #[arg(short, long)]
    pub verbose: bool,

    /// Subcommand to execute
    #[command(subcommand)]
    pub command: Commands,
}

/// Output format options
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    /// JSON output
    Json,
    /// Table format (human-readable)
    Table,
    /// Plain text
    Plain,
}

impl Default for OutputFormat {
    fn default() -> Self {
        OutputFormat::Table
    }
}

/// Available commands
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize P3 database schema
    Init,

    /// Start P3 API server
    Start {
        /// Host to bind to (env: P3_API_HOST)
        #[arg(short = 'H', long, env = "P3_API_HOST", default_value = "0.0.0.0")]
        host: String,
        /// Port to listen on (env: P3_API_PORT)
        #[arg(short, long, env = "P3_API_PORT", default_value = "3000")]
        port: u16,
    },

    /// Execute operations on the P3 economy layer
    #[command(subcommand)]
    Execute(execute::ExecuteCommands),

    /// Query state and information
    #[command(subcommand)]
    Query(query::QueryCommands),

    /// Verify data and proofs
    #[command(subcommand)]
    Verify(verify::VerifyCommands),

    /// Configuration management
    #[command(subcommand)]
    Config(config::ConfigCommands),

    /// Check health of P3 services
    Health,

    /// Show executor statistics
    Stats,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parse_help() {
        // Just verify that the parser can be constructed
        let result = Cli::try_parse_from(["p3", "--help"]);
        // --help causes an error (but it's expected)
        assert!(result.is_err());
    }

    #[test]
    fn test_output_format_default() {
        assert_eq!(OutputFormat::default(), OutputFormat::Table);
    }
}
