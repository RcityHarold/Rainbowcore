//! P3 CLI Entry Point
//!
//! Main entry point for the P3 command-line interface.
//!
//! Configuration is loaded from environment variables (via .env file).
//! Command-line arguments override environment variables.
//!
//! Usage:
//!   p3 init           - Initialize P3 database schema
//!   p3 start          - Start P3 API server (auto-initializes schema)
//!   p3 health         - Check health of P3 services
//!   p3 execute        - Execute operations
//!   p3 query          - Query state and information
//!   p3 verify         - Verify data and proofs

use clap::Parser;
use p3_cli::{handler, Cli};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    // Load .env file (ignore if not found)
    dotenvy::dotenv().ok();

    // Parse CLI arguments
    let cli = Cli::parse();

    // Initialize logging if verbose
    if cli.verbose {
        init_logging();
    }

    // Run the CLI
    if let Err(e) = handler::run(cli).await {
        eprintln!("Error: {}", e);
        std::process::exit(e.exit_code());
    }
}

/// Initialize logging with tracing
fn init_logging() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "p3_cli=debug,p3_api=debug,p3_executor=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}
