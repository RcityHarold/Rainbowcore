//! P3 CLI - Command Line Interface
//!
//! This crate provides a command-line interface for interacting with
//! the P3 Economy Layer.
//!
//! # Features
//!
//! - Execute operations (distribution, clawback, fine, etc.)
//! - Query state (providers, clearing, treasury, epochs)
//! - Verify data and proofs
//! - Manage configuration
//!
//! # Usage
//!
//! ```text
//! p3 [OPTIONS] <COMMAND>
//!
//! Commands:
//!   execute   Execute operations on the P3 economy layer
//!   query     Query state and information
//!   verify    Verify data and proofs
//!   config    Configuration management
//!   health    Check health of P3 services
//!   stats     Show executor statistics
//!
//! Options:
//!   -a, --api-url <URL>    API endpoint URL [default: http://localhost:3000]
//!   -f, --format <FORMAT>  Output format (json, table, plain) [default: table]
//!   -v, --verbose          Enable verbose output
//!   -h, --help             Print help
//!   -V, --version          Print version
//! ```
//!
//! # Examples
//!
//! ## Check health
//! ```text
//! p3 health
//! ```
//!
//! ## Execute distribution
//! ```text
//! p3 execute distribution \
//!   --target abc123def456 \
//!   --amount 100.00 \
//!   --epoch epoch:2024:001 \
//!   --initiator actor:1
//! ```
//!
//! ## Query providers
//! ```text
//! p3 query provider list --page 0 --page-size 20
//! ```
//!
//! ## Verify digest
//! ```text
//! p3 verify compute --data "hello world"
//! ```

pub mod client;
pub mod commands;
pub mod error;
pub mod handler;
pub mod output;

pub use client::P3Client;
pub use commands::{Cli, Commands, OutputFormat};
pub use error::{CliError, CliResult};

/// P3 CLI version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }
}
