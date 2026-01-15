//! Query Commands
//!
//! Commands for querying state and information from the P3 economy layer.

use clap::Subcommand;

/// Query subcommands
#[derive(Subcommand, Debug)]
pub enum QueryCommands {
    /// Query providers
    #[command(subcommand)]
    Provider(ProviderQueries),

    /// Query clearing batches
    #[command(subcommand)]
    Clearing(ClearingQueries),

    /// Query treasury pools
    #[command(subcommand)]
    Treasury(TreasuryQueries),

    /// Query proof batches
    #[command(subcommand)]
    Proofs(ProofQueries),

    /// Query epochs
    #[command(subcommand)]
    Epoch(EpochQueries),
}

/// Provider query subcommands
#[derive(Subcommand, Debug)]
pub enum ProviderQueries {
    /// List all providers
    List {
        /// Page number (0-indexed)
        #[arg(short, long, default_value = "0")]
        page: u64,

        /// Page size
        #[arg(short = 's', long, default_value = "20")]
        page_size: u64,

        /// Filter by status
        #[arg(long)]
        status: Option<String>,
    },

    /// Get provider details
    Get {
        /// Provider ID
        #[arg(short, long)]
        id: String,
    },

    /// Get provider balance
    Balance {
        /// Provider ID
        #[arg(short, long)]
        id: String,
    },
}

/// Clearing query subcommands
#[derive(Subcommand, Debug)]
pub enum ClearingQueries {
    /// List clearing batches
    List {
        /// Page number (0-indexed)
        #[arg(short, long, default_value = "0")]
        page: u64,

        /// Page size
        #[arg(short = 's', long, default_value = "20")]
        page_size: u64,

        /// Filter by epoch
        #[arg(short, long)]
        epoch: Option<String>,

        /// Filter by status
        #[arg(long)]
        status: Option<String>,
    },

    /// Get batch details
    Get {
        /// Batch ID
        #[arg(short, long)]
        id: String,
    },

    /// Get batch entries
    Entries {
        /// Batch ID
        #[arg(short, long)]
        batch_id: String,

        /// Page number
        #[arg(short, long, default_value = "0")]
        page: u64,
    },
}

/// Treasury query subcommands
#[derive(Subcommand, Debug)]
pub enum TreasuryQueries {
    /// List treasury pools
    List {
        /// Page number (0-indexed)
        #[arg(short, long, default_value = "0")]
        page: u64,

        /// Page size
        #[arg(short = 's', long, default_value = "20")]
        page_size: u64,
    },

    /// Get pool details
    Get {
        /// Pool ID
        #[arg(short, long)]
        id: String,
    },

    /// Get pool transactions
    Transactions {
        /// Pool ID
        #[arg(short, long)]
        pool_id: String,

        /// Page number
        #[arg(short = 'n', long, default_value = "0")]
        page: u64,

        /// Limit
        #[arg(short, long, default_value = "20")]
        limit: u64,
    },

    /// Get total balance across all pools
    TotalBalance,
}

/// Proof query subcommands
#[derive(Subcommand, Debug)]
pub enum ProofQueries {
    /// List proof batches
    List {
        /// Page number (0-indexed)
        #[arg(short, long, default_value = "0")]
        page: u64,

        /// Filter by epoch
        #[arg(short, long)]
        epoch: Option<String>,
    },

    /// Get batch details
    Get {
        /// Batch ID
        #[arg(short, long)]
        id: String,
    },

    /// Get proofs in a batch
    Proofs {
        /// Batch ID
        #[arg(short, long)]
        batch_id: String,
    },
}

/// Epoch query subcommands
#[derive(Subcommand, Debug)]
pub enum EpochQueries {
    /// Get current epoch
    Current,

    /// Get epoch details
    Get {
        /// Epoch ID
        #[arg(short, long)]
        id: String,
    },

    /// List recent epochs
    List {
        /// Number of epochs to show
        #[arg(short, long, default_value = "10")]
        limit: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        cmd: QueryCommands,
    }

    #[test]
    fn test_provider_list_parse() {
        let args = TestCli::try_parse_from(["test", "provider", "list", "--page", "1"]);
        assert!(args.is_ok());
    }

    #[test]
    fn test_provider_get_parse() {
        let args = TestCli::try_parse_from(["test", "provider", "get", "--id", "provider:1"]);
        assert!(args.is_ok());
    }

    #[test]
    fn test_clearing_list_parse() {
        let args = TestCli::try_parse_from(["test", "clearing", "list"]);
        assert!(args.is_ok());
    }

    #[test]
    fn test_treasury_total_balance() {
        let args = TestCli::try_parse_from(["test", "treasury", "total-balance"]);
        assert!(args.is_ok());
    }
}
