//! Config Commands
//!
//! Commands for managing CLI configuration.

use clap::Subcommand;

/// Configuration subcommands
#[derive(Subcommand, Debug)]
pub enum ConfigCommands {
    /// Show current configuration
    Show,

    /// Set configuration value
    Set {
        /// Configuration key
        #[arg(short, long)]
        key: String,

        /// Configuration value
        #[arg(short, long)]
        value: String,
    },

    /// Get configuration value
    Get {
        /// Configuration key
        #[arg(short, long)]
        key: String,
    },

    /// Reset configuration to defaults
    Reset {
        /// Reset all settings
        #[arg(long)]
        all: bool,
    },

    /// Initialize configuration file
    Init {
        /// Force overwrite existing config
        #[arg(short, long)]
        force: bool,
    },
}

/// Configuration keys
pub mod keys {
    /// API URL key
    pub const API_URL: &str = "api_url";
    /// Default output format
    pub const OUTPUT_FORMAT: &str = "output_format";
    /// Default page size
    pub const PAGE_SIZE: &str = "page_size";
    /// Request timeout (seconds)
    pub const TIMEOUT: &str = "timeout";
    /// Enable verbose output by default
    pub const VERBOSE: &str = "verbose";
}

/// Default configuration values
pub mod defaults {
    /// Default API URL
    pub const API_URL: &str = "http://localhost:3000";
    /// Default output format
    pub const OUTPUT_FORMAT: &str = "table";
    /// Default page size
    pub const PAGE_SIZE: u64 = 20;
    /// Default timeout (seconds)
    pub const TIMEOUT: u64 = 30;
    /// Default verbose setting
    pub const VERBOSE: bool = false;
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        cmd: ConfigCommands,
    }

    #[test]
    fn test_config_show() {
        let args = TestCli::try_parse_from(["test", "show"]);
        assert!(args.is_ok());
    }

    #[test]
    fn test_config_set() {
        let args = TestCli::try_parse_from([
            "test", "set",
            "--key", "api_url",
            "--value", "http://localhost:8080",
        ]);
        assert!(args.is_ok());
    }

    #[test]
    fn test_config_get() {
        let args = TestCli::try_parse_from(["test", "get", "--key", "api_url"]);
        assert!(args.is_ok());
    }

    #[test]
    fn test_config_reset() {
        let args = TestCli::try_parse_from(["test", "reset", "--all"]);
        assert!(args.is_ok());
    }

    #[test]
    fn test_config_init() {
        let args = TestCli::try_parse_from(["test", "init", "--force"]);
        assert!(args.is_ok());
    }

    #[test]
    fn test_default_values() {
        assert_eq!(defaults::API_URL, "http://localhost:3000");
        assert_eq!(defaults::OUTPUT_FORMAT, "table");
        assert_eq!(defaults::PAGE_SIZE, 20);
        assert_eq!(defaults::TIMEOUT, 30);
        assert!(!defaults::VERBOSE);
    }
}
