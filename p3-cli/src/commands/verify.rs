//! Verify Commands
//!
//! Commands for verifying data and proofs in the P3 economy layer.

use clap::Subcommand;

/// Verify subcommands
#[derive(Subcommand, Debug)]
pub enum VerifyCommands {
    /// Verify a digest against data
    Digest {
        /// Data to verify (hex-encoded)
        #[arg(short, long)]
        data: String,

        /// Expected digest (hex-encoded)
        #[arg(short, long)]
        expected: Option<String>,
    },

    /// Verify a proof
    Proof {
        /// Proof ID
        #[arg(short, long)]
        proof_id: String,
    },

    /// Verify a proof batch
    Batch {
        /// Batch ID
        #[arg(short, long)]
        batch_id: String,
    },

    /// Verify an epoch bundle
    Bundle {
        /// Bundle file path
        #[arg(short, long)]
        file: String,

        /// Verification level (L1, L2, L3)
        #[arg(short, long, default_value = "L1")]
        level: String,
    },

    /// Verify file integrity
    File {
        /// File path
        #[arg(short, long)]
        path: String,

        /// Expected digest (hex-encoded)
        #[arg(short, long)]
        expected: Option<String>,
    },

    /// Compute digest of data
    Compute {
        /// Data to hash (hex-encoded or plain text)
        #[arg(short, long)]
        data: String,

        /// Input is hex-encoded
        #[arg(long)]
        hex: bool,
    },
}

impl VerifyCommands {
    /// Get a description of the verification type
    pub fn description(&self) -> &'static str {
        match self {
            VerifyCommands::Digest { .. } => "digest verification",
            VerifyCommands::Proof { .. } => "proof verification",
            VerifyCommands::Batch { .. } => "batch verification",
            VerifyCommands::Bundle { .. } => "bundle verification",
            VerifyCommands::File { .. } => "file verification",
            VerifyCommands::Compute { .. } => "digest computation",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        cmd: VerifyCommands,
    }

    #[test]
    fn test_verify_digest() {
        let args = TestCli::try_parse_from([
            "test", "digest",
            "--data", "48656c6c6f",
            "--expected", "abc123",
        ]);
        assert!(args.is_ok());
    }

    #[test]
    fn test_verify_proof() {
        let args = TestCli::try_parse_from(["test", "proof", "--proof-id", "proof:123"]);
        assert!(args.is_ok());
    }

    #[test]
    fn test_verify_batch() {
        let args = TestCli::try_parse_from(["test", "batch", "--batch-id", "batch:123"]);
        assert!(args.is_ok());
    }

    #[test]
    fn test_verify_bundle() {
        let args = TestCli::try_parse_from([
            "test", "bundle",
            "--file", "/path/to/bundle.json",
            "--level", "L2",
        ]);
        assert!(args.is_ok());
    }

    #[test]
    fn test_compute() {
        let args = TestCli::try_parse_from([
            "test", "compute",
            "--data", "hello world",
        ]);
        assert!(args.is_ok());
    }

    #[test]
    fn test_description() {
        let cmd = VerifyCommands::Digest {
            data: "test".to_string(),
            expected: None,
        };
        assert_eq!(cmd.description(), "digest verification");
    }
}
