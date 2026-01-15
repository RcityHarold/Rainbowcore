//! Execute Commands
//!
//! Commands for executing operations on the P3 economy layer.

use clap::Subcommand;
use rust_decimal::Decimal;

/// Execute operation subcommands
#[derive(Subcommand, Debug)]
pub enum ExecuteCommands {
    /// Execute a distribution operation
    Distribution {
        /// Target reference (hex digest)
        #[arg(short, long)]
        target: String,

        /// Amount to distribute
        #[arg(short, long)]
        amount: Decimal,

        /// Epoch ID
        #[arg(short, long)]
        epoch: String,

        /// Initiator reference
        #[arg(short, long)]
        initiator: String,

        /// Executor reference (optional)
        #[arg(long)]
        executor: Option<String>,
    },

    /// Execute a clawback operation
    Clawback {
        /// Target reference (hex digest)
        #[arg(short, long)]
        target: String,

        /// Amount to clawback
        #[arg(short, long)]
        amount: Decimal,

        /// Epoch ID
        #[arg(short, long)]
        epoch: String,

        /// Initiator reference
        #[arg(short, long)]
        initiator: String,

        /// Reason for clawback
        #[arg(short, long)]
        reason: Option<String>,
    },

    /// Execute an attribution operation
    Attribution {
        /// Target reference (hex digest)
        #[arg(short, long)]
        target: String,

        /// Epoch ID
        #[arg(short, long)]
        epoch: String,

        /// Initiator reference
        #[arg(short, long)]
        initiator: String,
    },

    /// Execute a fine operation
    Fine {
        /// Target reference (hex digest)
        #[arg(short, long)]
        target: String,

        /// Fine amount
        #[arg(short, long)]
        amount: Decimal,

        /// Epoch ID
        #[arg(short, long)]
        epoch: String,

        /// Initiator reference
        #[arg(short, long)]
        initiator: String,

        /// Verdict reference
        #[arg(long)]
        verdict_ref: Option<String>,
    },

    /// Execute a subsidy operation
    Subsidy {
        /// Target reference (hex digest)
        #[arg(short, long)]
        target: String,

        /// Subsidy amount
        #[arg(short, long)]
        amount: Decimal,

        /// Epoch ID
        #[arg(short, long)]
        epoch: String,

        /// Initiator reference
        #[arg(short, long)]
        initiator: String,
    },

    /// Execute a deposit operation
    Deposit {
        /// Target reference (hex digest)
        #[arg(short, long)]
        target: String,

        /// Deposit amount
        #[arg(short, long)]
        amount: Decimal,

        /// Epoch ID
        #[arg(short, long)]
        epoch: String,

        /// Initiator reference
        #[arg(short, long)]
        initiator: String,
    },

    /// Execute a budget spend operation
    BudgetSpend {
        /// Target reference (hex digest)
        #[arg(short, long)]
        target: String,

        /// Spend amount
        #[arg(short, long)]
        amount: Decimal,

        /// Epoch ID
        #[arg(short, long)]
        epoch: String,

        /// Initiator reference
        #[arg(short, long)]
        initiator: String,

        /// Budget category
        #[arg(long)]
        category: Option<String>,
    },

    /// Execute a points calculation
    Points {
        /// Target reference (hex digest)
        #[arg(short, long)]
        target: String,

        /// Epoch ID
        #[arg(short, long)]
        epoch: String,

        /// Initiator reference
        #[arg(short, long)]
        initiator: String,
    },

    /// Generic operation execution
    Op {
        /// Operation type
        #[arg(short = 'T', long)]
        op_type: String,

        /// Target reference (hex digest)
        #[arg(short, long)]
        target: String,

        /// Amount (optional)
        #[arg(short, long)]
        amount: Option<Decimal>,

        /// Epoch ID
        #[arg(short, long)]
        epoch: String,

        /// Initiator reference
        #[arg(short, long)]
        initiator: String,

        /// Executor reference (optional)
        #[arg(long)]
        executor: Option<String>,
    },
}

impl ExecuteCommands {
    /// Get the operation type string
    pub fn operation_type(&self) -> &'static str {
        match self {
            ExecuteCommands::Distribution { .. } => "distribution",
            ExecuteCommands::Clawback { .. } => "clawback",
            ExecuteCommands::Attribution { .. } => "attribution",
            ExecuteCommands::Fine { .. } => "fine",
            ExecuteCommands::Subsidy { .. } => "subsidy",
            ExecuteCommands::Deposit { .. } => "deposit",
            ExecuteCommands::BudgetSpend { .. } => "budget_spend",
            ExecuteCommands::Points { .. } => "points_calculation",
            ExecuteCommands::Op { op_type, .. } => {
                // This leaks memory but it's acceptable for CLI
                Box::leak(op_type.clone().into_boxed_str())
            }
        }
    }

    /// Get the target digest
    pub fn target(&self) -> &str {
        match self {
            ExecuteCommands::Distribution { target, .. } => target,
            ExecuteCommands::Clawback { target, .. } => target,
            ExecuteCommands::Attribution { target, .. } => target,
            ExecuteCommands::Fine { target, .. } => target,
            ExecuteCommands::Subsidy { target, .. } => target,
            ExecuteCommands::Deposit { target, .. } => target,
            ExecuteCommands::BudgetSpend { target, .. } => target,
            ExecuteCommands::Points { target, .. } => target,
            ExecuteCommands::Op { target, .. } => target,
        }
    }

    /// Get the amount if applicable
    pub fn amount(&self) -> Option<Decimal> {
        match self {
            ExecuteCommands::Distribution { amount, .. } => Some(*amount),
            ExecuteCommands::Clawback { amount, .. } => Some(*amount),
            ExecuteCommands::Attribution { .. } => None,
            ExecuteCommands::Fine { amount, .. } => Some(*amount),
            ExecuteCommands::Subsidy { amount, .. } => Some(*amount),
            ExecuteCommands::Deposit { amount, .. } => Some(*amount),
            ExecuteCommands::BudgetSpend { amount, .. } => Some(*amount),
            ExecuteCommands::Points { .. } => None,
            ExecuteCommands::Op { amount, .. } => *amount,
        }
    }

    /// Get the epoch ID
    pub fn epoch(&self) -> &str {
        match self {
            ExecuteCommands::Distribution { epoch, .. } => epoch,
            ExecuteCommands::Clawback { epoch, .. } => epoch,
            ExecuteCommands::Attribution { epoch, .. } => epoch,
            ExecuteCommands::Fine { epoch, .. } => epoch,
            ExecuteCommands::Subsidy { epoch, .. } => epoch,
            ExecuteCommands::Deposit { epoch, .. } => epoch,
            ExecuteCommands::BudgetSpend { epoch, .. } => epoch,
            ExecuteCommands::Points { epoch, .. } => epoch,
            ExecuteCommands::Op { epoch, .. } => epoch,
        }
    }

    /// Get the initiator reference
    pub fn initiator(&self) -> &str {
        match self {
            ExecuteCommands::Distribution { initiator, .. } => initiator,
            ExecuteCommands::Clawback { initiator, .. } => initiator,
            ExecuteCommands::Attribution { initiator, .. } => initiator,
            ExecuteCommands::Fine { initiator, .. } => initiator,
            ExecuteCommands::Subsidy { initiator, .. } => initiator,
            ExecuteCommands::Deposit { initiator, .. } => initiator,
            ExecuteCommands::BudgetSpend { initiator, .. } => initiator,
            ExecuteCommands::Points { initiator, .. } => initiator,
            ExecuteCommands::Op { initiator, .. } => initiator,
        }
    }

    /// Get the executor reference if specified
    pub fn executor(&self) -> Option<&str> {
        match self {
            ExecuteCommands::Distribution { executor, .. } => executor.as_deref(),
            ExecuteCommands::Op { executor, .. } => executor.as_deref(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_distribution_command() {
        let cmd = ExecuteCommands::Distribution {
            target: "abc123".to_string(),
            amount: Decimal::new(1000, 2),
            epoch: "epoch:2024:001".to_string(),
            initiator: "actor:1".to_string(),
            executor: None,
        };

        assert_eq!(cmd.operation_type(), "distribution");
        assert_eq!(cmd.target(), "abc123");
        assert_eq!(cmd.amount(), Some(Decimal::new(1000, 2)));
        assert_eq!(cmd.epoch(), "epoch:2024:001");
        assert_eq!(cmd.initiator(), "actor:1");
        assert!(cmd.executor().is_none());
    }

    #[test]
    fn test_clawback_command() {
        let cmd = ExecuteCommands::Clawback {
            target: "def456".to_string(),
            amount: Decimal::new(500, 2),
            epoch: "epoch:2024:002".to_string(),
            initiator: "actor:2".to_string(),
            reason: Some("Violation".to_string()),
        };

        assert_eq!(cmd.operation_type(), "clawback");
        assert_eq!(cmd.amount(), Some(Decimal::new(500, 2)));
    }

    #[test]
    fn test_attribution_no_amount() {
        let cmd = ExecuteCommands::Attribution {
            target: "ghi789".to_string(),
            epoch: "epoch:2024:003".to_string(),
            initiator: "actor:3".to_string(),
        };

        assert_eq!(cmd.operation_type(), "attribution");
        assert!(cmd.amount().is_none());
    }
}
