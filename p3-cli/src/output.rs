//! Output Formatting
//!
//! Utilities for formatting CLI output in various formats.

use crate::client::{ExecuteResponse, HealthResponse, StatsResponse, VerifyResponse};
use crate::commands::OutputFormat;
use serde::Serialize;

/// Format and print data based on output format
pub fn print_output<T: Serialize>(data: &T, format: OutputFormat) {
    match format {
        OutputFormat::Json => print_json(data),
        OutputFormat::Table => print_table(data),
        OutputFormat::Plain => print_plain(data),
    }
}

/// Print as JSON
fn print_json<T: Serialize>(data: &T) {
    match serde_json::to_string_pretty(data) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("Error formatting JSON: {}", e),
    }
}

/// Print as table (generic fallback to JSON)
fn print_table<T: Serialize>(data: &T) {
    // For generic types, fall back to JSON
    print_json(data);
}

/// Print as plain text (generic fallback to JSON)
fn print_plain<T: Serialize>(data: &T) {
    // For generic types, fall back to JSON
    print_json(data);
}

/// Print health response
pub fn print_health(health: &HealthResponse, format: OutputFormat) {
    match format {
        OutputFormat::Json => print_json(health),
        OutputFormat::Table | OutputFormat::Plain => {
            println!("P3 Service Health");
            println!("==================");
            println!("Status:  {}", colorize_status(&health.status));
            println!("Version: {}", health.version);
            println!("Uptime:  {}s", health.uptime_secs);
            println!();
            println!("Components:");
            for component in &health.components {
                let status = colorize_status(&component.status);
                print!("  - {}: {}", component.name, status);
                if let Some(msg) = &component.message {
                    print!(" ({})", msg);
                }
                println!();
            }
        }
    }
}

/// Print stats response
pub fn print_stats(stats: &StatsResponse, format: OutputFormat) {
    match format {
        OutputFormat::Json => print_json(stats),
        OutputFormat::Table | OutputFormat::Plain => {
            println!("Executor Statistics");
            println!("====================");
            println!("Active Executions:     {}", stats.active_executions);
            println!("Active Attempt Chains: {}", stats.active_attempt_chains);
            println!("Proofs Generated:      {}", stats.proofs_generated);
            println!("Active Batches:        {}", stats.active_batches);
        }
    }
}

/// Print execute response
pub fn print_execute_result(result: &ExecuteResponse, format: OutputFormat) {
    match format {
        OutputFormat::Json => print_json(result),
        OutputFormat::Table | OutputFormat::Plain => {
            println!("Execution Result");
            println!("=================");
            println!("Execution ID:    {}", result.execution_id);
            println!("Status:          {}", colorize_status(&result.status));
            println!("Resolution Type: {}", result.resolution_type);
            if let Some(digest) = &result.result_digest {
                println!("Result Digest:   {}", digest);
            }
            println!("Completed At:    {}", result.completed_at);
            if let Some(proof) = &result.proof_ref {
                println!();
                println!("Proof:");
                println!("  ID:       {}", proof.proof_id);
                println!("  Type:     {}", proof.proof_type);
                println!("  Executor: {}", proof.executor_ref);
                println!("  Digest:   {}", proof.proof_digest);
            }
        }
    }
}

/// Print verify response
pub fn print_verify_result(result: &VerifyResponse, format: OutputFormat) {
    match format {
        OutputFormat::Json => print_json(result),
        OutputFormat::Table | OutputFormat::Plain => {
            println!("Verification Result");
            println!("===================");
            let status = if result.valid { "VALID" } else { "INVALID" };
            println!("Status: {}", colorize_status(status));
            println!("Digest: {}", result.digest);
            if let Some(details) = &result.details {
                println!("Details: {}", serde_json::to_string_pretty(details).unwrap_or_default());
            }
        }
    }
}

/// Print error message
pub fn print_error(error: &crate::error::CliError) {
    eprintln!("Error: {}", error);
}

/// Print success message
pub fn print_success(message: &str) {
    println!("{}", message);
}

/// Print warning message
pub fn print_warning(message: &str) {
    eprintln!("Warning: {}", message);
}

/// Print info message
pub fn print_info(message: &str) {
    println!("{}", message);
}

/// Colorize status text (placeholder - actual colors depend on terminal support)
fn colorize_status(status: &str) -> &str {
    // In a real implementation, we'd use terminal colors
    // For now, just return the status as-is
    status
}

/// Print a table row
pub fn print_row(key: &str, value: &str) {
    println!("{:<20} {}", key, value);
}

/// Print a separator line
pub fn print_separator() {
    println!("{}", "-".repeat(40));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_colorize_status() {
        assert_eq!(colorize_status("healthy"), "healthy");
        assert_eq!(colorize_status("unhealthy"), "unhealthy");
    }

    #[test]
    fn test_print_row_format() {
        // Just verify it doesn't panic
        print_row("Key", "Value");
    }
}
