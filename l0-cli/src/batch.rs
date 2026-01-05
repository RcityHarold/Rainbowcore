//! Batch Operations Support
//!
//! Execute multiple L0 commands from a file or script.

use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Batch operation configuration
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BatchConfig {
    /// Continue on error
    pub continue_on_error: bool,
    /// Verbose output
    pub verbose: bool,
    /// Dry run (parse only)
    pub dry_run: bool,
    /// Maximum parallel operations
    pub max_parallel: usize,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            continue_on_error: false,
            verbose: true,
            dry_run: false,
            max_parallel: 1,
        }
    }
}

/// A batch operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchOperation {
    /// Operation command
    pub command: String,
    /// Arguments
    pub args: Vec<String>,
    /// Optional description
    pub description: Option<String>,
    /// Depends on previous operation
    pub depends_on: Option<usize>,
}

#[allow(dead_code)]
impl BatchOperation {
    /// Create a new batch operation
    pub fn new(command: String, args: Vec<String>) -> Self {
        Self {
            command,
            args,
            description: None,
            depends_on: None,
        }
    }

    /// With description
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = Some(desc.to_string());
        self
    }

    /// With dependency
    pub fn with_dependency(mut self, idx: usize) -> Self {
        self.depends_on = Some(idx);
        self
    }

    /// Convert to command line string
    pub fn to_cli_string(&self) -> String {
        let mut parts = vec![self.command.clone()];
        parts.extend(self.args.iter().cloned());
        parts.join(" ")
    }
}

/// Result of a batch operation
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BatchOperationResult {
    /// Operation index
    pub index: usize,
    /// The operation
    pub operation: BatchOperation,
    /// Success flag
    pub success: bool,
    /// Output (if any)
    pub output: Option<String>,
    /// Error (if any)
    pub error: Option<String>,
    /// Duration in milliseconds
    pub duration_ms: u64,
}

/// Batch execution result
#[derive(Debug, Clone)]
pub struct BatchResult {
    /// Total operations
    pub total: usize,
    /// Successful operations
    pub succeeded: usize,
    /// Failed operations
    pub failed: usize,
    /// Skipped operations
    pub skipped: usize,
    /// Individual results
    pub results: Vec<BatchOperationResult>,
}

impl BatchResult {
    /// Create a new batch result
    pub fn new() -> Self {
        Self {
            total: 0,
            succeeded: 0,
            failed: 0,
            skipped: 0,
            results: Vec::new(),
        }
    }

    /// Add a result
    pub fn add(&mut self, result: BatchOperationResult) {
        self.total += 1;
        if result.success {
            self.succeeded += 1;
        } else {
            self.failed += 1;
        }
        self.results.push(result);
    }

    /// Add skipped count
    pub fn add_skipped(&mut self, count: usize) {
        self.skipped += count;
    }

    /// Check if all operations succeeded
    #[allow(dead_code)]
    pub fn all_succeeded(&self) -> bool {
        self.failed == 0 && self.skipped == 0
    }

    /// Print summary
    pub fn print_summary(&self) {
        println!("\nBatch Execution Summary:");
        println!("  Total: {}", self.total);
        println!("  Succeeded: {}", self.succeeded);
        println!("  Failed: {}", self.failed);
        println!("  Skipped: {}", self.skipped);

        if self.failed > 0 {
            println!("\nFailed operations:");
            for result in &self.results {
                if !result.success {
                    println!(
                        "  [{}] {} - {}",
                        result.index,
                        result.operation.to_cli_string(),
                        result.error.as_deref().unwrap_or("Unknown error")
                    );
                }
            }
        }
    }
}

impl Default for BatchResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse batch operations from a file
pub fn parse_batch_file(path: &Path) -> Result<Vec<BatchOperation>, String> {
    let file = std::fs::File::open(path)
        .map_err(|e| format!("Failed to open batch file: {}", e))?;

    let reader = BufReader::new(file);
    parse_batch_lines(reader.lines().filter_map(|l| l.ok()))
}

/// Parse batch operations from lines
pub fn parse_batch_lines<I>(lines: I) -> Result<Vec<BatchOperation>, String>
where
    I: Iterator<Item = String>,
{
    let mut operations = Vec::new();

    for (line_num, line) in lines.enumerate() {
        let trimmed = line.trim();

        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Parse the command
        match parse_batch_line(trimmed) {
            Ok(op) => operations.push(op),
            Err(e) => return Err(format!("Line {}: {}", line_num + 1, e)),
        }
    }

    Ok(operations)
}

/// Parse a single batch line
fn parse_batch_line(line: &str) -> Result<BatchOperation, String> {
    let parts = parse_command_parts(line);
    if parts.is_empty() {
        return Err("Empty command".to_string());
    }

    let command = parts[0].clone();
    let args = parts[1..].to_vec();

    Ok(BatchOperation::new(command, args))
}

/// Parse command parts with quote handling
fn parse_command_parts(input: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut quote_char = ' ';
    let mut escape_next = false;

    for c in input.chars() {
        if escape_next {
            current.push(c);
            escape_next = false;
            continue;
        }

        match c {
            '\\' => escape_next = true,
            '"' | '\'' => {
                if !in_quotes {
                    in_quotes = true;
                    quote_char = c;
                } else if c == quote_char {
                    in_quotes = false;
                } else {
                    current.push(c);
                }
            }
            ' ' | '\t' if !in_quotes => {
                if !current.is_empty() {
                    parts.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(c),
        }
    }

    if !current.is_empty() {
        parts.push(current);
    }

    parts
}

/// Generate a shell script from batch operations
pub fn generate_script(operations: &[BatchOperation], db_url: &str, tenant: &str) -> String {
    let mut script = String::new();

    // Header
    script.push_str("#!/bin/bash\n");
    script.push_str("# L0 Batch Script\n");
    script.push_str(&format!("# Generated: {}\n", chrono::Utc::now().to_rfc3339()));
    script.push_str("\n");

    // Environment
    script.push_str("set -e  # Exit on error\n");
    script.push_str("\n");
    script.push_str(&format!("export L0_DB_URL=\"{}\"\n", db_url));
    script.push_str(&format!("export L0_TENANT_ID=\"{}\"\n", tenant));
    script.push_str("\n");

    // Operations
    for (i, op) in operations.iter().enumerate() {
        if let Some(desc) = &op.description {
            script.push_str(&format!("# {}\n", desc));
        }
        script.push_str(&format!("echo \"[{}/{}] {}\"\n", i + 1, operations.len(), op.command));
        script.push_str(&format!("l0 {}\n", op.to_cli_string()));
        script.push_str("\n");
    }

    script.push_str("echo \"Batch complete!\"\n");

    script
}

/// Common batch templates
pub mod templates {
    use super::BatchOperation;

    /// Create a template for actor registration batch
    pub fn actor_registration_template(actors: &[(String, String, String)]) -> Vec<BatchOperation> {
        actors.iter().map(|(actor_type, pubkey, node_id)| {
            BatchOperation::new(
                "actor".to_string(),
                vec![
                    "register".to_string(),
                    "-t".to_string(),
                    actor_type.clone(),
                    "-p".to_string(),
                    pubkey.clone(),
                    "-n".to_string(),
                    node_id.clone(),
                ],
            )
        }).collect()
    }

    /// Create a template for consent grants
    pub fn consent_grant_template(
        grants: &[(String, String, String, Vec<String>, String)],
    ) -> Vec<BatchOperation> {
        grants.iter().map(|(grantor, grantee, resource, actions, terms)| {
            BatchOperation::new(
                "consent".to_string(),
                vec![
                    "grant".to_string(),
                    "-g".to_string(),
                    grantor.clone(),
                    "-e".to_string(),
                    grantee.clone(),
                    "-r".to_string(),
                    resource.clone(),
                    "-a".to_string(),
                    actions.join(","),
                    "-t".to_string(),
                    terms.clone(),
                ],
            )
        }).collect()
    }

    /// Create a template for batch commitment submission
    pub fn commitment_batch_template(
        commits: &[(String, String, String)],
    ) -> Vec<BatchOperation> {
        commits.iter().map(|(actor_id, scope, data)| {
            BatchOperation::new(
                "commit".to_string(),
                vec![
                    "-a".to_string(),
                    actor_id.clone(),
                    "-s".to_string(),
                    scope.clone(),
                    "-d".to_string(),
                    data.clone(),
                ],
            )
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_operation() {
        let op = BatchOperation::new("actor".to_string(), vec!["list".to_string()]);
        assert_eq!(op.command, "actor");
        assert_eq!(op.to_cli_string(), "actor list");
    }

    #[test]
    fn test_batch_operation_with_description() {
        let op = BatchOperation::new("actor".to_string(), vec!["list".to_string()])
            .with_description("List all actors");
        assert_eq!(op.description, Some("List all actors".to_string()));
    }

    #[test]
    fn test_parse_command_parts() {
        let parts = parse_command_parts("actor register -t human_actor -p key123");
        assert_eq!(parts, vec!["actor", "register", "-t", "human_actor", "-p", "key123"]);
    }

    #[test]
    fn test_parse_quoted_parts() {
        let parts = parse_command_parts("commit -d \"data with spaces\"");
        assert_eq!(parts, vec!["commit", "-d", "data with spaces"]);
    }

    #[test]
    fn test_parse_batch_lines() {
        let lines = vec![
            "# Comment".to_string(),
            "actor list".to_string(),
            "".to_string(),
            "status".to_string(),
        ];
        let ops = parse_batch_lines(lines.into_iter()).unwrap();
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].command, "actor");
        assert_eq!(ops[1].command, "status");
    }

    #[test]
    fn test_batch_result() {
        let mut result = BatchResult::new();
        result.add(BatchOperationResult {
            index: 0,
            operation: BatchOperation::new("test".to_string(), vec![]),
            success: true,
            output: None,
            error: None,
            duration_ms: 100,
        });
        result.add(BatchOperationResult {
            index: 1,
            operation: BatchOperation::new("test2".to_string(), vec![]),
            success: false,
            output: None,
            error: Some("Failed".to_string()),
            duration_ms: 50,
        });

        assert_eq!(result.total, 2);
        assert_eq!(result.succeeded, 1);
        assert_eq!(result.failed, 1);
        assert!(!result.all_succeeded());
    }

    #[test]
    fn test_generate_script() {
        let ops = vec![
            BatchOperation::new("actor".to_string(), vec!["list".to_string()]),
            BatchOperation::new("status".to_string(), vec![]),
        ];

        let script = generate_script(&ops, "mem://", "test");

        assert!(script.contains("#!/bin/bash"));
        assert!(script.contains("L0_DB_URL=\"mem://\""));
        assert!(script.contains("L0_TENANT_ID=\"test\""));
        assert!(script.contains("l0 actor list"));
        assert!(script.contains("l0 status"));
    }

    #[test]
    fn test_actor_registration_template() {
        let actors = vec![
            ("human_actor".to_string(), "key1".to_string(), "node1".to_string()),
            ("ai_actor".to_string(), "key2".to_string(), "node1".to_string()),
        ];

        let ops = templates::actor_registration_template(&actors);
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].command, "actor");
        assert!(ops[0].args.contains(&"human_actor".to_string()));
    }
}
