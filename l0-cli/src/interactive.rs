//! Interactive CLI Mode
//!
//! Provides a REPL-style interface for executing L0 commands.

use std::io::{self, Write};

/// Interactive mode configuration
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct InteractiveConfig {
    /// Prompt string
    pub prompt: String,
    /// History file path
    pub history_file: Option<String>,
    /// Maximum history entries
    pub max_history: usize,
    /// Enable colored output
    pub colored: bool,
}

impl Default for InteractiveConfig {
    fn default() -> Self {
        Self {
            prompt: "l0> ".to_string(),
            history_file: None,
            max_history: 1000,
            colored: true,
        }
    }
}

/// Command history for interactive mode
pub struct CommandHistory {
    entries: Vec<String>,
    max_size: usize,
}

impl CommandHistory {
    /// Create a new command history
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_size,
        }
    }

    /// Add a command to history
    pub fn add(&mut self, command: String) {
        if !command.trim().is_empty() {
            // Don't add duplicates of the last command
            if self.entries.last() != Some(&command) {
                self.entries.push(command);
                if self.entries.len() > self.max_size {
                    self.entries.remove(0);
                }
            }
        }
    }

    /// Get all history entries
    pub fn entries(&self) -> &[String] {
        &self.entries
    }

    /// Get the last N entries
    pub fn last_n(&self, n: usize) -> &[String] {
        let start = self.entries.len().saturating_sub(n);
        &self.entries[start..]
    }

    /// Clear history
    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

/// Interactive session state
pub struct InteractiveSession {
    /// Configuration
    pub config: InteractiveConfig,
    /// Command history
    pub history: CommandHistory,
    /// Current database URL
    pub db_url: String,
    /// Current tenant
    pub tenant: String,
    /// Running flag
    running: bool,
}

impl InteractiveSession {
    /// Create a new interactive session
    pub fn new(db_url: String, tenant: String) -> Self {
        Self {
            config: InteractiveConfig::default(),
            history: CommandHistory::new(1000),
            db_url,
            tenant,
            running: true,
        }
    }

    /// Create with custom config
    #[allow(dead_code)]
    pub fn with_config(db_url: String, tenant: String, config: InteractiveConfig) -> Self {
        let max_history = config.max_history;
        Self {
            config,
            history: CommandHistory::new(max_history),
            db_url,
            tenant,
            running: true,
        }
    }

    /// Check if session is running
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Stop the session
    pub fn stop(&mut self) {
        self.running = false;
    }

    /// Print the prompt and read a line
    pub fn read_line(&self) -> io::Result<String> {
        print!("{}", self.config.prompt);
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        Ok(input.trim().to_string())
    }

    /// Print help message
    pub fn print_help(&self) {
        println!("L0 Interactive Mode Commands:");
        println!();
        println!("  help, ?         - Show this help message");
        println!("  history [n]     - Show command history (last n entries)");
        println!("  clear           - Clear the screen");
        println!("  status          - Show current connection status");
        println!("  set db <url>    - Set database URL");
        println!("  set tenant <id> - Set tenant ID");
        println!("  exit, quit, q   - Exit interactive mode");
        println!();
        println!("L0 Commands:");
        println!("  actor register <type> <pubkey> <node_id>");
        println!("  actor get <actor_id>");
        println!("  actor list [--type <type>] [--limit <n>]");
        println!();
        println!("  commit -a <actor_id> -s <scope> -d <data_hex>");
        println!("  verify -c <commitment_id> [-d <depth>]");
        println!();
        println!("  receipt get <id>");
        println!("  receipt verify <id>");
        println!("  receipt list [--scope <type>] [--limit <n>]");
        println!();
        println!("  knowledge index -d <digest> -o <owner>");
        println!("  knowledge get <entry_id>");
        println!("  knowledge find -d <digest>");
        println!();
        println!("  consent grant -g <grantor> -e <grantee> -r <resource> -a <actions> -t <terms>");
        println!("  consent verify -g <grantor> -e <grantee> -a <action> -r <resource>");
        println!();
        println!("  dispute file -b <filed_by> -a <against> -s <subject> -e <evidence>");
        println!("  dispute get <dispute_id>");
        println!("  dispute list [--status <status>]");
        println!();
        println!("  anchor create -c <chain> -r <root> -n <epoch_seq> -b <batch_count>");
        println!("  anchor get <anchor_id>");
        println!("  anchor verify <anchor_id>");
        println!();
        println!("  backfill gaps -a <actor_id> -s <start> -e <end>");
        println!("  backfill continuity -a <actor_id> -s <start> -e <end>");
        println!();
        println!("  tipwitness submit -a <actor_id> -d <digest> -s <sequence>");
        println!("  tipwitness get <actor_id>");
        println!();
        println!("Use 'l0 <command> --help' for detailed command help.");
    }

    /// Print status
    pub fn print_status(&self) {
        println!("Connection Status:");
        println!("  Database URL: {}", self.db_url);
        println!("  Tenant: {}", self.tenant);
        println!("  History entries: {}", self.history.entries().len());
    }

    /// Parse and execute a built-in command
    pub fn execute_builtin(&mut self, input: &str) -> Option<BuiltinResult> {
        let parts: Vec<&str> = input.split_whitespace().collect();
        if parts.is_empty() {
            return Some(BuiltinResult::Empty);
        }

        match parts[0] {
            "help" | "?" => {
                self.print_help();
                Some(BuiltinResult::Handled)
            }
            "history" => {
                let n = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(10);
                let entries = self.history.last_n(n);
                println!("Last {} commands:", entries.len());
                for (i, entry) in entries.iter().enumerate() {
                    println!("  {}: {}", entries.len() - i, entry);
                }
                Some(BuiltinResult::Handled)
            }
            "clear" => {
                print!("\x1B[2J\x1B[1;1H"); // ANSI clear screen
                Some(BuiltinResult::Handled)
            }
            "status" => {
                self.print_status();
                Some(BuiltinResult::Handled)
            }
            "set" => {
                if parts.len() < 3 {
                    println!("Usage: set <db|tenant> <value>");
                } else {
                    match parts[1] {
                        "db" => {
                            self.db_url = parts[2].to_string();
                            println!("Database URL set to: {}", self.db_url);
                        }
                        "tenant" => {
                            self.tenant = parts[2].to_string();
                            println!("Tenant set to: {}", self.tenant);
                        }
                        _ => println!("Unknown setting: {}", parts[1]),
                    }
                }
                Some(BuiltinResult::Handled)
            }
            "exit" | "quit" | "q" => {
                self.stop();
                Some(BuiltinResult::Exit)
            }
            _ => None, // Not a built-in command
        }
    }
}

/// Result of executing a built-in command
pub enum BuiltinResult {
    /// Command was handled
    Handled,
    /// Empty input
    Empty,
    /// Exit requested
    Exit,
}

/// Parse command line from interactive input
pub fn parse_interactive_args(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escape_next = false;

    for c in input.chars() {
        if escape_next {
            current.push(c);
            escape_next = false;
            continue;
        }

        match c {
            '\\' => escape_next = true,
            '"' | '\'' => in_quotes = !in_quotes,
            ' ' | '\t' if !in_quotes => {
                if !current.is_empty() {
                    args.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(c),
        }
    }

    if !current.is_empty() {
        args.push(current);
    }

    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_history() {
        let mut history = CommandHistory::new(5);
        history.add("cmd1".to_string());
        history.add("cmd2".to_string());
        history.add("cmd3".to_string());

        assert_eq!(history.entries().len(), 3);
        assert_eq!(history.last_n(2), &["cmd2".to_string(), "cmd3".to_string()]);
    }

    #[test]
    fn test_history_max_size() {
        let mut history = CommandHistory::new(2);
        history.add("cmd1".to_string());
        history.add("cmd2".to_string());
        history.add("cmd3".to_string());

        assert_eq!(history.entries().len(), 2);
        assert_eq!(history.entries(), &["cmd2".to_string(), "cmd3".to_string()]);
    }

    #[test]
    fn test_history_no_duplicates() {
        let mut history = CommandHistory::new(5);
        history.add("cmd1".to_string());
        history.add("cmd1".to_string());
        history.add("cmd1".to_string());

        assert_eq!(history.entries().len(), 1);
    }

    #[test]
    fn test_parse_args_simple() {
        let args = parse_interactive_args("commit -a actor1 -s akn_batch");
        assert_eq!(args, vec!["commit", "-a", "actor1", "-s", "akn_batch"]);
    }

    #[test]
    fn test_parse_args_quotes() {
        let args = parse_interactive_args("actor register \"human_actor\" key123 node1");
        assert_eq!(args, vec!["actor", "register", "human_actor", "key123", "node1"]);
    }

    #[test]
    fn test_interactive_session() {
        let session = InteractiveSession::new("mem://".to_string(), "test".to_string());
        assert!(session.is_running());
        assert_eq!(session.db_url, "mem://");
        assert_eq!(session.tenant, "test");
    }

    #[test]
    fn test_session_stop() {
        let mut session = InteractiveSession::new("mem://".to_string(), "test".to_string());
        assert!(session.is_running());
        session.stop();
        assert!(!session.is_running());
    }

    #[test]
    fn test_builtin_exit() {
        let mut session = InteractiveSession::new("mem://".to_string(), "test".to_string());
        let result = session.execute_builtin("exit");
        assert!(matches!(result, Some(BuiltinResult::Exit)));
        assert!(!session.is_running());
    }

    #[test]
    fn test_builtin_set() {
        let mut session = InteractiveSession::new("mem://".to_string(), "test".to_string());
        session.execute_builtin("set db file://newdb");
        assert_eq!(session.db_url, "file://newdb");

        session.execute_builtin("set tenant newtenant");
        assert_eq!(session.tenant, "newtenant");
    }
}
