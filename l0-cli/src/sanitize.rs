//! Input Sanitization for CLI (ISSUE-023)
//!
//! This module provides input validation and sanitization for CLI commands.
//! It helps prevent:
//! - Command injection attacks
//! - Path traversal attacks
//! - Invalid data format issues
//! - Malicious input handling
//!
//! # Security Considerations
//!
//! 1. **ID Validation**: Actor IDs, commitment IDs, etc. must match expected patterns
//! 2. **Hex Validation**: All hex-encoded data must be valid hex strings
//! 3. **Path Validation**: File paths must not contain traversal sequences
//! 4. **Shell Escaping**: User input in shell commands must be properly escaped

use regex::Regex;
use once_cell::sync::Lazy;

/// Sanitization error types
#[derive(Debug, Clone, thiserror::Error)]
pub enum SanitizeError {
    /// Invalid ID format
    #[error("Invalid ID format: {0}")]
    InvalidId(String),

    /// Invalid hex string
    #[error("Invalid hex string: {0}")]
    InvalidHex(String),

    /// Invalid path (path traversal attempt)
    #[error("Invalid path: {0}")]
    InvalidPath(String),

    /// Shell injection attempt detected
    #[error("Potentially unsafe input detected: {0}")]
    UnsafeInput(String),

    /// Input too long
    #[error("Input exceeds maximum length ({max}): got {actual}")]
    InputTooLong { max: usize, actual: usize },

    /// Empty input when not allowed
    #[error("Input cannot be empty: {0}")]
    EmptyInput(String),

    /// Invalid URL format
    #[error("Invalid URL format: {0}")]
    InvalidUrl(String),

    /// Invalid actor type
    #[error("Invalid actor type: {0}")]
    InvalidActorType(String),

    /// Invalid chain type
    #[error("Invalid chain type: {0}")]
    InvalidChainType(String),
}

pub type SanitizeResult<T> = Result<T, SanitizeError>;

// =============================================================================
// Regex Patterns (compiled once)
// =============================================================================

/// Valid ID pattern: alphanumeric, underscores, hyphens, colons, max 256 chars
static ID_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z0-9_:\-\.]{1,256}$").expect("Invalid ID regex")
});

/// Valid hex pattern: only hex chars, even length
static HEX_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[0-9a-fA-F]*$").expect("Invalid hex regex")
});

/// Shell metacharacters that need escaping/blocking
static SHELL_UNSAFE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[;&|`$(){}<>\\\n\r\[\]]").expect("Invalid shell regex")
});

/// URL pattern (basic validation)
static URL_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(https?|mem|file|ws|wss)://[^\s]*$").expect("Invalid URL regex")
});

/// Path traversal pattern
static PATH_TRAVERSAL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(\.\.|/\.\.|\.\./|~)").expect("Invalid path traversal regex")
});

// =============================================================================
// Input Validators
// =============================================================================

/// Validate and sanitize an ID (actor_id, commitment_id, etc.)
///
/// Valid IDs are alphanumeric with underscores, hyphens, colons, and dots.
/// Maximum length is 256 characters.
pub fn validate_id<'a>(id: &'a str, field_name: &str) -> SanitizeResult<&'a str> {
    if id.is_empty() {
        return Err(SanitizeError::EmptyInput(field_name.to_string()));
    }

    if id.len() > 256 {
        return Err(SanitizeError::InputTooLong {
            max: 256,
            actual: id.len(),
        });
    }

    if !ID_PATTERN.is_match(id) {
        return Err(SanitizeError::InvalidId(format!(
            "{}: '{}' contains invalid characters",
            field_name, id
        )));
    }

    Ok(id)
}

/// Validate hex-encoded string
///
/// Must contain only hex characters (0-9, a-f, A-F).
/// Empty strings are allowed unless `allow_empty` is false.
pub fn validate_hex<'a>(hex: &'a str, field_name: &str, allow_empty: bool) -> SanitizeResult<&'a str> {
    if hex.is_empty() {
        if allow_empty {
            return Ok(hex);
        } else {
            return Err(SanitizeError::EmptyInput(field_name.to_string()));
        }
    }

    // Check for even length (hex should always have pairs)
    if hex.len() % 2 != 0 {
        return Err(SanitizeError::InvalidHex(format!(
            "{}: hex string must have even length, got {}",
            field_name,
            hex.len()
        )));
    }

    // Maximum 64KB of data (128KB hex chars)
    if hex.len() > 131072 {
        return Err(SanitizeError::InputTooLong {
            max: 131072,
            actual: hex.len(),
        });
    }

    if !HEX_PATTERN.is_match(hex) {
        return Err(SanitizeError::InvalidHex(format!(
            "{}: '{}...' contains non-hex characters",
            field_name,
            &hex[..hex.len().min(20)]
        )));
    }

    Ok(hex)
}

/// Validate file path (no path traversal)
///
/// Blocks attempts to use `..`, `~`, etc.
pub fn validate_path<'a>(path: &'a str, field_name: &str) -> SanitizeResult<&'a str> {
    if path.is_empty() {
        return Err(SanitizeError::EmptyInput(field_name.to_string()));
    }

    if PATH_TRAVERSAL.is_match(path) {
        return Err(SanitizeError::InvalidPath(format!(
            "{}: path traversal not allowed",
            field_name
        )));
    }

    // Also verify the path doesn't start with / for non-absolute operations
    // (caller can decide if absolute paths are allowed)

    Ok(path)
}

/// Validate URL format
pub fn validate_url<'a>(url: &'a str, field_name: &str) -> SanitizeResult<&'a str> {
    if url.is_empty() {
        return Err(SanitizeError::EmptyInput(field_name.to_string()));
    }

    if url.len() > 2048 {
        return Err(SanitizeError::InputTooLong {
            max: 2048,
            actual: url.len(),
        });
    }

    if !URL_PATTERN.is_match(url) {
        return Err(SanitizeError::InvalidUrl(format!(
            "{}: invalid URL format",
            field_name
        )));
    }

    Ok(url)
}

/// Check input for shell-unsafe characters
///
/// Used to detect potential command injection attempts in interactive mode.
pub fn check_shell_safe<'a>(input: &'a str, field_name: &str) -> SanitizeResult<&'a str> {
    if SHELL_UNSAFE.is_match(input) {
        // Find the first unsafe character for error message
        let unsafe_char = SHELL_UNSAFE.find(input).map(|m| m.as_str()).unwrap_or("?");
        return Err(SanitizeError::UnsafeInput(format!(
            "{}: contains shell metacharacter '{}'",
            field_name, unsafe_char
        )));
    }

    Ok(input)
}

/// Validate actor type
pub fn validate_actor_type(actor_type: &str) -> SanitizeResult<&str> {
    match actor_type {
        "human_actor" | "ai_actor" | "node_actor" | "group_actor" => Ok(actor_type),
        _ => Err(SanitizeError::InvalidActorType(format!(
            "must be one of: human_actor, ai_actor, node_actor, group_actor (got: {})",
            actor_type
        ))),
    }
}

/// Validate chain type
pub fn validate_chain_type(chain: &str) -> SanitizeResult<&str> {
    match chain {
        "ethereum" | "bitcoin" | "polygon" | "solana" | "internal" => Ok(chain),
        _ => Err(SanitizeError::InvalidChainType(format!(
            "must be one of: ethereum, bitcoin, polygon, solana, internal (got: {})",
            chain
        ))),
    }
}

/// Validate dispute priority
pub fn validate_priority(priority: &str) -> SanitizeResult<&str> {
    match priority {
        "normal" | "urgent" | "critical" => Ok(priority),
        _ => Err(SanitizeError::InvalidId(format!(
            "priority must be one of: normal, urgent, critical (got: {})",
            priority
        ))),
    }
}

/// Validate verdict type
pub fn validate_verdict_type(verdict_type: &str) -> SanitizeResult<&str> {
    match verdict_type {
        "in_favor" | "against" | "mixed" | "dismissed" | "inconclusive" => Ok(verdict_type),
        _ => Err(SanitizeError::InvalidId(format!(
            "verdict_type must be one of: in_favor, against, mixed, dismissed, inconclusive (got: {})",
            verdict_type
        ))),
    }
}

// =============================================================================
// Composite Validators
// =============================================================================

/// Sanitize interactive command input
///
/// This is the main entry point for sanitizing user input in interactive mode.
/// It checks for shell injection attempts and validates the overall structure.
pub fn sanitize_interactive_input(input: &str) -> SanitizeResult<String> {
    // Check for empty input
    if input.trim().is_empty() {
        return Ok(String::new());
    }

    // Check length limit
    if input.len() > 4096 {
        return Err(SanitizeError::InputTooLong {
            max: 4096,
            actual: input.len(),
        });
    }

    // Check for shell metacharacters
    // Note: We allow quotes for argument parsing but block most other shell chars
    let shell_dangerous = [';', '&', '|', '`', '$', '(', ')', '{', '}', '<', '>', '\n', '\r'];
    for ch in shell_dangerous {
        if input.contains(ch) {
            let ch_display = match ch {
                '\n' => "\\n".to_string(),
                '\r' => "\\r".to_string(),
                _ => ch.to_string(),
            };
            return Err(SanitizeError::UnsafeInput(format!(
                "input contains disallowed character '{}'",
                ch_display
            )));
        }
    }

    // Normalize whitespace
    let normalized = input
        .trim()
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ");

    Ok(normalized)
}

/// Sanitize arguments for batch file commands
pub fn sanitize_batch_args(args: &[String]) -> SanitizeResult<Vec<String>> {
    args.iter()
        .enumerate()
        .map(|(i, arg)| {
            // Check each argument for shell injection
            check_shell_safe(arg, &format!("argument {}", i))?;
            Ok(arg.clone())
        })
        .collect()
}

/// Validate commitment data input
pub struct CommitmentInput<'a> {
    pub actor_id: &'a str,
    pub scope_type: &'a str,
    pub data_hex: Option<&'a str>,
}

pub fn validate_commitment_input(input: &CommitmentInput) -> SanitizeResult<()> {
    validate_id(input.actor_id, "actor_id")?;
    validate_id(input.scope_type, "scope_type")?;

    if let Some(data) = input.data_hex {
        validate_hex(data, "data", true)?;
    }

    Ok(())
}

/// Validate consent input
pub struct ConsentInput<'a> {
    pub grantor: &'a str,
    pub grantee: &'a str,
    pub resource_type: &'a str,
    pub actions: &'a str,
    pub terms_digest: &'a str,
}

pub fn validate_consent_input(input: &ConsentInput) -> SanitizeResult<()> {
    validate_id(input.grantor, "grantor")?;
    validate_id(input.grantee, "grantee")?;
    validate_id(input.resource_type, "resource_type")?;

    // Actions are comma-separated
    for action in input.actions.split(',') {
        validate_id(action.trim(), "action")?;
    }

    validate_hex(input.terms_digest, "terms_digest", false)?;

    Ok(())
}

/// Validate anchor input
pub struct AnchorInput<'a> {
    pub chain: &'a str,
    pub epoch_root: &'a str,
    pub epoch_sequence: u64,
    pub batch_count: u64,
}

pub fn validate_anchor_input(input: &AnchorInput) -> SanitizeResult<()> {
    validate_chain_type(input.chain)?;
    validate_hex(input.epoch_root, "epoch_root", false)?;

    // Sequence numbers have no format restrictions beyond being valid u64
    Ok(())
}

// =============================================================================
// Shell Escaping for Subprocess Execution
// =============================================================================

/// Escape a string for safe use in shell commands
///
/// This wraps the string in single quotes and escapes any single quotes within.
pub fn shell_escape(s: &str) -> String {
    // Single-quote the string, escaping any internal single quotes
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Build a safe command string for execution
pub fn build_safe_command(program: &str, args: &[String]) -> SanitizeResult<Vec<String>> {
    let mut cmd = Vec::with_capacity(args.len() + 1);

    // Validate program name
    if program.contains(|c: char| !c.is_alphanumeric() && c != '_' && c != '-') {
        return Err(SanitizeError::UnsafeInput(format!(
            "program name contains unsafe characters: {}",
            program
        )));
    }
    cmd.push(program.to_string());

    // Each argument should be validated
    for (i, arg) in args.iter().enumerate() {
        // For arguments that look like flags (start with -), allow them
        if arg.starts_with('-') {
            // Validate flag format
            if !arg.chars().skip(1).all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
                return Err(SanitizeError::UnsafeInput(format!(
                    "invalid flag format at position {}: {}",
                    i, arg
                )));
            }
            cmd.push(arg.clone());
        } else {
            // For values, just add them (std::process::Command handles escaping)
            cmd.push(arg.clone());
        }
    }

    Ok(cmd)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_id_valid() {
        assert!(validate_id("actor_001", "test").is_ok());
        assert!(validate_id("commit:12345", "test").is_ok());
        assert!(validate_id("node-1-primary", "test").is_ok());
        assert!(validate_id("v1.0.0", "test").is_ok());
    }

    #[test]
    fn test_validate_id_invalid() {
        assert!(validate_id("", "test").is_err());
        assert!(validate_id("actor;rm -rf /", "test").is_err());
        assert!(validate_id("actor$(cmd)", "test").is_err());
        assert!(validate_id("actor`id`", "test").is_err());
    }

    #[test]
    fn test_validate_hex_valid() {
        assert!(validate_hex("", "test", true).is_ok());
        assert!(validate_hex("deadbeef", "test", false).is_ok());
        assert!(validate_hex("DEADBEEF", "test", false).is_ok());
        assert!(validate_hex("0123456789abcdef", "test", false).is_ok());
    }

    #[test]
    fn test_validate_hex_invalid() {
        assert!(validate_hex("", "test", false).is_err()); // empty not allowed
        assert!(validate_hex("deadbeefg", "test", false).is_err()); // 'g' not hex
        assert!(validate_hex("abc", "test", false).is_err()); // odd length
    }

    #[test]
    fn test_validate_path_valid() {
        assert!(validate_path("file.txt", "test").is_ok());
        assert!(validate_path("dir/file.txt", "test").is_ok());
        assert!(validate_path("/absolute/path", "test").is_ok());
    }

    #[test]
    fn test_validate_path_traversal() {
        assert!(validate_path("../etc/passwd", "test").is_err());
        assert!(validate_path("/etc/../passwd", "test").is_err());
        assert!(validate_path("~/.ssh/id_rsa", "test").is_err());
    }

    #[test]
    fn test_check_shell_safe() {
        assert!(check_shell_safe("normal input", "test").is_ok());
        assert!(check_shell_safe("input with numbers 123", "test").is_ok());

        assert!(check_shell_safe("input;injection", "test").is_err());
        assert!(check_shell_safe("input|pipe", "test").is_err());
        assert!(check_shell_safe("$(subcommand)", "test").is_err());
        assert!(check_shell_safe("`backtick`", "test").is_err());
    }

    #[test]
    fn test_sanitize_interactive_input() {
        assert!(sanitize_interactive_input("").unwrap().is_empty());
        assert!(sanitize_interactive_input("  normal  command  ").is_ok());
        assert_eq!(
            sanitize_interactive_input("  spaced   input  ").unwrap(),
            "spaced input"
        );

        assert!(sanitize_interactive_input("command;evil").is_err());
        assert!(sanitize_interactive_input("command|pipe").is_err());
        assert!(sanitize_interactive_input("$(injection)").is_err());
    }

    #[test]
    fn test_validate_actor_type() {
        assert!(validate_actor_type("human_actor").is_ok());
        assert!(validate_actor_type("ai_actor").is_ok());
        assert!(validate_actor_type("node_actor").is_ok());
        assert!(validate_actor_type("group_actor").is_ok());
        assert!(validate_actor_type("invalid_type").is_err());
    }

    #[test]
    fn test_validate_chain_type() {
        assert!(validate_chain_type("ethereum").is_ok());
        assert!(validate_chain_type("bitcoin").is_ok());
        assert!(validate_chain_type("internal").is_ok());
        assert!(validate_chain_type("invalid_chain").is_err());
    }

    #[test]
    fn test_validate_url() {
        assert!(validate_url("http://localhost:3000", "test").is_ok());
        assert!(validate_url("https://api.example.com/v1", "test").is_ok());
        assert!(validate_url("mem://", "test").is_ok());
        assert!(validate_url("file:///tmp/db", "test").is_ok());

        assert!(validate_url("", "test").is_err());
        assert!(validate_url("not-a-url", "test").is_err());
    }

    #[test]
    fn test_shell_escape() {
        assert_eq!(shell_escape("simple"), "'simple'");
        assert_eq!(shell_escape("with space"), "'with space'");
        assert_eq!(shell_escape("it's"), "'it'\\''s'");
    }

    #[test]
    fn test_build_safe_command() {
        let result = build_safe_command("l0", &[
            "--db-url".to_string(),
            "mem://".to_string(),
            "status".to_string(),
        ]);
        assert!(result.is_ok());

        // Invalid program name
        let result = build_safe_command("l0;rm", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_commitment_input_validation() {
        let valid = CommitmentInput {
            actor_id: "actor_001",
            scope_type: "akn_batch",
            data_hex: Some("deadbeef"),
        };
        assert!(validate_commitment_input(&valid).is_ok());

        let invalid = CommitmentInput {
            actor_id: "actor;evil",
            scope_type: "akn_batch",
            data_hex: None,
        };
        assert!(validate_commitment_input(&invalid).is_err());
    }

    #[test]
    fn test_input_length_limits() {
        // ID length limit
        let long_id = "a".repeat(257);
        assert!(validate_id(&long_id, "test").is_err());

        // Hex length limit
        let long_hex = "a".repeat(131074);
        assert!(validate_hex(&long_hex, "test", true).is_err());

        // URL length limit
        let long_url = format!("http://example.com/{}", "a".repeat(3000));
        assert!(validate_url(&long_url, "test").is_err());

        // Interactive input limit
        let long_input = "a ".repeat(3000);
        assert!(sanitize_interactive_input(&long_input).is_err());
    }
}
