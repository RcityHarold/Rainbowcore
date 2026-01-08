//! Logging Standards and Conventions
//!
//! This module defines logging conventions for the Rainbowcore protocol.
//! All modules should follow these standards for consistent log output.
//!
//! # Log Levels
//!
//! | Level | Usage | Examples |
//! |-------|-------|----------|
//! | ERROR | Unrecoverable errors, data corruption | Storage failure, integrity violation |
//! | WARN  | Recoverable issues, degraded operation | Retry needed, threshold exceeded |
//! | INFO  | Significant state changes, operations | Sync complete, migration done |
//! | DEBUG | Detailed operation flow | Function entry/exit, intermediate states |
//! | TRACE | Fine-grained debugging | All parameters, full payloads |
//!
//! # Structured Logging Fields
//!
//! Always use structured fields for key information:
//! - `ref_id`: Payload reference ID
//! - `actor_id`: Actor identifier
//! - `operation`: Operation name
//! - `duration_ms`: Operation duration
//! - `error`: Error message
//! - `count`: Item count
//! - `size`: Size in bytes
//!
//! # Examples
//!
//! ```ignore
//! use tracing::{info, warn, error, debug, instrument};
//!
//! // Good: Structured logging with context
//! info!(
//!     ref_id = %payload_ref,
//!     operation = "write",
//!     size = data.len(),
//!     duration_ms = elapsed.as_millis(),
//!     "Payload written successfully"
//! );
//!
//! // Good: Error with context
//! error!(
//!     ref_id = %payload_ref,
//!     error = %e,
//!     "Failed to write payload"
//! );
//!
//! // Bad: Unstructured logging
//! info!("Wrote payload {} with size {}", payload_ref, data.len());
//! ```

use serde::{Deserialize, Serialize};

/// Log level enumeration matching tracing levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Unrecoverable errors
    Error,
    /// Recoverable warnings
    Warn,
    /// Significant events
    Info,
    /// Detailed debugging
    Debug,
    /// Fine-grained tracing
    Trace,
}

impl LogLevel {
    /// Get the string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }

    /// Parse from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "error" => Some(Self::Error),
            "warn" | "warning" => Some(Self::Warn),
            "info" => Some(Self::Info),
            "debug" => Some(Self::Debug),
            "trace" => Some(Self::Trace),
            _ => None,
        }
    }

    /// Check if this level is enabled for the given max level
    pub fn is_enabled(&self, max_level: LogLevel) -> bool {
        self.priority() <= max_level.priority()
    }

    fn priority(&self) -> u8 {
        match self {
            Self::Error => 0,
            Self::Warn => 1,
            Self::Info => 2,
            Self::Debug => 3,
            Self::Trace => 4,
        }
    }
}

impl Default for LogLevel {
    fn default() -> Self {
        Self::Info
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Standard log field names
pub mod fields {
    /// Payload reference ID
    pub const REF_ID: &str = "ref_id";
    /// Actor identifier
    pub const ACTOR_ID: &str = "actor_id";
    /// Operation name
    pub const OPERATION: &str = "operation";
    /// Duration in milliseconds
    pub const DURATION_MS: &str = "duration_ms";
    /// Error message
    pub const ERROR: &str = "error";
    /// Item count
    pub const COUNT: &str = "count";
    /// Size in bytes
    pub const SIZE: &str = "size";
    /// Batch ID
    pub const BATCH_ID: &str = "batch_id";
    /// Sync ID
    pub const SYNC_ID: &str = "sync_id";
    /// Node ID
    pub const NODE_ID: &str = "node_id";
    /// Region
    pub const REGION: &str = "region";
    /// Status
    pub const STATUS: &str = "status";
    /// Level (evidence, etc.)
    pub const LEVEL: &str = "level";
    /// Temperature tier
    pub const TEMPERATURE: &str = "temperature";
    /// Checksum
    pub const CHECKSUM: &str = "checksum";
    /// Request ID
    pub const REQUEST_ID: &str = "request_id";
    /// Ticket ID
    pub const TICKET_ID: &str = "ticket_id";
    /// Case ID
    pub const CASE_ID: &str = "case_id";
}

/// Log operation categories for consistent naming
pub mod operations {
    // Storage operations
    pub const WRITE: &str = "write";
    pub const READ: &str = "read";
    pub const DELETE: &str = "delete";
    pub const TOMBSTONE: &str = "tombstone";

    // Sync operations
    pub const SYNC_START: &str = "sync_start";
    pub const SYNC_COMPLETE: &str = "sync_complete";
    pub const SYNC_FAILED: &str = "sync_failed";

    // Replication operations
    pub const REPLICATE: &str = "replicate";
    pub const REPLICATE_BATCH: &str = "replicate_batch";

    // Migration operations
    pub const MIGRATE: &str = "migrate";
    pub const PREHEAT: &str = "preheat";

    // Verification operations
    pub const VERIFY: &str = "verify";
    pub const INTEGRITY_CHECK: &str = "integrity_check";
    pub const SAMPLE: &str = "sample";

    // Access operations
    pub const TICKET_CREATE: &str = "ticket_create";
    pub const TICKET_VALIDATE: &str = "ticket_validate";
    pub const TICKET_REVOKE: &str = "ticket_revoke";
    pub const ACCESS_GRANT: &str = "access_grant";
    pub const ACCESS_DENY: &str = "access_deny";

    // Evidence operations
    pub const EVIDENCE_CREATE: &str = "evidence_create";
    pub const EVIDENCE_EXPORT: &str = "evidence_export";

    // Anchor operations
    pub const ANCHOR_SUBMIT: &str = "anchor_submit";
    pub const ANCHOR_CONFIRM: &str = "anchor_confirm";

    // Backfill operations
    pub const BACKFILL_START: &str = "backfill_start";
    pub const BACKFILL_COMPLETE: &str = "backfill_complete";

    // Health operations
    pub const HEALTH_CHECK: &str = "health_check";
    pub const FAILOVER: &str = "failover";
    pub const RECOVERY: &str = "recovery";
}

/// Logging guidelines for specific scenarios
pub mod guidelines {
    //! # When to use each level
    //!
    //! ## ERROR
    //! - Data corruption detected
    //! - Unrecoverable storage failure
    //! - Security violations (unauthorized access)
    //! - Protocol invariant violations
    //! - Must-open trigger conditions
    //!
    //! ## WARN
    //! - Operation retry needed
    //! - Approaching resource limits
    //! - Degraded mode entered
    //! - Slow operations (exceeding SLA)
    //! - Evidence level downgrade
    //! - Failed verification (non-critical)
    //!
    //! ## INFO
    //! - Operation completed successfully
    //! - State transitions (sync phases)
    //! - Configuration changes
    //! - Node join/leave
    //! - Scheduled tasks executed
    //! - Metrics collection points
    //!
    //! ## DEBUG
    //! - Operation parameters
    //! - Intermediate states
    //! - Cache hits/misses
    //! - Routing decisions
    //! - Filter results
    //!
    //! ## TRACE
    //! - Full request/response bodies
    //! - Binary data (hex encoded)
    //! - All function parameters
    //! - Detailed algorithm steps

    /// Maximum message length before truncation
    pub const MAX_MESSAGE_LENGTH: usize = 1000;

    /// Maximum binary data to log (hex encoded)
    pub const MAX_BINARY_LOG_BYTES: usize = 256;
}

/// Context for structured logging
#[derive(Debug, Clone, Default)]
pub struct LogContext {
    /// Request ID for tracing
    pub request_id: Option<String>,
    /// Actor ID
    pub actor_id: Option<String>,
    /// Operation name
    pub operation: Option<String>,
    /// Additional tags
    pub tags: Vec<(String, String)>,
}

impl LogContext {
    /// Create a new context
    pub fn new() -> Self {
        Self::default()
    }

    /// Set request ID
    pub fn with_request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }

    /// Set actor ID
    pub fn with_actor_id(mut self, id: impl Into<String>) -> Self {
        self.actor_id = Some(id.into());
        self
    }

    /// Set operation
    pub fn with_operation(mut self, op: impl Into<String>) -> Self {
        self.operation = Some(op.into());
        self
    }

    /// Add a tag
    pub fn with_tag(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.tags.push((key.into(), value.into()));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_parsing() {
        assert_eq!(LogLevel::from_str("error"), Some(LogLevel::Error));
        assert_eq!(LogLevel::from_str("INFO"), Some(LogLevel::Info));
        assert_eq!(LogLevel::from_str("warning"), Some(LogLevel::Warn));
        assert_eq!(LogLevel::from_str("invalid"), None);
    }

    #[test]
    fn test_log_level_enabled() {
        assert!(LogLevel::Error.is_enabled(LogLevel::Info));
        assert!(LogLevel::Info.is_enabled(LogLevel::Info));
        assert!(!LogLevel::Debug.is_enabled(LogLevel::Info));
    }

    #[test]
    fn test_log_context() {
        let ctx = LogContext::new()
            .with_request_id("req-123")
            .with_actor_id("actor-456")
            .with_operation("write")
            .with_tag("ref_id", "ref-789");

        assert_eq!(ctx.request_id, Some("req-123".to_string()));
        assert_eq!(ctx.actor_id, Some("actor-456".to_string()));
        assert_eq!(ctx.operation, Some("write".to_string()));
        assert_eq!(ctx.tags.len(), 1);
    }
}
