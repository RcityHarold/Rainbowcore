//! Structured Logging
//!
//! Provides structured logging with JSON output for production
//! and pretty-printed output for development.

use serde::{Deserialize, Serialize};
use std::io;
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    prelude::*,
    EnvFilter,
};

/// Log level
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl Default for LogLevel {
    fn default() -> Self {
        Self::Info
    }
}

impl From<LogLevel> for tracing::Level {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Trace => tracing::Level::TRACE,
            LogLevel::Debug => tracing::Level::DEBUG,
            LogLevel::Info => tracing::Level::INFO,
            LogLevel::Warn => tracing::Level::WARN,
            LogLevel::Error => tracing::Level::ERROR,
        }
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Trace => write!(f, "trace"),
            LogLevel::Debug => write!(f, "debug"),
            LogLevel::Info => write!(f, "info"),
            LogLevel::Warn => write!(f, "warn"),
            LogLevel::Error => write!(f, "error"),
        }
    }
}

/// Log format
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Pretty-printed for development
    Pretty,
    /// JSON for production
    Json,
    /// Compact single-line
    Compact,
}

impl Default for LogFormat {
    fn default() -> Self {
        Self::Pretty
    }
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// Log level
    pub level: LogLevel,
    /// Log format
    pub format: LogFormat,
    /// Include source file/line
    pub include_source: bool,
    /// Include thread ID
    pub include_thread_id: bool,
    /// Include span events
    pub include_span_events: bool,
    /// Environment filter string (e.g., "p2_storage=debug,tower=warn")
    pub filter: Option<String>,
    /// Log file path (if None, logs to stdout)
    pub file_path: Option<String>,
    /// Service name for log context
    pub service_name: String,
    /// Additional context fields
    pub context: std::collections::HashMap<String, String>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Pretty,
            include_source: true,
            include_thread_id: false,
            include_span_events: false,
            filter: None,
            file_path: None,
            service_name: "p2-storage".to_string(),
            context: std::collections::HashMap::new(),
        }
    }
}

impl LogConfig {
    /// Create a production-ready configuration
    pub fn production() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Json,
            include_source: false,
            include_thread_id: true,
            include_span_events: true,
            filter: None,
            file_path: None,
            service_name: "p2-storage".to_string(),
            context: std::collections::HashMap::new(),
        }
    }

    /// Create a development configuration
    pub fn development() -> Self {
        Self {
            level: LogLevel::Debug,
            format: LogFormat::Pretty,
            include_source: true,
            include_thread_id: false,
            include_span_events: false,
            filter: None,
            file_path: None,
            service_name: "p2-storage".to_string(),
            context: std::collections::HashMap::new(),
        }
    }

    /// Set service name
    pub fn with_service_name(mut self, name: &str) -> Self {
        self.service_name = name.to_string();
        self
    }

    /// Add context field
    pub fn with_context(mut self, key: &str, value: &str) -> Self {
        self.context.insert(key.to_string(), value.to_string());
        self
    }
}

/// Initialize logging with the given configuration
pub fn init_logging(config: &LogConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let filter = match &config.filter {
        Some(f) => EnvFilter::try_new(f)?,
        None => EnvFilter::try_new(format!(
            "{}={}",
            config.service_name.replace('-', "_"),
            config.level
        ))?,
    };

    let span_events = if config.include_span_events {
        FmtSpan::NEW | FmtSpan::CLOSE
    } else {
        FmtSpan::NONE
    };

    match config.format {
        LogFormat::Json => {
            let subscriber = tracing_subscriber::registry()
                .with(filter)
                .with(
                    fmt::layer()
                        .json()
                        .with_span_events(span_events)
                        .with_thread_ids(config.include_thread_id)
                        .with_file(config.include_source)
                        .with_line_number(config.include_source),
                );
            tracing::subscriber::set_global_default(subscriber)?;
        }
        LogFormat::Pretty => {
            let subscriber = tracing_subscriber::registry()
                .with(filter)
                .with(
                    fmt::layer()
                        .pretty()
                        .with_span_events(span_events)
                        .with_thread_ids(config.include_thread_id)
                        .with_file(config.include_source)
                        .with_line_number(config.include_source),
                );
            tracing::subscriber::set_global_default(subscriber)?;
        }
        LogFormat::Compact => {
            let subscriber = tracing_subscriber::registry()
                .with(filter)
                .with(
                    fmt::layer()
                        .compact()
                        .with_span_events(span_events)
                        .with_thread_ids(config.include_thread_id)
                        .with_file(config.include_source)
                        .with_line_number(config.include_source),
                );
            tracing::subscriber::set_global_default(subscriber)?;
        }
    }

    Ok(())
}

/// Structured log event builder
#[derive(Debug, Clone)]
pub struct LogEvent {
    pub level: LogLevel,
    pub message: String,
    pub fields: std::collections::HashMap<String, serde_json::Value>,
}

impl LogEvent {
    pub fn new(level: LogLevel, message: impl Into<String>) -> Self {
        Self {
            level,
            message: message.into(),
            fields: std::collections::HashMap::new(),
        }
    }

    pub fn info(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Info, message)
    }

    pub fn warn(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Warn, message)
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Error, message)
    }

    pub fn debug(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Debug, message)
    }

    pub fn field<V: Serialize>(mut self, key: &str, value: V) -> Self {
        if let Ok(v) = serde_json::to_value(value) {
            self.fields.insert(key.to_string(), v);
        }
        self
    }

    pub fn emit(&self) {
        match self.level {
            LogLevel::Trace => tracing::trace!(fields = ?self.fields, "{}", self.message),
            LogLevel::Debug => tracing::debug!(fields = ?self.fields, "{}", self.message),
            LogLevel::Info => tracing::info!(fields = ?self.fields, "{}", self.message),
            LogLevel::Warn => tracing::warn!(fields = ?self.fields, "{}", self.message),
            LogLevel::Error => tracing::error!(fields = ?self.fields, "{}", self.message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_config_default() {
        let config = LogConfig::default();
        assert_eq!(config.level, LogLevel::Info);
        assert_eq!(config.format, LogFormat::Pretty);
    }

    #[test]
    fn test_log_config_production() {
        let config = LogConfig::production();
        assert_eq!(config.format, LogFormat::Json);
        assert!(config.include_thread_id);
    }

    #[test]
    fn test_log_event_builder() {
        let event = LogEvent::info("Test message")
            .field("ref_id", "test:001")
            .field("duration_ms", 100);

        assert_eq!(event.level, LogLevel::Info);
        assert_eq!(event.message, "Test message");
        assert!(event.fields.contains_key("ref_id"));
    }
}
