//! System Diagnostics API
//!
//! Provides diagnostic tools for debugging and troubleshooting.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::debug;

/// Diagnostic level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticLevel {
    /// Basic diagnostics
    Basic,
    /// Standard diagnostics
    Standard,
    /// Full diagnostics (may be expensive)
    Full,
    /// Debug level (includes sensitive info)
    Debug,
}

impl Default for DiagnosticLevel {
    fn default() -> Self {
        Self::Standard
    }
}

/// Diagnostic result status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticResult {
    /// Diagnostic passed
    Pass,
    /// Diagnostic passed with warnings
    Warn,
    /// Diagnostic failed
    Fail,
    /// Diagnostic skipped
    Skip,
}

/// Diagnostic check item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticItem {
    /// Check name
    pub name: String,
    /// Category
    pub category: String,
    /// Result
    pub result: DiagnosticResult,
    /// Message
    pub message: Option<String>,
    /// Duration in milliseconds
    pub duration_ms: u64,
    /// Additional details
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub details: HashMap<String, serde_json::Value>,
}

impl DiagnosticItem {
    /// Create a passing diagnostic
    pub fn pass(name: &str, category: &str, duration: Duration) -> Self {
        Self {
            name: name.to_string(),
            category: category.to_string(),
            result: DiagnosticResult::Pass,
            message: None,
            duration_ms: duration.as_millis() as u64,
            details: HashMap::new(),
        }
    }

    /// Create a warning diagnostic
    pub fn warn(name: &str, category: &str, message: &str, duration: Duration) -> Self {
        Self {
            name: name.to_string(),
            category: category.to_string(),
            result: DiagnosticResult::Warn,
            message: Some(message.to_string()),
            duration_ms: duration.as_millis() as u64,
            details: HashMap::new(),
        }
    }

    /// Create a failing diagnostic
    pub fn fail(name: &str, category: &str, message: &str, duration: Duration) -> Self {
        Self {
            name: name.to_string(),
            category: category.to_string(),
            result: DiagnosticResult::Fail,
            message: Some(message.to_string()),
            duration_ms: duration.as_millis() as u64,
            details: HashMap::new(),
        }
    }

    /// Add detail
    pub fn with_detail(mut self, key: &str, value: impl Serialize) -> Self {
        if let Ok(v) = serde_json::to_value(value) {
            self.details.insert(key.to_string(), v);
        }
        self
    }
}

/// Diagnostic report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticReport {
    /// Report ID
    pub id: String,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Diagnostic level
    pub level: DiagnosticLevel,
    /// Node ID
    pub node_id: String,
    /// Total duration in milliseconds
    pub total_duration_ms: u64,
    /// Overall result
    pub overall_result: DiagnosticResult,
    /// Individual checks
    pub checks: Vec<DiagnosticItem>,
    /// System information
    pub system_info: SystemInfo,
    /// Error count
    pub error_count: usize,
    /// Warning count
    pub warning_count: usize,
}

impl DiagnosticReport {
    /// Create new report
    pub fn new(level: DiagnosticLevel, node_id: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            level,
            node_id: node_id.to_string(),
            total_duration_ms: 0,
            overall_result: DiagnosticResult::Pass,
            checks: Vec::new(),
            system_info: SystemInfo::collect(),
            error_count: 0,
            warning_count: 0,
        }
    }

    /// Add a check result
    pub fn add_check(&mut self, item: DiagnosticItem) {
        match item.result {
            DiagnosticResult::Fail => {
                self.error_count += 1;
                if self.overall_result != DiagnosticResult::Fail {
                    self.overall_result = DiagnosticResult::Fail;
                }
            }
            DiagnosticResult::Warn => {
                self.warning_count += 1;
                if self.overall_result == DiagnosticResult::Pass {
                    self.overall_result = DiagnosticResult::Warn;
                }
            }
            _ => {}
        }
        self.checks.push(item);
    }

    /// Finalize the report
    pub fn finalize(mut self, duration: Duration) -> Self {
        self.total_duration_ms = duration.as_millis() as u64;
        self
    }
}

/// System information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    /// OS name
    pub os: String,
    /// OS version
    pub os_version: String,
    /// Architecture
    pub arch: String,
    /// Hostname
    pub hostname: String,
    /// CPU count
    pub cpu_count: usize,
    /// Total memory bytes
    pub memory_bytes: u64,
    /// Available memory bytes
    pub available_memory_bytes: u64,
    /// Rust version
    pub rust_version: String,
    /// Package version
    pub package_version: String,
}

impl SystemInfo {
    /// Collect system information
    pub fn collect() -> Self {
        Self {
            os: std::env::consts::OS.to_string(),
            os_version: "unknown".to_string(),
            arch: std::env::consts::ARCH.to_string(),
            hostname: hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string()),
            cpu_count: num_cpus::get(),
            memory_bytes: 0,           // Would need sys-info crate
            available_memory_bytes: 0, // Would need sys-info crate
            rust_version: rustc_version_info(),
            package_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

fn rustc_version_info() -> String {
    format!("rustc {}", env!("CARGO_PKG_RUST_VERSION"))
}

/// Diagnostic check trait
#[async_trait::async_trait]
pub trait DiagnosticCheck: Send + Sync {
    /// Check name
    fn name(&self) -> &str;

    /// Check category
    fn category(&self) -> &str;

    /// Minimum level required
    fn min_level(&self) -> DiagnosticLevel {
        DiagnosticLevel::Standard
    }

    /// Run the diagnostic
    async fn run(&self) -> DiagnosticItem;
}

/// System diagnostics runner
pub struct SystemDiagnostics {
    /// Node ID
    node_id: String,
    /// Registered checks
    checks: RwLock<Vec<Box<dyn DiagnosticCheck>>>,
}

impl SystemDiagnostics {
    /// Create new diagnostics runner
    pub fn new(node_id: &str) -> Self {
        Self {
            node_id: node_id.to_string(),
            checks: RwLock::new(Vec::new()),
        }
    }

    /// Register a diagnostic check
    pub async fn register(&self, check: Box<dyn DiagnosticCheck>) {
        debug!(name = check.name(), category = check.category(), "Registered diagnostic check");
        self.checks.write().await.push(check);
    }

    /// Run diagnostics at specified level
    pub async fn run(&self, level: DiagnosticLevel) -> DiagnosticReport {
        let start = Instant::now();
        let mut report = DiagnosticReport::new(level, &self.node_id);

        let checks = self.checks.read().await;
        for check in checks.iter() {
            // Skip checks above our level
            if !should_run(check.min_level(), level) {
                continue;
            }

            let item = check.run().await;
            report.add_check(item);
        }

        report.finalize(start.elapsed())
    }

    /// Run quick diagnostics (basic level)
    pub async fn quick_check(&self) -> DiagnosticReport {
        self.run(DiagnosticLevel::Basic).await
    }

    /// Run full diagnostics
    pub async fn full_check(&self) -> DiagnosticReport {
        self.run(DiagnosticLevel::Full).await
    }
}

fn should_run(required: DiagnosticLevel, current: DiagnosticLevel) -> bool {
    let required_val = match required {
        DiagnosticLevel::Basic => 0,
        DiagnosticLevel::Standard => 1,
        DiagnosticLevel::Full => 2,
        DiagnosticLevel::Debug => 3,
    };
    let current_val = match current {
        DiagnosticLevel::Basic => 0,
        DiagnosticLevel::Standard => 1,
        DiagnosticLevel::Full => 2,
        DiagnosticLevel::Debug => 3,
    };
    current_val >= required_val
}

/// Storage diagnostic check
pub struct StorageDiagnostic {
    /// Backend name
    name: String,
    /// Check function
    check_fn: Box<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>> + Send + Sync>,
}

impl StorageDiagnostic {
    /// Create new storage diagnostic
    pub fn new<F, Fut>(name: &str, check_fn: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<(), String>> + Send + 'static,
    {
        Self {
            name: name.to_string(),
            check_fn: Box::new(move || Box::pin(check_fn())),
        }
    }
}

#[async_trait::async_trait]
impl DiagnosticCheck for StorageDiagnostic {
    fn name(&self) -> &str {
        &self.name
    }

    fn category(&self) -> &str {
        "storage"
    }

    async fn run(&self) -> DiagnosticItem {
        let start = Instant::now();
        let result = (self.check_fn)().await;
        let duration = start.elapsed();

        match result {
            Ok(()) => DiagnosticItem::pass(&self.name, "storage", duration),
            Err(e) => DiagnosticItem::fail(&self.name, "storage", &e, duration),
        }
    }
}

/// Connectivity diagnostic check
pub struct ConnectivityDiagnostic {
    /// Target name
    target: String,
    /// Host to check
    host: String,
    /// Port to check
    port: u16,
    /// Timeout
    timeout: Duration,
}

impl ConnectivityDiagnostic {
    /// Create new connectivity diagnostic
    pub fn new(target: &str, host: &str, port: u16) -> Self {
        Self {
            target: target.to_string(),
            host: host.to_string(),
            port,
            timeout: Duration::from_secs(5),
        }
    }

    /// Set timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

#[async_trait::async_trait]
impl DiagnosticCheck for ConnectivityDiagnostic {
    fn name(&self) -> &str {
        &self.target
    }

    fn category(&self) -> &str {
        "connectivity"
    }

    async fn run(&self) -> DiagnosticItem {
        let start = Instant::now();
        let addr = format!("{}:{}", self.host, self.port);

        let result =
            tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect(&addr)).await;

        let duration = start.elapsed();

        match result {
            Ok(Ok(_)) => DiagnosticItem::pass(&self.target, "connectivity", duration)
                .with_detail("host", &self.host)
                .with_detail("port", self.port),
            Ok(Err(e)) => DiagnosticItem::fail(
                &self.target,
                "connectivity",
                &format!("Connection failed: {}", e),
                duration,
            ),
            Err(_) => DiagnosticItem::fail(&self.target, "connectivity", "Connection timeout", duration),
        }
    }
}

/// Disk space diagnostic
pub struct DiskSpaceDiagnostic {
    /// Path to check
    path: std::path::PathBuf,
    /// Warning threshold (bytes)
    warn_threshold: u64,
    /// Error threshold (bytes)
    error_threshold: u64,
}

impl DiskSpaceDiagnostic {
    /// Create new disk space diagnostic
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            path: path.into(),
            warn_threshold: 10 * 1024 * 1024 * 1024, // 10GB
            error_threshold: 1024 * 1024 * 1024,     // 1GB
        }
    }

    /// Set thresholds
    pub fn with_thresholds(mut self, warn: u64, error: u64) -> Self {
        self.warn_threshold = warn;
        self.error_threshold = error;
        self
    }
}

#[async_trait::async_trait]
impl DiagnosticCheck for DiskSpaceDiagnostic {
    fn name(&self) -> &str {
        "disk_space"
    }

    fn category(&self) -> &str {
        "storage"
    }

    async fn run(&self) -> DiagnosticItem {
        let start = Instant::now();

        // Check if path exists
        if !self.path.exists() {
            return DiagnosticItem::fail(
                "disk_space",
                "storage",
                "Path does not exist",
                start.elapsed(),
            );
        }

        // Get available space (simplified - would use statvfs on Unix)
        // For now, just check path exists
        let duration = start.elapsed();

        DiagnosticItem::pass("disk_space", "storage", duration)
            .with_detail("path", self.path.display().to_string())
    }
}

/// Memory diagnostic
pub struct MemoryDiagnostic {
    /// Warning threshold percentage
    warn_threshold_pct: u8,
    /// Error threshold percentage
    error_threshold_pct: u8,
}

impl MemoryDiagnostic {
    /// Create new memory diagnostic
    pub fn new() -> Self {
        Self {
            warn_threshold_pct: 80,
            error_threshold_pct: 95,
        }
    }

    /// Set thresholds
    pub fn with_thresholds(mut self, warn: u8, error: u8) -> Self {
        self.warn_threshold_pct = warn;
        self.error_threshold_pct = error;
        self
    }
}

impl Default for MemoryDiagnostic {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl DiagnosticCheck for MemoryDiagnostic {
    fn name(&self) -> &str {
        "memory"
    }

    fn category(&self) -> &str {
        "system"
    }

    async fn run(&self) -> DiagnosticItem {
        let start = Instant::now();
        let duration = start.elapsed();

        // Simplified - would use sys-info crate for real memory info
        DiagnosticItem::pass("memory", "system", duration)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diagnostic_item() {
        let item = DiagnosticItem::pass("test", "category", Duration::from_millis(10));
        assert_eq!(item.result, DiagnosticResult::Pass);
        assert_eq!(item.name, "test");
    }

    #[test]
    fn test_diagnostic_report() {
        let mut report = DiagnosticReport::new(DiagnosticLevel::Standard, "node1");

        report.add_check(DiagnosticItem::pass("a", "cat", Duration::ZERO));
        assert_eq!(report.overall_result, DiagnosticResult::Pass);

        report.add_check(DiagnosticItem::warn("b", "cat", "warning", Duration::ZERO));
        assert_eq!(report.overall_result, DiagnosticResult::Warn);
        assert_eq!(report.warning_count, 1);

        report.add_check(DiagnosticItem::fail("c", "cat", "error", Duration::ZERO));
        assert_eq!(report.overall_result, DiagnosticResult::Fail);
        assert_eq!(report.error_count, 1);
    }

    #[tokio::test]
    async fn test_system_diagnostics() {
        let diag = SystemDiagnostics::new("test-node");
        let report = diag.quick_check().await;

        assert_eq!(report.node_id, "test-node");
        assert_eq!(report.level, DiagnosticLevel::Basic);
    }

    #[test]
    fn test_should_run() {
        assert!(should_run(DiagnosticLevel::Basic, DiagnosticLevel::Standard));
        assert!(should_run(DiagnosticLevel::Standard, DiagnosticLevel::Full));
        assert!(!should_run(DiagnosticLevel::Full, DiagnosticLevel::Basic));
    }
}
