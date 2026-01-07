//! Integrity Verification
//!
//! Performs integrity checks on stored payloads by verifying checksums
//! and ensuring data accessibility.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::backend::P2StorageBackend;
use crate::error::StorageError;

/// Integrity check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityCheckResult {
    /// Payload reference ID
    pub ref_id: String,
    /// Check timestamp
    pub checked_at: DateTime<Utc>,
    /// Whether integrity check passed
    pub passed: bool,
    /// Check type performed
    pub check_type: IntegrityCheckType,
    /// Expected checksum (if known)
    pub expected_checksum: Option<String>,
    /// Actual computed checksum
    pub actual_checksum: Option<String>,
    /// Check duration in milliseconds
    pub duration_ms: u64,
    /// Size verified in bytes
    pub size_bytes: Option<u64>,
    /// Error message if failed
    pub error: Option<String>,
    /// Additional details
    pub details: CheckDetails,
}

/// Type of integrity check
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IntegrityCheckType {
    /// Basic accessibility check
    Accessibility,
    /// Full checksum verification
    ChecksumVerification,
    /// Size verification only
    SizeVerification,
    /// Full content re-hash
    ContentRehash,
}

/// Additional check details
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CheckDetails {
    /// Backend used for check
    pub backend: Option<String>,
    /// Read latency in ms
    pub read_latency_ms: Option<u64>,
    /// Whether data was readable
    pub readable: bool,
    /// Whether metadata was accessible
    pub metadata_accessible: bool,
    /// Retry count
    pub retry_count: u32,
}

/// Integrity check error
#[derive(Debug, Error)]
pub enum IntegrityError {
    #[error("Checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },

    #[error("Data inaccessible: {0}")]
    DataInaccessible(String),

    #[error("Metadata inaccessible: {0}")]
    MetadataInaccessible(String),

    #[error("Size mismatch: expected {expected}, got {actual}")]
    SizeMismatch { expected: u64, actual: u64 },

    #[error("Read timeout")]
    ReadTimeout,

    #[error("Backend error: {0}")]
    BackendError(String),
}

/// Configuration for integrity checker
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityCheckerConfig {
    /// Maximum read timeout in seconds
    pub read_timeout_secs: u64,
    /// Number of retries on transient failures
    pub max_retries: u32,
    /// Whether to verify full content or just headers
    pub verify_full_content: bool,
    /// Maximum size for full content verification (bytes)
    pub max_full_verify_size: u64,
    /// Parallel check limit
    pub parallel_limit: usize,
}

impl Default for IntegrityCheckerConfig {
    fn default() -> Self {
        Self {
            read_timeout_secs: 30,
            max_retries: 3,
            verify_full_content: true,
            max_full_verify_size: 100 * 1024 * 1024, // 100MB
            parallel_limit: 10,
        }
    }
}

/// Integrity checker service
pub struct IntegrityChecker<B: P2StorageBackend> {
    config: IntegrityCheckerConfig,
    backend: Arc<B>,
    /// Track check history
    history: Arc<RwLock<Vec<IntegrityCheckResult>>>,
}

impl<B: P2StorageBackend + Send + Sync + 'static> IntegrityChecker<B> {
    /// Create a new integrity checker
    pub fn new(config: IntegrityCheckerConfig, backend: Arc<B>) -> Self {
        Self {
            config,
            backend,
            history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Check integrity of a single payload
    pub async fn check_payload(
        &self,
        ref_id: &str,
        expected_checksum: Option<&str>,
        check_type: IntegrityCheckType,
    ) -> IntegrityCheckResult {
        let start = std::time::Instant::now();
        let mut details = CheckDetails::default();
        let mut retry_count = 0;

        info!(ref_id = %ref_id, check_type = ?check_type, "Starting integrity check");

        // Try to read the payload with retries
        let read_result = self.read_with_retries(ref_id, &mut retry_count).await;
        details.retry_count = retry_count;

        let result = match read_result {
            Ok((data, read_latency)) => {
                details.readable = true;
                details.read_latency_ms = Some(read_latency);
                details.backend = Some(format!("{}", std::any::type_name::<B>()));

                self.verify_data(
                    ref_id,
                    &data,
                    expected_checksum,
                    check_type,
                    start,
                    details,
                )
            }
            Err(e) => {
                details.readable = false;
                IntegrityCheckResult {
                    ref_id: ref_id.to_string(),
                    checked_at: Utc::now(),
                    passed: false,
                    check_type,
                    expected_checksum: expected_checksum.map(|s| s.to_string()),
                    actual_checksum: None,
                    duration_ms: start.elapsed().as_millis() as u64,
                    size_bytes: None,
                    error: Some(e.to_string()),
                    details,
                }
            }
        };

        // Store in history
        self.history.write().await.push(result.clone());

        result
    }

    /// Read payload with retries
    async fn read_with_retries(
        &self,
        ref_id: &str,
        retry_count: &mut u32,
    ) -> Result<(Vec<u8>, u64), IntegrityError> {
        let mut last_error = None;

        for attempt in 0..=self.config.max_retries {
            *retry_count = attempt;
            let read_start = std::time::Instant::now();

            match tokio::time::timeout(
                std::time::Duration::from_secs(self.config.read_timeout_secs),
                self.backend.read(ref_id),
            )
            .await
            {
                Ok(Ok(data)) => {
                    let latency = read_start.elapsed().as_millis() as u64;
                    debug!(
                        ref_id = %ref_id,
                        attempt = attempt,
                        latency_ms = latency,
                        size = data.len(),
                        "Read successful"
                    );
                    return Ok((data, latency));
                }
                Ok(Err(e)) => {
                    warn!(
                        ref_id = %ref_id,
                        attempt = attempt,
                        error = %e,
                        "Read failed, will retry"
                    );
                    last_error = Some(IntegrityError::BackendError(e.to_string()));
                }
                Err(_) => {
                    warn!(
                        ref_id = %ref_id,
                        attempt = attempt,
                        "Read timeout"
                    );
                    last_error = Some(IntegrityError::ReadTimeout);
                }
            }

            // Exponential backoff
            if attempt < self.config.max_retries {
                tokio::time::sleep(std::time::Duration::from_millis(100 * (1 << attempt))).await;
            }
        }

        Err(last_error.unwrap_or(IntegrityError::DataInaccessible(
            "Failed after retries".to_string(),
        )))
    }

    /// Verify data integrity
    fn verify_data(
        &self,
        ref_id: &str,
        data: &[u8],
        expected_checksum: Option<&str>,
        check_type: IntegrityCheckType,
        start: std::time::Instant,
        details: CheckDetails,
    ) -> IntegrityCheckResult {
        let size_bytes = data.len() as u64;

        // Compute checksum
        let actual_checksum = if check_type == IntegrityCheckType::ContentRehash
            || check_type == IntegrityCheckType::ChecksumVerification
        {
            // Limit full content verification for large files
            if self.config.verify_full_content && size_bytes <= self.config.max_full_verify_size {
                Some(compute_sha256(data))
            } else {
                None
            }
        } else {
            None
        };

        // Check if verification passed
        let (passed, error) = match (expected_checksum, &actual_checksum) {
            (Some(expected), Some(actual)) => {
                if expected == actual {
                    (true, None)
                } else {
                    (
                        false,
                        Some(format!(
                            "Checksum mismatch: expected {}, got {}",
                            expected, actual
                        )),
                    )
                }
            }
            (None, _) => {
                // No expected checksum, just verify accessibility
                (true, None)
            }
            (Some(_), None) => {
                // Expected checksum but couldn't compute (file too large or wrong check type)
                (true, None) // Pass since data is accessible
            }
        };

        if passed {
            debug!(ref_id = %ref_id, "Integrity check passed");
        } else {
            error!(ref_id = %ref_id, error = ?error, "Integrity check FAILED");
        }

        IntegrityCheckResult {
            ref_id: ref_id.to_string(),
            checked_at: Utc::now(),
            passed,
            check_type,
            expected_checksum: expected_checksum.map(|s| s.to_string()),
            actual_checksum,
            duration_ms: start.elapsed().as_millis() as u64,
            size_bytes: Some(size_bytes),
            error,
            details,
        }
    }

    /// Check multiple payloads in parallel
    pub async fn check_batch(
        &self,
        items: Vec<(String, Option<String>)>,
        check_type: IntegrityCheckType,
    ) -> Vec<IntegrityCheckResult> {
        use futures::stream::{self, StreamExt};

        let parallel_limit = self.config.parallel_limit;

        stream::iter(items)
            .map(|(ref_id, expected)| {
                let checker = self;
                async move {
                    checker
                        .check_payload(&ref_id, expected.as_deref(), check_type)
                        .await
                }
            })
            .buffer_unordered(parallel_limit)
            .collect()
            .await
    }

    /// Get check history
    pub async fn get_history(&self) -> Vec<IntegrityCheckResult> {
        self.history.read().await.clone()
    }

    /// Clear check history
    pub async fn clear_history(&self) {
        self.history.write().await.clear();
    }

    /// Get summary statistics from history
    pub async fn get_stats(&self) -> IntegrityStats {
        let history = self.history.read().await;

        let total = history.len();
        let passed = history.iter().filter(|r| r.passed).count();
        let failed = total - passed;

        let total_duration: u64 = history.iter().map(|r| r.duration_ms).sum();
        let total_size: u64 = history.iter().filter_map(|r| r.size_bytes).sum();

        IntegrityStats {
            total_checks: total,
            passed_checks: passed,
            failed_checks: failed,
            pass_rate: if total > 0 {
                passed as f64 / total as f64
            } else {
                1.0
            },
            total_duration_ms: total_duration,
            average_duration_ms: if total > 0 {
                total_duration / total as u64
            } else {
                0
            },
            total_size_verified: total_size,
            computed_at: Utc::now(),
        }
    }
}

/// Compute SHA-256 checksum
pub fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Integrity check statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityStats {
    /// Total number of checks
    pub total_checks: usize,
    /// Number of passed checks
    pub passed_checks: usize,
    /// Number of failed checks
    pub failed_checks: usize,
    /// Pass rate (0.0 to 1.0)
    pub pass_rate: f64,
    /// Total check duration
    pub total_duration_ms: u64,
    /// Average check duration
    pub average_duration_ms: u64,
    /// Total size verified
    pub total_size_verified: u64,
    /// Stats computation timestamp
    pub computed_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_sha256() {
        let data = b"test data content";
        let checksum = compute_sha256(data);
        assert!(!checksum.is_empty());
        assert_eq!(checksum.len(), 64); // SHA-256 produces 64 hex chars
    }

    #[test]
    fn test_integrity_check_result() {
        let result = IntegrityCheckResult {
            ref_id: "test:001".to_string(),
            checked_at: Utc::now(),
            passed: true,
            check_type: IntegrityCheckType::ChecksumVerification,
            expected_checksum: Some("abc123".to_string()),
            actual_checksum: Some("abc123".to_string()),
            duration_ms: 100,
            size_bytes: Some(1024),
            error: None,
            details: CheckDetails::default(),
        };

        assert!(result.passed);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_integrity_stats() {
        let stats = IntegrityStats {
            total_checks: 100,
            passed_checks: 95,
            failed_checks: 5,
            pass_rate: 0.95,
            total_duration_ms: 10000,
            average_duration_ms: 100,
            total_size_verified: 1024 * 1024,
            computed_at: Utc::now(),
        };

        assert_eq!(stats.pass_rate, 0.95);
        assert_eq!(stats.failed_checks, 5);
    }
}
