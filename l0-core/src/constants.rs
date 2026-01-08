//! Protocol Constants
//!
//! Centralized constants for the Rainbowcore protocol.
//! All magic numbers, default values, and protocol-defined limits
//! should be defined here for consistency and maintainability.
//!
//! # Categories
//!
//! - **Version**: Protocol version strings
//! - **Limits**: Size limits, count limits
//! - **Timeouts**: Default timeout values
//! - **Thresholds**: Various threshold values
//! - **Defaults**: Default configuration values

// ============================================================================
// Protocol Versions
// ============================================================================

/// Current protocol version
pub const PROTOCOL_VERSION: &str = "1.0.0";

/// Canonicalization version for digest computation
pub const CANONICALIZATION_VERSION: &str = "v1";

/// Signer set version
pub const SIGNER_SET_VERSION: &str = "v1";

/// Anchor policy version
pub const ANCHOR_POLICY_VERSION: &str = "v1";

/// Fee schedule version
pub const FEE_SCHEDULE_VERSION: &str = "v1";

/// Map commit version
pub const MAP_COMMIT_VERSION: &str = "v1";

// ============================================================================
// Size Limits
// ============================================================================

/// Maximum payload size in bytes (100 MB)
pub const MAX_PAYLOAD_SIZE_BYTES: u64 = 100 * 1024 * 1024;

/// Maximum batch size (number of items)
pub const MAX_BATCH_SIZE: usize = 1000;

/// Maximum consent chain length
pub const MAX_CONSENT_CHAIN_LENGTH: usize = 100;

/// Maximum delegation depth
pub const MAX_DELEGATION_DEPTH: usize = 10;

/// Maximum selector items
pub const MAX_SELECTOR_ITEMS: usize = 100;

/// Maximum tags per payload
pub const MAX_PAYLOAD_TAGS: usize = 50;

/// Maximum tag key length
pub const MAX_TAG_KEY_LENGTH: usize = 64;

/// Maximum tag value length
pub const MAX_TAG_VALUE_LENGTH: usize = 256;

/// Maximum concurrent operations per actor
pub const MAX_CONCURRENT_OPERATIONS: usize = 100;

/// Digest length in bytes (SHA-256)
pub const DIGEST_LENGTH_BYTES: usize = 32;

/// Signature length in bytes (Ed25519)
pub const SIGNATURE_LENGTH_BYTES: usize = 64;

/// Public key length in bytes (Ed25519)
pub const PUBLIC_KEY_LENGTH_BYTES: usize = 32;

// ============================================================================
// Time Limits (in seconds unless specified)
// ============================================================================

/// Default request timeout (30 seconds)
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Default sync timeout (120 seconds)
pub const DEFAULT_SYNC_TIMEOUT_SECS: u64 = 120;

/// Default backfill timeout (300 seconds)
pub const DEFAULT_BACKFILL_TIMEOUT_SECS: u64 = 300;

/// Access ticket default validity (24 hours)
pub const DEFAULT_TICKET_VALIDITY_SECS: u64 = 24 * 60 * 60;

/// Maximum ticket validity (30 days)
pub const MAX_TICKET_VALIDITY_SECS: u64 = 30 * 24 * 60 * 60;

/// TipWitness staleness threshold (1 hour)
pub const TIP_WITNESS_STALENESS_SECS: u64 = 60 * 60;

/// Emergency override review deadline default (24 hours)
pub const EMERGENCY_REVIEW_DEADLINE_SECS: u64 = 24 * 60 * 60;

/// Snapshot interval (15 minutes)
pub const SNAPSHOT_INTERVAL_SECS: u64 = 15 * 60;

/// Epoch snapshot interval (1 hour)
pub const EPOCH_SNAPSHOT_INTERVAL_SECS: u64 = 60 * 60;

/// Replication sync timeout (100 milliseconds)
pub const REPLICATION_SYNC_TIMEOUT_MS: u64 = 100;

/// Replication async timeout (60 seconds)
pub const REPLICATION_ASYNC_TIMEOUT_SECS: u64 = 60;

// ============================================================================
// Performance Thresholds
// ============================================================================

/// Write latency target p99 (10 ms in microseconds)
pub const WRITE_LATENCY_TARGET_P99_US: u64 = 10_000;

/// Preheat latency target p99 (5 seconds in milliseconds)
pub const PREHEAT_LATENCY_TARGET_P99_MS: u64 = 5_000;

/// Three-phase sync latency target p99 (2 seconds in milliseconds)
pub const THREE_PHASE_SYNC_LATENCY_TARGET_P99_MS: u64 = 2_000;

/// Minimum concurrent connections target
pub const MIN_CONCURRENT_CONNECTIONS: usize = 1000;

/// Daily sampling rate (0.1%)
pub const DAILY_SAMPLING_RATE: f64 = 0.001;

// ============================================================================
// Replication Constants
// ============================================================================

/// Hot data minimum replication factor
pub const HOT_DATA_MIN_REPLICATION_FACTOR: u32 = 2;

/// Warm data minimum replication factor
pub const WARM_DATA_MIN_REPLICATION_FACTOR: u32 = 2;

/// Cold data minimum replication factor
pub const COLD_DATA_MIN_REPLICATION_FACTOR: u32 = 1;

/// Default replication batch size
pub const DEFAULT_REPLICATION_BATCH_SIZE: usize = 100;

// ============================================================================
// Anchor Constants
// ============================================================================

/// Anchor MUST priority max delay (seconds)
pub const ANCHOR_MUST_MAX_DELAY_SECS: u64 = 300; // 5 minutes

/// Anchor SHOULD priority max delay (seconds)
pub const ANCHOR_SHOULD_MAX_DELAY_SECS: u64 = 3600; // 1 hour

/// Anchor MAY priority max delay (seconds)
pub const ANCHOR_MAY_MAX_DELAY_SECS: u64 = 86400; // 24 hours

// ============================================================================
// Fee Constants
// ============================================================================

/// Base fee unit (in smallest currency unit)
pub const BASE_FEE_UNIT: u64 = 1;

/// Storage fee per byte per day
pub const STORAGE_FEE_PER_BYTE_DAY: u64 = 1;

/// Compute fee per operation
pub const COMPUTE_FEE_PER_OP: u64 = 10;

/// Transfer fee per transaction
pub const TRANSFER_FEE_PER_TX: u64 = 100;

/// Risk deposit multiplier
pub const RISK_DEPOSIT_MULTIPLIER: u64 = 10;

/// Maximum discount percentage
pub const MAX_DISCOUNT_PERCENTAGE: u8 = 50;

// ============================================================================
// Trust Score Constants
// ============================================================================

/// Trust score initial value
pub const TRUST_SCORE_INITIAL: f64 = 0.5;

/// Trust score minimum
pub const TRUST_SCORE_MIN: f64 = 0.0;

/// Trust score maximum
pub const TRUST_SCORE_MAX: f64 = 1.0;

/// Trust score penalty for failure
pub const TRUST_SCORE_FAILURE_PENALTY: f64 = 0.1;

/// Trust score recovery per successful operation
pub const TRUST_SCORE_SUCCESS_RECOVERY: f64 = 0.01;

/// Minimum trust score for connected node
pub const MIN_TRUST_SCORE_CONNECTED: f64 = 0.8;

// ============================================================================
// Evidence Level Constants
// ============================================================================

/// Evidence level A threshold (fully reconciled)
pub const EVIDENCE_LEVEL_A_RECONCILIATION_REQUIRED: bool = true;

/// Evidence level degradation on missing map commit
pub const EVIDENCE_DEGRADES_ON_MISSING_COMMIT: bool = true;

// ============================================================================
// Sampling Constants
// ============================================================================

/// Minimum daily samples
pub const MIN_DAILY_SAMPLES: u64 = 100;

/// Maximum daily samples
pub const MAX_DAILY_SAMPLES: u64 = 100_000;

/// Sampling alert threshold (failure rate)
pub const SAMPLING_ALERT_THRESHOLD: f64 = 0.01;

/// Must-open trigger threshold (consecutive failures)
pub const MUST_OPEN_TRIGGER_THRESHOLD: u32 = 3;

// ============================================================================
// Backfill Constants
// ============================================================================

/// Maximum backfill batch size
pub const MAX_BACKFILL_BATCH_SIZE: usize = 500;

/// Backfill retry limit
pub const BACKFILL_RETRY_LIMIT: u32 = 5;

/// Backfill concurrent workers
pub const BACKFILL_CONCURRENT_WORKERS: usize = 10;

// ============================================================================
// Retry Constants
// ============================================================================

/// Default retry attempts
pub const DEFAULT_RETRY_ATTEMPTS: u32 = 3;

/// Default retry initial backoff (milliseconds)
pub const DEFAULT_RETRY_INITIAL_BACKOFF_MS: u64 = 1000;

/// Default retry max backoff (milliseconds)
pub const DEFAULT_RETRY_MAX_BACKOFF_MS: u64 = 60_000;

/// Default retry backoff multiplier
pub const DEFAULT_RETRY_BACKOFF_MULTIPLIER: f64 = 2.0;

// ============================================================================
// HTTP/API Constants
// ============================================================================

/// Default HTTP port
pub const DEFAULT_HTTP_PORT: u16 = 3000;

/// Default metrics port
pub const DEFAULT_METRICS_PORT: u16 = 9090;

/// API version prefix
pub const API_VERSION_PREFIX: &str = "/api/v1";

/// Maximum request body size (10 MB)
pub const MAX_REQUEST_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Rate limit requests per second
pub const DEFAULT_RATE_LIMIT_RPS: u32 = 100;

/// Rate limit burst size
pub const DEFAULT_RATE_LIMIT_BURST: u32 = 200;

// ============================================================================
// Cache Constants
// ============================================================================

/// Default cache TTL (seconds)
pub const DEFAULT_CACHE_TTL_SECS: u64 = 300;

/// Maximum cache entries
pub const MAX_CACHE_ENTRIES: usize = 10_000;

/// Metadata cache TTL (seconds)
pub const METADATA_CACHE_TTL_SECS: u64 = 60;

// ============================================================================
// Health Check Constants
// ============================================================================

/// Health check interval (seconds)
pub const HEALTH_CHECK_INTERVAL_SECS: u64 = 30;

/// Health check timeout (seconds)
pub const HEALTH_CHECK_TIMEOUT_SECS: u64 = 5;

/// Unhealthy threshold (consecutive failures)
pub const UNHEALTHY_THRESHOLD: u32 = 3;

/// Recovery threshold (consecutive successes)
pub const RECOVERY_THRESHOLD: u32 = 2;

// ============================================================================
// Log Constants
// ============================================================================

/// Default log level
pub const DEFAULT_LOG_LEVEL: &str = "info";

/// Audit log retention days
pub const AUDIT_LOG_RETENTION_DAYS: u32 = 365;

/// Operation log retention days
pub const OPERATION_LOG_RETENTION_DAYS: u32 = 90;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_strings_valid() {
        assert!(!PROTOCOL_VERSION.is_empty());
        assert!(!CANONICALIZATION_VERSION.is_empty());
        assert!(!SIGNER_SET_VERSION.is_empty());
    }

    #[test]
    fn test_size_limits_reasonable() {
        assert!(MAX_PAYLOAD_SIZE_BYTES > 0);
        assert!(MAX_BATCH_SIZE > 0);
        assert!(DIGEST_LENGTH_BYTES == 32);
    }

    #[test]
    fn test_timeout_values_positive() {
        assert!(DEFAULT_REQUEST_TIMEOUT_SECS > 0);
        assert!(DEFAULT_SYNC_TIMEOUT_SECS > DEFAULT_REQUEST_TIMEOUT_SECS);
    }

    #[test]
    fn test_replication_factors() {
        assert!(HOT_DATA_MIN_REPLICATION_FACTOR >= 2);
        assert!(WARM_DATA_MIN_REPLICATION_FACTOR >= 1);
        assert!(COLD_DATA_MIN_REPLICATION_FACTOR >= 1);
    }
}
