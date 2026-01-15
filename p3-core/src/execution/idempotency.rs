//! Idempotency Management
//!
//! Ensures operations are executed exactly once.

use crate::error::{P3Error, P3Result};
use crate::types::*;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Idempotency manager with automatic cleanup
pub struct IdempotencyManager {
    /// Records by key
    records: HashMap<String, IdempotencyRecord>,
    /// Default TTL in seconds
    default_ttl_secs: u64,
    /// Auto cleanup configuration
    auto_cleanup_config: AutoCleanupConfig,
    /// Last cleanup timestamp
    last_cleanup_at: Option<DateTime<Utc>>,
    /// Operation counter since last cleanup
    ops_since_cleanup: u64,
}

/// Auto cleanup configuration
#[derive(Clone, Debug)]
pub struct AutoCleanupConfig {
    /// Enable automatic cleanup
    pub enabled: bool,
    /// Cleanup interval in seconds (time-based trigger)
    pub interval_secs: u64,
    /// Cleanup threshold by record count (count-based trigger)
    pub record_count_threshold: usize,
    /// Cleanup threshold by operations count (ops-based trigger)
    pub ops_count_threshold: u64,
}

impl Default for AutoCleanupConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 3600, // 1 hour
            record_count_threshold: 10000,
            ops_count_threshold: 1000,
        }
    }
}

impl IdempotencyManager {
    /// Create new manager
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
            default_ttl_secs: 86400, // 24 hours
            auto_cleanup_config: AutoCleanupConfig::default(),
            last_cleanup_at: None,
            ops_since_cleanup: 0,
        }
    }

    /// Set default TTL
    pub fn with_default_ttl(mut self, ttl_secs: u64) -> Self {
        self.default_ttl_secs = ttl_secs;
        self
    }

    /// Configure auto cleanup
    pub fn with_auto_cleanup(mut self, config: AutoCleanupConfig) -> Self {
        self.auto_cleanup_config = config;
        self
    }

    /// Disable auto cleanup
    pub fn without_auto_cleanup(mut self) -> Self {
        self.auto_cleanup_config.enabled = false;
        self
    }

    /// Check if auto cleanup should run
    fn should_auto_cleanup(&self, now: &DateTime<Utc>) -> bool {
        if !self.auto_cleanup_config.enabled {
            return false;
        }

        // Check record count threshold
        if self.records.len() >= self.auto_cleanup_config.record_count_threshold {
            return true;
        }

        // Check ops count threshold
        if self.ops_since_cleanup >= self.auto_cleanup_config.ops_count_threshold {
            return true;
        }

        // Check time interval
        if let Some(last_cleanup) = self.last_cleanup_at {
            let elapsed = (*now - last_cleanup).num_seconds() as u64;
            if elapsed >= self.auto_cleanup_config.interval_secs {
                return true;
            }
        } else {
            // Never cleaned up, check if we have records
            return !self.records.is_empty();
        }

        false
    }

    /// Run auto cleanup if needed
    fn maybe_auto_cleanup(&mut self, now: &DateTime<Utc>) {
        if self.should_auto_cleanup(now) {
            self.cleanup_expired(now);
            self.last_cleanup_at = Some(*now);
            self.ops_since_cleanup = 0;
        }
    }

    /// Increment ops counter
    fn inc_ops_counter(&mut self) {
        self.ops_since_cleanup = self.ops_since_cleanup.saturating_add(1);
    }

    /// Check if operation can proceed
    pub fn check(&self, key: &IdempotencyKey, params_digest: &P3Digest) -> IdempotencyCheck {
        let now = Utc::now();

        match self.records.get(key.as_str()) {
            None => IdempotencyCheck::Proceed,
            Some(record) => {
                // Check if expired
                if record.is_expired(&now) {
                    return IdempotencyCheck::Proceed;
                }

                // Check if parameters match
                if !record.parameters_match(params_digest) {
                    return IdempotencyCheck::Collision {
                        existing_params_digest: record.parameters_digest.clone(),
                    };
                }

                // Check status
                match record.status {
                    IdempotencyStatus::InProgress => IdempotencyCheck::InProgress {
                        started_at: record.created_at,
                    },
                    IdempotencyStatus::Completed => IdempotencyCheck::AlreadyCompleted {
                        result_digest: record.result_digest.clone(),
                        completed_at: record.completed_at.unwrap(),
                    },
                    IdempotencyStatus::Failed => IdempotencyCheck::Proceed, // Allow retry on failure
                }
            }
        }
    }

    /// Start operation
    pub fn start(
        &mut self,
        key: IdempotencyKey,
        operation_type: impl Into<String>,
        params_digest: P3Digest,
    ) -> P3Result<()> {
        let now = Utc::now();

        // Auto cleanup before starting new operation
        self.maybe_auto_cleanup(&now);
        self.inc_ops_counter();

        // Check if already exists
        let check = self.check(&key, &params_digest);
        match check {
            IdempotencyCheck::Proceed => {}
            IdempotencyCheck::Collision { .. } => {
                return Err(P3Error::IdempotencyKeyCollision {
                    key: key.as_str().to_string(),
                });
            }
            IdempotencyCheck::InProgress { .. } => {
                return Err(P3Error::InvalidState {
                    reason: "Operation already in progress".to_string(),
                });
            }
            IdempotencyCheck::AlreadyCompleted { .. } => {
                return Err(P3Error::InvalidState {
                    reason: "Operation already completed".to_string(),
                });
            }
        }

        let record = IdempotencyRecord {
            key: key.clone(),
            operation_type: operation_type.into(),
            parameters_digest: params_digest,
            result_digest: None,
            status: IdempotencyStatus::InProgress,
            created_at: now,
            completed_at: None,
            ttl_secs: Some(self.default_ttl_secs),
        };

        self.records.insert(key.as_str().to_string(), record);
        Ok(())
    }

    /// Complete operation successfully
    pub fn complete(&mut self, key: &IdempotencyKey, result_digest: P3Digest) -> P3Result<()> {
        let now = Utc::now();

        let record = self.records.get_mut(key.as_str()).ok_or_else(|| {
            P3Error::NotFound {
                entity: "IdempotencyRecord".to_string(),
                id: key.as_str().to_string(),
            }
        })?;

        if record.status != IdempotencyStatus::InProgress {
            return Err(P3Error::InvalidState {
                reason: format!("Cannot complete record in {:?} status", record.status),
            });
        }

        record.status = IdempotencyStatus::Completed;
        record.result_digest = Some(result_digest);
        record.completed_at = Some(now);

        Ok(())
    }

    /// Mark operation as failed
    pub fn fail(&mut self, key: &IdempotencyKey) -> P3Result<()> {
        let record = self.records.get_mut(key.as_str()).ok_or_else(|| {
            P3Error::NotFound {
                entity: "IdempotencyRecord".to_string(),
                id: key.as_str().to_string(),
            }
        })?;

        if record.status != IdempotencyStatus::InProgress {
            return Err(P3Error::InvalidState {
                reason: format!("Cannot fail record in {:?} status", record.status),
            });
        }

        record.status = IdempotencyStatus::Failed;
        record.completed_at = Some(Utc::now());

        Ok(())
    }

    /// Get record
    pub fn get(&self, key: &IdempotencyKey) -> Option<&IdempotencyRecord> {
        self.records.get(key.as_str())
    }

    /// Cleanup expired records
    pub fn cleanup_expired(&mut self, now: &DateTime<Utc>) {
        self.records.retain(|_, record| !record.is_expired(now));
    }

    /// Get count of records
    pub fn count(&self) -> usize {
        self.records.len()
    }

    /// Get count by status
    pub fn count_by_status(&self, status: IdempotencyStatus) -> usize {
        self.records.values().filter(|r| r.status == status).count()
    }
}

impl Default for IdempotencyManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of idempotency check
#[derive(Clone, Debug)]
pub enum IdempotencyCheck {
    /// Operation can proceed
    Proceed,
    /// Operation is already in progress
    InProgress {
        started_at: DateTime<Utc>,
    },
    /// Operation already completed
    AlreadyCompleted {
        result_digest: Option<P3Digest>,
        completed_at: DateTime<Utc>,
    },
    /// Key collision with different parameters
    Collision {
        existing_params_digest: P3Digest,
    },
}

impl IdempotencyCheck {
    /// Check if operation can proceed
    pub fn can_proceed(&self) -> bool {
        matches!(self, IdempotencyCheck::Proceed)
    }

    /// Check if already completed
    pub fn is_completed(&self) -> bool {
        matches!(self, IdempotencyCheck::AlreadyCompleted { .. })
    }
}

/// Idempotency guard for automatic cleanup
pub struct IdempotencyGuard<'a> {
    manager: &'a mut IdempotencyManager,
    key: IdempotencyKey,
    committed: bool,
}

impl<'a> IdempotencyGuard<'a> {
    /// Create new guard
    pub fn new(
        manager: &'a mut IdempotencyManager,
        key: IdempotencyKey,
        operation_type: impl Into<String>,
        params_digest: P3Digest,
    ) -> P3Result<Self> {
        manager.start(key.clone(), operation_type, params_digest)?;
        Ok(Self {
            manager,
            key,
            committed: false,
        })
    }

    /// Commit the operation
    pub fn commit(mut self, result_digest: P3Digest) -> P3Result<()> {
        self.committed = true;
        self.manager.complete(&self.key, result_digest)
    }

    /// Get the key
    pub fn key(&self) -> &IdempotencyKey {
        &self.key
    }
}

impl<'a> Drop for IdempotencyGuard<'a> {
    fn drop(&mut self) {
        if !self.committed {
            // Mark as failed if not committed
            let _ = self.manager.fail(&self.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_idempotency_manager_creation() {
        let manager = IdempotencyManager::new();
        assert_eq!(manager.count(), 0);
    }

    #[test]
    fn test_check_new_key() {
        let manager = IdempotencyManager::new();
        let key = IdempotencyKey::generate();
        let params = P3Digest::blake3(b"params");

        let check = manager.check(&key, &params);
        assert!(check.can_proceed());
    }

    #[test]
    fn test_start_and_complete() {
        let mut manager = IdempotencyManager::new();
        let key = IdempotencyKey::generate();
        let params = P3Digest::blake3(b"params");
        let result = P3Digest::blake3(b"result");

        manager.start(key.clone(), "test_op", params.clone()).unwrap();
        assert_eq!(manager.count_by_status(IdempotencyStatus::InProgress), 1);

        manager.complete(&key, result).unwrap();
        assert_eq!(manager.count_by_status(IdempotencyStatus::Completed), 1);
    }

    #[test]
    fn test_duplicate_detection() {
        let mut manager = IdempotencyManager::new();
        let key = IdempotencyKey::generate();
        let params = P3Digest::blake3(b"params");

        manager.start(key.clone(), "test_op", params.clone()).unwrap();

        // Same key, same params - should detect in progress
        let check = manager.check(&key, &params);
        assert!(matches!(check, IdempotencyCheck::InProgress { .. }));
    }

    #[test]
    fn test_collision_detection() {
        let mut manager = IdempotencyManager::new();
        let key = IdempotencyKey::generate();
        let params1 = P3Digest::blake3(b"params1");
        let params2 = P3Digest::blake3(b"params2");

        manager.start(key.clone(), "test_op", params1).unwrap();

        // Same key, different params - collision
        let check = manager.check(&key, &params2);
        assert!(matches!(check, IdempotencyCheck::Collision { .. }));
    }

    #[test]
    fn test_already_completed() {
        let mut manager = IdempotencyManager::new();
        let key = IdempotencyKey::generate();
        let params = P3Digest::blake3(b"params");
        let result = P3Digest::blake3(b"result");

        manager.start(key.clone(), "test_op", params.clone()).unwrap();
        manager.complete(&key, result).unwrap();

        let check = manager.check(&key, &params);
        assert!(check.is_completed());
    }

    #[test]
    fn test_fail_allows_retry() {
        let mut manager = IdempotencyManager::new();
        let key = IdempotencyKey::generate();
        let params = P3Digest::blake3(b"params");

        manager.start(key.clone(), "test_op", params.clone()).unwrap();
        manager.fail(&key).unwrap();

        // After failure, should allow retry
        let check = manager.check(&key, &params);
        assert!(check.can_proceed());
    }

    #[test]
    fn test_cleanup_expired() {
        let mut manager = IdempotencyManager::new().with_default_ttl(0);
        let key = IdempotencyKey::generate();
        let params = P3Digest::blake3(b"params");
        let result = P3Digest::blake3(b"result");

        manager.start(key.clone(), "test_op", params).unwrap();
        manager.complete(&key, result).unwrap();

        // Wait for expiry
        std::thread::sleep(std::time::Duration::from_millis(10));

        let now = Utc::now();
        manager.cleanup_expired(&now);

        assert_eq!(manager.count(), 0);
    }

    #[test]
    fn test_auto_cleanup_config_default() {
        let config = AutoCleanupConfig::default();
        assert!(config.enabled);
        assert_eq!(config.interval_secs, 3600);
        assert_eq!(config.record_count_threshold, 10000);
        assert_eq!(config.ops_count_threshold, 1000);
    }

    #[test]
    fn test_auto_cleanup_by_ops_threshold() {
        let config = AutoCleanupConfig {
            enabled: true,
            interval_secs: 3600,
            record_count_threshold: 10000,
            ops_count_threshold: 3, // Low threshold for testing
        };

        let mut manager = IdempotencyManager::new()
            .with_default_ttl(0) // Immediate expiry
            .with_auto_cleanup(config);

        // Add some records and complete them
        for i in 0..2 {
            let key = IdempotencyKey::new(format!("key:{}", i));
            let params = P3Digest::blake3(format!("params:{}", i).as_bytes());
            let result = P3Digest::blake3(format!("result:{}", i).as_bytes());
            manager.start(key.clone(), "test_op", params).unwrap();
            manager.complete(&key, result).unwrap();
        }

        // Wait for records to expire
        std::thread::sleep(std::time::Duration::from_millis(10));

        // At this point, ops_since_cleanup should be 2
        assert_eq!(manager.count(), 2);

        // Next operation should trigger cleanup (ops threshold = 3)
        let key3 = IdempotencyKey::new("key:3");
        let params3 = P3Digest::blake3(b"params:3");
        manager.start(key3.clone(), "test_op", params3).unwrap();

        // After auto-cleanup, expired records should be removed (only key:3 remains)
        assert_eq!(manager.count(), 1);
    }

    #[test]
    fn test_auto_cleanup_disabled() {
        let config = AutoCleanupConfig {
            enabled: false, // Disabled
            ..AutoCleanupConfig::default()
        };

        let mut manager = IdempotencyManager::new()
            .with_default_ttl(0)
            .with_auto_cleanup(config);

        // Add records
        let key1 = IdempotencyKey::new("key:1");
        let params1 = P3Digest::blake3(b"params:1");
        let result1 = P3Digest::blake3(b"result:1");
        manager.start(key1.clone(), "test_op", params1).unwrap();
        manager.complete(&key1, result1).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(10));

        // Add another record - should NOT trigger cleanup because auto-cleanup is disabled
        let key2 = IdempotencyKey::new("key:2");
        let params2 = P3Digest::blake3(b"params:2");
        manager.start(key2.clone(), "test_op", params2).unwrap();

        // Both records should still exist
        assert_eq!(manager.count(), 2);
    }

    #[test]
    fn test_without_auto_cleanup() {
        let manager = IdempotencyManager::new().without_auto_cleanup();
        assert!(!manager.auto_cleanup_config.enabled);
    }
}
