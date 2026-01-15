//! Attempt Chain Management
//!
//! Manages retry chains for failed operations.

use crate::error::{P3Error, P3Result};
use crate::types::*;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Attempt chain manager
pub struct AttemptChainManager {
    /// Active chains
    chains: HashMap<String, AttemptChain>,
    /// Default max attempts
    default_max_attempts: u32,
    /// Default backoff policy
    default_backoff: BackoffPolicy,
}

impl AttemptChainManager {
    /// Create new manager
    pub fn new() -> Self {
        Self {
            chains: HashMap::new(),
            default_max_attempts: 5,
            default_backoff: BackoffPolicy::default(),
        }
    }

    /// Set default max attempts
    pub fn with_max_attempts(mut self, max: u32) -> Self {
        self.default_max_attempts = max;
        self
    }

    /// Set default backoff policy
    pub fn with_backoff_policy(mut self, policy: BackoffPolicy) -> Self {
        self.default_backoff = policy;
        self
    }

    /// Create new attempt chain
    pub fn create_chain(
        &mut self,
        target_operation: impl Into<String>,
        target_ref: P3Digest,
    ) -> P3Result<AttemptChainId> {
        let now = Utc::now();
        let chain_id = AttemptChainId::new(format!("chain:{}:{}", target_operation.into(), now.timestamp_millis()));

        let chain = AttemptChain {
            chain_id: chain_id.clone(),
            target_operation: chain_id.as_str().to_string(),
            target_ref,
            max_attempts: self.default_max_attempts,
            attempts: Vec::new(),
            status: AttemptChainStatus::Pending,
            created_at: now,
            last_attempt_at: None,
            backoff_policy: self.default_backoff.clone(),
        };

        self.chains.insert(chain_id.as_str().to_string(), chain);
        Ok(chain_id)
    }

    /// Record an attempt
    pub fn record_attempt(
        &mut self,
        chain_id: &AttemptChainId,
        result: AttemptResult,
        error_digest: Option<P3Digest>,
        executor_ref: Option<String>,
    ) -> P3Result<AttemptOutcome> {
        let now = Utc::now();

        let chain = self.chains.get_mut(chain_id.as_str()).ok_or_else(|| {
            P3Error::NotFound {
                entity: "AttemptChain".to_string(),
                id: chain_id.as_str().to_string(),
            }
        })?;

        // Check if chain is still active
        if !chain.can_retry() && chain.status != AttemptChainStatus::Pending {
            return Err(P3Error::AttemptChainExhausted {
                chain_id: chain_id.as_str().to_string(),
                attempts: chain.attempt_count(),
            });
        }

        let attempt_no = chain.attempt_count() + 1;

        let attempt = Attempt {
            attempt_no,
            attempted_at: now,
            result: result.clone(),
            error_digest,
            executor_ref,
        };

        chain.attempts.push(attempt);
        chain.last_attempt_at = Some(now);
        chain.status = AttemptChainStatus::InProgress;

        // Determine outcome based on result
        let outcome = match result {
            AttemptResult::Success => {
                chain.status = AttemptChainStatus::Succeeded;
                AttemptOutcome::Success
            }
            AttemptResult::PermanentError => {
                chain.status = AttemptChainStatus::Failed;
                AttemptOutcome::PermanentFailure
            }
            AttemptResult::RetryableError | AttemptResult::Timeout => {
                if chain.can_retry() {
                    let next_retry = chain.next_retry_at().unwrap_or(now);
                    AttemptOutcome::RetryScheduled { retry_at: next_retry }
                } else {
                    chain.status = AttemptChainStatus::Exhausted;
                    AttemptOutcome::Exhausted
                }
            }
        };

        Ok(outcome)
    }

    /// Get chain
    pub fn get_chain(&self, chain_id: &AttemptChainId) -> Option<&AttemptChain> {
        self.chains.get(chain_id.as_str())
    }

    /// Get chain mutable
    pub fn get_chain_mut(&mut self, chain_id: &AttemptChainId) -> Option<&mut AttemptChain> {
        self.chains.get_mut(chain_id.as_str())
    }

    /// Cancel chain
    pub fn cancel_chain(&mut self, chain_id: &AttemptChainId) -> P3Result<()> {
        let chain = self.chains.get_mut(chain_id.as_str()).ok_or_else(|| {
            P3Error::NotFound {
                entity: "AttemptChain".to_string(),
                id: chain_id.as_str().to_string(),
            }
        })?;

        if chain.status == AttemptChainStatus::Succeeded {
            return Err(P3Error::InvalidState {
                reason: "Cannot cancel succeeded chain".to_string(),
            });
        }

        chain.status = AttemptChainStatus::Cancelled;
        Ok(())
    }

    /// Get chains ready for retry
    pub fn get_ready_for_retry(&self, now: &DateTime<Utc>) -> Vec<&AttemptChain> {
        self.chains
            .values()
            .filter(|chain| {
                chain.can_retry()
                    && chain
                        .next_retry_at()
                        .map(|t| &t <= now)
                        .unwrap_or(true)
            })
            .collect()
    }

    /// Get chains by status
    pub fn get_by_status(&self, status: AttemptChainStatus) -> Vec<&AttemptChain> {
        self.chains
            .values()
            .filter(|chain| chain.status == status)
            .collect()
    }

    /// Count chains
    pub fn count(&self) -> usize {
        self.chains.len()
    }

    /// Count by status
    pub fn count_by_status(&self, status: AttemptChainStatus) -> usize {
        self.chains.values().filter(|c| c.status == status).count()
    }

    /// Generate summary
    pub fn summary(&self) -> AttemptChainSummary {
        AttemptChainSummary {
            total_chains: self.chains.len(),
            pending: self.count_by_status(AttemptChainStatus::Pending),
            in_progress: self.count_by_status(AttemptChainStatus::InProgress),
            succeeded: self.count_by_status(AttemptChainStatus::Succeeded),
            failed: self.count_by_status(AttemptChainStatus::Failed),
            exhausted: self.count_by_status(AttemptChainStatus::Exhausted),
            cancelled: self.count_by_status(AttemptChainStatus::Cancelled),
        }
    }
}

impl Default for AttemptChainManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Attempt outcome
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// Operation succeeded
    Success,
    /// Permanent failure, no more retries
    PermanentFailure,
    /// Retry scheduled
    RetryScheduled { retry_at: DateTime<Utc> },
    /// All attempts exhausted
    Exhausted,
}

impl AttemptOutcome {
    /// Check if successful
    pub fn is_success(&self) -> bool {
        matches!(self, AttemptOutcome::Success)
    }

    /// Check if should retry
    pub fn should_retry(&self) -> bool {
        matches!(self, AttemptOutcome::RetryScheduled { .. })
    }

    /// Get retry time if applicable
    pub fn retry_at(&self) -> Option<DateTime<Utc>> {
        match self {
            AttemptOutcome::RetryScheduled { retry_at } => Some(*retry_at),
            _ => None,
        }
    }
}

/// Attempt chain summary
#[derive(Clone, Debug)]
pub struct AttemptChainSummary {
    /// Total chains
    pub total_chains: usize,
    /// Pending chains
    pub pending: usize,
    /// In progress chains
    pub in_progress: usize,
    /// Succeeded chains
    pub succeeded: usize,
    /// Failed chains
    pub failed: usize,
    /// Exhausted chains
    pub exhausted: usize,
    /// Cancelled chains
    pub cancelled: usize,
}

/// Builder for custom attempt chains
pub struct AttemptChainBuilder {
    target_operation: String,
    target_ref: P3Digest,
    max_attempts: Option<u32>,
    backoff_policy: Option<BackoffPolicy>,
}

impl AttemptChainBuilder {
    /// Create new builder
    pub fn new(target_operation: impl Into<String>, target_ref: P3Digest) -> Self {
        Self {
            target_operation: target_operation.into(),
            target_ref,
            max_attempts: None,
            backoff_policy: None,
        }
    }

    /// Set max attempts
    pub fn max_attempts(mut self, max: u32) -> Self {
        self.max_attempts = Some(max);
        self
    }

    /// Set backoff policy
    pub fn backoff_policy(mut self, policy: BackoffPolicy) -> Self {
        self.backoff_policy = Some(policy);
        self
    }

    /// Set exponential backoff
    pub fn exponential_backoff(self, initial_delay: u32, max_delay: u32, multiplier: f64) -> Self {
        self.backoff_policy(BackoffPolicy {
            initial_delay_secs: initial_delay,
            max_delay_secs: max_delay,
            multiplier,
            jitter: true,
        })
    }

    /// Set linear backoff
    pub fn linear_backoff(self, delay: u32) -> Self {
        self.backoff_policy(BackoffPolicy {
            initial_delay_secs: delay,
            max_delay_secs: delay,
            multiplier: 1.0,
            jitter: false,
        })
    }

    /// Build the chain
    pub fn build(self) -> AttemptChain {
        let now = Utc::now();
        let chain_id = AttemptChainId::new(format!(
            "chain:{}:{}",
            self.target_operation,
            now.timestamp_millis()
        ));

        AttemptChain {
            chain_id,
            target_operation: self.target_operation,
            target_ref: self.target_ref,
            max_attempts: self.max_attempts.unwrap_or(5),
            attempts: Vec::new(),
            status: AttemptChainStatus::Pending,
            created_at: now,
            last_attempt_at: None,
            backoff_policy: self.backoff_policy.unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attempt_chain_manager_creation() {
        let manager = AttemptChainManager::new();
        assert_eq!(manager.count(), 0);
    }

    #[test]
    fn test_create_chain() {
        let mut manager = AttemptChainManager::new();
        let chain_id = manager
            .create_chain("test_op", P3Digest::zero())
            .unwrap();

        assert!(manager.get_chain(&chain_id).is_some());
    }

    #[test]
    fn test_record_success() {
        let mut manager = AttemptChainManager::new();
        let chain_id = manager
            .create_chain("test_op", P3Digest::zero())
            .unwrap();

        let outcome = manager
            .record_attempt(&chain_id, AttemptResult::Success, None, None)
            .unwrap();

        assert!(outcome.is_success());
        assert_eq!(
            manager.get_chain(&chain_id).unwrap().status,
            AttemptChainStatus::Succeeded
        );
    }

    #[test]
    fn test_record_retryable_error() {
        let mut manager = AttemptChainManager::new().with_max_attempts(3);
        let chain_id = manager
            .create_chain("test_op", P3Digest::zero())
            .unwrap();

        let outcome = manager
            .record_attempt(&chain_id, AttemptResult::RetryableError, None, None)
            .unwrap();

        assert!(outcome.should_retry());
        assert!(manager.get_chain(&chain_id).unwrap().can_retry());
    }

    #[test]
    fn test_exhausted_attempts() {
        let mut manager = AttemptChainManager::new().with_max_attempts(2);
        let chain_id = manager
            .create_chain("test_op", P3Digest::zero())
            .unwrap();

        // First attempt
        manager
            .record_attempt(&chain_id, AttemptResult::RetryableError, None, None)
            .unwrap();

        // Second attempt - should exhaust
        let outcome = manager
            .record_attempt(&chain_id, AttemptResult::RetryableError, None, None)
            .unwrap();

        assert_eq!(outcome, AttemptOutcome::Exhausted);
        assert_eq!(
            manager.get_chain(&chain_id).unwrap().status,
            AttemptChainStatus::Exhausted
        );
    }

    #[test]
    fn test_permanent_failure() {
        let mut manager = AttemptChainManager::new();
        let chain_id = manager
            .create_chain("test_op", P3Digest::zero())
            .unwrap();

        let outcome = manager
            .record_attempt(&chain_id, AttemptResult::PermanentError, None, None)
            .unwrap();

        assert_eq!(outcome, AttemptOutcome::PermanentFailure);
        assert_eq!(
            manager.get_chain(&chain_id).unwrap().status,
            AttemptChainStatus::Failed
        );
    }

    #[test]
    fn test_cancel_chain() {
        let mut manager = AttemptChainManager::new();
        let chain_id = manager
            .create_chain("test_op", P3Digest::zero())
            .unwrap();

        manager.cancel_chain(&chain_id).unwrap();

        assert_eq!(
            manager.get_chain(&chain_id).unwrap().status,
            AttemptChainStatus::Cancelled
        );
    }

    #[test]
    fn test_cannot_cancel_succeeded() {
        let mut manager = AttemptChainManager::new();
        let chain_id = manager
            .create_chain("test_op", P3Digest::zero())
            .unwrap();

        manager
            .record_attempt(&chain_id, AttemptResult::Success, None, None)
            .unwrap();

        let result = manager.cancel_chain(&chain_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_summary() {
        let mut manager = AttemptChainManager::new();

        // Create chains with different statuses
        let c1 = manager.create_chain("op1", P3Digest::zero()).unwrap();
        let c2 = manager.create_chain("op2", P3Digest::zero()).unwrap();
        let c3 = manager.create_chain("op3", P3Digest::zero()).unwrap();

        manager
            .record_attempt(&c1, AttemptResult::Success, None, None)
            .unwrap();
        manager
            .record_attempt(&c2, AttemptResult::PermanentError, None, None)
            .unwrap();

        let summary = manager.summary();
        assert_eq!(summary.total_chains, 3);
        assert_eq!(summary.succeeded, 1);
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.pending, 1);
    }

    #[test]
    fn test_builder() {
        let chain = AttemptChainBuilder::new("test_op", P3Digest::zero())
            .max_attempts(10)
            .exponential_backoff(1, 60, 2.0)
            .build();

        assert_eq!(chain.max_attempts, 10);
        assert_eq!(chain.backoff_policy.initial_delay_secs, 1);
        assert_eq!(chain.backoff_policy.max_delay_secs, 60);
    }
}
