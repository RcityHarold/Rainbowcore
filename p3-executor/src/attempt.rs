//! Attempt Chain Management Module
//!
//! Manages retry chains for execution operations with exponential backoff
//! and maximum attempt limits.

use crate::error::{ExecutorError, ExecutorResult};
use chrono::{DateTime, Duration, Utc};
use p3_core::{AttemptChainId, P3Digest};
use std::collections::HashMap;

/// Local attempt outcome enum (extends p3-core's limited AttemptOutcome)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// Operation succeeded
    Success,
    /// Failure with retry information
    Failure {
        /// Error digest
        error_digest: P3Digest,
        /// Whether the operation can be retried
        retryable: bool,
    },
    /// Pending further action
    Pending {
        /// Reason for pending
        reason: String,
    },
}

/// Attempt chain configuration
#[derive(Clone, Debug)]
pub struct AttemptChainConfig {
    /// Maximum number of attempts
    pub max_attempts: u32,
    /// Initial retry delay in seconds
    pub initial_delay_secs: i64,
    /// Maximum retry delay in seconds
    pub max_delay_secs: i64,
    /// Backoff multiplier
    pub backoff_multiplier: f64,
    /// Jitter factor (0.0 to 1.0)
    pub jitter_factor: f64,
}

impl Default for AttemptChainConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay_secs: 1,
            max_delay_secs: 300, // 5 minutes
            backoff_multiplier: 2.0,
            jitter_factor: 0.1,
        }
    }
}

impl AttemptChainConfig {
    /// Create a config with custom max attempts
    pub fn with_max_attempts(mut self, max_attempts: u32) -> Self {
        self.max_attempts = max_attempts;
        self
    }

    /// Create a config with custom initial delay
    pub fn with_initial_delay(mut self, secs: i64) -> Self {
        self.initial_delay_secs = secs;
        self
    }

    /// Calculate delay for a given attempt number
    pub fn calculate_delay(&self, attempt_number: u32) -> Duration {
        if attempt_number == 0 {
            return Duration::zero();
        }

        let base_delay = self.initial_delay_secs as f64
            * self.backoff_multiplier.powi(attempt_number.saturating_sub(1) as i32);
        let capped_delay = base_delay.min(self.max_delay_secs as f64);

        // Add jitter
        let jitter_range = capped_delay * self.jitter_factor;
        let jittered_delay = capped_delay + (jitter_range * rand_factor());

        Duration::seconds(jittered_delay as i64)
    }
}

/// Simple deterministic pseudo-random for jitter
fn rand_factor() -> f64 {
    // Use current timestamp nanoseconds for pseudo-randomness
    let nanos = Utc::now().timestamp_subsec_nanos();
    (nanos % 1000) as f64 / 1000.0
}

/// Attempt record
#[derive(Clone, Debug)]
pub struct AttemptRecord {
    /// Attempt number (1-indexed)
    pub attempt_number: u32,
    /// Started at
    pub started_at: DateTime<Utc>,
    /// Completed at
    pub completed_at: Option<DateTime<Utc>>,
    /// Outcome
    pub outcome: Option<AttemptOutcome>,
    /// Error digest (if failed)
    pub error_digest: Option<P3Digest>,
    /// Next retry at
    pub next_retry_at: Option<DateTime<Utc>>,
}

/// Attempt chain for tracking retries
#[derive(Clone, Debug)]
pub struct AttemptChain {
    /// Chain ID
    pub chain_id: AttemptChainId,
    /// Operation type
    pub operation_type: String,
    /// Target reference
    pub target_ref: P3Digest,
    /// Configuration
    pub config: AttemptChainConfig,
    /// Attempts
    pub attempts: Vec<AttemptRecord>,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Final outcome
    pub final_outcome: Option<AttemptOutcome>,
}

impl AttemptChain {
    /// Create a new attempt chain
    pub fn new(
        chain_id: AttemptChainId,
        operation_type: impl Into<String>,
        target_ref: P3Digest,
        config: AttemptChainConfig,
    ) -> Self {
        Self {
            chain_id,
            operation_type: operation_type.into(),
            target_ref,
            config,
            attempts: Vec::new(),
            created_at: Utc::now(),
            final_outcome: None,
        }
    }

    /// Get current attempt number
    pub fn current_attempt(&self) -> u32 {
        self.attempts.len() as u32
    }

    /// Check if more attempts are available
    pub fn has_attempts_remaining(&self) -> bool {
        self.final_outcome.is_none() && self.current_attempt() < self.config.max_attempts
    }

    /// Check if chain is finalized
    pub fn is_finalized(&self) -> bool {
        self.final_outcome.is_some()
    }

    /// Start a new attempt
    pub fn start_attempt(&mut self) -> ExecutorResult<u32> {
        if self.is_finalized() {
            return Err(ExecutorError::InvalidPhaseTransition {
                from: "finalized".to_string(),
                to: "attempt".to_string(),
            });
        }

        if !self.has_attempts_remaining() {
            return Err(ExecutorError::AttemptChainExhausted {
                attempts: self.current_attempt(),
            });
        }

        let attempt_number = self.current_attempt() + 1;
        let now = Utc::now();

        self.attempts.push(AttemptRecord {
            attempt_number,
            started_at: now,
            completed_at: None,
            outcome: None,
            error_digest: None,
            next_retry_at: None,
        });

        Ok(attempt_number)
    }

    /// Complete current attempt with outcome
    pub fn complete_attempt(&mut self, outcome: AttemptOutcome) -> ExecutorResult<()> {
        if self.attempts.is_empty() {
            return Err(ExecutorError::Internal("No active attempt".to_string()));
        }

        let now = Utc::now();
        let current_attempt_num = self.current_attempt();
        let max_attempts = self.config.max_attempts;

        // First, determine if we need to schedule a retry
        let (should_finalize, next_retry_time) = match &outcome {
            AttemptOutcome::Success => (true, None),
            AttemptOutcome::Failure { retryable, .. } => {
                let has_remaining = self.final_outcome.is_none() && current_attempt_num < max_attempts;
                if !retryable || !has_remaining {
                    (true, None)
                } else {
                    // Schedule next retry
                    let delay = self.config.calculate_delay(current_attempt_num);
                    (false, Some(now + delay))
                }
            }
            AttemptOutcome::Pending { .. } => (false, None),
        };

        // Now update the attempt record
        let current = self.attempts.last_mut().unwrap();
        current.completed_at = Some(now);
        current.outcome = Some(outcome.clone());
        current.next_retry_at = next_retry_time;

        // Update final outcome if needed
        if should_finalize {
            match outcome {
                AttemptOutcome::Success => {
                    self.final_outcome = Some(AttemptOutcome::Success);
                }
                AttemptOutcome::Failure { .. } => {
                    self.final_outcome = Some(AttemptOutcome::Failure {
                        error_digest: P3Digest::zero(),
                        retryable: false,
                    });
                }
                AttemptOutcome::Pending { .. } => {}
            }
        }

        Ok(())
    }

    /// Mark attempt as failed with error
    pub fn fail_attempt(&mut self, error_digest: P3Digest, retryable: bool) -> ExecutorResult<()> {
        if let Some(current) = self.attempts.last_mut() {
            current.error_digest = Some(error_digest.clone());
        }

        self.complete_attempt(AttemptOutcome::Failure {
            error_digest,
            retryable,
        })
    }

    /// Get next retry time if available
    pub fn next_retry_at(&self) -> Option<DateTime<Utc>> {
        self.attempts.last().and_then(|a| a.next_retry_at)
    }

    /// Check if ready for retry
    pub fn is_ready_for_retry(&self, now: &DateTime<Utc>) -> bool {
        if let Some(next_retry) = self.next_retry_at() {
            now >= &next_retry
        } else {
            false
        }
    }
}

/// Attempt chain manager
pub struct AttemptChainManager {
    /// Active chains
    chains: HashMap<String, AttemptChain>,
    /// Default configuration
    default_config: AttemptChainConfig,
}

impl AttemptChainManager {
    /// Create a new attempt chain manager
    pub fn new() -> Self {
        Self {
            chains: HashMap::new(),
            default_config: AttemptChainConfig::default(),
        }
    }

    /// Set default configuration
    pub fn with_default_config(mut self, config: AttemptChainConfig) -> Self {
        self.default_config = config;
        self
    }

    /// Create a new attempt chain
    pub fn create_chain(
        &mut self,
        operation_type: impl Into<String>,
        target_ref: P3Digest,
        config: Option<AttemptChainConfig>,
    ) -> AttemptChainId {
        let now = Utc::now();
        let chain_id = AttemptChainId::new(format!(
            "chain:{}:{}",
            now.timestamp_millis(),
            self.chains.len()
        ));
        let cfg = config.unwrap_or_else(|| self.default_config.clone());

        let chain = AttemptChain::new(chain_id.clone(), operation_type, target_ref, cfg);

        self.chains.insert(chain_id.as_str().to_string(), chain);
        chain_id
    }

    /// Get a chain by ID
    pub fn get_chain(&self, chain_id: &AttemptChainId) -> Option<&AttemptChain> {
        self.chains.get(chain_id.as_str())
    }

    /// Get a mutable chain by ID
    pub fn get_chain_mut(&mut self, chain_id: &AttemptChainId) -> Option<&mut AttemptChain> {
        self.chains.get_mut(chain_id.as_str())
    }

    /// Start an attempt for a chain
    pub fn start_attempt(&mut self, chain_id: &AttemptChainId) -> ExecutorResult<u32> {
        let chain = self.chains.get_mut(chain_id.as_str()).ok_or_else(|| {
            ExecutorError::not_found("AttemptChain", chain_id.as_str())
        })?;

        chain.start_attempt()
    }

    /// Complete an attempt for a chain
    pub fn complete_attempt(
        &mut self,
        chain_id: &AttemptChainId,
        outcome: AttemptOutcome,
    ) -> ExecutorResult<()> {
        let chain = self.chains.get_mut(chain_id.as_str()).ok_or_else(|| {
            ExecutorError::not_found("AttemptChain", chain_id.as_str())
        })?;

        chain.complete_attempt(outcome)
    }

    /// Get chains ready for retry
    pub fn get_chains_ready_for_retry(&self, now: &DateTime<Utc>) -> Vec<&AttemptChain> {
        self.chains
            .values()
            .filter(|c| c.is_ready_for_retry(now))
            .collect()
    }

    /// Get finalized chains
    pub fn get_finalized_chains(&self) -> Vec<&AttemptChain> {
        self.chains.values().filter(|c| c.is_finalized()).collect()
    }

    /// Remove finalized chains
    pub fn cleanup_finalized(&mut self) {
        self.chains.retain(|_, c| !c.is_finalized());
    }

    /// Get active chain count
    pub fn active_chain_count(&self) -> usize {
        self.chains.len()
    }
}

impl Default for AttemptChainManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attempt_chain_config_default() {
        let config = AttemptChainConfig::default();
        assert_eq!(config.max_attempts, 3);
        assert_eq!(config.initial_delay_secs, 1);
    }

    #[test]
    fn test_attempt_chain_config_delay_calculation() {
        let config = AttemptChainConfig::default();

        // First attempt should have no delay
        let delay0 = config.calculate_delay(0);
        assert_eq!(delay0, Duration::zero());

        // Second attempt should have initial delay (plus jitter)
        let delay1 = config.calculate_delay(1);
        assert!(delay1.num_seconds() >= 1);
        assert!(delay1.num_seconds() <= 2);
    }

    #[test]
    fn test_attempt_chain_creation() {
        let chain_id = AttemptChainId::new("chain:test:1");
        let target = P3Digest::blake3(b"test");
        let config = AttemptChainConfig::default();

        let chain = AttemptChain::new(chain_id, "test_op", target, config);

        assert_eq!(chain.current_attempt(), 0);
        assert!(chain.has_attempts_remaining());
        assert!(!chain.is_finalized());
    }

    #[test]
    fn test_attempt_chain_start_attempt() {
        let chain_id = AttemptChainId::new("chain:test:2");
        let target = P3Digest::blake3(b"test");
        let config = AttemptChainConfig::default();

        let mut chain = AttemptChain::new(chain_id, "test_op", target, config);

        let attempt = chain.start_attempt().unwrap();
        assert_eq!(attempt, 1);
        assert_eq!(chain.current_attempt(), 1);
    }

    #[test]
    fn test_attempt_chain_success() {
        let chain_id = AttemptChainId::new("chain:test:3");
        let target = P3Digest::blake3(b"test");
        let config = AttemptChainConfig::default();

        let mut chain = AttemptChain::new(chain_id, "test_op", target, config);

        chain.start_attempt().unwrap();
        chain.complete_attempt(AttemptOutcome::Success).unwrap();

        assert!(chain.is_finalized());
        assert!(matches!(chain.final_outcome, Some(AttemptOutcome::Success)));
    }

    #[test]
    fn test_attempt_chain_retryable_failure() {
        let chain_id = AttemptChainId::new("chain:test:4");
        let target = P3Digest::blake3(b"test");
        let config = AttemptChainConfig::default().with_max_attempts(3);

        let mut chain = AttemptChain::new(chain_id, "test_op", target, config);

        chain.start_attempt().unwrap();
        chain
            .fail_attempt(P3Digest::blake3(b"error"), true)
            .unwrap();

        assert!(!chain.is_finalized());
        assert!(chain.has_attempts_remaining());
        assert!(chain.next_retry_at().is_some());
    }

    #[test]
    fn test_attempt_chain_exhausted() {
        let chain_id = AttemptChainId::new("chain:test:5");
        let target = P3Digest::blake3(b"test");
        let config = AttemptChainConfig::default().with_max_attempts(2);

        let mut chain = AttemptChain::new(chain_id, "test_op", target, config);

        // First attempt
        chain.start_attempt().unwrap();
        chain
            .fail_attempt(P3Digest::blake3(b"error1"), true)
            .unwrap();

        // Second attempt
        chain.start_attempt().unwrap();
        chain
            .fail_attempt(P3Digest::blake3(b"error2"), true)
            .unwrap();

        assert!(chain.is_finalized());
        assert!(!chain.has_attempts_remaining());
    }

    #[test]
    fn test_attempt_chain_manager() {
        let mut manager = AttemptChainManager::new();
        let target = P3Digest::blake3(b"test");

        let chain_id = manager.create_chain("test_op", target, None);

        assert_eq!(manager.active_chain_count(), 1);
        assert!(manager.get_chain(&chain_id).is_some());
    }

    #[test]
    fn test_attempt_chain_manager_lifecycle() {
        let mut manager = AttemptChainManager::new();
        let target = P3Digest::blake3(b"test");

        let chain_id = manager.create_chain("test_op", target, None);

        manager.start_attempt(&chain_id).unwrap();
        manager
            .complete_attempt(&chain_id, AttemptOutcome::Success)
            .unwrap();

        let chain = manager.get_chain(&chain_id).unwrap();
        assert!(chain.is_finalized());

        manager.cleanup_finalized();
        assert_eq!(manager.active_chain_count(), 0);
    }

    #[test]
    fn test_chains_ready_for_retry() {
        let mut manager = AttemptChainManager::new();
        let target = P3Digest::blake3(b"test");

        // Use zero delay config for testing
        let config = AttemptChainConfig::default()
            .with_max_attempts(3)
            .with_initial_delay(0);

        let chain_id = manager.create_chain("test_op", target, Some(config));

        manager.start_attempt(&chain_id).unwrap();
        manager
            .complete_attempt(
                &chain_id,
                AttemptOutcome::Failure {
                    error_digest: P3Digest::blake3(b"error"),
                    retryable: true,
                },
            )
            .unwrap();

        let now = Utc::now() + Duration::seconds(1);
        let ready = manager.get_chains_ready_for_retry(&now);

        assert_eq!(ready.len(), 1);
    }
}
