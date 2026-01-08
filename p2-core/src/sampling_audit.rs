//! Sampling Audit and Must-Open Trigger System
//!
//! This module implements the random sampling audit mechanism and the must-open
//! trigger for accountability enforcement in the DSN layer.
//!
//! # Key Concepts
//!
//! 1. **Random Sampling**: Periodically sample payloads for integrity verification
//! 2. **Audit Verification**: Verify sampled payloads against stored commitments
//! 3. **Must-Open Trigger**: Mandatory disclosure when sampling fails
//! 4. **Escalation**: Progressive escalation based on failure severity
//!
//! # Sampling Flow
//!
//! ```text
//! Select Sample → Retrieve Payload → Verify Integrity →
//! [Pass] → Log & Continue
//! [Fail] → Trigger Must-Open → Escalate → Notify Authorities
//! ```
//!
//! # Must-Open Trigger
//!
//! When a sampling audit fails, the must-open process is triggered:
//! 1. Freeze affected payloads
//! 2. Notify relevant authorities
//! 3. Generate forensic evidence bundle
//! 4. Initiate disclosure workflow

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use l0_core::types::{ActorId, Digest};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Sampling audit error types
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
pub enum SamplingError {
    #[error("Payload not found: {ref_id}")]
    PayloadNotFound { ref_id: String },

    #[error("Integrity check failed: {reason}")]
    IntegrityFailed { reason: String },

    #[error("Hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    #[error("Decryption failed: {reason}")]
    DecryptionFailed { reason: String },

    #[error("Sample selection failed: {reason}")]
    SelectionFailed { reason: String },

    #[error("Must-open already triggered: {trigger_id}")]
    MustOpenAlreadyTriggered { trigger_id: String },

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Escalation failed: {reason}")]
    EscalationFailed { reason: String },
}

pub type SamplingResult<T> = Result<T, SamplingError>;

/// Sampling run status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SamplingRunStatus {
    /// Scheduled but not started
    Scheduled,
    /// Currently running
    Running,
    /// Completed successfully (all samples passed)
    Passed,
    /// Completed with failures
    Failed,
    /// Must-open triggered
    MustOpenTriggered,
    /// Cancelled
    Cancelled,
}

/// Individual sample result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleResult {
    /// Sample ID
    pub sample_id: String,
    /// Payload ref_id
    pub ref_id: String,
    /// Sample passed
    pub passed: bool,
    /// Failure reason (if failed)
    pub failure_reason: Option<SamplingFailureReason>,
    /// Verification timestamp
    pub verified_at: DateTime<Utc>,
    /// Verification duration (ms)
    pub duration_ms: u64,
    /// Expected hash
    pub expected_hash: Option<Digest>,
    /// Actual hash
    pub actual_hash: Option<Digest>,
}

/// Sampling failure reason
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SamplingFailureReason {
    /// Payload not found in storage
    PayloadNotFound,
    /// Hash does not match commitment
    HashMismatch { expected: Digest, actual: Digest },
    /// Payload corrupted
    DataCorruption { details: String },
    /// Decryption verification failed
    DecryptionFailed { details: String },
    /// Commitment not found
    CommitmentNotFound,
    /// Metadata mismatch
    MetadataMismatch { field: String, expected: String, actual: String },
    /// Storage unavailable
    StorageUnavailable,
    /// Timeout
    Timeout,
}

/// Sampling run record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingRun {
    /// Run ID
    pub run_id: String,
    /// Run status
    pub status: SamplingRunStatus,
    /// Sample count
    pub sample_count: usize,
    /// Passed count
    pub passed_count: usize,
    /// Failed count
    pub failed_count: usize,
    /// Individual results
    pub results: Vec<SampleResult>,
    /// Started at
    pub started_at: DateTime<Utc>,
    /// Completed at
    pub completed_at: Option<DateTime<Utc>>,
    /// Must-open trigger (if any)
    pub must_open_trigger: Option<MustOpenTrigger>,
    /// Sampling strategy used
    pub strategy: SamplingStrategy,
}

impl SamplingRun {
    /// Create a new sampling run
    pub fn new(sample_count: usize, strategy: SamplingStrategy) -> Self {
        Self {
            run_id: format!("run:{}", Uuid::new_v4()),
            status: SamplingRunStatus::Scheduled,
            sample_count,
            passed_count: 0,
            failed_count: 0,
            results: Vec::new(),
            started_at: Utc::now(),
            completed_at: None,
            must_open_trigger: None,
            strategy,
        }
    }

    /// Record a sample result
    pub fn record_result(&mut self, result: SampleResult) {
        if result.passed {
            self.passed_count += 1;
        } else {
            self.failed_count += 1;
        }
        self.results.push(result);
    }

    /// Calculate pass rate
    pub fn pass_rate(&self) -> f64 {
        if self.results.is_empty() {
            0.0
        } else {
            self.passed_count as f64 / self.results.len() as f64
        }
    }
}

/// Sampling strategy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SamplingStrategy {
    /// Uniform random sampling
    UniformRandom {
        /// Sample rate (0.0 - 1.0)
        rate: f64,
    },
    /// Stratified by temperature tier
    StratifiedByTemperature {
        /// Hot tier rate
        hot_rate: f64,
        /// Warm tier rate
        warm_rate: f64,
        /// Cold tier rate
        cold_rate: f64,
    },
    /// Age-biased (newer payloads sampled more)
    AgeBiased {
        /// Base rate
        base_rate: f64,
        /// Age decay factor
        decay_factor: f64,
    },
    /// Risk-based (higher risk = more sampling)
    RiskBased {
        /// Base rate
        base_rate: f64,
        /// Risk multiplier
        risk_multiplier: f64,
    },
    /// Fixed sample count
    FixedCount {
        /// Number of samples
        count: usize,
    },
}

impl Default for SamplingStrategy {
    fn default() -> Self {
        Self::UniformRandom { rate: 0.01 } // 1% default
    }
}

/// Must-open trigger record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MustOpenTrigger {
    /// Trigger ID
    pub trigger_id: String,
    /// Triggering run ID
    pub run_id: String,
    /// Trigger reason
    pub reason: MustOpenReason,
    /// Affected payload ref_ids
    pub affected_payloads: Vec<String>,
    /// Trigger timestamp
    pub triggered_at: DateTime<Utc>,
    /// Escalation level
    pub escalation_level: EscalationLevel,
    /// Current status
    pub status: MustOpenStatus,
    /// Assigned investigators
    pub investigators: Vec<ActorId>,
    /// Evidence bundle ID (if generated)
    pub evidence_bundle_id: Option<String>,
    /// Resolution (if resolved)
    pub resolution: Option<MustOpenResolution>,
}

impl MustOpenTrigger {
    /// Create a new must-open trigger
    pub fn new(run_id: String, reason: MustOpenReason, affected_payloads: Vec<String>) -> Self {
        Self {
            trigger_id: format!("must-open:{}", Uuid::new_v4()),
            run_id,
            reason,
            affected_payloads,
            triggered_at: Utc::now(),
            escalation_level: EscalationLevel::Initial,
            status: MustOpenStatus::Pending,
            investigators: Vec::new(),
            evidence_bundle_id: None,
            resolution: None,
        }
    }
}

/// Must-open trigger reason
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MustOpenReason {
    /// Sampling failure rate exceeded threshold
    SamplingFailureThreshold {
        /// Actual failure rate
        failure_rate: f64,
        /// Threshold
        threshold: f64,
    },
    /// Critical integrity failure
    CriticalIntegrityFailure {
        /// Failed ref_ids
        failed_refs: Vec<String>,
        /// Failure details
        details: String,
    },
    /// Data corruption detected
    DataCorruption {
        /// Corrupted ref_ids
        corrupted_refs: Vec<String>,
    },
    /// Suspicious pattern detected
    SuspiciousPattern {
        /// Pattern description
        pattern: String,
        /// Related ref_ids
        related_refs: Vec<String>,
    },
    /// Manual trigger
    ManualTrigger {
        /// Triggered by
        triggered_by: ActorId,
        /// Reason
        reason: String,
    },
}

/// Must-open status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MustOpenStatus {
    /// Pending review
    Pending,
    /// Under investigation
    UnderInvestigation,
    /// Evidence generated
    EvidenceGenerated,
    /// Escalated to authorities
    Escalated,
    /// Resolved
    Resolved,
    /// Dismissed (false positive)
    Dismissed,
}

/// Escalation level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EscalationLevel {
    /// Initial detection
    Initial,
    /// Internal review
    InternalReview,
    /// Compliance team
    Compliance,
    /// Legal team
    Legal,
    /// Regulatory authorities
    Regulatory,
    /// Law enforcement
    LawEnforcement,
}

impl EscalationLevel {
    /// Get next escalation level
    pub fn next(&self) -> Option<Self> {
        match self {
            EscalationLevel::Initial => Some(EscalationLevel::InternalReview),
            EscalationLevel::InternalReview => Some(EscalationLevel::Compliance),
            EscalationLevel::Compliance => Some(EscalationLevel::Legal),
            EscalationLevel::Legal => Some(EscalationLevel::Regulatory),
            EscalationLevel::Regulatory => Some(EscalationLevel::LawEnforcement),
            EscalationLevel::LawEnforcement => None,
        }
    }
}

/// Must-open resolution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MustOpenResolution {
    /// Resolution type
    pub resolution_type: ResolutionType,
    /// Resolution timestamp
    pub resolved_at: DateTime<Utc>,
    /// Resolved by
    pub resolved_by: ActorId,
    /// Resolution notes
    pub notes: String,
    /// Actions taken
    pub actions_taken: Vec<String>,
}

/// Resolution type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResolutionType {
    /// False positive
    FalsePositive,
    /// Data recovered
    DataRecovered,
    /// Data lost (unrecoverable)
    DataLost,
    /// Operator error
    OperatorError,
    /// Malicious activity confirmed
    MaliciousActivity,
    /// Infrastructure failure
    InfrastructureFailure,
    /// Unknown cause
    Unknown,
}

/// Sampling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingConfig {
    /// Sampling strategy
    pub strategy: SamplingStrategy,
    /// Sampling interval (seconds)
    pub interval_secs: u64,
    /// Failure threshold for must-open trigger
    pub failure_threshold: f64,
    /// Minimum samples for statistical significance
    pub min_samples: usize,
    /// Maximum samples per run
    pub max_samples: usize,
    /// Auto-escalate on threshold breach
    pub auto_escalate: bool,
    /// Escalation timeout (hours)
    pub escalation_timeout_hours: u64,
    /// Notification recipients
    pub notification_recipients: Vec<ActorId>,
}

impl Default for SamplingConfig {
    fn default() -> Self {
        Self {
            strategy: SamplingStrategy::default(),
            interval_secs: 3600, // 1 hour
            failure_threshold: 0.01, // 1% failure triggers must-open
            min_samples: 10,
            max_samples: 1000,
            auto_escalate: true,
            escalation_timeout_hours: 24,
            notification_recipients: Vec::new(),
        }
    }
}

/// Payload provider interface for sampling
#[async_trait]
pub trait SamplingPayloadProvider: Send + Sync {
    /// Get all eligible payload ref_ids
    async fn get_eligible_payloads(&self) -> SamplingResult<Vec<PayloadInfo>>;

    /// Get payload data by ref_id
    async fn get_payload_data(&self, ref_id: &str) -> SamplingResult<Vec<u8>>;

    /// Get expected commitment for a payload
    async fn get_commitment(&self, ref_id: &str) -> SamplingResult<Digest>;

    /// Freeze a payload (prevent modifications)
    async fn freeze_payload(&self, ref_id: &str, trigger_id: &str) -> SamplingResult<()>;
}

/// Payload info for sampling selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadInfo {
    /// Payload ref_id
    pub ref_id: String,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Temperature tier
    pub temperature: PayloadTemperature,
    /// Size in bytes
    pub size_bytes: u64,
    /// Risk score (0.0 - 1.0)
    pub risk_score: f64,
}

/// Payload temperature tier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PayloadTemperature {
    Hot,
    Warm,
    Cold,
}

/// Notification handler interface
#[async_trait]
pub trait NotificationHandler: Send + Sync {
    /// Send must-open trigger notification
    async fn notify_must_open(&self, trigger: &MustOpenTrigger) -> SamplingResult<()>;

    /// Send escalation notification
    async fn notify_escalation(&self, trigger: &MustOpenTrigger, level: EscalationLevel) -> SamplingResult<()>;

    /// Send resolution notification
    async fn notify_resolution(&self, trigger: &MustOpenTrigger) -> SamplingResult<()>;
}

/// Sampling audit engine
pub struct SamplingAuditEngine<P: SamplingPayloadProvider, N: NotificationHandler> {
    /// Payload provider
    payload_provider: Arc<P>,
    /// Notification handler
    notification_handler: Arc<N>,
    /// Configuration
    config: RwLock<SamplingConfig>,
    /// Active runs
    active_runs: RwLock<HashMap<String, SamplingRun>>,
    /// Active must-open triggers
    active_triggers: RwLock<HashMap<String, MustOpenTrigger>>,
    /// Run history
    run_history: RwLock<Vec<SamplingRun>>,
}

impl<P: SamplingPayloadProvider, N: NotificationHandler> SamplingAuditEngine<P, N> {
    /// Create a new sampling audit engine
    pub fn new(
        payload_provider: Arc<P>,
        notification_handler: Arc<N>,
        config: SamplingConfig,
    ) -> Self {
        Self {
            payload_provider,
            notification_handler,
            config: RwLock::new(config),
            active_runs: RwLock::new(HashMap::new()),
            active_triggers: RwLock::new(HashMap::new()),
            run_history: RwLock::new(Vec::new()),
        }
    }

    /// Start a sampling run
    pub async fn start_sampling_run(&self) -> SamplingResult<String> {
        let config = self.config.read().await;

        // Select samples
        let payloads = self.payload_provider.get_eligible_payloads().await?;
        let selected = self.select_samples(&payloads, &config.strategy).await?;

        let sample_count = selected.len().min(config.max_samples);
        let mut run = SamplingRun::new(sample_count, config.strategy.clone());
        run.status = SamplingRunStatus::Running;
        let run_id = run.run_id.clone();
        drop(config);

        let mut runs = self.active_runs.write().await;
        runs.insert(run_id.clone(), run);
        drop(runs);

        tracing::info!(run_id = %run_id, sample_count = %sample_count, "Started sampling run");

        Ok(run_id)
    }

    /// Select samples based on strategy
    async fn select_samples(
        &self,
        payloads: &[PayloadInfo],
        strategy: &SamplingStrategy,
    ) -> SamplingResult<Vec<String>> {
        if payloads.is_empty() {
            return Ok(Vec::new());
        }

        let mut rng = rand::thread_rng();
        let selected: Vec<String> = match strategy {
            SamplingStrategy::UniformRandom { rate } => {
                payloads
                    .iter()
                    .filter(|_| rng.gen::<f64>() < *rate)
                    .map(|p| p.ref_id.clone())
                    .collect()
            }
            SamplingStrategy::StratifiedByTemperature { hot_rate, warm_rate, cold_rate } => {
                payloads
                    .iter()
                    .filter(|p| {
                        let rate = match p.temperature {
                            PayloadTemperature::Hot => *hot_rate,
                            PayloadTemperature::Warm => *warm_rate,
                            PayloadTemperature::Cold => *cold_rate,
                        };
                        rng.gen::<f64>() < rate
                    })
                    .map(|p| p.ref_id.clone())
                    .collect()
            }
            SamplingStrategy::AgeBiased { base_rate, decay_factor } => {
                let now = Utc::now();
                payloads
                    .iter()
                    .filter(|p| {
                        let age_days = (now - p.created_at).num_days() as f64;
                        let rate = base_rate * (-decay_factor * age_days).exp();
                        rng.gen::<f64>() < rate
                    })
                    .map(|p| p.ref_id.clone())
                    .collect()
            }
            SamplingStrategy::RiskBased { base_rate, risk_multiplier } => {
                payloads
                    .iter()
                    .filter(|p| {
                        let rate = base_rate * (1.0 + risk_multiplier * p.risk_score);
                        rng.gen::<f64>() < rate
                    })
                    .map(|p| p.ref_id.clone())
                    .collect()
            }
            SamplingStrategy::FixedCount { count } => {
                let mut indices: Vec<usize> = (0..payloads.len()).collect();
                indices.shuffle(&mut rng);
                indices.into_iter()
                    .take(*count)
                    .map(|i| payloads[i].ref_id.clone())
                    .collect()
            }
        };

        Ok(selected)
    }

    /// Execute verification for a run
    pub async fn execute_run(&self, run_id: &str) -> SamplingResult<SamplingRun> {
        let runs = self.active_runs.read().await;
        let run = runs.get(run_id).ok_or_else(|| SamplingError::SelectionFailed {
            reason: format!("Run not found: {}", run_id),
        })?.clone();
        drop(runs);

        // Get payloads to verify
        let payloads = self.payload_provider.get_eligible_payloads().await?;
        let config = self.config.read().await;
        let selected = self.select_samples(&payloads, &run.strategy).await?;
        drop(config);

        // Verify each sample
        let mut updated_run = run.clone();
        for ref_id in selected.iter().take(updated_run.sample_count) {
            let start = std::time::Instant::now();
            let result = self.verify_sample(ref_id).await;
            let duration_ms = start.elapsed().as_millis() as u64;

            let sample_result = match result {
                Ok((expected, actual)) => {
                    if expected == actual {
                        SampleResult {
                            sample_id: format!("sample:{}", Uuid::new_v4()),
                            ref_id: ref_id.clone(),
                            passed: true,
                            failure_reason: None,
                            verified_at: Utc::now(),
                            duration_ms,
                            expected_hash: Some(expected),
                            actual_hash: Some(actual),
                        }
                    } else {
                        SampleResult {
                            sample_id: format!("sample:{}", Uuid::new_v4()),
                            ref_id: ref_id.clone(),
                            passed: false,
                            failure_reason: Some(SamplingFailureReason::HashMismatch {
                                expected: expected.clone(),
                                actual: actual.clone(),
                            }),
                            verified_at: Utc::now(),
                            duration_ms,
                            expected_hash: Some(expected),
                            actual_hash: Some(actual),
                        }
                    }
                }
                Err(e) => {
                    SampleResult {
                        sample_id: format!("sample:{}", Uuid::new_v4()),
                        ref_id: ref_id.clone(),
                        passed: false,
                        failure_reason: Some(match e {
                            SamplingError::PayloadNotFound { .. } => SamplingFailureReason::PayloadNotFound,
                            SamplingError::IntegrityFailed { reason } => {
                                SamplingFailureReason::DataCorruption { details: reason }
                            }
                            _ => SamplingFailureReason::StorageUnavailable,
                        }),
                        verified_at: Utc::now(),
                        duration_ms,
                        expected_hash: None,
                        actual_hash: None,
                    }
                }
            };

            updated_run.record_result(sample_result);
        }

        // Check if must-open should be triggered
        let config = self.config.read().await;
        let failure_rate = updated_run.failed_count as f64 / updated_run.results.len() as f64;

        if failure_rate > config.failure_threshold && updated_run.results.len() >= config.min_samples {
            updated_run.status = SamplingRunStatus::MustOpenTriggered;

            // Trigger must-open
            let failed_refs: Vec<String> = updated_run.results
                .iter()
                .filter(|r| !r.passed)
                .map(|r| r.ref_id.clone())
                .collect();

            let trigger = self.trigger_must_open(
                run_id.to_string(),
                MustOpenReason::SamplingFailureThreshold {
                    failure_rate,
                    threshold: config.failure_threshold,
                },
                failed_refs,
            ).await?;

            updated_run.must_open_trigger = Some(trigger);
        } else {
            updated_run.status = if updated_run.failed_count > 0 {
                SamplingRunStatus::Failed
            } else {
                SamplingRunStatus::Passed
            };
        }
        drop(config);

        updated_run.completed_at = Some(Utc::now());

        // Update storage
        let mut runs = self.active_runs.write().await;
        runs.remove(run_id);
        drop(runs);

        let mut history = self.run_history.write().await;
        history.push(updated_run.clone());

        tracing::info!(
            run_id = %run_id,
            passed = %updated_run.passed_count,
            failed = %updated_run.failed_count,
            status = ?updated_run.status,
            "Sampling run completed"
        );

        Ok(updated_run)
    }

    /// Verify a single sample
    async fn verify_sample(&self, ref_id: &str) -> SamplingResult<(Digest, Digest)> {
        // Get expected commitment
        let expected = self.payload_provider.get_commitment(ref_id).await?;

        // Get actual payload data
        let data = self.payload_provider.get_payload_data(ref_id).await?;

        // Compute actual hash
        let actual = Digest::blake3(&data);

        Ok((expected, actual))
    }

    /// Trigger must-open process
    pub async fn trigger_must_open(
        &self,
        run_id: String,
        reason: MustOpenReason,
        affected_payloads: Vec<String>,
    ) -> SamplingResult<MustOpenTrigger> {
        let trigger = MustOpenTrigger::new(run_id, reason, affected_payloads.clone());
        let trigger_id = trigger.trigger_id.clone();

        // Freeze affected payloads
        for ref_id in &affected_payloads {
            if let Err(e) = self.payload_provider.freeze_payload(ref_id, &trigger_id).await {
                tracing::warn!(ref_id = %ref_id, error = %e, "Failed to freeze payload");
            }
        }

        // Store trigger
        let mut triggers = self.active_triggers.write().await;
        triggers.insert(trigger_id.clone(), trigger.clone());
        drop(triggers);

        // Send notification
        if let Err(e) = self.notification_handler.notify_must_open(&trigger).await {
            tracing::error!(trigger_id = %trigger_id, error = %e, "Failed to send must-open notification");
        }

        tracing::warn!(
            trigger_id = %trigger_id,
            affected_count = %affected_payloads.len(),
            "Must-open triggered"
        );

        Ok(trigger)
    }

    /// Escalate a must-open trigger
    pub async fn escalate_trigger(&self, trigger_id: &str) -> SamplingResult<EscalationLevel> {
        let mut triggers = self.active_triggers.write().await;
        let trigger = triggers.get_mut(trigger_id).ok_or_else(|| SamplingError::EscalationFailed {
            reason: format!("Trigger not found: {}", trigger_id),
        })?;

        let next_level = trigger.escalation_level.next().ok_or_else(|| SamplingError::EscalationFailed {
            reason: "Already at maximum escalation level".to_string(),
        })?;

        trigger.escalation_level = next_level;
        trigger.status = MustOpenStatus::Escalated;

        let trigger_clone = trigger.clone();
        drop(triggers);

        // Send escalation notification
        if let Err(e) = self.notification_handler.notify_escalation(&trigger_clone, next_level).await {
            tracing::error!(trigger_id = %trigger_id, error = %e, "Failed to send escalation notification");
        }

        tracing::warn!(
            trigger_id = %trigger_id,
            level = ?next_level,
            "Must-open escalated"
        );

        Ok(next_level)
    }

    /// Resolve a must-open trigger
    pub async fn resolve_trigger(
        &self,
        trigger_id: &str,
        resolution: MustOpenResolution,
    ) -> SamplingResult<()> {
        let mut triggers = self.active_triggers.write().await;
        let trigger = triggers.get_mut(trigger_id).ok_or_else(|| SamplingError::EscalationFailed {
            reason: format!("Trigger not found: {}", trigger_id),
        })?;

        trigger.status = MustOpenStatus::Resolved;
        trigger.resolution = Some(resolution);

        let trigger_clone = trigger.clone();
        drop(triggers);

        // Send resolution notification
        if let Err(e) = self.notification_handler.notify_resolution(&trigger_clone).await {
            tracing::error!(trigger_id = %trigger_id, error = %e, "Failed to send resolution notification");
        }

        tracing::info!(trigger_id = %trigger_id, "Must-open resolved");

        Ok(())
    }

    /// Assign investigator to a trigger
    pub async fn assign_investigator(
        &self,
        trigger_id: &str,
        investigator: ActorId,
    ) -> SamplingResult<()> {
        let mut triggers = self.active_triggers.write().await;
        let trigger = triggers.get_mut(trigger_id).ok_or_else(|| SamplingError::EscalationFailed {
            reason: format!("Trigger not found: {}", trigger_id),
        })?;

        if trigger.status == MustOpenStatus::Pending {
            trigger.status = MustOpenStatus::UnderInvestigation;
        }
        trigger.investigators.push(investigator.clone());

        tracing::info!(trigger_id = %trigger_id, investigator = %investigator, "Investigator assigned");

        Ok(())
    }

    /// Get active triggers
    pub async fn get_active_triggers(&self) -> Vec<MustOpenTrigger> {
        let triggers = self.active_triggers.read().await;
        triggers.values().cloned().collect()
    }

    /// Get sampling statistics
    pub async fn get_stats(&self) -> SamplingStats {
        let history = self.run_history.read().await;
        let triggers = self.active_triggers.read().await;

        let total_runs = history.len();
        let total_samples: usize = history.iter().map(|r| r.results.len()).sum();
        let total_failures: usize = history.iter().map(|r| r.failed_count).sum();

        SamplingStats {
            total_runs,
            total_samples,
            total_failures,
            overall_failure_rate: if total_samples > 0 {
                total_failures as f64 / total_samples as f64
            } else {
                0.0
            },
            active_triggers: triggers.len(),
            last_run: history.last().map(|r| r.started_at),
            collected_at: Utc::now(),
        }
    }

    /// Update configuration
    pub async fn update_config(&self, config: SamplingConfig) {
        let mut current = self.config.write().await;
        *current = config;
    }
}

/// Sampling statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingStats {
    /// Total sampling runs
    pub total_runs: usize,
    /// Total samples verified
    pub total_samples: usize,
    /// Total failures detected
    pub total_failures: usize,
    /// Overall failure rate
    pub overall_failure_rate: f64,
    /// Active must-open triggers
    pub active_triggers: usize,
    /// Last run timestamp
    pub last_run: Option<DateTime<Utc>>,
    /// Stats collection timestamp
    pub collected_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sampling_run_new() {
        let run = SamplingRun::new(100, SamplingStrategy::default());
        assert_eq!(run.sample_count, 100);
        assert_eq!(run.status, SamplingRunStatus::Scheduled);
        assert!(run.results.is_empty());
    }

    #[test]
    fn test_sampling_run_record_result() {
        let mut run = SamplingRun::new(10, SamplingStrategy::default());

        run.record_result(SampleResult {
            sample_id: "sample:1".to_string(),
            ref_id: "ref:1".to_string(),
            passed: true,
            failure_reason: None,
            verified_at: Utc::now(),
            duration_ms: 100,
            expected_hash: None,
            actual_hash: None,
        });

        assert_eq!(run.passed_count, 1);
        assert_eq!(run.failed_count, 0);
        assert_eq!(run.pass_rate(), 1.0);

        run.record_result(SampleResult {
            sample_id: "sample:2".to_string(),
            ref_id: "ref:2".to_string(),
            passed: false,
            failure_reason: Some(SamplingFailureReason::PayloadNotFound),
            verified_at: Utc::now(),
            duration_ms: 50,
            expected_hash: None,
            actual_hash: None,
        });

        assert_eq!(run.passed_count, 1);
        assert_eq!(run.failed_count, 1);
        assert_eq!(run.pass_rate(), 0.5);
    }

    #[test]
    fn test_escalation_level() {
        let level = EscalationLevel::Initial;
        assert_eq!(level.next(), Some(EscalationLevel::InternalReview));

        let max_level = EscalationLevel::LawEnforcement;
        assert_eq!(max_level.next(), None);
    }

    #[test]
    fn test_must_open_trigger_new() {
        let trigger = MustOpenTrigger::new(
            "run:123".to_string(),
            MustOpenReason::CriticalIntegrityFailure {
                failed_refs: vec!["ref:1".to_string()],
                details: "test".to_string(),
            },
            vec!["ref:1".to_string()],
        );

        assert!(trigger.trigger_id.starts_with("must-open:"));
        assert_eq!(trigger.status, MustOpenStatus::Pending);
        assert_eq!(trigger.escalation_level, EscalationLevel::Initial);
    }

    #[test]
    fn test_sampling_config_default() {
        let config = SamplingConfig::default();
        assert_eq!(config.failure_threshold, 0.01);
        assert_eq!(config.min_samples, 10);
        assert!(config.auto_escalate);
    }
}
