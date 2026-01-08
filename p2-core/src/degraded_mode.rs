//! DSN Degraded Mode Handler
//!
//! Implements the DSN Down degradation matrix as defined in DSN documentation Chapter 9.
//!
//! When DSN (P2 storage layer) is unavailable, the system MUST:
//! 1. **Prohibit plaintext expansion and export** - No decrypt/expand operations allowed
//! 2. **Allow digest-only progression** - Operations can proceed with digests only
//! 3. **Suspend high-consequence operations** - Certain operations must be suspended
//!
//! This ensures consistency and accountability even during DSN outages.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

/// Degraded mode errors
#[derive(Debug, Error)]
pub enum DegradedModeError {
    /// Operation not allowed in degraded mode
    #[error("Operation '{0}' not allowed in degraded mode")]
    OperationNotAllowed(String),

    /// DSN unavailable
    #[error("DSN is unavailable: {0}")]
    DsnUnavailable(String),

    /// Operation suspended
    #[error("Operation suspended until DSN recovery: {0}")]
    OperationSuspended(String),

    /// Consent required for degraded operation
    #[error("Explicit consent required for degraded operation: {0}")]
    ConsentRequired(String),

    /// State transition error
    #[error("Invalid state transition: {0}")]
    InvalidTransition(String),
}

/// Result type for degraded mode operations
pub type DegradedModeResult<T> = Result<T, DegradedModeError>;

/// DSN availability state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DsnAvailabilityState {
    /// DSN is fully available
    Available,
    /// DSN is partially available (some operations may be slow)
    Degraded,
    /// DSN is unavailable
    Unavailable,
    /// DSN is recovering (transitioning from unavailable to available)
    Recovering,
}

impl Default for DsnAvailabilityState {
    fn default() -> Self {
        Self::Available
    }
}

impl DsnAvailabilityState {
    /// Check if any operations are restricted
    pub fn has_restrictions(&self) -> bool {
        !matches!(self, Self::Available)
    }

    /// Check if DSN is fully operational
    pub fn is_operational(&self) -> bool {
        matches!(self, Self::Available)
    }
}

/// Operation type for degraded mode checking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationType {
    /// Decrypt/expand payload
    Decrypt,
    /// Export payload to external system
    Export,
    /// Read payload content
    Read,
    /// Write new payload
    Write,
    /// Digest-only verification
    DigestVerify,
    /// Create snapshot
    CreateSnapshot,
    /// Issue access ticket
    IssueTicket,
    /// Use access ticket
    UseTicket,
    /// Tombstone (delete)
    Tombstone,
    /// Evidence bundle submission
    SubmitEvidence,
    /// High-consequence verdict
    HighConsequenceVerdict,
    /// Clawback operation
    Clawback,
}

impl OperationType {
    /// Check if this operation requires full DSN availability
    pub fn requires_full_dsn(&self) -> bool {
        matches!(
            self,
            Self::Decrypt
                | Self::Export
                | Self::Read
                | Self::HighConsequenceVerdict
                | Self::Clawback
        )
    }

    /// Check if this operation can proceed in degraded mode
    pub fn allowed_in_degraded(&self) -> bool {
        matches!(
            self,
            Self::DigestVerify | Self::Write | Self::CreateSnapshot
        )
    }

    /// Check if this is a high-consequence operation
    pub fn is_high_consequence(&self) -> bool {
        matches!(self, Self::HighConsequenceVerdict | Self::Clawback | Self::Tombstone)
    }
}

/// Degraded mode policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegradedModePolicy {
    /// Operations allowed in degraded mode
    pub allowed_operations: HashSet<OperationType>,
    /// Operations that require explicit consent in degraded mode
    pub consent_required_operations: HashSet<OperationType>,
    /// Operations that are always suspended when unavailable
    pub suspended_operations: HashSet<OperationType>,
    /// Maximum time to stay in degraded mode before escalation
    pub max_degraded_duration: Duration,
    /// Grace period before entering degraded mode
    pub grace_period: Duration,
    /// Auto-recovery enabled
    pub auto_recovery_enabled: bool,
}

impl Default for DegradedModePolicy {
    fn default() -> Self {
        let mut allowed = HashSet::new();
        allowed.insert(OperationType::DigestVerify);
        allowed.insert(OperationType::Write);
        allowed.insert(OperationType::CreateSnapshot);

        let mut consent_required = HashSet::new();
        consent_required.insert(OperationType::IssueTicket);
        consent_required.insert(OperationType::UseTicket);

        let mut suspended = HashSet::new();
        suspended.insert(OperationType::Decrypt);
        suspended.insert(OperationType::Export);
        suspended.insert(OperationType::Read);
        suspended.insert(OperationType::HighConsequenceVerdict);
        suspended.insert(OperationType::Clawback);

        Self {
            allowed_operations: allowed,
            consent_required_operations: consent_required,
            suspended_operations: suspended,
            max_degraded_duration: Duration::hours(24),
            grace_period: Duration::minutes(5),
            auto_recovery_enabled: true,
        }
    }
}

/// Degraded mode state tracker
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegradedModeState {
    /// Current availability state
    pub state: DsnAvailabilityState,
    /// When this state started
    pub state_started_at: DateTime<Utc>,
    /// Reason for current state
    pub reason: String,
    /// Operations blocked since state change
    pub blocked_operations: u64,
    /// Operations allowed since state change
    pub allowed_operations: u64,
    /// Last health check timestamp
    pub last_health_check: DateTime<Utc>,
    /// Consecutive health check failures
    pub consecutive_failures: u32,
    /// Queued operations (pending DSN recovery)
    pub queued_operations: u64,
}

impl Default for DegradedModeState {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            state: DsnAvailabilityState::Available,
            state_started_at: now,
            reason: "Initial state".to_string(),
            blocked_operations: 0,
            allowed_operations: 0,
            last_health_check: now,
            consecutive_failures: 0,
            queued_operations: 0,
        }
    }
}

impl DegradedModeState {
    /// Get duration in current state
    pub fn state_duration(&self) -> Duration {
        Utc::now().signed_duration_since(self.state_started_at)
    }
}

/// Degraded Mode Manager
///
/// Central manager for handling DSN degraded mode.
/// All operations that interact with P2 storage should check with this manager.
pub struct DegradedModeManager {
    /// Current state
    state: Arc<RwLock<DegradedModeState>>,
    /// Policy
    policy: Arc<RwLock<DegradedModePolicy>>,
    /// Is in degraded mode (fast atomic check)
    is_degraded: Arc<AtomicBool>,
    /// Explicit consents (operation -> actor IDs that consented)
    consents: Arc<RwLock<std::collections::HashMap<String, HashSet<String>>>>,
}

impl DegradedModeManager {
    /// Create a new manager
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(DegradedModeState::default())),
            policy: Arc::new(RwLock::new(DegradedModePolicy::default())),
            is_degraded: Arc::new(AtomicBool::new(false)),
            consents: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Create with custom policy
    pub fn with_policy(policy: DegradedModePolicy) -> Self {
        Self {
            state: Arc::new(RwLock::new(DegradedModeState::default())),
            policy: Arc::new(RwLock::new(policy)),
            is_degraded: Arc::new(AtomicBool::new(false)),
            consents: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Check if operation is allowed
    pub async fn check_operation(&self, operation: OperationType) -> DegradedModeResult<OperationCheck> {
        // Fast path: not in degraded mode
        if !self.is_degraded.load(Ordering::Relaxed) {
            return Ok(OperationCheck::Allowed);
        }

        let state = self.state.read().await;
        let policy = self.policy.read().await;

        match state.state {
            DsnAvailabilityState::Available => {
                Ok(OperationCheck::Allowed)
            }
            DsnAvailabilityState::Degraded | DsnAvailabilityState::Recovering => {
                if policy.allowed_operations.contains(&operation) {
                    Ok(OperationCheck::AllowedDegraded)
                } else if policy.consent_required_operations.contains(&operation) {
                    Ok(OperationCheck::RequiresConsent)
                } else if policy.suspended_operations.contains(&operation) {
                    Err(DegradedModeError::OperationSuspended(
                        format!("{:?} is suspended during degraded mode", operation)
                    ))
                } else {
                    Ok(OperationCheck::AllowedDegraded)
                }
            }
            DsnAvailabilityState::Unavailable => {
                if policy.allowed_operations.contains(&operation) {
                    Ok(OperationCheck::AllowedDegraded)
                } else {
                    Err(DegradedModeError::OperationNotAllowed(
                        format!("{:?} not allowed when DSN is unavailable", operation)
                    ))
                }
            }
        }
    }

    /// Check operation with consent
    pub async fn check_operation_with_consent(
        &self,
        operation: OperationType,
        actor_id: &str,
    ) -> DegradedModeResult<OperationCheck> {
        let check = self.check_operation(operation).await?;

        if check == OperationCheck::RequiresConsent {
            let consents = self.consents.read().await;
            let key = format!("{:?}", operation);
            if let Some(actors) = consents.get(&key) {
                if actors.contains(actor_id) {
                    return Ok(OperationCheck::AllowedWithConsent);
                }
            }
            Err(DegradedModeError::ConsentRequired(
                format!("{:?} requires explicit consent in degraded mode", operation)
            ))
        } else {
            Ok(check)
        }
    }

    /// Record consent for degraded operation
    pub async fn record_consent(&self, operation: OperationType, actor_id: &str) {
        let mut consents = self.consents.write().await;
        let key = format!("{:?}", operation);
        consents
            .entry(key)
            .or_insert_with(HashSet::new)
            .insert(actor_id.to_string());
    }

    /// Enter degraded mode
    pub async fn enter_degraded_mode(&self, reason: &str) -> DegradedModeResult<()> {
        let mut state = self.state.write().await;

        if state.state == DsnAvailabilityState::Available {
            state.state = DsnAvailabilityState::Degraded;
            state.state_started_at = Utc::now();
            state.reason = reason.to_string();
            self.is_degraded.store(true, Ordering::Release);

            tracing::warn!("Entering degraded mode: {}", reason);
            Ok(())
        } else {
            Err(DegradedModeError::InvalidTransition(
                format!("Cannot enter degraded mode from {:?}", state.state)
            ))
        }
    }

    /// Enter unavailable mode
    pub async fn enter_unavailable_mode(&self, reason: &str) -> DegradedModeResult<()> {
        let mut state = self.state.write().await;

        if matches!(state.state, DsnAvailabilityState::Available | DsnAvailabilityState::Degraded) {
            state.state = DsnAvailabilityState::Unavailable;
            state.state_started_at = Utc::now();
            state.reason = reason.to_string();
            self.is_degraded.store(true, Ordering::Release);

            tracing::error!("DSN unavailable: {}", reason);
            Ok(())
        } else {
            Err(DegradedModeError::InvalidTransition(
                format!("Cannot enter unavailable mode from {:?}", state.state)
            ))
        }
    }

    /// Start recovery
    pub async fn start_recovery(&self) -> DegradedModeResult<()> {
        let mut state = self.state.write().await;

        if state.state == DsnAvailabilityState::Unavailable {
            state.state = DsnAvailabilityState::Recovering;
            state.state_started_at = Utc::now();
            state.reason = "Recovery initiated".to_string();

            tracing::info!("DSN recovery initiated");
            Ok(())
        } else {
            Err(DegradedModeError::InvalidTransition(
                format!("Cannot start recovery from {:?}", state.state)
            ))
        }
    }

    /// Complete recovery and return to available
    pub async fn complete_recovery(&self) -> DegradedModeResult<()> {
        let mut state = self.state.write().await;

        if matches!(state.state, DsnAvailabilityState::Recovering | DsnAvailabilityState::Degraded) {
            state.state = DsnAvailabilityState::Available;
            state.state_started_at = Utc::now();
            state.reason = "Recovery complete".to_string();
            state.consecutive_failures = 0;
            self.is_degraded.store(false, Ordering::Release);

            // Clear queued operations counter (they should be processed now)
            state.queued_operations = 0;

            // Clear consents
            self.consents.write().await.clear();

            tracing::info!("DSN recovery complete, returning to normal operation");
            Ok(())
        } else {
            Err(DegradedModeError::InvalidTransition(
                format!("Cannot complete recovery from {:?}", state.state)
            ))
        }
    }

    /// Record health check result
    pub async fn record_health_check(&self, healthy: bool) {
        let mut state = self.state.write().await;
        state.last_health_check = Utc::now();

        if healthy {
            state.consecutive_failures = 0;
        } else {
            state.consecutive_failures += 1;
        }
    }

    /// Record blocked operation
    pub async fn record_blocked_operation(&self) {
        let mut state = self.state.write().await;
        state.blocked_operations += 1;
    }

    /// Record allowed operation
    pub async fn record_allowed_operation(&self) {
        let mut state = self.state.write().await;
        state.allowed_operations += 1;
    }

    /// Queue operation for later execution
    pub async fn queue_operation(&self) {
        let mut state = self.state.write().await;
        state.queued_operations += 1;
    }

    /// Get current state
    pub async fn get_state(&self) -> DegradedModeState {
        self.state.read().await.clone()
    }

    /// Get current availability
    pub async fn get_availability(&self) -> DsnAvailabilityState {
        self.state.read().await.state
    }

    /// Quick check if in degraded mode
    pub fn is_degraded(&self) -> bool {
        self.is_degraded.load(Ordering::Relaxed)
    }

    /// Get policy
    pub async fn get_policy(&self) -> DegradedModePolicy {
        self.policy.read().await.clone()
    }

    /// Update policy
    pub async fn update_policy(&self, policy: DegradedModePolicy) {
        *self.policy.write().await = policy;
    }
}

impl Default for DegradedModeManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Operation check result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationCheck {
    /// Operation is fully allowed
    Allowed,
    /// Operation allowed in degraded mode
    AllowedDegraded,
    /// Operation allowed with prior consent
    AllowedWithConsent,
    /// Operation requires explicit consent
    RequiresConsent,
}

impl OperationCheck {
    /// Check if operation is allowed
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed | Self::AllowedDegraded | Self::AllowedWithConsent)
    }
}

/// Degraded mode event for logging/auditing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegradedModeEvent {
    /// Event ID
    pub event_id: String,
    /// Event type
    pub event_type: DegradedModeEventType,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Previous state
    pub previous_state: Option<DsnAvailabilityState>,
    /// New state
    pub new_state: DsnAvailabilityState,
    /// Reason
    pub reason: String,
    /// Actor (if applicable)
    pub actor: Option<String>,
}

/// Degraded mode event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradedModeEventType {
    /// State changed
    StateChanged,
    /// Operation blocked
    OperationBlocked,
    /// Operation allowed in degraded mode
    OperationAllowedDegraded,
    /// Consent recorded
    ConsentRecorded,
    /// Recovery started
    RecoveryStarted,
    /// Recovery completed
    RecoveryCompleted,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_type_requirements() {
        assert!(OperationType::Decrypt.requires_full_dsn());
        assert!(OperationType::Export.requires_full_dsn());
        assert!(!OperationType::DigestVerify.requires_full_dsn());
        assert!(!OperationType::Write.requires_full_dsn());

        assert!(OperationType::DigestVerify.allowed_in_degraded());
        assert!(!OperationType::Decrypt.allowed_in_degraded());

        assert!(OperationType::HighConsequenceVerdict.is_high_consequence());
        assert!(OperationType::Clawback.is_high_consequence());
    }

    #[tokio::test]
    async fn test_degraded_mode_manager() {
        let manager = DegradedModeManager::new();

        // Initially available
        assert!(!manager.is_degraded());
        let check = manager.check_operation(OperationType::Decrypt).await;
        assert!(check.is_ok());

        // Enter degraded mode
        manager.enter_degraded_mode("Test degradation").await.unwrap();
        assert!(manager.is_degraded());

        // Decrypt should be blocked
        let check = manager.check_operation(OperationType::Decrypt).await;
        assert!(check.is_err());

        // DigestVerify should be allowed
        let check = manager.check_operation(OperationType::DigestVerify).await;
        assert!(check.is_ok());
    }

    #[tokio::test]
    async fn test_recovery_flow() {
        let manager = DegradedModeManager::new();

        // Enter unavailable
        manager.enter_unavailable_mode("DSN down").await.unwrap();
        assert_eq!(manager.get_availability().await, DsnAvailabilityState::Unavailable);

        // Start recovery
        manager.start_recovery().await.unwrap();
        assert_eq!(manager.get_availability().await, DsnAvailabilityState::Recovering);

        // Complete recovery
        manager.complete_recovery().await.unwrap();
        assert_eq!(manager.get_availability().await, DsnAvailabilityState::Available);
        assert!(!manager.is_degraded());
    }

    #[tokio::test]
    async fn test_consent_flow() {
        let manager = DegradedModeManager::new();
        manager.enter_degraded_mode("Test").await.unwrap();

        // Record consent
        manager.record_consent(OperationType::IssueTicket, "actor:001").await;

        // Check with consent
        let check = manager.check_operation_with_consent(
            OperationType::IssueTicket,
            "actor:001"
        ).await;
        assert!(check.is_ok());

        // Check without consent (different actor)
        let check = manager.check_operation_with_consent(
            OperationType::IssueTicket,
            "actor:002"
        ).await;
        assert!(check.is_err());
    }

    #[test]
    fn test_default_policy() {
        let policy = DegradedModePolicy::default();

        assert!(policy.allowed_operations.contains(&OperationType::DigestVerify));
        assert!(policy.suspended_operations.contains(&OperationType::Decrypt));
        assert!(policy.consent_required_operations.contains(&OperationType::IssueTicket));
    }
}
