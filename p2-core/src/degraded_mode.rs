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
    /// P1 (L0 Consensus Layer) connection status
    #[serde(default)]
    pub p1_status: P1ConnectionStatus,
    /// Econ subsystem status
    #[serde(default)]
    pub econ_status: EconSubsystemStatus,
}

// ============================================================================
// P1 and Econ Linkage (问题10)
// ============================================================================

/// P1 (L0 Consensus Layer) Connection Status
///
/// Degraded mode MUST consider P1 connection status because:
/// 1. Evidence level A requires P1 receipts
/// 2. Map commits must be anchored to P1
/// 3. High-consequence operations need P1 confirmation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P1ConnectionStatus {
    /// P1 is connected and responsive
    pub connected: bool,
    /// Last successful P1 interaction
    pub last_success: Option<DateTime<Utc>>,
    /// Current P1 endpoint (if connected)
    pub endpoint: Option<String>,
    /// P1 health status
    pub health: P1HealthStatus,
    /// Pending P1 operations count
    pub pending_operations: u32,
    /// Last error (if any)
    pub last_error: Option<String>,
}

impl Default for P1ConnectionStatus {
    fn default() -> Self {
        Self {
            connected: true, // Assume connected initially
            last_success: Some(Utc::now()),
            endpoint: None,
            health: P1HealthStatus::Healthy,
            pending_operations: 0,
            last_error: None,
        }
    }
}

/// P1 health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum P1HealthStatus {
    /// P1 is healthy and responsive
    Healthy,
    /// P1 is slow but operational
    Degraded,
    /// P1 is experiencing issues
    Unhealthy,
    /// P1 is unreachable
    Unreachable,
}

impl Default for P1HealthStatus {
    fn default() -> Self {
        Self::Healthy
    }
}

/// Econ Subsystem Status
///
/// Econ subsystem handles fee schedules, staking, and economic incentives.
/// Its status affects:
/// 1. Fee calculation for operations
/// 2. Staking verification for high-value operations
/// 3. Economic penalty enforcement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconSubsystemStatus {
    /// Econ subsystem is operational
    pub operational: bool,
    /// Current fee schedule version
    pub fee_schedule_version: Option<String>,
    /// Staking verification available
    pub staking_available: bool,
    /// Last sync timestamp
    pub last_sync: Option<DateTime<Utc>>,
    /// Econ health
    pub health: EconHealthStatus,
    /// Pending settlements count
    pub pending_settlements: u32,
}

impl Default for EconSubsystemStatus {
    fn default() -> Self {
        Self {
            operational: true,
            fee_schedule_version: Some("v1".to_string()),
            staking_available: true,
            last_sync: Some(Utc::now()),
            health: EconHealthStatus::Healthy,
            pending_settlements: 0,
        }
    }
}

/// Econ health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EconHealthStatus {
    /// Fully operational
    Healthy,
    /// Operational but degraded
    Degraded,
    /// Limited functionality
    Limited,
    /// Unavailable
    Unavailable,
}

impl Default for EconHealthStatus {
    fn default() -> Self {
        Self::Healthy
    }
}

/// Combined system health for degraded mode decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealthStatus {
    /// DSN (P2) availability
    pub dsn_state: DsnAvailabilityState,
    /// P1 connection status
    pub p1_status: P1ConnectionStatus,
    /// Econ subsystem status
    pub econ_status: EconSubsystemStatus,
    /// Overall system health
    pub overall_health: OverallHealthLevel,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

impl SystemHealthStatus {
    /// Calculate overall health from component statuses
    pub fn calculate(
        dsn_state: DsnAvailabilityState,
        p1_status: &P1ConnectionStatus,
        econ_status: &EconSubsystemStatus,
    ) -> Self {
        let overall_health = Self::compute_overall_health(&dsn_state, p1_status, econ_status);

        Self {
            dsn_state,
            p1_status: p1_status.clone(),
            econ_status: econ_status.clone(),
            overall_health,
            timestamp: Utc::now(),
        }
    }

    fn compute_overall_health(
        dsn_state: &DsnAvailabilityState,
        p1_status: &P1ConnectionStatus,
        econ_status: &EconSubsystemStatus,
    ) -> OverallHealthLevel {
        // If DSN is unavailable, system is critical
        if matches!(dsn_state, DsnAvailabilityState::Unavailable) {
            return OverallHealthLevel::Critical;
        }

        // If P1 is unreachable, system is critical (can't anchor anything)
        if matches!(p1_status.health, P1HealthStatus::Unreachable) || !p1_status.connected {
            return OverallHealthLevel::Critical;
        }

        // If Econ is unavailable, system is degraded (can't process fees)
        if matches!(econ_status.health, EconHealthStatus::Unavailable) || !econ_status.operational {
            return OverallHealthLevel::Degraded;
        }

        // If any component is degraded, overall is degraded
        if matches!(dsn_state, DsnAvailabilityState::Degraded | DsnAvailabilityState::Recovering)
            || matches!(p1_status.health, P1HealthStatus::Degraded | P1HealthStatus::Unhealthy)
            || matches!(econ_status.health, EconHealthStatus::Degraded | EconHealthStatus::Limited)
        {
            return OverallHealthLevel::Degraded;
        }

        OverallHealthLevel::Healthy
    }

    /// Check if system can process high-consequence operations
    pub fn can_process_high_consequence(&self) -> bool {
        matches!(self.overall_health, OverallHealthLevel::Healthy)
            && self.p1_status.connected
            && self.econ_status.staking_available
    }

    /// Check if system can anchor to P1
    pub fn can_anchor_to_p1(&self) -> bool {
        self.p1_status.connected
            && matches!(self.p1_status.health, P1HealthStatus::Healthy | P1HealthStatus::Degraded)
    }

    /// Check if economic operations are available
    pub fn can_process_economic(&self) -> bool {
        self.econ_status.operational
            && matches!(self.econ_status.health, EconHealthStatus::Healthy | EconHealthStatus::Degraded)
    }
}

/// Overall health level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverallHealthLevel {
    /// All systems healthy
    Healthy,
    /// Some systems degraded but operational
    Degraded,
    /// Critical - some operations blocked
    Critical,
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
            p1_status: P1ConnectionStatus::default(),
            econ_status: EconSubsystemStatus::default(),
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

    // ========== P1 and Econ Linkage Methods ==========

    /// Update P1 connection status
    pub async fn update_p1_status(&self, status: P1ConnectionStatus) {
        let mut state = self.state.write().await;
        let old_connected = state.p1_status.connected;
        state.p1_status = status.clone();

        // Auto-trigger degraded mode if P1 becomes unreachable
        if old_connected && !status.connected {
            if state.state == DsnAvailabilityState::Available {
                state.state = DsnAvailabilityState::Degraded;
                state.state_started_at = Utc::now();
                state.reason = "P1 connection lost".to_string();
                self.is_degraded.store(true, Ordering::Release);
                tracing::warn!("Entering degraded mode due to P1 connection loss");
            }
        }
    }

    /// Update Econ subsystem status
    pub async fn update_econ_status(&self, status: EconSubsystemStatus) {
        let mut state = self.state.write().await;
        let old_operational = state.econ_status.operational;
        state.econ_status = status.clone();

        // Auto-trigger degraded mode if Econ becomes unavailable
        if old_operational && !status.operational {
            if state.state == DsnAvailabilityState::Available {
                state.state = DsnAvailabilityState::Degraded;
                state.state_started_at = Utc::now();
                state.reason = "Econ subsystem unavailable".to_string();
                self.is_degraded.store(true, Ordering::Release);
                tracing::warn!("Entering degraded mode due to Econ subsystem unavailability");
            }
        }
    }

    /// Get combined system health status
    pub async fn get_system_health(&self) -> SystemHealthStatus {
        let state = self.state.read().await;
        SystemHealthStatus::calculate(
            state.state,
            &state.p1_status,
            &state.econ_status,
        )
    }

    /// Check if high-consequence operations are allowed
    pub async fn can_high_consequence(&self) -> bool {
        let health = self.get_system_health().await;
        health.can_process_high_consequence()
    }

    /// Check if P1 anchoring is available
    pub async fn can_anchor_p1(&self) -> bool {
        let health = self.get_system_health().await;
        health.can_anchor_to_p1()
    }

    /// Check if economic operations are available
    pub async fn can_economic(&self) -> bool {
        let health = self.get_system_health().await;
        health.can_process_economic()
    }

    /// Check operation considering all system health factors
    pub async fn check_operation_full(&self, operation: OperationType) -> DegradedModeResult<OperationCheckResult> {
        let health = self.get_system_health().await;

        // High-consequence operations need full system health
        if operation.is_high_consequence() && !health.can_process_high_consequence() {
            return Err(DegradedModeError::OperationSuspended(
                format!("{:?} requires full system health (P1 connected, Econ available)", operation)
            ));
        }

        // Operations requiring P1 anchoring
        if operation.requires_full_dsn() && !health.can_anchor_to_p1() {
            return Err(DegradedModeError::OperationSuspended(
                format!("{:?} requires P1 connectivity for anchoring", operation)
            ));
        }

        // Check DSN-specific restrictions
        let dsn_check = self.check_operation(operation).await?;

        Ok(OperationCheckResult {
            operation,
            check: dsn_check,
            system_health: health,
            restrictions: self.get_active_restrictions(&operation).await,
        })
    }

    /// Get active restrictions for an operation
    async fn get_active_restrictions(&self, operation: &OperationType) -> Vec<OperationRestriction> {
        let health = self.get_system_health().await;
        let mut restrictions = Vec::new();

        if matches!(health.overall_health, OverallHealthLevel::Critical) {
            restrictions.push(OperationRestriction::SystemCritical);
        }

        if !health.p1_status.connected {
            restrictions.push(OperationRestriction::P1Unavailable);
        }

        if !health.econ_status.operational {
            restrictions.push(OperationRestriction::EconUnavailable);
        }

        if matches!(health.dsn_state, DsnAvailabilityState::Degraded | DsnAvailabilityState::Unavailable) {
            restrictions.push(OperationRestriction::DsnDegraded);
        }

        if operation.is_high_consequence() && !health.econ_status.staking_available {
            restrictions.push(OperationRestriction::StakingRequired);
        }

        restrictions
    }
}

/// Full operation check result with system health context
#[derive(Debug, Clone)]
pub struct OperationCheckResult {
    /// Operation being checked
    pub operation: OperationType,
    /// Basic DSN check result
    pub check: OperationCheck,
    /// Current system health
    pub system_health: SystemHealthStatus,
    /// Active restrictions
    pub restrictions: Vec<OperationRestriction>,
}

impl OperationCheckResult {
    /// Check if operation is fully allowed without restrictions
    pub fn is_fully_allowed(&self) -> bool {
        self.check.is_allowed() && self.restrictions.is_empty()
    }

    /// Check if operation is allowed (possibly with restrictions)
    pub fn is_allowed(&self) -> bool {
        self.check.is_allowed()
    }

    /// Get human-readable summary
    pub fn summary(&self) -> String {
        if self.is_fully_allowed() {
            format!("{:?}: Allowed", self.operation)
        } else if self.is_allowed() {
            format!("{:?}: Allowed with restrictions: {:?}", self.operation, self.restrictions)
        } else {
            format!("{:?}: Blocked, restrictions: {:?}", self.operation, self.restrictions)
        }
    }
}

/// Operation restrictions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationRestriction {
    /// System in critical state
    SystemCritical,
    /// P1 (L0) unavailable
    P1Unavailable,
    /// Econ subsystem unavailable
    EconUnavailable,
    /// DSN (P2) degraded
    DsnDegraded,
    /// Staking required but unavailable
    StakingRequired,
    /// Consent required
    ConsentRequired,
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
    /// Ticket replay started
    TicketReplayStarted,
    /// Ticket replay completed
    TicketReplayCompleted,
}

// ============================================================================
// Ticket Replay System (问题11)
// ============================================================================

/// Ticket operation recorded during degraded mode
///
/// When operating in degraded mode, ticket operations that couldn't be
/// fully verified against P1 are recorded for later replay/reconciliation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegradedModeTicketOperation {
    /// Operation ID
    pub operation_id: String,
    /// Ticket ID
    pub ticket_id: String,
    /// Operation type
    pub operation_type: TicketOperationType,
    /// Actor who performed the operation
    pub actor: String,
    /// Target resource
    pub target_resource: String,
    /// Operation timestamp
    pub timestamp: DateTime<Utc>,
    /// Consent used
    pub consent_used: bool,
    /// Operation details digest (for verification)
    pub details_digest: Digest,
    /// Replay status
    pub replay_status: TicketReplayStatus,
    /// Local validation passed
    pub local_validation_passed: bool,
}

/// Ticket operation type during degraded mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketOperationType {
    /// Ticket issued
    Issue,
    /// Ticket used for access
    Use,
    /// Ticket revoked
    Revoke,
    /// Ticket refreshed
    Refresh,
}

/// Ticket replay status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketReplayStatus {
    /// Pending replay
    Pending,
    /// Currently being replayed
    InProgress,
    /// Replay successful - operation reconciled
    Reconciled,
    /// Replay failed - conflict detected
    Conflict,
    /// Replay skipped - not needed
    Skipped,
}

/// Ticket replay result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketReplayResult {
    /// Total operations to replay
    pub total_operations: u32,
    /// Successfully reconciled
    pub reconciled: u32,
    /// Conflicts detected
    pub conflicts: u32,
    /// Skipped (not needed)
    pub skipped: u32,
    /// Failed operations
    pub failed: u32,
    /// Conflict details
    pub conflict_details: Vec<TicketConflict>,
    /// Replay started at
    pub started_at: DateTime<Utc>,
    /// Replay completed at
    pub completed_at: Option<DateTime<Utc>>,
    /// Replay duration (ms)
    pub duration_ms: Option<i64>,
}

impl TicketReplayResult {
    /// Create a new replay result
    pub fn new(total_operations: u32) -> Self {
        Self {
            total_operations,
            reconciled: 0,
            conflicts: 0,
            skipped: 0,
            failed: 0,
            conflict_details: Vec::new(),
            started_at: Utc::now(),
            completed_at: None,
            duration_ms: None,
        }
    }

    /// Mark as completed
    pub fn complete(&mut self) {
        self.completed_at = Some(Utc::now());
        self.duration_ms = Some((Utc::now() - self.started_at).num_milliseconds());
    }

    /// Check if replay was successful (no conflicts or failures)
    pub fn is_successful(&self) -> bool {
        self.conflicts == 0 && self.failed == 0
    }

    /// Get success rate
    pub fn success_rate(&self) -> f64 {
        if self.total_operations == 0 {
            return 1.0;
        }
        (self.reconciled + self.skipped) as f64 / self.total_operations as f64
    }
}

/// Ticket conflict during replay
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketConflict {
    /// Operation ID
    pub operation_id: String,
    /// Ticket ID
    pub ticket_id: String,
    /// Conflict type
    pub conflict_type: TicketConflictType,
    /// Description
    pub description: String,
    /// Resolution strategy
    pub resolution: Option<TicketConflictResolution>,
}

/// Types of ticket conflicts
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketConflictType {
    /// Ticket was revoked on P1 during degraded mode
    RevokedOnP1,
    /// Ticket expired during degraded mode
    Expired,
    /// Usage count exceeded
    UsageExceeded,
    /// Consent was withdrawn
    ConsentWithdrawn,
    /// Resource was modified
    ResourceModified,
    /// P1 state doesn't match local state
    StateMismatch,
}

/// Conflict resolution strategies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketConflictResolution {
    /// Accept local operation (degraded mode wins)
    AcceptLocal,
    /// Accept P1 state (P1 wins)
    AcceptP1,
    /// Require manual resolution
    ManualResolution,
    /// Compensate (undo local operation)
    Compensate,
}

/// Ticket replay queue
#[derive(Debug, Default)]
pub struct TicketReplayQueue {
    /// Queued operations
    operations: Vec<DegradedModeTicketOperation>,
    /// Queue locked (replay in progress)
    locked: bool,
}

impl TicketReplayQueue {
    /// Create a new replay queue
    pub fn new() -> Self {
        Self::default()
    }

    /// Add operation to queue
    pub fn enqueue(&mut self, operation: DegradedModeTicketOperation) {
        if !self.locked {
            self.operations.push(operation);
        }
    }

    /// Get pending operations count
    pub fn pending_count(&self) -> usize {
        self.operations.iter()
            .filter(|op| matches!(op.replay_status, TicketReplayStatus::Pending))
            .count()
    }

    /// Lock queue for replay
    pub fn lock(&mut self) {
        self.locked = true;
    }

    /// Unlock queue
    pub fn unlock(&mut self) {
        self.locked = false;
    }

    /// Clear completed operations
    pub fn clear_completed(&mut self) {
        self.operations.retain(|op| {
            matches!(op.replay_status, TicketReplayStatus::Pending | TicketReplayStatus::InProgress)
        });
    }

    /// Get all operations for replay
    pub fn get_pending_operations(&self) -> Vec<&DegradedModeTicketOperation> {
        self.operations.iter()
            .filter(|op| matches!(op.replay_status, TicketReplayStatus::Pending))
            .collect()
    }

    /// Update operation status
    pub fn update_status(&mut self, operation_id: &str, status: TicketReplayStatus) {
        if let Some(op) = self.operations.iter_mut().find(|op| op.operation_id == operation_id) {
            op.replay_status = status;
        }
    }
}

/// Ticket replay configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketReplayConfig {
    /// Auto-replay on recovery
    pub auto_replay: bool,
    /// Maximum replay batch size
    pub max_batch_size: u32,
    /// Conflict resolution strategy
    pub default_resolution: TicketConflictResolution,
    /// Require manual approval for conflicts
    pub require_manual_conflict_approval: bool,
    /// Replay timeout (seconds)
    pub replay_timeout_seconds: u32,
}

impl Default for TicketReplayConfig {
    fn default() -> Self {
        Self {
            auto_replay: true,
            max_batch_size: 100,
            default_resolution: TicketConflictResolution::AcceptP1,
            require_manual_conflict_approval: true,
            replay_timeout_seconds: 300, // 5 minutes
        }
    }
}

use l0_core::types::Digest;

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
