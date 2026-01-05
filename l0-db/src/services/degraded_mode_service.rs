//! Degraded Mode Service
//!
//! Manages operational mode transitions and recovery actions.

use async_trait::async_trait;
use chrono::Utc;
use l0_core::error::LedgerError;
use l0_core::ledger::LedgerResult;
use l0_core::types::{
    ActorId, DegradationLevel, DegradedEventType, DegradedModeEvent, DegradedModePolicy,
    DegradedModeStatus, DegradedReason, OperationalMode, OperationType, RecoveryAction,
    RecoveryActionStatus, RecoveryActionType,
};
use soulbase_storage::surreal::SurrealDatastore;
use soulbase_storage::Datastore;
use soulbase_types::prelude::TenantId;
use std::sync::{Arc, RwLock};

/// Degraded Mode Ledger trait
#[async_trait]
pub trait DegradedModeLedger: Send + Sync {
    /// Get current status
    async fn get_status(&self) -> LedgerResult<DegradedModeStatus>;

    /// Update metrics and potentially change mode
    async fn update_metrics(
        &self,
        active_signers: u32,
        network_health: u8,
        consensus_rate: u8,
    ) -> LedgerResult<DegradedModeStatus>;

    /// Manually set operational mode
    async fn set_mode(
        &self,
        mode: OperationalMode,
        reasons: Vec<DegradedReason>,
        triggered_by: &ActorId,
        details: &str,
    ) -> LedgerResult<DegradedModeEvent>;

    /// Check if operation is allowed
    async fn can_perform_operation(&self, op_type: OperationType) -> LedgerResult<bool>;

    /// Initiate recovery action
    async fn initiate_recovery(
        &self,
        action_type: RecoveryActionType,
        initiated_by: &ActorId,
        target: Option<&str>,
    ) -> LedgerResult<RecoveryAction>;

    /// Complete recovery action
    async fn complete_recovery(
        &self,
        action_id: &str,
        status: RecoveryActionStatus,
        result: Option<&str>,
    ) -> LedgerResult<RecoveryAction>;

    /// Get recent events
    async fn get_recent_events(&self, limit: usize) -> LedgerResult<Vec<DegradedModeEvent>>;

    /// Get active recovery actions
    async fn get_active_recoveries(&self) -> LedgerResult<Vec<RecoveryAction>>;

    /// Update policy
    async fn update_policy(&self, policy: DegradedModePolicy) -> LedgerResult<()>;

    /// Get current policy
    async fn get_policy(&self) -> LedgerResult<DegradedModePolicy>;
}

/// Degraded Mode Service implementation
pub struct DegradedModeService {
    datastore: Arc<SurrealDatastore>,
    tenant_id: TenantId,
    status: RwLock<DegradedModeStatus>,
    policy: RwLock<DegradedModePolicy>,
    events: RwLock<Vec<DegradedModeEvent>>,
    recoveries: RwLock<Vec<RecoveryAction>>,
    sequence: std::sync::atomic::AtomicU64,
    consecutive_healthy_epochs: std::sync::atomic::AtomicU32,
}

impl DegradedModeService {
    pub fn new(datastore: Arc<SurrealDatastore>, tenant_id: TenantId) -> Self {
        let now = Utc::now();
        Self {
            datastore,
            tenant_id,
            status: RwLock::new(DegradedModeStatus {
                mode: OperationalMode::Normal,
                active_reasons: Vec::new(),
                level: DegradationLevel::Minor,
                started_at: None,
                expected_resolution: None,
                active_signers: 9,
                required_signers: 9,
                network_health: 100,
                consensus_rate: 100,
                updated_at: now,
                status_message: "System operating normally".to_string(),
            }),
            policy: RwLock::new(DegradedModePolicy::default()),
            events: RwLock::new(Vec::new()),
            recoveries: RwLock::new(Vec::new()),
            sequence: std::sync::atomic::AtomicU64::new(0),
            consecutive_healthy_epochs: std::sync::atomic::AtomicU32::new(0),
        }
    }

    fn generate_event_id(&self) -> String {
        let seq = self.sequence.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let timestamp = Utc::now().timestamp_micros();
        format!("dmev_{:016x}_{:08x}", timestamp, seq)
    }

    fn generate_action_id(&self) -> String {
        let seq = self.sequence.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let timestamp = Utc::now().timestamp_micros();
        format!("rcv_{:016x}_{:08x}", timestamp, seq)
    }

    fn record_event(
        &self,
        event_type: DegradedEventType,
        previous_mode: OperationalMode,
        new_mode: OperationalMode,
        reasons: Vec<DegradedReason>,
        level: DegradationLevel,
        triggered_by: Option<ActorId>,
        details: String,
    ) -> DegradedModeEvent {
        let event = DegradedModeEvent {
            event_id: self.generate_event_id(),
            event_type,
            previous_mode,
            new_mode,
            reasons,
            level,
            timestamp: Utc::now(),
            epoch: 0, // TODO: Get current epoch
            triggered_by,
            details,
        };

        {
            let mut events = self.events.write().unwrap();
            events.push(event.clone());
            // Keep only last 1000 events
            if events.len() > 1000 {
                events.drain(0..100);
            }
        }

        event
    }

    async fn save_event_to_db(&self, event: &DegradedModeEvent) -> LedgerResult<()> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let event_id = event.event_id.clone();
        let event_type = serde_json::to_string(&event.event_type).unwrap_or_default();
        let previous_mode = serde_json::to_string(&event.previous_mode).unwrap_or_default();
        let new_mode = serde_json::to_string(&event.new_mode).unwrap_or_default();
        let reasons = serde_json::to_string(&event.reasons).unwrap_or_default();
        let level = serde_json::to_string(&event.level).unwrap_or_default();
        let timestamp = event.timestamp.to_rfc3339();
        let epoch = event.epoch;
        let triggered_by = event.triggered_by.as_ref().map(|a| a.0.clone());
        let details = event.details.clone();

        let _: Option<DegradedModeEvent> = session
            .client()
            .query(
                "INSERT INTO degraded_mode_events {
                    tenant_id: $tenant,
                    event_id: $event_id,
                    event_type: $event_type,
                    previous_mode: $previous_mode,
                    new_mode: $new_mode,
                    reasons: $reasons,
                    level: $level,
                    timestamp: $timestamp,
                    epoch: $epoch,
                    triggered_by: $triggered_by,
                    details: $details
                }",
            )
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("event_id", event_id))
            .bind(("event_type", event_type))
            .bind(("previous_mode", previous_mode))
            .bind(("new_mode", new_mode))
            .bind(("reasons", reasons))
            .bind(("level", level))
            .bind(("timestamp", timestamp))
            .bind(("epoch", epoch))
            .bind(("triggered_by", triggered_by))
            .bind(("details", details))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        Ok(())
    }

    async fn save_recovery_to_db(&self, action: &RecoveryAction) -> LedgerResult<()> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let action_id = action.action_id.clone();
        let action_type = serde_json::to_string(&action.action_type).unwrap_or_default();
        let initiated_by = action.initiated_by.0.clone();
        let target = action.target.clone();
        let initiated_at = action.initiated_at.to_rfc3339();
        let completed_at = action.completed_at.map(|d| d.to_rfc3339());
        let status = serde_json::to_string(&action.status).unwrap_or_default();
        let result = action.result.clone();

        let _: Option<RecoveryAction> = session
            .client()
            .query(
                "UPSERT recovery_actions SET
                    tenant_id = $tenant,
                    action_id = $action_id,
                    action_type = $action_type,
                    initiated_by = $initiated_by,
                    target = $target,
                    initiated_at = $initiated_at,
                    completed_at = $completed_at,
                    status = $status,
                    result = $result
                WHERE tenant_id = $tenant AND action_id = $action_id",
            )
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("action_id", action_id))
            .bind(("action_type", action_type))
            .bind(("initiated_by", initiated_by))
            .bind(("target", target))
            .bind(("initiated_at", initiated_at))
            .bind(("completed_at", completed_at))
            .bind(("status", status))
            .bind(("result", result))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        Ok(())
    }
}

#[async_trait]
impl DegradedModeLedger for DegradedModeService {
    async fn get_status(&self) -> LedgerResult<DegradedModeStatus> {
        let status = self.status.read().unwrap();
        Ok(status.clone())
    }

    async fn update_metrics(
        &self,
        active_signers: u32,
        network_health: u8,
        consensus_rate: u8,
    ) -> LedgerResult<DegradedModeStatus> {
        let (new_status, event) = {
            let policy = self.policy.read().unwrap();
            let mut status = self.status.write().unwrap();

            let previous_mode = status.mode;
            let new_mode = policy.determine_mode(active_signers, network_health, consensus_rate);
            let new_level = policy.determine_level(active_signers, network_health);

            // Determine reasons
            let mut reasons = Vec::new();
            if active_signers < policy.min_signers_warning {
                reasons.push(DegradedReason::InsufficientSigners);
            }
            if network_health < policy.network_health_warning {
                reasons.push(DegradedReason::NetworkPartition);
            }
            if consensus_rate < policy.consensus_rate_warning {
                reasons.push(DegradedReason::ConsensusFailure);
            }

            // Update status
            status.active_signers = active_signers;
            status.network_health = network_health;
            status.consensus_rate = consensus_rate;
            status.active_reasons = reasons.clone();
            status.level = new_level;
            status.updated_at = Utc::now();

            // Handle mode transition
            let event = if new_mode != previous_mode {
                status.mode = new_mode;

                let event_type = if new_mode > previous_mode {
                    // Getting worse
                    if new_mode == OperationalMode::Normal {
                        DegradedEventType::Exited
                    } else {
                        DegradedEventType::Escalated
                    }
                } else {
                    // Getting better
                    if new_mode == OperationalMode::Normal {
                        DegradedEventType::Exited
                    } else {
                        DegradedEventType::DeEscalated
                    }
                };

                status.status_message = match new_mode {
                    OperationalMode::Normal => "System operating normally".to_string(),
                    OperationalMode::Warning => format!("Warning: {} signers active", active_signers),
                    OperationalMode::Degraded => format!("Degraded: {} signers, {}% health", active_signers, network_health),
                    OperationalMode::Emergency => "Emergency mode - essential operations only".to_string(),
                    OperationalMode::Halted => "System halted - manual intervention required".to_string(),
                    OperationalMode::Recovery => "Recovery in progress".to_string(),
                };

                if new_mode != OperationalMode::Normal {
                    if status.started_at.is_none() {
                        status.started_at = Some(Utc::now());
                    }
                } else {
                    status.started_at = None;
                }

                Some(self.record_event(
                    event_type,
                    previous_mode,
                    new_mode,
                    reasons,
                    new_level,
                    None,
                    status.status_message.clone(),
                ))
            } else {
                None
            };

            // Track consecutive healthy epochs for auto-recovery
            if new_mode == OperationalMode::Normal {
                self.consecutive_healthy_epochs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            } else {
                self.consecutive_healthy_epochs.store(0, std::sync::atomic::Ordering::SeqCst);
            }

            (status.clone(), event)
        };

        // Save event if mode changed
        if let Some(event) = event {
            self.save_event_to_db(&event).await?;
        }

        Ok(new_status)
    }

    async fn set_mode(
        &self,
        mode: OperationalMode,
        reasons: Vec<DegradedReason>,
        triggered_by: &ActorId,
        details: &str,
    ) -> LedgerResult<DegradedModeEvent> {
        let event = {
            let policy = self.policy.read().unwrap();
            let mut status = self.status.write().unwrap();

            let previous_mode = status.mode;
            status.mode = mode;
            status.active_reasons = reasons.clone();
            status.updated_at = Utc::now();
            status.status_message = details.to_string();

            if mode != OperationalMode::Normal {
                if status.started_at.is_none() {
                    status.started_at = Some(Utc::now());
                }
            } else {
                status.started_at = None;
            }

            self.record_event(
                DegradedEventType::ManualOverride,
                previous_mode,
                mode,
                reasons,
                policy.determine_level(status.active_signers, status.network_health),
                Some(triggered_by.clone()),
                details.to_string(),
            )
        };

        self.save_event_to_db(&event).await?;
        Ok(event)
    }

    async fn can_perform_operation(&self, op_type: OperationType) -> LedgerResult<bool> {
        let status = self.status.read().unwrap();
        let policy = self.policy.read().unwrap();
        Ok(status.can_perform(op_type, &policy))
    }

    async fn initiate_recovery(
        &self,
        action_type: RecoveryActionType,
        initiated_by: &ActorId,
        target: Option<&str>,
    ) -> LedgerResult<RecoveryAction> {
        let action = RecoveryAction {
            action_id: self.generate_action_id(),
            action_type,
            initiated_by: initiated_by.clone(),
            target: target.map(|s| s.to_string()),
            initiated_at: Utc::now(),
            completed_at: None,
            status: RecoveryActionStatus::Pending,
            result: None,
        };

        {
            let mut recoveries = self.recoveries.write().unwrap();
            recoveries.push(action.clone());
        }

        self.save_recovery_to_db(&action).await?;
        Ok(action)
    }

    async fn complete_recovery(
        &self,
        action_id: &str,
        status: RecoveryActionStatus,
        result: Option<&str>,
    ) -> LedgerResult<RecoveryAction> {
        let action = {
            let mut recoveries = self.recoveries.write().unwrap();
            let action = recoveries
                .iter_mut()
                .find(|a| a.action_id == action_id)
                .ok_or_else(|| LedgerError::NotFound(format!("Action {}", action_id)))?;

            action.status = status;
            action.completed_at = Some(Utc::now());
            action.result = result.map(|s| s.to_string());

            action.clone()
        };

        self.save_recovery_to_db(&action).await?;
        Ok(action)
    }

    async fn get_recent_events(&self, limit: usize) -> LedgerResult<Vec<DegradedModeEvent>> {
        let events = self.events.read().unwrap();
        let start = events.len().saturating_sub(limit);
        Ok(events[start..].to_vec())
    }

    async fn get_active_recoveries(&self) -> LedgerResult<Vec<RecoveryAction>> {
        let recoveries = self.recoveries.read().unwrap();
        Ok(recoveries
            .iter()
            .filter(|r| matches!(r.status, RecoveryActionStatus::Pending | RecoveryActionStatus::InProgress))
            .cloned()
            .collect())
    }

    async fn update_policy(&self, policy: DegradedModePolicy) -> LedgerResult<()> {
        let mut current = self.policy.write().unwrap();
        *current = policy;
        Ok(())
    }

    async fn get_policy(&self) -> LedgerResult<DegradedModePolicy> {
        let policy = self.policy.read().unwrap();
        Ok(policy.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mode_comparison() {
        // Verify OperationalMode has comparison
        assert!(OperationalMode::Degraded != OperationalMode::Normal);
    }
}
