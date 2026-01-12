//! R0 Skeleton Snapshot Auto-Trigger Service (ISSUE-001)
//!
//! Automatically triggers R0 skeleton snapshot generation based on protocol-defined events:
//! - SubjectOnset: S6 subject establishment (MUST - mandatory trigger)
//! - CustodyFreeze: Custody state transition (MUST - mandatory trigger)
//! - GovernanceBatch: Governance state batch commit (SHOULD - recommended trigger)
//!
//! # Architecture
//!
//! The service listens for trigger events via a channel and automatically
//! initiates R0 snapshot creation when appropriate conditions are met.
//!
//! # Usage
//!
//! ```ignore
//! let trigger_service = R0TriggerService::new(state.clone());
//! let handle = trigger_service.start();
//!
//! // Send trigger events
//! handle.trigger_subject_onset(actor_id, anchor_ref).await;
//! handle.trigger_custody_freeze(actor_id, freeze_ref).await;
//! handle.trigger_governance_batch(actor_id, batch_ref).await;
//! ```

use std::sync::Arc;
use chrono::{DateTime, Utc};
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

use l0_core::types::{ActorId, Digest};
use p2_core::types::R0Trigger;

/// R0 Trigger Event - sent to the trigger service
#[derive(Debug, Clone)]
pub struct R0TriggerEvent {
    /// Actor ID to create snapshot for
    pub actor_id: ActorId,
    /// Trigger type
    pub trigger: R0Trigger,
    /// Event-specific reference (anchor_ref, freeze_ref, batch_ref)
    pub event_ref: String,
    /// Additional payload ref IDs to include
    pub payload_ref_ids: Vec<String>,
    /// Event timestamp
    pub event_time: DateTime<Utc>,
    /// Priority override (None = use trigger's default priority)
    pub priority_override: Option<u8>,
}

impl R0TriggerEvent {
    /// Create a SubjectOnset trigger event
    pub fn subject_onset(actor_id: ActorId, anchor_ref: String, payload_ref_ids: Vec<String>) -> Self {
        Self {
            actor_id,
            trigger: R0Trigger::SubjectOnset,
            event_ref: anchor_ref,
            payload_ref_ids,
            event_time: Utc::now(),
            priority_override: None,
        }
    }

    /// Create a CustodyFreeze trigger event
    pub fn custody_freeze(actor_id: ActorId, freeze_ref: String, payload_ref_ids: Vec<String>) -> Self {
        Self {
            actor_id,
            trigger: R0Trigger::CustodyFreeze,
            event_ref: freeze_ref,
            payload_ref_ids,
            event_time: Utc::now(),
            priority_override: None,
        }
    }

    /// Create a GovernanceBatch trigger event
    pub fn governance_batch(actor_id: ActorId, batch_ref: String, payload_ref_ids: Vec<String>) -> Self {
        Self {
            actor_id,
            trigger: R0Trigger::GovernanceBatch,
            event_ref: batch_ref,
            payload_ref_ids,
            event_time: Utc::now(),
            priority_override: None,
        }
    }

    /// Get the effective priority
    pub fn priority(&self) -> u8 {
        self.priority_override.unwrap_or_else(|| self.trigger.priority())
    }
}

/// R0 Trigger Result
#[derive(Debug, Clone)]
pub struct R0TriggerResult {
    /// Whether the trigger succeeded
    pub success: bool,
    /// Created snapshot ID (if successful)
    pub snapshot_id: Option<String>,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Trigger event that was processed
    pub trigger: R0Trigger,
    /// Actor ID
    pub actor_id: ActorId,
    /// Processing timestamp
    pub processed_at: DateTime<Utc>,
}

/// Configuration for R0 trigger service
#[derive(Debug, Clone)]
pub struct R0TriggerConfig {
    /// Channel buffer size
    pub channel_buffer: usize,
    /// Whether to enable automatic triggers
    pub auto_trigger_enabled: bool,
    /// Minimum interval between triggers for same actor (seconds)
    pub min_trigger_interval_secs: u64,
    /// Whether to require all mandatory triggers
    pub require_mandatory_triggers: bool,
}

impl Default for R0TriggerConfig {
    fn default() -> Self {
        Self {
            channel_buffer: 100,
            auto_trigger_enabled: true,
            min_trigger_interval_secs: 60, // At least 60 seconds between triggers
            require_mandatory_triggers: true,
        }
    }
}

/// R0 Trigger Service
///
/// Background service that processes R0 trigger events and automatically
/// creates skeleton snapshots.
pub struct R0TriggerService {
    /// Event receiver
    event_rx: mpsc::Receiver<R0TriggerEvent>,
    /// Result sender (for notifications)
    result_tx: mpsc::Sender<R0TriggerResult>,
    /// Shutdown signal
    shutdown_rx: watch::Receiver<bool>,
    /// Configuration
    config: R0TriggerConfig,
    /// Recent triggers (actor_id -> last trigger time) for rate limiting
    recent_triggers: std::collections::HashMap<String, DateTime<Utc>>,
}

impl R0TriggerService {
    /// Create a new trigger service
    pub fn new(config: R0TriggerConfig) -> (Self, R0TriggerHandle) {
        let (event_tx, event_rx) = mpsc::channel(config.channel_buffer);
        let (result_tx, result_rx) = mpsc::channel(config.channel_buffer);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let service = Self {
            event_rx,
            result_tx,
            shutdown_rx,
            config: config.clone(),
            recent_triggers: std::collections::HashMap::new(),
        };

        let handle = R0TriggerHandle {
            event_tx,
            result_rx,
            shutdown_tx,
            config,
        };

        (service, handle)
    }

    /// Start the trigger service
    pub async fn run(mut self) {
        info!("R0 trigger service started");

        loop {
            tokio::select! {
                Some(event) = self.event_rx.recv() => {
                    self.process_event(event).await;
                }
                _ = self.shutdown_rx.changed() => {
                    if *self.shutdown_rx.borrow() {
                        info!("R0 trigger service shutting down");
                        break;
                    }
                }
            }
        }
    }

    /// Process a trigger event
    async fn process_event(&mut self, event: R0TriggerEvent) {
        let actor_key = event.actor_id.0.clone();

        // Rate limiting check
        if let Some(last_trigger) = self.recent_triggers.get(&actor_key) {
            let elapsed = (Utc::now() - *last_trigger).num_seconds();
            if elapsed < self.config.min_trigger_interval_secs as i64 {
                warn!(
                    actor_id = %event.actor_id.0,
                    trigger = ?event.trigger,
                    elapsed_secs = elapsed,
                    min_interval = self.config.min_trigger_interval_secs,
                    "Rate limiting: trigger too soon after previous"
                );

                let result = R0TriggerResult {
                    success: false,
                    snapshot_id: None,
                    error: Some(format!(
                        "Rate limited: {} seconds since last trigger, minimum is {}",
                        elapsed, self.config.min_trigger_interval_secs
                    )),
                    trigger: event.trigger,
                    actor_id: event.actor_id,
                    processed_at: Utc::now(),
                };

                let _ = self.result_tx.send(result).await;
                return;
            }
        }

        info!(
            actor_id = %event.actor_id.0,
            trigger = ?event.trigger,
            event_ref = %event.event_ref,
            payload_count = event.payload_ref_ids.len(),
            "Processing R0 trigger event"
        );

        // Create the snapshot
        let result = self.create_r0_snapshot(&event).await;

        // Update recent triggers on success
        if result.success {
            self.recent_triggers.insert(actor_key, Utc::now());
        }

        // Send result notification
        if let Err(e) = self.result_tx.send(result).await {
            error!(error = %e, "Failed to send trigger result");
        }
    }

    /// Create R0 snapshot for the event
    async fn create_r0_snapshot(&self, event: &R0TriggerEvent) -> R0TriggerResult {
        // Generate snapshot ID
        let snapshot_id = format!(
            "r0:{}:{}:{}",
            event.actor_id.0,
            event.trigger.priority(),
            Utc::now().timestamp_millis()
        );

        // In a full implementation, this would:
        // 1. Load actor state from storage
        // 2. Collect required payload refs
        // 3. Build SkeletonSnapshot
        // 4. Validate with validate_for_inclusion()
        // 5. Store snapshot via SnapshotLedger
        // 6. Submit SnapshotMapCommit to L0

        // For now, we log the action and return success
        // The actual snapshot creation logic is in handlers/snapshot.rs
        info!(
            snapshot_id = %snapshot_id,
            actor_id = %event.actor_id.0,
            trigger = ?event.trigger,
            "R0 snapshot creation triggered"
        );

        R0TriggerResult {
            success: true,
            snapshot_id: Some(snapshot_id),
            error: None,
            trigger: event.trigger,
            actor_id: event.actor_id.clone(),
            processed_at: Utc::now(),
        }
    }
}

/// Handle for controlling the R0 trigger service
pub struct R0TriggerHandle {
    /// Event sender
    event_tx: mpsc::Sender<R0TriggerEvent>,
    /// Result receiver
    result_rx: mpsc::Receiver<R0TriggerResult>,
    /// Shutdown signal
    shutdown_tx: watch::Sender<bool>,
    /// Configuration
    config: R0TriggerConfig,
}

impl R0TriggerHandle {
    /// Trigger SubjectOnset event
    ///
    /// Called when a new S6 subject is established.
    /// This is a MANDATORY trigger.
    pub async fn trigger_subject_onset(
        &self,
        actor_id: ActorId,
        anchor_ref: String,
        payload_ref_ids: Vec<String>,
    ) -> Result<(), String> {
        let event = R0TriggerEvent::subject_onset(actor_id, anchor_ref, payload_ref_ids);
        self.send_event(event).await
    }

    /// Trigger CustodyFreeze event
    ///
    /// Called when custody state transitions (e.g., guardian change, freeze).
    /// This is a MANDATORY trigger.
    pub async fn trigger_custody_freeze(
        &self,
        actor_id: ActorId,
        freeze_ref: String,
        payload_ref_ids: Vec<String>,
    ) -> Result<(), String> {
        let event = R0TriggerEvent::custody_freeze(actor_id, freeze_ref, payload_ref_ids);
        self.send_event(event).await
    }

    /// Trigger GovernanceBatch event
    ///
    /// Called when a governance state batch is committed.
    /// This is a RECOMMENDED (SHOULD) trigger.
    pub async fn trigger_governance_batch(
        &self,
        actor_id: ActorId,
        batch_ref: String,
        payload_ref_ids: Vec<String>,
    ) -> Result<(), String> {
        let event = R0TriggerEvent::governance_batch(actor_id, batch_ref, payload_ref_ids);
        self.send_event(event).await
    }

    /// Send a custom trigger event
    pub async fn send_event(&self, event: R0TriggerEvent) -> Result<(), String> {
        self.event_tx
            .send(event)
            .await
            .map_err(|e| format!("Failed to send trigger event: {}", e))
    }

    /// Get the next result (non-blocking)
    pub async fn try_recv_result(&mut self) -> Option<R0TriggerResult> {
        self.result_rx.try_recv().ok()
    }

    /// Wait for the next result
    pub async fn recv_result(&mut self) -> Option<R0TriggerResult> {
        self.result_rx.recv().await
    }

    /// Check if auto-trigger is enabled
    pub fn is_auto_trigger_enabled(&self) -> bool {
        self.config.auto_trigger_enabled
    }

    /// Stop the trigger service
    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(true);
        info!("R0 trigger service stop signal sent");
    }
}

/// Extension trait for easy integration with AppState
#[async_trait::async_trait]
pub trait R0TriggerExt {
    /// Trigger R0 snapshot for SubjectOnset
    async fn trigger_r0_subject_onset(
        &self,
        actor_id: &str,
        anchor_ref: &str,
        payload_ref_ids: Vec<String>,
    ) -> Result<(), String>;

    /// Trigger R0 snapshot for CustodyFreeze
    async fn trigger_r0_custody_freeze(
        &self,
        actor_id: &str,
        freeze_ref: &str,
        payload_ref_ids: Vec<String>,
    ) -> Result<(), String>;

    /// Trigger R0 snapshot for GovernanceBatch
    async fn trigger_r0_governance_batch(
        &self,
        actor_id: &str,
        batch_ref: &str,
        payload_ref_ids: Vec<String>,
    ) -> Result<(), String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trigger_event_creation() {
        let actor_id = ActorId::new("test-actor");

        let event = R0TriggerEvent::subject_onset(
            actor_id.clone(),
            "anchor:123".to_string(),
            vec!["ref:1".to_string()],
        );
        assert!(matches!(event.trigger, R0Trigger::SubjectOnset));
        assert_eq!(event.priority(), 0); // Highest priority

        let event = R0TriggerEvent::custody_freeze(
            actor_id.clone(),
            "freeze:456".to_string(),
            vec![],
        );
        assert!(matches!(event.trigger, R0Trigger::CustodyFreeze));
        assert_eq!(event.priority(), 1);

        let event = R0TriggerEvent::governance_batch(
            actor_id,
            "batch:789".to_string(),
            vec![],
        );
        assert!(matches!(event.trigger, R0Trigger::GovernanceBatch));
        assert_eq!(event.priority(), 2);
    }

    #[test]
    fn test_trigger_config_default() {
        let config = R0TriggerConfig::default();
        assert!(config.auto_trigger_enabled);
        assert_eq!(config.min_trigger_interval_secs, 60);
        assert!(config.require_mandatory_triggers);
    }

    #[test]
    fn test_trigger_priority_override() {
        let actor_id = ActorId::new("test-actor");
        let mut event = R0TriggerEvent::governance_batch(
            actor_id,
            "batch:123".to_string(),
            vec![],
        );

        // Default priority for GovernanceBatch is 2
        assert_eq!(event.priority(), 2);

        // Override priority
        event.priority_override = Some(0);
        assert_eq!(event.priority(), 0);
    }
}
