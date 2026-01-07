//! Backend Failover Management
//!
//! Handles automatic failover when primary backends fail.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::backend::BackendType;

/// Failover manager configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverConfig {
    /// Enable automatic failover
    pub auto_failover: bool,
    /// Enable automatic failback
    pub auto_failback: bool,
    /// Minimum time in failover state before failback (seconds)
    pub failback_delay_secs: u64,
    /// Number of consecutive successes before failback
    pub failback_success_threshold: u32,
    /// Maximum failover chain depth
    pub max_failover_depth: u8,
}

impl Default for FailoverConfig {
    fn default() -> Self {
        Self {
            auto_failover: true,
            auto_failback: true,
            failback_delay_secs: 300, // 5 minutes
            failback_success_threshold: 10,
            max_failover_depth: 3,
        }
    }
}

/// Failover state for a backend
#[derive(Debug, Clone)]
pub struct FailoverState {
    /// Current active backend
    pub active_backend: BackendType,
    /// Original primary backend
    pub primary_backend: BackendType,
    /// Is currently in failover state
    pub in_failover: bool,
    /// Time when failover occurred
    pub failover_at: Option<DateTime<Utc>>,
    /// Consecutive successes since failover
    pub success_count: u32,
    /// Failover chain (backend sequence)
    pub failover_chain: Vec<BackendType>,
}

impl FailoverState {
    /// Create a new failover state
    pub fn new(primary: BackendType) -> Self {
        Self {
            active_backend: primary,
            primary_backend: primary,
            in_failover: false,
            failover_at: None,
            success_count: 0,
            failover_chain: vec![primary],
        }
    }
}

/// Failover event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverEvent {
    /// Event ID
    pub event_id: String,
    /// Source backend (failed)
    pub from_backend: BackendType,
    /// Target backend (failover to)
    pub to_backend: BackendType,
    /// Reason for failover
    pub reason: String,
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Whether this is a failback event
    pub is_failback: bool,
}

/// Failover manager
pub struct FailoverManager {
    config: FailoverConfig,
    /// Failover states by primary backend
    states: RwLock<HashMap<BackendType, FailoverState>>,
    /// Configured failover chains
    failover_chains: RwLock<HashMap<BackendType, Vec<BackendType>>>,
    /// Failover event history
    events: RwLock<Vec<FailoverEvent>>,
}

impl FailoverManager {
    /// Create a new failover manager
    pub fn new(config: FailoverConfig) -> Self {
        Self {
            config,
            states: RwLock::new(HashMap::new()),
            failover_chains: RwLock::new(HashMap::new()),
            events: RwLock::new(Vec::new()),
        }
    }

    /// Create with default configuration
    pub fn default_manager() -> Arc<Self> {
        Arc::new(Self::new(FailoverConfig::default()))
    }

    /// Configure failover chain for a backend
    pub async fn configure_chain(&self, primary: BackendType, failovers: Vec<BackendType>) {
        let mut chains = self.failover_chains.write().await;
        chains.insert(primary, failovers.clone());

        // Initialize state if not exists
        let mut states = self.states.write().await;
        states.entry(primary).or_insert_with(|| FailoverState::new(primary));

        info!(
            primary = ?primary,
            failovers = ?failovers,
            "Configured failover chain"
        );
    }

    /// Get failover order for a backend
    pub async fn get_failover_order(&self, primary: BackendType) -> Vec<BackendType> {
        let chains = self.failover_chains.read().await;
        chains.get(&primary).cloned().unwrap_or_default()
    }

    /// Trigger failover
    pub async fn trigger_failover(&self, primary: BackendType, reason: &str) -> Option<BackendType> {
        if !self.config.auto_failover {
            return None;
        }

        let mut states = self.states.write().await;
        let state = states.entry(primary).or_insert_with(|| FailoverState::new(primary));

        // Check if we can failover further
        let current_depth = state.failover_chain.len();
        if current_depth >= self.config.max_failover_depth as usize {
            warn!(
                primary = ?primary,
                depth = current_depth,
                "Max failover depth reached"
            );
            return None;
        }

        // Find next failover target
        let next_backend = {
            let chains = self.failover_chains.read().await;
            let chain = chains.get(&primary)?;

            let current_index = chain.iter().position(|&b| b == state.active_backend)?;
            *chain.get(current_index + 1)?
        };

        // Update state
        state.active_backend = next_backend;
        state.in_failover = true;
        state.failover_at = Some(Utc::now());
        state.success_count = 0;
        state.failover_chain.push(next_backend);

        // Record event
        let event = FailoverEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            from_backend: primary,
            to_backend: next_backend,
            reason: reason.to_string(),
            timestamp: Utc::now(),
            is_failback: false,
        };

        self.events.write().await.push(event.clone());

        warn!(
            from = ?primary,
            to = ?next_backend,
            reason = %reason,
            "Triggered failover"
        );

        Some(next_backend)
    }

    /// Record successful operation
    pub async fn record_success(&self, primary: BackendType) {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(&primary) {
            state.success_count += 1;
        }
    }

    /// Check if failback is possible
    pub async fn check_failback(&self, primary: BackendType) -> Option<BackendType> {
        if !self.config.auto_failback {
            return None;
        }

        let mut states = self.states.write().await;
        let state = states.get_mut(&primary)?;

        if !state.in_failover {
            return None;
        }

        // Check failback conditions
        let failover_at = state.failover_at?;
        let elapsed = (Utc::now() - failover_at).num_seconds() as u64;

        if elapsed < self.config.failback_delay_secs {
            return None;
        }

        if state.success_count < self.config.failback_success_threshold {
            return None;
        }

        // Perform failback
        let previous_backend = state.active_backend;
        state.active_backend = state.primary_backend;
        state.in_failover = false;
        state.failover_at = None;
        state.success_count = 0;
        state.failover_chain = vec![state.primary_backend];

        // Record event
        let event = FailoverEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            from_backend: previous_backend,
            to_backend: state.primary_backend,
            reason: "Automatic failback after recovery".to_string(),
            timestamp: Utc::now(),
            is_failback: true,
        };

        drop(states);
        self.events.write().await.push(event);

        info!(
            from = ?previous_backend,
            to = ?primary,
            "Performed automatic failback"
        );

        Some(primary)
    }

    /// Get current active backend for a primary
    pub async fn get_active_backend(&self, primary: BackendType) -> BackendType {
        let states = self.states.read().await;
        states
            .get(&primary)
            .map(|s| s.active_backend)
            .unwrap_or(primary)
    }

    /// Check if a backend is in failover state
    pub async fn is_in_failover(&self, primary: BackendType) -> bool {
        let states = self.states.read().await;
        states.get(&primary).map(|s| s.in_failover).unwrap_or(false)
    }

    /// Get failover state
    pub async fn get_state(&self, primary: BackendType) -> Option<FailoverState> {
        let states = self.states.read().await;
        states.get(&primary).cloned()
    }

    /// Get recent failover events
    pub async fn get_events(&self, limit: usize) -> Vec<FailoverEvent> {
        let events = self.events.read().await;
        events.iter().rev().take(limit).cloned().collect()
    }

    /// Force failback (manual)
    pub async fn force_failback(&self, primary: BackendType) -> bool {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(&primary) {
            if state.in_failover {
                let previous_backend = state.active_backend;
                state.active_backend = state.primary_backend;
                state.in_failover = false;
                state.failover_at = None;
                state.success_count = 0;
                state.failover_chain = vec![state.primary_backend];

                // Record event
                let event = FailoverEvent {
                    event_id: uuid::Uuid::new_v4().to_string(),
                    from_backend: previous_backend,
                    to_backend: state.primary_backend,
                    reason: "Manual failback".to_string(),
                    timestamp: Utc::now(),
                    is_failback: true,
                };

                drop(states);
                self.events.write().await.push(event);

                info!(primary = ?primary, "Forced manual failback");
                return true;
            }
        }
        false
    }

    /// Get failover statistics
    pub async fn get_stats(&self) -> FailoverStats {
        let states = self.states.read().await;
        let events = self.events.read().await;

        let backends_in_failover = states.values().filter(|s| s.in_failover).count();
        let total_failovers = events.iter().filter(|e| !e.is_failback).count();
        let total_failbacks = events.iter().filter(|e| e.is_failback).count();

        FailoverStats {
            backends_in_failover,
            total_failovers,
            total_failbacks,
            last_failover: events.iter().filter(|e| !e.is_failback).last().cloned(),
            last_failback: events.iter().filter(|e| e.is_failback).last().cloned(),
        }
    }
}

/// Failover statistics
#[derive(Debug, Clone)]
pub struct FailoverStats {
    /// Number of backends currently in failover state
    pub backends_in_failover: usize,
    /// Total number of failover events
    pub total_failovers: usize,
    /// Total number of failback events
    pub total_failbacks: usize,
    /// Last failover event
    pub last_failover: Option<FailoverEvent>,
    /// Last failback event
    pub last_failback: Option<FailoverEvent>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_failover_chain_configuration() {
        let manager = FailoverManager::new(FailoverConfig::default());

        manager
            .configure_chain(
                BackendType::Local,
                vec![BackendType::Local, BackendType::Ipfs, BackendType::S3],
            )
            .await;

        let order = manager.get_failover_order(BackendType::Local).await;
        assert_eq!(order.len(), 3);
        assert_eq!(order[0], BackendType::Local);
        assert_eq!(order[1], BackendType::Ipfs);
    }

    #[tokio::test]
    async fn test_trigger_failover() {
        let manager = FailoverManager::new(FailoverConfig::default());

        manager
            .configure_chain(
                BackendType::Local,
                vec![BackendType::Local, BackendType::Ipfs],
            )
            .await;

        let next = manager
            .trigger_failover(BackendType::Local, "Test failure")
            .await;

        assert_eq!(next, Some(BackendType::Ipfs));
        assert!(manager.is_in_failover(BackendType::Local).await);
    }

    #[tokio::test]
    async fn test_active_backend() {
        let manager = FailoverManager::new(FailoverConfig::default());

        // Without configuration, should return the same backend
        let active = manager.get_active_backend(BackendType::Local).await;
        assert_eq!(active, BackendType::Local);
    }
}
