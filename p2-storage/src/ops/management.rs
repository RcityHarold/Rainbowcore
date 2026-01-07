//! Management API
//!
//! Provides operational management and control endpoints.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, RwLock};
use tracing::{info, warn};

/// Maintenance mode configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceMode {
    /// Is maintenance mode enabled
    pub enabled: bool,
    /// Reason for maintenance
    pub reason: Option<String>,
    /// When maintenance started
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Expected end time
    pub expected_end: Option<chrono::DateTime<chrono::Utc>>,
    /// Allow reads during maintenance
    pub allow_reads: bool,
    /// Message to show clients
    pub message: Option<String>,
}

impl Default for MaintenanceMode {
    fn default() -> Self {
        Self {
            enabled: false,
            reason: None,
            started_at: None,
            expected_end: None,
            allow_reads: true,
            message: None,
        }
    }
}

/// Shutdown request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownRequest {
    /// Graceful shutdown timeout
    pub timeout_secs: u64,
    /// Reason for shutdown
    pub reason: Option<String>,
    /// Force shutdown (skip graceful)
    pub force: bool,
}

impl Default for ShutdownRequest {
    fn default() -> Self {
        Self {
            timeout_secs: 30,
            reason: None,
            force: false,
        }
    }
}

/// Configuration update request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigUpdate {
    /// Configuration key path
    pub key: String,
    /// New value (JSON)
    pub value: serde_json::Value,
    /// Apply immediately
    pub immediate: bool,
}

/// Operation control event
#[derive(Debug, Clone)]
pub enum ControlEvent {
    /// Entering maintenance mode
    MaintenanceStarted(MaintenanceMode),
    /// Exiting maintenance mode
    MaintenanceEnded,
    /// Shutdown requested
    ShutdownRequested(ShutdownRequest),
    /// Configuration updated
    ConfigUpdated(String),
    /// Backend enabled
    BackendEnabled(String),
    /// Backend disabled
    BackendDisabled(String),
}

/// Operation control manager
pub struct OperationControl {
    /// Maintenance mode state
    maintenance: RwLock<MaintenanceMode>,
    /// Is shutting down
    shutting_down: AtomicBool,
    /// Event broadcaster
    event_tx: broadcast::Sender<ControlEvent>,
    /// Enabled backends
    enabled_backends: RwLock<Vec<String>>,
    /// Read-only mode
    read_only: AtomicBool,
}

impl OperationControl {
    /// Create new operation control
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(32);

        Self {
            maintenance: RwLock::new(MaintenanceMode::default()),
            shutting_down: AtomicBool::new(false),
            event_tx,
            enabled_backends: RwLock::new(Vec::new()),
            read_only: AtomicBool::new(false),
        }
    }

    /// Enter maintenance mode
    pub async fn enter_maintenance(&self, config: MaintenanceMode) {
        let mut mode = MaintenanceMode {
            enabled: true,
            started_at: Some(chrono::Utc::now()),
            ..config
        };

        info!(
            reason = ?mode.reason,
            allow_reads = mode.allow_reads,
            "Entering maintenance mode"
        );

        *self.maintenance.write().await = mode.clone();
        let _ = self.event_tx.send(ControlEvent::MaintenanceStarted(mode));
    }

    /// Exit maintenance mode
    pub async fn exit_maintenance(&self) {
        info!("Exiting maintenance mode");

        *self.maintenance.write().await = MaintenanceMode::default();
        let _ = self.event_tx.send(ControlEvent::MaintenanceEnded);
    }

    /// Check if in maintenance mode
    pub async fn is_maintenance(&self) -> bool {
        self.maintenance.read().await.enabled
    }

    /// Get maintenance mode config
    pub async fn maintenance_config(&self) -> MaintenanceMode {
        self.maintenance.read().await.clone()
    }

    /// Check if reads are allowed
    pub async fn reads_allowed(&self) -> bool {
        let maintenance = self.maintenance.read().await;
        !maintenance.enabled || maintenance.allow_reads
    }

    /// Check if writes are allowed
    pub async fn writes_allowed(&self) -> bool {
        let maintenance = self.maintenance.read().await;
        !maintenance.enabled && !self.read_only.load(Ordering::Relaxed)
    }

    /// Request shutdown
    pub async fn request_shutdown(&self, request: ShutdownRequest) {
        if self.shutting_down.swap(true, Ordering::SeqCst) {
            warn!("Shutdown already in progress");
            return;
        }

        info!(
            timeout_secs = request.timeout_secs,
            force = request.force,
            reason = ?request.reason,
            "Shutdown requested"
        );

        let _ = self.event_tx.send(ControlEvent::ShutdownRequested(request));
    }

    /// Check if shutting down
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::Relaxed)
    }

    /// Set read-only mode
    pub fn set_read_only(&self, read_only: bool) {
        self.read_only.store(read_only, Ordering::SeqCst);
        if read_only {
            info!("Entered read-only mode");
        } else {
            info!("Exited read-only mode");
        }
    }

    /// Check if read-only
    pub fn is_read_only(&self) -> bool {
        self.read_only.load(Ordering::Relaxed)
    }

    /// Enable a backend
    pub async fn enable_backend(&self, name: &str) {
        let mut backends = self.enabled_backends.write().await;
        if !backends.contains(&name.to_string()) {
            backends.push(name.to_string());
        }
        let _ = self
            .event_tx
            .send(ControlEvent::BackendEnabled(name.to_string()));
        info!(backend = name, "Backend enabled");
    }

    /// Disable a backend
    pub async fn disable_backend(&self, name: &str) {
        let mut backends = self.enabled_backends.write().await;
        backends.retain(|b| b != name);
        let _ = self
            .event_tx
            .send(ControlEvent::BackendDisabled(name.to_string()));
        warn!(backend = name, "Backend disabled");
    }

    /// Check if backend is enabled
    pub async fn is_backend_enabled(&self, name: &str) -> bool {
        self.enabled_backends
            .read()
            .await
            .contains(&name.to_string())
    }

    /// Get enabled backends
    pub async fn enabled_backends(&self) -> Vec<String> {
        self.enabled_backends.read().await.clone()
    }

    /// Subscribe to control events
    pub fn subscribe(&self) -> broadcast::Receiver<ControlEvent> {
        self.event_tx.subscribe()
    }

    /// Get current status
    pub async fn status(&self) -> ControlStatus {
        ControlStatus {
            maintenance: self.maintenance.read().await.clone(),
            shutting_down: self.shutting_down.load(Ordering::Relaxed),
            read_only: self.read_only.load(Ordering::Relaxed),
            enabled_backends: self.enabled_backends.read().await.clone(),
        }
    }
}

impl Default for OperationControl {
    fn default() -> Self {
        Self::new()
    }
}

/// Control status response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlStatus {
    /// Maintenance mode
    pub maintenance: MaintenanceMode,
    /// Is shutting down
    pub shutting_down: bool,
    /// Read-only mode
    pub read_only: bool,
    /// Enabled backends
    pub enabled_backends: Vec<String>,
}

/// Graceful shutdown handler
pub struct GracefulShutdown {
    /// Control reference
    control: Arc<OperationControl>,
    /// Shutdown timeout
    timeout: Duration,
    /// Shutdown hooks
    hooks: RwLock<Vec<ShutdownHook>>,
}

type ShutdownHook = Box<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync>;

impl GracefulShutdown {
    /// Create new graceful shutdown handler
    pub fn new(control: Arc<OperationControl>, timeout: Duration) -> Self {
        Self {
            control,
            timeout,
            hooks: RwLock::new(Vec::new()),
        }
    }

    /// Register a shutdown hook
    pub async fn on_shutdown<F, Fut>(&self, hook: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        self.hooks.write().await.push(Box::new(move || Box::pin(hook())));
    }

    /// Execute graceful shutdown
    pub async fn shutdown(&self) {
        info!(timeout = ?self.timeout, "Starting graceful shutdown");

        // Enter maintenance mode first
        self.control
            .enter_maintenance(MaintenanceMode {
                enabled: true,
                reason: Some("Graceful shutdown".to_string()),
                allow_reads: false,
                message: Some("Service is shutting down".to_string()),
                ..Default::default()
            })
            .await;

        // Wait for in-flight operations (simplified)
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Run shutdown hooks with timeout
        let hooks = self.hooks.read().await;
        for hook in hooks.iter() {
            let fut = hook();
            let result = tokio::time::timeout(self.timeout, fut).await;
            if result.is_err() {
                warn!("Shutdown hook timed out");
            }
        }

        info!("Graceful shutdown complete");
    }
}

/// Drain controller for graceful connection draining
pub struct DrainController {
    /// Active connections count
    active: std::sync::atomic::AtomicUsize,
    /// Is draining
    draining: AtomicBool,
    /// Drain complete notifier
    drain_complete: tokio::sync::Notify,
}

impl DrainController {
    /// Create new drain controller
    pub fn new() -> Self {
        Self {
            active: std::sync::atomic::AtomicUsize::new(0),
            draining: AtomicBool::new(false),
            drain_complete: tokio::sync::Notify::new(),
        }
    }

    /// Acquire a connection slot
    pub fn acquire(&self) -> Option<DrainGuard> {
        if self.draining.load(Ordering::Relaxed) {
            return None;
        }

        self.active.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Some(DrainGuard { controller: self })
    }

    /// Start draining
    pub fn start_drain(&self) {
        self.draining.store(true, Ordering::SeqCst);
        if self.active.load(std::sync::atomic::Ordering::Relaxed) == 0 {
            self.drain_complete.notify_waiters();
        }
    }

    /// Wait for drain to complete
    pub async fn wait_drained(&self, timeout: Duration) -> bool {
        tokio::select! {
            _ = self.drain_complete.notified() => true,
            _ = tokio::time::sleep(timeout) => false,
        }
    }

    /// Get active connection count
    pub fn active_count(&self) -> usize {
        self.active.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn release(&self) {
        let prev = self.active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        if prev == 1 && self.draining.load(Ordering::Relaxed) {
            self.drain_complete.notify_waiters();
        }
    }
}

impl Default for DrainController {
    fn default() -> Self {
        Self::new()
    }
}

/// Guard for drain controller
pub struct DrainGuard<'a> {
    controller: &'a DrainController,
}

impl<'a> Drop for DrainGuard<'a> {
    fn drop(&mut self) {
        self.controller.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_maintenance_mode() {
        let control = OperationControl::new();

        assert!(!control.is_maintenance().await);
        assert!(control.writes_allowed().await);

        control
            .enter_maintenance(MaintenanceMode {
                reason: Some("Test".to_string()),
                allow_reads: true,
                ..Default::default()
            })
            .await;

        assert!(control.is_maintenance().await);
        assert!(control.reads_allowed().await);
        assert!(!control.writes_allowed().await);

        control.exit_maintenance().await;
        assert!(!control.is_maintenance().await);
    }

    #[tokio::test]
    async fn test_shutdown_request() {
        let control = OperationControl::new();

        assert!(!control.is_shutting_down());

        control
            .request_shutdown(ShutdownRequest {
                timeout_secs: 10,
                reason: Some("Test".to_string()),
                force: false,
            })
            .await;

        assert!(control.is_shutting_down());
    }

    #[test]
    fn test_drain_controller() {
        let drain = DrainController::new();

        let guard1 = drain.acquire().unwrap();
        let guard2 = drain.acquire().unwrap();

        assert_eq!(drain.active_count(), 2);

        drain.start_drain();
        assert!(drain.acquire().is_none());

        drop(guard1);
        assert_eq!(drain.active_count(), 1);

        drop(guard2);
        assert_eq!(drain.active_count(), 0);
    }

    #[tokio::test]
    async fn test_backend_control() {
        let control = OperationControl::new();

        control.enable_backend("local").await;
        control.enable_backend("s3").await;

        assert!(control.is_backend_enabled("local").await);
        assert!(control.is_backend_enabled("s3").await);

        control.disable_backend("s3").await;
        assert!(!control.is_backend_enabled("s3").await);

        let backends = control.enabled_backends().await;
        assert_eq!(backends, vec!["local"]);
    }
}
