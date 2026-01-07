//! Asynchronous Replication
//!
//! Implements asynchronous replication where writes complete after primary
//! storage succeeds, and replication happens in the background.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

use crate::error::{StorageError, StorageResult};

use super::config::{AsyncReplicationConfig, ReplicationConfig, ReplicaNodeConfig, RetryConfig};
use super::sync::ReplicaClient;

/// Pending replication task
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationTask {
    /// Unique task ID
    pub task_id: String,
    /// Payload reference ID
    pub ref_id: String,
    /// Operation type
    pub operation: ReplicationOperation,
    /// Target node ID
    pub target_node: String,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Number of attempts
    pub attempts: u32,
    /// Last attempt timestamp
    pub last_attempt: Option<DateTime<Utc>>,
    /// Next retry time
    pub next_retry: Option<DateTime<Utc>>,
    /// Priority (higher = more urgent)
    pub priority: u8,
}

/// Replication operation type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReplicationOperation {
    /// Write/replicate data
    Write { data: Vec<u8> },
    /// Delete data
    Delete,
}

/// Async replication queue status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueStatus {
    /// Number of pending tasks
    pub pending: usize,
    /// Number of in-progress tasks
    pub in_progress: usize,
    /// Number of completed tasks (in window)
    pub completed: u64,
    /// Number of failed tasks (in window)
    pub failed: u64,
    /// Current lag in milliseconds
    pub lag_ms: u64,
    /// Oldest pending task age in milliseconds
    pub oldest_task_age_ms: Option<u64>,
    /// Status timestamp
    pub timestamp: DateTime<Utc>,
}

/// Async replication metrics
#[derive(Debug, Default)]
pub struct AsyncReplicationMetrics {
    pub tasks_enqueued: AtomicU64,
    pub tasks_completed: AtomicU64,
    pub tasks_failed: AtomicU64,
    pub bytes_replicated: AtomicU64,
}

/// Command for async replicator
enum AsyncCommand {
    Enqueue(ReplicationTask),
    Shutdown,
}

/// Asynchronous replicator
pub struct AsyncReplicator<C: ReplicaClient> {
    config: Arc<RwLock<ReplicationConfig>>,
    client: Arc<C>,
    /// Pending tasks queue
    queue: Arc<RwLock<VecDeque<ReplicationTask>>>,
    /// In-progress tasks
    in_progress: Arc<RwLock<HashMap<String, ReplicationTask>>>,
    /// Metrics
    metrics: Arc<AsyncReplicationMetrics>,
    /// Command channel
    command_tx: Option<mpsc::Sender<AsyncCommand>>,
}

impl<C: ReplicaClient + 'static> AsyncReplicator<C> {
    /// Create a new async replicator
    pub fn new(config: ReplicationConfig, client: Arc<C>) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            client,
            queue: Arc::new(RwLock::new(VecDeque::new())),
            in_progress: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(AsyncReplicationMetrics::default()),
            command_tx: None,
        }
    }

    /// Start the background replication worker
    pub async fn start(&mut self) {
        let (tx, mut rx) = mpsc::channel::<AsyncCommand>(1000);
        self.command_tx = Some(tx);

        let queue = self.queue.clone();
        let in_progress = self.in_progress.clone();
        let client = self.client.clone();
        let config = self.config.clone();
        let metrics = self.metrics.clone();

        tokio::spawn(async move {
            let async_config = config.read().await.async_config.clone();
            let retry_config = config.read().await.retry_config.clone();
            let nodes: HashMap<_, _> = config
                .read()
                .await
                .nodes
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            drop(config);

            let mut flush_interval = interval(Duration::from_millis(async_config.flush_interval_ms));

            loop {
                tokio::select! {
                    Some(cmd) = rx.recv() => {
                        match cmd {
                            AsyncCommand::Enqueue(task) => {
                                let mut q = queue.write().await;
                                q.push_back(task);
                                metrics.tasks_enqueued.fetch_add(1, Ordering::Relaxed);
                            }
                            AsyncCommand::Shutdown => {
                                info!("Async replicator shutting down");
                                break;
                            }
                        }
                    }
                    _ = flush_interval.tick() => {
                        // Process batch of tasks
                        let batch_size = async_config.batch_size;
                        let tasks: Vec<ReplicationTask> = {
                            let mut q = queue.write().await;
                            let mut tasks = Vec::new();
                            while tasks.len() < batch_size {
                                if let Some(task) = q.pop_front() {
                                    // Check if ready for retry
                                    if let Some(next_retry) = task.next_retry {
                                        if next_retry > Utc::now() {
                                            // Not ready yet, push back
                                            q.push_back(task);
                                            continue;
                                        }
                                    }
                                    tasks.push(task);
                                } else {
                                    break;
                                }
                            }
                            tasks
                        };

                        for task in tasks {
                            let node = match nodes.get(&task.target_node) {
                                Some(n) => n.clone(),
                                None => {
                                    warn!(
                                        task_id = %task.task_id,
                                        node_id = %task.target_node,
                                        "Unknown target node"
                                    );
                                    continue;
                                }
                            };

                            // Mark as in-progress
                            in_progress.write().await.insert(task.task_id.clone(), task.clone());

                            let client = client.clone();
                            let queue = queue.clone();
                            let in_progress = in_progress.clone();
                            let metrics = metrics.clone();
                            let retry_config = retry_config.clone();

                            tokio::spawn(async move {
                                let result = match &task.operation {
                                    ReplicationOperation::Write { data } => {
                                        client.write(&node, &task.ref_id, data).await
                                    }
                                    ReplicationOperation::Delete => {
                                        client.delete(&node, &task.ref_id).await
                                    }
                                };

                                // Remove from in-progress
                                in_progress.write().await.remove(&task.task_id);

                                match result {
                                    Ok(_) => {
                                        debug!(
                                            task_id = %task.task_id,
                                            ref_id = %task.ref_id,
                                            "Async replication completed"
                                        );
                                        metrics.tasks_completed.fetch_add(1, Ordering::Relaxed);
                                        if let ReplicationOperation::Write { data } = &task.operation {
                                            metrics.bytes_replicated.fetch_add(data.len() as u64, Ordering::Relaxed);
                                        }
                                    }
                                    Err(e) => {
                                        if task.attempts < retry_config.max_attempts {
                                            // Schedule retry
                                            let mut retry_task = task.clone();
                                            retry_task.attempts += 1;
                                            retry_task.last_attempt = Some(Utc::now());
                                            let backoff = retry_config.backoff_ms(retry_task.attempts);
                                            retry_task.next_retry = Some(
                                                Utc::now() + chrono::Duration::milliseconds(backoff as i64)
                                            );

                                            warn!(
                                                task_id = %retry_task.task_id,
                                                attempt = retry_task.attempts,
                                                backoff_ms = backoff,
                                                error = %e,
                                                "Async replication failed, scheduling retry"
                                            );

                                            queue.write().await.push_back(retry_task);
                                        } else {
                                            error!(
                                                task_id = %task.task_id,
                                                ref_id = %task.ref_id,
                                                attempts = task.attempts,
                                                error = %e,
                                                "Async replication failed after max retries"
                                            );
                                            metrics.tasks_failed.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                }
                            });
                        }
                    }
                }
            }
        });

        info!("Async replicator started");
    }

    /// Stop the background worker
    pub async fn stop(&self) {
        if let Some(tx) = &self.command_tx {
            let _ = tx.send(AsyncCommand::Shutdown).await;
        }
    }

    /// Enqueue a replication task
    pub async fn enqueue(&self, ref_id: &str, data: Vec<u8>, target_nodes: Vec<String>) -> StorageResult<()> {
        let tx = self.command_tx.as_ref().ok_or_else(|| {
            StorageError::OperationFailed("Async replicator not started".to_string())
        })?;

        for node_id in target_nodes {
            let task = ReplicationTask {
                task_id: format!("task:{}", uuid::Uuid::new_v4()),
                ref_id: ref_id.to_string(),
                operation: ReplicationOperation::Write { data: data.clone() },
                target_node: node_id,
                created_at: Utc::now(),
                attempts: 0,
                last_attempt: None,
                next_retry: None,
                priority: 100,
            };

            tx.send(AsyncCommand::Enqueue(task)).await.map_err(|e| {
                StorageError::OperationFailed(format!("Failed to enqueue task: {}", e))
            })?;
        }

        Ok(())
    }

    /// Enqueue a delete task
    pub async fn enqueue_delete(&self, ref_id: &str, target_nodes: Vec<String>) -> StorageResult<()> {
        let tx = self.command_tx.as_ref().ok_or_else(|| {
            StorageError::OperationFailed("Async replicator not started".to_string())
        })?;

        for node_id in target_nodes {
            let task = ReplicationTask {
                task_id: format!("task:{}", uuid::Uuid::new_v4()),
                ref_id: ref_id.to_string(),
                operation: ReplicationOperation::Delete,
                target_node: node_id,
                created_at: Utc::now(),
                attempts: 0,
                last_attempt: None,
                next_retry: None,
                priority: 50,
            };

            tx.send(AsyncCommand::Enqueue(task)).await.map_err(|e| {
                StorageError::OperationFailed(format!("Failed to enqueue task: {}", e))
            })?;
        }

        Ok(())
    }

    /// Get queue status
    pub async fn get_status(&self) -> QueueStatus {
        let queue = self.queue.read().await;
        let in_progress = self.in_progress.read().await;

        let oldest_age = queue.front().map(|t| {
            (Utc::now() - t.created_at).num_milliseconds() as u64
        });

        QueueStatus {
            pending: queue.len(),
            in_progress: in_progress.len(),
            completed: self.metrics.tasks_completed.load(Ordering::Relaxed),
            failed: self.metrics.tasks_failed.load(Ordering::Relaxed),
            lag_ms: oldest_age.unwrap_or(0),
            oldest_task_age_ms: oldest_age,
            timestamp: Utc::now(),
        }
    }

    /// Get metrics
    pub fn get_metrics(&self) -> &AsyncReplicationMetrics {
        &self.metrics
    }

    /// Check if replication lag is within acceptable limits
    pub async fn is_lag_acceptable(&self) -> bool {
        let config = self.config.read().await;
        let max_lag = config.max_lag_ms;
        drop(config);

        let status = self.get_status().await;
        status.lag_ms <= max_lag
    }

    /// Wait for queue to drain
    pub async fn drain(&self, timeout: Duration) -> bool {
        let start = std::time::Instant::now();
        loop {
            let status = self.get_status().await;
            if status.pending == 0 && status.in_progress == 0 {
                return true;
            }
            if start.elapsed() > timeout {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::sync::MockReplicaClient;

    #[tokio::test]
    async fn test_async_enqueue() {
        let client = Arc::new(MockReplicaClient::new());
        let mut config = ReplicationConfig::asynchronous();

        config.add_node(ReplicaNodeConfig {
            node_id: "node1".to_string(),
            priority: 100,
            enabled: true,
            ..Default::default()
        });

        let mut replicator = AsyncReplicator::new(config, client);
        replicator.start().await;

        replicator
            .enqueue("test:001", b"test data".to_vec(), vec!["node1".to_string()])
            .await
            .unwrap();

        // Wait for processing
        tokio::time::sleep(Duration::from_millis(200)).await;

        let status = replicator.get_status().await;
        assert_eq!(status.completed, 1);

        replicator.stop().await;
    }

    #[tokio::test]
    async fn test_queue_status() {
        let client = Arc::new(MockReplicaClient::new());
        let config = ReplicationConfig::asynchronous();

        let replicator = AsyncReplicator::new(config, client);
        let status = replicator.get_status().await;

        assert_eq!(status.pending, 0);
        assert_eq!(status.in_progress, 0);
    }
}
