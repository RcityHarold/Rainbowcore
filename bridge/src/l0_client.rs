//! L0 Commit Client
//!
//! Client for interacting with L0 consensus layer for payload map commits,
//! receipt creation, and verification.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use l0_core::types::{
    ActorId, FeeReceipt, L0Receipt, ReceiptId, ReceiptVerifyResult, RootKind, ScopeType,
};
use serde::{Deserialize, Serialize};

use crate::error::BridgeError;
use crate::payload_map_commit::PayloadMapCommit;

/// Result type for L0 client operations
pub type L0ClientResult<T> = Result<T, BridgeError>;

/// L0 Commit Client trait
///
/// Defines the interface for P2/DSN to communicate with L0 consensus layer.
/// This abstraction allows for different implementations:
/// - Direct database access (same process)
/// - HTTP client (remote L0 API)
/// - Mock client (testing)
#[async_trait]
pub trait L0CommitClient: Send + Sync {
    /// Submit a payload map commit to L0
    ///
    /// Returns the receipt ID on success.
    async fn submit_commit(&self, commit: &PayloadMapCommit) -> L0ClientResult<ReceiptId>;

    /// Get a receipt by ID
    async fn get_receipt(&self, receipt_id: &ReceiptId) -> L0ClientResult<Option<L0Receipt>>;

    /// Verify a receipt
    async fn verify_receipt(&self, receipt_id: &ReceiptId) -> L0ClientResult<ReceiptVerifyResult>;

    /// Get receipts for a batch sequence
    async fn get_receipts_by_batch(&self, batch_sequence: u64) -> L0ClientResult<Vec<L0Receipt>>;

    /// Check if L0 is available
    async fn health_check(&self) -> L0ClientResult<L0HealthStatus>;

    /// Get the current batch sequence number
    async fn current_batch_sequence(&self) -> L0ClientResult<u64>;
}

/// L0 health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L0HealthStatus {
    /// Is L0 available
    pub available: bool,
    /// Current batch sequence
    pub current_batch: u64,
    /// Lag in seconds (time since last batch)
    pub batch_lag_seconds: u64,
    /// Status message
    pub message: String,
    /// Checked at
    pub checked_at: DateTime<Utc>,
}

impl L0HealthStatus {
    /// Create healthy status
    pub fn healthy(current_batch: u64) -> Self {
        Self {
            available: true,
            current_batch,
            batch_lag_seconds: 0,
            message: "OK".to_string(),
            checked_at: Utc::now(),
        }
    }

    /// Create unavailable status
    pub fn unavailable(message: &str) -> Self {
        Self {
            available: false,
            current_batch: 0,
            batch_lag_seconds: 0,
            message: message.to_string(),
            checked_at: Utc::now(),
        }
    }
}

/// Submit commit request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitCommitRequest {
    /// Committer actor ID
    pub committer: ActorId,
    /// Payload map commit
    pub commit: PayloadMapCommit,
    /// Priority (higher = processed sooner)
    pub priority: Option<u8>,
}

/// Submit commit response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitCommitResponse {
    /// Receipt ID (available immediately)
    pub receipt_id: ReceiptId,
    /// Estimated batch sequence (may change)
    pub estimated_batch: Option<u64>,
    /// Estimated confirmation time
    pub estimated_confirmation: Option<DateTime<Utc>>,
    /// Fee receipt
    pub fee_receipt: Option<FeeReceipt>,
}

// ============================================================================
// HTTP Client Implementation
// ============================================================================

/// HTTP-based L0 client
///
/// Connects to L0 API over HTTP for remote deployments.
pub struct HttpL0Client {
    /// Base URL for L0 API
    base_url: String,
    /// HTTP client
    client: reqwest::Client,
    /// Request timeout
    timeout: std::time::Duration,
    /// Retry configuration
    retry_config: RetryConfig,
}

/// Retry configuration
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum retries
    pub max_retries: u32,
    /// Initial backoff in milliseconds
    pub initial_backoff_ms: u64,
    /// Maximum backoff in milliseconds
    pub max_backoff_ms: u64,
    /// Backoff multiplier
    pub multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_backoff_ms: 100,
            max_backoff_ms: 5000,
            multiplier: 2.0,
        }
    }
}

impl HttpL0Client {
    /// Create a new HTTP L0 client
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
            timeout: std::time::Duration::from_secs(30),
            retry_config: RetryConfig::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(base_url: &str, timeout_secs: u64, retry_config: RetryConfig) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(timeout_secs))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            timeout: std::time::Duration::from_secs(timeout_secs),
            retry_config,
        }
    }

    /// Execute request with retry
    async fn execute_with_retry<T, F, Fut>(&self, operation: F) -> L0ClientResult<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = L0ClientResult<T>>,
    {
        let mut last_error = BridgeError::L0Unavailable("No attempts made".to_string());
        let mut backoff_ms = self.retry_config.initial_backoff_ms;

        for attempt in 0..=self.retry_config.max_retries {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    last_error = e;
                    if attempt < self.retry_config.max_retries {
                        tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                        backoff_ms = std::cmp::min(
                            (backoff_ms as f64 * self.retry_config.multiplier) as u64,
                            self.retry_config.max_backoff_ms,
                        );
                    }
                }
            }
        }

        Err(last_error)
    }
}

#[async_trait]
impl L0CommitClient for HttpL0Client {
    async fn submit_commit(&self, commit: &PayloadMapCommit) -> L0ClientResult<ReceiptId> {
        let url = format!("{}/api/v1/commitments", self.base_url);

        // Build request body
        let body = serde_json::json!({
            "actor_id": commit.committer,
            "scope_type": "log_batch",
            "commitment_digest": commit.refs_set_digest.to_hex(),
            "parent_ref": null,
            "metadata": {
                "commit_id": commit.commit_id,
                "payload_count": commit.payload_count,
                "total_size_bytes": commit.total_size_bytes,
                "commit_type": format!("{:?}", commit.commit_type),
            }
        });

        let response = self
            .client
            .post(&url)
            .json(&body)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| BridgeError::L0Unavailable(format!("HTTP request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(BridgeError::CommitFailed(format!(
                "L0 commit failed with status {}: {}",
                status, error_text
            )));
        }

        #[derive(Deserialize)]
        struct CommitResponse {
            commitment_id: String,
            receipt_id: Option<String>,
        }

        let result: CommitResponse = response
            .json()
            .await
            .map_err(|e| BridgeError::CommitFailed(format!("Failed to parse response: {}", e)))?;

        // Use receipt_id if available, otherwise use commitment_id as placeholder
        let receipt_id = result
            .receipt_id
            .unwrap_or_else(|| format!("pending:{}", result.commitment_id));

        Ok(ReceiptId(receipt_id))
    }

    async fn get_receipt(&self, receipt_id: &ReceiptId) -> L0ClientResult<Option<L0Receipt>> {
        let url = format!("{}/api/v1/receipts/{}", self.base_url, receipt_id.0);

        let response = self
            .client
            .get(&url)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| BridgeError::L0Unavailable(format!("HTTP request failed: {}", e)))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !response.status().is_success() {
            let status = response.status();
            return Err(BridgeError::L0Unavailable(format!(
                "Failed to get receipt: status {}",
                status
            )));
        }

        let receipt: L0Receipt = response
            .json()
            .await
            .map_err(|e| BridgeError::L0Unavailable(format!("Failed to parse receipt: {}", e)))?;

        Ok(Some(receipt))
    }

    async fn verify_receipt(&self, receipt_id: &ReceiptId) -> L0ClientResult<ReceiptVerifyResult> {
        let url = format!("{}/api/v1/receipts/{}/verify", self.base_url, receipt_id.0);

        let response = self
            .client
            .get(&url)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| BridgeError::L0Unavailable(format!("HTTP request failed: {}", e)))?;

        if !response.status().is_success() {
            return Ok(ReceiptVerifyResult::failed(vec![format!(
                "Verification request failed: status {}",
                response.status()
            )]));
        }

        let result: ReceiptVerifyResult = response.json().await.map_err(|e| {
            BridgeError::L0Unavailable(format!("Failed to parse verify result: {}", e))
        })?;

        Ok(result)
    }

    async fn get_receipts_by_batch(&self, batch_sequence: u64) -> L0ClientResult<Vec<L0Receipt>> {
        let url = format!(
            "{}/api/v1/batches/{}/receipts",
            self.base_url, batch_sequence
        );

        let response = self
            .client
            .get(&url)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| BridgeError::L0Unavailable(format!("HTTP request failed: {}", e)))?;

        if !response.status().is_success() {
            return Ok(vec![]);
        }

        let receipts: Vec<L0Receipt> = response.json().await.unwrap_or_default();

        Ok(receipts)
    }

    async fn health_check(&self) -> L0ClientResult<L0HealthStatus> {
        let url = format!("{}/health", self.base_url);

        let response = self
            .client
            .get(&url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                // Try to get batch sequence from health response or separate endpoint
                let batch = self.current_batch_sequence().await.unwrap_or(0);
                Ok(L0HealthStatus::healthy(batch))
            }
            Ok(resp) => Ok(L0HealthStatus::unavailable(&format!(
                "Unhealthy: status {}",
                resp.status()
            ))),
            Err(e) => Ok(L0HealthStatus::unavailable(&format!(
                "Connection failed: {}",
                e
            ))),
        }
    }

    async fn current_batch_sequence(&self) -> L0ClientResult<u64> {
        let url = format!("{}/api/v1/batches/current", self.base_url);

        let response = self
            .client
            .get(&url)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| BridgeError::L0Unavailable(format!("HTTP request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(BridgeError::L0Unavailable("Failed to get current batch".to_string()));
        }

        #[derive(Deserialize)]
        struct BatchInfo {
            sequence: u64,
        }

        let info: BatchInfo = response
            .json()
            .await
            .map_err(|e| BridgeError::L0Unavailable(format!("Failed to parse: {}", e)))?;

        Ok(info.sequence)
    }
}

// ============================================================================
// Direct Database Client Implementation
// ============================================================================

/// Direct L0 client using l0-db
///
/// For same-process integration where L0 and P2 share the same runtime.
#[cfg(feature = "direct-l0")]
pub struct DirectL0Client<R>
where
    R: l0_core::ledger::ReceiptLedger + Send + Sync,
{
    /// Receipt ledger
    receipt_ledger: Arc<R>,
    /// Batch sequence counter
    batch_sequence: std::sync::atomic::AtomicU64,
}

#[cfg(feature = "direct-l0")]
impl<R> DirectL0Client<R>
where
    R: l0_core::ledger::ReceiptLedger + Send + Sync,
{
    /// Create a new direct L0 client
    pub fn new(receipt_ledger: Arc<R>) -> Self {
        Self {
            receipt_ledger,
            batch_sequence: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

#[cfg(feature = "direct-l0")]
#[async_trait]
impl<R> L0CommitClient for DirectL0Client<R>
where
    R: l0_core::ledger::ReceiptLedger + Send + Sync + 'static,
{
    async fn submit_commit(&self, commit: &PayloadMapCommit) -> L0ClientResult<ReceiptId> {
        use l0_core::ledger::{ChargeFeeRequest, CreateReceiptRequest};

        // Charge fee first
        let fee_request = ChargeFeeRequest {
            payer_actor_id: ActorId::new(&commit.committer),
            anchor_type: "payload_map_commit".to_string(),
            units: FeeUnits::BatchRoot,
            units_count: 1,
            fee_schedule_version: "v1.0.0".to_string(),
        };

        let fee_receipt = self
            .receipt_ledger
            .charge_fee(fee_request)
            .await
            .map_err(|e| BridgeError::CommitFailed(format!("Fee charge failed: {}", e)))?;

        // Get next batch sequence
        let batch_seq = self
            .batch_sequence
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        // Create receipt
        let now = Utc::now();
        let request = CreateReceiptRequest {
            scope_type: ScopeType::LogBatch,
            root_kind: RootKind::BatchRoot,
            root: commit.refs_set_digest.clone(),
            time_window_start: now,
            time_window_end: now + Duration::seconds(60),
            batch_sequence_no: Some(batch_seq),
            signer_set_version: "v1".to_string(),
            canonicalization_version: "v1".to_string(),
            anchor_policy_version: "v1".to_string(),
            fee_schedule_version: "v1.0.0".to_string(),
            signed_snapshot_ref: format!("snapshot:{}", commit.commit_id),
        };

        let receipt = self
            .receipt_ledger
            .create_receipt(request, fee_receipt.fee_receipt_id.clone())
            .await
            .map_err(|e| BridgeError::CommitFailed(format!("Receipt creation failed: {}", e)))?;

        // Link fee to receipt
        self.receipt_ledger
            .link_fee_to_receipt(&fee_receipt.fee_receipt_id, &receipt.receipt_id.0)
            .await
            .map_err(|e| BridgeError::CommitFailed(format!("Fee linking failed: {}", e)))?;

        Ok(receipt.receipt_id)
    }

    async fn get_receipt(&self, receipt_id: &ReceiptId) -> L0ClientResult<Option<L0Receipt>> {
        self.receipt_ledger
            .get_receipt(&receipt_id.0)
            .await
            .map_err(|e| BridgeError::L0Unavailable(format!("Get receipt failed: {}", e)))
    }

    async fn verify_receipt(&self, receipt_id: &ReceiptId) -> L0ClientResult<ReceiptVerifyResult> {
        self.receipt_ledger
            .verify_receipt(&receipt_id.0)
            .await
            .map_err(|e| BridgeError::L0Unavailable(format!("Verify failed: {}", e)))
    }

    async fn get_receipts_by_batch(&self, batch_sequence: u64) -> L0ClientResult<Vec<L0Receipt>> {
        self.receipt_ledger
            .get_receipts_by_batch(batch_sequence)
            .await
            .map_err(|e| BridgeError::L0Unavailable(format!("Get by batch failed: {}", e)))
    }

    async fn health_check(&self) -> L0ClientResult<L0HealthStatus> {
        let batch = self
            .batch_sequence
            .load(std::sync::atomic::Ordering::SeqCst);
        Ok(L0HealthStatus::healthy(batch))
    }

    async fn current_batch_sequence(&self) -> L0ClientResult<u64> {
        Ok(self
            .batch_sequence
            .load(std::sync::atomic::Ordering::SeqCst))
    }
}

// ============================================================================
// Mock Client for Testing
// ============================================================================

/// Mock L0 client for testing
pub struct MockL0Client {
    /// Stored receipts
    receipts: std::sync::RwLock<std::collections::HashMap<String, L0Receipt>>,
    /// Batch sequence counter
    batch_sequence: std::sync::atomic::AtomicU64,
    /// Simulate failure mode
    fail_mode: std::sync::atomic::AtomicBool,
}

impl MockL0Client {
    /// Create a new mock client
    pub fn new() -> Self {
        Self {
            receipts: std::sync::RwLock::new(std::collections::HashMap::new()),
            batch_sequence: std::sync::atomic::AtomicU64::new(1),
            fail_mode: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Enable failure mode for testing
    pub fn set_fail_mode(&self, fail: bool) {
        self.fail_mode
            .store(fail, std::sync::atomic::Ordering::SeqCst);
    }

    /// Get all stored receipts (for testing)
    pub fn get_all_receipts(&self) -> Vec<L0Receipt> {
        self.receipts.read().unwrap().values().cloned().collect()
    }
}

impl Default for MockL0Client {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl L0CommitClient for MockL0Client {
    async fn submit_commit(&self, commit: &PayloadMapCommit) -> L0ClientResult<ReceiptId> {
        if self.fail_mode.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(BridgeError::L0Unavailable("Mock failure mode".to_string()));
        }

        let receipt_id = format!("receipt:{}", uuid::Uuid::new_v4());
        let batch_seq = self
            .batch_sequence
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let now = Utc::now();

        let receipt = L0Receipt {
            receipt_id: ReceiptId(receipt_id.clone()),
            scope_type: ScopeType::LogBatch,
            root_kind: RootKind::BatchRoot,
            root: commit.refs_set_digest.clone(),
            time_window_start: now,
            time_window_end: now + Duration::seconds(60),
            batch_sequence_no: Some(batch_seq),
            signer_set_version: "v1".to_string(),
            canonicalization_version: "v1".to_string(),
            anchor_policy_version: "v1".to_string(),
            fee_schedule_version: "v1.0.0".to_string(),
            fee_receipt_id: format!("fee:{}", uuid::Uuid::new_v4()),
            signed_snapshot_ref: format!("snapshot:{}", commit.commit_id),
            created_at: now,
            rejected: Some(false),
            reject_reason_code: None,
            observer_reports_digest: None,
        };

        self.receipts
            .write()
            .unwrap()
            .insert(receipt_id.clone(), receipt);

        Ok(ReceiptId(receipt_id))
    }

    async fn get_receipt(&self, receipt_id: &ReceiptId) -> L0ClientResult<Option<L0Receipt>> {
        if self.fail_mode.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(BridgeError::L0Unavailable("Mock failure mode".to_string()));
        }

        Ok(self.receipts.read().unwrap().get(&receipt_id.0).cloned())
    }

    async fn verify_receipt(&self, receipt_id: &ReceiptId) -> L0ClientResult<ReceiptVerifyResult> {
        if self.fail_mode.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(BridgeError::L0Unavailable("Mock failure mode".to_string()));
        }

        match self.get_receipt(receipt_id).await? {
            Some(receipt) => {
                if receipt.rejected.unwrap_or(false) {
                    Ok(ReceiptVerifyResult::failed(vec!["Receipt rejected".to_string()]))
                } else {
                    Ok(ReceiptVerifyResult::verified_a())
                }
            }
            None => Ok(ReceiptVerifyResult::failed(vec![
                "Receipt not found".to_string()
            ])),
        }
    }

    async fn get_receipts_by_batch(&self, batch_sequence: u64) -> L0ClientResult<Vec<L0Receipt>> {
        if self.fail_mode.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(BridgeError::L0Unavailable("Mock failure mode".to_string()));
        }

        Ok(self
            .receipts
            .read()
            .unwrap()
            .values()
            .filter(|r| r.batch_sequence_no == Some(batch_sequence))
            .cloned()
            .collect())
    }

    async fn health_check(&self) -> L0ClientResult<L0HealthStatus> {
        if self.fail_mode.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(L0HealthStatus::unavailable("Mock failure mode"));
        }

        let batch = self
            .batch_sequence
            .load(std::sync::atomic::Ordering::SeqCst);
        Ok(L0HealthStatus::healthy(batch))
    }

    async fn current_batch_sequence(&self) -> L0ClientResult<u64> {
        if self.fail_mode.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(BridgeError::L0Unavailable("Mock failure mode".to_string()));
        }

        Ok(self
            .batch_sequence
            .load(std::sync::atomic::Ordering::SeqCst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload_map_commit::CommitType;
    use p2_core::types::SealedPayloadRef;

    fn create_test_commit() -> PayloadMapCommit {
        PayloadMapCommit::from_refs(&[], "test-committer", CommitType::Batch)
    }

    #[tokio::test]
    async fn test_mock_client_submit_and_get() {
        let client = MockL0Client::new();
        let commit = create_test_commit();

        let receipt_id = client.submit_commit(&commit).await.unwrap();
        assert!(!receipt_id.0.is_empty());

        let receipt = client.get_receipt(&receipt_id).await.unwrap();
        assert!(receipt.is_some());

        let r = receipt.unwrap();
        assert_eq!(r.receipt_id.0, receipt_id.0);
        assert_eq!(r.scope_type, ScopeType::LogBatch);
    }

    #[tokio::test]
    async fn test_mock_client_verify() {
        let client = MockL0Client::new();
        let commit = create_test_commit();

        let receipt_id = client.submit_commit(&commit).await.unwrap();
        let result = client.verify_receipt(&receipt_id).await.unwrap();

        assert!(result.valid);
        assert_eq!(result.evidence_level, l0_core::types::EvidenceLevel::A);
    }

    #[tokio::test]
    async fn test_mock_client_fail_mode() {
        let client = MockL0Client::new();
        client.set_fail_mode(true);

        let commit = create_test_commit();
        let result = client.submit_commit(&commit).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_mock_client_health_check() {
        let client = MockL0Client::new();
        let status = client.health_check().await.unwrap();

        assert!(status.available);
        assert!(status.current_batch > 0);
    }

    #[tokio::test]
    async fn test_mock_client_batch_receipts() {
        let client = MockL0Client::new();
        let commit1 = create_test_commit();
        let commit2 = create_test_commit();

        // Submit two commits (they'll have sequential batch numbers)
        let _id1 = client.submit_commit(&commit1).await.unwrap();
        let _id2 = client.submit_commit(&commit2).await.unwrap();

        // Get receipts for batch 1
        let batch1_receipts = client.get_receipts_by_batch(1).await.unwrap();
        assert_eq!(batch1_receipts.len(), 1);

        // Get receipts for batch 2
        let batch2_receipts = client.get_receipts_by_batch(2).await.unwrap();
        assert_eq!(batch2_receipts.len(), 1);
    }
}
