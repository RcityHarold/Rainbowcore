//! API Client
//!
//! HTTP client for communicating with the P3 API.

use crate::error::{CliError, CliResult};
use reqwest::Client;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// P3 API client
pub struct P3Client {
    /// HTTP client
    client: Client,
    /// Base URL
    base_url: String,
}

impl P3Client {
    /// Create a new client
    pub fn new(base_url: impl Into<String>) -> CliResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| CliError::connection(e.to_string()))?;

        Ok(Self {
            client,
            base_url: base_url.into(),
        })
    }

    /// Create with custom timeout
    pub fn with_timeout(base_url: impl Into<String>, timeout_secs: u64) -> CliResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .map_err(|e| CliError::connection(e.to_string()))?;

        Ok(Self {
            client,
            base_url: base_url.into(),
        })
    }

    /// Get health status
    pub async fn health(&self) -> CliResult<HealthResponse> {
        let url = format!("{}/api/v1/health", self.base_url);
        let response = self.client.get(&url).send().await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            Err(CliError::api(
                response.status().as_u16(),
                response.text().await.unwrap_or_default(),
            ))
        }
    }

    /// Get executor stats
    pub async fn stats(&self) -> CliResult<StatsResponse> {
        let url = format!("{}/api/v1/stats", self.base_url);
        let response = self.client.get(&url).send().await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            Err(CliError::api(
                response.status().as_u16(),
                response.text().await.unwrap_or_default(),
            ))
        }
    }

    /// Execute an operation
    pub async fn execute(&self, request: ExecuteRequest) -> CliResult<ExecuteResponse> {
        let url = format!("{}/api/v1/execute", self.base_url);
        let response = self.client.post(&url).json(&request).send().await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            Err(CliError::api(
                response.status().as_u16(),
                response.text().await.unwrap_or_default(),
            ))
        }
    }

    /// Verify data
    pub async fn verify(&self, request: VerifyRequest) -> CliResult<VerifyResponse> {
        let url = format!("{}/api/v1/verify", self.base_url);
        let response = self.client.post(&url).json(&request).send().await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            Err(CliError::api(
                response.status().as_u16(),
                response.text().await.unwrap_or_default(),
            ))
        }
    }

    /// List providers
    pub async fn list_providers(&self, page: u64, page_size: u64) -> CliResult<PaginatedResponse<serde_json::Value>> {
        let url = format!(
            "{}/api/v1/providers?page={}&page_size={}",
            self.base_url, page, page_size
        );
        let response = self.client.get(&url).send().await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            Err(CliError::api(
                response.status().as_u16(),
                response.text().await.unwrap_or_default(),
            ))
        }
    }

    /// List clearing batches
    pub async fn list_clearing_batches(&self, page: u64, page_size: u64) -> CliResult<PaginatedResponse<serde_json::Value>> {
        let url = format!(
            "{}/api/v1/clearing/batches?page={}&page_size={}",
            self.base_url, page, page_size
        );
        let response = self.client.get(&url).send().await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            Err(CliError::api(
                response.status().as_u16(),
                response.text().await.unwrap_or_default(),
            ))
        }
    }

    /// List treasury pools
    pub async fn list_treasury_pools(&self, page: u64, page_size: u64) -> CliResult<PaginatedResponse<serde_json::Value>> {
        let url = format!(
            "{}/api/v1/treasury/pools?page={}&page_size={}",
            self.base_url, page, page_size
        );
        let response = self.client.get(&url).send().await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            Err(CliError::api(
                response.status().as_u16(),
                response.text().await.unwrap_or_default(),
            ))
        }
    }

    /// Create proof batch
    pub async fn create_proof_batch(&self, epoch_id: &str) -> CliResult<serde_json::Value> {
        let url = format!("{}/api/v1/proofs/batches", self.base_url);
        let request = serde_json::json!({ "epoch_id": epoch_id });
        let response = self.client.post(&url).json(&request).send().await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            Err(CliError::api(
                response.status().as_u16(),
                response.text().await.unwrap_or_default(),
            ))
        }
    }

    /// Seal proof batch
    pub async fn seal_proof_batch(&self, batch_id: &str) -> CliResult<serde_json::Value> {
        let url = format!("{}/api/v1/proofs/batches/{}/seal", self.base_url, batch_id);
        let response = self.client.post(&url).send().await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            Err(CliError::api(
                response.status().as_u16(),
                response.text().await.unwrap_or_default(),
            ))
        }
    }
}

// ============================================
// Request/Response Types
// ============================================

/// Health response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_secs: u64,
    pub components: Vec<ComponentHealth>,
}

/// Component health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub name: String,
    pub status: String,
    pub message: Option<String>,
}

/// Stats response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsResponse {
    pub active_executions: usize,
    pub active_attempt_chains: usize,
    pub proofs_generated: u64,
    pub active_batches: usize,
}

/// Execute request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteRequest {
    pub operation_type: String,
    pub target_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<Decimal>,
    pub epoch_id: String,
    pub initiator_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executor_ref: Option<String>,
}

/// Execute response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteResponse {
    pub execution_id: String,
    pub status: String,
    pub resolution_type: String,
    pub result_digest: Option<String>,
    pub proof_ref: Option<ProofRef>,
    pub completed_at: String,
}

/// Proof reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRef {
    pub proof_id: String,
    pub proof_type: String,
    pub executor_ref: String,
    pub executed_at: String,
    pub proof_digest: String,
}

/// Verify request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub data: String,
    pub verification_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_digest: Option<String>,
}

/// Verify response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    pub valid: bool,
    pub digest: String,
    pub details: Option<serde_json::Value>,
}

/// Paginated response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total: u64,
    pub page: u64,
    pub page_size: u64,
    pub has_more: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_request_serialization() {
        let request = ExecuteRequest {
            operation_type: "distribution".to_string(),
            target_digest: "abc123".to_string(),
            amount: Some(Decimal::new(1000, 2)),
            epoch_id: "epoch:2024:001".to_string(),
            initiator_ref: "actor:1".to_string(),
            executor_ref: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("distribution"));
        assert!(json.contains("abc123"));
    }

    #[test]
    fn test_verify_request_without_expected() {
        let request = VerifyRequest {
            data: "48656c6c6f".to_string(),
            verification_type: "blake3".to_string(),
            expected_digest: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(!json.contains("expected_digest"));
    }

    #[test]
    fn test_health_response_deserialization() {
        let json = r#"{
            "status": "healthy",
            "version": "0.1.0",
            "uptime_secs": 3600,
            "components": [
                {"name": "executor", "status": "healthy", "message": null}
            ]
        }"#;

        let response: HealthResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.status, "healthy");
        assert_eq!(response.components.len(), 1);
    }
}
