//! Retention Checker
//!
//! Scans for expired payloads and checks retention compliance.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::legal_hold::LegalHoldManager;
use super::policy::{RetentionPolicy, RetentionPolicyConfig};

/// Retention check result for a payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionCheckResult {
    /// Payload reference ID
    pub ref_id: String,
    /// Check timestamp
    pub checked_at: DateTime<Utc>,
    /// Status
    pub status: RetentionStatus,
    /// Days until expiration (negative if expired)
    pub days_until_expiration: Option<i64>,
    /// Whether under legal hold
    pub under_legal_hold: bool,
    /// Recommended action
    pub action: RetentionAction,
}

/// Retention status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionStatus {
    /// Within minimum retention period
    WithinMinRetention,
    /// Within maximum retention period
    Active,
    /// Approaching expiration (within 30 days)
    NearExpiration,
    /// Past expiration date
    Expired,
    /// Under legal hold
    LegalHold,
    /// No expiration set
    NoExpiration,
}

/// Recommended action for retention
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionAction {
    /// No action needed
    None,
    /// Consider archiving
    Archive,
    /// Ready for deletion
    Delete,
    /// Requires legal hold release first
    AwaitLegalRelease,
    /// Notify owner of approaching expiration
    NotifyExpiration,
}

/// Retention checker for scanning payloads
pub struct RetentionChecker {
    /// Retention policy configuration
    config: Arc<RetentionPolicyConfig>,
    /// Legal hold manager
    legal_hold_manager: Arc<LegalHoldManager>,
    /// Retention policies by ref_id
    policies: RwLock<HashMap<String, RetentionPolicy>>,
    /// Near expiration threshold (days)
    near_expiration_days: u32,
}

impl RetentionChecker {
    /// Create a new retention checker
    pub fn new(
        config: RetentionPolicyConfig,
        legal_hold_manager: Arc<LegalHoldManager>,
    ) -> Self {
        Self {
            config: Arc::new(config),
            legal_hold_manager,
            policies: RwLock::new(HashMap::new()),
            near_expiration_days: 30,
        }
    }

    /// Register a retention policy for a payload
    pub async fn register_policy(&self, ref_id: String, policy: RetentionPolicy) {
        self.policies.write().await.insert(ref_id, policy);
    }

    /// Create and register a new policy
    pub async fn create_policy(
        &self,
        ref_id: String,
        content_type: String,
        category: Option<String>,
    ) -> RetentionPolicy {
        let policy = RetentionPolicy::new(
            format!("retention:{}", ref_id),
            content_type,
            category,
            &self.config,
        );

        self.policies
            .write()
            .await
            .insert(ref_id.clone(), policy.clone());

        policy
    }

    /// Get policy for a payload
    pub async fn get_policy(&self, ref_id: &str) -> Option<RetentionPolicy> {
        self.policies.read().await.get(ref_id).cloned()
    }

    /// Check retention status for a specific payload
    pub async fn check(&self, ref_id: &str) -> Option<RetentionCheckResult> {
        let policy = self.get_policy(ref_id).await?;

        let now = Utc::now();

        // Check legal hold
        let under_legal_hold = self
            .legal_hold_manager
            .is_under_hold(ref_id)
            .await
            .unwrap_or(policy.legal_hold);

        // Calculate days until expiration
        let days_until_expiration = policy.effective_expiration().map(|exp| {
            (exp - now).num_days()
        });

        // Determine status
        let status = if under_legal_hold {
            RetentionStatus::LegalHold
        } else if policy.is_within_min_retention() {
            RetentionStatus::WithinMinRetention
        } else if policy.effective_expiration().is_none() {
            RetentionStatus::NoExpiration
        } else if policy.is_expired() {
            RetentionStatus::Expired
        } else if let Some(days) = days_until_expiration {
            if days <= self.near_expiration_days as i64 {
                RetentionStatus::NearExpiration
            } else {
                RetentionStatus::Active
            }
        } else {
            RetentionStatus::Active
        };

        // Determine action
        let action = match status {
            RetentionStatus::Expired => RetentionAction::Delete,
            RetentionStatus::LegalHold => RetentionAction::AwaitLegalRelease,
            RetentionStatus::NearExpiration => RetentionAction::NotifyExpiration,
            RetentionStatus::Active => {
                if let Some(days) = days_until_expiration {
                    if days > 365 {
                        RetentionAction::Archive
                    } else {
                        RetentionAction::None
                    }
                } else {
                    RetentionAction::None
                }
            }
            _ => RetentionAction::None,
        };

        Some(RetentionCheckResult {
            ref_id: ref_id.to_string(),
            checked_at: now,
            status,
            days_until_expiration,
            under_legal_hold,
            action,
        })
    }

    /// Scan all payloads and return those needing action
    pub async fn scan_all(&self) -> Vec<RetentionCheckResult> {
        let policies = self.policies.read().await;
        let mut results = Vec::new();

        for ref_id in policies.keys() {
            if let Some(result) = self.check(ref_id).await {
                if result.action != RetentionAction::None {
                    results.push(result);
                }
            }
        }

        // Sort by urgency (expired first, then near expiration)
        results.sort_by(|a, b| {
            let a_priority = action_priority(&a.action);
            let b_priority = action_priority(&b.action);
            a_priority.cmp(&b_priority)
        });

        info!(
            "Retention scan complete: {} payloads need action",
            results.len()
        );

        results
    }

    /// Get all expired payloads
    pub async fn get_expired(&self) -> Vec<RetentionCheckResult> {
        self.scan_all()
            .await
            .into_iter()
            .filter(|r| r.status == RetentionStatus::Expired)
            .collect()
    }

    /// Get payloads approaching expiration
    pub async fn get_near_expiration(&self) -> Vec<RetentionCheckResult> {
        self.scan_all()
            .await
            .into_iter()
            .filter(|r| r.status == RetentionStatus::NearExpiration)
            .collect()
    }

    /// Record access and update retention policy
    pub async fn record_access(&self, ref_id: &str) {
        let mut policies = self.policies.write().await;
        if let Some(policy) = policies.get_mut(ref_id) {
            policy.record_access(&self.config);
            debug!(ref_id = %ref_id, "Recorded access, updated retention policy");
        }
    }

    /// Extend retention for a payload
    pub async fn extend_retention(&self, ref_id: &str, until: DateTime<Utc>) -> bool {
        let mut policies = self.policies.write().await;
        if let Some(policy) = policies.get_mut(ref_id) {
            policy.extend_retention(until);
            info!(ref_id = %ref_id, until = %until, "Extended retention");
            return true;
        }
        false
    }

    /// Get retention statistics
    pub async fn get_stats(&self) -> RetentionStats {
        let policies = self.policies.read().await;
        let now = Utc::now();

        let mut stats = RetentionStats::default();
        stats.total_payloads = policies.len();

        for policy in policies.values() {
            if policy.legal_hold {
                stats.under_legal_hold += 1;
            }

            if policy.is_expired() {
                stats.expired += 1;
            } else if policy.is_within_min_retention() {
                stats.within_min_retention += 1;
            } else if let Some(exp) = policy.effective_expiration() {
                let days = (exp - now).num_days();
                if days <= self.near_expiration_days as i64 {
                    stats.near_expiration += 1;
                } else {
                    stats.active += 1;
                }
            } else {
                stats.no_expiration += 1;
            }
        }

        stats.checked_at = now;
        stats
    }
}

/// Get action priority for sorting (lower = more urgent)
fn action_priority(action: &RetentionAction) -> u8 {
    match action {
        RetentionAction::Delete => 0,
        RetentionAction::AwaitLegalRelease => 1,
        RetentionAction::NotifyExpiration => 2,
        RetentionAction::Archive => 3,
        RetentionAction::None => 4,
    }
}

/// Retention statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RetentionStats {
    /// Total payloads tracked
    pub total_payloads: usize,
    /// Payloads within minimum retention
    pub within_min_retention: usize,
    /// Active payloads
    pub active: usize,
    /// Payloads approaching expiration
    pub near_expiration: usize,
    /// Expired payloads
    pub expired: usize,
    /// Payloads under legal hold
    pub under_legal_hold: usize,
    /// Payloads with no expiration
    pub no_expiration: usize,
    /// Statistics timestamp
    pub checked_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    async fn create_test_checker() -> RetentionChecker {
        let config = RetentionPolicyConfig::default();
        let legal_manager = Arc::new(LegalHoldManager::new());
        RetentionChecker::new(config, legal_manager)
    }

    #[tokio::test]
    async fn test_create_and_check_policy() {
        let checker = create_test_checker().await;

        let policy = checker
            .create_policy(
                "payload:001".to_string(),
                "evidence/bundle".to_string(),
                None,
            )
            .await;

        assert!(!policy.is_expired());

        let result = checker.check("payload:001").await.unwrap();
        assert_eq!(result.status, RetentionStatus::WithinMinRetention);
        assert_eq!(result.action, RetentionAction::None);
    }

    #[tokio::test]
    async fn test_expired_policy() {
        let checker = create_test_checker().await;

        let mut policy = RetentionPolicy::new(
            "retention:002".to_string(),
            "temporary/cache".to_string(),
            None,
            &RetentionPolicyConfig::default(),
        );

        // Force expiration
        policy.expires_at = Some(Utc::now() - Duration::days(1));
        policy.min_retention_until = Utc::now() - Duration::days(10);

        checker
            .register_policy("payload:002".to_string(), policy)
            .await;

        let result = checker.check("payload:002").await.unwrap();
        assert_eq!(result.status, RetentionStatus::Expired);
        assert_eq!(result.action, RetentionAction::Delete);
    }

    #[tokio::test]
    async fn test_get_stats() {
        let checker = create_test_checker().await;

        checker
            .create_policy("payload:001".to_string(), "evidence/bundle".to_string(), None)
            .await;

        checker
            .create_policy("payload:002".to_string(), "temporary/cache".to_string(), None)
            .await;

        let stats = checker.get_stats().await;
        assert_eq!(stats.total_payloads, 2);
    }
}
