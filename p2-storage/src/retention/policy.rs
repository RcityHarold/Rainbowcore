//! Retention Policy Configuration
//!
//! Defines retention rules by content type and category.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Retention policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicyConfig {
    /// Policy version
    pub version: String,
    /// Default retention days for unknown types
    pub default_retention_days: u32,
    /// Minimum retention days (cannot be set lower)
    pub min_retention_days: u32,
    /// Maximum retention days (hard cap)
    pub max_retention_days: u32,
    /// Rules by content type
    pub rules_by_type: HashMap<String, RetentionRule>,
    /// Rules by category
    pub rules_by_category: HashMap<String, RetentionRule>,
    /// Whether tombstoned data counts against retention
    pub tombstone_counts_as_deleted: bool,
    /// Grace period before actual deletion (days)
    pub deletion_grace_period_days: u32,
}

impl Default for RetentionPolicyConfig {
    fn default() -> Self {
        let mut rules_by_type = HashMap::new();

        // Default rules by content type
        rules_by_type.insert(
            "evidence/*".to_string(),
            RetentionRule {
                min_days: 365 * 7, // 7 years
                max_days: None,    // Forever
                description: "Evidence materials - legal requirement".to_string(),
                auto_extend_on_access: false,
                require_audit_on_delete: true,
            },
        );

        rules_by_type.insert(
            "audit/*".to_string(),
            RetentionRule {
                min_days: 365 * 10, // 10 years
                max_days: None,
                description: "Audit logs - compliance requirement".to_string(),
                auto_extend_on_access: false,
                require_audit_on_delete: true,
            },
        );

        rules_by_type.insert(
            "snapshot/*".to_string(),
            RetentionRule {
                min_days: 365 * 5, // 5 years
                max_days: Some(365 * 20), // 20 years max
                description: "Resurrection snapshots".to_string(),
                auto_extend_on_access: true,
                require_audit_on_delete: true,
            },
        );

        rules_by_type.insert(
            "temporary/*".to_string(),
            RetentionRule {
                min_days: 1,
                max_days: Some(30),
                description: "Temporary data".to_string(),
                auto_extend_on_access: false,
                require_audit_on_delete: false,
            },
        );

        let mut rules_by_category = HashMap::new();

        rules_by_category.insert(
            "personal_data".to_string(),
            RetentionRule {
                min_days: 30,
                max_days: Some(365 * 3), // 3 years unless legally required
                description: "Personal data - GDPR considerations".to_string(),
                auto_extend_on_access: false,
                require_audit_on_delete: true,
            },
        );

        rules_by_category.insert(
            "biometric".to_string(),
            RetentionRule {
                min_days: 30,
                max_days: Some(365), // 1 year
                description: "Biometric data - strict retention".to_string(),
                auto_extend_on_access: false,
                require_audit_on_delete: true,
            },
        );

        Self {
            version: "v1".to_string(),
            default_retention_days: 365 * 3, // 3 years default
            min_retention_days: 1,
            max_retention_days: 365 * 100, // 100 years hard cap
            rules_by_type,
            rules_by_category,
            tombstone_counts_as_deleted: false,
            deletion_grace_period_days: 30,
        }
    }
}

impl RetentionPolicyConfig {
    /// Get the applicable rule for a content type and category
    pub fn get_rule(&self, content_type: &str, category: Option<&str>) -> RetentionRule {
        // First check exact type match
        if let Some(rule) = self.rules_by_type.get(content_type) {
            return rule.clone();
        }

        // Check wildcard type matches
        for (pattern, rule) in &self.rules_by_type {
            if pattern.ends_with("/*") {
                let prefix = &pattern[..pattern.len() - 2];
                if content_type.starts_with(prefix) {
                    return rule.clone();
                }
            }
        }

        // Check category
        if let Some(cat) = category {
            if let Some(rule) = self.rules_by_category.get(cat) {
                return rule.clone();
            }
        }

        // Return default
        RetentionRule {
            min_days: self.min_retention_days,
            max_days: Some(self.default_retention_days),
            description: "Default retention policy".to_string(),
            auto_extend_on_access: false,
            require_audit_on_delete: false,
        }
    }

    /// Calculate expiration date for new data
    pub fn calculate_expiration(
        &self,
        content_type: &str,
        category: Option<&str>,
        created_at: DateTime<Utc>,
    ) -> Option<DateTime<Utc>> {
        let rule = self.get_rule(content_type, category);

        rule.max_days
            .map(|days| created_at + Duration::days(days as i64))
    }

    /// Check if data can be deleted based on minimum retention
    pub fn can_delete(
        &self,
        content_type: &str,
        category: Option<&str>,
        created_at: DateTime<Utc>,
    ) -> bool {
        let rule = self.get_rule(content_type, category);
        let min_retention_end = created_at + Duration::days(rule.min_days as i64);

        Utc::now() >= min_retention_end
    }
}

/// Retention rule for a specific type/category
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionRule {
    /// Minimum retention period (days)
    pub min_days: u32,
    /// Maximum retention period (days), None = forever
    pub max_days: Option<u32>,
    /// Human-readable description
    pub description: String,
    /// Whether to automatically extend retention on access
    pub auto_extend_on_access: bool,
    /// Whether deletion requires audit log entry
    pub require_audit_on_delete: bool,
}

impl RetentionRule {
    /// Check if this rule allows indefinite retention
    pub fn is_indefinite(&self) -> bool {
        self.max_days.is_none()
    }

    /// Get the retention period as Duration
    pub fn min_duration(&self) -> Duration {
        Duration::days(self.min_days as i64)
    }

    /// Get max retention period as Duration
    pub fn max_duration(&self) -> Option<Duration> {
        self.max_days.map(|d| Duration::days(d as i64))
    }
}

/// Retention policy instance for a specific payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Policy reference
    pub policy_ref: String,
    /// Content type
    pub content_type: String,
    /// Category (optional)
    pub category: Option<String>,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Minimum retention end date
    pub min_retention_until: DateTime<Utc>,
    /// Maximum retention end date (expiration)
    pub expires_at: Option<DateTime<Utc>>,
    /// Last accessed timestamp
    pub last_accessed_at: Option<DateTime<Utc>>,
    /// Whether under legal hold
    pub legal_hold: bool,
    /// Legal hold reference (if applicable)
    pub legal_hold_ref: Option<String>,
    /// Manually extended until
    pub extended_until: Option<DateTime<Utc>>,
}

impl RetentionPolicy {
    /// Create a new retention policy for a payload
    pub fn new(
        policy_ref: String,
        content_type: String,
        category: Option<String>,
        config: &RetentionPolicyConfig,
    ) -> Self {
        let now = Utc::now();
        let rule = config.get_rule(&content_type, category.as_deref());

        let min_retention_until = now + rule.min_duration();
        let expires_at = rule.max_duration().map(|d| now + d);

        Self {
            policy_ref,
            content_type,
            category,
            created_at: now,
            min_retention_until,
            expires_at,
            last_accessed_at: None,
            legal_hold: false,
            legal_hold_ref: None,
            extended_until: None,
        }
    }

    /// Check if the data is within minimum retention period
    pub fn is_within_min_retention(&self) -> bool {
        Utc::now() < self.min_retention_until
    }

    /// Check if the data has expired
    pub fn is_expired(&self) -> bool {
        if self.legal_hold {
            return false; // Legal hold prevents expiration
        }

        if let Some(extended) = self.extended_until {
            if Utc::now() < extended {
                return false;
            }
        }

        if let Some(expires) = self.expires_at {
            Utc::now() >= expires
        } else {
            false // No expiration = never expires
        }
    }

    /// Check if the data can be deleted
    pub fn can_delete(&self) -> bool {
        if self.legal_hold {
            return false;
        }

        if self.is_within_min_retention() {
            return false;
        }

        true
    }

    /// Update access timestamp and potentially extend retention
    pub fn record_access(&mut self, config: &RetentionPolicyConfig) {
        self.last_accessed_at = Some(Utc::now());

        let rule = config.get_rule(&self.content_type, self.category.as_deref());

        if rule.auto_extend_on_access {
            // Extend by half the min retention period on each access
            let extension = rule.min_duration() / 2;
            let new_expiration = Utc::now() + extension;

            if let Some(current) = self.expires_at {
                if new_expiration > current {
                    self.expires_at = Some(new_expiration);
                }
            }
        }
    }

    /// Apply legal hold
    pub fn apply_legal_hold(&mut self, hold_ref: String) {
        self.legal_hold = true;
        self.legal_hold_ref = Some(hold_ref);
    }

    /// Release legal hold
    pub fn release_legal_hold(&mut self) {
        self.legal_hold = false;
        self.legal_hold_ref = None;
    }

    /// Manually extend retention
    pub fn extend_retention(&mut self, until: DateTime<Utc>) {
        self.extended_until = Some(until);
    }

    /// Get effective expiration date considering all factors
    pub fn effective_expiration(&self) -> Option<DateTime<Utc>> {
        if self.legal_hold {
            return None; // No expiration under legal hold
        }

        let base_expiration = self.expires_at;
        let extended = self.extended_until;

        match (base_expiration, extended) {
            (Some(base), Some(ext)) => Some(base.max(ext)),
            (Some(base), None) => Some(base),
            (None, Some(ext)) => Some(ext),
            (None, None) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RetentionPolicyConfig::default();

        // Evidence should have 7 year minimum
        let rule = config.get_rule("evidence/bundle", None);
        assert_eq!(rule.min_days, 365 * 7);
        assert!(rule.max_days.is_none());

        // Temporary should have 30 day max
        let rule = config.get_rule("temporary/cache", None);
        assert_eq!(rule.max_days, Some(30));
    }

    #[test]
    fn test_category_override() {
        let config = RetentionPolicyConfig::default();

        // Personal data category should apply
        let rule = config.get_rule("application/json", Some("personal_data"));
        assert_eq!(rule.max_days, Some(365 * 3));
    }

    #[test]
    fn test_retention_policy_creation() {
        let config = RetentionPolicyConfig::default();
        let policy = RetentionPolicy::new(
            "policy:001".to_string(),
            "evidence/bundle".to_string(),
            None,
            &config,
        );

        assert!(!policy.is_expired());
        assert!(policy.is_within_min_retention());
        assert!(!policy.can_delete());
        assert!(policy.expires_at.is_none()); // Evidence never expires
    }

    #[test]
    fn test_legal_hold() {
        let config = RetentionPolicyConfig::default();
        let mut policy = RetentionPolicy::new(
            "policy:002".to_string(),
            "temporary/cache".to_string(),
            None,
            &config,
        );

        // Manually set to expired
        policy.expires_at = Some(Utc::now() - Duration::days(1));
        assert!(policy.is_expired());

        // Apply legal hold
        policy.apply_legal_hold("hold:001".to_string());
        assert!(!policy.is_expired()); // Legal hold prevents expiration
        assert!(!policy.can_delete());

        // Release hold
        policy.release_legal_hold();
        assert!(policy.is_expired());
    }

    #[test]
    fn test_can_delete_respects_min_retention() {
        let config = RetentionPolicyConfig::default();

        // Cannot delete within minimum retention period
        assert!(!config.can_delete("evidence/bundle", None, Utc::now()));

        // Can delete after minimum period (simulated old data)
        let old_date = Utc::now() - Duration::days(365 * 10);
        assert!(config.can_delete("evidence/bundle", None, old_date));
    }
}
