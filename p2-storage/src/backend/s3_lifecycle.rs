//! S3 Lifecycle Policies
//!
//! Manages S3 bucket lifecycle rules for automatic temperature transitions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::s3::S3StorageClass;

/// Lifecycle rule status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifecycleRuleStatus {
    /// Rule is active
    Enabled,
    /// Rule is disabled
    Disabled,
}

impl Default for LifecycleRuleStatus {
    fn default() -> Self {
        Self::Enabled
    }
}

/// Lifecycle transition definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleTransition {
    /// Days after creation to transition
    pub days: u32,
    /// Target storage class
    pub storage_class: S3StorageClass,
}

/// Lifecycle expiration definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleExpiration {
    /// Days after creation to expire
    pub days: Option<u32>,
    /// Specific date for expiration
    pub date: Option<DateTime<Utc>>,
    /// Expire delete markers
    pub expired_object_delete_marker: bool,
}

/// Lifecycle filter for rule scope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleFilter {
    /// Key prefix filter
    pub prefix: Option<String>,
    /// Tag filters
    pub tags: HashMap<String, String>,
    /// Minimum object size (bytes)
    pub object_size_greater_than: Option<u64>,
    /// Maximum object size (bytes)
    pub object_size_less_than: Option<u64>,
}

impl Default for LifecycleFilter {
    fn default() -> Self {
        Self {
            prefix: None,
            tags: HashMap::new(),
            object_size_greater_than: None,
            object_size_less_than: None,
        }
    }
}

impl LifecycleFilter {
    /// Create a prefix filter
    pub fn with_prefix(prefix: &str) -> Self {
        Self {
            prefix: Some(prefix.to_string()),
            ..Default::default()
        }
    }

    /// Add a tag filter
    pub fn with_tag(mut self, key: &str, value: &str) -> Self {
        self.tags.insert(key.to_string(), value.to_string());
        self
    }
}

/// Non-current version transition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoncurrentVersionTransition {
    /// Days after becoming non-current
    pub noncurrent_days: u32,
    /// Number of newer versions to retain
    pub newer_noncurrent_versions: Option<u32>,
    /// Target storage class
    pub storage_class: S3StorageClass,
}

/// Non-current version expiration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoncurrentVersionExpiration {
    /// Days after becoming non-current
    pub noncurrent_days: u32,
    /// Number of newer versions to retain
    pub newer_noncurrent_versions: Option<u32>,
}

/// Abort incomplete multipart upload rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbortIncompleteMultipartUpload {
    /// Days after initiation
    pub days_after_initiation: u32,
}

/// S3 Lifecycle Rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleRule {
    /// Rule ID
    pub id: String,
    /// Rule status
    pub status: LifecycleRuleStatus,
    /// Filter for rule scope
    pub filter: LifecycleFilter,
    /// Transitions for current versions
    pub transitions: Vec<LifecycleTransition>,
    /// Expiration for current versions
    pub expiration: Option<LifecycleExpiration>,
    /// Transitions for non-current versions
    pub noncurrent_version_transitions: Vec<NoncurrentVersionTransition>,
    /// Expiration for non-current versions
    pub noncurrent_version_expiration: Option<NoncurrentVersionExpiration>,
    /// Abort incomplete multipart uploads
    pub abort_incomplete_multipart_upload: Option<AbortIncompleteMultipartUpload>,
}

impl LifecycleRule {
    /// Create a new lifecycle rule
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            status: LifecycleRuleStatus::Enabled,
            filter: LifecycleFilter::default(),
            transitions: Vec::new(),
            expiration: None,
            noncurrent_version_transitions: Vec::new(),
            noncurrent_version_expiration: None,
            abort_incomplete_multipart_upload: None,
        }
    }

    /// Set filter
    pub fn with_filter(mut self, filter: LifecycleFilter) -> Self {
        self.filter = filter;
        self
    }

    /// Add a transition
    pub fn add_transition(mut self, days: u32, storage_class: S3StorageClass) -> Self {
        self.transitions.push(LifecycleTransition {
            days,
            storage_class,
        });
        self
    }

    /// Set expiration
    pub fn with_expiration_days(mut self, days: u32) -> Self {
        self.expiration = Some(LifecycleExpiration {
            days: Some(days),
            date: None,
            expired_object_delete_marker: false,
        });
        self
    }

    /// Disable the rule
    pub fn disable(mut self) -> Self {
        self.status = LifecycleRuleStatus::Disabled;
        self
    }
}

/// S3 Lifecycle Configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LifecycleConfiguration {
    /// Lifecycle rules
    pub rules: Vec<LifecycleRule>,
}

impl LifecycleConfiguration {
    /// Create a new lifecycle configuration
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a rule
    pub fn add_rule(mut self, rule: LifecycleRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Create P2 default lifecycle configuration
    ///
    /// This creates rules that align with P2's temperature tiers:
    /// - Hot → Standard (0-30 days)
    /// - Warm → Standard-IA (30-90 days)
    /// - Cold → Glacier-IR (90+ days)
    pub fn p2_default() -> Self {
        Self::new()
            .add_rule(
                LifecycleRule::new("p2-hot-to-warm")
                    .with_filter(LifecycleFilter::with_prefix("payloads/").with_tag("temperature", "hot"))
                    .add_transition(30, S3StorageClass::StandardIa),
            )
            .add_rule(
                LifecycleRule::new("p2-warm-to-cold")
                    .with_filter(LifecycleFilter::with_prefix("payloads/").with_tag("temperature", "warm"))
                    .add_transition(60, S3StorageClass::GlacierIr),
            )
            .add_rule(
                LifecycleRule::new("p2-cold-to-archive")
                    .with_filter(LifecycleFilter::with_prefix("payloads/").with_tag("temperature", "cold"))
                    .add_transition(365, S3StorageClass::GlacierDeepArchive),
            )
            .add_rule(
                LifecycleRule::new("p2-cleanup-incomplete")
                    .with_filter(LifecycleFilter::with_prefix("payloads/"))
                    .add_abort_multipart(7),
            )
    }

    /// Create lifecycle configuration for tombstoned objects
    pub fn tombstone_cleanup(retention_days: u32) -> Self {
        Self::new().add_rule(
            LifecycleRule::new("tombstone-cleanup")
                .with_filter(LifecycleFilter::with_prefix("tombstones/"))
                .with_expiration_days(retention_days),
        )
    }

    /// Convert to XML for S3 API
    pub fn to_xml(&self) -> String {
        let mut xml = String::from(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
        xml.push_str(r#"<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#);

        for rule in &self.rules {
            xml.push_str("<Rule>");
            xml.push_str(&format!("<ID>{}</ID>", rule.id));

            // Filter
            xml.push_str("<Filter>");
            if let Some(prefix) = &rule.filter.prefix {
                xml.push_str(&format!("<Prefix>{}</Prefix>", prefix));
            }
            for (key, value) in &rule.filter.tags {
                xml.push_str("<Tag>");
                xml.push_str(&format!("<Key>{}</Key>", key));
                xml.push_str(&format!("<Value>{}</Value>", value));
                xml.push_str("</Tag>");
            }
            xml.push_str("</Filter>");

            // Status
            let status = match rule.status {
                LifecycleRuleStatus::Enabled => "Enabled",
                LifecycleRuleStatus::Disabled => "Disabled",
            };
            xml.push_str(&format!("<Status>{}</Status>", status));

            // Transitions
            for transition in &rule.transitions {
                xml.push_str("<Transition>");
                xml.push_str(&format!("<Days>{}</Days>", transition.days));
                xml.push_str(&format!(
                    "<StorageClass>{}</StorageClass>",
                    transition.storage_class.as_aws_str()
                ));
                xml.push_str("</Transition>");
            }

            // Expiration
            if let Some(exp) = &rule.expiration {
                xml.push_str("<Expiration>");
                if let Some(days) = exp.days {
                    xml.push_str(&format!("<Days>{}</Days>", days));
                }
                xml.push_str("</Expiration>");
            }

            // Abort multipart
            if let Some(abort) = &rule.abort_incomplete_multipart_upload {
                xml.push_str("<AbortIncompleteMultipartUpload>");
                xml.push_str(&format!(
                    "<DaysAfterInitiation>{}</DaysAfterInitiation>",
                    abort.days_after_initiation
                ));
                xml.push_str("</AbortIncompleteMultipartUpload>");
            }

            xml.push_str("</Rule>");
        }

        xml.push_str("</LifecycleConfiguration>");
        xml
    }
}

impl LifecycleRule {
    /// Add abort incomplete multipart upload
    pub fn add_abort_multipart(mut self, days: u32) -> Self {
        self.abort_incomplete_multipart_upload = Some(AbortIncompleteMultipartUpload {
            days_after_initiation: days,
        });
        self
    }

    /// Add noncurrent version transition
    pub fn add_noncurrent_transition(
        mut self,
        days: u32,
        storage_class: S3StorageClass,
        retain_versions: Option<u32>,
    ) -> Self {
        self.noncurrent_version_transitions
            .push(NoncurrentVersionTransition {
                noncurrent_days: days,
                newer_noncurrent_versions: retain_versions,
                storage_class,
            });
        self
    }

    /// Set noncurrent version expiration
    pub fn with_noncurrent_expiration(mut self, days: u32, retain_versions: Option<u32>) -> Self {
        self.noncurrent_version_expiration = Some(NoncurrentVersionExpiration {
            noncurrent_days: days,
            newer_noncurrent_versions: retain_versions,
        });
        self
    }
}

/// S3 Lifecycle Manager
pub struct LifecycleManager {
    bucket: String,
    configuration: LifecycleConfiguration,
}

impl LifecycleManager {
    /// Create a new lifecycle manager
    pub fn new(bucket: &str) -> Self {
        Self {
            bucket: bucket.to_string(),
            configuration: LifecycleConfiguration::new(),
        }
    }

    /// Set lifecycle configuration
    pub fn set_configuration(&mut self, config: LifecycleConfiguration) {
        self.configuration = config;
    }

    /// Get current configuration
    pub fn get_configuration(&self) -> &LifecycleConfiguration {
        &self.configuration
    }

    /// Get configuration XML
    pub fn get_configuration_xml(&self) -> String {
        self.configuration.to_xml()
    }

    /// Add a rule
    pub fn add_rule(&mut self, rule: LifecycleRule) {
        self.configuration.rules.push(rule);
    }

    /// Remove a rule by ID
    pub fn remove_rule(&mut self, id: &str) -> bool {
        let initial_len = self.configuration.rules.len();
        self.configuration.rules.retain(|r| r.id != id);
        self.configuration.rules.len() != initial_len
    }

    /// Get a rule by ID
    pub fn get_rule(&self, id: &str) -> Option<&LifecycleRule> {
        self.configuration.rules.iter().find(|r| r.id == id)
    }

    /// Enable a rule
    pub fn enable_rule(&mut self, id: &str) -> bool {
        if let Some(rule) = self.configuration.rules.iter_mut().find(|r| r.id == id) {
            rule.status = LifecycleRuleStatus::Enabled;
            true
        } else {
            false
        }
    }

    /// Disable a rule
    pub fn disable_rule(&mut self, id: &str) -> bool {
        if let Some(rule) = self.configuration.rules.iter_mut().find(|r| r.id == id) {
            rule.status = LifecycleRuleStatus::Disabled;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lifecycle_rule_creation() {
        let rule = LifecycleRule::new("test-rule")
            .with_filter(LifecycleFilter::with_prefix("test/"))
            .add_transition(30, S3StorageClass::StandardIa)
            .add_transition(90, S3StorageClass::GlacierIr);

        assert_eq!(rule.id, "test-rule");
        assert_eq!(rule.transitions.len(), 2);
        assert_eq!(rule.transitions[0].days, 30);
    }

    #[test]
    fn test_lifecycle_configuration() {
        let config = LifecycleConfiguration::p2_default();
        assert!(!config.rules.is_empty());
    }

    #[test]
    fn test_lifecycle_xml() {
        let config = LifecycleConfiguration::new().add_rule(
            LifecycleRule::new("test")
                .with_filter(LifecycleFilter::with_prefix("prefix/"))
                .add_transition(30, S3StorageClass::StandardIa),
        );

        let xml = config.to_xml();
        assert!(xml.contains("<ID>test</ID>"));
        assert!(xml.contains("<Days>30</Days>"));
        assert!(xml.contains("STANDARD_IA"));
    }

    #[test]
    fn test_lifecycle_manager() {
        let mut manager = LifecycleManager::new("test-bucket");

        manager.add_rule(LifecycleRule::new("rule1"));
        assert!(manager.get_rule("rule1").is_some());

        manager.disable_rule("rule1");
        assert_eq!(
            manager.get_rule("rule1").unwrap().status,
            LifecycleRuleStatus::Disabled
        );

        assert!(manager.remove_rule("rule1"));
        assert!(manager.get_rule("rule1").is_none());
    }
}
