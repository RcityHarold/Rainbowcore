//! Compliance Rules
//!
//! Defines compliance rules and rule sets for validation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Rule severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleSeverity {
    /// Informational - no action required
    Info,
    /// Warning - review recommended
    Warning,
    /// Error - must be addressed
    Error,
    /// Critical - immediate action required
    Critical,
}

impl Default for RuleSeverity {
    fn default() -> Self {
        Self::Warning
    }
}

impl RuleSeverity {
    /// Check if this severity blocks operations
    pub fn is_blocking(&self) -> bool {
        matches!(self, Self::Error | Self::Critical)
    }
}

/// Rule category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleCategory {
    /// Data retention rules
    Retention,
    /// Access control rules
    AccessControl,
    /// Encryption requirements
    Encryption,
    /// Geographic/residency rules
    DataResidency,
    /// Size and quota limits
    SizeLimits,
    /// Content type restrictions
    ContentType,
    /// Audit requirements
    Audit,
    /// Naming conventions
    Naming,
    /// Metadata requirements
    Metadata,
    /// Replication requirements
    Replication,
    /// Custom rules
    Custom,
}

impl std::fmt::Display for RuleCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retention => write!(f, "Retention"),
            Self::AccessControl => write!(f, "Access Control"),
            Self::Encryption => write!(f, "Encryption"),
            Self::DataResidency => write!(f, "Data Residency"),
            Self::SizeLimits => write!(f, "Size Limits"),
            Self::ContentType => write!(f, "Content Type"),
            Self::Audit => write!(f, "Audit"),
            Self::Naming => write!(f, "Naming"),
            Self::Metadata => write!(f, "Metadata"),
            Self::Replication => write!(f, "Replication"),
            Self::Custom => write!(f, "Custom"),
        }
    }
}

/// Rule violation details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleViolation {
    /// Rule ID that was violated
    pub rule_id: String,
    /// Rule name
    pub rule_name: String,
    /// Category
    pub category: RuleCategory,
    /// Severity
    pub severity: RuleSeverity,
    /// Violation message
    pub message: String,
    /// Affected field or resource
    pub affected: Option<String>,
    /// Remediation suggestion
    pub remediation: Option<String>,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl RuleViolation {
    /// Create new violation
    pub fn new(rule: &ComplianceRule, message: &str) -> Self {
        Self {
            rule_id: rule.id.clone(),
            rule_name: rule.name.clone(),
            category: rule.category,
            severity: rule.severity,
            message: message.to_string(),
            affected: None,
            remediation: rule.remediation.clone(),
            timestamp: chrono::Utc::now(),
        }
    }

    /// Add affected resource
    pub fn with_affected(mut self, affected: &str) -> Self {
        self.affected = Some(affected.to_string());
        self
    }
}

/// Compliance rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRule {
    /// Unique rule identifier
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Description
    pub description: String,
    /// Category
    pub category: RuleCategory,
    /// Severity
    pub severity: RuleSeverity,
    /// Is this rule enabled
    pub enabled: bool,
    /// Rule parameters
    #[serde(default)]
    pub parameters: HashMap<String, serde_json::Value>,
    /// Remediation guidance
    pub remediation: Option<String>,
    /// Applicable data classification levels
    #[serde(default)]
    pub classifications: Vec<String>,
    /// Tags
    #[serde(default)]
    pub tags: Vec<String>,
}

impl ComplianceRule {
    /// Create a new rule
    pub fn new(id: &str, name: &str, category: RuleCategory) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            description: String::new(),
            category,
            severity: RuleSeverity::Warning,
            enabled: true,
            parameters: HashMap::new(),
            remediation: None,
            classifications: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Set description
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    /// Set severity
    pub fn with_severity(mut self, severity: RuleSeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Set remediation guidance
    pub fn with_remediation(mut self, remediation: &str) -> Self {
        self.remediation = Some(remediation.to_string());
        self
    }

    /// Add a parameter
    pub fn with_parameter(mut self, key: &str, value: impl Serialize) -> Self {
        if let Ok(v) = serde_json::to_value(value) {
            self.parameters.insert(key.to_string(), v);
        }
        self
    }

    /// Add classification
    pub fn with_classification(mut self, class: &str) -> Self {
        self.classifications.push(class.to_string());
        self
    }

    /// Add tag
    pub fn with_tag(mut self, tag: &str) -> Self {
        self.tags.push(tag.to_string());
        self
    }

    /// Disable the rule
    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Get parameter as specific type
    pub fn get_param<T: serde::de::DeserializeOwned>(&self, key: &str) -> Option<T> {
        self.parameters
            .get(key)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }
}

/// Set of compliance rules
#[derive(Debug, Clone, Default)]
pub struct ComplianceRuleSet {
    /// Rules by ID
    rules: HashMap<String, ComplianceRule>,
    /// Rules by category
    by_category: HashMap<RuleCategory, Vec<String>>,
}

impl ComplianceRuleSet {
    /// Create empty rule set
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with default P2 rules
    pub fn p2_default() -> Self {
        let mut set = Self::new();

        // Encryption rules
        set.add_rule(
            ComplianceRule::new("ENC-001", "Encryption Required", RuleCategory::Encryption)
                .with_description("All data must be encrypted at rest")
                .with_severity(RuleSeverity::Critical)
                .with_remediation("Ensure encryption is enabled for all storage backends"),
        );

        set.add_rule(
            ComplianceRule::new("ENC-002", "Minimum Key Length", RuleCategory::Encryption)
                .with_description("Encryption keys must be at least 256 bits")
                .with_severity(RuleSeverity::Error)
                .with_parameter("min_key_bits", 256),
        );

        // Retention rules
        set.add_rule(
            ComplianceRule::new("RET-001", "Minimum Retention", RuleCategory::Retention)
                .with_description("Data must be retained for minimum period")
                .with_severity(RuleSeverity::Error)
                .with_parameter("min_days", 30),
        );

        set.add_rule(
            ComplianceRule::new("RET-002", "Maximum Retention", RuleCategory::Retention)
                .with_description("Data should not be retained beyond maximum period")
                .with_severity(RuleSeverity::Warning)
                .with_parameter("max_days", 365 * 7), // 7 years
        );

        // Replication rules
        set.add_rule(
            ComplianceRule::new("REP-001", "Minimum Replicas", RuleCategory::Replication)
                .with_description("Data must have minimum number of replicas")
                .with_severity(RuleSeverity::Error)
                .with_parameter("min_replicas", 2),
        );

        set.add_rule(
            ComplianceRule::new("REP-002", "Geographic Distribution", RuleCategory::Replication)
                .with_description("Replicas should be geographically distributed")
                .with_severity(RuleSeverity::Warning),
        );

        // Size limits
        set.add_rule(
            ComplianceRule::new("SIZE-001", "Maximum Object Size", RuleCategory::SizeLimits)
                .with_description("Individual objects cannot exceed maximum size")
                .with_severity(RuleSeverity::Error)
                .with_parameter("max_bytes", 10 * 1024 * 1024 * 1024u64), // 10GB
        );

        // Audit rules
        set.add_rule(
            ComplianceRule::new("AUD-001", "Access Logging", RuleCategory::Audit)
                .with_description("All access must be logged")
                .with_severity(RuleSeverity::Critical),
        );

        set.add_rule(
            ComplianceRule::new("AUD-002", "Modification Logging", RuleCategory::Audit)
                .with_description("All modifications must be logged with actor")
                .with_severity(RuleSeverity::Critical),
        );

        // Metadata rules
        set.add_rule(
            ComplianceRule::new("META-001", "Content Type Required", RuleCategory::Metadata)
                .with_description("All objects must have content type")
                .with_severity(RuleSeverity::Warning),
        );

        set.add_rule(
            ComplianceRule::new("META-002", "Classification Required", RuleCategory::Metadata)
                .with_description("Sensitive data must have classification label")
                .with_severity(RuleSeverity::Error)
                .with_classification("sensitive")
                .with_classification("confidential"),
        );

        set
    }

    /// Add a rule
    pub fn add_rule(&mut self, rule: ComplianceRule) {
        let id = rule.id.clone();
        let category = rule.category;

        self.rules.insert(id.clone(), rule);
        self.by_category
            .entry(category)
            .or_default()
            .push(id);
    }

    /// Remove a rule
    pub fn remove_rule(&mut self, id: &str) -> Option<ComplianceRule> {
        if let Some(rule) = self.rules.remove(id) {
            if let Some(ids) = self.by_category.get_mut(&rule.category) {
                ids.retain(|i| i != id);
            }
            Some(rule)
        } else {
            None
        }
    }

    /// Get a rule by ID
    pub fn get(&self, id: &str) -> Option<&ComplianceRule> {
        self.rules.get(id)
    }

    /// Get rules by category
    pub fn by_category(&self, category: RuleCategory) -> Vec<&ComplianceRule> {
        self.by_category
            .get(&category)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.rules.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all enabled rules
    pub fn enabled_rules(&self) -> impl Iterator<Item = &ComplianceRule> {
        self.rules.values().filter(|r| r.enabled)
    }

    /// Get all rules
    pub fn all_rules(&self) -> impl Iterator<Item = &ComplianceRule> {
        self.rules.values()
    }

    /// Count rules
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Enable a rule
    pub fn enable(&mut self, id: &str) {
        if let Some(rule) = self.rules.get_mut(id) {
            rule.enabled = true;
        }
    }

    /// Disable a rule
    pub fn disable(&mut self, id: &str) {
        if let Some(rule) = self.rules.get_mut(id) {
            rule.enabled = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_severity() {
        assert!(!RuleSeverity::Info.is_blocking());
        assert!(!RuleSeverity::Warning.is_blocking());
        assert!(RuleSeverity::Error.is_blocking());
        assert!(RuleSeverity::Critical.is_blocking());
    }

    #[test]
    fn test_compliance_rule() {
        let rule = ComplianceRule::new("TEST-001", "Test Rule", RuleCategory::Encryption)
            .with_description("Test description")
            .with_severity(RuleSeverity::Error)
            .with_parameter("max_size", 1024);

        assert_eq!(rule.id, "TEST-001");
        assert_eq!(rule.category, RuleCategory::Encryption);
        assert_eq!(rule.get_param::<i64>("max_size"), Some(1024));
    }

    #[test]
    fn test_rule_set() {
        let mut set = ComplianceRuleSet::new();

        set.add_rule(ComplianceRule::new("A", "Rule A", RuleCategory::Encryption));
        set.add_rule(ComplianceRule::new("B", "Rule B", RuleCategory::Encryption));
        set.add_rule(ComplianceRule::new("C", "Rule C", RuleCategory::Retention));

        assert_eq!(set.len(), 3);
        assert_eq!(set.by_category(RuleCategory::Encryption).len(), 2);
        assert_eq!(set.by_category(RuleCategory::Retention).len(), 1);
    }

    #[test]
    fn test_p2_default_rules() {
        let set = ComplianceRuleSet::p2_default();
        assert!(!set.is_empty());
        assert!(set.get("ENC-001").is_some());
    }
}
