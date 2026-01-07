//! Compliance Checker
//!
//! Validates data and operations against compliance rules.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use super::rules::{ComplianceRule, ComplianceRuleSet, RuleCategory, RuleSeverity, RuleViolation};

/// Compliance status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ComplianceStatus {
    /// Fully compliant
    Compliant,
    /// Compliant with warnings
    Warning,
    /// Non-compliant (blocking issues)
    NonCompliant,
    /// Unknown status
    Unknown,
}

impl Default for ComplianceStatus {
    fn default() -> Self {
        Self::Unknown
    }
}

impl ComplianceStatus {
    /// Check if operations should be allowed
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Compliant | Self::Warning)
    }
}

/// Context for compliance checking
#[derive(Debug, Clone, Default)]
pub struct ComplianceContext {
    /// Object/resource ID
    pub resource_id: Option<String>,
    /// Content type
    pub content_type: Option<String>,
    /// Size in bytes
    pub size_bytes: Option<u64>,
    /// Classification labels
    pub classifications: Vec<String>,
    /// Is encrypted
    pub encrypted: Option<bool>,
    /// Encryption algorithm
    pub encryption_algorithm: Option<String>,
    /// Key size in bits
    pub key_size_bits: Option<u32>,
    /// Retention days
    pub retention_days: Option<u64>,
    /// Number of replicas
    pub replica_count: Option<u32>,
    /// Geographic regions
    pub regions: Vec<String>,
    /// Custom metadata
    pub metadata: HashMap<String, String>,
    /// Actor/user performing operation
    pub actor: Option<String>,
    /// Operation being performed
    pub operation: Option<String>,
}

impl ComplianceContext {
    /// Create new context
    pub fn new() -> Self {
        Self::default()
    }

    /// Set resource ID
    pub fn with_resource(mut self, id: &str) -> Self {
        self.resource_id = Some(id.to_string());
        self
    }

    /// Set content type
    pub fn with_content_type(mut self, ct: &str) -> Self {
        self.content_type = Some(ct.to_string());
        self
    }

    /// Set size
    pub fn with_size(mut self, size: u64) -> Self {
        self.size_bytes = Some(size);
        self
    }

    /// Set encryption info
    pub fn with_encryption(mut self, encrypted: bool, algorithm: Option<&str>, key_bits: Option<u32>) -> Self {
        self.encrypted = Some(encrypted);
        self.encryption_algorithm = algorithm.map(|s| s.to_string());
        self.key_size_bits = key_bits;
        self
    }

    /// Set retention
    pub fn with_retention(mut self, days: u64) -> Self {
        self.retention_days = Some(days);
        self
    }

    /// Set replication
    pub fn with_replicas(mut self, count: u32, regions: Vec<String>) -> Self {
        self.replica_count = Some(count);
        self.regions = regions;
        self
    }

    /// Add classification
    pub fn with_classification(mut self, class: &str) -> Self {
        self.classifications.push(class.to_string());
        self
    }

    /// Set actor
    pub fn with_actor(mut self, actor: &str) -> Self {
        self.actor = Some(actor.to_string());
        self
    }

    /// Set operation
    pub fn with_operation(mut self, op: &str) -> Self {
        self.operation = Some(op.to_string());
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }
}

/// Compliance check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceCheckResult {
    /// Overall status
    pub status: ComplianceStatus,
    /// Resource checked
    pub resource_id: Option<String>,
    /// Violations found
    pub violations: Vec<RuleViolation>,
    /// Rules checked
    pub rules_checked: usize,
    /// Check duration in milliseconds
    pub duration_ms: u64,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl ComplianceCheckResult {
    /// Create compliant result
    pub fn compliant(rules_checked: usize, duration_ms: u64) -> Self {
        Self {
            status: ComplianceStatus::Compliant,
            resource_id: None,
            violations: Vec::new(),
            rules_checked,
            duration_ms,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Create from violations
    pub fn from_violations(violations: Vec<RuleViolation>, rules_checked: usize, duration_ms: u64) -> Self {
        let status = if violations.iter().any(|v| v.severity.is_blocking()) {
            ComplianceStatus::NonCompliant
        } else if violations.is_empty() {
            ComplianceStatus::Compliant
        } else {
            ComplianceStatus::Warning
        };

        Self {
            status,
            resource_id: None,
            violations,
            rules_checked,
            duration_ms,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Set resource ID
    pub fn with_resource(mut self, id: &str) -> Self {
        self.resource_id = Some(id.to_string());
        self
    }

    /// Check if compliant
    pub fn is_compliant(&self) -> bool {
        self.status == ComplianceStatus::Compliant
    }

    /// Check if operations are allowed
    pub fn is_allowed(&self) -> bool {
        self.status.is_allowed()
    }

    /// Get blocking violations
    pub fn blocking_violations(&self) -> Vec<&RuleViolation> {
        self.violations
            .iter()
            .filter(|v| v.severity.is_blocking())
            .collect()
    }
}

/// Rule validator trait
#[async_trait::async_trait]
pub trait RuleValidator: Send + Sync {
    /// Rule categories this validator handles
    fn categories(&self) -> Vec<RuleCategory>;

    /// Validate a rule against context
    async fn validate(&self, rule: &ComplianceRule, context: &ComplianceContext) -> Option<RuleViolation>;
}

/// Built-in encryption validator
pub struct EncryptionValidator;

#[async_trait::async_trait]
impl RuleValidator for EncryptionValidator {
    fn categories(&self) -> Vec<RuleCategory> {
        vec![RuleCategory::Encryption]
    }

    async fn validate(&self, rule: &ComplianceRule, context: &ComplianceContext) -> Option<RuleViolation> {
        match rule.id.as_str() {
            "ENC-001" => {
                // Encryption required
                if context.encrypted == Some(false) {
                    return Some(RuleViolation::new(rule, "Data is not encrypted")
                        .with_affected(context.resource_id.as_deref().unwrap_or("unknown")));
                }
            }
            "ENC-002" => {
                // Minimum key length
                if let Some(min_bits) = rule.get_param::<u32>("min_key_bits") {
                    if let Some(key_bits) = context.key_size_bits {
                        if key_bits < min_bits {
                            return Some(RuleViolation::new(
                                rule,
                                &format!("Key size {} bits is less than required {} bits", key_bits, min_bits),
                            ));
                        }
                    }
                }
            }
            _ => {}
        }
        None
    }
}

/// Built-in retention validator
pub struct RetentionValidator;

#[async_trait::async_trait]
impl RuleValidator for RetentionValidator {
    fn categories(&self) -> Vec<RuleCategory> {
        vec![RuleCategory::Retention]
    }

    async fn validate(&self, rule: &ComplianceRule, context: &ComplianceContext) -> Option<RuleViolation> {
        match rule.id.as_str() {
            "RET-001" => {
                if let Some(min_days) = rule.get_param::<u64>("min_days") {
                    if let Some(retention) = context.retention_days {
                        if retention < min_days {
                            return Some(RuleViolation::new(
                                rule,
                                &format!("Retention {} days is less than minimum {} days", retention, min_days),
                            ));
                        }
                    }
                }
            }
            "RET-002" => {
                if let Some(max_days) = rule.get_param::<u64>("max_days") {
                    if let Some(retention) = context.retention_days {
                        if retention > max_days {
                            return Some(RuleViolation::new(
                                rule,
                                &format!("Retention {} days exceeds maximum {} days", retention, max_days),
                            ));
                        }
                    }
                }
            }
            _ => {}
        }
        None
    }
}

/// Built-in size validator
pub struct SizeValidator;

#[async_trait::async_trait]
impl RuleValidator for SizeValidator {
    fn categories(&self) -> Vec<RuleCategory> {
        vec![RuleCategory::SizeLimits]
    }

    async fn validate(&self, rule: &ComplianceRule, context: &ComplianceContext) -> Option<RuleViolation> {
        match rule.id.as_str() {
            "SIZE-001" => {
                if let Some(max_bytes) = rule.get_param::<u64>("max_bytes") {
                    if let Some(size) = context.size_bytes {
                        if size > max_bytes {
                            return Some(RuleViolation::new(
                                rule,
                                &format!("Size {} bytes exceeds maximum {} bytes", size, max_bytes),
                            ));
                        }
                    }
                }
            }
            _ => {}
        }
        None
    }
}

/// Built-in replication validator
pub struct ReplicationValidator;

#[async_trait::async_trait]
impl RuleValidator for ReplicationValidator {
    fn categories(&self) -> Vec<RuleCategory> {
        vec![RuleCategory::Replication]
    }

    async fn validate(&self, rule: &ComplianceRule, context: &ComplianceContext) -> Option<RuleViolation> {
        match rule.id.as_str() {
            "REP-001" => {
                if let Some(min_replicas) = rule.get_param::<u32>("min_replicas") {
                    if let Some(count) = context.replica_count {
                        if count < min_replicas {
                            return Some(RuleViolation::new(
                                rule,
                                &format!("{} replicas is less than minimum {}", count, min_replicas),
                            ));
                        }
                    }
                }
            }
            "REP-002" => {
                // Geographic distribution check
                if context.regions.len() < 2 && context.replica_count.unwrap_or(0) > 1 {
                    return Some(RuleViolation::new(
                        rule,
                        "Replicas should be distributed across multiple regions",
                    ));
                }
            }
            _ => {}
        }
        None
    }
}

/// Main compliance checker
pub struct ComplianceChecker {
    /// Rule set
    rules: RwLock<ComplianceRuleSet>,
    /// Registered validators
    validators: RwLock<Vec<Arc<dyn RuleValidator>>>,
}

impl ComplianceChecker {
    /// Create new checker with default rules
    pub fn new() -> Self {
        Self {
            rules: RwLock::new(ComplianceRuleSet::p2_default()),
            validators: RwLock::new(Vec::new()),
        }
    }

    /// Create with custom rule set
    pub fn with_rules(rules: ComplianceRuleSet) -> Self {
        Self {
            rules: RwLock::new(rules),
            validators: RwLock::new(Vec::new()),
        }
    }

    /// Register built-in validators
    pub async fn register_builtin_validators(&self) {
        let mut validators = self.validators.write().await;
        validators.push(Arc::new(EncryptionValidator));
        validators.push(Arc::new(RetentionValidator));
        validators.push(Arc::new(SizeValidator));
        validators.push(Arc::new(ReplicationValidator));
    }

    /// Register a custom validator
    pub async fn register_validator(&self, validator: Arc<dyn RuleValidator>) {
        self.validators.write().await.push(validator);
    }

    /// Check compliance
    pub async fn check(&self, context: &ComplianceContext) -> ComplianceCheckResult {
        let start = std::time::Instant::now();
        let mut violations = Vec::new();
        let mut rules_checked = 0;

        let rules = self.rules.read().await;
        let validators = self.validators.read().await;

        for rule in rules.enabled_rules() {
            rules_checked += 1;

            // Find matching validator
            for validator in validators.iter() {
                if validator.categories().contains(&rule.category) {
                    if let Some(violation) = validator.validate(rule, context).await {
                        warn!(
                            rule_id = %rule.id,
                            severity = ?violation.severity,
                            message = %violation.message,
                            "Compliance violation"
                        );
                        violations.push(violation);
                    }
                }
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        let mut result = ComplianceCheckResult::from_violations(violations, rules_checked, duration_ms);

        if let Some(ref id) = context.resource_id {
            result = result.with_resource(id);
        }

        debug!(
            status = ?result.status,
            violations = result.violations.len(),
            rules_checked = rules_checked,
            "Compliance check complete"
        );

        result
    }

    /// Quick check - only blocking rules
    pub async fn quick_check(&self, context: &ComplianceContext) -> ComplianceCheckResult {
        let start = std::time::Instant::now();
        let mut violations = Vec::new();
        let mut rules_checked = 0;

        let rules = self.rules.read().await;
        let validators = self.validators.read().await;

        // Only check blocking severity rules
        for rule in rules.enabled_rules().filter(|r| r.severity.is_blocking()) {
            rules_checked += 1;

            for validator in validators.iter() {
                if validator.categories().contains(&rule.category) {
                    if let Some(violation) = validator.validate(rule, context).await {
                        violations.push(violation);
                    }
                }
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        ComplianceCheckResult::from_violations(violations, rules_checked, duration_ms)
    }

    /// Add a rule
    pub async fn add_rule(&self, rule: ComplianceRule) {
        self.rules.write().await.add_rule(rule);
    }

    /// Remove a rule
    pub async fn remove_rule(&self, id: &str) -> Option<ComplianceRule> {
        self.rules.write().await.remove_rule(id)
    }

    /// Enable a rule
    pub async fn enable_rule(&self, id: &str) {
        self.rules.write().await.enable(id);
    }

    /// Disable a rule
    pub async fn disable_rule(&self, id: &str) {
        self.rules.write().await.disable(id);
    }

    /// Get all rules
    pub async fn rules(&self) -> ComplianceRuleSet {
        self.rules.read().await.clone()
    }
}

impl Default for ComplianceChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_compliance_checker_compliant() {
        let checker = ComplianceChecker::new();
        checker.register_builtin_validators().await;

        let context = ComplianceContext::new()
            .with_encryption(true, Some("AES-256"), Some(256))
            .with_retention(90)
            .with_replicas(3, vec!["us-east".to_string(), "eu-west".to_string()]);

        let result = checker.check(&context).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_compliance_checker_violation() {
        let checker = ComplianceChecker::new();
        checker.register_builtin_validators().await;

        let context = ComplianceContext::new()
            .with_encryption(false, None, None); // Violates ENC-001

        let result = checker.check(&context).await;
        assert!(!result.is_compliant());
        assert!(result.violations.iter().any(|v| v.rule_id == "ENC-001"));
    }

    #[tokio::test]
    async fn test_size_violation() {
        let checker = ComplianceChecker::new();
        checker.register_builtin_validators().await;

        let context = ComplianceContext::new()
            .with_size(20 * 1024 * 1024 * 1024); // 20GB > 10GB limit

        let result = checker.check(&context).await;
        assert!(result.violations.iter().any(|v| v.rule_id == "SIZE-001"));
    }

    #[test]
    fn test_compliance_context() {
        let ctx = ComplianceContext::new()
            .with_resource("test-123")
            .with_content_type("application/json")
            .with_size(1024)
            .with_actor("user-1");

        assert_eq!(ctx.resource_id, Some("test-123".to_string()));
        assert_eq!(ctx.content_type, Some("application/json".to_string()));
        assert_eq!(ctx.size_bytes, Some(1024));
        assert_eq!(ctx.actor, Some("user-1".to_string()));
    }
}
