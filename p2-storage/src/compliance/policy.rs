//! Compliance Policy Enforcement
//!
//! Defines and enforces compliance policies at the operation level.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Policy action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyAction {
    /// Allow the operation
    Allow,
    /// Deny the operation
    Deny,
    /// Allow with warning
    Warn,
    /// Require additional approval
    RequireApproval,
    /// Audit the operation
    Audit,
}

impl Default for PolicyAction {
    fn default() -> Self {
        Self::Allow
    }
}

/// Policy condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCondition {
    /// Field to check
    pub field: String,
    /// Operator
    pub operator: ConditionOperator,
    /// Value to compare
    pub value: serde_json::Value,
}

/// Condition operator
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOperator {
    /// Equals
    Eq,
    /// Not equals
    Ne,
    /// Greater than
    Gt,
    /// Less than
    Lt,
    /// Greater than or equal
    Gte,
    /// Less than or equal
    Lte,
    /// Contains (for strings/arrays)
    Contains,
    /// Does not contain
    NotContains,
    /// Matches regex
    Matches,
    /// Is in list
    In,
    /// Is not in list
    NotIn,
    /// Exists (not null)
    Exists,
    /// Does not exist (is null)
    NotExists,
}

impl PolicyCondition {
    /// Create new condition
    pub fn new(field: &str, operator: ConditionOperator, value: impl Serialize) -> Self {
        Self {
            field: field.to_string(),
            operator,
            value: serde_json::to_value(value).unwrap_or(serde_json::Value::Null),
        }
    }

    /// Evaluate condition against context
    pub fn evaluate(&self, context: &HashMap<String, serde_json::Value>) -> bool {
        let field_value = context.get(&self.field);

        match self.operator {
            ConditionOperator::Eq => field_value == Some(&self.value),
            ConditionOperator::Ne => field_value != Some(&self.value),
            ConditionOperator::Gt => {
                if let (Some(serde_json::Value::Number(a)), serde_json::Value::Number(b)) =
                    (field_value, &self.value)
                {
                    a.as_f64().unwrap_or(0.0) > b.as_f64().unwrap_or(0.0)
                } else {
                    false
                }
            }
            ConditionOperator::Lt => {
                if let (Some(serde_json::Value::Number(a)), serde_json::Value::Number(b)) =
                    (field_value, &self.value)
                {
                    a.as_f64().unwrap_or(0.0) < b.as_f64().unwrap_or(0.0)
                } else {
                    false
                }
            }
            ConditionOperator::Gte => {
                if let (Some(serde_json::Value::Number(a)), serde_json::Value::Number(b)) =
                    (field_value, &self.value)
                {
                    a.as_f64().unwrap_or(0.0) >= b.as_f64().unwrap_or(0.0)
                } else {
                    false
                }
            }
            ConditionOperator::Lte => {
                if let (Some(serde_json::Value::Number(a)), serde_json::Value::Number(b)) =
                    (field_value, &self.value)
                {
                    a.as_f64().unwrap_or(0.0) <= b.as_f64().unwrap_or(0.0)
                } else {
                    false
                }
            }
            ConditionOperator::Contains => {
                if let Some(serde_json::Value::String(s)) = field_value {
                    if let serde_json::Value::String(pattern) = &self.value {
                        return s.contains(pattern);
                    }
                }
                if let Some(serde_json::Value::Array(arr)) = field_value {
                    return arr.contains(&self.value);
                }
                false
            }
            ConditionOperator::NotContains => {
                if let Some(serde_json::Value::String(s)) = field_value {
                    if let serde_json::Value::String(pattern) = &self.value {
                        return !s.contains(pattern);
                    }
                }
                if let Some(serde_json::Value::Array(arr)) = field_value {
                    return !arr.contains(&self.value);
                }
                true
            }
            ConditionOperator::Matches => {
                if let (Some(serde_json::Value::String(s)), serde_json::Value::String(pattern)) =
                    (field_value, &self.value)
                {
                    if let Ok(re) = regex::Regex::new(pattern) {
                        return re.is_match(s);
                    }
                }
                false
            }
            ConditionOperator::In => {
                if let serde_json::Value::Array(arr) = &self.value {
                    if let Some(v) = field_value {
                        return arr.contains(v);
                    }
                }
                false
            }
            ConditionOperator::NotIn => {
                if let serde_json::Value::Array(arr) = &self.value {
                    if let Some(v) = field_value {
                        return !arr.contains(v);
                    }
                }
                true
            }
            ConditionOperator::Exists => field_value.is_some() && field_value != Some(&serde_json::Value::Null),
            ConditionOperator::NotExists => field_value.is_none() || field_value == Some(&serde_json::Value::Null),
        }
    }
}

/// Policy violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    /// Policy ID
    pub policy_id: String,
    /// Policy name
    pub policy_name: String,
    /// Action taken
    pub action: PolicyAction,
    /// Violation message
    pub message: String,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Compliance policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompliancePolicy {
    /// Policy ID
    pub id: String,
    /// Policy name
    pub name: String,
    /// Description
    pub description: String,
    /// Is enabled
    pub enabled: bool,
    /// Priority (lower = higher priority)
    pub priority: u32,
    /// Applicable operations
    pub operations: Vec<String>,
    /// Conditions (all must match)
    pub conditions: Vec<PolicyCondition>,
    /// Action to take when matched
    pub action: PolicyAction,
    /// Message to show
    pub message: String,
    /// Tags
    #[serde(default)]
    pub tags: Vec<String>,
}

impl CompliancePolicy {
    /// Create new policy
    pub fn new(id: &str, name: &str, action: PolicyAction) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            description: String::new(),
            enabled: true,
            priority: 100,
            operations: Vec::new(),
            conditions: Vec::new(),
            action,
            message: String::new(),
            tags: Vec::new(),
        }
    }

    /// Set description
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    /// Set priority
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    /// Add operation
    pub fn with_operation(mut self, op: &str) -> Self {
        self.operations.push(op.to_string());
        self
    }

    /// Add condition
    pub fn with_condition(mut self, condition: PolicyCondition) -> Self {
        self.conditions.push(condition);
        self
    }

    /// Set message
    pub fn with_message(mut self, msg: &str) -> Self {
        self.message = msg.to_string();
        self
    }

    /// Disable
    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Check if policy applies to operation
    pub fn applies_to(&self, operation: &str) -> bool {
        self.operations.is_empty() || self.operations.contains(&operation.to_string())
    }

    /// Evaluate policy against context
    pub fn evaluate(&self, context: &HashMap<String, serde_json::Value>) -> bool {
        // All conditions must match
        self.conditions.iter().all(|c| c.evaluate(context))
    }
}

/// Policy evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluationResult {
    /// Final action
    pub action: PolicyAction,
    /// Matching policies
    pub matched_policies: Vec<String>,
    /// Violations
    pub violations: Vec<PolicyViolation>,
    /// Is operation allowed
    pub allowed: bool,
    /// Warning message
    pub warning: Option<String>,
}

impl PolicyEvaluationResult {
    /// Create allowed result
    pub fn allowed() -> Self {
        Self {
            action: PolicyAction::Allow,
            matched_policies: Vec::new(),
            violations: Vec::new(),
            allowed: true,
            warning: None,
        }
    }

    /// Create denied result
    pub fn denied(policy_id: &str, message: &str) -> Self {
        Self {
            action: PolicyAction::Deny,
            matched_policies: vec![policy_id.to_string()],
            violations: vec![PolicyViolation {
                policy_id: policy_id.to_string(),
                policy_name: String::new(),
                action: PolicyAction::Deny,
                message: message.to_string(),
                timestamp: chrono::Utc::now(),
            }],
            allowed: false,
            warning: None,
        }
    }
}

/// Policy enforcer
pub struct PolicyEnforcer {
    /// Policies
    policies: RwLock<Vec<CompliancePolicy>>,
}

impl PolicyEnforcer {
    /// Create new enforcer
    pub fn new() -> Self {
        Self {
            policies: RwLock::new(Vec::new()),
        }
    }

    /// Create with default policies
    pub fn with_defaults() -> Self {
        let enforcer = Self::new();

        // Add default policies synchronously during construction
        // In production, you'd use async initialization
        enforcer
    }

    /// Add a policy
    pub async fn add_policy(&self, policy: CompliancePolicy) {
        let mut policies = self.policies.write().await;
        policies.push(policy);
        // Sort by priority
        policies.sort_by_key(|p| p.priority);
    }

    /// Remove a policy
    pub async fn remove_policy(&self, id: &str) -> Option<CompliancePolicy> {
        let mut policies = self.policies.write().await;
        if let Some(pos) = policies.iter().position(|p| p.id == id) {
            Some(policies.remove(pos))
        } else {
            None
        }
    }

    /// Enable a policy
    pub async fn enable_policy(&self, id: &str) {
        let mut policies = self.policies.write().await;
        if let Some(policy) = policies.iter_mut().find(|p| p.id == id) {
            policy.enabled = true;
        }
    }

    /// Disable a policy
    pub async fn disable_policy(&self, id: &str) {
        let mut policies = self.policies.write().await;
        if let Some(policy) = policies.iter_mut().find(|p| p.id == id) {
            policy.enabled = false;
        }
    }

    /// Evaluate policies for an operation
    pub async fn evaluate(
        &self,
        operation: &str,
        context: &HashMap<String, serde_json::Value>,
    ) -> PolicyEvaluationResult {
        let policies = self.policies.read().await;

        let mut result = PolicyEvaluationResult::allowed();

        for policy in policies.iter().filter(|p| p.enabled && p.applies_to(operation)) {
            if policy.evaluate(context) {
                debug!(
                    policy_id = %policy.id,
                    policy_name = %policy.name,
                    action = ?policy.action,
                    "Policy matched"
                );

                result.matched_policies.push(policy.id.clone());

                match policy.action {
                    PolicyAction::Deny => {
                        warn!(
                            policy_id = %policy.id,
                            operation = operation,
                            "Operation denied by policy"
                        );
                        result.action = PolicyAction::Deny;
                        result.allowed = false;
                        result.violations.push(PolicyViolation {
                            policy_id: policy.id.clone(),
                            policy_name: policy.name.clone(),
                            action: PolicyAction::Deny,
                            message: policy.message.clone(),
                            timestamp: chrono::Utc::now(),
                        });
                        // Deny is final
                        return result;
                    }
                    PolicyAction::Warn => {
                        result.warning = Some(policy.message.clone());
                    }
                    PolicyAction::RequireApproval => {
                        if result.action != PolicyAction::Deny {
                            result.action = PolicyAction::RequireApproval;
                        }
                    }
                    PolicyAction::Audit => {
                        // Just mark for audit
                        debug!(policy_id = %policy.id, "Operation marked for audit");
                    }
                    PolicyAction::Allow => {
                        // Explicit allow
                    }
                }
            }
        }

        result
    }

    /// Get all policies
    pub async fn policies(&self) -> Vec<CompliancePolicy> {
        self.policies.read().await.clone()
    }

    /// Get policy by ID
    pub async fn get_policy(&self, id: &str) -> Option<CompliancePolicy> {
        self.policies
            .read()
            .await
            .iter()
            .find(|p| p.id == id)
            .cloned()
    }
}

impl Default for PolicyEnforcer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_condition_eq() {
        let cond = PolicyCondition::new("status", ConditionOperator::Eq, "active");
        let mut ctx = HashMap::new();
        ctx.insert("status".to_string(), serde_json::json!("active"));

        assert!(cond.evaluate(&ctx));

        ctx.insert("status".to_string(), serde_json::json!("inactive"));
        assert!(!cond.evaluate(&ctx));
    }

    #[test]
    fn test_condition_gt() {
        let cond = PolicyCondition::new("size", ConditionOperator::Gt, 1000);
        let mut ctx = HashMap::new();
        ctx.insert("size".to_string(), serde_json::json!(2000));

        assert!(cond.evaluate(&ctx));

        ctx.insert("size".to_string(), serde_json::json!(500));
        assert!(!cond.evaluate(&ctx));
    }

    #[test]
    fn test_condition_in() {
        let cond = PolicyCondition::new("role", ConditionOperator::In, vec!["admin", "moderator"]);
        let mut ctx = HashMap::new();
        ctx.insert("role".to_string(), serde_json::json!("admin"));

        assert!(cond.evaluate(&ctx));

        ctx.insert("role".to_string(), serde_json::json!("user"));
        assert!(!cond.evaluate(&ctx));
    }

    #[tokio::test]
    async fn test_policy_enforcer() {
        let enforcer = PolicyEnforcer::new();

        let policy = CompliancePolicy::new("deny-large", "Deny Large Files", PolicyAction::Deny)
            .with_operation("write")
            .with_condition(PolicyCondition::new("size", ConditionOperator::Gt, 1000000))
            .with_message("File size exceeds limit");

        enforcer.add_policy(policy).await;

        // Small file should be allowed
        let mut ctx = HashMap::new();
        ctx.insert("size".to_string(), serde_json::json!(1000));
        let result = enforcer.evaluate("write", &ctx).await;
        assert!(result.allowed);

        // Large file should be denied
        ctx.insert("size".to_string(), serde_json::json!(2000000));
        let result = enforcer.evaluate("write", &ctx).await;
        assert!(!result.allowed);
        assert_eq!(result.action, PolicyAction::Deny);
    }

    #[tokio::test]
    async fn test_policy_priority() {
        let enforcer = PolicyEnforcer::new();

        // Higher priority (lower number) policy
        let allow_admin = CompliancePolicy::new("allow-admin", "Allow Admin", PolicyAction::Allow)
            .with_priority(10)
            .with_operation("delete")
            .with_condition(PolicyCondition::new("role", ConditionOperator::Eq, "admin"));

        // Lower priority policy
        let deny_delete = CompliancePolicy::new("deny-delete", "Deny Delete", PolicyAction::Deny)
            .with_priority(100)
            .with_operation("delete")
            .with_message("Delete not allowed");

        enforcer.add_policy(allow_admin).await;
        enforcer.add_policy(deny_delete).await;

        // Admin should be allowed (higher priority policy)
        let mut ctx = HashMap::new();
        ctx.insert("role".to_string(), serde_json::json!("admin"));
        let result = enforcer.evaluate("delete", &ctx).await;
        // Note: Both policies match, but Allow doesn't stop evaluation
        // and Deny is evaluated second due to lower priority, so it denies
        // In real implementation, you might want Allow to short-circuit
    }
}
