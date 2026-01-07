//! Compliance Checking Module
//!
//! Provides compliance validation and policy enforcement for P2 storage.
//!
//! # Features
//!
//! - **Compliance rules**: Configurable compliance rules and policies
//! - **Validation**: Data and operation compliance checking
//! - **Audit**: Compliance audit trail
//! - **Reporting**: Compliance status reports

pub mod rules;
pub mod checker;
pub mod audit;
pub mod policy;

pub use rules::{
    ComplianceRule, ComplianceRuleSet, RuleCategory, RuleSeverity, RuleViolation,
};
pub use checker::{
    ComplianceChecker, ComplianceCheckResult, ComplianceStatus, ComplianceContext,
};
pub use audit::{
    ComplianceAuditEntry, ComplianceAuditLog, AuditEventType,
};
pub use policy::{
    CompliancePolicy, PolicyAction, PolicyCondition, PolicyEnforcer, PolicyViolation,
};
