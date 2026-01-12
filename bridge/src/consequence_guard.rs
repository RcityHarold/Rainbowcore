//! Evidence-Level Consequence Guard (ISSUE-005)
//!
//! Implements strong consequence blocking based on evidence level.
//! Per DSN documentation, certain high-consequence operations MUST be blocked
//! when evidence is at B-level (lacking full proof chain).
//!
//! # Blocked Operations at B-Level
//!
//! - **Binding Operations**: Creating binding agreements, contracts
//! - **Strong Settlement**: Irreversible financial settlements
//! - **Custody Transfer**: Permanent custody changes
//! - **Asset Liquidation**: Forced liquidation actions
//!
//! # Allowed Operations at B-Level
//!
//! - Read-only queries
//! - Evidence gathering
//! - Temporary holds
//! - Audit logging
//!
//! # Usage
//!
//! ```ignore
//! let guard = ConsequenceGuard::new(evidence_level);
//! guard.check_operation(ConsequenceOperation::Binding)?;
//! ```

use chrono::{DateTime, Utc};
use l0_core::types::EvidenceLevel;
use serde::{Deserialize, Serialize};
use std::fmt;

/// High-consequence operations that may be blocked
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsequenceOperation {
    /// Creating binding agreements or contracts
    Binding,
    /// Irreversible financial settlement
    StrongSettlement,
    /// Temporary/reversible settlement
    WeakSettlement,
    /// Permanent custody transfer
    CustodyTransfer,
    /// Temporary custody hold
    CustodyHold,
    /// Forced asset liquidation
    AssetLiquidation,
    /// Voluntary asset transfer
    AssetTransfer,
    /// Evidence export for legal proceedings
    EvidenceExport,
    /// Audit query (read-only)
    AuditQuery,
    /// Dispute initiation
    DisputeInitiation,
    /// Verdict execution
    VerdictExecution,
}

impl ConsequenceOperation {
    /// Check if this operation is high-consequence (requires A-level evidence)
    pub fn is_high_consequence(&self) -> bool {
        matches!(
            self,
            ConsequenceOperation::Binding
                | ConsequenceOperation::StrongSettlement
                | ConsequenceOperation::CustodyTransfer
                | ConsequenceOperation::AssetLiquidation
                | ConsequenceOperation::VerdictExecution
        )
    }

    /// Check if this operation is allowed at B-level evidence
    pub fn allowed_at_b_level(&self) -> bool {
        matches!(
            self,
            ConsequenceOperation::WeakSettlement
                | ConsequenceOperation::CustodyHold
                | ConsequenceOperation::AssetTransfer
                | ConsequenceOperation::EvidenceExport
                | ConsequenceOperation::AuditQuery
                | ConsequenceOperation::DisputeInitiation
        )
    }

    /// Get the minimum required evidence level
    pub fn minimum_evidence_level(&self) -> EvidenceLevel {
        if self.is_high_consequence() {
            EvidenceLevel::A
        } else {
            EvidenceLevel::B
        }
    }
}

impl fmt::Display for ConsequenceOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConsequenceOperation::Binding => write!(f, "binding"),
            ConsequenceOperation::StrongSettlement => write!(f, "strong_settlement"),
            ConsequenceOperation::WeakSettlement => write!(f, "weak_settlement"),
            ConsequenceOperation::CustodyTransfer => write!(f, "custody_transfer"),
            ConsequenceOperation::CustodyHold => write!(f, "custody_hold"),
            ConsequenceOperation::AssetLiquidation => write!(f, "asset_liquidation"),
            ConsequenceOperation::AssetTransfer => write!(f, "asset_transfer"),
            ConsequenceOperation::EvidenceExport => write!(f, "evidence_export"),
            ConsequenceOperation::AuditQuery => write!(f, "audit_query"),
            ConsequenceOperation::DisputeInitiation => write!(f, "dispute_initiation"),
            ConsequenceOperation::VerdictExecution => write!(f, "verdict_execution"),
        }
    }
}

/// Error when operation is blocked due to evidence level
#[derive(Debug, Clone)]
pub struct ConsequenceBlockedError {
    /// The operation that was blocked
    pub operation: ConsequenceOperation,
    /// Current evidence level
    pub current_level: EvidenceLevel,
    /// Required evidence level
    pub required_level: EvidenceLevel,
    /// Reason for blocking
    pub reason: String,
    /// Blocked timestamp
    pub blocked_at: DateTime<Utc>,
    /// Suggestions for resolution
    pub resolution_hints: Vec<String>,
}

impl fmt::Display for ConsequenceBlockedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Operation '{}' blocked: requires {:?} evidence but current level is {:?}. {}",
            self.operation, self.required_level, self.current_level, self.reason
        )
    }
}

impl std::error::Error for ConsequenceBlockedError {}

impl ConsequenceBlockedError {
    /// Create a new blocked error
    pub fn new(
        operation: ConsequenceOperation,
        current_level: EvidenceLevel,
        required_level: EvidenceLevel,
    ) -> Self {
        let reason = format!(
            "High-consequence operation '{}' requires full evidence chain (A-level)",
            operation
        );

        let resolution_hints = match current_level {
            EvidenceLevel::B => vec![
                "Ensure payload_map_commit is present and anchored".to_string(),
                "Verify L0 receipt exists for all evidence bundles".to_string(),
                "Run backfill process to upgrade evidence level".to_string(),
                "Contact support if evidence chain cannot be established".to_string(),
            ],
            EvidenceLevel::A => vec![], // Shouldn't happen
        };

        Self {
            operation,
            current_level,
            required_level,
            reason,
            blocked_at: Utc::now(),
            resolution_hints,
        }
    }
}

/// Consequence Guard - blocks high-consequence operations at B-level
#[derive(Debug, Clone)]
pub struct ConsequenceGuard {
    /// Current evidence level
    evidence_level: EvidenceLevel,
    /// Reference to evidence bundle (for audit)
    evidence_ref: Option<String>,
    /// Whether to enforce strict mode (block all high-consequence ops)
    strict_mode: bool,
    /// Override permissions (for emergency/admin use)
    override_permissions: Vec<ConsequenceOperation>,
}

impl ConsequenceGuard {
    /// Create a new consequence guard
    pub fn new(evidence_level: EvidenceLevel) -> Self {
        Self {
            evidence_level,
            evidence_ref: None,
            strict_mode: true,
            override_permissions: Vec::new(),
        }
    }

    /// Create with evidence reference
    pub fn with_evidence_ref(mut self, evidence_ref: String) -> Self {
        self.evidence_ref = Some(evidence_ref);
        self
    }

    /// Disable strict mode (allows some operations with warnings)
    pub fn with_relaxed_mode(mut self) -> Self {
        self.strict_mode = false;
        self
    }

    /// Add override permission for specific operation
    ///
    /// **WARNING**: Use only for emergency/admin scenarios with proper audit trail
    pub fn with_override(mut self, operation: ConsequenceOperation) -> Self {
        self.override_permissions.push(operation);
        self
    }

    /// Check if an operation is allowed
    pub fn check_operation(
        &self,
        operation: ConsequenceOperation,
    ) -> Result<ConsequenceCheckResult, ConsequenceBlockedError> {
        // Check if operation has override
        if self.override_permissions.contains(&operation) {
            return Ok(ConsequenceCheckResult {
                allowed: true,
                operation,
                evidence_level: self.evidence_level,
                was_overridden: true,
                warnings: vec!["Operation allowed via override - ensure proper audit trail".to_string()],
            });
        }

        let required_level = operation.minimum_evidence_level();

        // A-level evidence allows all operations
        if self.evidence_level == EvidenceLevel::A {
            return Ok(ConsequenceCheckResult {
                allowed: true,
                operation,
                evidence_level: self.evidence_level,
                was_overridden: false,
                warnings: vec![],
            });
        }

        // B-level evidence: check if operation is allowed
        if operation.allowed_at_b_level() {
            return Ok(ConsequenceCheckResult {
                allowed: true,
                operation,
                evidence_level: self.evidence_level,
                was_overridden: false,
                warnings: vec![format!(
                    "Operating at B-level evidence. Consider upgrading to A-level for stronger guarantees."
                )],
            });
        }

        // High-consequence operation at B-level: BLOCK
        if self.strict_mode {
            return Err(ConsequenceBlockedError::new(
                operation,
                self.evidence_level,
                required_level,
            ));
        }

        // Relaxed mode: allow with strong warning
        Ok(ConsequenceCheckResult {
            allowed: true,
            operation,
            evidence_level: self.evidence_level,
            was_overridden: false,
            warnings: vec![
                format!(
                    "HIGH RISK: Operation '{}' executed at B-level evidence in relaxed mode",
                    operation
                ),
                "This operation normally requires A-level evidence".to_string(),
                "Ensure proper manual verification before proceeding".to_string(),
            ],
        })
    }

    /// Convenience method: check binding operation
    pub fn check_binding(&self) -> Result<ConsequenceCheckResult, ConsequenceBlockedError> {
        self.check_operation(ConsequenceOperation::Binding)
    }

    /// Convenience method: check strong settlement
    pub fn check_strong_settlement(&self) -> Result<ConsequenceCheckResult, ConsequenceBlockedError> {
        self.check_operation(ConsequenceOperation::StrongSettlement)
    }

    /// Convenience method: check custody transfer
    pub fn check_custody_transfer(&self) -> Result<ConsequenceCheckResult, ConsequenceBlockedError> {
        self.check_operation(ConsequenceOperation::CustodyTransfer)
    }

    /// Convenience method: check asset liquidation
    pub fn check_asset_liquidation(&self) -> Result<ConsequenceCheckResult, ConsequenceBlockedError> {
        self.check_operation(ConsequenceOperation::AssetLiquidation)
    }

    /// Get the current evidence level
    pub fn evidence_level(&self) -> EvidenceLevel {
        self.evidence_level
    }

    /// Check if guard is in strict mode
    pub fn is_strict(&self) -> bool {
        self.strict_mode
    }
}

/// Result of a consequence check
#[derive(Debug, Clone)]
pub struct ConsequenceCheckResult {
    /// Whether the operation is allowed
    pub allowed: bool,
    /// The operation that was checked
    pub operation: ConsequenceOperation,
    /// Evidence level at time of check
    pub evidence_level: EvidenceLevel,
    /// Whether an override was used
    pub was_overridden: bool,
    /// Warnings (if any)
    pub warnings: Vec<String>,
}

/// Summary of consequence guard state for reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsequenceGuardSummary {
    /// Current evidence level
    pub evidence_level: String,
    /// Whether strict mode is enabled
    pub strict_mode: bool,
    /// List of blocked operations at current level
    pub blocked_operations: Vec<String>,
    /// List of allowed operations at current level
    pub allowed_operations: Vec<String>,
    /// Number of override permissions
    pub override_count: usize,
}

impl ConsequenceGuard {
    /// Get a summary of the guard state
    pub fn summary(&self) -> ConsequenceGuardSummary {
        let all_ops = vec![
            ConsequenceOperation::Binding,
            ConsequenceOperation::StrongSettlement,
            ConsequenceOperation::WeakSettlement,
            ConsequenceOperation::CustodyTransfer,
            ConsequenceOperation::CustodyHold,
            ConsequenceOperation::AssetLiquidation,
            ConsequenceOperation::AssetTransfer,
            ConsequenceOperation::EvidenceExport,
            ConsequenceOperation::AuditQuery,
            ConsequenceOperation::DisputeInitiation,
            ConsequenceOperation::VerdictExecution,
        ];

        let mut blocked = Vec::new();
        let mut allowed = Vec::new();

        for op in all_ops {
            if self.evidence_level == EvidenceLevel::A
                || op.allowed_at_b_level()
                || self.override_permissions.contains(&op)
            {
                allowed.push(op.to_string());
            } else {
                blocked.push(op.to_string());
            }
        }

        ConsequenceGuardSummary {
            evidence_level: format!("{:?}", self.evidence_level),
            strict_mode: self.strict_mode,
            blocked_operations: blocked,
            allowed_operations: allowed,
            override_count: self.override_permissions.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_high_consequence_operations() {
        assert!(ConsequenceOperation::Binding.is_high_consequence());
        assert!(ConsequenceOperation::StrongSettlement.is_high_consequence());
        assert!(ConsequenceOperation::CustodyTransfer.is_high_consequence());
        assert!(ConsequenceOperation::AssetLiquidation.is_high_consequence());
        assert!(ConsequenceOperation::VerdictExecution.is_high_consequence());

        assert!(!ConsequenceOperation::WeakSettlement.is_high_consequence());
        assert!(!ConsequenceOperation::AuditQuery.is_high_consequence());
    }

    #[test]
    fn test_b_level_allowed_operations() {
        assert!(ConsequenceOperation::WeakSettlement.allowed_at_b_level());
        assert!(ConsequenceOperation::CustodyHold.allowed_at_b_level());
        assert!(ConsequenceOperation::AuditQuery.allowed_at_b_level());

        assert!(!ConsequenceOperation::Binding.allowed_at_b_level());
        assert!(!ConsequenceOperation::StrongSettlement.allowed_at_b_level());
    }

    #[test]
    fn test_guard_a_level_allows_all() {
        let guard = ConsequenceGuard::new(EvidenceLevel::A);

        assert!(guard.check_binding().is_ok());
        assert!(guard.check_strong_settlement().is_ok());
        assert!(guard.check_custody_transfer().is_ok());
        assert!(guard.check_asset_liquidation().is_ok());
    }

    #[test]
    fn test_guard_b_level_blocks_high_consequence() {
        let guard = ConsequenceGuard::new(EvidenceLevel::B);

        // High-consequence ops should be blocked
        assert!(guard.check_binding().is_err());
        assert!(guard.check_strong_settlement().is_err());
        assert!(guard.check_custody_transfer().is_err());
        assert!(guard.check_asset_liquidation().is_err());

        // Low-consequence ops should be allowed
        assert!(guard.check_operation(ConsequenceOperation::WeakSettlement).is_ok());
        assert!(guard.check_operation(ConsequenceOperation::AuditQuery).is_ok());
    }

    #[test]
    fn test_guard_override() {
        let guard = ConsequenceGuard::new(EvidenceLevel::B)
            .with_override(ConsequenceOperation::Binding);

        // Overridden operation should be allowed
        let result = guard.check_binding().unwrap();
        assert!(result.allowed);
        assert!(result.was_overridden);
    }

    #[test]
    fn test_guard_relaxed_mode() {
        let guard = ConsequenceGuard::new(EvidenceLevel::B).with_relaxed_mode();

        // In relaxed mode, high-consequence ops allowed with warnings
        let result = guard.check_binding().unwrap();
        assert!(result.allowed);
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn test_blocked_error_message() {
        let error = ConsequenceBlockedError::new(
            ConsequenceOperation::Binding,
            EvidenceLevel::B,
            EvidenceLevel::A,
        );

        assert!(error.to_string().contains("binding"));
        assert!(error.to_string().contains("blocked"));
        assert!(!error.resolution_hints.is_empty());
    }

    #[test]
    fn test_guard_summary() {
        let guard = ConsequenceGuard::new(EvidenceLevel::B);
        let summary = guard.summary();

        assert_eq!(summary.evidence_level, "B");
        assert!(summary.strict_mode);
        assert!(summary.blocked_operations.contains(&"binding".to_string()));
        assert!(summary.allowed_operations.contains(&"audit_query".to_string()));
    }
}
