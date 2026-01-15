//! Strong Economic Action Gate
//!
//! Defines which actions are considered "strong" and their requirements

use crate::error::P3Error;
use crate::types::{P3Digest, StrongEconomicAction};
use super::GateCheckResult;

/// Strong economic action gate
pub struct StrongActionGate;

impl StrongActionGate {
    pub fn new() -> Self {
        Self
    }

    /// Check if action requires execution proof
    pub fn requires_execution_proof(&self, action: &StrongEconomicAction) -> bool {
        matches!(
            action,
            StrongEconomicAction::FinalClawbackExecute
                | StrongEconomicAction::FinalRewardPayout
                | StrongEconomicAction::PermanentDepositForfeit
                | StrongEconomicAction::IrreversibleAccountFreeze
        )
    }

    /// Check if action requires verdict reference
    pub fn requires_verdict_ref(&self, action: &StrongEconomicAction) -> bool {
        matches!(
            action,
            StrongEconomicAction::FinalClawbackExecute
                | StrongEconomicAction::PermanentDepositForfeit
        )
    }

    /// Check if action is forbidden (historic mutation)
    pub fn is_forbidden(&self, action: &StrongEconomicAction) -> bool {
        matches!(action, StrongEconomicAction::HistoricResultMutation)
    }

    /// Require verdict reference for forfeit/fine operations
    pub fn require_verdict_ref(&self, verdict_ref: Option<&P3Digest>) -> GateCheckResult {
        match verdict_ref {
            Some(v) if !v.is_zero() => GateCheckResult::pass(),
            _ => GateCheckResult::fail(P3Error::VerdictRefRequired),
        }
    }

    /// Check if action can proceed
    pub fn can_proceed(&self, action: &StrongEconomicAction) -> GateCheckResult {
        if self.is_forbidden(action) {
            GateCheckResult::fail(P3Error::AppendOnlyViolation {
                epoch_id: "historic_mutation".to_string(),
            })
        } else {
            GateCheckResult::pass()
        }
    }

    /// Get all requirements for an action
    pub fn get_requirements(&self, action: &StrongEconomicAction) -> ActionRequirements {
        ActionRequirements {
            requires_evidence_a: true,
            requires_not_degraded: true,
            requires_known_versions: true,
            requires_execution_proof: self.requires_execution_proof(action),
            requires_verdict_ref: self.requires_verdict_ref(action),
            is_forbidden: self.is_forbidden(action),
        }
    }
}

impl Default for StrongActionGate {
    fn default() -> Self {
        Self::new()
    }
}

/// Requirements for a strong action
#[derive(Clone, Debug)]
pub struct ActionRequirements {
    pub requires_evidence_a: bool,
    pub requires_not_degraded: bool,
    pub requires_known_versions: bool,
    pub requires_execution_proof: bool,
    pub requires_verdict_ref: bool,
    pub is_forbidden: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_requires_execution_proof() {
        let gate = StrongActionGate::new();
        assert!(gate.requires_execution_proof(&StrongEconomicAction::FinalClawbackExecute));
        assert!(gate.requires_execution_proof(&StrongEconomicAction::FinalRewardPayout));
        assert!(!gate.requires_execution_proof(&StrongEconomicAction::HistoricResultMutation));
    }

    #[test]
    fn test_requires_verdict_ref() {
        let gate = StrongActionGate::new();
        assert!(gate.requires_verdict_ref(&StrongEconomicAction::FinalClawbackExecute));
        assert!(gate.requires_verdict_ref(&StrongEconomicAction::PermanentDepositForfeit));
        assert!(!gate.requires_verdict_ref(&StrongEconomicAction::FinalRewardPayout));
    }

    #[test]
    fn test_is_forbidden() {
        let gate = StrongActionGate::new();
        assert!(gate.is_forbidden(&StrongEconomicAction::HistoricResultMutation));
        assert!(!gate.is_forbidden(&StrongEconomicAction::FinalClawbackExecute));
    }

    #[test]
    fn test_require_verdict_ref() {
        let gate = StrongActionGate::new();

        let result = gate.require_verdict_ref(Some(&P3Digest::blake3(b"verdict")));
        assert!(result.passed);

        let result = gate.require_verdict_ref(Some(&P3Digest::zero()));
        assert!(!result.passed);

        let result = gate.require_verdict_ref(None);
        assert!(!result.passed);
    }

    #[test]
    fn test_get_requirements() {
        let gate = StrongActionGate::new();
        let reqs = gate.get_requirements(&StrongEconomicAction::FinalClawbackExecute);
        assert!(reqs.requires_evidence_a);
        assert!(reqs.requires_execution_proof);
        assert!(reqs.requires_verdict_ref);
        assert!(!reqs.is_forbidden);
    }
}
