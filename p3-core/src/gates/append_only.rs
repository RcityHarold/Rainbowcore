//! Append-Only Gate
//!
//! require_append_only: Sealed epochs cannot be modified

use crate::error::P3Error;
use crate::types::EpochId;
use super::GateCheckResult;

/// Append-only gate
pub struct AppendOnlyGate;

impl AppendOnlyGate {
    pub fn new() -> Self {
        Self
    }

    /// Require epoch is not sealed (can be modified)
    pub fn require_not_sealed(&self, epoch_id: &EpochId, is_sealed: bool) -> GateCheckResult {
        if is_sealed {
            GateCheckResult::fail(P3Error::AppendOnlyViolation {
                epoch_id: epoch_id.0.clone(),
            })
        } else {
            GateCheckResult::pass()
        }
    }

    /// Check if modification is allowed (only via superseded chain)
    pub fn check_modification_allowed(
        &self,
        epoch_id: &EpochId,
        is_sealed: bool,
        has_superseded_ref: bool,
    ) -> GateCheckResult {
        if !is_sealed {
            // Not sealed, can modify directly
            GateCheckResult::pass()
        } else if has_superseded_ref {
            // Sealed but has superseded reference, allowed via append
            GateCheckResult::pass()
        } else {
            // Sealed without superseded ref, forbidden
            GateCheckResult::fail(P3Error::AppendOnlyViolation {
                epoch_id: epoch_id.0.clone(),
            })
        }
    }

    /// Validate superseded chain (cannot form cycles)
    pub fn validate_superseded_chain(
        &self,
        current_epoch_id: &EpochId,
        superseded_epoch_id: &EpochId,
    ) -> GateCheckResult {
        // Cannot supersede self
        if current_epoch_id.0 == superseded_epoch_id.0 {
            GateCheckResult::fail(P3Error::AppendOnlyViolation {
                epoch_id: format!("self_reference:{}", current_epoch_id.0),
            })
        } else {
            GateCheckResult::pass()
        }
    }
}

impl Default for AppendOnlyGate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_require_not_sealed_passes() {
        let gate = AppendOnlyGate::new();
        let epoch_id = EpochId::new("epoch:test");
        let result = gate.require_not_sealed(&epoch_id, false);
        assert!(result.passed);
    }

    #[test]
    fn test_require_not_sealed_fails() {
        let gate = AppendOnlyGate::new();
        let epoch_id = EpochId::new("epoch:test");
        let result = gate.require_not_sealed(&epoch_id, true);
        assert!(!result.passed);
    }

    #[test]
    fn test_modification_with_superseded() {
        let gate = AppendOnlyGate::new();
        let epoch_id = EpochId::new("epoch:test");

        // Sealed with superseded ref is allowed
        let result = gate.check_modification_allowed(&epoch_id, true, true);
        assert!(result.passed);

        // Sealed without superseded ref is forbidden
        let result = gate.check_modification_allowed(&epoch_id, true, false);
        assert!(!result.passed);
    }

    #[test]
    fn test_validate_superseded_chain() {
        let gate = AppendOnlyGate::new();
        let epoch1 = EpochId::new("epoch:1");
        let epoch2 = EpochId::new("epoch:2");

        // Different epochs are valid
        let result = gate.validate_superseded_chain(&epoch2, &epoch1);
        assert!(result.passed);

        // Self-reference is invalid
        let result = gate.validate_superseded_chain(&epoch1, &epoch1);
        assert!(!result.passed);
    }
}
