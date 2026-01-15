//! Degraded Mode Gate
//!
//! require_not_degraded: Degraded mode blocks strong economic actions

use crate::error::P3Error;
use crate::types::{DegradedFlag, PendingKind};
use super::GateCheckResult;

/// Degraded mode gate
pub struct DegradedGate;

impl DegradedGate {
    pub fn new() -> Self {
        Self
    }

    /// Require not in degraded mode
    pub fn require_not_degraded(&self, flags: &[DegradedFlag]) -> GateCheckResult {
        if flags.is_empty() {
            GateCheckResult::pass()
        } else {
            // Return the first blocking flag
            let flag = &flags[0];
            GateCheckResult::pending(
                P3Error::DegradedModeBlocks {
                    flag: flag.name().to_string(),
                },
                self.pending_kind_for_flag(flag),
            )
        }
    }

    /// Check if a specific degraded flag is present
    pub fn is_degraded(&self, flags: &[DegradedFlag], check: &DegradedFlag) -> bool {
        flags.iter().any(|f| f == check)
    }

    /// Get pending kind for a degraded flag
    fn pending_kind_for_flag(&self, flag: &DegradedFlag) -> PendingKind {
        match flag {
            DegradedFlag::DsnDown => PendingKind::Evidence,
            DegradedFlag::L0Down => PendingKind::Evidence,
            DegradedFlag::EconDown => PendingKind::Execution,
            DegradedFlag::AnchorCap => PendingKind::Budget,
            DegradedFlag::VersionDrift => PendingKind::Version,
            DegradedFlag::UnknownVersion => PendingKind::Version,
        }
    }

    /// Get all blocking flags for strong actions
    pub fn get_blocking_flags<'a>(&self, flags: &'a [DegradedFlag]) -> Vec<&'a DegradedFlag> {
        // All degraded flags block strong actions
        flags.iter().collect()
    }
}

impl Default for DegradedGate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_not_degraded_passes() {
        let gate = DegradedGate::new();
        let result = gate.require_not_degraded(&[]);
        assert!(result.passed);
    }

    #[test]
    fn test_degraded_fails() {
        let gate = DegradedGate::new();
        let result = gate.require_not_degraded(&[DegradedFlag::DsnDown]);
        assert!(!result.passed);
        assert!(result.pending_kind.is_some());
    }

    #[test]
    fn test_is_degraded() {
        let gate = DegradedGate::new();
        let flags = vec![DegradedFlag::DsnDown, DegradedFlag::AnchorCap];
        assert!(gate.is_degraded(&flags, &DegradedFlag::DsnDown));
        assert!(!gate.is_degraded(&flags, &DegradedFlag::L0Down));
    }
}
