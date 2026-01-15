//! Evidence Gate
//!
//! require_A: Evidence level A required for strong economic actions

use crate::error::{EvidenceLevelThreshold, P3Error};
use crate::types::EvidenceLevel;
use super::GateCheckResult;

/// Evidence level gate
pub struct EvidenceGate;

impl EvidenceGate {
    pub fn new() -> Self {
        Self
    }

    /// Require evidence level A
    pub fn require_a(&self, level: &EvidenceLevel) -> GateCheckResult {
        match level {
            EvidenceLevel::A => GateCheckResult::pass(),
            EvidenceLevel::B => GateCheckResult::fail(P3Error::EvidenceBelowThreshold {
                required: EvidenceLevelThreshold::A,
                actual: EvidenceLevelThreshold::B,
            }),
            EvidenceLevel::Pending => GateCheckResult::fail(P3Error::EvidenceBelowThreshold {
                required: EvidenceLevelThreshold::A,
                actual: EvidenceLevelThreshold::Pending,
            }),
        }
    }

    /// Require at least evidence level B
    pub fn require_b(&self, level: &EvidenceLevel) -> GateCheckResult {
        match level {
            EvidenceLevel::A | EvidenceLevel::B => GateCheckResult::pass(),
            EvidenceLevel::Pending => GateCheckResult::fail(P3Error::EvidenceBelowThreshold {
                required: EvidenceLevelThreshold::B,
                actual: EvidenceLevelThreshold::Pending,
            }),
        }
    }

    /// Check if evidence level meets threshold
    pub fn meets_threshold(&self, level: &EvidenceLevel, threshold: EvidenceLevelThreshold) -> bool {
        match (level, threshold) {
            (EvidenceLevel::A, _) => true,
            (EvidenceLevel::B, EvidenceLevelThreshold::B) => true,
            (EvidenceLevel::B, EvidenceLevelThreshold::Pending) => true,
            (EvidenceLevel::Pending, EvidenceLevelThreshold::Pending) => true,
            _ => false,
        }
    }
}

impl Default for EvidenceGate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_require_a_passes() {
        let gate = EvidenceGate::new();
        let result = gate.require_a(&EvidenceLevel::A);
        assert!(result.passed);
    }

    #[test]
    fn test_require_a_fails_for_b() {
        let gate = EvidenceGate::new();
        let result = gate.require_a(&EvidenceLevel::B);
        assert!(!result.passed);
    }

    #[test]
    fn test_require_b_passes_for_a() {
        let gate = EvidenceGate::new();
        let result = gate.require_b(&EvidenceLevel::A);
        assert!(result.passed);
    }

    #[test]
    fn test_require_b_passes_for_b() {
        let gate = EvidenceGate::new();
        let result = gate.require_b(&EvidenceLevel::B);
        assert!(result.passed);
    }

    #[test]
    fn test_meets_threshold() {
        let gate = EvidenceGate::new();
        assert!(gate.meets_threshold(&EvidenceLevel::A, EvidenceLevelThreshold::A));
        assert!(gate.meets_threshold(&EvidenceLevel::A, EvidenceLevelThreshold::B));
        assert!(!gate.meets_threshold(&EvidenceLevel::B, EvidenceLevelThreshold::A));
    }
}
