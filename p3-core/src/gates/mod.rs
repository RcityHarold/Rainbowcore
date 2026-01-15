//! Hard Gates - Threshold Functions
//!
//! All strong economic actions must pass through hard gates:
//! - require_A: Evidence level A required
//! - require_not_degraded: Degraded mode blocks strong actions
//! - require_known_versions: Unknown versions block strong actions
//! - require_execution_proof: Execution proof required for final payouts
//! - require_verdict_ref: Verdict reference required for forfeit/fine
//! - require_append_only: Sealed epochs cannot be modified

mod append_only;
mod degraded;
mod evidence;
mod proof;
mod strong_action;
mod version;

pub use append_only::*;
pub use degraded::*;
pub use evidence::*;
pub use proof::*;
pub use strong_action::*;
pub use version::*;

use crate::error::{EvidenceLevelThreshold, P3Error, P3Result};
use crate::types::*;

/// Gate check context
#[derive(Clone, Debug)]
pub struct GateContext {
    /// Current epoch ID
    pub epoch_id: EpochId,
    /// Current degraded flags
    pub degraded_flags: Vec<DegradedFlag>,
    /// Known version set
    pub known_versions: KnownVersionSet,
    /// Evidence level for the action
    pub evidence_level: EvidenceLevel,
}

impl GateContext {
    pub fn new(epoch_id: EpochId) -> Self {
        Self {
            epoch_id,
            degraded_flags: Vec::new(),
            known_versions: KnownVersionSet::default_v1(),
            evidence_level: EvidenceLevel::B,
        }
    }

    pub fn with_evidence_level(mut self, level: EvidenceLevel) -> Self {
        self.evidence_level = level;
        self
    }

    pub fn with_degraded_flag(mut self, flag: DegradedFlag) -> Self {
        self.degraded_flags.push(flag);
        self
    }

    pub fn is_degraded(&self) -> bool {
        !self.degraded_flags.is_empty()
    }
}

/// Gate check result
#[derive(Clone, Debug)]
pub struct GateCheckResult {
    pub passed: bool,
    pub error: Option<P3Error>,
    pub pending_kind: Option<PendingKind>,
}

impl GateCheckResult {
    pub fn pass() -> Self {
        Self {
            passed: true,
            error: None,
            pending_kind: None,
        }
    }

    pub fn fail(error: P3Error) -> Self {
        Self {
            passed: false,
            error: Some(error),
            pending_kind: None,
        }
    }

    pub fn pending(error: P3Error, kind: PendingKind) -> Self {
        Self {
            passed: false,
            error: Some(error),
            pending_kind: Some(kind),
        }
    }
}

/// Combined gate checker
pub struct GateChecker {
    evidence_gate: EvidenceGate,
    degraded_gate: DegradedGate,
    version_gate: VersionGate,
    proof_gate: ProofGate,
    append_only_gate: AppendOnlyGate,
    strong_action_gate: StrongActionGate,
}

impl GateChecker {
    pub fn new() -> Self {
        Self {
            evidence_gate: EvidenceGate::new(),
            degraded_gate: DegradedGate::new(),
            version_gate: VersionGate::new(),
            proof_gate: ProofGate::new(),
            append_only_gate: AppendOnlyGate::new(),
            strong_action_gate: StrongActionGate::new(),
        }
    }

    /// Check all gates for a strong economic action
    pub fn check_strong_action(
        &self,
        ctx: &GateContext,
        action: &StrongEconomicAction,
        proof: Option<&ExecutionProofRef>,
        verdict_ref: Option<&P3Digest>,
    ) -> GateCheckResult {
        // 1. Check evidence level
        let evidence_result = self.evidence_gate.require_a(&ctx.evidence_level);
        if !evidence_result.passed {
            return evidence_result;
        }

        // 2. Check not degraded
        let degraded_result = self.degraded_gate.require_not_degraded(&ctx.degraded_flags);
        if !degraded_result.passed {
            return degraded_result;
        }

        // 3. Check versions known
        let version_result = self.version_gate.require_known(&ctx.known_versions);
        if !version_result.passed {
            return version_result;
        }

        // 4. Check execution proof for certain actions
        if self.strong_action_gate.requires_execution_proof(action) {
            let proof_result = self.proof_gate.require_proof(proof);
            if !proof_result.passed {
                return proof_result;
            }
        }

        // 5. Check verdict ref for forfeit/fine
        if self.strong_action_gate.requires_verdict_ref(action) {
            let verdict_result = self.strong_action_gate.require_verdict_ref(verdict_ref);
            if !verdict_result.passed {
                return verdict_result;
            }
        }

        GateCheckResult::pass()
    }

    /// Check if epoch modification is allowed
    pub fn check_epoch_modification(
        &self,
        epoch: &EconomyEpoch,
        is_sealed: bool,
    ) -> GateCheckResult {
        self.append_only_gate.require_not_sealed(&epoch.epoch_id, is_sealed)
    }
}

impl Default for GateChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gate_context_creation() {
        let ctx = GateContext::new(EpochId::new("epoch:test"))
            .with_evidence_level(EvidenceLevel::A);
        assert_eq!(ctx.evidence_level, EvidenceLevel::A);
        assert!(!ctx.is_degraded());
    }

    #[test]
    fn test_gate_context_degraded() {
        let ctx = GateContext::new(EpochId::new("epoch:test"))
            .with_degraded_flag(DegradedFlag::DsnDown);
        assert!(ctx.is_degraded());
    }
}
