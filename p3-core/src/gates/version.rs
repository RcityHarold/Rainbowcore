//! Version Gate
//!
//! require_known_versions: Unknown versions block strong economic actions

use crate::error::P3Error;
use crate::types::{KnownVersionSet, PendingKind, VersionType};
use super::GateCheckResult;

/// Version gate
pub struct VersionGate;

impl VersionGate {
    pub fn new() -> Self {
        Self
    }

    /// Require all versions in the set are known
    pub fn require_known(&self, known_set: &KnownVersionSet) -> GateCheckResult {
        // For now, we assume the known set is valid if it has v1 versions
        // In a real implementation, this would check against a registry
        if known_set.weights_versions.is_empty() {
            return GateCheckResult::pending(
                P3Error::UnknownVersionBlocks {
                    version: "weights".to_string(),
                },
                PendingKind::Version,
            );
        }
        GateCheckResult::pass()
    }

    /// Check if a specific version is known
    pub fn is_version_known(
        &self,
        known_set: &KnownVersionSet,
        version_type: &VersionType,
        version_id: &str,
    ) -> GateCheckResult {
        if known_set.is_known(version_type, version_id) {
            GateCheckResult::pass()
        } else {
            GateCheckResult::pending(
                P3Error::UnknownVersionBlocks {
                    version: format!("{}:{}", version_type.name(), version_id),
                },
                PendingKind::Version,
            )
        }
    }

    /// Require a specific weights version is known
    pub fn require_weights_version_known(
        &self,
        known_set: &KnownVersionSet,
        version_id: &str,
    ) -> GateCheckResult {
        self.is_version_known(known_set, &VersionType::Weights, version_id)
    }

    /// Require a specific policy version is known
    pub fn require_policy_version_known(
        &self,
        known_set: &KnownVersionSet,
        version_id: &str,
    ) -> GateCheckResult {
        self.is_version_known(known_set, &VersionType::LineagePolicy, version_id)
    }

    /// Check for version drift (warning only)
    pub fn check_version_drift(
        &self,
        expected: &str,
        actual: &str,
    ) -> Option<VersionDriftWarning> {
        if expected != actual {
            Some(VersionDriftWarning {
                expected: expected.to_string(),
                actual: actual.to_string(),
            })
        } else {
            None
        }
    }
}

impl Default for VersionGate {
    fn default() -> Self {
        Self::new()
    }
}

/// Version drift warning
#[derive(Clone, Debug)]
pub struct VersionDriftWarning {
    pub expected: String,
    pub actual: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_require_known_passes() {
        let gate = VersionGate::new();
        let known_set = KnownVersionSet::default_v1();
        let result = gate.require_known(&known_set);
        assert!(result.passed);
    }

    #[test]
    fn test_require_known_fails_empty() {
        let gate = VersionGate::new();
        let known_set = KnownVersionSet {
            weights_versions: vec![],
            pool_ratio_versions: vec!["v1".to_string()],
            fee_schedule_versions: vec!["v1".to_string()],
            lineage_policy_versions: vec!["v1".to_string()],
            error_code_versions: vec!["v1".to_string()],
            canon_versions: vec!["v1".to_string()],
        };
        let result = gate.require_known(&known_set);
        assert!(!result.passed);
    }

    #[test]
    fn test_is_version_known() {
        let gate = VersionGate::new();
        let known_set = KnownVersionSet::default_v1();

        let result = gate.is_version_known(&known_set, &VersionType::Weights, "v1");
        assert!(result.passed);

        let result = gate.is_version_known(&known_set, &VersionType::Weights, "v2");
        assert!(!result.passed);
    }

    #[test]
    fn test_version_drift() {
        let gate = VersionGate::new();
        assert!(gate.check_version_drift("v1", "v2").is_some());
        assert!(gate.check_version_drift("v1", "v1").is_none());
    }
}
