//! Evidence Level Determination
//!
//! This module implements the hard rule for evidence level determination:
//!
//! **HARD INVARIANT: Missing payload_map_commit MUST result in B-level evidence.**
//!
//! Evidence levels are critical for the legal and compliance aspects of the
//! Rainbow Public Reality Stack. A-level evidence is fully chain-backed and
//! reconciled, while B-level indicates some aspect is missing or unverified.

use chrono::{DateTime, Utc};
use l0_core::types::{Digest, EvidenceLevel, L0Receipt, ReceiptId, ReceiptVerifyResult};
use p2_core::types::SealedPayloadRef;
use serde::{Deserialize, Serialize};

use crate::error::{BridgeError, BridgeResult};
use crate::l0_client::L0CommitClient;
use crate::payload_map_commit::{PayloadMapCommit, VerifyResult};

/// Evidence level determination result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceLevelResult {
    /// Determined evidence level
    pub level: EvidenceLevel,
    /// Detailed breakdown of checks
    pub checks: Vec<EvidenceCheck>,
    /// Overall valid
    pub is_valid: bool,
    /// Downgrade reasons (if B-level)
    pub downgrade_reasons: Vec<DowngradeReason>,
    /// Determination timestamp
    pub determined_at: DateTime<Utc>,
}

impl EvidenceLevelResult {
    /// Create an A-level result (all checks passed)
    pub fn a_level() -> Self {
        Self {
            level: EvidenceLevel::A,
            checks: Vec::new(),
            is_valid: true,
            downgrade_reasons: Vec::new(),
            determined_at: Utc::now(),
        }
    }

    /// Create a B-level result with reasons
    pub fn b_level(reasons: Vec<DowngradeReason>) -> Self {
        Self {
            level: EvidenceLevel::B,
            checks: Vec::new(),
            is_valid: true,
            downgrade_reasons: reasons,
            determined_at: Utc::now(),
        }
    }

    /// Add a check result
    pub fn with_check(mut self, check: EvidenceCheck) -> Self {
        // If any check fails to pass for A-level, downgrade to B
        if !check.passed && self.level == EvidenceLevel::A {
            self.level = EvidenceLevel::B;
            self.downgrade_reasons.push(DowngradeReason::CheckFailed {
                check_name: check.name.clone(),
                details: check.details.clone(),
            });
        }
        self.checks.push(check);
        self
    }
}

/// Individual evidence check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceCheck {
    /// Check name
    pub name: String,
    /// Check passed
    pub passed: bool,
    /// Check details
    pub details: Option<String>,
    /// Check timestamp
    pub checked_at: DateTime<Utc>,
}

impl EvidenceCheck {
    /// Create a passing check
    pub fn pass(name: &str) -> Self {
        Self {
            name: name.to_string(),
            passed: true,
            details: None,
            checked_at: Utc::now(),
        }
    }

    /// Create a failing check
    pub fn fail(name: &str, details: &str) -> Self {
        Self {
            name: name.to_string(),
            passed: false,
            details: Some(details.to_string()),
            checked_at: Utc::now(),
        }
    }
}

/// Reason for evidence level downgrade
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DowngradeReason {
    /// No payload_map_commit exists (HARD INVARIANT VIOLATION)
    MissingMapCommit,
    /// No receipt exists
    MissingReceipt,
    /// Receipt verification failed
    ReceiptVerificationFailed { details: String },
    /// Payload digest mismatch
    DigestMismatch { expected: String, actual: String },
    /// Payload count mismatch
    CountMismatch { expected: u64, actual: u64 },
    /// Some payloads missing
    PayloadsMissing { refs: Vec<String> },
    /// Individual check failed
    CheckFailed { check_name: String, details: Option<String> },
    /// L0 unavailable during verification
    L0Unavailable { details: String },
}

/// Evidence level determiner
pub struct EvidenceLevelDeterminer<L>
where
    L: L0CommitClient,
{
    l0_client: L,
}

impl<L> EvidenceLevelDeterminer<L>
where
    L: L0CommitClient,
{
    /// Create a new evidence level determiner
    pub fn new(l0_client: L) -> Self {
        Self { l0_client }
    }

    /// Determine evidence level for a payload map commit and its payloads
    ///
    /// This is the main entry point for evidence level determination.
    ///
    /// # Hard Invariants Checked
    ///
    /// 1. payload_map_commit must exist - REQUIRED
    /// 2. receipt must exist - REQUIRED for A-level
    /// 3. receipt must verify - REQUIRED for A-level
    /// 4. payload digest must match - REQUIRED for A-level
    /// 5. all payloads must be accessible - REQUIRED for A-level
    pub async fn determine(
        &self,
        map_commit: Option<&PayloadMapCommit>,
        receipt_id: Option<&ReceiptId>,
        p2_payloads: &[SealedPayloadRef],
    ) -> BridgeResult<EvidenceLevelResult> {
        let mut result = EvidenceLevelResult::a_level();

        // Check 1: payload_map_commit existence (HARD INVARIANT)
        let map_commit = match map_commit {
            Some(commit) => {
                result = result.with_check(EvidenceCheck::pass("map_commit_exists"));
                commit
            }
            None => {
                // HARD INVARIANT VIOLATION: Missing map_commit MUST result in B-level
                return Ok(EvidenceLevelResult::b_level(vec![DowngradeReason::MissingMapCommit]));
            }
        };

        // Check 2: Receipt existence
        let receipt_id = match receipt_id {
            Some(id) => {
                result = result.with_check(EvidenceCheck::pass("receipt_exists"));
                id
            }
            None => {
                result = result.with_check(EvidenceCheck::fail(
                    "receipt_exists",
                    "No receipt ID provided",
                ));
                return Ok(result);
            }
        };

        // Check 3: Receipt verification
        match self.l0_client.verify_receipt(receipt_id).await {
            Ok(verify_result) => {
                if verify_result.valid {
                    result = result.with_check(EvidenceCheck::pass("receipt_verified"));
                } else {
                    result = result.with_check(EvidenceCheck::fail(
                        "receipt_verified",
                        &format!("Receipt verification failed: {:?}", verify_result.errors),
                    ));
                }
            }
            Err(e) => {
                result = result.with_check(EvidenceCheck::fail(
                    "receipt_verified",
                    &format!("L0 unavailable: {}", e),
                ));
            }
        }

        // Check 4: Payload digest reconciliation
        let verify_result = map_commit.verify_against_p2(p2_payloads);
        match &verify_result {
            VerifyResult::Valid => {
                result = result.with_check(EvidenceCheck::pass("payload_digest_match"));
                result = result.with_check(EvidenceCheck::pass("payload_count_match"));
                result = result.with_check(EvidenceCheck::pass("all_payloads_accessible"));
            }
            VerifyResult::DigestMismatch { expected, actual } => {
                result = result.with_check(EvidenceCheck::fail(
                    "payload_digest_match",
                    &format!("Expected: {}, Actual: {}", expected.to_hex(), actual.to_hex()),
                ));
            }
            VerifyResult::CountMismatch { expected, actual } => {
                result = result.with_check(EvidenceCheck::fail(
                    "payload_count_match",
                    &format!("Expected: {}, Actual: {}", expected, actual),
                ));
            }
            VerifyResult::PayloadsMissing { missing_refs } => {
                result = result.with_check(EvidenceCheck::fail(
                    "all_payloads_accessible",
                    &format!("Missing: {:?}", missing_refs),
                ));
            }
        }

        Ok(result)
    }

    /// Quick check if evidence would be A-level
    ///
    /// Returns true only if all conditions for A-level are met.
    pub async fn is_a_level(
        &self,
        map_commit: Option<&PayloadMapCommit>,
        receipt_id: Option<&ReceiptId>,
        p2_payloads: &[SealedPayloadRef],
    ) -> bool {
        match self.determine(map_commit, receipt_id, p2_payloads).await {
            Ok(result) => result.level == EvidenceLevel::A,
            Err(_) => false,
        }
    }

    /// Attempt to upgrade B-level evidence to A-level (ISSUE-005)
    ///
    /// This method checks if previously B-level evidence can now be upgraded to A-level.
    /// This is used when missing data (receipt, map_commit, etc.) has been backfilled.
    ///
    /// # Upgrade Conditions
    ///
    /// B-level evidence can be upgraded to A-level when:
    /// 1. The missing map_commit has been backfilled
    /// 2. A receipt has been obtained
    /// 3. The receipt verifies successfully
    /// 4. All payload digests match
    /// 5. All payloads are accessible
    ///
    /// # Returns
    ///
    /// Returns an `UpgradeResult` indicating whether upgrade was successful
    /// and the new evidence level.
    pub async fn attempt_upgrade(
        &self,
        previous_result: &EvidenceLevelResult,
        map_commit: Option<&PayloadMapCommit>,
        receipt_id: Option<&ReceiptId>,
        p2_payloads: &[SealedPayloadRef],
    ) -> BridgeResult<UpgradeResult> {
        // Can only upgrade B-level evidence
        if previous_result.level != EvidenceLevel::B {
            return Ok(UpgradeResult {
                upgraded: false,
                previous_level: previous_result.level,
                new_level: previous_result.level,
                new_result: None,
                upgrade_reasons: vec![],
                remaining_issues: vec![],
            });
        }

        // Re-determine the evidence level with current data
        let new_result = self.determine(map_commit, receipt_id, p2_payloads).await?;

        let upgraded = new_result.level == EvidenceLevel::A;
        let upgrade_reasons = if upgraded {
            // Find what was fixed
            previous_result.downgrade_reasons.iter()
                .filter(|reason| {
                    // Check if this reason is no longer present
                    !new_result.downgrade_reasons.contains(reason)
                })
                .cloned()
                .map(|reason| format!("Fixed: {:?}", reason))
                .collect()
        } else {
            vec![]
        };

        let remaining_issues: Vec<String> = new_result.downgrade_reasons.iter()
            .map(|r| format!("{:?}", r))
            .collect();

        Ok(UpgradeResult {
            upgraded,
            previous_level: EvidenceLevel::B,
            new_level: new_result.level,
            new_result: Some(new_result),
            upgrade_reasons,
            remaining_issues,
        })
    }

    /// Check what's needed to upgrade B-level evidence to A-level
    ///
    /// Returns a list of actions that need to be taken.
    pub fn get_upgrade_requirements(
        result: &EvidenceLevelResult,
    ) -> Vec<UpgradeRequirement> {
        if result.level == EvidenceLevel::A {
            return vec![];
        }

        result.downgrade_reasons.iter().map(|reason| {
            match reason {
                DowngradeReason::MissingMapCommit => UpgradeRequirement {
                    action: "backfill_map_commit".to_string(),
                    description: "Submit a backfill map_commit to L0".to_string(),
                    priority: UpgradePriority::Critical,
                },
                DowngradeReason::MissingReceipt => UpgradeRequirement {
                    action: "obtain_receipt".to_string(),
                    description: "Obtain an L0 receipt for the map_commit".to_string(),
                    priority: UpgradePriority::High,
                },
                DowngradeReason::ReceiptVerificationFailed { details } => UpgradeRequirement {
                    action: "verify_receipt".to_string(),
                    description: format!("Resolve receipt verification issue: {}", details),
                    priority: UpgradePriority::High,
                },
                DowngradeReason::DigestMismatch { expected, actual } => UpgradeRequirement {
                    action: "fix_digest_mismatch".to_string(),
                    description: format!(
                        "Resolve digest mismatch (expected: {}, actual: {})",
                        expected, actual
                    ),
                    priority: UpgradePriority::Critical,
                },
                DowngradeReason::PayloadsMissing { refs } => UpgradeRequirement {
                    action: "restore_payloads".to_string(),
                    description: format!("Restore missing payloads: {:?}", refs),
                    priority: UpgradePriority::High,
                },
                DowngradeReason::CountMismatch { expected, actual } => UpgradeRequirement {
                    action: "fix_count_mismatch".to_string(),
                    description: format!(
                        "Resolve payload count mismatch (expected: {}, actual: {})",
                        expected, actual
                    ),
                    priority: UpgradePriority::Medium,
                },
                DowngradeReason::CheckFailed { check_name, details } => UpgradeRequirement {
                    action: format!("fix_{}", check_name),
                    description: format!(
                        "Fix failed check '{}': {}",
                        check_name,
                        details.as_deref().unwrap_or("no details")
                    ),
                    priority: UpgradePriority::Medium,
                },
                DowngradeReason::L0Unavailable { details } => UpgradeRequirement {
                    action: "retry_when_l0_available".to_string(),
                    description: format!("Retry when L0 is available: {}", details),
                    priority: UpgradePriority::Low,
                },
            }
        }).collect()
    }
}

/// Result of an evidence level upgrade attempt (ISSUE-005)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeResult {
    /// Whether upgrade was successful
    pub upgraded: bool,
    /// Previous evidence level
    pub previous_level: EvidenceLevel,
    /// New evidence level
    pub new_level: EvidenceLevel,
    /// New determination result (if re-evaluated)
    pub new_result: Option<EvidenceLevelResult>,
    /// Reasons for successful upgrade
    pub upgrade_reasons: Vec<String>,
    /// Remaining issues preventing A-level
    pub remaining_issues: Vec<String>,
}

/// Requirement for upgrading evidence level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeRequirement {
    /// Action identifier
    pub action: String,
    /// Human-readable description
    pub description: String,
    /// Priority of this requirement
    pub priority: UpgradePriority,
}

/// Priority for upgrade requirements
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradePriority {
    /// Critical - must be fixed for any upgrade
    Critical,
    /// High priority
    High,
    /// Medium priority
    Medium,
    /// Low priority - can be addressed later
    Low,
}

/// Reconciliation checker for P1-P2 consistency
pub struct ReconciliationChecker<L>
where
    L: L0CommitClient,
{
    l0_client: L,
}

/// Reconciliation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationResult {
    /// Is reconciled
    pub reconciled: bool,
    /// Reconciliation status
    pub status: ReconciliationStatus,
    /// P1 commit digest
    pub p1_digest: Option<String>,
    /// P2 computed digest
    pub p2_digest: Option<String>,
    /// Discrepancies found
    pub discrepancies: Vec<ReconciliationDiscrepancy>,
    /// Checked at
    pub checked_at: DateTime<Utc>,
}

/// Reconciliation status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationStatus {
    /// Fully reconciled
    Reconciled,
    /// P1 commit missing
    P1Missing,
    /// P2 payloads missing
    P2Missing,
    /// Digest mismatch
    DigestMismatch,
    /// Count mismatch
    CountMismatch,
    /// Partial reconciliation (some payloads match)
    PartiallyReconciled,
}

/// Reconciliation discrepancy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationDiscrepancy {
    /// Discrepancy type
    pub discrepancy_type: DiscrepancyType,
    /// Affected ref_id
    pub ref_id: Option<String>,
    /// Expected value
    pub expected: Option<String>,
    /// Actual value
    pub actual: Option<String>,
    /// Details
    pub details: String,
}

/// Discrepancy type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscrepancyType {
    /// Payload missing in P2
    PayloadMissing,
    /// Extra payload in P2 (not in commit)
    ExtraPayload,
    /// Checksum mismatch
    ChecksumMismatch,
    /// Status mismatch (e.g., tombstoned)
    StatusMismatch,
}

impl<L> ReconciliationChecker<L>
where
    L: L0CommitClient,
{
    /// Create a new reconciliation checker
    pub fn new(l0_client: L) -> Self {
        Self { l0_client }
    }

    /// Check reconciliation between P1 commit and P2 payloads
    pub fn check(
        &self,
        map_commit: &PayloadMapCommit,
        p2_payloads: &[SealedPayloadRef],
    ) -> ReconciliationResult {
        let verify_result = map_commit.verify_against_p2(p2_payloads);
        let p1_digest = map_commit.refs_set_digest.to_hex();
        let p2_digest = PayloadMapCommit::compute_refs_digest(p2_payloads).to_hex();

        match verify_result {
            VerifyResult::Valid => ReconciliationResult {
                reconciled: true,
                status: ReconciliationStatus::Reconciled,
                p1_digest: Some(p1_digest),
                p2_digest: Some(p2_digest),
                discrepancies: vec![],
                checked_at: Utc::now(),
            },
            VerifyResult::DigestMismatch { expected, actual } => {
                let discrepancy = ReconciliationDiscrepancy {
                    discrepancy_type: DiscrepancyType::ChecksumMismatch,
                    ref_id: None,
                    expected: Some(expected.to_hex()),
                    actual: Some(actual.to_hex()),
                    details: "Merkle root mismatch".to_string(),
                };
                ReconciliationResult {
                    reconciled: false,
                    status: ReconciliationStatus::DigestMismatch,
                    p1_digest: Some(p1_digest),
                    p2_digest: Some(p2_digest),
                    discrepancies: vec![discrepancy],
                    checked_at: Utc::now(),
                }
            }
            VerifyResult::CountMismatch { expected, actual } => {
                let discrepancy = ReconciliationDiscrepancy {
                    discrepancy_type: DiscrepancyType::PayloadMissing,
                    ref_id: None,
                    expected: Some(expected.to_string()),
                    actual: Some(actual.to_string()),
                    details: format!("Expected {} payloads, found {}", expected, actual),
                };
                ReconciliationResult {
                    reconciled: false,
                    status: ReconciliationStatus::CountMismatch,
                    p1_digest: Some(p1_digest),
                    p2_digest: Some(p2_digest),
                    discrepancies: vec![discrepancy],
                    checked_at: Utc::now(),
                }
            }
            VerifyResult::PayloadsMissing { missing_refs } => {
                let discrepancies: Vec<_> = missing_refs
                    .iter()
                    .map(|ref_id| ReconciliationDiscrepancy {
                        discrepancy_type: DiscrepancyType::PayloadMissing,
                        ref_id: Some(ref_id.clone()),
                        expected: Some("accessible".to_string()),
                        actual: Some("inaccessible".to_string()),
                        details: format!("Payload {} is not accessible", ref_id),
                    })
                    .collect();
                ReconciliationResult {
                    reconciled: false,
                    status: ReconciliationStatus::P2Missing,
                    p1_digest: Some(p1_digest),
                    p2_digest: Some(p2_digest),
                    discrepancies,
                    checked_at: Utc::now(),
                }
            }
        }
    }

    /// Find payloads in P2 that are not in P1 commit
    pub fn find_extra_payloads(
        &self,
        map_commit: &PayloadMapCommit,
        p2_payloads: &[SealedPayloadRef],
        committed_ref_ids: &[String],
    ) -> Vec<String> {
        p2_payloads
            .iter()
            .filter(|p| !committed_ref_ids.contains(&p.ref_id))
            .map(|p| p.ref_id.clone())
            .collect()
    }
}

/// Convenience function to check if evidence is A-level
///
/// # Hard Rule Check
///
/// This function enforces the hard invariant:
/// **Missing payload_map_commit MUST result in B-level evidence.**
pub fn check_evidence_level(
    has_map_commit: bool,
    has_receipt: bool,
    receipt_verified: bool,
    digest_matches: bool,
) -> EvidenceLevel {
    // Hard invariant: missing map_commit = B-level
    if !has_map_commit {
        return EvidenceLevel::B;
    }

    // All conditions must be met for A-level
    if has_receipt && receipt_verified && digest_matches {
        EvidenceLevel::A
    } else {
        EvidenceLevel::B
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l0_client::MockL0Client;
    use crate::payload_map_commit::CommitType;

    fn create_test_refs(count: usize) -> Vec<SealedPayloadRef> {
        (0..count)
            .map(|i| {
                let checksum = Digest::blake3(format!("payload_{}", i).as_bytes());
                SealedPayloadRef::new(
                    format!("ref:{}", i),
                    checksum,
                    Digest::zero(),
                    100 + i as u64,
                )
            })
            .collect()
    }

    #[test]
    fn test_check_evidence_level_a() {
        assert_eq!(
            check_evidence_level(true, true, true, true),
            EvidenceLevel::A
        );
    }

    #[test]
    fn test_check_evidence_level_b_missing_map_commit() {
        // Hard invariant: missing map_commit = B-level
        assert_eq!(
            check_evidence_level(false, true, true, true),
            EvidenceLevel::B
        );
    }

    #[test]
    fn test_check_evidence_level_b_missing_receipt() {
        assert_eq!(
            check_evidence_level(true, false, true, true),
            EvidenceLevel::B
        );
    }

    #[test]
    fn test_check_evidence_level_b_unverified_receipt() {
        assert_eq!(
            check_evidence_level(true, true, false, true),
            EvidenceLevel::B
        );
    }

    #[test]
    fn test_check_evidence_level_b_digest_mismatch() {
        assert_eq!(
            check_evidence_level(true, true, true, false),
            EvidenceLevel::B
        );
    }

    #[tokio::test]
    async fn test_evidence_level_determiner_missing_map_commit() {
        let l0_client = MockL0Client::new();
        let determiner = EvidenceLevelDeterminer::new(l0_client);

        let refs = create_test_refs(3);
        let result = determiner.determine(None, None, &refs).await.unwrap();

        assert_eq!(result.level, EvidenceLevel::B);
        assert!(matches!(
            result.downgrade_reasons.first(),
            Some(DowngradeReason::MissingMapCommit)
        ));
    }

    #[tokio::test]
    async fn test_evidence_level_determiner_full_a_level() {
        let l0_client = MockL0Client::new();
        let refs = create_test_refs(3);

        // Create commit
        let commit = PayloadMapCommit::from_refs(&refs, "test", CommitType::Batch);

        // Submit to get receipt
        let receipt_id = l0_client.submit_commit(&commit).await.unwrap();

        let determiner = EvidenceLevelDeterminer::new(l0_client);
        let result = determiner
            .determine(Some(&commit), Some(&receipt_id), &refs)
            .await
            .unwrap();

        assert_eq!(result.level, EvidenceLevel::A);
        assert!(result.downgrade_reasons.is_empty());
    }

    #[test]
    fn test_reconciliation_checker_reconciled() {
        let l0_client = MockL0Client::new();
        let checker = ReconciliationChecker::new(l0_client);

        let refs = create_test_refs(3);
        let commit = PayloadMapCommit::from_refs(&refs, "test", CommitType::Batch);

        let result = checker.check(&commit, &refs);
        assert!(result.reconciled);
        assert_eq!(result.status, ReconciliationStatus::Reconciled);
        assert!(result.discrepancies.is_empty());
    }

    #[test]
    fn test_reconciliation_checker_digest_mismatch() {
        let l0_client = MockL0Client::new();
        let checker = ReconciliationChecker::new(l0_client);

        let refs = create_test_refs(3);
        let commit = PayloadMapCommit::from_refs(&refs, "test", CommitType::Batch);

        // Different refs
        let different_refs = create_test_refs(3);
        // Modify to make different
        let mut different_refs = different_refs;
        different_refs[0] = SealedPayloadRef::new(
            "ref:999".to_string(),
            Digest::blake3(b"different"),
            Digest::zero(),
            100,
        );

        let result = checker.check(&commit, &different_refs);
        assert!(!result.reconciled);
        assert_eq!(result.status, ReconciliationStatus::DigestMismatch);
    }

    #[test]
    fn test_reconciliation_checker_count_mismatch() {
        let l0_client = MockL0Client::new();
        let checker = ReconciliationChecker::new(l0_client);

        let refs = create_test_refs(5);
        let commit = PayloadMapCommit::from_refs(&refs, "test", CommitType::Batch);

        // Fewer refs
        let fewer_refs = create_test_refs(3);

        let result = checker.check(&commit, &fewer_refs);
        assert!(!result.reconciled);
        assert_eq!(result.status, ReconciliationStatus::CountMismatch);
    }
}
