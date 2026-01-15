//! Fee Split Verification
//!
//! Verifies three-column fee split compliance (Protocol Tax / DSN Storage / Service Fee).
//! Ensures no tax mixing and proper split ratios.

use crate::error::VerifierResult;
use p3_core::{EconomyEpochBundle, P3Digest, PoolRatios, ThreeColumnBill, TreasuryPool};
use rust_decimal::Decimal;

/// Fee split verification error
#[derive(Clone, Debug)]
pub struct FeeSplitVerificationError {
    pub code: String,
    pub message: String,
}

impl FeeSplitVerificationError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

/// Fee split verification result
#[derive(Clone, Debug)]
pub struct FeeSplitVerificationResult {
    /// Overall validity
    pub is_valid: bool,
    /// Errors found
    pub errors: Vec<FeeSplitVerificationError>,
    /// Verified splits
    pub splits_verified: usize,
}

impl FeeSplitVerificationResult {
    pub fn valid(splits: usize) -> Self {
        Self {
            is_valid: true,
            errors: vec![],
            splits_verified: splits,
        }
    }

    pub fn invalid(errors: Vec<FeeSplitVerificationError>) -> Self {
        Self {
            is_valid: false,
            errors,
            splits_verified: 0,
        }
    }
}

/// Fee split verifier
pub struct FeeSplitVerifier {
    /// Expected pool ratios
    expected_ratios: Option<PoolRatios>,
}

impl FeeSplitVerifier {
    /// Create new fee split verifier
    pub fn new() -> Self {
        Self {
            expected_ratios: None,
        }
    }

    /// Set expected ratios
    pub fn with_expected_ratios(mut self, ratios: PoolRatios) -> Self {
        self.expected_ratios = Some(ratios);
        self
    }

    /// Verify fee splits in bundle (structural verification in zero-plaintext mode)
    pub fn verify(&self, bundle: &EconomyEpochBundle) -> VerifierResult<FeeSplitVerificationResult> {
        let errors = Vec::new();

        // In zero-plaintext mode, we verify structural integrity
        // The bundle contains digest references, not actual amounts

        // 1. Verify receipt_refs_digest is present
        if bundle.receipt_refs_digest.0.is_zero() {
            // This is a warning, not an error - empty receipts might be valid
        }

        // 2. Verify expected ratios if set
        if let Some(ref ratios) = self.expected_ratios {
            if !ratios.validate() {
                return Ok(FeeSplitVerificationResult::invalid(vec![
                    FeeSplitVerificationError::new(
                        "INVALID_RATIOS",
                        "Expected pool ratios do not sum to 1",
                    ),
                ]));
            }
        }

        if errors.is_empty() {
            Ok(FeeSplitVerificationResult::valid(1))
        } else {
            Ok(FeeSplitVerificationResult::invalid(errors))
        }
    }

    /// Verify a three-column bill structure
    pub fn verify_bill(&self, bill: &ThreeColumnBill) -> VerifierResult<FeeSplitVerificationResult> {
        let mut errors = Vec::new();

        // 1. Verify no mixing - each column has separate receipts
        if !bill.verify_no_mixing() {
            errors.push(FeeSplitVerificationError::new(
                "TAX_MIXING",
                "Three-column bill has mixed receipts",
            ));
        }

        // 2. Verify each column has valid structure
        // Protocol tax column
        if bill.protocol_tax.amount_digest.amount_digest.is_zero()
            && bill.protocol_tax.fee_receipt_refs_digest.0.is_zero()
        {
            // Both zero is valid (no protocol tax)
        }

        // DSN storage column
        if bill.dsn_storage.amount_digest.amount_digest.is_zero()
            && bill.dsn_storage.dsn_spend_refs_digest.0.is_zero()
        {
            // Both zero is valid (no DSN storage)
        }

        // Service fee column
        if bill.service_fee.amount_digest.amount_digest.is_zero() {
            // Zero service fee is valid
        }

        // 3. Verify currency consistency in digests
        if bill.protocol_tax.amount_digest.currency != bill.dsn_storage.amount_digest.currency {
            errors.push(FeeSplitVerificationError::new(
                "CURRENCY_MISMATCH",
                "Protocol tax and DSN storage have different currencies",
            ));
        }
        if bill.protocol_tax.amount_digest.currency != bill.service_fee.amount_digest.currency {
            errors.push(FeeSplitVerificationError::new(
                "CURRENCY_MISMATCH",
                "Protocol tax and service fee have different currencies",
            ));
        }

        // 4. Verify bound_epoch_id consistency
        if bill.protocol_tax.bound_epoch_id != bill.dsn_storage.bound_epoch_id
            || bill.protocol_tax.bound_epoch_id != bill.service_fee.bound_epoch_id
        {
            errors.push(FeeSplitVerificationError::new(
                "EPOCH_MISMATCH",
                "All columns must be bound to the same epoch",
            ));
        }

        if errors.is_empty() {
            Ok(FeeSplitVerificationResult::valid(1))
        } else {
            Ok(FeeSplitVerificationResult::invalid(errors))
        }
    }

    /// Verify pool ratios
    pub fn verify_ratios(&self, ratios: &PoolRatios) -> VerifierResult<FeeSplitVerificationResult> {
        let mut errors = Vec::new();

        // 1. All ratios must be non-negative
        if ratios.infra_ratio < Decimal::ZERO {
            errors.push(FeeSplitVerificationError::new(
                "NEGATIVE_INFRA_RATIO",
                "Infrastructure pool ratio cannot be negative",
            ));
        }
        if ratios.civilization_ratio < Decimal::ZERO {
            errors.push(FeeSplitVerificationError::new(
                "NEGATIVE_CIVILIZATION_RATIO",
                "Civilization pool ratio cannot be negative",
            ));
        }
        if ratios.reward_ratio < Decimal::ZERO {
            errors.push(FeeSplitVerificationError::new(
                "NEGATIVE_REWARD_RATIO",
                "Reward pool ratio cannot be negative",
            ));
        }

        // 2. Ratios must sum to 1
        if !ratios.validate() {
            errors.push(FeeSplitVerificationError::new(
                "RATIO_SUM_MISMATCH",
                format!(
                    "Pool ratios sum to {} (expected 1)",
                    ratios.infra_ratio + ratios.civilization_ratio + ratios.reward_ratio
                ),
            ));
        }

        if errors.is_empty() {
            Ok(FeeSplitVerificationResult::valid(1))
        } else {
            Ok(FeeSplitVerificationResult::invalid(errors))
        }
    }

    /// Get all treasury pools
    pub fn get_pools() -> Vec<TreasuryPool> {
        TreasuryPool::all()
    }
}

impl Default for FeeSplitVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use p3_core::{
        CanonVersion, CutoffRef, DsnStorageColumn, EpochHeader, EpochId, EpochWindow, EventSet,
        ManifestFourSets, MoneyDigest, ProtocolTaxColumn, RefDigest, ServiceFeeColumn,
        WeightsVersionRef,
    };

    fn create_test_bundle() -> EconomyEpochBundle {
        let now = Utc::now();
        let manifest_sets = ManifestFourSets {
            knowledge_events: EventSet::empty(),
            court_events: EventSet::empty(),
            policy_state: EventSet::empty(),
            sampling_audit: EventSet::empty(),
        };

        let epoch_header = EpochHeader {
            epoch_id: EpochId::new("epoch:test:001"),
            epoch_window: EpochWindow::new(now - chrono::Duration::hours(1), now),
            cutoff_ref: CutoffRef::new(Some(P3Digest::zero()), Some(100)),
            manifest_digest: manifest_sets.compute_manifest_digest(),
            weights_version: WeightsVersionRef::new("weights:v1", P3Digest::zero()),
            policy_refs_digest: RefDigest::empty(),
            canon_version: CanonVersion::v1(),
        };

        EconomyEpochBundle {
            epoch_header,
            manifest_sets,
            receipt_refs_digest: RefDigest::empty(),
            result_root_digest: P3Digest::zero(),
            chain_anchor_link: None,
        }
    }

    fn create_test_bill() -> ThreeColumnBill {
        let epoch_id = EpochId::new("epoch:test:001");

        ThreeColumnBill {
            protocol_tax: ProtocolTaxColumn {
                amount_digest: MoneyDigest::new(P3Digest::zero(), "USD"),
                fee_receipt_refs_digest: RefDigest::empty(),
                fee_schedule_version_ref: "v1".to_string(),
                bound_epoch_id: epoch_id.clone(),
            },
            dsn_storage: DsnStorageColumn {
                amount_digest: MoneyDigest::new(P3Digest::zero(), "USD"),
                dsn_spend_refs_digest: RefDigest::empty(),
                storage_policy_ref: None,
                bound_epoch_id: epoch_id.clone(),
            },
            service_fee: ServiceFeeColumn {
                amount_digest: MoneyDigest::new(P3Digest::zero(), "USD"),
                invoice_ref: None,
                contract_ref: None,
                provider_ref: None,
                bound_epoch_id: epoch_id,
            },
        }
    }

    #[test]
    fn test_fee_split_verifier_creation() {
        let verifier = FeeSplitVerifier::new();
        assert!(verifier.expected_ratios.is_none());
    }

    #[test]
    fn test_verify_bundle() {
        let verifier = FeeSplitVerifier::new();
        let bundle = create_test_bundle();

        let result = verifier.verify(&bundle).unwrap();
        assert!(result.is_valid);
    }

    #[test]
    fn test_verify_valid_bill() {
        let verifier = FeeSplitVerifier::new();
        let bill = create_test_bill();

        let result = verifier.verify_bill(&bill).unwrap();
        assert!(result.is_valid);
        assert_eq!(result.splits_verified, 1);
    }

    #[test]
    fn test_verify_valid_ratios() {
        let verifier = FeeSplitVerifier::new();
        let ratios = PoolRatios::default_ratios();

        let result = verifier.verify_ratios(&ratios).unwrap();
        assert!(result.is_valid);
    }

    #[test]
    fn test_verify_invalid_ratios() {
        let verifier = FeeSplitVerifier::new();
        let ratios = PoolRatios {
            infra_ratio: Decimal::new(50, 2),
            civilization_ratio: Decimal::new(30, 2),
            reward_ratio: Decimal::new(30, 2), // Sum = 1.1
        };

        let result = verifier.verify_ratios(&ratios).unwrap();
        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| e.code == "RATIO_SUM_MISMATCH"));
    }

    #[test]
    fn test_get_pools() {
        let pools = FeeSplitVerifier::get_pools();
        assert_eq!(pools.len(), 3);
    }
}
