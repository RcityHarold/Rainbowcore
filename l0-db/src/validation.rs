//! L0 Protocol Validation Rules
//!
//! This module implements the validation rules specified in the L0 development
//! documentation (Appendix C). These rules are critical for protocol integrity.
//!
//! # Rules Implemented
//!
//! 1. **Space禁止规则**: Space不得出现在parties/approvers/payer/targets字段
//! 2. **字段名禁止规则**: clause_akn_id禁止作为字段名，统一使用clause_id
//! 3. **TipWitness免费规则**: TipWitness不得收费（永久免费）
//! 4. **扣费与回执绑定规则**: 扣费失败不得出A级回执

use crate::error::{L0DbError, L0DbResult};

/// Validation error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationRule {
    /// Space cannot appear in parties/approvers/payer/targets fields
    SpaceInParties,
    /// clause_akn_id is prohibited as field name
    ProhibitedFieldName,
    /// TipWitness must be free
    TipWitnessFee,
    /// Fee failure cannot produce A-level receipt
    FeeFailureReceipt,
}

impl std::fmt::Display for ValidationRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SpaceInParties => write!(
                f,
                "Space cannot appear in parties/approvers/payer/targets fields"
            ),
            Self::ProhibitedFieldName => {
                write!(f, "clause_akn_id is prohibited; use clause_id instead")
            }
            Self::TipWitnessFee => write!(f, "TipWitness must be free (no fees allowed)"),
            Self::FeeFailureReceipt => {
                write!(f, "Fee failure cannot produce A-level receipt")
            }
        }
    }
}

/// Validates that an actor ID is not a Space ID.
///
/// # Rule
/// Space不得出现在parties/approvers/payer/targets字段
/// Space只能作为context_ref，不能作为参与者。
///
/// # Arguments
/// * `actor_id` - The actor ID to validate
/// * `field_name` - The field name for error messages
///
/// # Returns
/// Ok(()) if valid, Err with validation error if the ID appears to be a Space
pub fn validate_not_space(actor_id: &str, field_name: &str) -> L0DbResult<()> {
    // Space IDs typically have a specific pattern
    // Common patterns: starts with "space_", "space:", or contains "space_id"
    let lower = actor_id.to_lowercase();
    if lower.starts_with("space_")
        || lower.starts_with("space:")
        || lower.contains("space_id")
        || actor_id.contains("SpaceId")
    {
        return Err(L0DbError::Validation(format!(
            "{}: Space cannot appear in {} field. Space is only allowed as context_ref. \
             Received: '{}'",
            ValidationRule::SpaceInParties,
            field_name,
            actor_id
        )));
    }
    Ok(())
}

/// Validates that none of the party actor IDs are Spaces.
///
/// # Arguments
/// * `parties` - List of party actor IDs to validate
/// * `field_name` - The field name for error messages (e.g., "parties", "approvers")
pub fn validate_parties_not_space(parties: &[String], field_name: &str) -> L0DbResult<()> {
    for party in parties {
        validate_not_space(party, field_name)?;
    }
    Ok(())
}

/// Validates fee status before creating a receipt.
///
/// # Rule
/// 扣费失败不得出A级回执
/// Fee must be successfully charged before issuing an A-level receipt.
///
/// # Arguments
/// * `fee_status` - The fee status (e.g., "charged", "failed", "pending")
/// * `receipt_level` - The receipt level (A, B, etc.)
///
/// # Returns
/// Ok(()) if valid, Err if attempting to create A-level receipt without successful fee
pub fn validate_fee_for_receipt(fee_status: &str, receipt_level: &str) -> L0DbResult<()> {
    // A-level receipts require successful fee charging
    if receipt_level.to_uppercase() == "A" {
        match fee_status {
            "charged" | "charged_pending_receipt" => Ok(()),
            "failed" | "refunded" | "pending" => Err(L0DbError::Validation(format!(
                "{}: Cannot issue A-level receipt with fee status '{}'. \
                 Fee must be successfully charged first.",
                ValidationRule::FeeFailureReceipt,
                fee_status
            ))),
            other => Err(L0DbError::Validation(format!(
                "{}: Unknown fee status '{}' for A-level receipt creation.",
                ValidationRule::FeeFailureReceipt,
                other
            ))),
        }
    } else {
        Ok(())
    }
}

/// Validates that TipWitness operations are not charged fees.
///
/// # Rule
/// TipWitness不得收费（永久免费）
/// TipWitness is a mandatory free service for nodes.
///
/// # Arguments
/// * `operation_type` - The type of operation
/// * `fee_amount` - The fee amount being charged
pub fn validate_tipwitness_free(operation_type: &str, fee_amount: u64) -> L0DbResult<()> {
    let lower = operation_type.to_lowercase();
    if (lower.contains("tipwitness") || lower.contains("tip_witness")) && fee_amount > 0 {
        return Err(L0DbError::Validation(format!(
            "{}: TipWitness operations must be free. Attempted fee: {}",
            ValidationRule::TipWitnessFee,
            fee_amount
        )));
    }
    Ok(())
}

/// Validates that field names don't use prohibited names.
///
/// # Rule
/// clause_akn_id禁止作为字段名，统一使用clause_id
///
/// # Arguments
/// * `field_name` - The field name to validate
pub fn validate_field_name(field_name: &str) -> L0DbResult<()> {
    if field_name == "clause_akn_id" {
        return Err(L0DbError::Validation(format!(
            "{}: Use 'clause_id' instead of 'clause_akn_id'",
            ValidationRule::ProhibitedFieldName
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_not_space() {
        // Valid actor IDs
        assert!(validate_not_space("actor_123", "parties").is_ok());
        assert!(validate_not_space("user_abc", "approvers").is_ok());
        assert!(validate_not_space("node_xyz", "payer").is_ok());

        // Invalid - Space IDs
        assert!(validate_not_space("space_123", "parties").is_err());
        assert!(validate_not_space("space:abc", "approvers").is_err());
        assert!(validate_not_space("my_space_id_123", "payer").is_err());
    }

    #[test]
    fn test_validate_parties_not_space() {
        // Valid parties
        let valid_parties = vec!["actor_1".to_string(), "actor_2".to_string()];
        assert!(validate_parties_not_space(&valid_parties, "parties").is_ok());

        // Invalid - contains Space
        let invalid_parties = vec!["actor_1".to_string(), "space_123".to_string()];
        assert!(validate_parties_not_space(&invalid_parties, "parties").is_err());
    }

    #[test]
    fn test_validate_fee_for_receipt() {
        // Valid combinations
        assert!(validate_fee_for_receipt("charged", "A").is_ok());
        assert!(validate_fee_for_receipt("charged_pending_receipt", "A").is_ok());
        assert!(validate_fee_for_receipt("failed", "B").is_ok());
        assert!(validate_fee_for_receipt("pending", "C").is_ok());

        // Invalid - A-level receipt without successful fee
        assert!(validate_fee_for_receipt("failed", "A").is_err());
        assert!(validate_fee_for_receipt("pending", "A").is_err());
        assert!(validate_fee_for_receipt("refunded", "A").is_err());
    }

    #[test]
    fn test_validate_tipwitness_free() {
        // Valid - TipWitness with zero fee
        assert!(validate_tipwitness_free("tipwitness_submit", 0).is_ok());
        assert!(validate_tipwitness_free("tip_witness_verify", 0).is_ok());

        // Valid - non-TipWitness can have fees
        assert!(validate_tipwitness_free("commitment_submit", 100).is_ok());

        // Invalid - TipWitness with non-zero fee
        assert!(validate_tipwitness_free("tipwitness_submit", 100).is_err());
        assert!(validate_tipwitness_free("tip_witness_verify", 50).is_err());
    }

    #[test]
    fn test_validate_field_name() {
        // Valid field names
        assert!(validate_field_name("clause_id").is_ok());
        assert!(validate_field_name("actor_id").is_ok());

        // Invalid - prohibited field name
        assert!(validate_field_name("clause_akn_id").is_err());
    }
}
