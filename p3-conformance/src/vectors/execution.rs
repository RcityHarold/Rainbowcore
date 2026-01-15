//! Execution Test Vectors
//!
//! Test vectors for P3 execution flow conformance.

use super::TestVector;
use p3_core::{EpochId, OperationType};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

/// Execution test input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionInput {
    /// Operation type
    pub operation_type: String,
    /// Target identifier
    pub target: String,
    /// Amount
    pub amount: String,
    /// Epoch ID
    pub epoch_id: String,
    /// Initiator reference
    pub initiator: String,
    /// Optional executor reference
    pub executor: Option<String>,
}

/// Execution expected outcome
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionExpected {
    /// Whether execution should succeed
    pub should_succeed: bool,
    /// Expected state after execution
    pub final_state: Option<String>,
    /// Expected error type (if failure)
    pub error_type: Option<String>,
}

/// Get all execution test vectors
pub fn all_vectors() -> Vec<TestVector<ExecutionInput>> {
    let mut vectors = Vec::new();

    // Valid operation vectors
    vectors.extend(valid_operations());

    // Invalid operation vectors
    vectors.extend(invalid_operations());

    // Edge case vectors
    vectors.extend(edge_cases());

    vectors
}

/// Valid operation test vectors
pub fn valid_operations() -> Vec<TestVector<ExecutionInput>> {
    vec![
        // Distribution
        TestVector::new(
            "exec-001",
            "Valid distribution operation",
            ExecutionInput {
                operation_type: "Distribution".to_string(),
                target: "provider:test:001".to_string(),
                amount: "100.00".to_string(),
                epoch_id: "epoch:2024:001".to_string(),
                initiator: "initiator:test:001".to_string(),
                executor: Some("executor:test:001".to_string()),
            },
        )
        .with_expected(serde_json::json!({
            "should_succeed": true,
            "final_state": "Resolved"
        }))
        .with_tags(vec!["valid", "distribution"]),

        // Clawback
        TestVector::new(
            "exec-002",
            "Valid clawback operation",
            ExecutionInput {
                operation_type: "Clawback".to_string(),
                target: "provider:test:002".to_string(),
                amount: "50.00".to_string(),
                epoch_id: "epoch:2024:001".to_string(),
                initiator: "initiator:test:001".to_string(),
                executor: Some("executor:test:001".to_string()),
            },
        )
        .with_expected(serde_json::json!({
            "should_succeed": true,
            "final_state": "Resolved"
        }))
        .with_tags(vec!["valid", "clawback"]),

        // Fine
        TestVector::new(
            "exec-003",
            "Valid fine operation",
            ExecutionInput {
                operation_type: "Fine".to_string(),
                target: "provider:test:003".to_string(),
                amount: "25.00".to_string(),
                epoch_id: "epoch:2024:001".to_string(),
                initiator: "system:p3".to_string(),
                executor: Some("executor:test:001".to_string()),
            },
        )
        .with_expected(serde_json::json!({
            "should_succeed": true,
            "final_state": "Resolved"
        }))
        .with_tags(vec!["valid", "fine"]),

        // Subsidy
        TestVector::new(
            "exec-004",
            "Valid subsidy operation",
            ExecutionInput {
                operation_type: "Subsidy".to_string(),
                target: "provider:test:004".to_string(),
                amount: "200.00".to_string(),
                epoch_id: "epoch:2024:001".to_string(),
                initiator: "treasury:main".to_string(),
                executor: Some("executor:test:001".to_string()),
            },
        )
        .with_expected(serde_json::json!({
            "should_succeed": true,
            "final_state": "Resolved"
        }))
        .with_tags(vec!["valid", "subsidy"]),

        // Deposit
        TestVector::new(
            "exec-005",
            "Valid deposit operation",
            ExecutionInput {
                operation_type: "DepositOperation".to_string(),
                target: "provider:test:005".to_string(),
                amount: "1000.00".to_string(),
                epoch_id: "epoch:2024:001".to_string(),
                initiator: "initiator:test:001".to_string(),
                executor: Some("executor:test:001".to_string()),
            },
        )
        .with_expected(serde_json::json!({
            "should_succeed": true,
            "final_state": "Resolved"
        }))
        .with_tags(vec!["valid", "deposit"]),

        // Points Calculation
        TestVector::new(
            "exec-006",
            "Valid points calculation operation",
            ExecutionInput {
                operation_type: "PointsCalculation".to_string(),
                target: "provider:test:006".to_string(),
                amount: "500.00".to_string(),
                epoch_id: "epoch:2024:001".to_string(),
                initiator: "system:p3".to_string(),
                executor: Some("executor:test:001".to_string()),
            },
        )
        .with_expected(serde_json::json!({
            "should_succeed": true,
            "final_state": "Resolved"
        }))
        .with_tags(vec!["valid", "points"]),

        // Attribution
        TestVector::new(
            "exec-007",
            "Valid attribution operation",
            ExecutionInput {
                operation_type: "Attribution".to_string(),
                target: "provider:test:007".to_string(),
                amount: "75.00".to_string(),
                epoch_id: "epoch:2024:001".to_string(),
                initiator: "initiator:test:001".to_string(),
                executor: Some("executor:test:001".to_string()),
            },
        )
        .with_expected(serde_json::json!({
            "should_succeed": true,
            "final_state": "Resolved"
        }))
        .with_tags(vec!["valid", "attribution"]),

        // Budget Spend
        TestVector::new(
            "exec-008",
            "Valid budget spend operation",
            ExecutionInput {
                operation_type: "BudgetSpend".to_string(),
                target: "budget:marketing".to_string(),
                amount: "5000.00".to_string(),
                epoch_id: "epoch:2024:001".to_string(),
                initiator: "treasury:main".to_string(),
                executor: Some("executor:test:001".to_string()),
            },
        )
        .with_expected(serde_json::json!({
            "should_succeed": true,
            "final_state": "Resolved"
        }))
        .with_tags(vec!["valid", "budget"]),
    ]
}

/// Invalid operation test vectors
pub fn invalid_operations() -> Vec<TestVector<ExecutionInput>> {
    vec![
        // Negative amount
        TestVector::new(
            "exec-101",
            "Invalid operation with negative amount",
            ExecutionInput {
                operation_type: "Distribution".to_string(),
                target: "provider:test:001".to_string(),
                amount: "-100.00".to_string(),
                epoch_id: "epoch:2024:001".to_string(),
                initiator: "initiator:test:001".to_string(),
                executor: None,
            },
        )
        .should_fail()
        .with_expected(serde_json::json!({
            "should_succeed": false,
            "error_type": "InvalidAmount"
        }))
        .with_tags(vec!["invalid", "negative-amount"]),

        // Empty target
        TestVector::new(
            "exec-102",
            "Invalid operation with empty target",
            ExecutionInput {
                operation_type: "Distribution".to_string(),
                target: "".to_string(),
                amount: "100.00".to_string(),
                epoch_id: "epoch:2024:001".to_string(),
                initiator: "initiator:test:001".to_string(),
                executor: None,
            },
        )
        .should_fail()
        .with_expected(serde_json::json!({
            "should_succeed": false,
            "error_type": "InvalidTarget"
        }))
        .with_tags(vec!["invalid", "empty-target"]),

        // Empty epoch
        TestVector::new(
            "exec-103",
            "Invalid operation with empty epoch",
            ExecutionInput {
                operation_type: "Distribution".to_string(),
                target: "provider:test:001".to_string(),
                amount: "100.00".to_string(),
                epoch_id: "".to_string(),
                initiator: "initiator:test:001".to_string(),
                executor: None,
            },
        )
        .should_fail()
        .with_expected(serde_json::json!({
            "should_succeed": false,
            "error_type": "InvalidEpoch"
        }))
        .with_tags(vec!["invalid", "empty-epoch"]),

        // Unknown operation type
        TestVector::new(
            "exec-104",
            "Invalid operation with unknown type",
            ExecutionInput {
                operation_type: "UnknownOperation".to_string(),
                target: "provider:test:001".to_string(),
                amount: "100.00".to_string(),
                epoch_id: "epoch:2024:001".to_string(),
                initiator: "initiator:test:001".to_string(),
                executor: None,
            },
        )
        .should_fail()
        .with_expected(serde_json::json!({
            "should_succeed": false,
            "error_type": "InvalidOperationType"
        }))
        .with_tags(vec!["invalid", "unknown-type"]),
    ]
}

/// Edge case test vectors
pub fn edge_cases() -> Vec<TestVector<ExecutionInput>> {
    vec![
        // Zero amount
        TestVector::new(
            "exec-201",
            "Edge case: zero amount distribution",
            ExecutionInput {
                operation_type: "Distribution".to_string(),
                target: "provider:test:001".to_string(),
                amount: "0.00".to_string(),
                epoch_id: "epoch:2024:001".to_string(),
                initiator: "initiator:test:001".to_string(),
                executor: Some("executor:test:001".to_string()),
            },
        )
        .with_expected(serde_json::json!({
            "should_succeed": true,
            "final_state": "Resolved"
        }))
        .with_tags(vec!["edge-case", "zero-amount"]),

        // Very small amount
        TestVector::new(
            "exec-202",
            "Edge case: very small amount (0.01)",
            ExecutionInput {
                operation_type: "Distribution".to_string(),
                target: "provider:test:001".to_string(),
                amount: "0.01".to_string(),
                epoch_id: "epoch:2024:001".to_string(),
                initiator: "initiator:test:001".to_string(),
                executor: Some("executor:test:001".to_string()),
            },
        )
        .with_expected(serde_json::json!({
            "should_succeed": true,
            "final_state": "Resolved"
        }))
        .with_tags(vec!["edge-case", "small-amount"]),

        // Large amount
        TestVector::new(
            "exec-203",
            "Edge case: large amount (1 million)",
            ExecutionInput {
                operation_type: "Distribution".to_string(),
                target: "provider:test:001".to_string(),
                amount: "1000000.00".to_string(),
                epoch_id: "epoch:2024:001".to_string(),
                initiator: "initiator:test:001".to_string(),
                executor: Some("executor:test:001".to_string()),
            },
        )
        .with_expected(serde_json::json!({
            "should_succeed": true,
            "final_state": "Resolved"
        }))
        .with_tags(vec!["edge-case", "large-amount"]),

        // Many decimal places
        TestVector::new(
            "exec-204",
            "Edge case: many decimal places",
            ExecutionInput {
                operation_type: "Distribution".to_string(),
                target: "provider:test:001".to_string(),
                amount: "123.456789".to_string(),
                epoch_id: "epoch:2024:001".to_string(),
                initiator: "initiator:test:001".to_string(),
                executor: Some("executor:test:001".to_string()),
            },
        )
        .with_expected(serde_json::json!({
            "should_succeed": true,
            "final_state": "Resolved"
        }))
        .with_tags(vec!["edge-case", "precision"]),
    ]
}

/// Parse operation type from string
pub fn parse_operation_type(s: &str) -> Option<OperationType> {
    match s.to_lowercase().as_str() {
        "pointscalculation" | "points_calculation" | "points" => Some(OperationType::PointsCalculation),
        "attribution" => Some(OperationType::Attribution),
        "distribution" => Some(OperationType::Distribution),
        "clawback" => Some(OperationType::Clawback),
        "depositoperation" | "deposit_operation" | "deposit" => Some(OperationType::DepositOperation),
        "fine" => Some(OperationType::Fine),
        "subsidy" => Some(OperationType::Subsidy),
        "budgetspend" | "budget_spend" | "budget" => Some(OperationType::BudgetSpend),
        _ => None,
    }
}

/// Parse amount from string
pub fn parse_amount(s: &str) -> Option<Decimal> {
    s.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_vectors_count() {
        let vectors = all_vectors();
        assert!(vectors.len() >= 16, "Expected at least 16 execution vectors");
    }

    #[test]
    fn test_valid_operations_count() {
        let vectors = valid_operations();
        assert_eq!(vectors.len(), 8, "Expected 8 valid operation types");
    }

    #[test]
    fn test_invalid_operations_should_fail() {
        for vector in invalid_operations() {
            assert!(!vector.should_succeed, "Invalid vector {} should be marked as should_fail", vector.id);
        }
    }

    #[test]
    fn test_parse_operation_types() {
        assert!(parse_operation_type("Distribution").is_some());
        assert!(parse_operation_type("distribution").is_some());
        assert!(parse_operation_type("Clawback").is_some());
        assert!(parse_operation_type("Fine").is_some());
        assert!(parse_operation_type("Subsidy").is_some());
        assert!(parse_operation_type("DepositOperation").is_some());
        assert!(parse_operation_type("deposit").is_some());
        assert!(parse_operation_type("PointsCalculation").is_some());
        assert!(parse_operation_type("points").is_some());
        assert!(parse_operation_type("Attribution").is_some());
        assert!(parse_operation_type("BudgetSpend").is_some());
        assert!(parse_operation_type("budget").is_some());
        assert!(parse_operation_type("Unknown").is_none());
    }

    #[test]
    fn test_parse_amounts() {
        assert_eq!(parse_amount("100.00"), Some(Decimal::new(10000, 2)));
        assert_eq!(parse_amount("0.01"), Some(Decimal::new(1, 2)));
        assert_eq!(parse_amount("-50.00"), Some(Decimal::new(-5000, 2)));
        assert!(parse_amount("invalid").is_none());
    }

    #[test]
    fn test_vector_tags() {
        for vector in all_vectors() {
            assert!(!vector.tags.is_empty(), "Vector {} should have tags", vector.id);
        }
    }
}
