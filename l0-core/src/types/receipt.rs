//! Receipt types for L0

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use super::common::Digest;
use super::actor::ReceiptId;

/// Domain batch type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeType {
    AknBatch,
    ConsentBatch,
    VerdictBatch,
    DisputeBatch,
    RepairBatch,
    ClawbackBatch,
    LogBatch,
    TraceBatch,
    BackfillBatch,
    IdentityBatch,
    CovenantStatusBatch,
}

/// Root type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootKind {
    BatchRoot,
    EpochRoot,
}

/// L0 Receipt - the core accountability object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L0Receipt {
    pub receipt_id: ReceiptId,
    pub scope_type: ScopeType,
    pub root_kind: RootKind,
    pub root: Digest,
    pub time_window_start: DateTime<Utc>,
    pub time_window_end: DateTime<Utc>,
    pub batch_sequence_no: Option<u64>,
    pub signer_set_version: String,
    pub canonicalization_version: String,
    pub anchor_policy_version: String,
    pub fee_schedule_version: String,
    pub fee_receipt_id: String,
    pub signed_snapshot_ref: String,
    pub created_at: DateTime<Utc>,
    pub rejected: Option<bool>,
    pub reject_reason_code: Option<String>,
    pub observer_reports_digest: Option<Digest>,
}

/// Fee units type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeUnits {
    BatchRoot,
    EntryCount,
    SizeTier,
}

impl Default for FeeUnits {
    fn default() -> Self {
        Self::BatchRoot
    }
}

/// Fee receipt status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeReceiptStatus {
    ChargedPendingReceipt,
    Charged,
    Refunded,
    Forfeited,
    ChargedNoReceipt,
}

/// Fee receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeReceipt {
    pub fee_receipt_id: String,
    pub fee_schedule_version: String,
    pub payer_actor_id: String,
    pub anchor_type: String,
    pub units: FeeUnits,
    pub units_count: u32,
    pub risk_multiplier: Option<String>,
    pub amount: String,
    pub timestamp: DateTime<Utc>,
    pub linked_anchor_id: String,
    pub linked_receipt_id: Option<String>,
    pub deposit_amount: Option<String>,
    pub discount_digest: Option<Digest>,
    pub subsidy_digest: Option<Digest>,
    pub status: FeeReceiptStatus,
}

/// Receipt verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptVerifyResult {
    pub valid: bool,
    pub evidence_level: super::common::EvidenceLevel,
    pub chain_anchored: bool,
    pub errors: Vec<String>,
}

impl ReceiptVerifyResult {
    pub fn verified_a() -> Self {
        Self {
            valid: true,
            evidence_level: super::common::EvidenceLevel::A,
            chain_anchored: false,
            errors: vec![],
        }
    }

    pub fn verified_a_with_chain() -> Self {
        Self {
            valid: true,
            evidence_level: super::common::EvidenceLevel::A,
            chain_anchored: true,
            errors: vec![],
        }
    }

    pub fn local_only() -> Self {
        Self {
            valid: true,
            evidence_level: super::common::EvidenceLevel::B,
            chain_anchored: false,
            errors: vec![],
        }
    }

    pub fn failed(errors: Vec<String>) -> Self {
        Self {
            valid: false,
            evidence_level: super::common::EvidenceLevel::B,
            chain_anchored: false,
            errors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_type_serialization() {
        let scope = ScopeType::VerdictBatch;
        let json = serde_json::to_string(&scope).unwrap();
        assert_eq!(json, "\"verdict_batch\"");
    }

    #[test]
    fn test_root_kind_serialization() {
        let kind = RootKind::BatchRoot;
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, "\"batch_root\"");
    }
}
