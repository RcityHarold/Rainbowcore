//! Snapshot types for L0 threshold signing

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use super::common::Digest;
use super::actor::ReceiptId;

/// Signer Set Reference - defines who can sign
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerSetRef {
    pub signer_set_id: String,
    pub version: u32,
    /// Must be exactly 9 in phase 1
    pub certified_signer_pubkeys: Vec<String>,
    pub observer_pubkeys: Vec<String>,
    /// Locked to "5/9" in phase 1
    pub threshold_rule: String,
    pub valid_from: DateTime<Utc>,
    pub supersedes: Option<String>,
    pub admission_policy_version: String,
    pub slashing_policy_version: Option<String>,
    pub receipt_id: Option<ReceiptId>,
    pub metadata_digest: Option<Digest>,
}

impl SignerSetRef {
    /// Get the full version string
    pub fn version_string(&self) -> String {
        format!("{}:{}", self.signer_set_id, self.version)
    }

    /// Validate the signer set configuration
    pub fn validate(&self) -> Result<(), String> {
        // Phase 1: exactly 9 certified signers
        if self.certified_signer_pubkeys.len() != 9 {
            return Err(format!(
                "Expected 9 certified signers, got {}",
                self.certified_signer_pubkeys.len()
            ));
        }

        // Phase 1: threshold must be 5/9
        if self.threshold_rule != "5/9" {
            return Err(format!(
                "Expected threshold rule '5/9', got '{}'",
                self.threshold_rule
            ));
        }

        Ok(())
    }
}

/// Signed batch snapshot - threshold signature proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedBatchSnapshot {
    pub snapshot_id: String,
    pub batch_root: Digest,
    pub time_window_start: DateTime<Utc>,
    pub time_window_end: DateTime<Utc>,
    pub batch_sequence_no: u64,
    pub parent_batch_root: Option<Digest>,
    /// MUST be covered by signature
    pub signer_set_version: String,
    /// MUST be covered by signature
    pub canonicalization_version: String,
    /// MUST be covered by signature
    pub anchor_policy_version: String,
    /// MUST be covered by signature
    pub fee_schedule_version: String,
    pub threshold_rule: String,
    /// Bitmap or index set digest indicating which signers signed
    pub signature_bitmap: String,
    /// Aggregated signature or multi-sig collection
    pub threshold_proof: String,
    pub observer_reports_digest: Option<Digest>,
}

impl SignedBatchSnapshot {
    /// Get the message bytes that should be signed
    pub fn signing_message(&self) -> Vec<u8> {
        // Domain tag + TLV encoded fields
        let mut message = Vec::new();
        message.extend_from_slice(b"L0:SignedBatchSnapshotMsg:v1\0");

        // Fields in canonical order
        message.extend_from_slice(self.batch_root.as_bytes());
        message.extend_from_slice(self.time_window_start.to_rfc3339().as_bytes());
        message.extend_from_slice(b"\0");
        message.extend_from_slice(self.time_window_end.to_rfc3339().as_bytes());
        message.extend_from_slice(b"\0");
        message.extend_from_slice(&self.batch_sequence_no.to_le_bytes());

        if let Some(ref parent) = self.parent_batch_root {
            message.extend_from_slice(parent.as_bytes());
        } else {
            message.push(0x00); // null marker
        }

        message.extend_from_slice(self.signer_set_version.as_bytes());
        message.extend_from_slice(b"\0");
        message.extend_from_slice(self.canonicalization_version.as_bytes());
        message.extend_from_slice(b"\0");
        message.extend_from_slice(self.anchor_policy_version.as_bytes());
        message.extend_from_slice(b"\0");
        message.extend_from_slice(self.fee_schedule_version.as_bytes());
        message.extend_from_slice(b"\0");
        message.extend_from_slice(self.threshold_rule.as_bytes());

        if let Some(ref reports) = self.observer_reports_digest {
            message.extend_from_slice(reports.as_bytes());
        } else {
            message.push(0x00);
        }

        message
    }
}

/// Epoch snapshot for chain anchoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochSnapshot {
    pub epoch_id: String,
    pub epoch_root: Digest,
    pub epoch_window_start: DateTime<Utc>,
    pub epoch_window_end: DateTime<Utc>,
    pub epoch_sequence_no: u64,
    pub parent_epoch_root: Option<Digest>,
    pub signer_set_version: String,
    pub canonicalization_version: String,
    pub chain_anchor_policy_version: String,
    pub threshold_rule: String,
    pub signature_bitmap: Option<String>,
    pub threshold_proof: Option<String>,
    pub gaps_digest: Option<Digest>,
    pub batch_receipts_digest: Digest,
}

/// Chain anchor input for P4
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainAnchorInput {
    pub epoch_root: Digest,
    pub epoch_window_start: DateTime<Utc>,
    pub epoch_window_end: DateTime<Utc>,
    pub signer_set_version: String,
    pub canonicalization_version: String,
    pub chain_anchor_policy_version: String,
    pub epoch_snapshot_ref: Option<String>,
    pub gaps_digest: Option<Digest>,
}

/// Chain anchor link - connects L0 receipts to chain txs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainAnchorLink {
    pub chain_anchor_link_id: String,
    pub chain_network: String,  // btc/atomicals
    pub chain_txid_or_asset_id: String,
    pub epoch_root: Digest,
    pub epoch_window_start: DateTime<Utc>,
    pub epoch_window_end: DateTime<Utc>,
    pub chain_anchor_policy_version: String,
    pub budget_policy_version: String,
    pub payer_actor_id: String,
    pub linked_receipt_ids_digest: Digest,
    pub status: ChainAnchorStatus,
    pub confirmed_at: Option<DateTime<Utc>>,
}

/// Chain anchor status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainAnchorStatus {
    Submitted,
    Confirmed,
    Finalized,
    Failed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signer_set_validation() {
        let mut set = SignerSetRef {
            signer_set_id: "test".to_string(),
            version: 1,
            certified_signer_pubkeys: vec!["pk".to_string(); 9],
            observer_pubkeys: vec![],
            threshold_rule: "5/9".to_string(),
            valid_from: Utc::now(),
            supersedes: None,
            admission_policy_version: "v1".to_string(),
            slashing_policy_version: None,
            receipt_id: None,
            metadata_digest: None,
        };

        assert!(set.validate().is_ok());

        set.certified_signer_pubkeys = vec!["pk".to_string(); 8];
        assert!(set.validate().is_err());
    }
}
