//! Signer Set Management
//!
//! Manages the set of 9 certified signers for L0 threshold signing.
//! Phase 1: Fixed 5/9 threshold rule.

use chrono::{DateTime, Utc};
use l0_core::types::{Digest, ReceiptId, SignerSetRef};
use std::collections::HashMap;

use crate::error::{SignerError, SignerResult};

/// Signer information
#[derive(Debug, Clone)]
pub struct SignerInfo {
    /// Signer's public key (Ed25519)
    pub pubkey: String,
    /// Signer's node ID
    pub node_id: String,
    /// Whether this is an observer (non-voting)
    pub is_observer: bool,
    /// When this signer was added to the set
    pub added_at: DateTime<Utc>,
}

/// Active signer set (exactly 9 certified signers)
#[derive(Debug, Clone)]
pub struct SignerSet {
    /// Signer set ID
    pub set_id: String,
    /// Version number
    pub version: u32,
    /// Certified signers (must be exactly 9)
    certified_signers: Vec<SignerInfo>,
    /// Observer signers (non-voting)
    observers: Vec<SignerInfo>,
    /// Threshold rule (locked to 5/9 in phase 1)
    pub threshold_rule: String,
    /// When this set became valid
    pub valid_from: DateTime<Utc>,
    /// Previous set ID this supersedes
    pub supersedes: Option<String>,
    /// Pubkey -> index map for fast lookup
    pubkey_index: HashMap<String, usize>,
}

impl SignerSet {
    /// Required number of certified signers (phase 1)
    pub const REQUIRED_SIGNERS: usize = 9;
    /// Required threshold (phase 1)
    pub const THRESHOLD: u32 = 5;
    /// Threshold rule string
    pub const THRESHOLD_RULE: &'static str = "5/9";

    /// Create a new signer set
    pub fn new(
        set_id: String,
        version: u32,
        certified_signers: Vec<SignerInfo>,
        observers: Vec<SignerInfo>,
        valid_from: DateTime<Utc>,
        supersedes: Option<String>,
    ) -> SignerResult<Self> {
        // Phase 1: Exactly 9 certified signers required
        if certified_signers.len() != Self::REQUIRED_SIGNERS {
            return Err(SignerError::InvalidSigner(format!(
                "Expected {} certified signers, got {}",
                Self::REQUIRED_SIGNERS,
                certified_signers.len()
            )));
        }

        // Build pubkey index
        let mut pubkey_index = HashMap::new();
        for (i, signer) in certified_signers.iter().enumerate() {
            pubkey_index.insert(signer.pubkey.clone(), i);
        }

        Ok(Self {
            set_id,
            version,
            certified_signers,
            observers,
            threshold_rule: Self::THRESHOLD_RULE.to_string(),
            valid_from,
            supersedes,
            pubkey_index,
        })
    }

    /// Get the version string
    pub fn version_string(&self) -> String {
        format!("{}:{}", self.set_id, self.version)
    }

    /// Check if a pubkey is a certified signer
    pub fn is_certified_signer(&self, pubkey: &str) -> bool {
        self.pubkey_index.contains_key(pubkey)
    }

    /// Check if a pubkey is an observer
    pub fn is_observer(&self, pubkey: &str) -> bool {
        self.observers.iter().any(|o| o.pubkey == pubkey)
    }

    /// Get the index of a certified signer
    pub fn signer_index(&self, pubkey: &str) -> Option<usize> {
        self.pubkey_index.get(pubkey).copied()
    }

    /// Get all certified signer pubkeys
    pub fn certified_pubkeys(&self) -> Vec<&str> {
        self.certified_signers.iter().map(|s| s.pubkey.as_str()).collect()
    }

    /// Get the threshold required
    pub fn threshold(&self) -> u32 {
        Self::THRESHOLD
    }

    /// Create a SignerSetRef for embedding in snapshots
    pub fn to_ref(&self, receipt_id: Option<ReceiptId>, metadata_digest: Option<Digest>) -> SignerSetRef {
        SignerSetRef {
            signer_set_id: self.set_id.clone(),
            version: self.version,
            certified_signer_pubkeys: self.certified_signers.iter().map(|s| s.pubkey.clone()).collect(),
            observer_pubkeys: self.observers.iter().map(|o| o.pubkey.clone()).collect(),
            threshold_rule: self.threshold_rule.clone(),
            valid_from: self.valid_from,
            supersedes: self.supersedes.clone(),
            admission_policy_version: "v1".to_string(),
            slashing_policy_version: None,
            receipt_id,
            metadata_digest,
        }
    }

    /// Create a signature bitmap string from a set of signer indices
    pub fn create_bitmap(&self, signer_indices: &[usize]) -> String {
        // Create a 9-bit bitmap where each bit represents a signer
        let mut bitmap: u16 = 0;
        for &idx in signer_indices {
            if idx < Self::REQUIRED_SIGNERS {
                bitmap |= 1 << idx;
            }
        }
        format!("{:09b}", bitmap)
    }

    /// Parse a signature bitmap to get signer indices
    pub fn parse_bitmap(&self, bitmap: &str) -> Vec<usize> {
        let mut indices = Vec::new();
        for (i, c) in bitmap.chars().rev().enumerate() {
            if c == '1' && i < Self::REQUIRED_SIGNERS {
                indices.push(i);
            }
        }
        indices
    }
}

/// Signer Set Manager - manages signer set lifecycle
pub struct SignerSetManager {
    /// Current active signer set
    current_set: Option<SignerSet>,
    /// Historical sets (for verification of old receipts)
    historical_sets: HashMap<String, SignerSet>,
}

impl SignerSetManager {
    /// Create a new manager
    pub fn new() -> Self {
        Self {
            current_set: None,
            historical_sets: HashMap::new(),
        }
    }

    /// Get the current signer set
    pub fn current(&self) -> Option<&SignerSet> {
        self.current_set.as_ref()
    }

    /// Set the current signer set
    pub fn set_current(&mut self, set: SignerSet) {
        // Archive the previous set
        if let Some(old) = self.current_set.take() {
            self.historical_sets.insert(old.version_string(), old);
        }
        self.current_set = Some(set);
    }

    /// Get a signer set by version string
    pub fn get_by_version(&self, version: &str) -> Option<&SignerSet> {
        if let Some(ref current) = self.current_set {
            if current.version_string() == version {
                return Some(current);
            }
        }
        self.historical_sets.get(version)
    }

    /// Validate that a signer set ref matches a known set
    pub fn validate_ref(&self, signer_ref: &SignerSetRef) -> SignerResult<&SignerSet> {
        let version = format!("{}:{}", signer_ref.signer_set_id, signer_ref.version);
        self.get_by_version(&version).ok_or_else(|| {
            SignerError::InvalidSigner(format!("Unknown signer set version: {}", version))
        })
    }
}

impl Default for SignerSetManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_signers(count: usize) -> Vec<SignerInfo> {
        (0..count)
            .map(|i| SignerInfo {
                pubkey: format!("pubkey_{}", i),
                node_id: format!("node_{}", i),
                is_observer: false,
                added_at: Utc::now(),
            })
            .collect()
    }

    #[test]
    fn test_signer_set_requires_nine() {
        let signers = make_test_signers(8);
        let result = SignerSet::new(
            "test".to_string(),
            1,
            signers,
            vec![],
            Utc::now(),
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_signer_set_valid() {
        let signers = make_test_signers(9);
        let result = SignerSet::new(
            "test".to_string(),
            1,
            signers,
            vec![],
            Utc::now(),
            None,
        );
        assert!(result.is_ok());
        let set = result.unwrap();
        assert_eq!(set.threshold(), 5);
        assert!(set.is_certified_signer("pubkey_0"));
        assert!(!set.is_certified_signer("unknown"));
    }

    #[test]
    fn test_bitmap() {
        let signers = make_test_signers(9);
        let set = SignerSet::new("test".to_string(), 1, signers, vec![], Utc::now(), None).unwrap();

        let indices = vec![0, 2, 4, 6, 8];
        let bitmap = set.create_bitmap(&indices);
        assert_eq!(bitmap, "101010101");

        let parsed = set.parse_bitmap(&bitmap);
        assert_eq!(parsed, vec![0, 2, 4, 6, 8]);
    }
}
