//! L0-specific canonicalization extensions
//!
//! Provides domain tags and L0-specific commitment computation.

use crate::types::L0Digest;
use soulbase_crypto::{Canonicalizer, JsonCanonicalizer, DefaultDigester, Digester};

/// Domain separation tags for L0 signing contexts
pub mod domain_tags {
    /// Tag for batch snapshot signing
    pub const BATCH_SNAPSHOT: &[u8] = b"L0:SignedBatchSnapshotMsg:v1\0";
    /// Tag for epoch snapshot signing
    pub const EPOCH_SNAPSHOT: &[u8] = b"L0:EpochSnapshotMsg:v1\0";
    /// Tag for commitment signing
    pub const COMMITMENT: &[u8] = b"L0:CommitmentMsg:v1\0";
    /// Tag for receipt signing
    pub const RECEIPT: &[u8] = b"L0:ReceiptMsg:v1\0";
    /// Tag for consent signing
    pub const CONSENT: &[u8] = b"L0:ConsentMsg:v1\0";
    /// Tag for verdict signing
    pub const VERDICT: &[u8] = b"L0:VerdictMsg:v1\0";
    /// Tag for TipWitness signing
    pub const TIP_WITNESS: &[u8] = b"L0:TipWitnessMsg:v1\0";
}

/// L0 commitment computer using soulbase_crypto
pub struct L0Commitment {
    canonicalizer: JsonCanonicalizer,
    digester: DefaultDigester,
}

impl Default for L0Commitment {
    fn default() -> Self {
        Self::new()
    }
}

impl L0Commitment {
    /// Create a new L0Commitment instance
    pub fn new() -> Self {
        Self {
            canonicalizer: JsonCanonicalizer,
            digester: DefaultDigester,
        }
    }

    /// Compute commitment digest for a JSON value with domain tag
    pub fn commit_with_domain(
        &self,
        domain_tag: &[u8],
        value: &serde_json::Value,
    ) -> Result<L0Digest, soulbase_crypto::errors::CryptoError> {
        // 1. Canonicalize JSON
        let canonical = self.canonicalizer.canonical_json(value)?;

        // 2. Prepend domain tag
        let mut tagged = domain_tag.to_vec();
        tagged.extend_from_slice(&canonical);

        // 3. Compute BLAKE3 hash
        let digest = self.digester.blake3(&tagged)?;

        Ok(L0Digest::from_soulbase(&digest))
    }

    /// Compute commitment digest for raw bytes with domain tag
    pub fn commit_bytes_with_domain(
        &self,
        domain_tag: &[u8],
        data: &[u8],
    ) -> Result<L0Digest, soulbase_crypto::errors::CryptoError> {
        let mut tagged = domain_tag.to_vec();
        tagged.extend_from_slice(data);

        let digest = self.digester.blake3(&tagged)?;
        Ok(L0Digest::from_soulbase(&digest))
    }

    /// Compute simple BLAKE3 hash (no domain tag)
    pub fn hash(&self, data: &[u8]) -> L0Digest {
        L0Digest::blake3(data)
    }

    /// Get the underlying canonicalizer
    pub fn canonicalizer(&self) -> &JsonCanonicalizer {
        &self.canonicalizer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_commit_with_domain() {
        let committer = L0Commitment::new();
        let value = json!({"actor_id": "actor:123", "action": "submit"});

        let digest = committer
            .commit_with_domain(domain_tags::COMMITMENT, &value)
            .unwrap();

        assert!(!digest.is_zero());
    }

    #[test]
    fn test_domain_tag_affects_hash() {
        let committer = L0Commitment::new();
        let value = json!({"data": "test"});

        let d1 = committer
            .commit_with_domain(domain_tags::COMMITMENT, &value)
            .unwrap();
        let d2 = committer
            .commit_with_domain(domain_tags::RECEIPT, &value)
            .unwrap();

        assert_ne!(d1, d2);
    }

    #[test]
    fn test_deterministic() {
        let committer = L0Commitment::new();
        let value = json!({"b": 2, "a": 1}); // Unordered

        let d1 = committer
            .commit_with_domain(domain_tags::COMMITMENT, &value)
            .unwrap();
        let d2 = committer
            .commit_with_domain(domain_tags::COMMITMENT, &value)
            .unwrap();

        assert_eq!(d1, d2);
    }
}
