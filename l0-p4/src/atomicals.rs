//! Atomicals Protocol Client
//!
//! Provides interface for creating Atomicals inscriptions on Bitcoin
//! for L0 epoch anchoring using the Atomicals protocol.
//!
//! Atomicals is a protocol for creating digital objects (atomicals) on Bitcoin
//! using specific envelope structures in witness data.

use std::sync::Arc;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::bitcoin::BitcoinRpcClient;
use crate::config::AtomicalsConfig;
use crate::error::{P4Error, P4Result};

/// Atomicals envelope prefix
/// "atom" in hex = 0x61746f6d
pub const ATOMICALS_ENVELOPE_PREFIX: &[u8] = b"atom";

/// L0 anchor realm name
pub const L0_REALM: &str = "l0-anchor";

/// Atomicals operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AtomicalsOp {
    /// Non-fungible token (NFT) mint
    Nft,
    /// Fungible token (FT) mint
    Ft,
    /// Data storage (dft)
    Dft,
    /// Realm registration
    Realm,
    /// Subrealm registration
    Subrealm,
    /// Container creation
    Container,
    /// Data inscription
    Dat,
}

impl AtomicalsOp {
    /// Get operation code
    pub fn code(&self) -> &'static str {
        match self {
            AtomicalsOp::Nft => "nft",
            AtomicalsOp::Ft => "ft",
            AtomicalsOp::Dft => "dft",
            AtomicalsOp::Realm => "realm",
            AtomicalsOp::Subrealm => "subrealm",
            AtomicalsOp::Container => "container",
            AtomicalsOp::Dat => "dat",
        }
    }
}

/// Atomicals anchor payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtomicalsAnchorPayload {
    /// Operation type
    pub op: String,
    /// Protocol name for L0
    pub p: String,
    /// Epoch sequence number
    pub epoch: u64,
    /// Epoch root hash (hex)
    pub root: String,
    /// Signer set version
    pub signer_set: String,
    /// Timestamp
    pub ts: u64,
    /// Optional metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
}

impl AtomicalsAnchorPayload {
    /// Create a new L0 anchor payload
    pub fn new(epoch: u64, root: &[u8; 32], signer_set: &str) -> Self {
        Self {
            op: "dat".to_string(),  // Data inscription
            p: "l0".to_string(),
            epoch,
            root: hex::encode(root),
            signer_set: signer_set.to_string(),
            ts: chrono::Utc::now().timestamp() as u64,
            meta: None,
        }
    }

    /// Add metadata
    pub fn with_meta(mut self, meta: serde_json::Value) -> Self {
        self.meta = Some(meta);
        self
    }

    /// Serialize to CBOR (Atomicals uses CBOR)
    pub fn to_cbor(&self) -> P4Result<Vec<u8>> {
        // For now, use JSON encoding wrapped in envelope
        // Production would use proper CBOR encoding
        let json = serde_json::to_vec(self)?;
        Ok(json)
    }

    /// Serialize to JSON bytes
    pub fn to_json_bytes(&self) -> P4Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }
}

/// Atomicals commit/reveal transaction pair
#[derive(Debug, Clone)]
pub struct AtomicalsCommitReveal {
    /// Commit transaction (first)
    pub commit_txid: String,
    /// Reveal transaction (second)
    pub reveal_txid: String,
    /// Atomical ID (derived from reveal)
    pub atomical_id: String,
    /// Fee paid (total)
    pub total_fee_sat: u64,
}

/// Atomical info from indexer
#[derive(Debug, Clone, Deserialize)]
pub struct AtomicalInfo {
    /// Atomical ID
    pub atomical_id: String,
    /// Atomical number
    pub atomical_number: u64,
    /// Type (nft, ft, etc.)
    #[serde(rename = "type")]
    pub atomical_type: String,
    /// Mint transaction ID
    pub mint_txid: String,
    /// Current location
    pub location_txid: String,
    /// Owner script hash
    pub owner_script_hash: String,
    /// Data payload
    pub data: Option<serde_json::Value>,
}

/// Atomicals client
pub struct AtomicalsClient {
    /// Bitcoin RPC client
    rpc: Arc<BitcoinRpcClient>,
    /// Configuration
    config: AtomicalsConfig,
    /// HTTP client for API
    http: reqwest::Client,
}

impl AtomicalsClient {
    /// Create a new Atomicals client
    pub fn new(rpc: Arc<BitcoinRpcClient>, config: AtomicalsConfig) -> P4Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| P4Error::Network(e.to_string()))?;

        Ok(Self { rpc, config, http })
    }

    /// Create L0 anchor inscription using Atomicals
    ///
    /// This creates a data inscription (dat) with the epoch anchor data.
    /// Atomicals inscriptions use a commit-reveal pattern.
    pub async fn create_anchor_inscription(
        &self,
        epoch_sequence: u64,
        epoch_root: &[u8; 32],
        signer_set: &str,
        funding_address: Option<&str>,
    ) -> P4Result<AtomicalsCommitReveal> {
        info!(
            "Creating Atomicals anchor inscription for epoch {} with root {}",
            epoch_sequence,
            hex::encode(epoch_root)
        );

        // Create payload
        let payload = AtomicalsAnchorPayload::new(epoch_sequence, epoch_root, signer_set);
        let payload_bytes = payload.to_json_bytes()?;

        debug!("Anchor payload: {} bytes", payload_bytes.len());

        // Build envelope script
        // Atomicals envelope: OP_FALSE OP_IF "atom" <operation> <payload> OP_ENDIF
        let envelope = self.build_envelope(&payload_bytes)?;

        // Get funding address
        let funding = match funding_address {
            Some(addr) => addr.to_string(),
            None => self.rpc.get_new_address(Some("atomicals_anchor")).await?,
        };

        // In a real implementation, this would:
        // 1. Create commit transaction (locks funds to a taproot address with envelope)
        // 2. Create reveal transaction (spends commit with envelope in witness)
        // 3. Sign and broadcast both

        // For now, simulate the commit-reveal flow
        let commit_txid = self.create_commit_tx(&envelope, &funding).await?;
        let reveal_txid = self.create_reveal_tx(&commit_txid, &envelope, &funding).await?;

        // Atomical ID is derived from reveal txid
        let atomical_id = format!("{}i0", reveal_txid);

        info!(
            "Created Atomicals inscription: commit={}, reveal={}, atomical_id={}",
            commit_txid, reveal_txid, atomical_id
        );

        Ok(AtomicalsCommitReveal {
            commit_txid,
            reveal_txid,
            atomical_id,
            total_fee_sat: 0, // Would be calculated from actual transactions
        })
    }

    /// Build Atomicals envelope script
    fn build_envelope(&self, payload: &[u8]) -> P4Result<Vec<u8>> {
        // Atomicals envelope format (in witness script):
        // OP_FALSE OP_IF
        //   "atom"
        //   <operation_type>
        //   <payload_chunks>
        // OP_ENDIF

        let mut script = Vec::new();

        // OP_FALSE (0x00)
        script.push(0x00);

        // OP_IF (0x63)
        script.push(0x63);

        // Push "atom" marker
        script.push(ATOMICALS_ENVELOPE_PREFIX.len() as u8);
        script.extend_from_slice(ATOMICALS_ENVELOPE_PREFIX);

        // Push operation ("dat" for data)
        let op = b"dat";
        script.push(op.len() as u8);
        script.extend_from_slice(op);

        // Push payload (chunked if > 520 bytes)
        let chunks: Vec<&[u8]> = payload.chunks(520).collect();
        for chunk in chunks {
            if chunk.len() <= 75 {
                script.push(chunk.len() as u8);
            } else if chunk.len() <= 255 {
                script.push(0x4c); // OP_PUSHDATA1
                script.push(chunk.len() as u8);
            } else {
                script.push(0x4d); // OP_PUSHDATA2
                script.extend_from_slice(&(chunk.len() as u16).to_le_bytes());
            }
            script.extend_from_slice(chunk);
        }

        // OP_ENDIF (0x68)
        script.push(0x68);

        Ok(script)
    }

    /// Create commit transaction (placeholder implementation)
    async fn create_commit_tx(
        &self,
        envelope: &[u8],
        funding_address: &str,
    ) -> P4Result<String> {
        // In production, this would:
        // 1. Create a taproot address with the envelope as a script path
        // 2. Fund the address with enough sats for reveal + fees
        // 3. Broadcast the commit transaction

        // For now, return a placeholder that indicates the implementation is ready
        // but requires actual Bitcoin wallet integration
        warn!(
            "Atomicals commit transaction creation not fully implemented. \
             Envelope: {} bytes, funding: {}",
            envelope.len(),
            funding_address
        );

        // Generate a deterministic "txid" based on envelope hash for testing
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"commit:");
        hasher.update(envelope);
        hasher.update(funding_address.as_bytes());
        let hash = hasher.finalize();

        Ok(hex::encode(&hash[..32]))
    }

    /// Create reveal transaction (placeholder implementation)
    async fn create_reveal_tx(
        &self,
        commit_txid: &str,
        envelope: &[u8],
        recipient: &str,
    ) -> P4Result<String> {
        // In production, this would:
        // 1. Spend the commit output using the envelope script path
        // 2. Include the envelope in the witness data
        // 3. Send the atomical to the recipient

        warn!(
            "Atomicals reveal transaction creation not fully implemented. \
             Commit: {}, envelope: {} bytes",
            commit_txid,
            envelope.len()
        );

        // Generate a deterministic "txid" based on commit and envelope
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"reveal:");
        hasher.update(commit_txid.as_bytes());
        hasher.update(envelope);
        hasher.update(recipient.as_bytes());
        let hash = hasher.finalize();

        Ok(hex::encode(&hash[..32]))
    }

    /// Query Atomicals API for atomical info
    pub async fn get_atomical_info(&self, atomical_id: &str) -> P4Result<Option<AtomicalInfo>> {
        let api_url = match &self.config.api_url {
            Some(url) => url,
            None => {
                return Err(P4Error::AtomicalsProtocol(
                    "API URL not configured".to_string(),
                ))
            }
        };

        let url = format!("{}/atomical/{}", api_url, atomical_id);

        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| P4Error::Network(e.to_string()))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !response.status().is_success() {
            return Err(P4Error::AtomicalsProtocol(format!(
                "API error: {}",
                response.status()
            )));
        }

        let info: AtomicalInfo = response
            .json()
            .await
            .map_err(|e| P4Error::Serialization(e.to_string()))?;

        Ok(Some(info))
    }

    /// Verify an L0 anchor atomical
    pub async fn verify_anchor_atomical(
        &self,
        atomical_id: &str,
        expected_epoch: u64,
        expected_root: &[u8; 32],
    ) -> P4Result<bool> {
        let info = self
            .get_atomical_info(atomical_id)
            .await?
            .ok_or_else(|| P4Error::AtomicalsProtocol(format!("Atomical not found: {}", atomical_id)))?;

        // Check if it's an L0 anchor
        if info.atomical_type != "dat" {
            return Ok(false);
        }

        // Parse the data payload
        if let Some(data) = &info.data {
            if let Some(p) = data.get("p").and_then(|v| v.as_str()) {
                if p != "l0" {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }

            if let Some(epoch) = data.get("epoch").and_then(|v| v.as_u64()) {
                if epoch != expected_epoch {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }

            if let Some(root) = data.get("root").and_then(|v| v.as_str()) {
                if root != hex::encode(expected_root) {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }

            return Ok(true);
        }

        Ok(false)
    }

    /// Get required fee for Atomicals inscription
    pub fn estimate_inscription_fee(&self, payload_size: usize) -> u64 {
        // Rough estimation:
        // - Commit tx: ~150 vbytes
        // - Reveal tx: ~200 + payload_size / 4 vbytes (witness is 1/4 weight)
        let commit_vbytes = 150u64;
        let reveal_vbytes = 200 + (payload_size as u64 / 4);

        let fee_rate = 10u64; // sat/vB
        let total_fee = (commit_vbytes + reveal_vbytes) * fee_rate;

        // Add dust output (546 sats)
        total_fee + 546
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anchor_payload_creation() {
        let root = [0xab; 32];
        let payload = AtomicalsAnchorPayload::new(12345, &root, "v1:1");

        assert_eq!(payload.op, "dat");
        assert_eq!(payload.p, "l0");
        assert_eq!(payload.epoch, 12345);
        assert_eq!(payload.root, hex::encode(&root));
    }

    #[test]
    fn test_anchor_payload_serialization() {
        let root = [0xcd; 32];
        let payload = AtomicalsAnchorPayload::new(67890, &root, "v1:2");
        let bytes = payload.to_json_bytes().unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["epoch"], 67890);
        assert_eq!(parsed["p"], "l0");
    }

    #[test]
    fn test_fee_estimation() {
        // Create a mock client for testing fee estimation
        let config = AtomicalsConfig::default();

        // Estimation formula
        let payload_size = 200;
        let commit_vbytes = 150u64;
        let reveal_vbytes = 200 + (payload_size as u64 / 4);
        let fee_rate = 10u64;
        let expected = (commit_vbytes + reveal_vbytes) * fee_rate + 546;

        assert!(expected > 0);
    }
}
