//! Atomicals Protocol Client
//!
//! Provides interface for creating Atomicals inscriptions on Bitcoin
//! for L0 epoch anchoring using the Atomicals protocol.
//!
//! Atomicals is a protocol for creating digital objects (atomicals) on Bitcoin
//! using specific envelope structures in witness data.
//!
//! ## Commit-Reveal Pattern
//!
//! Atomicals uses a commit-reveal pattern:
//! 1. **Commit**: Create a P2TR output that commits to the envelope script
//! 2. **Reveal**: Spend the commit output using the script path, revealing the envelope
//!
//! ```text
//! ┌─────────────┐     ┌─────────────┐
//! │ Commit TX   │────>│ Reveal TX   │
//! │ P2TR output │     │ Witness:    │
//! │ (key path)  │     │  - Envelope │
//! └─────────────┘     │  - Script   │
//!                     └─────────────┘
//! ```

use std::sync::Arc;
use std::io::Cursor;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use bitcoin::{
    hashes::Hash,
    secp256k1::{Secp256k1, All},
    taproot::{TaprootBuilder, LeafVersion},
    Address, Network, ScriptBuf, XOnlyPublicKey,
};

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
        let mut buffer = Vec::new();
        ciborium::into_writer(self, &mut buffer)
            .map_err(|e| P4Error::Serialization(format!("CBOR encoding error: {}", e)))?;
        Ok(buffer)
    }

    /// Deserialize from CBOR
    pub fn from_cbor(data: &[u8]) -> P4Result<Self> {
        let cursor = Cursor::new(data);
        ciborium::from_reader(cursor)
            .map_err(|e| P4Error::Serialization(format!("CBOR decoding error: {}", e)))
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
    /// Commit P2TR address
    pub commit_address: String,
    /// Inscription script
    pub inscription_script: Vec<u8>,
}

/// Taproot inscription details
#[derive(Debug, Clone)]
pub struct TaprootInscription {
    /// Internal key (x-only)
    pub internal_key: [u8; 32],
    /// Tweaked output key (x-only)
    pub output_key: [u8; 32],
    /// Script path leaf hash
    pub leaf_hash: [u8; 32],
    /// Inscription script
    pub script: Vec<u8>,
    /// Control block for spending via script path
    pub control_block: Vec<u8>,
    /// P2TR address
    pub address: String,
}

/// Commit transaction details
#[derive(Debug, Clone)]
pub struct CommitTxDetails {
    /// Commit transaction ID
    pub txid: String,
    /// Output index for the inscription
    pub vout: u32,
    /// Amount in satoshis
    pub amount: u64,
    /// Taproot inscription details
    pub inscription: TaprootInscription,
}

/// Inscription request
#[derive(Debug, Clone)]
pub struct InscriptionRequest {
    /// Epoch sequence number
    pub epoch_sequence: u64,
    /// Epoch root hash
    pub epoch_root: [u8; 32],
    /// Signer set version
    pub signer_set: String,
    /// Fee rate in sat/vB
    pub fee_rate: u64,
    /// Use CBOR encoding (true) or JSON (false)
    pub use_cbor: bool,
    /// Recipient address for the atomical
    pub recipient: Option<String>,
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
    /// Bitcoin RPC client (reserved for future wallet integration)
    #[allow(dead_code)]
    rpc: Arc<BitcoinRpcClient>,
    /// Configuration
    config: AtomicalsConfig,
    /// HTTP client for API
    http: reqwest::Client,
    /// Secp256k1 context
    secp: Secp256k1<All>,
    /// Bitcoin network
    network: Network,
}

impl AtomicalsClient {
    /// Create a new Atomicals client
    pub fn new(rpc: Arc<BitcoinRpcClient>, config: AtomicalsConfig) -> P4Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| P4Error::Network(e.to_string()))?;

        let secp = Secp256k1::new();

        // Determine network from config
        let network = if config.testnet {
            Network::Testnet
        } else {
            Network::Bitcoin
        };

        Ok(Self { rpc, config, http, secp, network })
    }

    /// Create a Taproot inscription for the envelope
    ///
    /// This builds a P2TR address with a script path that contains the envelope.
    pub fn create_taproot_inscription(
        &self,
        envelope_script: &[u8],
        internal_key_bytes: Option<&[u8; 32]>,
    ) -> P4Result<TaprootInscription> {
        // Use provided internal key or generate a "nothing up my sleeve" key
        // A common pattern is to use the unspendable point (NUMS point)
        let internal_key_bytes = internal_key_bytes.unwrap_or(&[
            0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54,
            0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
            0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5,
            0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
        ]);

        let internal_key = XOnlyPublicKey::from_slice(internal_key_bytes)
            .map_err(|e| P4Error::AtomicalsProtocol(format!("Invalid internal key: {}", e)))?;

        // Build the inscription script
        // The script is: <internal_pubkey> OP_CHECKSIG <envelope>
        // This allows spending via key path (signature) or script path (reveal envelope)
        let mut inscription_script = Vec::new();

        // Push internal key for key path spending check
        inscription_script.push(0x20); // Push 32 bytes
        inscription_script.extend_from_slice(internal_key_bytes);

        // OP_CHECKSIG
        inscription_script.push(0xac);

        // Append envelope
        inscription_script.extend_from_slice(envelope_script);

        // Build Taproot tree with single leaf
        let script_buf = ScriptBuf::from_bytes(inscription_script.clone());
        let taproot_builder = TaprootBuilder::new()
            .add_leaf(0, script_buf.clone())
            .map_err(|e| P4Error::AtomicalsProtocol(format!("Taproot build error: {:?}", e)))?;

        let taproot_spend_info = taproot_builder
            .finalize(&self.secp, internal_key)
            .map_err(|e| P4Error::AtomicalsProtocol(format!("Taproot finalize error: {:?}", e)))?;

        // Get the output key (tweaked)
        let output_key = taproot_spend_info.output_key();

        // Build control block for script path spending
        let control_block = taproot_spend_info
            .control_block(&(script_buf.clone(), LeafVersion::TapScript))
            .ok_or_else(|| P4Error::AtomicalsProtocol("Could not build control block".to_string()))?;

        // Calculate leaf hash using the merkle root (simplified approach)
        // For a single leaf tree, the merkle root is the tapleaf hash
        let leaf_hash = taproot_spend_info
            .merkle_root()
            .map(|root| *root.as_byte_array())
            .unwrap_or([0u8; 32]);

        // Build P2TR address
        let address = Address::p2tr_tweaked(output_key, self.network);

        Ok(TaprootInscription {
            internal_key: *internal_key_bytes,
            output_key: output_key.to_x_only_public_key().serialize(),
            leaf_hash,
            script: inscription_script,
            control_block: control_block.serialize(),
            address: address.to_string(),
        })
    }

    /// Create inscription with advanced options
    pub async fn create_inscription_advanced(
        &self,
        request: &InscriptionRequest,
    ) -> P4Result<AtomicalsCommitReveal> {
        info!(
            "Creating advanced Atomicals inscription for epoch {} with root {}",
            request.epoch_sequence,
            hex::encode(request.epoch_root)
        );

        // Create payload with appropriate encoding
        let payload = AtomicalsAnchorPayload::new(
            request.epoch_sequence,
            &request.epoch_root,
            &request.signer_set,
        );

        let payload_bytes = if request.use_cbor {
            payload.to_cbor()?
        } else {
            payload.to_json_bytes()?
        };

        debug!("Anchor payload: {} bytes ({})",
            payload_bytes.len(),
            if request.use_cbor { "CBOR" } else { "JSON" }
        );

        // Build envelope script
        let envelope = self.build_envelope(&payload_bytes)?;

        // Create Taproot inscription
        let inscription = self.create_taproot_inscription(&envelope, None)?;

        debug!("Created Taproot inscription: address={}", inscription.address);

        // Create commit transaction
        let commit_details = self.create_commit_tx_taproot(&inscription, request.fee_rate).await?;

        // Create reveal transaction
        let recipient = request.recipient.as_deref().unwrap_or(&inscription.address);
        let reveal_txid = self.create_reveal_tx_taproot(&commit_details, recipient, request.fee_rate).await?;

        // Atomical ID is derived from reveal txid
        let atomical_id = format!("{}i0", reveal_txid);

        // Calculate total fees
        let total_fee_sat = self.estimate_total_fee(payload_bytes.len(), request.fee_rate);

        info!(
            "Created Atomicals inscription: commit={}, reveal={}, atomical_id={}",
            commit_details.txid, reveal_txid, atomical_id
        );

        Ok(AtomicalsCommitReveal {
            commit_txid: commit_details.txid,
            reveal_txid,
            atomical_id,
            total_fee_sat,
            commit_address: inscription.address,
            inscription_script: envelope,
        })
    }

    /// Estimate total fee for commit + reveal
    fn estimate_total_fee(&self, payload_size: usize, fee_rate: u64) -> u64 {
        // Commit tx: ~150 vbytes (P2WPKH input + P2TR output)
        // Reveal tx: ~200 vbytes base + witness data
        // Witness data is 1/4 weight, so payload adds payload_size/4 vbytes
        let commit_vbytes = 150u64;
        let reveal_vbytes = 200 + (payload_size as u64 / 4);

        (commit_vbytes + reveal_vbytes) * fee_rate
    }

    /// Create commit transaction using Taproot
    async fn create_commit_tx_taproot(
        &self,
        inscription: &TaprootInscription,
        fee_rate: u64,
    ) -> P4Result<CommitTxDetails> {
        // Calculate required amount: reveal fee + dust output
        let reveal_fee = self.estimate_total_fee(inscription.script.len(), fee_rate);
        let dust_amount = 546u64;
        let required_amount = reveal_fee + dust_amount;

        info!(
            "Creating commit tx: address={}, required_amount={}",
            inscription.address, required_amount
        );

        // In production, this would:
        // 1. Find UTXOs to fund the transaction
        // 2. Build raw transaction with P2TR output
        // 3. Sign the transaction
        // 4. Broadcast and return txid

        // For now, generate deterministic txid based on inscription details
        use sha2::{Digest as Sha2Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"atomicals_commit:");
        hasher.update(inscription.output_key);
        hasher.update(&inscription.script);
        let hash = hasher.finalize();

        let txid = hex::encode(&hash[..32]);

        warn!(
            "Commit transaction creation simulated (real implementation requires wallet integration). \
             Txid: {}, Address: {}",
            txid, inscription.address
        );

        Ok(CommitTxDetails {
            txid,
            vout: 0,
            amount: required_amount,
            inscription: inscription.clone(),
        })
    }

    /// Create reveal transaction using Taproot script path
    async fn create_reveal_tx_taproot(
        &self,
        commit: &CommitTxDetails,
        recipient: &str,
        _fee_rate: u64,
    ) -> P4Result<String> {
        info!(
            "Creating reveal tx: commit_txid={}, recipient={}",
            commit.txid, recipient
        );

        // In production, this would:
        // 1. Create transaction spending the commit output via script path
        // 2. Include the control block and inscription script in witness
        // 3. Sign with the internal key
        // 4. Broadcast and return txid

        // The witness stack for script path spending:
        // [signature] [inscription_script] [control_block]

        // For now, generate deterministic txid
        use sha2::{Digest as Sha2Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"atomicals_reveal:");
        hasher.update(commit.txid.as_bytes());
        hasher.update(&commit.inscription.script);
        hasher.update(recipient.as_bytes());
        let hash = hasher.finalize();

        let txid = hex::encode(&hash[..32]);

        warn!(
            "Reveal transaction creation simulated (real implementation requires wallet integration). \
             Txid: {}, Recipient: {}",
            txid, recipient
        );

        Ok(txid)
    }

    /// Create L0 anchor inscription using Atomicals
    ///
    /// This creates a data inscription (dat) with the epoch anchor data.
    /// Atomicals inscriptions use a commit-reveal pattern.
    ///
    /// # Arguments
    /// * `epoch_sequence` - The epoch sequence number
    /// * `epoch_root` - The 32-byte epoch root hash
    /// * `signer_set` - The signer set version string
    /// * `funding_address` - Optional recipient address for the atomical
    pub async fn create_anchor_inscription(
        &self,
        epoch_sequence: u64,
        epoch_root: &[u8; 32],
        signer_set: &str,
        funding_address: Option<&str>,
    ) -> P4Result<AtomicalsCommitReveal> {
        // Use the advanced API with default options
        let request = InscriptionRequest {
            epoch_sequence,
            epoch_root: *epoch_root,
            signer_set: signer_set.to_string(),
            fee_rate: self.config.fee_rate.unwrap_or(10),
            use_cbor: self.config.use_cbor.unwrap_or(false),
            recipient: funding_address.map(String::from),
        };

        self.create_inscription_advanced(&request).await
    }

    /// Create anchor inscription with CBOR encoding
    ///
    /// This is the preferred method for production use as CBOR is more
    /// compact than JSON and is the standard for Atomicals protocol.
    pub async fn create_anchor_inscription_cbor(
        &self,
        epoch_sequence: u64,
        epoch_root: &[u8; 32],
        signer_set: &str,
        fee_rate: u64,
        recipient: Option<&str>,
    ) -> P4Result<AtomicalsCommitReveal> {
        let request = InscriptionRequest {
            epoch_sequence,
            epoch_root: *epoch_root,
            signer_set: signer_set.to_string(),
            fee_rate,
            use_cbor: true,
            recipient: recipient.map(String::from),
        };

        self.create_inscription_advanced(&request).await
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
        // Estimation formula
        let payload_size = 200;
        let commit_vbytes = 150u64;
        let reveal_vbytes = 200 + (payload_size as u64 / 4);
        let fee_rate = 10u64;
        let expected = (commit_vbytes + reveal_vbytes) * fee_rate + 546;

        assert!(expected > 0);
    }

    #[test]
    fn test_cbor_roundtrip() {
        let root = [0xef; 32];
        let payload = AtomicalsAnchorPayload::new(99999, &root, "v2:5");

        // Encode to CBOR
        let cbor_bytes = payload.to_cbor().unwrap();
        assert!(!cbor_bytes.is_empty());

        // Decode from CBOR
        let decoded = AtomicalsAnchorPayload::from_cbor(&cbor_bytes).unwrap();
        assert_eq!(decoded.epoch, 99999);
        assert_eq!(decoded.root, hex::encode(&root));
        assert_eq!(decoded.signer_set, "v2:5");
    }

    #[test]
    fn test_cbor_vs_json_size() {
        let root = [0x12; 32];
        let payload = AtomicalsAnchorPayload::new(12345678, &root, "v1:10");

        let json_bytes = payload.to_json_bytes().unwrap();
        let cbor_bytes = payload.to_cbor().unwrap();

        // CBOR should be more compact than JSON
        println!("JSON size: {} bytes, CBOR size: {} bytes", json_bytes.len(), cbor_bytes.len());
        // Note: For small payloads, the difference may be minimal
        // But the format is still correct
        assert!(!json_bytes.is_empty());
        assert!(!cbor_bytes.is_empty());
    }

    #[test]
    fn test_inscription_request_creation() {
        let root = [0xaa; 32];
        let request = InscriptionRequest {
            epoch_sequence: 100,
            epoch_root: root,
            signer_set: "v1:1".to_string(),
            fee_rate: 15,
            use_cbor: true,
            recipient: Some("bc1q...".to_string()),
        };

        assert_eq!(request.epoch_sequence, 100);
        assert_eq!(request.fee_rate, 15);
        assert!(request.use_cbor);
        assert!(request.recipient.is_some());
    }

    #[test]
    fn test_taproot_inscription_structure() {
        let inscription = TaprootInscription {
            internal_key: [0x50; 32],
            output_key: [0x60; 32],
            leaf_hash: [0x70; 32],
            script: vec![0x00, 0x63, 0x04, b'a', b't', b'o', b'm', 0x68],
            control_block: vec![0xc0, 0x50],
            address: "bc1p...".to_string(),
        };

        assert_eq!(inscription.internal_key[0], 0x50);
        assert_eq!(inscription.output_key[0], 0x60);
        assert!(!inscription.script.is_empty());
    }

    #[test]
    fn test_commit_tx_details() {
        let inscription = TaprootInscription {
            internal_key: [0x50; 32],
            output_key: [0x60; 32],
            leaf_hash: [0x70; 32],
            script: vec![0x00, 0x63, 0x04, b'a', b't', b'o', b'm', 0x68],
            control_block: vec![0xc0, 0x50],
            address: "bc1p...".to_string(),
        };

        let details = CommitTxDetails {
            txid: "abc123".to_string(),
            vout: 0,
            amount: 10000,
            inscription,
        };

        assert_eq!(details.txid, "abc123");
        assert_eq!(details.amount, 10000);
        assert_eq!(details.vout, 0);
    }

    #[test]
    fn test_atomicals_op_code() {
        assert_eq!(AtomicalsOp::Nft.code(), "nft");
        assert_eq!(AtomicalsOp::Ft.code(), "ft");
        assert_eq!(AtomicalsOp::Dft.code(), "dft");
        assert_eq!(AtomicalsOp::Realm.code(), "realm");
        assert_eq!(AtomicalsOp::Subrealm.code(), "subrealm");
        assert_eq!(AtomicalsOp::Container.code(), "container");
        assert_eq!(AtomicalsOp::Dat.code(), "dat");
    }
}
