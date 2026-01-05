//! Transaction Builder for L0 Anchoring
//!
//! Builds Bitcoin transactions with OP_RETURN outputs containing L0 epoch roots.

use std::sync::Arc;
use tracing::{debug, info};

use crate::bitcoin::BitcoinRpcClient;
use crate::config::P4Config;
use crate::error::{P4Error, P4Result};

/// L0 anchor protocol magic bytes
/// "L0v1" in ASCII = [0x4C, 0x30, 0x76, 0x31]
pub const L0_ANCHOR_MAGIC: [u8; 4] = [0x4C, 0x30, 0x76, 0x31];

/// Maximum OP_RETURN data size (80 bytes for standard relay)
pub const MAX_OP_RETURN_SIZE: usize = 80;

/// L0 anchor data structure
/// Format: MAGIC (4) + VERSION (1) + EPOCH_SEQ (8) + EPOCH_ROOT (32) + CHECKSUM (4) = 49 bytes
pub const L0_ANCHOR_DATA_SIZE: usize = 49;

/// Anchor transaction builder
pub struct AnchorTxBuilder {
    /// Bitcoin RPC client
    rpc: Arc<BitcoinRpcClient>,
    /// P4 configuration
    config: P4Config,
}

/// Anchor data to be embedded in OP_RETURN
#[derive(Debug, Clone)]
pub struct AnchorData {
    /// Protocol magic
    pub magic: [u8; 4],
    /// Protocol version
    pub version: u8,
    /// Epoch sequence number
    pub epoch_sequence: u64,
    /// Epoch root (32 bytes)
    pub epoch_root: [u8; 32],
    /// Checksum (first 4 bytes of hash of above)
    pub checksum: [u8; 4],
}

impl AnchorData {
    /// Create new anchor data
    pub fn new(epoch_sequence: u64, epoch_root: [u8; 32]) -> Self {
        let mut data = Self {
            magic: L0_ANCHOR_MAGIC,
            version: 1,
            epoch_sequence,
            epoch_root,
            checksum: [0; 4],
        };
        data.compute_checksum();
        data
    }

    /// Compute checksum
    fn compute_checksum(&mut self) {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&self.magic);
        hasher.update([self.version]);
        hasher.update(self.epoch_sequence.to_be_bytes());
        hasher.update(&self.epoch_root);
        let hash = hasher.finalize();
        self.checksum.copy_from_slice(&hash[..4]);
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(L0_ANCHOR_DATA_SIZE);
        bytes.extend_from_slice(&self.magic);
        bytes.push(self.version);
        bytes.extend_from_slice(&self.epoch_sequence.to_be_bytes());
        bytes.extend_from_slice(&self.epoch_root);
        bytes.extend_from_slice(&self.checksum);
        bytes
    }

    /// Parse from bytes
    pub fn from_bytes(bytes: &[u8]) -> P4Result<Self> {
        if bytes.len() < L0_ANCHOR_DATA_SIZE {
            return Err(P4Error::InvalidEpochRoot(format!(
                "Anchor data too short: {} < {}",
                bytes.len(),
                L0_ANCHOR_DATA_SIZE
            )));
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[0..4]);

        if magic != L0_ANCHOR_MAGIC {
            return Err(P4Error::InvalidEpochRoot("Invalid magic bytes".to_string()));
        }

        let version = bytes[4];
        if version != 1 {
            return Err(P4Error::InvalidEpochRoot(format!(
                "Unsupported version: {}",
                version
            )));
        }

        let mut epoch_seq_bytes = [0u8; 8];
        epoch_seq_bytes.copy_from_slice(&bytes[5..13]);
        let epoch_sequence = u64::from_be_bytes(epoch_seq_bytes);

        let mut epoch_root = [0u8; 32];
        epoch_root.copy_from_slice(&bytes[13..45]);

        let mut checksum = [0u8; 4];
        checksum.copy_from_slice(&bytes[45..49]);

        let mut data = Self {
            magic,
            version,
            epoch_sequence,
            epoch_root,
            checksum: [0; 4],
        };

        // Verify checksum
        data.compute_checksum();
        if data.checksum != checksum {
            return Err(P4Error::InvalidEpochRoot("Checksum mismatch".to_string()));
        }

        data.checksum = checksum;
        Ok(data)
    }

    /// Get hex string of anchor data
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }
}

/// Built transaction ready for broadcast
#[derive(Debug, Clone)]
pub struct BuiltTransaction {
    /// Signed transaction hex
    pub hex: String,
    /// Transaction ID
    pub txid: String,
    /// Transaction fee in satoshis
    pub fee_sat: u64,
    /// Transaction size in virtual bytes
    pub vsize: u32,
    /// Anchor data embedded
    pub anchor_data: AnchorData,
}

impl AnchorTxBuilder {
    /// Create a new anchor transaction builder
    pub fn new(rpc: Arc<BitcoinRpcClient>, config: P4Config) -> Self {
        Self { rpc, config }
    }

    /// Build an anchor transaction
    pub async fn build_anchor_tx(
        &self,
        epoch_sequence: u64,
        epoch_root: &[u8; 32],
        change_address: Option<&str>,
    ) -> P4Result<BuiltTransaction> {
        info!(
            "Building anchor transaction for epoch {} with root {}",
            epoch_sequence,
            hex::encode(epoch_root)
        );

        // Create anchor data
        let anchor_data = AnchorData::new(epoch_sequence, *epoch_root);
        let op_return_data = anchor_data.to_bytes();

        debug!("Anchor data: {} bytes", op_return_data.len());

        // Get fee rate
        let fee_rate = self
            .rpc
            .estimate_smart_fee(6)
            .await
            .unwrap_or(self.config.fee_rate_sat_vb);

        debug!("Using fee rate: {} sat/vB", fee_rate);

        // Build OP_RETURN output
        // Script: OP_RETURN <data>
        let op_return_hex = format!(
            "6a{}{}",
            push_data_opcode(op_return_data.len()),
            hex::encode(&op_return_data)
        );

        // Create raw transaction with OP_RETURN output
        let outputs = serde_json::json!({
            "data": hex::encode(&op_return_data)
        });

        // Get change address if not provided
        let change_addr = match change_address {
            Some(addr) => addr.to_string(),
            None => self.rpc.get_new_address(Some("l0_anchor_change")).await?,
        };

        // Create transaction with just OP_RETURN (will be funded next)
        let raw_tx = self
            .rpc
            .create_raw_transaction(&[], &outputs)
            .await?;

        debug!("Created raw transaction: {}", raw_tx);

        // Fund the transaction (adds inputs and change)
        let fund_options = serde_json::json!({
            "changeAddress": change_addr,
            "feeRate": fee_rate as f64 / 100_000.0,  // Convert sat/vB to BTC/kvB
            "includeWatching": false,
            "lockUnspents": true
        });

        let (funded_tx, fee_btc, _change_pos) = self
            .rpc
            .fund_raw_transaction(&raw_tx, Some(fund_options))
            .await?;

        let fee_sat = (fee_btc * 100_000_000.0) as u64;

        // Check max fee
        if fee_sat > self.config.max_fee_sat {
            return Err(P4Error::InsufficientFunds {
                required: fee_sat,
                available: self.config.max_fee_sat,
            });
        }

        debug!("Funded transaction, fee: {} sat", fee_sat);

        // Sign the transaction
        let signed_tx = self
            .rpc
            .sign_raw_transaction_with_wallet(&funded_tx)
            .await?;

        // Decode to get txid and vsize
        let decoded = self.rpc.decode_raw_transaction(&signed_tx).await?;
        let txid = decoded["txid"]
            .as_str()
            .ok_or_else(|| P4Error::TransactionBuild("No txid in decoded tx".to_string()))?
            .to_string();
        let vsize = decoded["vsize"].as_u64().unwrap_or(0) as u32;

        // Test mempool accept
        let accepted = self.rpc.test_mempool_accept(&signed_tx).await?;
        if !accepted {
            return Err(P4Error::InvalidTransaction(
                "Transaction rejected by mempool".to_string(),
            ));
        }

        info!(
            "Built anchor transaction: txid={}, fee={}sat, vsize={}vB",
            txid, fee_sat, vsize
        );

        Ok(BuiltTransaction {
            hex: signed_tx,
            txid,
            fee_sat,
            vsize,
            anchor_data,
        })
    }

    /// Broadcast a built transaction
    pub async fn broadcast(&self, tx: &BuiltTransaction) -> P4Result<String> {
        let result = self.rpc.send_raw_transaction(&tx.hex).await?;
        info!("Broadcast anchor transaction: {}", result.txid);
        Ok(result.txid)
    }

    /// Build and broadcast an anchor transaction
    pub async fn anchor_epoch(
        &self,
        epoch_sequence: u64,
        epoch_root: &[u8; 32],
        change_address: Option<&str>,
    ) -> P4Result<String> {
        let tx = self
            .build_anchor_tx(epoch_sequence, epoch_root, change_address)
            .await?;
        self.broadcast(&tx).await
    }
}

/// Get OP_PUSHDATA opcode for data length
fn push_data_opcode(len: usize) -> String {
    if len <= 75 {
        // Direct push
        format!("{:02x}", len)
    } else if len <= 255 {
        // OP_PUSHDATA1
        format!("4c{:02x}", len)
    } else if len <= 65535 {
        // OP_PUSHDATA2
        format!("4d{:02x}{:02x}", len & 0xff, (len >> 8) & 0xff)
    } else {
        // OP_PUSHDATA4
        format!(
            "4e{:02x}{:02x}{:02x}{:02x}",
            len & 0xff,
            (len >> 8) & 0xff,
            (len >> 16) & 0xff,
            (len >> 24) & 0xff
        )
    }
}

/// Parse anchor data from a transaction output
pub fn parse_anchor_from_tx(tx_hex: &str) -> P4Result<Option<AnchorData>> {
    // This is a simplified parser - in production would use bitcoin crate
    let tx_bytes = hex::decode(tx_hex)?;

    // Look for OP_RETURN (0x6a) followed by L0 magic
    let magic_pattern = [0x6a, L0_ANCHOR_MAGIC[0], L0_ANCHOR_MAGIC[1]];

    for i in 0..tx_bytes.len().saturating_sub(L0_ANCHOR_DATA_SIZE + 2) {
        if tx_bytes[i] == 0x6a {
            // Found OP_RETURN, check for push opcode and magic
            let push_len = tx_bytes.get(i + 1).copied().unwrap_or(0) as usize;
            if push_len >= L0_ANCHOR_DATA_SIZE && i + 2 + push_len <= tx_bytes.len() {
                let data = &tx_bytes[i + 2..i + 2 + push_len];
                if data.starts_with(&L0_ANCHOR_MAGIC) {
                    return Ok(Some(AnchorData::from_bytes(data)?));
                }
            }
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anchor_data_serialization() {
        let epoch_root = [0xab; 32];
        let anchor = AnchorData::new(12345, epoch_root);

        let bytes = anchor.to_bytes();
        assert_eq!(bytes.len(), L0_ANCHOR_DATA_SIZE);

        // Check magic
        assert_eq!(&bytes[0..4], &L0_ANCHOR_MAGIC);

        // Parse back
        let parsed = AnchorData::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.epoch_sequence, 12345);
        assert_eq!(parsed.epoch_root, epoch_root);
        assert_eq!(parsed.checksum, anchor.checksum);
    }

    #[test]
    fn test_anchor_data_invalid_magic() {
        let mut bytes = vec![0u8; L0_ANCHOR_DATA_SIZE];
        bytes[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        let result = AnchorData::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_anchor_data_checksum_verification() {
        let epoch_root = [0xcd; 32];
        let anchor = AnchorData::new(67890, epoch_root);
        let mut bytes = anchor.to_bytes();

        // Corrupt checksum
        bytes[47] ^= 0xff;

        let result = AnchorData::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_push_data_opcode() {
        assert_eq!(push_data_opcode(32), "20");
        assert_eq!(push_data_opcode(49), "31");
        assert_eq!(push_data_opcode(75), "4b");
        assert_eq!(push_data_opcode(76), "4c4c");
        assert_eq!(push_data_opcode(255), "4cff");
        assert_eq!(push_data_opcode(256), "4d0001");
    }
}
