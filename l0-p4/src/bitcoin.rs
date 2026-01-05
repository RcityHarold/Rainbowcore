//! Bitcoin RPC Client
//!
//! Provides interface to Bitcoin Core RPC for L0 anchoring operations.

use base64::Engine;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

use crate::config::BitcoinRpcConfig;
use crate::error::{P4Error, P4Result};

/// Bitcoin RPC client for interacting with Bitcoin Core
pub struct BitcoinRpcClient {
    /// HTTP client
    client: Client,
    /// RPC configuration
    config: BitcoinRpcConfig,
    /// Request ID counter
    request_id: std::sync::atomic::AtomicU64,
}

/// JSON-RPC request
#[derive(Debug, Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: serde_json::Value,
}

/// JSON-RPC response
#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
    #[allow(dead_code)]
    id: u64,
}

/// JSON-RPC error
#[derive(Debug, Deserialize)]
struct RpcError {
    code: i32,
    message: String,
}

/// UTXO (Unspent Transaction Output)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Utxo {
    /// Transaction ID
    pub txid: String,
    /// Output index
    pub vout: u32,
    /// Script pubkey (hex)
    pub script_pub_key: String,
    /// Amount in satoshis
    pub amount_sat: u64,
    /// Confirmations
    pub confirmations: u32,
    /// Is spendable
    pub spendable: bool,
    /// Address (if available)
    pub address: Option<String>,
}

/// Transaction info from RPC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionInfo {
    /// Transaction ID
    pub txid: String,
    /// Block hash (if confirmed)
    pub blockhash: Option<String>,
    /// Block height (if confirmed)
    pub blockheight: Option<u64>,
    /// Confirmations (0 if unconfirmed)
    pub confirmations: u32,
    /// Transaction time
    pub time: Option<u64>,
    /// Block time
    pub blocktime: Option<u64>,
    /// Raw transaction hex
    pub hex: String,
}

/// Block info from RPC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockInfo {
    /// Block hash
    pub hash: String,
    /// Block height
    pub height: u64,
    /// Previous block hash
    pub previousblockhash: Option<String>,
    /// Block time
    pub time: u64,
    /// Number of confirmations
    pub confirmations: i32,
    /// Number of transactions
    pub nTx: u32,
}

/// Network info from RPC
#[derive(Debug, Clone, Deserialize)]
pub struct NetworkInfo {
    /// Node version
    pub version: u64,
    /// Subversion string
    pub subversion: String,
    /// Protocol version
    pub protocolversion: u64,
    /// Number of connections
    pub connections: u32,
    /// Is network active
    pub networkactive: bool,
}

/// Blockchain info from RPC
#[derive(Debug, Clone, Deserialize)]
pub struct BlockchainInfo {
    /// Current chain
    pub chain: String,
    /// Number of blocks
    pub blocks: u64,
    /// Number of headers
    pub headers: u64,
    /// Best block hash
    pub bestblockhash: String,
    /// Verification progress
    pub verificationprogress: f64,
    /// Is pruned
    pub pruned: bool,
}

/// Send raw transaction result
#[derive(Debug, Clone)]
pub struct SendResult {
    /// Transaction ID
    pub txid: String,
}

/// Fee estimation result
#[derive(Debug, Clone, Deserialize)]
pub struct FeeEstimate {
    /// Fee rate in BTC/kvB
    pub feerate: Option<f64>,
    /// Errors (if any)
    pub errors: Option<Vec<String>>,
    /// Target blocks
    pub blocks: u32,
}

impl BitcoinRpcClient {
    /// Create a new Bitcoin RPC client
    pub fn new(config: BitcoinRpcConfig) -> P4Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|e| P4Error::RpcConnection(e.to_string()))?;

        Ok(Self {
            client,
            config,
            request_id: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Make an RPC call
    async fn call<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> P4Result<T> {
        let id = self.request_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        let request = RpcRequest {
            jsonrpc: "2.0",
            id,
            method,
            params,
        };

        let auth = format!("{}:{}", self.config.username, self.config.password);
        let auth_header = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(auth)
        );

        debug!("Bitcoin RPC call: {} id={}", method, id);

        let response = self
            .client
            .post(&self.config.rpc_url())
            .header("Authorization", auth_header)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| P4Error::RpcConnection(e.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(P4Error::RpcRequest(format!(
                "HTTP {} - {}",
                status, body
            )));
        }

        let rpc_response: RpcResponse<T> = response
            .json()
            .await
            .map_err(|e| P4Error::RpcRequest(e.to_string()))?;

        if let Some(error) = rpc_response.error {
            return Err(P4Error::RpcResponse {
                code: error.code,
                message: error.message,
            });
        }

        rpc_response
            .result
            .ok_or_else(|| P4Error::RpcRequest("Empty response".to_string()))
    }

    /// Test connection to the node
    pub async fn ping(&self) -> P4Result<()> {
        let _: serde_json::Value = self.call("getblockchaininfo", serde_json::json!([])).await?;
        Ok(())
    }

    /// Get network info
    pub async fn get_network_info(&self) -> P4Result<NetworkInfo> {
        self.call("getnetworkinfo", serde_json::json!([])).await
    }

    /// Get blockchain info
    pub async fn get_blockchain_info(&self) -> P4Result<BlockchainInfo> {
        self.call("getblockchaininfo", serde_json::json!([])).await
    }

    /// Get current block count
    pub async fn get_block_count(&self) -> P4Result<u64> {
        self.call("getblockcount", serde_json::json!([])).await
    }

    /// Get best block hash
    pub async fn get_best_block_hash(&self) -> P4Result<String> {
        self.call("getbestblockhash", serde_json::json!([])).await
    }

    /// Get block by hash
    pub async fn get_block(&self, hash: &str) -> P4Result<BlockInfo> {
        self.call("getblock", serde_json::json!([hash, 1])).await
    }

    /// Get block hash by height
    pub async fn get_block_hash(&self, height: u64) -> P4Result<String> {
        self.call("getblockhash", serde_json::json!([height])).await
    }

    /// Get raw transaction
    pub async fn get_raw_transaction(&self, txid: &str, verbose: bool) -> P4Result<serde_json::Value> {
        self.call("getrawtransaction", serde_json::json!([txid, verbose]))
            .await
    }

    /// Get transaction info
    pub async fn get_transaction_info(&self, txid: &str) -> P4Result<TransactionInfo> {
        #[derive(Deserialize)]
        struct RawTx {
            txid: String,
            hash: String,
            blockhash: Option<String>,
            blockheight: Option<u64>,
            confirmations: Option<u32>,
            time: Option<u64>,
            blocktime: Option<u64>,
            hex: String,
        }

        let raw: RawTx = self
            .call("getrawtransaction", serde_json::json!([txid, true]))
            .await?;

        Ok(TransactionInfo {
            txid: raw.txid,
            blockhash: raw.blockhash,
            blockheight: raw.blockheight,
            confirmations: raw.confirmations.unwrap_or(0),
            time: raw.time,
            blocktime: raw.blocktime,
            hex: raw.hex,
        })
    }

    /// Get transaction confirmations
    pub async fn get_transaction_confirmations(&self, txid: &str) -> P4Result<u32> {
        match self.get_transaction_info(txid).await {
            Ok(info) => Ok(info.confirmations),
            Err(P4Error::RpcResponse { code: -5, .. }) => {
                // TX not found in mempool or blockchain
                Err(P4Error::TransactionNotFound(txid.to_string()))
            }
            Err(e) => Err(e),
        }
    }

    /// Send raw transaction
    pub async fn send_raw_transaction(&self, hex: &str) -> P4Result<SendResult> {
        let txid: String = self
            .call("sendrawtransaction", serde_json::json!([hex]))
            .await?;

        info!("Broadcast transaction: {}", txid);
        Ok(SendResult { txid })
    }

    /// Estimate smart fee (in sat/vB)
    pub async fn estimate_smart_fee(&self, conf_target: u32) -> P4Result<u64> {
        let estimate: FeeEstimate = self
            .call("estimatesmartfee", serde_json::json!([conf_target]))
            .await?;

        if let Some(errors) = &estimate.errors {
            if !errors.is_empty() {
                warn!("Fee estimation warnings: {:?}", errors);
            }
        }

        // Convert BTC/kvB to sat/vB
        let feerate_btc_kvb = estimate.feerate.unwrap_or(0.00001); // Default 1 sat/vB
        let feerate_sat_vb = (feerate_btc_kvb * 100_000.0) as u64;

        Ok(feerate_sat_vb.max(1))
    }

    /// List unspent outputs
    pub async fn list_unspent(
        &self,
        min_conf: u32,
        max_conf: u32,
        addresses: Option<&[&str]>,
    ) -> P4Result<Vec<Utxo>> {
        #[derive(Deserialize)]
        struct RpcUtxo {
            txid: String,
            vout: u32,
            address: Option<String>,
            scriptPubKey: String,
            amount: f64,
            confirmations: u32,
            spendable: bool,
        }

        let params = match addresses {
            Some(addrs) => serde_json::json!([min_conf, max_conf, addrs]),
            None => serde_json::json!([min_conf, max_conf]),
        };

        let utxos: Vec<RpcUtxo> = self.call("listunspent", params).await?;

        Ok(utxos
            .into_iter()
            .map(|u| Utxo {
                txid: u.txid,
                vout: u.vout,
                script_pub_key: u.scriptPubKey,
                amount_sat: (u.amount * 100_000_000.0) as u64,
                confirmations: u.confirmations,
                spendable: u.spendable,
                address: u.address,
            })
            .collect())
    }

    /// Create raw transaction
    pub async fn create_raw_transaction(
        &self,
        inputs: &[serde_json::Value],
        outputs: &serde_json::Value,
    ) -> P4Result<String> {
        self.call("createrawtransaction", serde_json::json!([inputs, outputs]))
            .await
    }

    /// Sign raw transaction with wallet
    pub async fn sign_raw_transaction_with_wallet(&self, hex: &str) -> P4Result<String> {
        #[derive(Deserialize)]
        struct SignResult {
            hex: String,
            complete: bool,
        }

        let result: SignResult = self
            .call("signrawtransactionwithwallet", serde_json::json!([hex]))
            .await?;

        if !result.complete {
            return Err(P4Error::TransactionSign("Signing incomplete".to_string()));
        }

        Ok(result.hex)
    }

    /// Decode raw transaction
    pub async fn decode_raw_transaction(&self, hex: &str) -> P4Result<serde_json::Value> {
        self.call("decoderawtransaction", serde_json::json!([hex]))
            .await
    }

    /// Get new address from wallet
    pub async fn get_new_address(&self, label: Option<&str>) -> P4Result<String> {
        let params = match label {
            Some(l) => serde_json::json!([l]),
            None => serde_json::json!([]),
        };
        self.call("getnewaddress", params).await
    }

    /// Get wallet balance
    pub async fn get_balance(&self) -> P4Result<f64> {
        self.call("getbalance", serde_json::json!([])).await
    }

    /// Fund raw transaction
    pub async fn fund_raw_transaction(
        &self,
        hex: &str,
        options: Option<serde_json::Value>,
    ) -> P4Result<(String, f64, u32)> {
        #[derive(Deserialize)]
        struct FundResult {
            hex: String,
            fee: f64,
            changepos: i32,
        }

        let params = match options {
            Some(opts) => serde_json::json!([hex, opts]),
            None => serde_json::json!([hex]),
        };

        let result: FundResult = self.call("fundrawtransaction", params).await?;
        Ok((result.hex, result.fee, result.changepos as u32))
    }

    /// Test mempool accept
    pub async fn test_mempool_accept(&self, hex: &str) -> P4Result<bool> {
        #[derive(Deserialize)]
        struct TestResult {
            txid: String,
            allowed: bool,
            #[serde(rename = "reject-reason")]
            reject_reason: Option<String>,
        }

        let results: Vec<TestResult> = self
            .call("testmempoolaccept", serde_json::json!([[hex]]))
            .await?;

        if let Some(result) = results.first() {
            if !result.allowed {
                if let Some(reason) = &result.reject_reason {
                    return Err(P4Error::InvalidTransaction(reason.clone()));
                }
            }
            Ok(result.allowed)
        } else {
            Err(P4Error::RpcRequest("Empty testmempoolaccept response".to_string()))
        }
    }

    /// Get mempool entry
    pub async fn get_mempool_entry(&self, txid: &str) -> P4Result<serde_json::Value> {
        self.call("getmempoolentry", serde_json::json!([txid])).await
    }

    /// Check if transaction is in mempool
    pub async fn is_in_mempool(&self, txid: &str) -> P4Result<bool> {
        match self.get_mempool_entry(txid).await {
            Ok(_) => Ok(true),
            Err(P4Error::RpcResponse { code: -5, .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

/// Create a shared Bitcoin RPC client
pub fn create_bitcoin_client(config: BitcoinRpcConfig) -> P4Result<Arc<BitcoinRpcClient>> {
    Ok(Arc::new(BitcoinRpcClient::new(config)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_config() {
        let config = BitcoinRpcConfig::regtest(
            "http://localhost:18443",
            "user",
            "pass",
        );
        assert_eq!(config.rpc_url(), "http://localhost:18443");
    }

    #[test]
    fn test_rpc_config_with_wallet() {
        let config = BitcoinRpcConfig::regtest(
            "http://localhost:18443",
            "user",
            "pass",
        )
        .with_wallet("l0_wallet");
        assert_eq!(config.rpc_url(), "http://localhost:18443/wallet/l0_wallet");
    }
}
