//! P4 Layer Configuration
//!
//! Configuration for Bitcoin and Atomicals blockchain connections.
//! Supports loading from environment variables with L0_P4_ prefix.

use serde::{Deserialize, Serialize};
use std::env;

/// Bitcoin network type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BitcoinNetwork {
    /// Bitcoin mainnet
    Mainnet,
    /// Bitcoin testnet
    Testnet,
    /// Bitcoin signet
    Signet,
    /// Bitcoin regtest (for development)
    Regtest,
}

impl Default for BitcoinNetwork {
    fn default() -> Self {
        Self::Mainnet
    }
}

impl BitcoinNetwork {
    /// Parse from string (for environment variables)
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "mainnet" | "main" => Some(Self::Mainnet),
            "testnet" | "test" => Some(Self::Testnet),
            "signet" => Some(Self::Signet),
            "regtest" | "reg" => Some(Self::Regtest),
            _ => None,
        }
    }

    /// Get the network magic bytes
    pub fn magic(&self) -> [u8; 4] {
        match self {
            BitcoinNetwork::Mainnet => [0xf9, 0xbe, 0xb4, 0xd9],
            BitcoinNetwork::Testnet => [0x0b, 0x11, 0x09, 0x07],
            BitcoinNetwork::Signet => [0x0a, 0x03, 0xcf, 0x40],
            BitcoinNetwork::Regtest => [0xfa, 0xbf, 0xb5, 0xda],
        }
    }

    /// Get the default port
    pub fn default_port(&self) -> u16 {
        match self {
            BitcoinNetwork::Mainnet => 8332,
            BitcoinNetwork::Testnet => 18332,
            BitcoinNetwork::Signet => 38332,
            BitcoinNetwork::Regtest => 18443,
        }
    }

    /// Get the required confirmations for finality
    pub fn required_confirmations(&self) -> u32 {
        match self {
            BitcoinNetwork::Mainnet => 6,
            BitcoinNetwork::Testnet => 3,
            BitcoinNetwork::Signet => 3,
            BitcoinNetwork::Regtest => 1,
        }
    }
}

/// Bitcoin RPC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinRpcConfig {
    /// RPC endpoint URL
    pub url: String,
    /// RPC username
    pub username: String,
    /// RPC password
    pub password: String,
    /// Network type
    pub network: BitcoinNetwork,
    /// Request timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// Wallet name (for wallet-enabled nodes)
    pub wallet: Option<String>,
}

fn default_timeout() -> u64 {
    30
}

impl Default for BitcoinRpcConfig {
    fn default() -> Self {
        Self {
            url: "http://127.0.0.1:8332".to_string(),
            username: "rpcuser".to_string(),
            password: "rpcpassword".to_string(),
            network: BitcoinNetwork::Mainnet,
            timeout_secs: 30,
            wallet: None,
        }
    }
}

impl BitcoinRpcConfig {
    /// Load configuration from environment variables
    ///
    /// Environment variables:
    /// - L0_P4_BITCOIN_RPC_URL: RPC endpoint URL
    /// - L0_P4_BITCOIN_RPC_USER: RPC username
    /// - L0_P4_BITCOIN_RPC_PASS: RPC password
    /// - L0_P4_BITCOIN_NETWORK: Network type (mainnet/testnet/signet/regtest)
    /// - L0_P4_BITCOIN_RPC_TIMEOUT: Request timeout in seconds
    /// - L0_P4_BITCOIN_WALLET: Wallet name (optional)
    pub fn from_env() -> Self {
        let network = env::var("L0_P4_BITCOIN_NETWORK")
            .ok()
            .and_then(|s| BitcoinNetwork::from_str(&s))
            .unwrap_or(BitcoinNetwork::Testnet);

        let default_port = network.default_port();
        let default_url = format!("http://127.0.0.1:{}", default_port);

        Self {
            url: env::var("L0_P4_BITCOIN_RPC_URL").unwrap_or(default_url),
            username: env::var("L0_P4_BITCOIN_RPC_USER").unwrap_or_default(),
            password: env::var("L0_P4_BITCOIN_RPC_PASS").unwrap_or_default(),
            network,
            timeout_secs: env::var("L0_P4_BITCOIN_RPC_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
            wallet: env::var("L0_P4_BITCOIN_WALLET").ok(),
        }
    }

    /// Create a new configuration for mainnet
    pub fn mainnet(url: &str, username: &str, password: &str) -> Self {
        Self {
            url: url.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            network: BitcoinNetwork::Mainnet,
            timeout_secs: 30,
            wallet: None,
        }
    }

    /// Create a new configuration for testnet
    pub fn testnet(url: &str, username: &str, password: &str) -> Self {
        Self {
            url: url.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            network: BitcoinNetwork::Testnet,
            timeout_secs: 30,
            wallet: None,
        }
    }

    /// Create a new configuration for regtest
    pub fn regtest(url: &str, username: &str, password: &str) -> Self {
        Self {
            url: url.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            network: BitcoinNetwork::Regtest,
            timeout_secs: 30,
            wallet: None,
        }
    }

    /// Set wallet name
    pub fn with_wallet(mut self, wallet: &str) -> Self {
        self.wallet = Some(wallet.to_string());
        self
    }

    /// Get the full RPC URL (including wallet if specified)
    pub fn rpc_url(&self) -> String {
        match &self.wallet {
            Some(wallet) => format!("{}/wallet/{}", self.url, wallet),
            None => self.url.clone(),
        }
    }
}

/// Atomicals protocol configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtomicalsConfig {
    /// Electrum server URL for Atomicals
    pub electrum_url: String,
    /// Atomicals API URL (for indexer)
    pub api_url: Option<String>,
    /// Bitcoin RPC config (Atomicals uses Bitcoin)
    pub bitcoin_rpc: BitcoinRpcConfig,
    /// Default mint bitworkc (mining difficulty)
    #[serde(default = "default_bitworkc")]
    pub default_bitworkc: String,
}

fn default_bitworkc() -> String {
    "1234".to_string()
}

impl Default for AtomicalsConfig {
    fn default() -> Self {
        Self {
            electrum_url: "wss://electrumx.atomicals.xyz:50012".to_string(),
            api_url: Some("https://ep.atomicals.xyz/proxy".to_string()),
            bitcoin_rpc: BitcoinRpcConfig::default(),
            default_bitworkc: "1234".to_string(),
        }
    }
}

/// P4 Layer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P4Config {
    /// Bitcoin RPC configuration
    pub bitcoin: BitcoinRpcConfig,
    /// Atomicals configuration
    pub atomicals: Option<AtomicalsConfig>,
    /// Enable Bitcoin anchoring
    #[serde(default = "default_true")]
    pub enable_bitcoin: bool,
    /// Enable Atomicals anchoring
    #[serde(default)]
    pub enable_atomicals: bool,
    /// Maximum retry attempts
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    /// Retry delay in seconds
    #[serde(default = "default_retry_delay")]
    pub retry_delay_secs: u64,
    /// Confirmation check interval in seconds
    #[serde(default = "default_confirmation_interval")]
    pub confirmation_interval_secs: u64,
    /// Fee rate in satoshis per vbyte
    #[serde(default = "default_fee_rate")]
    pub fee_rate_sat_vb: u64,
    /// Maximum fee in satoshis
    #[serde(default = "default_max_fee")]
    pub max_fee_sat: u64,
    /// Default fee rate (sat/vB) - used when estimation fails
    #[serde(default)]
    pub default_fee_rate: Option<u64>,
    /// Maximum fee rate (sat/vB) - cap on dynamic fee estimation
    #[serde(default)]
    pub max_fee_rate: Option<u64>,
    /// Maximum single transaction fee (satoshis)
    #[serde(default)]
    pub max_single_tx_fee: Option<u64>,
}

fn default_true() -> bool {
    true
}

fn default_max_retries() -> u32 {
    3
}

fn default_retry_delay() -> u64 {
    60
}

fn default_confirmation_interval() -> u64 {
    60
}

fn default_fee_rate() -> u64 {
    10
}

fn default_max_fee() -> u64 {
    100_000 // 0.001 BTC max fee
}

impl Default for P4Config {
    fn default() -> Self {
        Self {
            bitcoin: BitcoinRpcConfig::default(),
            atomicals: None,
            enable_bitcoin: true,
            enable_atomicals: false,
            max_retries: 3,
            retry_delay_secs: 60,
            confirmation_interval_secs: 60,
            fee_rate_sat_vb: 10,
            max_fee_sat: 100_000,
            default_fee_rate: Some(10),
            max_fee_rate: Some(500),
            max_single_tx_fee: Some(100_000),
        }
    }
}

impl P4Config {
    /// Load configuration from environment variables
    ///
    /// Environment variables:
    /// - L0_P4_BITCOIN_ENABLED: Enable Bitcoin anchoring (true/false)
    /// - L0_P4_ATOMICALS_ENABLED: Enable Atomicals anchoring (true/false)
    /// - L0_P4_MAX_RETRIES: Maximum retry attempts
    /// - L0_P4_RETRY_INITIAL_DELAY: Initial retry delay in seconds
    /// - L0_P4_RETRY_MAX_DELAY: Maximum retry delay in seconds
    /// - L0_P4_ANCHOR_FEE_RATE: Fee rate in sat/vB (0 = auto)
    /// - L0_P4_MIN_CONFIRMATIONS: Override minimum confirmations
    ///
    /// Also reads Bitcoin and Atomicals config from their respective env vars.
    pub fn from_env() -> Self {
        let bitcoin = BitcoinRpcConfig::from_env();

        let enable_bitcoin = env::var("L0_P4_BITCOIN_ENABLED")
            .map(|s| s.to_lowercase() == "true" || s == "1")
            .unwrap_or(false);

        let enable_atomicals = env::var("L0_P4_ATOMICALS_ENABLED")
            .map(|s| s.to_lowercase() == "true" || s == "1")
            .unwrap_or(false);

        let atomicals = if enable_atomicals {
            Some(AtomicalsConfig {
                electrum_url: env::var("L0_P4_ATOMICALS_ELECTRUM_URL")
                    .unwrap_or_else(|_| "wss://electrumx.atomicals.xyz:50012".to_string()),
                api_url: env::var("L0_P4_ATOMICALS_API_URL").ok(),
                bitcoin_rpc: bitcoin.clone(),
                default_bitworkc: env::var("L0_P4_ATOMICALS_BITWORKC")
                    .unwrap_or_else(|_| "1234".to_string()),
            })
        } else {
            None
        };

        let fee_rate = env::var("L0_P4_ANCHOR_FEE_RATE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        Self {
            bitcoin,
            atomicals,
            enable_bitcoin,
            enable_atomicals,
            max_retries: env::var("L0_P4_MAX_RETRIES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(3),
            retry_delay_secs: env::var("L0_P4_RETRY_INITIAL_DELAY")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(60),
            confirmation_interval_secs: 60,
            fee_rate_sat_vb: if fee_rate == 0 { 10 } else { fee_rate },
            max_fee_sat: 100_000,
            default_fee_rate: Some(if fee_rate == 0 { 10 } else { fee_rate }),
            max_fee_rate: env::var("L0_P4_MAX_FEE_RATE")
                .ok()
                .and_then(|s| s.parse().ok()),
            max_single_tx_fee: env::var("L0_P4_MAX_SINGLE_TX_FEE")
                .ok()
                .and_then(|s| s.parse().ok()),
        }
    }

    /// Create a development configuration (regtest)
    pub fn development() -> Self {
        Self {
            bitcoin: BitcoinRpcConfig::regtest(
                "http://127.0.0.1:18443",
                "rpcuser",
                "rpcpassword",
            ),
            atomicals: None,
            enable_bitcoin: true,
            enable_atomicals: false,
            max_retries: 3,
            retry_delay_secs: 5,
            confirmation_interval_secs: 5,
            fee_rate_sat_vb: 1,
            max_fee_sat: 10_000,
            default_fee_rate: Some(1),
            max_fee_rate: Some(100),
            max_single_tx_fee: Some(10_000),
        }
    }

    /// Create a testnet configuration
    pub fn testnet(url: &str, username: &str, password: &str) -> Self {
        Self {
            bitcoin: BitcoinRpcConfig::testnet(url, username, password),
            atomicals: None,
            enable_bitcoin: true,
            enable_atomicals: false,
            max_retries: 3,
            retry_delay_secs: 30,
            confirmation_interval_secs: 30,
            fee_rate_sat_vb: 5,
            max_fee_sat: 50_000,
            default_fee_rate: Some(5),
            max_fee_rate: Some(200),
            max_single_tx_fee: Some(50_000),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitcoin_network_defaults() {
        let network = BitcoinNetwork::default();
        assert_eq!(network, BitcoinNetwork::Mainnet);
        assert_eq!(network.required_confirmations(), 6);
        assert_eq!(network.default_port(), 8332);
    }

    #[test]
    fn test_bitcoin_rpc_config() {
        let config = BitcoinRpcConfig::mainnet(
            "http://localhost:8332",
            "user",
            "pass",
        );
        assert_eq!(config.network, BitcoinNetwork::Mainnet);
        assert_eq!(config.rpc_url(), "http://localhost:8332");

        let config_with_wallet = config.with_wallet("l0_wallet");
        assert_eq!(config_with_wallet.rpc_url(), "http://localhost:8332/wallet/l0_wallet");
    }

    #[test]
    fn test_p4_config_defaults() {
        let config = P4Config::default();
        assert!(config.enable_bitcoin);
        assert!(!config.enable_atomicals);
        assert_eq!(config.max_retries, 3);
    }

    #[test]
    fn test_p4_config_development() {
        let config = P4Config::development();
        assert_eq!(config.bitcoin.network, BitcoinNetwork::Regtest);
        assert_eq!(config.retry_delay_secs, 5);
    }
}
