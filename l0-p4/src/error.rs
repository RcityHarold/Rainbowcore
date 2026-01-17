//! P4 Layer Error Types
//!
//! Error definitions for blockchain anchoring operations.

use thiserror::Error;

/// P4 Layer Error
#[derive(Error, Debug)]
pub enum P4Error {
    /// Bitcoin RPC connection error
    #[error("Bitcoin RPC connection failed: {0}")]
    RpcConnection(String),

    /// Bitcoin RPC request error
    #[error("Bitcoin RPC request failed: {0}")]
    RpcRequest(String),

    /// Bitcoin RPC response error
    #[error("Bitcoin RPC response error: {message}")]
    RpcResponse { code: i32, message: String },

    /// Transaction building error
    #[error("Transaction build failed: {0}")]
    TransactionBuild(String),

    /// Transaction signing error
    #[error("Transaction signing failed: {0}")]
    TransactionSign(String),

    /// Transaction broadcast error
    #[error("Transaction broadcast failed: {0}")]
    TransactionBroadcast(String),

    /// Transaction not found
    #[error("Transaction not found: {0}")]
    TransactionNotFound(String),

    /// Insufficient funds
    #[error("Insufficient funds: required {required} satoshis, available {available}")]
    InsufficientFunds { required: u64, available: u64 },

    /// Invalid address
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    /// Invalid transaction
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    /// Confirmation timeout
    #[error("Confirmation timeout after {attempts} attempts")]
    ConfirmationTimeout { attempts: u32 },

    /// Atomicals protocol error
    #[error("Atomicals protocol error: {0}")]
    AtomicalsProtocol(String),

    /// Atomicals mint error
    #[error("Atomicals mint failed: {0}")]
    AtomicalsMint(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Network error
    #[error("Network error: {0}")]
    Network(String),

    /// Retry exhausted
    #[error("Retry exhausted after {attempts} attempts: {last_error}")]
    RetryExhausted { attempts: u32, last_error: String },

    /// Chain not supported
    #[error("Chain not supported: {0}")]
    ChainNotSupported(String),

    /// Invalid epoch root
    #[error("Invalid epoch root: {0}")]
    InvalidEpochRoot(String),

    /// Invalid input
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Storage error
    #[error("Storage error: {0}")]
    Storage(String),

    /// State transition error
    #[error("State transition error: {0}")]
    StateTransition(String),

    /// Cap exhausted (budget insufficient)
    #[error("Cap exhausted: required {required} satoshis, available {available}")]
    CapExhausted { required: u64, available: u64 },

    /// Budget reservation failed
    #[error("Budget reservation failed: {0}")]
    BudgetReservationFailed(String),

    /// Budget already reserved for this job
    #[error("Budget already reserved for job: {0}")]
    BudgetAlreadyReserved(String),

    /// Budget entry not found
    #[error("Budget entry not found: {0}")]
    BudgetEntryNotFound(String),

    /// Budget operation failed
    #[error("Budget operation failed: {0}")]
    BudgetOperationFailed(String),

    /// Verification failed
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    /// Merkle proof invalid
    #[error("Merkle proof invalid: {0}")]
    MerkleProofInvalid(String),

    /// Fake endorsement detected
    #[error("Fake endorsement detected: {0}")]
    FakeEndorsementDetected(String),

    /// Link verification failed
    #[error("Link verification failed: {0}")]
    LinkVerificationFailed(String),

    /// DSN unavailable
    #[error("DSN unavailable: {0}")]
    DsnUnavailable(String),

    /// L0 unavailable
    #[error("L0 unavailable: {0}")]
    L0Unavailable(String),

    /// Econ unavailable
    #[error("Economic system unavailable: {0}")]
    EconUnavailable(String),

    /// Epoch not found
    #[error("Epoch not found: sequence {0}")]
    EpochNotFound(u64),

    /// Budget insufficient
    #[error("Budget insufficient: required {required} satoshis, available {available}")]
    BudgetInsufficient { required: u64, available: u64 },
}

/// P4 错误码注册表
///
/// 提供标准化的错误码，便于日志分析和监控。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum P4ErrorCode {
    // 1xxx: 输入错误
    /// 无效输入
    InvalidInput = 1001,
    /// 无效 epoch root
    InvalidEpochRoot = 1002,
    /// 幂等键冲突
    IdempotencyConflict = 1003,
    /// 无效优先级
    InvalidPriority = 1004,
    /// Epoch 未找到
    EpochNotFound = 1005,

    // 2xxx: 执行错误
    /// 交易构建失败
    TransactionBuildFailed = 2001,
    /// 交易签名失败
    TransactionSignFailed = 2002,
    /// 交易被拒绝
    TransactionRejected = 2003,
    /// 手续费不足
    InsufficientFee = 2004,
    /// 交易广播失败
    TransactionBroadcastFailed = 2005,
    /// 确认超时
    ConfirmationTimeout = 2006,

    // 3xxx: Cap 错误
    /// 预算耗尽
    CapExhausted = 3001,
    /// 预算预留失败
    BudgetReservationFailed = 3002,
    /// 预算已预留
    BudgetAlreadyReserved = 3003,
    /// 预算条目未找到
    BudgetEntryNotFound = 3004,
    /// 预算不足
    BudgetInsufficient = 3005,

    // 4xxx: 降级错误
    /// DSN 不可用
    DsnUnavailable = 4001,
    /// L0 不可用
    L0Unavailable = 4002,
    /// 经济系统不可用
    EconUnavailable = 4003,
    /// Bitcoin 节点不可用
    BitcoinUnavailable = 4004,

    // 5xxx: 验证错误
    /// Link 验证失败
    LinkVerificationFailed = 5001,
    /// Merkle 证明无效
    MerkleProofInvalid = 5002,
    /// 检测到伪背书
    FakeEndorsementDetected = 5003,
    /// 确认数不足
    InsufficientConfirmations = 5004,
    /// epoch_root 不匹配
    EpochRootMismatch = 5005,

    // 6xxx: 内部错误
    /// 存储错误
    StorageError = 6001,
    /// RPC 连接失败
    RpcConnectionFailed = 6002,
    /// 序列化错误
    SerializationError = 6003,
    /// 状态转换错误
    StateTransitionError = 6004,

    // 9xxx: 未知错误
    /// 未知错误
    Unknown = 9999,
}

impl P4ErrorCode {
    /// 获取错误码数值
    pub fn code(&self) -> u32 {
        *self as u32
    }

    /// 获取错误类别
    pub fn category(&self) -> ErrorCategory {
        match self.code() {
            1000..=1999 => ErrorCategory::Input,
            2000..=2999 => ErrorCategory::Execution,
            3000..=3999 => ErrorCategory::Cap,
            4000..=4999 => ErrorCategory::Degradation,
            5000..=5999 => ErrorCategory::Verification,
            6000..=6999 => ErrorCategory::Internal,
            _ => ErrorCategory::Unknown,
        }
    }

    /// 是否可重试
    pub fn is_retriable(&self) -> bool {
        matches!(
            self,
            Self::TransactionBroadcastFailed
                | Self::ConfirmationTimeout
                | Self::DsnUnavailable
                | Self::L0Unavailable
                | Self::BitcoinUnavailable
                | Self::RpcConnectionFailed
        )
    }

    /// 获取推荐的重试延迟（毫秒）
    pub fn suggested_retry_delay_ms(&self) -> Option<u64> {
        if self.is_retriable() {
            Some(match self {
                Self::TransactionBroadcastFailed => 30_000,
                Self::ConfirmationTimeout => 60_000,
                Self::DsnUnavailable => 10_000,
                Self::L0Unavailable => 5_000,
                Self::BitcoinUnavailable => 15_000,
                Self::RpcConnectionFailed => 5_000,
                _ => 10_000,
            })
        } else {
            None
        }
    }
}

impl std::fmt::Display for P4ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "P4-{:04}", self.code())
    }
}

/// 错误类别
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    /// 输入错误
    Input,
    /// 执行错误
    Execution,
    /// Cap 错误
    Cap,
    /// 降级错误
    Degradation,
    /// 验证错误
    Verification,
    /// 内部错误
    Internal,
    /// 未知错误
    Unknown,
}

impl std::fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Input => write!(f, "INPUT"),
            Self::Execution => write!(f, "EXECUTION"),
            Self::Cap => write!(f, "CAP"),
            Self::Degradation => write!(f, "DEGRADATION"),
            Self::Verification => write!(f, "VERIFICATION"),
            Self::Internal => write!(f, "INTERNAL"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

impl P4Error {
    /// 获取对应的错误码
    pub fn error_code(&self) -> P4ErrorCode {
        match self {
            Self::InvalidInput(_) => P4ErrorCode::InvalidInput,
            Self::InvalidEpochRoot(_) => P4ErrorCode::InvalidEpochRoot,
            Self::TransactionBuild(_) => P4ErrorCode::TransactionBuildFailed,
            Self::TransactionSign(_) => P4ErrorCode::TransactionSignFailed,
            Self::TransactionBroadcast(_) => P4ErrorCode::TransactionBroadcastFailed,
            Self::ConfirmationTimeout { .. } => P4ErrorCode::ConfirmationTimeout,
            Self::InsufficientFunds { .. } => P4ErrorCode::InsufficientFee,
            Self::CapExhausted { .. } => P4ErrorCode::CapExhausted,
            Self::BudgetReservationFailed(_) => P4ErrorCode::BudgetReservationFailed,
            Self::BudgetAlreadyReserved(_) => P4ErrorCode::BudgetAlreadyReserved,
            Self::BudgetEntryNotFound(_) => P4ErrorCode::BudgetEntryNotFound,
            Self::BudgetInsufficient { .. } => P4ErrorCode::BudgetInsufficient,
            Self::DsnUnavailable(_) => P4ErrorCode::DsnUnavailable,
            Self::L0Unavailable(_) => P4ErrorCode::L0Unavailable,
            Self::EconUnavailable(_) => P4ErrorCode::EconUnavailable,
            Self::EpochNotFound(_) => P4ErrorCode::EpochNotFound,
            Self::LinkVerificationFailed(_) => P4ErrorCode::LinkVerificationFailed,
            Self::MerkleProofInvalid(_) => P4ErrorCode::MerkleProofInvalid,
            Self::FakeEndorsementDetected(_) => P4ErrorCode::FakeEndorsementDetected,
            Self::Storage(_) => P4ErrorCode::StorageError,
            Self::RpcConnection(_) => P4ErrorCode::RpcConnectionFailed,
            Self::Serialization(_) => P4ErrorCode::SerializationError,
            Self::StateTransition(_) => P4ErrorCode::StateTransitionError,
            _ => P4ErrorCode::Unknown,
        }
    }

    /// 是否可重试
    pub fn is_retriable(&self) -> bool {
        self.error_code().is_retriable()
    }

    /// 获取推荐的重试延迟
    pub fn suggested_retry_delay_ms(&self) -> Option<u64> {
        self.error_code().suggested_retry_delay_ms()
    }
}

/// P4 Result type
pub type P4Result<T> = Result<T, P4Error>;

impl From<reqwest::Error> for P4Error {
    fn from(e: reqwest::Error) -> Self {
        P4Error::Network(e.to_string())
    }
}

impl From<serde_json::Error> for P4Error {
    fn from(e: serde_json::Error) -> Self {
        P4Error::Serialization(e.to_string())
    }
}

impl From<hex::FromHexError> for P4Error {
    fn from(e: hex::FromHexError) -> Self {
        P4Error::Serialization(format!("Hex decode error: {}", e))
    }
}
