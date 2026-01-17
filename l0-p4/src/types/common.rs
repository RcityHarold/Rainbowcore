//! P4 通用类型定义
//!
//! 包含各模块共享的基础类型。

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// 32字节摘要类型
pub type Digest32 = [u8; 32];

/// 输入ID类型
pub type InputId = Digest32;

/// 作业ID类型
pub type JobId = Digest32;

/// 链接ID类型
pub type LinkId = Digest32;

/// 对账ID类型
pub type ReconcileId = Digest32;

/// 幂等键类型
pub type IdempotencyKey = Digest32;

/// 时间戳类型（Unix毫秒）
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct Timestamp(pub u64);

impl Timestamp {
    /// 获取当前时间戳
    pub fn now() -> Self {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Self(duration.as_millis() as u64)
    }

    /// 从毫秒创建
    pub fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    /// 转换为毫秒
    pub fn as_millis(&self) -> u64 {
        self.0
    }

    /// 是否为零
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// 锚定优先级
///
/// 根据文档第3篇，分级决定"是否入队、优先级、预算承诺"，不决定证据等级。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum AnchorPriority {
    /// 必须锚定（不可丢弃）
    /// - 不能丢弃、不能静默失败
    /// - 只能延迟排队（cap_blocked）或进入 pending_anchor_cost
    /// - 完成定义：必须产生 ChainAnchorLink 并完成对账闭合
    Must = 0,

    /// 应该锚定（可延迟但不可随意丢弃）
    /// - 应当锚定，但允许延迟/降级（必须显性化原因）
    /// - 不得静默跳过：若不锚定必须有记录（SkippedWithReason）
    #[default]
    Should = 1,

    /// 可选锚定（可根据预算情况丢弃）
    /// - 可不锚定；但一旦锚定仍必须遵守闭环
    /// - 不得用来绕开 MUST
    May = 2,
}


impl fmt::Display for AnchorPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Must => write!(f, "MUST"),
            Self::Should => write!(f, "SHOULD"),
            Self::May => write!(f, "MAY"),
        }
    }
}

/// 策略版本
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct PolicyVersion(pub u32);

impl PolicyVersion {
    pub fn new(version: u32) -> Self {
        Self(version)
    }

    pub fn to_bytes(&self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    pub fn from_bytes(bytes: [u8; 4]) -> Self {
        Self(u32::from_be_bytes(bytes))
    }
}

impl fmt::Display for PolicyVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// 规范化版本
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct CanonVersion(pub u32);

impl CanonVersion {
    pub fn new(version: u32) -> Self {
        Self(version)
    }

    pub fn to_bytes(&self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    pub fn from_bytes(bytes: [u8; 4]) -> Self {
        Self(u32::from_be_bytes(bytes))
    }
}

impl fmt::Display for CanonVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "canon_v{}", self.0)
    }
}

/// 目标链类型
///
/// 重新导出 l0-core 的 AnchorChainType，并添加 P4 特有的扩展。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum ChainType {
    /// 比特币主网/测试网
    #[default]
    Bitcoin,
    /// Atomicals 协议（基于比特币）
    Atomicals,
    /// 内部锚定（不上链）
    Internal,
}


impl fmt::Display for ChainType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bitcoin => write!(f, "bitcoin"),
            Self::Atomicals => write!(f, "atomicals"),
            Self::Internal => write!(f, "internal"),
        }
    }
}

/// 生成随机 ID
pub fn generate_random_id() -> Digest32 {
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut hasher = Sha256::new();

    // 使用时间戳和随机数
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    hasher.update(timestamp.to_le_bytes());

    // 添加进程 ID
    hasher.update(std::process::id().to_le_bytes());

    // 添加线程 ID 的哈希
    let thread_id = format!("{:?}", std::thread::current().id());
    hasher.update(thread_id.as_bytes());

    let result = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    id
}

/// 计算摘要
pub fn compute_digest(data: &[u8]) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&result);
    digest
}

/// 将摘要转换为十六进制字符串
pub fn digest_to_hex(digest: &Digest32) -> String {
    hex::encode(digest)
}

/// 从十六进制字符串解析摘要
pub fn digest_from_hex(hex_str: &str) -> Result<Digest32, hex::FromHexError> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 32 {
        return Err(hex::FromHexError::InvalidStringLength);
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&bytes);
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp() {
        let ts = Timestamp::now();
        assert!(!ts.is_zero());
        assert!(ts.as_millis() > 0);
    }

    #[test]
    fn test_anchor_priority_ordering() {
        assert!(AnchorPriority::Must < AnchorPriority::Should);
        assert!(AnchorPriority::Should < AnchorPriority::May);
    }

    #[test]
    fn test_policy_version_bytes() {
        let v = PolicyVersion::new(42);
        let bytes = v.to_bytes();
        let v2 = PolicyVersion::from_bytes(bytes);
        assert_eq!(v, v2);
    }

    #[test]
    fn test_generate_random_id() {
        let id1 = generate_random_id();
        let id2 = generate_random_id();
        // 两次生成的 ID 应该不同
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_digest_hex_roundtrip() {
        let original = [0xab; 32];
        let hex_str = digest_to_hex(&original);
        let parsed = digest_from_hex(&hex_str).unwrap();
        assert_eq!(original, parsed);
    }
}
