//! P3 Basic Types
//!
//! Naming conventions:
//! - `_id` suffix: Primary key identifiers
//! - `_ref` suffix: References or foreign keys
//! - `_digest` suffix: Cryptographic digests

use crate::error::{P3Error, P3Result};
use l0_core::types::Digest as L0Digest;
use serde::{Deserialize, Serialize};

// ============================================================
// Basic Digest Types (newtype pattern, non-interchangeable)
// ============================================================

/// P3 Digest type (32 bytes)
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct P3Digest(pub [u8; 32]);

impl P3Digest {
    /// Create from hex string
    pub fn from_hex(s: &str) -> P3Result<Self> {
        let bytes = hex::decode(s).map_err(|_| P3Error::InvalidDigest)?;
        if bytes.len() != 32 {
            return Err(P3Error::InvalidDigest);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// BLAKE3 hash
    pub fn blake3(data: &[u8]) -> Self {
        let hash = blake3::hash(data);
        Self(*hash.as_bytes())
    }

    /// Create zero digest
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Check if empty set digest
    pub fn is_empty_set(&self) -> bool {
        self.0 == EMPTY_SET_DIGEST
    }

    /// Check if zero
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// From L0Digest
    pub fn from_l0(digest: &L0Digest) -> Self {
        Self(*digest.as_bytes())
    }

    /// To L0Digest
    pub fn to_l0(&self) -> L0Digest {
        L0Digest::new(self.0)
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Combine two digests (for Merkle tree)
    pub fn combine(left: &Self, right: &Self) -> Self {
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(&left.0);
        combined.extend_from_slice(&right.0);
        Self::blake3(&combined)
    }
}

impl std::fmt::Debug for P3Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "P3Digest({}...)", &self.to_hex()[..16])
    }
}

impl std::fmt::Display for P3Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Default for P3Digest {
    fn default() -> Self {
        Self::zero()
    }
}

/// Set digest (for four sets)
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SetDigest(pub P3Digest);

impl SetDigest {
    pub fn new(digest: P3Digest) -> Self {
        Self(digest)
    }

    pub fn empty() -> Self {
        Self(P3Digest::zero())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_zero()
    }
}

/// Reference set digest
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RefDigest(pub P3Digest);

impl RefDigest {
    pub fn new(digest: P3Digest) -> Self {
        Self(digest)
    }

    pub fn empty() -> Self {
        Self(P3Digest::zero())
    }
}

/// Money digest (zero plaintext)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneyDigest {
    pub amount_digest: P3Digest,
    pub currency: String,
}

impl MoneyDigest {
    pub fn new(amount_digest: P3Digest, currency: impl Into<String>) -> Self {
        Self {
            amount_digest,
            currency: currency.into(),
        }
    }
}

/// Points digest
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PointsDigest(pub P3Digest);

// ============================================================
// ID Types
// ============================================================

/// Epoch ID
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EpochId(pub String);

impl EpochId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for EpochId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Event ID
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventId(pub String);

impl EventId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Pending ID
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PendingId(pub String);

impl PendingId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Attempt Chain ID
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AttemptChainId(pub String);

impl AttemptChainId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Provider ID
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProviderId(pub String);

impl ProviderId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

/// Distribution ID
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DistributionId(pub String);

impl DistributionId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

/// Idempotency Key
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdempotencyKey(pub String);

impl IdempotencyKey {
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }

    pub fn generate() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Version ID (for governance versioning)
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VersionId(pub String);

impl VersionId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ============================================================
// Version Types
// ============================================================

/// Canonicalization version
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonVersion(pub String);

impl CanonVersion {
    pub fn new(version: impl Into<String>) -> Self {
        Self(version.into())
    }

    pub fn v1() -> Self {
        Self("v1".to_string())
    }
}

impl Default for CanonVersion {
    fn default() -> Self {
        Self::v1()
    }
}

/// Error code version
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorCodeVersion(pub String);

impl ErrorCodeVersion {
    pub fn new(version: impl Into<String>) -> Self {
        Self(version.into())
    }

    pub fn v1() -> Self {
        Self("v1".to_string())
    }
}

// ============================================================
// Core Enums
// ============================================================

/// Evidence level
#[derive(Clone, Debug, PartialEq, Eq, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLevel {
    /// A = receipt-backed + payload_map_commit reconcilable
    A,
    /// B = missing payload_map_commit
    B,
    /// Pending evidence
    Pending,
}

impl Default for EvidenceLevel {
    fn default() -> Self {
        Self::B
    }
}

/// Strong economic action (v1 minimal set)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrongEconomicAction {
    /// Final clawback/recovery
    FinalClawbackExecute,
    /// Final reward payout
    FinalRewardPayout,
    /// Permanent deposit forfeit
    PermanentDepositForfeit,
    /// Irreversible account freeze
    IrreversibleAccountFreeze,
    /// Historic result mutation (prohibited overwrite, only append chain allowed)
    HistoricResultMutation,
}

impl StrongEconomicAction {
    /// Get action name for error messages
    pub fn name(&self) -> &'static str {
        match self {
            StrongEconomicAction::FinalClawbackExecute => "FinalClawbackExecute",
            StrongEconomicAction::FinalRewardPayout => "FinalRewardPayout",
            StrongEconomicAction::PermanentDepositForfeit => "PermanentDepositForfeit",
            StrongEconomicAction::IrreversibleAccountFreeze => "IrreversibleAccountFreeze",
            StrongEconomicAction::HistoricResultMutation => "HistoricResultMutation",
        }
    }
}

/// Pending type
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingKind {
    /// Evidence missing
    Evidence,
    /// Execution incomplete
    Execution,
    /// Budget insufficient
    Budget,
    /// Appeal period
    Appeal,
    /// Unknown version
    Version,
}

/// Degraded flag indicating system degradation conditions
///
/// Core flags (from Chapter 7 specification):
/// - DsnDown: DSN network unavailable
/// - L0Down: L0 layer unavailable
/// - EconDown: Economy executor unavailable
/// - AnchorCap: Chain anchor budget cap reached
///
/// Implementation extensions (for runtime version management):
/// - VersionDrift: Version drift detected between components
/// - UnknownVersion: Reference to unknown/unregistered version
///
/// When any degraded flag is set, strong economic actions (StrongAction) are blocked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradedFlag {
    // --- Core flags (Chapter 7 specification) ---
    /// DSN network unavailable - blocks all DSN-dependent operations
    DsnDown,
    /// L0 layer unavailable - blocks L0-dependent operations
    L0Down,
    /// Economy executor unavailable - blocks economic execution
    EconDown,
    /// Chain anchor budget cap reached - blocks new anchor operations
    AnchorCap,

    // --- Implementation extensions ---
    /// Version drift detected between components (implementation extension)
    /// Used when component versions are out of sync
    VersionDrift,
    /// Reference to unknown/unregistered version (implementation extension)
    /// Used when an operation references a version not in the registry
    UnknownVersion,
}

impl DegradedFlag {
    /// Get flag name for error messages
    pub fn name(&self) -> &'static str {
        match self {
            DegradedFlag::DsnDown => "DsnDown",
            DegradedFlag::L0Down => "L0Down",
            DegradedFlag::EconDown => "EconDown",
            DegradedFlag::AnchorCap => "AnchorCap",
            DegradedFlag::VersionDrift => "VersionDrift",
            DegradedFlag::UnknownVersion => "UnknownVersion",
        }
    }

    /// Check if this is a core flag (defined in specification)
    pub fn is_core_flag(&self) -> bool {
        matches!(
            self,
            DegradedFlag::DsnDown
                | DegradedFlag::L0Down
                | DegradedFlag::EconDown
                | DegradedFlag::AnchorCap
        )
    }

    /// Check if this is an implementation extension flag
    pub fn is_extension_flag(&self) -> bool {
        !self.is_core_flag()
    }

    /// Get all core flags (specification defined)
    pub fn core_flags() -> Vec<DegradedFlag> {
        vec![
            DegradedFlag::DsnDown,
            DegradedFlag::L0Down,
            DegradedFlag::EconDown,
            DegradedFlag::AnchorCap,
        ]
    }

    /// Get all flags including extensions
    pub fn all_flags() -> Vec<DegradedFlag> {
        vec![
            DegradedFlag::DsnDown,
            DegradedFlag::L0Down,
            DegradedFlag::EconDown,
            DegradedFlag::AnchorCap,
            DegradedFlag::VersionDrift,
            DegradedFlag::UnknownVersion,
        ]
    }

    /// Get description for this flag
    pub fn description(&self) -> &'static str {
        match self {
            DegradedFlag::DsnDown => "DSN network is unavailable",
            DegradedFlag::L0Down => "L0 layer is unavailable",
            DegradedFlag::EconDown => "Economy executor is unavailable",
            DegradedFlag::AnchorCap => "Chain anchor budget cap reached",
            DegradedFlag::VersionDrift => "Version drift detected between components",
            DegradedFlag::UnknownVersion => "Reference to unknown version",
        }
    }
}

/// Deposit status
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepositStatus {
    Created,
    Locked,
    Refund,
    Forfeit,
    Resolved,
    PendingExecution,
}

/// Execution status
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Pending,
    Executed,
    Resolved,
    Escalated,
}

// ============================================================
// Empty Set Constant
// ============================================================

/// Empty set digest (fixed value)
pub const EMPTY_SET_DIGEST: [u8; 32] = [0u8; 32];

// ============================================================
// Re-exports from L0 for convenience
// ============================================================

// Re-export L0 types directly (not via use statement)
// These are re-exported in the types/mod.rs with proper visibility

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p3_digest_hex_roundtrip() {
        let original = P3Digest::blake3(b"test data");
        let hex = original.to_hex();
        let parsed = P3Digest::from_hex(&hex).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_p3_digest_zero() {
        let zero = P3Digest::zero();
        assert!(zero.is_zero());
        assert!(zero.is_empty_set());
    }

    #[test]
    fn test_epoch_id_creation() {
        let id = EpochId::new("epoch:2024:001");
        assert_eq!(id.as_str(), "epoch:2024:001");
    }

    #[test]
    fn test_idempotency_key_generate() {
        let key1 = IdempotencyKey::generate();
        let key2 = IdempotencyKey::generate();
        assert_ne!(key1.as_str(), key2.as_str());
    }
}
