//! Treasury Entity

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use soulbase_storage::model::Entity;
use soulbase_types::prelude::TenantId;

/// Treasury pool type
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TreasuryPoolType {
    /// Infrastructure pool
    Infra,
    /// Civilization pool
    Civilization,
    /// Reward pool
    Reward,
}

impl std::fmt::Display for TreasuryPoolType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Infra => write!(f, "infra"),
            Self::Civilization => write!(f, "civilization"),
            Self::Reward => write!(f, "reward"),
        }
    }
}

/// Treasury pool entity
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreasuryPoolEntity {
    /// Entity ID
    pub id: String,
    /// Tenant ID
    pub tenant_id: TenantId,
    /// Pool type
    pub pool_type: TreasuryPoolType,
    /// Balance digest (zero-plaintext)
    pub balance_digest: String,
    /// Currency
    pub currency: String,
    /// Last updated epoch
    pub last_updated_epoch: String,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Updated at
    pub updated_at: DateTime<Utc>,
}

impl Entity for TreasuryPoolEntity {
    const TABLE: &'static str = "p3_treasury_pool";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}

impl TreasuryPoolEntity {
    /// Create a new treasury pool entity
    pub fn new(tenant_id: TenantId, pool_type: TreasuryPoolType, currency: impl Into<String>) -> Self {
        let now = Utc::now();
        let id = format!("{}:{}:{}", Self::TABLE, tenant_id.0, pool_type);
        Self {
            id,
            tenant_id,
            pool_type,
            balance_digest: String::new(),
            currency: currency.into(),
            last_updated_epoch: String::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Update balance digest
    pub fn update_balance(&mut self, digest: impl Into<String>, epoch_id: impl Into<String>) {
        self.balance_digest = digest.into();
        self.last_updated_epoch = epoch_id.into();
        self.updated_at = Utc::now();
    }
}

/// Treasury transaction type
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TreasuryTxType {
    /// Deposit into pool
    Deposit,
    /// Withdraw from pool
    Withdraw,
    /// Transfer between pools
    Transfer,
    /// Distribution to actors
    Distribution,
}

impl std::fmt::Display for TreasuryTxType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Deposit => write!(f, "deposit"),
            Self::Withdraw => write!(f, "withdraw"),
            Self::Transfer => write!(f, "transfer"),
            Self::Distribution => write!(f, "distribution"),
        }
    }
}

/// Treasury transaction entity
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreasuryTxEntity {
    /// Entity ID
    pub id: String,
    /// Tenant ID
    pub tenant_id: TenantId,
    /// Transaction ID
    pub tx_id: String,
    /// Epoch ID
    pub epoch_id: String,
    /// Pool type
    pub pool_type: TreasuryPoolType,
    /// Transaction type
    pub tx_type: TreasuryTxType,
    /// Amount digest (zero-plaintext)
    pub amount_digest: String,
    /// Currency
    pub currency: String,
    /// Counterparty reference
    pub counterparty_ref: Option<String>,
    /// Reason code
    pub reason_code: String,
    /// Created at
    pub created_at: DateTime<Utc>,
}

impl Entity for TreasuryTxEntity {
    const TABLE: &'static str = "p3_treasury_tx";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}

impl TreasuryTxEntity {
    /// Create a new treasury transaction entity
    pub fn new(
        tenant_id: TenantId,
        tx_id: impl Into<String>,
        epoch_id: impl Into<String>,
        pool_type: TreasuryPoolType,
        tx_type: TreasuryTxType,
    ) -> Self {
        let now = Utc::now();
        let tid = tx_id.into();
        let id = format!("{}:{}:{}", Self::TABLE, tenant_id.0, tid);
        Self {
            id,
            tenant_id,
            tx_id: tid,
            epoch_id: epoch_id.into(),
            pool_type,
            tx_type,
            amount_digest: String::new(),
            currency: "USD".to_string(),
            counterparty_ref: None,
            reason_code: String::new(),
            created_at: now,
        }
    }

    /// Set amount digest
    pub fn with_amount_digest(mut self, digest: impl Into<String>) -> Self {
        self.amount_digest = digest.into();
        self
    }

    /// Set reason code
    pub fn with_reason_code(mut self, code: impl Into<String>) -> Self {
        self.reason_code = code.into();
        self
    }
}

/// Fee schedule entity
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeScheduleEntity {
    /// Entity ID
    pub id: String,
    /// Tenant ID
    pub tenant_id: TenantId,
    /// Schedule ID
    pub schedule_id: String,
    /// Version
    pub version: i32,
    /// Schedule digest
    pub schedule_digest: String,
    /// Effective from
    pub effective_from: DateTime<Utc>,
    /// Effective until
    pub effective_until: Option<DateTime<Utc>>,
    /// Pool ratios JSON
    pub pool_ratios_json: String,
    /// Created at
    pub created_at: DateTime<Utc>,
}

impl Entity for FeeScheduleEntity {
    const TABLE: &'static str = "p3_fee_schedule";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}

impl FeeScheduleEntity {
    /// Create a new fee schedule entity
    pub fn new(tenant_id: TenantId, schedule_id: impl Into<String>, version: i32) -> Self {
        let now = Utc::now();
        let sid = schedule_id.into();
        let id = format!("{}:{}:{}:v{}", Self::TABLE, tenant_id.0, sid, version);
        Self {
            id,
            tenant_id,
            schedule_id: sid,
            version,
            schedule_digest: String::new(),
            effective_from: now,
            effective_until: None,
            pool_ratios_json: "{}".to_string(),
            created_at: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_tenant() -> TenantId {
        TenantId("test".to_string())
    }

    #[test]
    fn test_treasury_pool_entity() {
        let entity = TreasuryPoolEntity::new(test_tenant(), TreasuryPoolType::Infra, "USD");
        assert_eq!(entity.pool_type, TreasuryPoolType::Infra);
        assert_eq!(entity.currency, "USD");
    }

    #[test]
    fn test_treasury_tx_entity() {
        let entity = TreasuryTxEntity::new(
            test_tenant(),
            "tx:001",
            "epoch:001",
            TreasuryPoolType::Reward,
            TreasuryTxType::Distribution,
        );
        assert_eq!(entity.tx_id, "tx:001");
        assert_eq!(entity.tx_type, TreasuryTxType::Distribution);
    }
}
