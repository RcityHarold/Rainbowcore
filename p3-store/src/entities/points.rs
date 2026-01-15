//! Points Entity

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use soulbase_storage::model::Entity;
use soulbase_types::prelude::TenantId;

/// Point type
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PointType {
    /// Actor Contribution Points
    ACP,
    /// Civilization Tax Points
    CTP,
    /// Governance Token Points
    GTP,
}

impl std::fmt::Display for PointType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ACP => write!(f, "ACP"),
            Self::CTP => write!(f, "CTP"),
            Self::GTP => write!(f, "GTP"),
        }
    }
}

/// Points balance entity
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PointsBalanceEntity {
    /// Entity ID
    pub id: String,
    /// Tenant ID
    pub tenant_id: TenantId,
    /// Actor ID
    pub actor_id: String,
    /// Point type
    pub point_type: PointType,
    /// Balance (stored as string for precision)
    pub balance: String,
    /// Last updated epoch
    pub last_updated_epoch: String,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Updated at
    pub updated_at: DateTime<Utc>,
}

impl Entity for PointsBalanceEntity {
    const TABLE: &'static str = "p3_points_balance";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}

impl PointsBalanceEntity {
    /// Create a new points balance entity
    pub fn new(tenant_id: TenantId, actor_id: impl Into<String>, point_type: PointType) -> Self {
        let now = Utc::now();
        let aid = actor_id.into();
        let id = format!("{}:{}:{}:{}", Self::TABLE, tenant_id.0, aid, point_type);
        Self {
            id,
            tenant_id,
            actor_id: aid,
            point_type,
            balance: "0".to_string(),
            last_updated_epoch: String::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Get balance as Decimal
    pub fn balance_decimal(&self) -> Decimal {
        self.balance.parse().unwrap_or(Decimal::ZERO)
    }

    /// Set balance
    pub fn with_balance(mut self, balance: Decimal) -> Self {
        self.balance = balance.to_string();
        self.updated_at = Utc::now();
        self
    }

    /// Add to balance
    pub fn add(&mut self, amount: Decimal, epoch_id: &str) {
        let current = self.balance_decimal();
        self.balance = (current + amount).to_string();
        self.last_updated_epoch = epoch_id.to_string();
        self.updated_at = Utc::now();
    }

    /// Subtract from balance
    pub fn subtract(&mut self, amount: Decimal, epoch_id: &str) -> bool {
        let current = self.balance_decimal();
        if current < amount {
            return false;
        }
        self.balance = (current - amount).to_string();
        self.last_updated_epoch = epoch_id.to_string();
        self.updated_at = Utc::now();
        true
    }
}

/// Points history entity
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PointsHistoryEntity {
    /// Entity ID
    pub id: String,
    /// Tenant ID
    pub tenant_id: TenantId,
    /// Actor ID
    pub actor_id: String,
    /// Point type
    pub point_type: PointType,
    /// Epoch ID
    pub epoch_id: String,
    /// Delta (change amount, stored as string)
    pub delta: String,
    /// Reason code
    pub reason_code: String,
    /// Reason reference
    pub reason_ref: Option<String>,
    /// Balance after
    pub balance_after: String,
    /// Created at
    pub created_at: DateTime<Utc>,
}

impl Entity for PointsHistoryEntity {
    const TABLE: &'static str = "p3_points_history";

    fn id(&self) -> &str {
        &self.id
    }

    fn tenant(&self) -> &TenantId {
        &self.tenant_id
    }
}

impl PointsHistoryEntity {
    /// Create a new points history entity
    pub fn new(
        tenant_id: TenantId,
        actor_id: impl Into<String>,
        point_type: PointType,
        epoch_id: impl Into<String>,
        delta: Decimal,
        reason_code: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        let aid = actor_id.into();
        let eid = epoch_id.into();
        let id = format!("{}:{}:{}:{}:{}:{}", Self::TABLE, tenant_id.0, aid, point_type, eid, now.timestamp_nanos_opt().unwrap_or(0));
        Self {
            id,
            tenant_id,
            actor_id: aid,
            point_type,
            epoch_id: eid,
            delta: delta.to_string(),
            reason_code: reason_code.into(),
            reason_ref: None,
            balance_after: "0".to_string(),
            created_at: now,
        }
    }

    /// Set balance after
    pub fn with_balance_after(mut self, balance: Decimal) -> Self {
        self.balance_after = balance.to_string();
        self
    }

    /// Set reason reference
    pub fn with_reason_ref(mut self, reason_ref: impl Into<String>) -> Self {
        self.reason_ref = Some(reason_ref.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_tenant() -> TenantId {
        TenantId("test".to_string())
    }

    #[test]
    fn test_points_balance_entity() {
        let entity = PointsBalanceEntity::new(test_tenant(), "actor:001", PointType::ACP);
        assert_eq!(entity.actor_id, "actor:001");
        assert_eq!(entity.point_type, PointType::ACP);
        assert_eq!(entity.balance_decimal(), Decimal::ZERO);
    }

    #[test]
    fn test_points_balance_operations() {
        let mut entity = PointsBalanceEntity::new(test_tenant(), "actor:001", PointType::ACP);

        entity.add(Decimal::new(100, 0), "epoch:001");
        assert_eq!(entity.balance_decimal(), Decimal::new(100, 0));

        let success = entity.subtract(Decimal::new(30, 0), "epoch:002");
        assert!(success);
        assert_eq!(entity.balance_decimal(), Decimal::new(70, 0));

        let fail = entity.subtract(Decimal::new(100, 0), "epoch:003");
        assert!(!fail);
        assert_eq!(entity.balance_decimal(), Decimal::new(70, 0));
    }

    #[test]
    fn test_points_history_entity() {
        let entity = PointsHistoryEntity::new(
            test_tenant(),
            "actor:001",
            PointType::CTP,
            "epoch:001",
            Decimal::new(50, 0),
            "contribution",
        );
        assert_eq!(entity.actor_id, "actor:001");
        assert_eq!(entity.delta, "50");
    }
}
