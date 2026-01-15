//! Points Repository

use async_trait::async_trait;
use rust_decimal::Decimal;
use crate::entities::{PointsBalanceEntity, PointsHistoryEntity, PointType};
use crate::error::{P3StoreError, P3StoreResult};

/// Points balance repository trait
#[async_trait]
pub trait PointsBalanceRepository: Send + Sync {
    /// Create or update points balance
    async fn upsert(&self, entity: PointsBalanceEntity) -> P3StoreResult<PointsBalanceEntity>;

    /// Get points balance for actor and type
    async fn get(
        &self,
        actor_id: &str,
        point_type: PointType,
    ) -> P3StoreResult<Option<PointsBalanceEntity>>;

    /// Get all balances for actor
    async fn get_all_for_actor(&self, actor_id: &str) -> P3StoreResult<Vec<PointsBalanceEntity>>;

    /// Add to balance
    async fn add_balance(
        &self,
        actor_id: &str,
        point_type: PointType,
        amount: Decimal,
        epoch_id: &str,
    ) -> P3StoreResult<PointsBalanceEntity>;

    /// Subtract from balance
    async fn subtract_balance(
        &self,
        actor_id: &str,
        point_type: PointType,
        amount: Decimal,
        epoch_id: &str,
    ) -> P3StoreResult<PointsBalanceEntity>;

    /// Get total balance of a point type across all actors
    async fn get_total_balance(&self, point_type: PointType) -> P3StoreResult<Decimal>;
}

/// Points history repository trait
#[async_trait]
pub trait PointsHistoryRepository: Send + Sync {
    /// Create history entry
    async fn create(&self, entity: PointsHistoryEntity) -> P3StoreResult<PointsHistoryEntity>;

    /// Get history for actor
    async fn get_for_actor(
        &self,
        actor_id: &str,
        limit: usize,
    ) -> P3StoreResult<Vec<PointsHistoryEntity>>;

    /// Get history for actor and point type
    async fn get_for_actor_and_type(
        &self,
        actor_id: &str,
        point_type: PointType,
        limit: usize,
    ) -> P3StoreResult<Vec<PointsHistoryEntity>>;

    /// Get history for epoch
    async fn get_for_epoch(&self, epoch_id: &str) -> P3StoreResult<Vec<PointsHistoryEntity>>;

    /// Get history for actor in epoch
    async fn get_for_actor_in_epoch(
        &self,
        actor_id: &str,
        epoch_id: &str,
    ) -> P3StoreResult<Vec<PointsHistoryEntity>>;
}

/// Combined points service for transactional operations
#[async_trait]
pub trait PointsService: Send + Sync {
    /// Award points to an actor (creates history entry)
    async fn award_points(
        &self,
        actor_id: &str,
        point_type: PointType,
        amount: Decimal,
        epoch_id: &str,
        reason_code: &str,
        reason_ref: Option<&str>,
    ) -> P3StoreResult<PointsBalanceEntity>;

    /// Deduct points from an actor (creates history entry)
    async fn deduct_points(
        &self,
        actor_id: &str,
        point_type: PointType,
        amount: Decimal,
        epoch_id: &str,
        reason_code: &str,
        reason_ref: Option<&str>,
    ) -> P3StoreResult<PointsBalanceEntity>;

    /// Transfer points between actors
    async fn transfer_points(
        &self,
        from_actor: &str,
        to_actor: &str,
        point_type: PointType,
        amount: Decimal,
        epoch_id: &str,
        reason_code: &str,
    ) -> P3StoreResult<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Repository trait tests would go here with mock implementations
}
