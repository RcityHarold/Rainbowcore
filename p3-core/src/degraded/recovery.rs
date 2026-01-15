//! Degraded Mode Recovery
//!
//! Handles recovery from degraded mode.

use super::{
    DegradedModeDetector, RecoveryCondition, RecoveryConditionType,
    RecoveryAction, RecoveryActionType, RecoveryActionStatus, RecoveryResult,
};
use crate::error::{P3Error, P3Result};
use crate::types::DegradedFlag;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Recovery manager
pub struct RecoveryManager {
    /// Active recovery plans
    plans: HashMap<String, RecoveryPlan>,
    /// Recovery conditions
    conditions: HashMap<String, RecoveryCondition>,
    /// Pending actions
    pending_actions: Vec<RecoveryAction>,
    /// Completed actions
    completed_actions: Vec<RecoveryAction>,
    /// Max retry attempts
    max_retries: u32,
    /// Plan counter for unique IDs
    plan_counter: u64,
}

impl RecoveryManager {
    /// Create new manager
    pub fn new() -> Self {
        Self {
            plans: HashMap::new(),
            conditions: HashMap::new(),
            pending_actions: Vec::new(),
            completed_actions: Vec::new(),
            max_retries: 3,
            plan_counter: 0,
        }
    }

    /// Set max retries
    pub fn with_max_retries(mut self, max: u32) -> Self {
        self.max_retries = max;
        self
    }

    /// Create recovery plan for flag
    pub fn create_plan(&mut self, flag: DegradedFlag) -> P3Result<RecoveryPlan> {
        self.plan_counter += 1;
        let plan_id = format!("plan:{}:{}:{}", flag.name(), Utc::now().timestamp_millis(), self.plan_counter);

        let plan = RecoveryPlan {
            plan_id: plan_id.clone(),
            flag: flag.clone(),
            conditions: self.default_conditions_for(&flag),
            actions: self.default_actions_for(&flag),
            status: RecoveryPlanStatus::Created,
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            current_action_index: 0,
        };

        self.plans.insert(plan_id.clone(), plan.clone());

        // Register conditions
        for condition in &plan.conditions {
            self.conditions
                .insert(condition.condition_id.clone(), condition.clone());
        }

        Ok(plan)
    }

    /// Start recovery plan
    pub fn start_plan(&mut self, plan_id: &str) -> P3Result<()> {
        let plan = self.plans.get_mut(plan_id).ok_or_else(|| P3Error::NotFound {
            entity: "RecoveryPlan".to_string(),
            id: plan_id.to_string(),
        })?;

        if plan.status != RecoveryPlanStatus::Created {
            return Err(P3Error::InvalidState {
                reason: format!("Plan is in {:?} status", plan.status),
            });
        }

        plan.status = RecoveryPlanStatus::InProgress;
        plan.started_at = Some(Utc::now());

        // Queue first action
        if let Some(action) = plan.actions.first() {
            let mut action = action.clone();
            action.status = RecoveryActionStatus::Pending;
            self.pending_actions.push(action);
        }

        Ok(())
    }

    /// Execute next pending action
    pub fn execute_next_action(&mut self) -> P3Result<Option<RecoveryAction>> {
        if self.pending_actions.is_empty() {
            return Ok(None);
        }

        let mut action = self.pending_actions.remove(0);
        action.status = RecoveryActionStatus::InProgress;
        action.executed_at = Some(Utc::now());

        // Execute based on action type
        let result = self.execute_action(&action)?;
        action.result = Some(result.clone());

        if result.success {
            action.status = RecoveryActionStatus::Completed;
        } else {
            action.status = RecoveryActionStatus::Failed;
        }

        self.completed_actions.push(action.clone());
        Ok(Some(action))
    }

    /// Check and update conditions
    pub fn check_conditions(&mut self, metrics: &HashMap<String, f64>) -> Vec<String> {
        let mut met_conditions = Vec::new();

        for (id, condition) in &mut self.conditions {
            if let Some(value) = metrics.get(&condition.condition_id) {
                if condition.evaluate(*value) {
                    met_conditions.push(id.clone());
                }
            }
        }

        met_conditions
    }

    /// Check if all conditions for flag are met
    pub fn all_conditions_met(&self, flag: &DegradedFlag) -> bool {
        self.conditions
            .values()
            .filter(|c| &c.flag == flag)
            .all(|c| c.is_met)
    }

    /// Complete plan
    pub fn complete_plan(&mut self, plan_id: &str, success: bool) -> P3Result<()> {
        let plan = self.plans.get_mut(plan_id).ok_or_else(|| P3Error::NotFound {
            entity: "RecoveryPlan".to_string(),
            id: plan_id.to_string(),
        })?;

        plan.status = if success {
            RecoveryPlanStatus::Completed
        } else {
            RecoveryPlanStatus::Failed
        };
        plan.completed_at = Some(Utc::now());

        Ok(())
    }

    /// Get plan
    pub fn get_plan(&self, plan_id: &str) -> Option<&RecoveryPlan> {
        self.plans.get(plan_id)
    }

    /// Get plans for flag
    pub fn plans_for_flag(&self, flag: &DegradedFlag) -> Vec<&RecoveryPlan> {
        self.plans
            .values()
            .filter(|p| &p.flag == flag)
            .collect()
    }

    /// Get pending actions count
    pub fn pending_action_count(&self) -> usize {
        self.pending_actions.len()
    }

    /// Trigger automatic recovery
    pub fn trigger_auto_recovery(
        &mut self,
        detector: &mut DegradedModeDetector,
    ) -> P3Result<Vec<RecoveryAction>> {
        let mut executed = Vec::new();

        // Check conditions and execute pending actions
        while let Some(action) = self.execute_next_action()? {
            executed.push(action.clone());

            // If action succeeded and conditions are met, clear the flag
            if action.status == RecoveryActionStatus::Completed {
                if self.all_conditions_met(&action.flag) {
                    detector.clear_flag(&action.flag)?;
                }
            }
        }

        Ok(executed)
    }

    /// Execute a recovery action
    fn execute_action(&self, action: &RecoveryAction) -> P3Result<RecoveryResult> {
        // In a real implementation, this would perform actual recovery actions
        let success = match action.action_type {
            RecoveryActionType::AutoRetry => true,
            RecoveryActionType::ClearFlag => true,
            RecoveryActionType::Escalate => true,
            RecoveryActionType::RestartService => true,
            RecoveryActionType::Failover => true,
            RecoveryActionType::ManualIntervention => false,
        };

        Ok(RecoveryResult {
            success,
            message: format!("Action {:?} executed", action.action_type),
            new_flags: Vec::new(),
            completed_at: Utc::now(),
        })
    }

    /// Default conditions for flag
    fn default_conditions_for(&self, flag: &DegradedFlag) -> Vec<RecoveryCondition> {
        match flag {
            DegradedFlag::DsnDown => vec![RecoveryCondition::new(
                "dsn_health",
                flag.clone(),
                RecoveryConditionType::ValueAbove,
            )
            .with_threshold(0.9)],
            DegradedFlag::VersionDrift => vec![RecoveryCondition::new(
                "version_sync",
                flag.clone(),
                RecoveryConditionType::ValueBelow,
            )
            .with_threshold(0.05)],
            _ => vec![RecoveryCondition::new(
                "generic",
                flag.clone(),
                RecoveryConditionType::Manual,
            )],
        }
    }

    /// Default actions for flag
    fn default_actions_for(&self, flag: &DegradedFlag) -> Vec<RecoveryAction> {
        match flag {
            DegradedFlag::DsnDown => vec![
                RecoveryAction::new(
                    "retry_dsn",
                    flag.clone(),
                    RecoveryActionType::AutoRetry,
                )
                .with_priority(1),
                RecoveryAction::new(
                    "failover_dsn",
                    flag.clone(),
                    RecoveryActionType::Failover,
                )
                .with_priority(2),
            ],
            DegradedFlag::VersionDrift => vec![RecoveryAction::new(
                "sync_version",
                flag.clone(),
                RecoveryActionType::AutoRetry,
            )],
            _ => vec![RecoveryAction::new(
                "escalate",
                flag.clone(),
                RecoveryActionType::Escalate,
            )],
        }
    }
}

impl Default for RecoveryManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Recovery plan
#[derive(Clone, Debug)]
pub struct RecoveryPlan {
    /// Plan ID
    pub plan_id: String,
    /// Target flag
    pub flag: DegradedFlag,
    /// Recovery conditions
    pub conditions: Vec<RecoveryCondition>,
    /// Recovery actions
    pub actions: Vec<RecoveryAction>,
    /// Plan status
    pub status: RecoveryPlanStatus,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Started at
    pub started_at: Option<DateTime<Utc>>,
    /// Completed at
    pub completed_at: Option<DateTime<Utc>>,
    /// Current action index
    pub current_action_index: usize,
}

/// Recovery plan status
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryPlanStatus {
    /// Created but not started
    Created,
    /// In progress
    InProgress,
    /// Completed successfully
    Completed,
    /// Failed
    Failed,
    /// Cancelled
    Cancelled,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_manager_creation() {
        let manager = RecoveryManager::new();
        assert_eq!(manager.pending_action_count(), 0);
    }

    #[test]
    fn test_create_plan() {
        let mut manager = RecoveryManager::new();
        let plan = manager.create_plan(DegradedFlag::DsnDown).unwrap();

        assert_eq!(plan.status, RecoveryPlanStatus::Created);
        assert!(!plan.conditions.is_empty());
        assert!(!plan.actions.is_empty());
    }

    #[test]
    fn test_start_plan() {
        let mut manager = RecoveryManager::new();
        let plan = manager.create_plan(DegradedFlag::DsnDown).unwrap();
        let plan_id = plan.plan_id.clone();

        manager.start_plan(&plan_id).unwrap();

        let plan = manager.get_plan(&plan_id).unwrap();
        assert_eq!(plan.status, RecoveryPlanStatus::InProgress);
        assert!(manager.pending_action_count() > 0);
    }

    #[test]
    fn test_execute_action() {
        let mut manager = RecoveryManager::new();
        let plan = manager.create_plan(DegradedFlag::VersionDrift).unwrap();
        let plan_id = plan.plan_id.clone();

        manager.start_plan(&plan_id).unwrap();

        let action = manager.execute_next_action().unwrap();
        assert!(action.is_some());
        assert_eq!(action.unwrap().status, RecoveryActionStatus::Completed);
    }

    #[test]
    fn test_check_conditions() {
        let mut manager = RecoveryManager::new();
        manager.create_plan(DegradedFlag::DsnDown).unwrap();

        let mut metrics = HashMap::new();
        metrics.insert("dsn_health".to_string(), 0.95);

        let met = manager.check_conditions(&metrics);
        assert!(!met.is_empty());
    }

    #[test]
    fn test_complete_plan() {
        let mut manager = RecoveryManager::new();
        let plan = manager.create_plan(DegradedFlag::DsnDown).unwrap();
        let plan_id = plan.plan_id.clone();

        manager.start_plan(&plan_id).unwrap();
        manager.complete_plan(&plan_id, true).unwrap();

        let plan = manager.get_plan(&plan_id).unwrap();
        assert_eq!(plan.status, RecoveryPlanStatus::Completed);
    }

    #[test]
    fn test_plans_for_flag() {
        let mut manager = RecoveryManager::new();
        manager.create_plan(DegradedFlag::DsnDown).unwrap();
        manager.create_plan(DegradedFlag::DsnDown).unwrap();
        manager.create_plan(DegradedFlag::VersionDrift).unwrap();

        let dsn_plans = manager.plans_for_flag(&DegradedFlag::DsnDown);
        assert_eq!(dsn_plans.len(), 2);
    }
}
