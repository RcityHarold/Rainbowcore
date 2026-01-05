//! Temperature Policy Configuration
//!
//! Defines policies for automatic temperature tier migration.

use chrono::{DateTime, Duration, Utc};
use p2_core::types::StorageTemperature;
use serde::{Deserialize, Serialize};

/// Temperature policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemperaturePolicyConfig {
    /// Policy name/ID
    pub name: String,
    /// Policy version
    pub version: String,
    /// Whether policy is enabled
    pub enabled: bool,
    /// Hot to Warm threshold
    pub hot_to_warm: TemperatureThreshold,
    /// Warm to Cold threshold
    pub warm_to_cold: TemperatureThreshold,
    /// Cold to Warm threshold (preheat)
    pub cold_to_warm: Option<TemperatureThreshold>,
    /// Warm to Hot threshold (heat)
    pub warm_to_hot: Option<TemperatureThreshold>,
    /// Minimum size for migration (bytes)
    pub min_size_bytes: u64,
    /// Maximum migrations per batch
    pub max_batch_size: usize,
    /// Scan interval (seconds)
    pub scan_interval_seconds: u64,
    /// Excluded payload patterns (ref_id prefixes)
    pub excluded_prefixes: Vec<String>,
    /// Excluded tags
    pub excluded_tags: Vec<String>,
}

impl Default for TemperaturePolicyConfig {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            version: "v1".to_string(),
            enabled: true,
            hot_to_warm: TemperatureThreshold {
                direction: MigrationDirection::Cool,
                triggers: vec![
                    MigrationTrigger::Age {
                        days: 7,
                    },
                    MigrationTrigger::AccessPattern {
                        pattern: AccessPattern::Infrequent,
                        threshold_accesses: 5,
                        window_days: 7,
                    },
                ],
                require_all: false, // Any trigger can cause migration
            },
            warm_to_cold: TemperatureThreshold {
                direction: MigrationDirection::Cool,
                triggers: vec![
                    MigrationTrigger::Age {
                        days: 30,
                    },
                    MigrationTrigger::AccessPattern {
                        pattern: AccessPattern::Rare,
                        threshold_accesses: 1,
                        window_days: 30,
                    },
                ],
                require_all: false,
            },
            cold_to_warm: Some(TemperatureThreshold {
                direction: MigrationDirection::Heat,
                triggers: vec![MigrationTrigger::AccessPattern {
                    pattern: AccessPattern::Frequent,
                    threshold_accesses: 10,
                    window_days: 7,
                }],
                require_all: true,
            }),
            warm_to_hot: Some(TemperatureThreshold {
                direction: MigrationDirection::Heat,
                triggers: vec![MigrationTrigger::AccessPattern {
                    pattern: AccessPattern::Frequent,
                    threshold_accesses: 50,
                    window_days: 7,
                }],
                require_all: true,
            }),
            min_size_bytes: 0,
            max_batch_size: 100,
            scan_interval_seconds: 3600, // 1 hour
            excluded_prefixes: Vec::new(),
            excluded_tags: vec!["pinned".to_string(), "no-migrate".to_string()],
        }
    }
}

impl TemperaturePolicyConfig {
    /// Create a policy for evidence (longer retention at hot/warm)
    pub fn evidence_policy() -> Self {
        Self {
            name: "evidence".to_string(),
            hot_to_warm: TemperatureThreshold {
                direction: MigrationDirection::Cool,
                triggers: vec![MigrationTrigger::Age { days: 30 }],
                require_all: true,
            },
            warm_to_cold: TemperatureThreshold {
                direction: MigrationDirection::Cool,
                triggers: vec![MigrationTrigger::Age { days: 365 }],
                require_all: true,
            },
            cold_to_warm: None, // Evidence doesn't auto-heat
            warm_to_hot: None,
            excluded_tags: vec!["active-case".to_string()],
            ..Default::default()
        }
    }

    /// Create a policy for snapshots (cold storage after short period)
    pub fn snapshot_policy() -> Self {
        Self {
            name: "snapshot".to_string(),
            hot_to_warm: TemperatureThreshold {
                direction: MigrationDirection::Cool,
                triggers: vec![MigrationTrigger::Age { days: 1 }],
                require_all: true,
            },
            warm_to_cold: TemperatureThreshold {
                direction: MigrationDirection::Cool,
                triggers: vec![MigrationTrigger::Age { days: 7 }],
                require_all: true,
            },
            cold_to_warm: Some(TemperatureThreshold {
                direction: MigrationDirection::Heat,
                triggers: vec![MigrationTrigger::ExplicitRequest],
                require_all: true,
            }),
            warm_to_hot: None,
            ..Default::default()
        }
    }

    /// Get the threshold for a specific transition
    pub fn get_threshold(
        &self,
        from: StorageTemperature,
        to: StorageTemperature,
    ) -> Option<&TemperatureThreshold> {
        match (from, to) {
            (StorageTemperature::Hot, StorageTemperature::Warm) => Some(&self.hot_to_warm),
            (StorageTemperature::Warm, StorageTemperature::Cold) => Some(&self.warm_to_cold),
            (StorageTemperature::Cold, StorageTemperature::Warm) => self.cold_to_warm.as_ref(),
            (StorageTemperature::Warm, StorageTemperature::Hot) => self.warm_to_hot.as_ref(),
            _ => None,
        }
    }
}

/// Temperature threshold for migration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemperatureThreshold {
    /// Direction of migration
    pub direction: MigrationDirection,
    /// Triggers that can cause migration
    pub triggers: Vec<MigrationTrigger>,
    /// Whether all triggers must match (AND) or any (OR)
    pub require_all: bool,
}

impl TemperatureThreshold {
    /// Evaluate if migration should occur
    pub fn evaluate(&self, context: &MigrationContext) -> bool {
        if self.require_all {
            self.triggers.iter().all(|t| t.evaluate(context))
        } else {
            self.triggers.iter().any(|t| t.evaluate(context))
        }
    }
}

/// Migration direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationDirection {
    /// Moving to cooler storage (Hot -> Warm -> Cold)
    Cool,
    /// Moving to warmer storage (Cold -> Warm -> Hot)
    Heat,
}

/// Migration trigger
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MigrationTrigger {
    /// Age-based trigger
    Age {
        /// Days since creation
        days: u32,
    },
    /// Access pattern trigger
    AccessPattern {
        /// Target access pattern
        pattern: AccessPattern,
        /// Threshold number of accesses
        threshold_accesses: u32,
        /// Window in days
        window_days: u32,
    },
    /// Size-based trigger
    Size {
        /// Minimum size in bytes
        min_bytes: u64,
        /// Maximum size in bytes
        max_bytes: Option<u64>,
    },
    /// Explicit request (manual migration)
    ExplicitRequest,
    /// Storage utilization trigger
    StorageUtilization {
        /// Utilization percentage threshold
        threshold_percent: u8,
    },
}

impl MigrationTrigger {
    /// Evaluate if this trigger should fire
    pub fn evaluate(&self, context: &MigrationContext) -> bool {
        match self {
            MigrationTrigger::Age { days } => {
                let age = Utc::now() - context.created_at;
                age >= Duration::days(*days as i64)
            }
            MigrationTrigger::AccessPattern {
                pattern,
                threshold_accesses,
                window_days,
            } => {
                let accesses_in_window = context.access_count_in_days(*window_days);
                pattern.matches(accesses_in_window, *threshold_accesses)
            }
            MigrationTrigger::Size { min_bytes, max_bytes } => {
                if context.size_bytes < *min_bytes {
                    return false;
                }
                if let Some(max) = max_bytes {
                    if context.size_bytes > *max {
                        return false;
                    }
                }
                true
            }
            MigrationTrigger::ExplicitRequest => context.explicit_request,
            MigrationTrigger::StorageUtilization { threshold_percent } => {
                context.storage_utilization_percent >= *threshold_percent
            }
        }
    }
}

/// Access pattern category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessPattern {
    /// Frequently accessed (many accesses in window)
    Frequent,
    /// Moderately accessed
    Moderate,
    /// Infrequently accessed
    Infrequent,
    /// Rarely accessed
    Rare,
}

impl AccessPattern {
    /// Check if access count matches this pattern
    pub fn matches(&self, access_count: u32, threshold: u32) -> bool {
        match self {
            AccessPattern::Frequent => access_count >= threshold,
            AccessPattern::Moderate => access_count >= threshold / 2 && access_count < threshold,
            AccessPattern::Infrequent => access_count > 0 && access_count < threshold,
            AccessPattern::Rare => access_count == 0,
        }
    }
}

/// Context for evaluating migration triggers
#[derive(Debug, Clone)]
pub struct MigrationContext {
    /// Payload reference ID
    pub ref_id: String,
    /// Current temperature
    pub current_temp: StorageTemperature,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last access timestamp
    pub last_accessed_at: Option<DateTime<Utc>>,
    /// Payload size in bytes
    pub size_bytes: u64,
    /// Access history (timestamp, count pairs for each day)
    pub access_history: Vec<(DateTime<Utc>, u32)>,
    /// Whether this is an explicit migration request
    pub explicit_request: bool,
    /// Current storage utilization percentage
    pub storage_utilization_percent: u8,
    /// Payload tags
    pub tags: Vec<String>,
}

impl MigrationContext {
    /// Get access count in the last N days
    pub fn access_count_in_days(&self, days: u32) -> u32 {
        let cutoff = Utc::now() - Duration::days(days as i64);
        self.access_history
            .iter()
            .filter(|(timestamp, _)| *timestamp >= cutoff)
            .map(|(_, count)| count)
            .sum()
    }

    /// Check if payload has any excluded tags
    pub fn has_excluded_tag(&self, excluded: &[String]) -> bool {
        self.tags.iter().any(|t| excluded.contains(t))
    }
}

/// Temperature policy for evaluating migrations
pub struct TemperaturePolicy {
    config: TemperaturePolicyConfig,
}

impl TemperaturePolicy {
    /// Create a new policy from config
    pub fn new(config: TemperaturePolicyConfig) -> Self {
        Self { config }
    }

    /// Create with default config
    pub fn default_policy() -> Self {
        Self::new(TemperaturePolicyConfig::default())
    }

    /// Get the config
    pub fn config(&self) -> &TemperaturePolicyConfig {
        &self.config
    }

    /// Evaluate if a payload should be migrated
    pub fn evaluate(&self, context: &MigrationContext) -> Option<StorageTemperature> {
        if !self.config.enabled {
            return None;
        }

        // Check exclusions
        if self.is_excluded(context) {
            return None;
        }

        // Check size threshold
        if context.size_bytes < self.config.min_size_bytes {
            return None;
        }

        // Evaluate based on current temperature
        match context.current_temp {
            StorageTemperature::Hot => {
                // Check if should cool to warm
                if self.config.hot_to_warm.evaluate(context) {
                    return Some(StorageTemperature::Warm);
                }
            }
            StorageTemperature::Warm => {
                // Check if should cool to cold
                if self.config.warm_to_cold.evaluate(context) {
                    return Some(StorageTemperature::Cold);
                }
                // Check if should heat to hot
                if let Some(threshold) = &self.config.warm_to_hot {
                    if threshold.evaluate(context) {
                        return Some(StorageTemperature::Hot);
                    }
                }
            }
            StorageTemperature::Cold => {
                // Check if should heat to warm
                if let Some(threshold) = &self.config.cold_to_warm {
                    if threshold.evaluate(context) {
                        return Some(StorageTemperature::Warm);
                    }
                }
            }
        }

        None
    }

    /// Check if a payload is excluded from migration
    fn is_excluded(&self, context: &MigrationContext) -> bool {
        // Check prefix exclusions
        for prefix in &self.config.excluded_prefixes {
            if context.ref_id.starts_with(prefix) {
                return true;
            }
        }

        // Check tag exclusions
        context.has_excluded_tag(&self.config.excluded_tags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_context(temp: StorageTemperature, age_days: i64) -> MigrationContext {
        MigrationContext {
            ref_id: "test:001".to_string(),
            current_temp: temp,
            created_at: Utc::now() - Duration::days(age_days),
            last_accessed_at: None,
            size_bytes: 1024,
            access_history: vec![],
            explicit_request: false,
            storage_utilization_percent: 50,
            tags: vec![],
        }
    }

    #[test]
    fn test_age_trigger() {
        let trigger = MigrationTrigger::Age { days: 7 };

        // 10 day old payload
        let context = create_test_context(StorageTemperature::Hot, 10);
        assert!(trigger.evaluate(&context));

        // 3 day old payload
        let context = create_test_context(StorageTemperature::Hot, 3);
        assert!(!trigger.evaluate(&context));
    }

    #[test]
    fn test_default_policy_hot_to_warm() {
        let policy = TemperaturePolicy::default_policy();

        // 10 day old hot payload should migrate to warm
        let context = create_test_context(StorageTemperature::Hot, 10);
        assert_eq!(policy.evaluate(&context), Some(StorageTemperature::Warm));

        // 3 day old hot payload should stay hot
        let context = create_test_context(StorageTemperature::Hot, 3);
        assert_eq!(policy.evaluate(&context), None);
    }

    #[test]
    fn test_exclusion_by_tag() {
        let policy = TemperaturePolicy::default_policy();

        let mut context = create_test_context(StorageTemperature::Hot, 10);
        context.tags = vec!["pinned".to_string()];

        // Should be excluded due to pinned tag
        assert_eq!(policy.evaluate(&context), None);
    }

    #[test]
    fn test_access_pattern_matching() {
        // Frequent: access_count >= threshold
        assert!(AccessPattern::Frequent.matches(10, 10));
        assert!(AccessPattern::Frequent.matches(15, 10));
        assert!(!AccessPattern::Frequent.matches(5, 10));

        // Rare: access_count == 0
        assert!(AccessPattern::Rare.matches(0, 10));
        assert!(!AccessPattern::Rare.matches(1, 10));
    }

    #[test]
    fn test_evidence_policy() {
        let policy = TemperaturePolicy::new(TemperaturePolicyConfig::evidence_policy());

        // 10 day old evidence should stay hot
        let context = create_test_context(StorageTemperature::Hot, 10);
        assert_eq!(policy.evaluate(&context), None);

        // 35 day old evidence should migrate to warm
        let context = create_test_context(StorageTemperature::Hot, 35);
        assert_eq!(policy.evaluate(&context), Some(StorageTemperature::Warm));
    }
}
