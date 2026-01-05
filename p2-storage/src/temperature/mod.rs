//! Temperature Policy Module
//!
//! Implements automatic temperature tier migration for P2 storage.
//! Payloads are automatically migrated between Hot, Warm, and Cold tiers
//! based on configurable policies.

pub mod executor;
pub mod policy;

pub use executor::{
    MigrationBatch, MigrationCandidate, MigrationProgress, MigrationResult, MigrationStatus,
    TemperaturePolicyExecutor,
};
pub use policy::{
    AccessPattern, MigrationDirection, MigrationTrigger, TemperaturePolicy, TemperaturePolicyConfig,
    TemperatureThreshold,
};
