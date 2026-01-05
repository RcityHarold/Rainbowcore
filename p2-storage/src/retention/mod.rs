//! Retention Policy Module
//!
//! Manages data retention policies, legal holds, and automatic expiration.

pub mod checker;
pub mod gc;
pub mod legal_hold;
pub mod policy;

pub use checker::RetentionChecker;
pub use gc::RetentionGC;
pub use legal_hold::{LegalHold, LegalHoldManager, LegalHoldStatus};
pub use policy::{RetentionPolicy, RetentionPolicyConfig, RetentionRule};
