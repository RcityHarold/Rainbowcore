//! 策略管理模块
//!
//! 提供链锚定策略的版本化管理。
//!
//! # 核心组件
//!
//! - `ChainAnchorPolicyVersion`: 策略版本定义
//! - `PolicyManager`: 策略生命周期管理

pub mod version;
pub mod manager;

pub use version::{
    ChainAnchorPolicyVersion,
    PoolConfig,
    FeeConfig,
    ConfirmationRequirements,
    RetryConfig,
    CapConfig,
    ExhaustionStrategy,
};

pub use manager::{
    PolicyManager,
    PolicyChangeListener,
};
