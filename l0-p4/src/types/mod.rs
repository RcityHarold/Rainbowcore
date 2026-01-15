//! P4 核心类型定义
//!
//! 本模块定义了 P4 比特币锚定层的核心对象类型，基于 09-比特币锚定层开发文档。
//!
//! # 四大核心对象
//!
//! - [`ChainAnchorInput`]: 锚定输入承诺 - 来自 L0 的待锚定数据
//! - [`ChainAnchorJob`]: 锚定作业对象 - 执行尝试的最小审计单位
//! - [`ChainAnchorLink`]: 链锚定结果 - 对账闭合凭据
//! - [`ReconcileResult`]: 对账结果 - 输入与链锚定的最终对账
//!
//! # 设计原则
//!
//! 根据文档宪法要求：
//! - **零明文**: 只承载摘要/引用，不承载明文载荷
//! - **链锚≠证据完备**: Link 不能改变 A/B 与强后果门槛
//! - **MUST队列不丢弃**: cap不足只能 pending，不得静默
//! - **失败不得静默**: 任何失败必须对象化 failure_reason_digest / error_codes
//! - **幂等**: 同输入不产生两个冲突Link；重试必须归并

pub mod input;
pub mod job;
pub mod link;
pub mod reconcile;
pub mod common;

pub use input::*;
pub use job::*;
pub use link::*;
pub use reconcile::*;
pub use common::*;
