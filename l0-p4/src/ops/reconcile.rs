//! Reconcile 阶段 - 对账
//!
//! 创建最终的对账结果，验证三状态分离。
//!
//! # 核心原则
//!
//! `confirmed ≠ A` - 链锚定不等于证据完备
//!
//! 三状态必须独立验证：
//! - evidence_status: P4 不得改写
//! - execution_status: 执行流程状态
//! - chain_anchor_status: P4 唯一负责

use serde::{Deserialize, Serialize};

use crate::error::{P4Error, P4Result};
use crate::storage::AnchorStorage;
use crate::types::{
    ChainAnchorInput, ChainAnchorJob, ChainAnchorLink, ChainAnchorStatus, EvidenceStatus,
    ExecutionStatus, LinkStatus, ReconcileFailure, ReconcileResult, ReconcileStatus,
    ReconcileErrorCode,
};

use super::AnchorOps;

/// Reconcile 错误
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReconcileError {
    /// 缺少 Link
    MissingLink,
    /// Link 状态不正确
    InvalidLinkStatus(String),
    /// 三状态验证失败
    ThreeStateValidationFailed(String),
    /// 输入与 Link 不匹配
    InputLinkMismatch { input_id: String, link_input_id: String },
}

impl std::fmt::Display for ReconcileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReconcileError::MissingLink => {
                write!(f, "Cannot reconcile without a valid Link")
            }
            ReconcileError::InvalidLinkStatus(status) => {
                write!(f, "Invalid link status for reconcile: {}", status)
            }
            ReconcileError::ThreeStateValidationFailed(msg) => {
                write!(f, "Three-state validation failed: {}", msg)
            }
            ReconcileError::InputLinkMismatch { input_id, link_input_id } => {
                write!(
                    f,
                    "Input/Link mismatch: input={}, link.input={}",
                    input_id, link_input_id
                )
            }
        }
    }
}

impl std::error::Error for ReconcileError {}

/// 执行 Reconcile 阶段
pub async fn execute<S: AnchorStorage + 'static>(
    _ops: &AnchorOps<S>,
    input: &ChainAnchorInput,
    job: Option<&ChainAnchorJob>,
    link: Option<&ChainAnchorLink>,
) -> P4Result<ReconcileResult> {
    // 确定链锚定状态
    let chain_anchor_status = if let Some(link) = link {
        // 验证 Link 与 Input 匹配
        if link.input_id != input.input_id {
            return Err(P4Error::InvalidInput(format!(
                "Link input_id mismatch: expected {:?}, got {:?}",
                hex::encode(&input.input_id[..8]),
                hex::encode(&link.input_id[..8])
            )));
        }

        match link.status {
            LinkStatus::Confirmed => ChainAnchorStatus::Confirmed,
            LinkStatus::None | LinkStatus::Queued => ChainAnchorStatus::Queued,
            LinkStatus::Failed => ChainAnchorStatus::Failed,
            LinkStatus::Superseded => ChainAnchorStatus::None,
        }
    } else {
        ChainAnchorStatus::None
    };

    // 确定执行状态
    // 注意：execution_status 与 chain_anchor_status 分离
    let execution_status = match chain_anchor_status {
        ChainAnchorStatus::Confirmed => ExecutionStatus::Resolved,
        ChainAnchorStatus::Queued => ExecutionStatus::InProgress,
        ChainAnchorStatus::Failed => ExecutionStatus::Failed,
        ChainAnchorStatus::None => ExecutionStatus::NotStarted,
    };

    // 确定证据状态
    // 重要：P4 不得改写 evidence_status
    // 这里只设置为 PendingEvidence，实际状态应由上层 P1 确定
    let evidence_status = EvidenceStatus::PendingEvidence;

    // 创建对账结果
    let result = match (chain_anchor_status, link, job) {
        // 完全成功：需要 link 和 job
        (ChainAnchorStatus::Confirmed, Some(link), Some(job)) => {
            if evidence_status == EvidenceStatus::A {
                ReconcileResult::success(
                    input.input_id,
                    link.link_id,
                    job.job_id,
                    evidence_status,
                )
            } else {
                // 部分成功：链锚定成功但证据未完成
                ReconcileResult::partial_success(
                    input.input_id,
                    link.link_id,
                    job.job_id,
                    evidence_status,
                )
            }
        }
        // 失败
        (ChainAnchorStatus::Failed, _, job) => {
            ReconcileResult::failure(
                input.input_id,
                job.map(|j| j.job_id),
                ReconcileFailure::NoLink,
                evidence_status,
                execution_status,
                chain_anchor_status,
            )
        }
        // 待处理
        _ => {
            ReconcileResult::pending(input.input_id)
        }
    };

    tracing::info!(
        "Reconcile for input {:?}: status={:?}, chain_anchor={:?}",
        hex::encode(&input.input_id[..8]),
        result.status,
        chain_anchor_status
    );

    // 验证三状态一致性
    let validation = result.validate_three_state_consistency();
    if !validation.is_consistent {
        for issue in &validation.issues {
            tracing::warn!("Three-state issue: {:?}", issue);
        }
    }

    Ok(result)
}

/// 确定对账状态
///
/// 注意：此函数目前仅在测试中使用，但保留以供未来对账流程完善使用。
#[allow(dead_code)]
fn determine_reconcile_status(
    evidence_status: EvidenceStatus,
    execution_status: ExecutionStatus,
    chain_anchor_status: ChainAnchorStatus,
) -> ReconcileStatus {
    // 核心原则：confirmed ≠ A
    // 只有三状态都完成才算成功

    match (evidence_status, execution_status, chain_anchor_status) {
        // 完全成功：证据完整 + 执行完成 + 链锚定确认
        (EvidenceStatus::A, ExecutionStatus::Resolved, ChainAnchorStatus::Confirmed) => {
            ReconcileStatus::Success
        }

        // 部分成功：链锚定成功但证据未完成
        // 重要：这不是完全成功！confirmed ≠ A
        (_, ExecutionStatus::Resolved, ChainAnchorStatus::Confirmed) => {
            ReconcileStatus::PartialSuccess
        }

        // 失败
        (_, ExecutionStatus::Failed, _) | (_, _, ChainAnchorStatus::Failed) => {
            ReconcileStatus::Failed
        }

        // 待处理
        _ => ReconcileStatus::Pending,
    }
}

/// 验证对账结果是否可以宣称强后果
///
/// 只有当三状态都完成时才能宣称强后果。
/// 这是 `confirmed ≠ A` 原则的具体实现。
pub fn can_claim_strong_consequence(result: &ReconcileResult) -> bool {
    result.can_claim_strong_consequence()
}

/// 创建失败的对账结果
pub fn create_failure_result(
    input: &ChainAnchorInput,
    error_code: ReconcileErrorCode,
    message: String,
) -> ReconcileResult {
    let mut result = ReconcileResult::failure(
        input.input_id,
        None,
        ReconcileFailure::Other(message),
        EvidenceStatus::Missing,
        ExecutionStatus::Failed,
        ChainAnchorStatus::Failed,
    );

    result.error_codes.push(error_code);

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determine_reconcile_status_success() {
        let status = determine_reconcile_status(
            EvidenceStatus::A,
            ExecutionStatus::Resolved,
            ChainAnchorStatus::Confirmed,
        );
        assert_eq!(status, ReconcileStatus::Success);
    }

    #[test]
    fn test_determine_reconcile_status_partial() {
        // confirmed ≠ A: 链锚定确认但证据未完成
        let status = determine_reconcile_status(
            EvidenceStatus::PendingEvidence,
            ExecutionStatus::Resolved,
            ChainAnchorStatus::Confirmed,
        );
        assert_eq!(status, ReconcileStatus::PartialSuccess);
    }

    #[test]
    fn test_determine_reconcile_status_failed() {
        let status = determine_reconcile_status(
            EvidenceStatus::A,
            ExecutionStatus::Failed,
            ChainAnchorStatus::Confirmed,
        );
        assert_eq!(status, ReconcileStatus::Failed);
    }

    #[test]
    fn test_determine_reconcile_status_pending() {
        let status = determine_reconcile_status(
            EvidenceStatus::PendingEvidence,
            ExecutionStatus::InProgress,
            ChainAnchorStatus::Queued,
        );
        assert_eq!(status, ReconcileStatus::Pending);
    }

    #[test]
    fn test_reconcile_error_display() {
        let err = ReconcileError::ThreeStateValidationFailed(
            "evidence incomplete".to_string()
        );
        assert!(err.to_string().contains("evidence incomplete"));
    }
}
