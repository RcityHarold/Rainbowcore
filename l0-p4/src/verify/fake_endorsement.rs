//! 伪背书检测
//!
//! 检测系统中可能存在的伪背书情况。
//!
//! # 什么是伪背书？
//!
//! 伪背书是指：
//! 1. 宣称锚定完成但无有效 Link
//! 2. Link 与实际链上数据不匹配
//! 3. 确认数不足但标记为已确认
//!
//! # 设计原则
//!
//! - 主动检测：定期扫描可疑状态
//! - 被动验证：在关键操作时验证
//! - 不可抵赖：所有检测结果记录审计

use std::sync::Arc;
use std::hash::Hash;
use serde::{Deserialize, Serialize};

use crate::error::P4Result;
use crate::storage::AnchorStorage;
use crate::types::{
    ChainAnchorInput, ChainAnchorJob, ChainAnchorLink, InputId, InputStatus,
    JobStatus, LinkStatus, Timestamp,
};

/// 伪背书类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FakeEndorsementType {
    /// 无 Link 宣称完成
    CompletedWithoutLink,
    /// Link 与输入不匹配
    LinkInputMismatch,
    /// 确认数不足
    InsufficientConfirmations,
    /// 交易数据不匹配
    TransactionDataMismatch,
    /// epoch_root 不匹配
    EpochRootMismatch,
    /// 幂等键冲突
    IdempotencyConflict,
    /// 状态不一致
    StateInconsistency,
}

impl std::fmt::Display for FakeEndorsementType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CompletedWithoutLink => write!(f, "COMPLETED_WITHOUT_LINK"),
            Self::LinkInputMismatch => write!(f, "LINK_INPUT_MISMATCH"),
            Self::InsufficientConfirmations => write!(f, "INSUFFICIENT_CONFIRMATIONS"),
            Self::TransactionDataMismatch => write!(f, "TRANSACTION_DATA_MISMATCH"),
            Self::EpochRootMismatch => write!(f, "EPOCH_ROOT_MISMATCH"),
            Self::IdempotencyConflict => write!(f, "IDEMPOTENCY_CONFLICT"),
            Self::StateInconsistency => write!(f, "STATE_INCONSISTENCY"),
        }
    }
}

/// 伪背书记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FakeEndorsement {
    /// 输入ID
    pub input_id: InputId,

    /// 伪背书类型
    pub endorsement_type: FakeEndorsementType,

    /// 宣称的状态
    pub claimed_status: Option<InputStatus>,

    /// 实际的 Link（如有）
    pub actual_link: Option<ChainAnchorLink>,

    /// 检测时间
    pub detected_at: Timestamp,

    /// 详细描述
    pub description: String,

    /// 证据数据
    pub evidence: FakeEndorsementEvidence,
}

/// 伪背书证据
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FakeEndorsementEvidence {
    /// 期望值
    pub expected: Option<String>,
    /// 实际值
    pub actual: Option<String>,
    /// 相关 Job ID
    pub job_id: Option<[u8; 32]>,
    /// 相关 Link ID
    pub link_id: Option<[u8; 32]>,
    /// 额外上下文
    pub context: std::collections::HashMap<String, String>,
}

/// 伪背书检测器
pub struct FakeEndorsementDetector<S: AnchorStorage> {
    /// 存储
    storage: Arc<S>,

    /// 所需确认数
    required_confirmations: u32,
}

impl<S: AnchorStorage + 'static> FakeEndorsementDetector<S> {
    /// 创建新的检测器
    pub fn new(storage: Arc<S>, required_confirmations: u32) -> Self {
        Self {
            storage,
            required_confirmations,
        }
    }

    /// 检测单个输入的伪背书
    pub async fn detect(&self, input_id: &InputId) -> P4Result<Option<FakeEndorsement>> {
        let input = self.storage.get_input(input_id).await?;

        if let Some(input) = input {
            // 检查类型1：完成状态但无Link
            if input.status == InputStatus::Completed {
                let link = self.storage.get_link_by_input(input_id).await?;

                if link.is_none() {
                    return Ok(Some(FakeEndorsement {
                        input_id: *input_id,
                        endorsement_type: FakeEndorsementType::CompletedWithoutLink,
                        claimed_status: Some(input.status),
                        actual_link: None,
                        detected_at: Timestamp::now(),
                        description: "Input marked as completed but no Link found".to_string(),
                        evidence: FakeEndorsementEvidence::default(),
                    }));
                }

                // 检查 Link 与输入是否匹配
                if let Some(link) = link {
                    if let Some(fake) = self.check_link_input_match(&input, &link) {
                        return Ok(Some(fake));
                    }

                    // 检查确认数
                    if let Some(fake) = self.check_confirmations(&input, &link) {
                        return Ok(Some(fake));
                    }
                }
            }
        }

        Ok(None)
    }

    /// 检测指定输入列表的伪背书
    pub async fn detect_inputs(&self, inputs: &[ChainAnchorInput]) -> P4Result<Vec<FakeEndorsement>> {
        let mut fake_endorsements = Vec::new();

        for input in inputs {
            if input.status == InputStatus::Completed {
                if let Some(fake) = self.detect(&input.input_id).await? {
                    fake_endorsements.push(fake);
                }
            }
        }

        Ok(fake_endorsements)
    }

    /// 检查 Link 与输入是否匹配
    fn check_link_input_match(
        &self,
        input: &ChainAnchorInput,
        link: &ChainAnchorLink,
    ) -> Option<FakeEndorsement> {
        // 检查 epoch_root
        if link.epoch_root != input.epoch_root {
            return Some(FakeEndorsement {
                input_id: input.input_id,
                endorsement_type: FakeEndorsementType::EpochRootMismatch,
                claimed_status: Some(input.status),
                actual_link: Some(link.clone()),
                detected_at: Timestamp::now(),
                description: "Link epoch_root does not match input".to_string(),
                evidence: FakeEndorsementEvidence {
                    expected: Some(hex::encode(input.epoch_root)),
                    actual: Some(hex::encode(link.epoch_root)),
                    link_id: Some(link.link_id),
                    ..Default::default()
                },
            });
        }

        // 检查 epoch_sequence
        if link.epoch_sequence != input.epoch_sequence {
            return Some(FakeEndorsement {
                input_id: input.input_id,
                endorsement_type: FakeEndorsementType::LinkInputMismatch,
                claimed_status: Some(input.status),
                actual_link: Some(link.clone()),
                detected_at: Timestamp::now(),
                description: "Link epoch_sequence does not match input".to_string(),
                evidence: FakeEndorsementEvidence {
                    expected: Some(input.epoch_sequence.to_string()),
                    actual: Some(link.epoch_sequence.to_string()),
                    link_id: Some(link.link_id),
                    ..Default::default()
                },
            });
        }

        // 检查 linked_receipt_ids_digest
        if link.linked_receipt_ids_digest != input.linked_receipt_ids_digest {
            return Some(FakeEndorsement {
                input_id: input.input_id,
                endorsement_type: FakeEndorsementType::LinkInputMismatch,
                claimed_status: Some(input.status),
                actual_link: Some(link.clone()),
                detected_at: Timestamp::now(),
                description: "Link linked_receipt_ids_digest does not match input".to_string(),
                evidence: FakeEndorsementEvidence {
                    expected: Some(hex::encode(input.linked_receipt_ids_digest)),
                    actual: Some(hex::encode(link.linked_receipt_ids_digest)),
                    link_id: Some(link.link_id),
                    ..Default::default()
                },
            });
        }

        None
    }

    /// 检查确认数
    fn check_confirmations(
        &self,
        input: &ChainAnchorInput,
        link: &ChainAnchorLink,
    ) -> Option<FakeEndorsement> {
        if link.status == LinkStatus::Confirmed && link.confirmations < self.required_confirmations {
            return Some(FakeEndorsement {
                input_id: input.input_id,
                endorsement_type: FakeEndorsementType::InsufficientConfirmations,
                claimed_status: Some(input.status),
                actual_link: Some(link.clone()),
                detected_at: Timestamp::now(),
                description: format!(
                    "Link marked as confirmed but has only {} confirmations (required: {})",
                    link.confirmations, self.required_confirmations
                ),
                evidence: FakeEndorsementEvidence {
                    expected: Some(self.required_confirmations.to_string()),
                    actual: Some(link.confirmations.to_string()),
                    link_id: Some(link.link_id),
                    ..Default::default()
                },
            });
        }

        None
    }

    /// 验证 Job 和 Link 的一致性
    pub async fn verify_job_link_consistency(
        &self,
        job: &ChainAnchorJob,
    ) -> P4Result<Option<FakeEndorsement>> {
        // 只检查已确认的 Job
        if job.status != JobStatus::Confirmed && job.status != JobStatus::Finalized {
            return Ok(None);
        }

        // 检查是否有对应的 Link（通过 input_id 查找）
        let link = self.storage.get_link_by_input(&job.input_id).await?;

        if link.is_none() {
            let input = self.storage.get_input(&job.input_id).await?;
            return Ok(Some(FakeEndorsement {
                input_id: job.input_id,
                endorsement_type: FakeEndorsementType::CompletedWithoutLink,
                claimed_status: input.map(|i| i.status),
                actual_link: None,
                detected_at: Timestamp::now(),
                description: "Job marked as confirmed but no Link found".to_string(),
                evidence: FakeEndorsementEvidence {
                    job_id: Some(job.job_id),
                    ..Default::default()
                },
            }));
        }

        Ok(None)
    }

    /// 检测状态不一致
    pub async fn detect_state_inconsistency(
        &self,
        input_id: &InputId,
    ) -> P4Result<Option<FakeEndorsement>> {
        let input = self.storage.get_input(input_id).await?;
        let jobs = self.storage.get_jobs_by_input(input_id).await?;
        let link = self.storage.get_link_by_input(input_id).await?;

        // 取最新的 job
        let job = jobs.into_iter().max_by_key(|j| j.created_at);

        if let (Some(input), Some(job)) = (input.as_ref(), job.as_ref()) {
            // 检查：Input 完成但 Job 未确认
            if input.status == InputStatus::Completed
                && job.status != JobStatus::Confirmed
                && job.status != JobStatus::Finalized
            {
                return Ok(Some(FakeEndorsement {
                    input_id: *input_id,
                    endorsement_type: FakeEndorsementType::StateInconsistency,
                    claimed_status: Some(input.status),
                    actual_link: link,
                    detected_at: Timestamp::now(),
                    description: format!(
                        "Input marked as Completed but Job status is {:?}",
                        job.status
                    ),
                    evidence: FakeEndorsementEvidence {
                        job_id: Some(job.job_id),
                        expected: Some("Confirmed or Finalized".to_string()),
                        actual: Some(format!("{:?}", job.status)),
                        ..Default::default()
                    },
                }));
            }

            // 检查：Job 确认但无 Link
            if (job.status == JobStatus::Confirmed || job.status == JobStatus::Finalized)
                && link.is_none()
            {
                return Ok(Some(FakeEndorsement {
                    input_id: *input_id,
                    endorsement_type: FakeEndorsementType::CompletedWithoutLink,
                    claimed_status: Some(input.status),
                    actual_link: None,
                    detected_at: Timestamp::now(),
                    description: "Job confirmed but no Link exists".to_string(),
                    evidence: FakeEndorsementEvidence {
                        job_id: Some(job.job_id),
                        ..Default::default()
                    },
                }));
            }
        }

        Ok(None)
    }
}

/// 检测结果摘要
#[derive(Debug, Clone, Default)]
pub struct DetectionSummary {
    /// 检测的输入数
    pub inputs_checked: usize,
    /// 发现的伪背书数
    pub fake_endorsements_found: usize,
    /// 按类型分类
    pub by_type: std::collections::HashMap<FakeEndorsementType, usize>,
    /// 检测时间
    pub detected_at: Timestamp,
    /// 检测耗时（毫秒）
    pub duration_ms: u64,
}

impl DetectionSummary {
    /// 添加检测结果
    pub fn add(&mut self, fake: &FakeEndorsement) {
        self.fake_endorsements_found += 1;
        *self.by_type.entry(fake.endorsement_type).or_insert(0) += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;
    use crate::types::AnchorPriority;

    fn create_test_input() -> ChainAnchorInput {
        ChainAnchorInput::new(
            1,
            [0x12; 32],
            [0x34; 32],
            AnchorPriority::Must,
        )
    }

    #[tokio::test]
    async fn test_detect_completed_without_link() {
        let storage = Arc::new(MemoryStorage::new());
        let detector = FakeEndorsementDetector::new(storage.clone(), 6);

        // 创建一个标记为完成的输入
        let mut input = create_test_input();
        input.status = InputStatus::Completed;
        storage.save_input(&input).await.unwrap();

        // 检测应该发现伪背书
        let result = detector.detect(&input.input_id).await.unwrap();
        assert!(result.is_some());

        let fake = result.unwrap();
        assert_eq!(fake.endorsement_type, FakeEndorsementType::CompletedWithoutLink);
    }

    #[tokio::test]
    async fn test_no_fake_endorsement_pending() {
        let storage = Arc::new(MemoryStorage::new());
        let detector = FakeEndorsementDetector::new(storage.clone(), 6);

        // 创建一个待处理的输入
        let input = create_test_input();
        storage.save_input(&input).await.unwrap();

        // 检测不应该发现伪背书
        let result = detector.detect(&input.input_id).await.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_fake_endorsement_type_display() {
        assert_eq!(
            format!("{}", FakeEndorsementType::CompletedWithoutLink),
            "COMPLETED_WITHOUT_LINK"
        );
        assert_eq!(
            format!("{}", FakeEndorsementType::EpochRootMismatch),
            "EPOCH_ROOT_MISMATCH"
        );
    }

    #[test]
    fn test_detection_summary() {
        let mut summary = DetectionSummary::default();

        let fake = FakeEndorsement {
            input_id: [0x12; 32],
            endorsement_type: FakeEndorsementType::CompletedWithoutLink,
            claimed_status: None,
            actual_link: None,
            detected_at: Timestamp::now(),
            description: "Test".to_string(),
            evidence: FakeEndorsementEvidence::default(),
        };

        summary.add(&fake);
        assert_eq!(summary.fake_endorsements_found, 1);
        assert_eq!(
            summary.by_type.get(&FakeEndorsementType::CompletedWithoutLink),
            Some(&1)
        );
    }
}
