//! Hard Invariants Test Coverage (问题17)
//!
//! This module provides systematic testing for all HARD RULEs defined in the DSN documentation.
//! Every invariant MUST have at least one test that verifies correct enforcement.
//!
//! # Hard Invariants Covered
//!
//! 1. Missing payload_map_commit MUST result in B-level evidence
//! 2. UnknownVersion MUST be rejected for strong verification
//! 3. Unapproved MSN MUST NOT be included in R0
//! 4. R0 triggers MUST be one of: SubjectOnset, CustodyFreeze, GovernanceBatch
//! 5. Batch sequence numbers MUST be strictly increasing
//! 6. Audit log MUST be written BEFORE decrypt/export operations
//! 7. Evidence level requires VERIFICATION, not just existence
//! 8. Cold storage payloads MAY impact evidence availability
//! 9. P1 unavailability MUST trigger degraded mode
//! 10. Canonicalization version mismatch MUST be rejected

#[cfg(test)]
mod tests {
    use crate::types::{
        EvidenceBundle, EvidenceLevel, SealedPayloadRef, SealedPayloadStatus,
        StorageTemperature, MSNApprovalStatus, MSNWithApproval,
    };
    use l0_core::types::{ActorId, Digest, ReceiptId};
    use chrono::Utc;

    // ========================================================================
    // HARD INVARIANT 1: Missing payload_map_commit MUST result in B-level
    // ========================================================================

    #[test]
    fn hard_invariant_missing_map_commit_is_b_level() {
        let bundle = EvidenceBundle::new(
            "bundle:001".to_string(),
            "case:001".to_string(),
            ActorId::new("actor:001"),
            vec![],
        );

        // No map_commit_ref set
        assert!(bundle.map_commit_ref.is_none());

        // MUST be B-level
        assert_eq!(bundle.evidence_level(), EvidenceLevel::B);
    }

    #[test]
    fn hard_invariant_missing_map_commit_with_all_else_verified() {
        let mut bundle = EvidenceBundle::new(
            "bundle:001".to_string(),
            "case:001".to_string(),
            ActorId::new("actor:001"),
            vec![],
        );

        // Set everything except map_commit
        bundle.receipt_id = Some(ReceiptId("receipt:001".to_string()));
        bundle.set_receipt_verified(true, None);
        // map_commit_ref is still None, but we try to reconcile anyway
        bundle.set_map_commit_reconciled(true, None);
        bundle.set_payload_verification(true, true, 0);

        // MUST still be B-level because map_commit_ref is None
        assert!(bundle.map_commit_ref.is_none());
        assert_eq!(bundle.evidence_level(), EvidenceLevel::B);
    }

    // ========================================================================
    // HARD INVARIANT 2: UnknownVersion MUST be rejected
    // ========================================================================

    #[test]
    fn hard_invariant_unknown_payload_format_version() {
        use crate::types::sealed_payload::PayloadFormatVersion;

        let unknown_version = PayloadFormatVersion {
            encoding_version: "99.0.0".to_string(), // Unknown
            envelope_version: "1.0.0".to_string(),
            checksum_version: "blake3-1.0".to_string(),
        };

        // MUST NOT be known
        assert!(!unknown_version.is_known());

        // Unknown versions should be listed
        let unknowns = unknown_version.unknown_versions();
        assert!(!unknowns.is_empty());
        assert!(unknowns.iter().any(|(name, _)| *name == "encoding_version"));
    }

    #[test]
    fn hard_invariant_sealed_payload_unknown_version_blocks_strong_verify() {
        use crate::types::sealed_payload::PayloadFormatVersion;

        let ref_id = "test:ref".to_string();
        let checksum = Digest::zero();
        let enc_meta = Digest::zero();

        let mut payload_ref = SealedPayloadRef::new(ref_id, checksum, enc_meta, 1024);

        // Set unknown version
        payload_ref.format_version = PayloadFormatVersion {
            encoding_version: "2.0.0".to_string(), // Unknown version
            envelope_version: "1.0.0".to_string(),
            checksum_version: "blake3-1.0".to_string(),
        };

        // MUST NOT allow strong verification
        assert!(!payload_ref.has_known_format());
        assert!(!payload_ref.can_strong_verify());
    }

    // ========================================================================
    // HARD INVARIANT 3: Unapproved MSN MUST NOT be included in R0
    // ========================================================================

    #[test]
    fn hard_invariant_unapproved_msn_cannot_include_in_r0() {
        let payload_ref = SealedPayloadRef::new(
            "msn:001".to_string(),
            Digest::zero(),
            Digest::zero(),
            1024,
        );

        let msn = MSNWithApproval::new_pending(payload_ref, Digest::zero());

        // Pending MSN MUST NOT be includable in R0
        assert_eq!(msn.approval_status, MSNApprovalStatus::Pending);
        assert!(!msn.can_include_in_r0());
    }

    #[test]
    fn hard_invariant_rejected_msn_cannot_include_in_r0() {
        use crate::types::resurrection::MSNRejectionReason;

        let payload_ref = SealedPayloadRef::new(
            "msn:002".to_string(),
            Digest::zero(),
            Digest::zero(),
            1024,
        );

        let mut msn = MSNWithApproval::new_pending(payload_ref, Digest::zero());
        msn.reject(
            "reviewer:001".to_string(),
            MSNRejectionReason::ProhibitedContent,
            None,
        );

        // Rejected MSN MUST NOT be includable in R0
        assert_eq!(msn.approval_status, MSNApprovalStatus::Rejected);
        assert!(!msn.can_include_in_r0());
    }

    #[test]
    fn hard_invariant_approved_msn_can_include_in_r0() {
        let payload_ref = SealedPayloadRef::new(
            "msn:003".to_string(),
            Digest::zero(),
            Digest::zero(),
            1024,
        );

        let mut msn = MSNWithApproval::new_pending(payload_ref, Digest::zero());
        msn.approve("reviewer:001".to_string(), None);

        // Only approved MSN can be included
        assert_eq!(msn.approval_status, MSNApprovalStatus::Approved);
        assert!(msn.can_include_in_r0());
    }

    // ========================================================================
    // HARD INVARIANT 4: R0 triggers MUST be protocol-defined
    // ========================================================================

    #[test]
    fn hard_invariant_r0_triggers_are_limited() {
        use crate::types::resurrection::R0Trigger;

        // Only these three triggers are valid for R0
        let valid_triggers = [
            R0Trigger::SubjectOnset,
            R0Trigger::CustodyFreeze,
            R0Trigger::GovernanceBatch,
        ];

        // All valid triggers should exist and work
        for trigger in &valid_triggers {
            // Should serialize/deserialize correctly
            let json = serde_json::to_string(trigger).unwrap();
            let _: R0Trigger = serde_json::from_str(&json).unwrap();
        }

        // Verify mandatory triggers
        assert!(R0Trigger::SubjectOnset.is_mandatory());
        assert!(R0Trigger::CustodyFreeze.is_mandatory());
        assert!(!R0Trigger::GovernanceBatch.is_mandatory());
    }

    // ========================================================================
    // HARD INVARIANT 5: Batch sequence MUST be strictly increasing
    // ========================================================================

    #[test]
    fn hard_invariant_batch_sequence_gap_detected() {
        use bridge::payload_map_commit::{BatchMapCommit, BatchSequenceValidation};

        let refs = vec![];
        let now = Utc::now();

        // Create batch 0
        let batch0 = BatchMapCommit::new(&refs, "test", 0, now, now);

        // Create batch 2 (skipping 1)
        let batch2 = BatchMapCommit::new(&refs, "test", 2, now, now)
            .with_parent(&batch0.commit.commit_id, 0);

        // Gap MUST be detected
        let validation = batch2.validate_sequence();
        assert!(!validation.is_valid());
        assert!(matches!(validation, BatchSequenceValidation::GapDetected { gap_size: 1, .. }));
    }

    #[test]
    fn hard_invariant_batch_sequence_reversal_rejected() {
        use bridge::payload_map_commit::{BatchMapCommit, BatchSequenceValidation};

        let refs = vec![];
        let now = Utc::now();

        // Create batch claiming parent seq 10 but with seq 5 (reversal)
        let batch = BatchMapCommit::new(&refs, "test", 5, now, now)
            .with_parent("parent:001", 10);

        // Reversal MUST be detected
        let validation = batch.validate_sequence();
        assert!(!validation.is_valid());
        assert!(matches!(validation, BatchSequenceValidation::SequenceReversal { .. }));
    }

    // ========================================================================
    // HARD INVARIANT 6: Audit log MUST be written BEFORE operations
    // ========================================================================

    #[test]
    fn hard_invariant_audit_guard_state_machine() {
        use crate::types::audit_artifacts::{
            MandatoryAuditGuard, MandatoryAuditOperation, AuditGuardState,
        };

        // Create guard (simulating successful audit write)
        let mut guard = MandatoryAuditGuard::from_written_log(
            "audit:001".to_string(),
            MandatoryAuditOperation::Decrypt,
        );

        // Initially pending - can proceed
        assert_eq!(guard.state(), AuditGuardState::Pending);
        assert!(guard.can_proceed());

        // After completion - cannot proceed again
        guard.mark_completed();
        assert_eq!(guard.state(), AuditGuardState::Completed);
        assert!(!guard.can_proceed());
    }

    #[test]
    fn hard_invariant_audit_write_error_blocks_operation() {
        use crate::types::audit_artifacts::{AuditWriteError, AuditErrorCode, AuditWriteResult};

        // Simulate audit write failure
        let error = AuditWriteError::new(AuditErrorCode::StorageUnavailable, "Backend down");
        let result = AuditWriteResult::Failed { error };

        // Failed audit write MUST block operation
        assert!(!result.is_success());
        assert!(result.log_id().is_none());
    }

    // ========================================================================
    // HARD INVARIANT 7: Evidence level requires VERIFICATION
    // ========================================================================

    #[test]
    fn hard_invariant_evidence_needs_verification_not_just_existence() {
        let mut bundle = EvidenceBundle::new(
            "bundle:001".to_string(),
            "case:001".to_string(),
            ActorId::new("actor:001"),
            vec![],
        );

        // Set receipt and map_commit (existence)
        bundle.receipt_id = Some(ReceiptId("receipt:001".to_string()));
        bundle.map_commit_ref = Some("pmc:001".to_string());

        // WITHOUT verification, MUST still be B-level
        assert!(bundle.has_required_refs());
        assert_eq!(bundle.evidence_level(), EvidenceLevel::B);

        // Need to verify each component
        bundle.set_receipt_verified(true, None);
        assert_eq!(bundle.evidence_level(), EvidenceLevel::B);

        bundle.set_map_commit_reconciled(true, None);
        assert_eq!(bundle.evidence_level(), EvidenceLevel::B);

        bundle.set_payload_verification(true, true, 0);
        // NOW it can be A-level
        assert_eq!(bundle.evidence_level(), EvidenceLevel::A);
    }

    // ========================================================================
    // HARD INVARIANT 8: Storage temperature affects availability
    // ========================================================================

    #[test]
    fn hard_invariant_cold_storage_needs_preheat() {
        use crate::types::evidence_bundle::TemperatureImpact;

        let cold_ref = SealedPayloadRef {
            ref_id: "ref:cold".to_string(),
            checksum: Digest::zero(),
            encryption_meta_digest: Digest::zero(),
            access_policy_version: "v1".to_string(),
            format_version: Default::default(),
            size_bytes: 1024,
            status: SealedPayloadStatus::Active,
            temperature: StorageTemperature::Cold,
            created_at: Utc::now(),
            last_accessed_at: None,
            content_type: None,
            retention_policy_ref: None,
        };

        let impact = TemperatureImpact::from_refs(&[cold_ref]);

        // Cold storage MUST require preheat
        assert_eq!(impact.cold_count, 1);
        assert!(impact.needs_preheat());
        assert!(!impact.all_immediately_accessible);
    }

    // ========================================================================
    // HARD INVARIANT 9: P1 unavailability triggers degraded mode
    // ========================================================================

    #[tokio::test]
    async fn hard_invariant_p1_loss_triggers_degradation() {
        use crate::degraded_mode::{
            DegradedModeManager, P1ConnectionStatus, P1HealthStatus, DsnAvailabilityState,
        };

        let manager = DegradedModeManager::new();

        // Initially available
        assert!(!manager.is_degraded());

        // P1 goes down
        let p1_down = P1ConnectionStatus {
            connected: false,
            last_success: None,
            endpoint: None,
            health: P1HealthStatus::Unreachable,
            pending_operations: 0,
            last_error: Some("Connection refused".to_string()),
        };

        manager.update_p1_status(p1_down).await;

        // MUST be degraded now
        assert!(manager.is_degraded());

        let state = manager.get_state().await;
        assert!(matches!(state.state, DsnAvailabilityState::Degraded));
    }

    // ========================================================================
    // HARD INVARIANT 10: Unknown canonicalization version rejected
    // ========================================================================

    #[test]
    fn hard_invariant_unknown_canonicalization_rejected() {
        use bridge::canonicalization::{CanonicalizerRegistry, CanonicalizationError};
        use std::collections::BTreeMap;

        let registry = CanonicalizerRegistry::new();
        let data = b"test data";
        let metadata = BTreeMap::new();

        // Unknown version MUST be rejected
        let result = registry.canonicalize("unknown.version", data, &metadata);
        assert!(matches!(result, Err(CanonicalizationError::UnknownVersion(_))));
    }

    #[test]
    fn hard_invariant_known_canonicalization_works() {
        use bridge::canonicalization::CanonicalizerRegistry;
        use std::collections::BTreeMap;

        let registry = CanonicalizerRegistry::new();
        let data = b"test data";
        let metadata = BTreeMap::new();

        // Known version (1.0.0) should work
        let result = registry.canonicalize("1.0.0", data, &metadata);
        assert!(result.is_ok());
    }

    // ========================================================================
    // Additional Coverage: Combined invariants
    // ========================================================================

    #[test]
    fn combined_invariant_full_evidence_chain() {
        let mut bundle = EvidenceBundle::new(
            "bundle:full".to_string(),
            "case:full".to_string(),
            ActorId::new("actor:full"),
            vec![],
        );

        // Start at B-level
        assert_eq!(bundle.evidence_level(), EvidenceLevel::B);

        // Add required refs
        bundle.receipt_id = Some(ReceiptId("receipt:full".to_string()));
        bundle.map_commit_ref = Some("pmc:full".to_string());

        // Still B until verified
        assert_eq!(bundle.evidence_level(), EvidenceLevel::B);

        // Verify all components
        bundle.set_receipt_verified(true, None);
        bundle.set_map_commit_reconciled(true, None);
        bundle.set_payload_verification(true, true, 0);

        // NOW A-level
        assert_eq!(bundle.evidence_level(), EvidenceLevel::A);
        assert!(bundle.is_complete());
    }
}
