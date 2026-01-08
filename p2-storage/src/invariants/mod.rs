//! P2 Hard Invariants Enforcement
//!
//! This module enforces the critical hard invariants for P2 storage:
//!
//! 1. **Append-Only**: No direct overwrites, deletions only via tombstone
//! 2. **Zero-Plaintext**: P2 only stores encrypted data (ciphertext)
//! 3. **Non-Platform**: All assertions must be third-party verifiable
//!
//! All storage operations MUST go through this module to ensure invariants are enforced.

pub mod append_only;
pub mod ciphertext_validator;
pub mod deletion_guard;
pub mod audit_logger;

pub use append_only::{AppendOnlyGuard, AppendOnlyError, AppendOnlyResult, WriteOperation, WriteCheckResult};
pub use ciphertext_validator::{CiphertextValidator, CiphertextError, CiphertextValidation, EncryptionFormat};
pub use deletion_guard::{DeletionGuard, DeletionError, DeletionRequest, DeletionResult, TombstoneRecord, ExistenceProof};
pub use audit_logger::{InvariantAuditLogger, InvariantAuditEntry, InvariantViolationType, AuditSeverity};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use l0_core::types::Digest;
use p2_core::types::{SealedPayloadRef, StorageTemperature};
use serde::{Deserialize, Serialize};

use crate::backend::{P2StorageBackend, WriteMetadata, PayloadMetadata};
use crate::error::{StorageError, StorageResult};

/// Invariant-enforced storage wrapper
///
/// This wrapper ensures all storage operations comply with P2's hard invariants.
/// It wraps any P2StorageBackend and adds invariant checking.
pub struct InvariantEnforcedStorage<B: P2StorageBackend> {
    /// The underlying storage backend
    inner: B,
    /// Append-only guard
    append_only_guard: AppendOnlyGuard,
    /// Ciphertext validator
    ciphertext_validator: CiphertextValidator,
    /// Deletion guard
    deletion_guard: DeletionGuard,
    /// Audit logger
    audit_logger: InvariantAuditLogger,
    /// Configuration
    config: InvariantConfig,
}

/// Invariant enforcement configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantConfig {
    /// Enable strict ciphertext validation
    pub strict_ciphertext_validation: bool,
    /// Minimum ciphertext size (bytes)
    pub min_ciphertext_size: usize,
    /// Enable audit logging for all operations
    pub audit_all_operations: bool,
    /// Fail on audit log write failure
    pub fail_on_audit_error: bool,
    /// Supported encryption formats
    pub supported_formats: Vec<String>,
}

impl Default for InvariantConfig {
    fn default() -> Self {
        Self {
            strict_ciphertext_validation: true,
            min_ciphertext_size: 32, // Minimum encrypted payload size
            audit_all_operations: true,
            fail_on_audit_error: true,
            supported_formats: vec![
                "AES-256-GCM".to_string(),
                "ChaCha20-Poly1305".to_string(),
                "P2-ENVELOPE-V1".to_string(),
            ],
        }
    }
}

impl<B: P2StorageBackend> InvariantEnforcedStorage<B> {
    /// Create a new invariant-enforced storage wrapper
    pub fn new(inner: B, config: InvariantConfig) -> Self {
        Self {
            inner,
            append_only_guard: AppendOnlyGuard::new(),
            ciphertext_validator: CiphertextValidator::new(
                config.strict_ciphertext_validation,
                config.min_ciphertext_size,
            ),
            deletion_guard: DeletionGuard::new(),
            audit_logger: InvariantAuditLogger::new(),
            config,
        }
    }

    /// Create with default configuration
    pub fn with_defaults(inner: B) -> Self {
        Self::new(inner, InvariantConfig::default())
    }

    /// Get reference to inner backend
    pub fn inner(&self) -> &B {
        &self.inner
    }

    /// Get mutable reference to inner backend
    pub fn inner_mut(&mut self) -> &mut B {
        &mut self.inner
    }

    /// Log an invariant violation
    async fn log_violation(&self, violation_type: InvariantViolationType, details: &str) {
        let entry = InvariantAuditEntry::violation(violation_type, details);
        if let Err(e) = self.audit_logger.log(entry).await {
            tracing::error!("Failed to log invariant violation: {}", e);
        }
    }

    /// Log a successful operation
    async fn log_operation(&self, operation: &str, ref_id: &str) {
        if self.config.audit_all_operations {
            let entry = InvariantAuditEntry::operation(operation, ref_id);
            if let Err(e) = self.audit_logger.log(entry).await {
                tracing::warn!("Failed to log operation: {}", e);
            }
        }
    }
}

#[async_trait]
impl<B: P2StorageBackend> P2StorageBackend for InvariantEnforcedStorage<B> {
    async fn write(&self, data: &[u8], metadata: WriteMetadata) -> StorageResult<SealedPayloadRef> {
        // INVARIANT 1: Validate ciphertext (Zero-Plaintext)
        let validation = self.ciphertext_validator.validate(data);
        if !validation.is_valid {
            self.log_violation(
                InvariantViolationType::PlaintextDetected,
                &validation.reason.unwrap_or_default(),
            ).await;
            return Err(StorageError::WriteFailed(
                "INVARIANT VIOLATION: Data does not appear to be encrypted. P2 only stores ciphertext.".to_string()
            ));
        }

        // INVARIANT 2: Check append-only (compute ref_id first)
        let checksum = Digest::blake3(data);
        let ref_id = format!("local:{}", &checksum.to_hex()[..32]);

        let write_op = WriteOperation {
            ref_id: ref_id.clone(),
            data_hash: checksum.clone(),
            size_bytes: data.len() as u64,
            timestamp: Utc::now(),
        };

        if let Err(e) = self.append_only_guard.check_write(&self.inner, &write_op).await {
            self.log_violation(
                InvariantViolationType::OverwriteAttempt,
                &format!("ref_id: {}, error: {}", ref_id, e),
            ).await;
            return Err(StorageError::WriteFailed(
                format!("INVARIANT VIOLATION: {}", e)
            ));
        }

        // Proceed with write
        let result = self.inner.write(data, metadata).await;

        // Log successful write
        if let Ok(ref payload_ref) = result {
            self.log_operation("write", &payload_ref.ref_id).await;
        }

        result
    }

    async fn read(&self, ref_id: &str) -> StorageResult<Vec<u8>> {
        let result = self.inner.read(ref_id).await;

        if result.is_ok() {
            self.log_operation("read", ref_id).await;
        }

        result
    }

    async fn exists(&self, ref_id: &str) -> StorageResult<bool> {
        self.inner.exists(ref_id).await
    }

    async fn get_metadata(&self, ref_id: &str) -> StorageResult<PayloadMetadata> {
        self.inner.get_metadata(ref_id).await
    }

    async fn tombstone(&self, ref_id: &str) -> StorageResult<()> {
        // INVARIANT 3: Deletion only via tombstone with audit
        let request = DeletionRequest {
            ref_id: ref_id.to_string(),
            reason: "tombstone_request".to_string(),
            requestor: "system".to_string(),
            timestamp: Utc::now(),
        };

        // Validate and record the deletion request
        let tombstone_record = self.deletion_guard.process_deletion(&self.inner, request).await
            .map_err(|e| {
                StorageError::OperationFailed(format!("Deletion guard rejected: {}", e))
            })?;

        // Proceed with tombstone
        let result = self.inner.tombstone(ref_id).await;

        // Log tombstone operation
        if result.is_ok() {
            self.log_operation("tombstone", ref_id).await;
            tracing::info!(
                "Tombstone executed: ref_id={}, record_id={}",
                ref_id,
                tombstone_record.record_id
            );
        }

        result
    }

    async fn migrate_temperature(
        &self,
        ref_id: &str,
        target_temp: StorageTemperature,
    ) -> StorageResult<SealedPayloadRef> {
        // Temperature migration is allowed (not a content modification)
        let result = self.inner.migrate_temperature(ref_id, target_temp).await;

        if result.is_ok() {
            self.log_operation("migrate_temperature", ref_id).await;
        }

        result
    }

    async fn verify_integrity(&self, ref_id: &str) -> StorageResult<crate::backend::IntegrityResult> {
        self.inner.verify_integrity(ref_id).await
    }

    fn backend_type(&self) -> crate::backend::BackendType {
        self.inner.backend_type()
    }

    fn capabilities(&self) -> crate::backend::BackendCapabilities {
        self.inner.capabilities()
    }

    async fn health_check(&self) -> StorageResult<crate::backend::HealthStatus> {
        self.inner.health_check().await
    }
}

/// Invariant check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantCheckResult {
    /// All invariants passed
    pub passed: bool,
    /// Individual check results
    pub checks: Vec<InvariantCheck>,
    /// Check timestamp
    pub checked_at: DateTime<Utc>,
}

/// Individual invariant check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantCheck {
    /// Invariant name
    pub name: String,
    /// Check passed
    pub passed: bool,
    /// Details
    pub details: Option<String>,
}

impl InvariantCheckResult {
    /// Create a passing result
    pub fn pass() -> Self {
        Self {
            passed: true,
            checks: vec![
                InvariantCheck {
                    name: "append_only".to_string(),
                    passed: true,
                    details: None,
                },
                InvariantCheck {
                    name: "zero_plaintext".to_string(),
                    passed: true,
                    details: None,
                },
                InvariantCheck {
                    name: "non_platform".to_string(),
                    passed: true,
                    details: None,
                },
            ],
            checked_at: Utc::now(),
        }
    }

    /// Create a failing result
    pub fn fail(failed_check: &str, reason: &str) -> Self {
        Self {
            passed: false,
            checks: vec![
                InvariantCheck {
                    name: failed_check.to_string(),
                    passed: false,
                    details: Some(reason.to_string()),
                },
            ],
            checked_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invariant_config_default() {
        let config = InvariantConfig::default();
        assert!(config.strict_ciphertext_validation);
        assert!(config.audit_all_operations);
        assert_eq!(config.min_ciphertext_size, 32);
    }

    #[test]
    fn test_invariant_check_result() {
        let pass = InvariantCheckResult::pass();
        assert!(pass.passed);
        assert_eq!(pass.checks.len(), 3);

        let fail = InvariantCheckResult::fail("append_only", "overwrite detected");
        assert!(!fail.passed);
    }
}
