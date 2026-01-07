//! Evidence Ledger Implementation
//!
//! Persistent storage for evidence bundles with P1 commitment tracking.
//! All data is encrypted at rest using the encrypted_storage module.

use async_trait::async_trait;
use chrono::Utc;
use l0_core::types::{ActorId, Digest, ReceiptId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::fs;
use tokio::sync::RwLock;

use super::encrypted_storage::{EncryptedStorage, EncryptedStorageConfig};
use super::traits::EvidenceLedger;
use crate::error::{P2Error, P2Result};
use crate::types::EvidenceBundle;

/// Index entry for evidence bundle lookup
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EvidenceIndexEntry {
    bundle_id: String,
    case_ref: String,
    submitter: String,
    created_at: chrono::DateTime<Utc>,
    has_receipt: bool,
    has_map_commit: bool,
}

/// File-based evidence ledger implementation with encryption at rest
pub struct FileEvidenceLedger {
    /// Base path for evidence storage
    base_path: PathBuf,
    /// Bundles directory
    bundles_path: PathBuf,
    /// Index path
    index_path: PathBuf,
    /// In-memory index cache
    index_cache: RwLock<HashMap<String, EvidenceIndexEntry>>,
    /// Encrypted storage handler
    storage: EncryptedStorage,
}

impl FileEvidenceLedger {
    /// Create a new file-based evidence ledger with default encryption
    pub async fn new(base_path: impl Into<PathBuf>) -> P2Result<Self> {
        Self::with_config(base_path, EncryptedStorageConfig::default()).await
    }

    /// Create with custom encryption config
    pub async fn with_config(
        base_path: impl Into<PathBuf>,
        encryption_config: EncryptedStorageConfig,
    ) -> P2Result<Self> {
        let base_path = base_path.into();
        let bundles_path = base_path.join("bundles");
        let index_path = base_path.join("evidence_index.enc");

        // Create directories
        for path in [&base_path, &bundles_path] {
            fs::create_dir_all(path).await.map_err(|e| {
                P2Error::Storage(format!("Failed to create directory {:?}: {}", path, e))
            })?;
        }

        let storage = EncryptedStorage::new(encryption_config);

        // Load or create index
        let index_cache = if index_path.exists() {
            let entries: Vec<EvidenceIndexEntry> = storage
                .read(&index_path, "evidence-ledger-index")
                .await
                .unwrap_or_default();
            let mut map = HashMap::new();
            for entry in entries {
                map.insert(entry.bundle_id.clone(), entry);
            }
            RwLock::new(map)
        } else {
            RwLock::new(HashMap::new())
        };

        Ok(Self {
            base_path,
            bundles_path,
            index_path,
            index_cache,
            storage,
        })
    }

    /// Create with encryption disabled (for testing only)
    #[cfg(test)]
    pub async fn unencrypted(base_path: impl Into<PathBuf>) -> P2Result<Self> {
        Self::with_config(base_path, EncryptedStorageConfig::unencrypted()).await
    }

    /// Save the index to disk (encrypted)
    async fn save_index(&self) -> P2Result<()> {
        let entries: Vec<_> = self
            .index_cache
            .read()
            .await
            .values()
            .cloned()
            .collect();

        self.storage
            .write(&self.index_path, &entries, "evidence-ledger-index")
            .await
    }

    /// Get the file path for a bundle
    fn bundle_file_path(&self, bundle_id: &str) -> PathBuf {
        self.bundles_path.join(format!("{}.enc", bundle_id))
    }

    /// Update bundle on disk (encrypted)
    async fn write_bundle(&self, bundle: &EvidenceBundle) -> P2Result<()> {
        let path = self.bundle_file_path(&bundle.bundle_id);
        self.storage
            .write(&path, bundle, &bundle.bundle_id)
            .await
    }
}

#[async_trait]
impl EvidenceLedger for FileEvidenceLedger {
    async fn create_bundle(&self, bundle: EvidenceBundle) -> P2Result<String> {
        let bundle_id = bundle.bundle_id.clone();

        // Write bundle to disk
        self.write_bundle(&bundle).await?;

        // Update index
        {
            let mut cache = self.index_cache.write().await;
            cache.insert(
                bundle_id.clone(),
                EvidenceIndexEntry {
                    bundle_id: bundle_id.clone(),
                    case_ref: bundle.case_ref.clone(),
                    submitter: bundle.submitter.0.clone(),
                    created_at: bundle.created_at,
                    has_receipt: bundle.receipt_id.is_some(),
                    has_map_commit: bundle.map_commit_ref.is_some(),
                },
            );
        }

        self.save_index().await?;

        Ok(bundle_id)
    }

    async fn get_bundle(&self, bundle_id: &str) -> P2Result<Option<EvidenceBundle>> {
        let path = self.bundle_file_path(bundle_id);
        if !path.exists() {
            return Ok(None);
        }

        let bundle: EvidenceBundle = self.storage.read(&path, bundle_id).await?;
        Ok(Some(bundle))
    }

    async fn list_bundles_for_case(
        &self,
        case_ref: &str,
        limit: usize,
    ) -> P2Result<Vec<EvidenceBundle>> {
        let entries = {
            let cache = self.index_cache.read().await;

            let mut entries: Vec<_> = cache
                .values()
                .filter(|e| e.case_ref == case_ref)
                .cloned()
                .collect();

            // Sort by created_at descending
            entries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            entries.truncate(limit);
            entries
        };

        let mut bundles = Vec::new();
        for entry in entries {
            if let Some(bundle) = self.get_bundle(&entry.bundle_id).await? {
                bundles.push(bundle);
            }
        }

        Ok(bundles)
    }

    async fn list_bundles_by_submitter(
        &self,
        submitter: &ActorId,
        limit: usize,
    ) -> P2Result<Vec<EvidenceBundle>> {
        let entries = {
            let cache = self.index_cache.read().await;

            let mut entries: Vec<_> = cache
                .values()
                .filter(|e| e.submitter == submitter.0)
                .cloned()
                .collect();

            // Sort by created_at descending
            entries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            entries.truncate(limit);
            entries
        };

        let mut bundles = Vec::new();
        for entry in entries {
            if let Some(bundle) = self.get_bundle(&entry.bundle_id).await? {
                bundles.push(bundle);
            }
        }

        Ok(bundles)
    }

    async fn set_bundle_receipt(
        &self,
        bundle_id: &str,
        receipt_id: ReceiptId,
    ) -> P2Result<()> {
        // Read current bundle
        let mut bundle = self.get_bundle(bundle_id).await?.ok_or_else(|| {
            P2Error::Storage(format!("Evidence bundle not found: {}", bundle_id))
        })?;

        // Update receipt
        bundle.receipt_id = Some(receipt_id);

        // Write back
        self.write_bundle(&bundle).await?;

        // Update index
        {
            let mut cache = self.index_cache.write().await;
            if let Some(entry) = cache.get_mut(bundle_id) {
                entry.has_receipt = true;
            }
        }

        self.save_index().await?;

        Ok(())
    }

    async fn set_bundle_map_commit(
        &self,
        bundle_id: &str,
        map_commit_ref: String,
    ) -> P2Result<()> {
        // Read current bundle
        let mut bundle = self.get_bundle(bundle_id).await?.ok_or_else(|| {
            P2Error::Storage(format!("Evidence bundle not found: {}", bundle_id))
        })?;

        // Update map_commit
        bundle.map_commit_ref = Some(map_commit_ref);

        // Write back
        self.write_bundle(&bundle).await?;

        // Update index
        {
            let mut cache = self.index_cache.write().await;
            if let Some(entry) = cache.get_mut(bundle_id) {
                entry.has_map_commit = true;
            }
        }

        self.save_index().await?;

        Ok(())
    }

    async fn verify_bundle(&self, bundle_id: &str, expected_digest: &Digest) -> P2Result<bool> {
        let bundle = match self.get_bundle(bundle_id).await? {
            Some(b) => b,
            None => return Ok(false),
        };

        Ok(bundle.verify_map_commit(expected_digest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SealedPayloadRef;
    use tempfile::TempDir;

    fn create_test_bundle() -> EvidenceBundle {
        EvidenceBundle::new(
            format!("bundle:{}", uuid::Uuid::new_v4()),
            "case:test".to_string(),
            ActorId::new("actor:submitter"),
            vec![SealedPayloadRef::new(
                "payload:001".to_string(),
                Digest::blake3(b"test"),
                Digest::blake3(b"encryption_meta"),
                1024,
            )],
        )
    }

    #[tokio::test]
    async fn test_create_and_get_bundle() {
        let temp_dir = TempDir::new().unwrap();
        let ledger = FileEvidenceLedger::unencrypted(temp_dir.path()).await.unwrap();

        let bundle = create_test_bundle();
        let bundle_id = bundle.bundle_id.clone();

        ledger.create_bundle(bundle.clone()).await.unwrap();

        let retrieved = ledger.get_bundle(&bundle_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().bundle_id, bundle_id);
    }

    #[tokio::test]
    async fn test_list_bundles_for_case() {
        let temp_dir = TempDir::new().unwrap();
        let ledger = FileEvidenceLedger::unencrypted(temp_dir.path()).await.unwrap();

        // Create multiple bundles for same case
        for _ in 0..3 {
            let bundle = create_test_bundle();
            ledger.create_bundle(bundle).await.unwrap();
        }

        let bundles = ledger.list_bundles_for_case("case:test", 10).await.unwrap();
        assert_eq!(bundles.len(), 3);
    }

    #[tokio::test]
    async fn test_set_bundle_receipt() {
        let temp_dir = TempDir::new().unwrap();
        let ledger = FileEvidenceLedger::unencrypted(temp_dir.path()).await.unwrap();

        let bundle = create_test_bundle();
        let bundle_id = bundle.bundle_id.clone();
        ledger.create_bundle(bundle).await.unwrap();

        // Initially no receipt
        let bundle = ledger.get_bundle(&bundle_id).await.unwrap().unwrap();
        assert!(bundle.receipt_id.is_none());

        // Set receipt
        ledger
            .set_bundle_receipt(&bundle_id, ReceiptId("receipt:001".to_string()))
            .await
            .unwrap();

        // Now has receipt
        let bundle = ledger.get_bundle(&bundle_id).await.unwrap().unwrap();
        assert!(bundle.receipt_id.is_some());
    }

    #[tokio::test]
    async fn test_verify_bundle() {
        let temp_dir = TempDir::new().unwrap();
        let ledger = FileEvidenceLedger::unencrypted(temp_dir.path()).await.unwrap();

        let bundle = create_test_bundle();
        let bundle_id = bundle.bundle_id.clone();
        let expected_digest = bundle.payload_refs_digest.clone();

        ledger.create_bundle(bundle).await.unwrap();

        // Verify with correct digest
        assert!(ledger.verify_bundle(&bundle_id, &expected_digest).await.unwrap());

        // Verify with wrong digest
        assert!(!ledger.verify_bundle(&bundle_id, &Digest::zero()).await.unwrap());
    }
}
