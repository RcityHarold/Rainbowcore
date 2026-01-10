//! Snapshot Ledger Implementation
//!
//! Persistent storage for R0/R1 resurrection snapshots.
//! All data is encrypted at rest using the encrypted_storage module.

use async_trait::async_trait;
use chrono::Utc;
use l0_core::types::ActorId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::fs;
use tokio::sync::RwLock;

use super::encrypted_storage::{EncryptedStorage, EncryptedStorageConfig};
use super::traits::SnapshotLedger;
use crate::error::{P2Error, P2Result};
use crate::types::{FullResurrectionSnapshot, SkeletonSnapshot};

/// Index entry for snapshot lookup
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotIndexEntry {
    snapshot_id: String,
    actor_id: String,
    created_at: chrono::DateTime<Utc>,
    snapshot_type: SnapshotIndexType,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum SnapshotIndexType {
    R0,
    R1,
}

/// File-based snapshot ledger implementation with encryption at rest
pub struct FileSnapshotLedger {
    /// Base path for snapshot storage
    base_path: PathBuf,
    /// R0 snapshots directory
    r0_path: PathBuf,
    /// R1 snapshots directory
    r1_path: PathBuf,
    /// Index path
    index_path: PathBuf,
    /// In-memory index cache
    index_cache: RwLock<HashMap<String, SnapshotIndexEntry>>,
    /// Encrypted storage handler
    storage: EncryptedStorage,
}

impl FileSnapshotLedger {
    /// Create a new file-based snapshot ledger with default encryption
    pub async fn new(base_path: impl Into<PathBuf>) -> P2Result<Self> {
        Self::with_config(base_path, EncryptedStorageConfig::default()).await
    }

    /// Create with custom encryption config
    pub async fn with_config(
        base_path: impl Into<PathBuf>,
        encryption_config: EncryptedStorageConfig,
    ) -> P2Result<Self> {
        let base_path = base_path.into();
        let r0_path = base_path.join("r0");
        let r1_path = base_path.join("r1");
        let index_path = base_path.join("index.enc");

        // Create directories
        for path in [&base_path, &r0_path, &r1_path] {
            fs::create_dir_all(path).await.map_err(|e| {
                P2Error::Storage(format!("Failed to create directory {:?}: {}", path, e))
            })?;
        }

        let storage = EncryptedStorage::new(encryption_config);

        // Load or create index
        let index_cache = if index_path.exists() {
            let entries: Vec<SnapshotIndexEntry> = storage
                .read(&index_path, "snapshot-ledger-index")
                .await
                .unwrap_or_default();
            let mut map = HashMap::new();
            for entry in entries {
                map.insert(entry.snapshot_id.clone(), entry);
            }
            RwLock::new(map)
        } else {
            RwLock::new(HashMap::new())
        };

        Ok(Self {
            base_path,
            r0_path,
            r1_path,
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
            .write(&self.index_path, &entries, "snapshot-ledger-index")
            .await
    }

    /// Get the file path for an R0 snapshot
    fn r0_file_path(&self, snapshot_id: &str) -> PathBuf {
        self.r0_path.join(format!("{}.enc", snapshot_id))
    }

    /// Get the file path for an R1 snapshot
    fn r1_file_path(&self, snapshot_id: &str) -> PathBuf {
        self.r1_path.join(format!("{}.enc", snapshot_id))
    }
}

#[async_trait]
impl SnapshotLedger for FileSnapshotLedger {
    async fn store_r0(&self, snapshot: SkeletonSnapshot) -> P2Result<String> {
        let snapshot_id = snapshot.snapshot_id.clone();
        let actor_id = snapshot.actor_id.0.clone();

        // Write encrypted snapshot
        let path = self.r0_file_path(&snapshot_id);
        self.storage.write(&path, &snapshot, &snapshot_id).await?;

        // Update index
        {
            let mut cache = self.index_cache.write().await;
            cache.insert(
                snapshot_id.clone(),
                SnapshotIndexEntry {
                    snapshot_id: snapshot_id.clone(),
                    actor_id,
                    created_at: snapshot.generated_at,
                    snapshot_type: SnapshotIndexType::R0,
                },
            );
        }

        self.save_index().await?;

        Ok(snapshot_id)
    }

    async fn store_r1(&self, snapshot: FullResurrectionSnapshot) -> P2Result<String> {
        let snapshot_id = snapshot.snapshot_id.clone();
        let actor_id = snapshot.actor_id.0.clone();

        // Write encrypted snapshot
        let path = self.r1_file_path(&snapshot_id);
        self.storage.write(&path, &snapshot, &snapshot_id).await?;

        // Update index
        {
            let mut cache = self.index_cache.write().await;
            cache.insert(
                snapshot_id.clone(),
                SnapshotIndexEntry {
                    snapshot_id: snapshot_id.clone(),
                    actor_id,
                    created_at: snapshot.generated_at,
                    snapshot_type: SnapshotIndexType::R1,
                },
            );
        }

        self.save_index().await?;

        Ok(snapshot_id)
    }

    async fn get_r0(&self, snapshot_id: &str) -> P2Result<Option<SkeletonSnapshot>> {
        let path = self.r0_file_path(snapshot_id);
        if !path.exists() {
            return Ok(None);
        }

        let snapshot: SkeletonSnapshot = self.storage.read(&path, snapshot_id).await?;
        Ok(Some(snapshot))
    }

    async fn get_r1(&self, snapshot_id: &str) -> P2Result<Option<FullResurrectionSnapshot>> {
        let path = self.r1_file_path(snapshot_id);
        if !path.exists() {
            return Ok(None);
        }

        let snapshot: FullResurrectionSnapshot = self.storage.read(&path, snapshot_id).await?;
        Ok(Some(snapshot))
    }

    async fn list_r0_for_actor(
        &self,
        actor_id: &ActorId,
        limit: usize,
    ) -> P2Result<Vec<SkeletonSnapshot>> {
        let entries = {
            let cache = self.index_cache.read().await;

            let mut entries: Vec<_> = cache
                .values()
                .filter(|e| {
                    e.actor_id == actor_id.0 && matches!(e.snapshot_type, SnapshotIndexType::R0)
                })
                .cloned()
                .collect();

            // Sort by created_at descending
            entries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            entries.truncate(limit);
            entries
        };

        let mut snapshots = Vec::new();
        for entry in entries {
            if let Some(snapshot) = self.get_r0(&entry.snapshot_id).await? {
                snapshots.push(snapshot);
            }
        }

        Ok(snapshots)
    }

    async fn list_r1_for_actor(
        &self,
        actor_id: &ActorId,
        limit: usize,
    ) -> P2Result<Vec<FullResurrectionSnapshot>> {
        let entries = {
            let cache = self.index_cache.read().await;

            let mut entries: Vec<_> = cache
                .values()
                .filter(|e| {
                    e.actor_id == actor_id.0 && matches!(e.snapshot_type, SnapshotIndexType::R1)
                })
                .cloned()
                .collect();

            // Sort by created_at descending
            entries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            entries.truncate(limit);
            entries
        };

        let mut snapshots = Vec::new();
        for entry in entries {
            if let Some(snapshot) = self.get_r1(&entry.snapshot_id).await? {
                snapshots.push(snapshot);
            }
        }

        Ok(snapshots)
    }

    async fn get_latest_r0(&self, actor_id: &ActorId) -> P2Result<Option<SkeletonSnapshot>> {
        let snapshots = self.list_r0_for_actor(actor_id, 1).await?;
        Ok(snapshots.into_iter().next())
    }

    async fn get_latest_r1(&self, actor_id: &ActorId) -> P2Result<Option<FullResurrectionSnapshot>> {
        let snapshots = self.list_r1_for_actor(actor_id, 1).await?;
        Ok(snapshots.into_iter().next())
    }

    async fn verify_snapshot(&self, snapshot_id: &str) -> P2Result<bool> {
        // Check if it exists in either R0 or R1
        let entry = {
            let cache = self.index_cache.read().await;
            match cache.get(snapshot_id) {
                Some(e) => e.clone(),
                None => return Ok(false),
            }
        };

        // Verify the file exists and is valid JSON
        match entry.snapshot_type {
            SnapshotIndexType::R0 => {
                let snapshot = self.get_r0(snapshot_id).await?;
                Ok(snapshot.is_some())
            }
            SnapshotIndexType::R1 => {
                let snapshot = self.get_r1(snapshot_id).await?;
                Ok(snapshot.is_some())
            }
        }
    }

    async fn set_snapshot_map_commit(
        &self,
        snapshot_id: &str,
        map_commit_ref: String,
    ) -> P2Result<()> {
        // Check if R0 or R1 based on index
        let snapshot_type = {
            let cache = self.index_cache.read().await;
            cache
                .get(snapshot_id)
                .map(|e| e.snapshot_type)
                .ok_or_else(|| P2Error::Storage(format!("Snapshot not found: {}", snapshot_id)))?
        };

        match snapshot_type {
            SnapshotIndexType::R0 => {
                // Read snapshot
                let mut snapshot = self
                    .get_r0(snapshot_id)
                    .await?
                    .ok_or_else(|| P2Error::Storage(format!("R0 snapshot not found: {}", snapshot_id)))?;

                // Update map_commit_ref
                snapshot.map_commit_ref.payload_map_commit_ref = map_commit_ref;

                // Write back
                let path = self.r0_file_path(snapshot_id);
                self.storage.write(&path, &snapshot, snapshot_id).await?;

                Ok(())
            }
            SnapshotIndexType::R1 => {
                // R1 snapshots don't have map_commit_ref in the same way
                // For now, just return Ok (could add this field to R1 later if needed)
                Ok(())
            }
        }
    }

    async fn set_snapshot_receipt(
        &self,
        snapshot_id: &str,
        receipt_id: l0_core::types::ReceiptId,
    ) -> P2Result<()> {
        // Check if R0 or R1 based on index
        let snapshot_type = {
            let cache = self.index_cache.read().await;
            cache
                .get(snapshot_id)
                .map(|e| e.snapshot_type)
                .ok_or_else(|| P2Error::Storage(format!("Snapshot not found: {}", snapshot_id)))?
        };

        match snapshot_type {
            SnapshotIndexType::R0 => {
                // Read snapshot
                let mut snapshot = self
                    .get_r0(snapshot_id)
                    .await?
                    .ok_or_else(|| P2Error::Storage(format!("R0 snapshot not found: {}", snapshot_id)))?;

                // Update receipt_id
                snapshot.receipt_id = Some(receipt_id);

                // Write back
                let path = self.r0_file_path(snapshot_id);
                self.storage.write(&path, &snapshot, snapshot_id).await?;

                Ok(())
            }
            SnapshotIndexType::R1 => {
                // Read snapshot
                let mut snapshot = self
                    .get_r1(snapshot_id)
                    .await?
                    .ok_or_else(|| P2Error::Storage(format!("R1 snapshot not found: {}", snapshot_id)))?;

                // Update receipt_id
                snapshot.receipt_id = Some(receipt_id);

                // Write back
                let path = self.r1_file_path(snapshot_id);
                self.storage.write(&path, &snapshot, snapshot_id).await?;

                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        ContinuitySkeleton, ContinuityState, GovernanceStateSkeleton, MapCommitRef,
        MinimalRelationshipSkeleton, R0Trigger, SkeletonManifest, SubjectProof,
    };
    use l0_core::types::Digest;
    use tempfile::TempDir;

    fn create_test_r0() -> SkeletonSnapshot {
        SkeletonSnapshot {
            snapshot_id: format!("r0:{}", uuid::Uuid::new_v4()),
            package_digest: Digest::blake3(b"test"),
            actor_id: ActorId::new("actor:test"),
            issuer_node_id: "node:test".to_string(),
            subject_proof: SubjectProof {
                subject_onset_anchor_ref: "anchor:test".to_string(),
                subject_stage: "created".to_string(),
                stage_digest: Digest::blake3(b"stage"),
            },
            continuity_skeleton: ContinuitySkeleton {
                ac_sequence_skeleton_digest: Digest::zero(),
                tip_witness_refs_digest: Digest::zero(),
                continuity_state: ContinuityState::Pass,
            },
            governance_skeleton: GovernanceStateSkeleton {
                in_repair: false,
                active_penalties_digest: None,
                constraints: vec![],
                pending_cases_refs: vec![],
            },
            relationship_skeleton: MinimalRelationshipSkeleton {
                org_membership_digest: None,
                group_membership_digest: None,
                relationship_structure_digest: Digest::zero(),
            },
            map_commit_ref: MapCommitRef {
                payload_map_commit_ref: "pmc:test".to_string(),
                sealed_payload_refs_digest: Digest::zero(),
            },
            msn_payload_ref: None,
            boot_config: None,
            payload_refs: vec![],
            payload_refs_digest: Digest::zero(),
            manifest: SkeletonManifest {
                version: "v1".to_string(),
                shards: vec![],
                generation_reason: "test".to_string(),
                coverage_scope: "full".to_string(),
                missing_payloads: vec![],
            },
            trigger: R0Trigger::SubjectOnset,
            generated_at: Utc::now(),
            policy_version: "v1".to_string(),
        }
    }

    #[tokio::test]
    async fn test_store_and_get_r0() {
        let temp_dir = TempDir::new().unwrap();
        let ledger = FileSnapshotLedger::unencrypted(temp_dir.path()).await.unwrap();

        let snapshot = create_test_r0();
        let snapshot_id = snapshot.snapshot_id.clone();

        ledger.store_r0(snapshot.clone()).await.unwrap();

        let retrieved = ledger.get_r0(&snapshot_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().snapshot_id, snapshot_id);
    }

    #[tokio::test]
    async fn test_list_r0_for_actor() {
        let temp_dir = TempDir::new().unwrap();
        let ledger = FileSnapshotLedger::unencrypted(temp_dir.path()).await.unwrap();

        // Store multiple snapshots for same actor
        for _ in 0..3 {
            let snapshot = create_test_r0();
            ledger.store_r0(snapshot).await.unwrap();
        }

        let actor_id = ActorId::new("actor:test");
        let snapshots = ledger.list_r0_for_actor(&actor_id, 10).await.unwrap();
        assert_eq!(snapshots.len(), 3);
    }

    #[tokio::test]
    async fn test_verify_snapshot() {
        let temp_dir = TempDir::new().unwrap();
        let ledger = FileSnapshotLedger::unencrypted(temp_dir.path()).await.unwrap();

        let snapshot = create_test_r0();
        let snapshot_id = snapshot.snapshot_id.clone();

        ledger.store_r0(snapshot).await.unwrap();

        assert!(ledger.verify_snapshot(&snapshot_id).await.unwrap());
        assert!(!ledger.verify_snapshot("nonexistent").await.unwrap());
    }
}
