//! Snapshot Ledger Implementation
//!
//! Persistent storage for R0/R1 resurrection snapshots.

use async_trait::async_trait;
use chrono::Utc;
use l0_core::types::ActorId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::fs;
use tokio::sync::RwLock;

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

/// File-based snapshot ledger implementation
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
}

impl FileSnapshotLedger {
    /// Create a new file-based snapshot ledger
    pub async fn new(base_path: impl Into<PathBuf>) -> P2Result<Self> {
        let base_path = base_path.into();
        let r0_path = base_path.join("r0");
        let r1_path = base_path.join("r1");
        let index_path = base_path.join("index.json");

        // Create directories
        for path in [&base_path, &r0_path, &r1_path] {
            fs::create_dir_all(path).await.map_err(|e| {
                P2Error::Storage(format!("Failed to create directory {:?}: {}", path, e))
            })?;
        }

        // Load or create index
        let index_cache = if index_path.exists() {
            let data = fs::read_to_string(&index_path).await.map_err(|e| {
                P2Error::Storage(format!("Failed to read index: {}", e))
            })?;
            let entries: Vec<SnapshotIndexEntry> = serde_json::from_str(&data).unwrap_or_default();
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
        })
    }

    /// Save the index to disk
    async fn save_index(&self) -> P2Result<()> {
        let entries: Vec<_> = self
            .index_cache
            .read()
            .await
            .values()
            .cloned()
            .collect();

        let json = serde_json::to_string_pretty(&entries)
            .map_err(|e| P2Error::Storage(format!("Serialization error: {}", e)))?;

        fs::write(&self.index_path, json).await.map_err(|e| {
            P2Error::Storage(format!("Failed to write index: {}", e))
        })?;

        Ok(())
    }

    /// Get the file path for an R0 snapshot
    fn r0_file_path(&self, snapshot_id: &str) -> PathBuf {
        self.r0_path.join(format!("{}.json", snapshot_id))
    }

    /// Get the file path for an R1 snapshot
    fn r1_file_path(&self, snapshot_id: &str) -> PathBuf {
        self.r1_path.join(format!("{}.json", snapshot_id))
    }
}

#[async_trait]
impl SnapshotLedger for FileSnapshotLedger {
    async fn store_r0(&self, snapshot: SkeletonSnapshot) -> P2Result<String> {
        let snapshot_id = snapshot.snapshot_id.clone();
        let actor_id = snapshot.actor_id.0.clone();

        // Serialize and write
        let json = serde_json::to_string_pretty(&snapshot)
            .map_err(|e| P2Error::Storage(format!("Serialization error: {}", e)))?;

        let path = self.r0_file_path(&snapshot_id);
        fs::write(&path, json).await.map_err(|e| {
            P2Error::Storage(format!("Failed to write R0 snapshot: {}", e))
        })?;

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

        // Serialize and write
        let json = serde_json::to_string_pretty(&snapshot)
            .map_err(|e| P2Error::Storage(format!("Serialization error: {}", e)))?;

        let path = self.r1_file_path(&snapshot_id);
        fs::write(&path, json).await.map_err(|e| {
            P2Error::Storage(format!("Failed to write R1 snapshot: {}", e))
        })?;

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

        let json = fs::read_to_string(&path).await.map_err(|e| {
            P2Error::Storage(format!("Failed to read R0 snapshot: {}", e))
        })?;

        let snapshot: SkeletonSnapshot = serde_json::from_str(&json)
            .map_err(|e| P2Error::Storage(format!("Failed to parse R0 snapshot: {}", e)))?;

        Ok(Some(snapshot))
    }

    async fn get_r1(&self, snapshot_id: &str) -> P2Result<Option<FullResurrectionSnapshot>> {
        let path = self.r1_file_path(snapshot_id);
        if !path.exists() {
            return Ok(None);
        }

        let json = fs::read_to_string(&path).await.map_err(|e| {
            P2Error::Storage(format!("Failed to read R1 snapshot: {}", e))
        })?;

        let snapshot: FullResurrectionSnapshot = serde_json::from_str(&json)
            .map_err(|e| P2Error::Storage(format!("Failed to parse R1 snapshot: {}", e)))?;

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
        let ledger = FileSnapshotLedger::new(temp_dir.path()).await.unwrap();

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
        let ledger = FileSnapshotLedger::new(temp_dir.path()).await.unwrap();

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
        let ledger = FileSnapshotLedger::new(temp_dir.path()).await.unwrap();

        let snapshot = create_test_r0();
        let snapshot_id = snapshot.snapshot_id.clone();

        ledger.store_r0(snapshot).await.unwrap();

        assert!(ledger.verify_snapshot(&snapshot_id).await.unwrap());
        assert!(!ledger.verify_snapshot("nonexistent").await.unwrap());
    }
}
