//! Knowledge-Index Ledger Service Implementation
//!
//! Implements the KnowledgeLedger trait using l0-db repositories.
//! Zero-plaintext content indexing for the L0 ledger.

use async_trait::async_trait;
use chrono::Utc;
use l0_core::crypto::IncrementalMerkleTree;
use l0_core::error::LedgerError;
use l0_core::ledger::{
    CrossReference, IndexEntryType, KnowledgeIndexEntry, KnowledgeLedger, Ledger, LedgerResult,
    QueryOptions,
};
use l0_core::types::{ActorId, AnchoringState, Digest, EvidenceLevel, ReceiptId, SpaceId};
use soulbase_storage::model::Entity;
use soulbase_storage::surreal::SurrealDatastore;
use soulbase_storage::Datastore;
use soulbase_types::prelude::TenantId;
use std::sync::Arc;

use crate::entities::{CrossReferenceEntity, KnowledgeIndexEntity};

/// Knowledge-Index Ledger Service
pub struct KnowledgeService {
    datastore: Arc<SurrealDatastore>,
    tenant_id: TenantId,
    sequence: std::sync::atomic::AtomicU64,
}

impl KnowledgeService {
    /// Create a new Knowledge Service
    pub fn new(datastore: Arc<SurrealDatastore>, tenant_id: TenantId) -> Self {
        Self {
            datastore,
            tenant_id,
            sequence: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Generate a new entry ID
    fn generate_entry_id(&self) -> String {
        let seq = self
            .sequence
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let timestamp = Utc::now().timestamp_micros();
        format!("kidx_{:016x}_{:08x}", timestamp, seq)
    }

    /// Convert string to IndexEntryType
    fn str_to_entry_type(s: &str) -> IndexEntryType {
        match s {
            "content_digest" => IndexEntryType::ContentDigest,
            "relation_digest" => IndexEntryType::RelationDigest,
            "aggregate_digest" => IndexEntryType::AggregateDigest,
            "scene_digest" => IndexEntryType::SceneDigest,
            _ => IndexEntryType::ContentDigest,
        }
    }

    /// Convert IndexEntryType to string
    fn entry_type_to_str(t: IndexEntryType) -> &'static str {
        match t {
            IndexEntryType::ContentDigest => "content_digest",
            IndexEntryType::RelationDigest => "relation_digest",
            IndexEntryType::AggregateDigest => "aggregate_digest",
            IndexEntryType::SceneDigest => "scene_digest",
        }
    }

    /// Convert string to EvidenceLevel
    fn str_to_evidence_level(s: &str) -> EvidenceLevel {
        match s {
            "a" => EvidenceLevel::A,
            "b" => EvidenceLevel::B,
            _ => EvidenceLevel::B,
        }
    }

    /// Convert EvidenceLevel to string
    fn evidence_level_to_str(level: EvidenceLevel) -> &'static str {
        match level {
            EvidenceLevel::A => "a",
            EvidenceLevel::B => "b",
        }
    }

    /// Convert string to AnchoringState
    fn str_to_anchoring_state(s: &str) -> AnchoringState {
        match s {
            "local_unconfirmed" => AnchoringState::LocalUnconfirmed,
            "anchored" => AnchoringState::Anchored,
            _ => AnchoringState::LocalUnconfirmed,
        }
    }

    /// Convert AnchoringState to string
    fn anchoring_state_to_str(state: AnchoringState) -> &'static str {
        match state {
            AnchoringState::LocalUnconfirmed => "local_unconfirmed",
            AnchoringState::Anchored => "anchored",
        }
    }

    /// Convert entity to domain model
    fn entity_to_entry(entity: &KnowledgeIndexEntity) -> KnowledgeIndexEntry {
        KnowledgeIndexEntry {
            entry_id: entity.entry_id.clone(),
            entry_type: Self::str_to_entry_type(&entity.entry_type),
            content_digest: Digest::from_hex(&entity.content_digest).unwrap_or_default(),
            parent_digest: entity
                .parent_digest
                .as_ref()
                .and_then(|d| Digest::from_hex(d).ok()),
            space_id: entity.space_id.as_ref().map(|s| SpaceId(s.clone())),
            owner_actor_id: ActorId(entity.owner_actor_id.clone()),
            created_at: entity.created_at,
            evidence_level: Self::str_to_evidence_level(&entity.evidence_level),
            anchoring_state: Self::str_to_anchoring_state(&entity.anchoring_state),
            receipt_id: entity.receipt_id.as_ref().map(|r| ReceiptId(r.clone())),
        }
    }

    /// Convert entity to cross-reference domain model
    fn entity_to_crossref(entity: &CrossReferenceEntity) -> CrossReference {
        CrossReference {
            ref_id: entity.ref_id.clone(),
            source_digest: Digest::from_hex(&entity.source_digest).unwrap_or_default(),
            target_digest: Digest::from_hex(&entity.target_digest).unwrap_or_default(),
            ref_type: entity.ref_type.clone(),
            created_at: entity.created_at,
            receipt_id: entity.receipt_id.as_ref().map(|r| ReceiptId(r.clone())),
        }
    }

    /// Query knowledge index entries
    async fn query_entries(&self, where_clause: &str, limit: u32) -> LedgerResult<Vec<KnowledgeIndexEntity>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant {} ORDER BY created_at DESC LIMIT {}",
            KnowledgeIndexEntity::TABLE,
            where_clause,
            limit
        );

        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let results: Vec<KnowledgeIndexEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        Ok(results)
    }

    /// Create knowledge index entry
    async fn create_entry(&self, entity: KnowledgeIndexEntity) -> LedgerResult<KnowledgeIndexEntity> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        // Create the entity first
        let create_query = format!("CREATE {} CONTENT $data", KnowledgeIndexEntity::TABLE);
        let entry_id = entity.entry_id.clone();

        session
            .client()
            .query(&create_query)
            .bind(("data", entity))
            .await
            .map_err(|e| LedgerError::Storage(format!("Create failed: {}", e)))?;

        // Fetch with type::string(id) to convert Thing to String
        let select_query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE entry_id = $entry_id LIMIT 1",
            KnowledgeIndexEntity::TABLE
        );

        let mut response = session
            .client()
            .query(&select_query)
            .bind(("entry_id", entry_id))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let result: Option<KnowledgeIndexEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        result.ok_or_else(|| LedgerError::Storage("Create returned no result".to_string()))
    }
}

#[async_trait]
impl Ledger for KnowledgeService {
    fn name(&self) -> &'static str {
        "knowledge"
    }

    async fn current_sequence(&self) -> LedgerResult<u64> {
        Ok(self.sequence.load(std::sync::atomic::Ordering::SeqCst))
    }

    async fn current_root(&self) -> LedgerResult<Digest> {
        // Query all knowledge index entries for this tenant
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant ORDER BY created_at ASC",
            KnowledgeIndexEntity::TABLE
        );

        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let entries: Vec<KnowledgeIndexEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        if entries.is_empty() {
            return Ok(Digest::zero());
        }

        // Compute Merkle root from all entries
        let mut tree = IncrementalMerkleTree::new();
        for entry in &entries {
            // Compute digest from entry data: entry_id + content_digest + entry_type + owner
            let entry_data = format!(
                "{}:{}:{}:{}",
                entry.entry_id, entry.content_digest, entry.entry_type, entry.owner_actor_id
            );
            let digest = Digest::blake3(entry_data.as_bytes());
            tree.add(digest);
        }

        Ok(tree.root())
    }

    async fn verify_integrity(&self) -> LedgerResult<bool> {
        // Query all knowledge index entries for this tenant
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant",
            KnowledgeIndexEntity::TABLE
        );

        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let entries: Vec<KnowledgeIndexEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        // Verify integrity by checking:
        // 1. No duplicate entry_ids
        // 2. All required fields are present
        // 3. Valid entry_type and evidence_level values
        let mut seen_ids = std::collections::HashSet::new();
        for entry in &entries {
            // Check for duplicate entry_ids
            if !seen_ids.insert(&entry.entry_id) {
                return Ok(false);
            }

            // Check required fields are not empty
            if entry.entry_id.is_empty()
                || entry.content_digest.is_empty()
                || entry.entry_type.is_empty()
                || entry.owner_actor_id.is_empty()
            {
                return Ok(false);
            }

            // Validate entry_type
            if !["content_digest", "relation_digest", "aggregate_digest", "scene_digest"]
                .contains(&entry.entry_type.as_str())
            {
                return Ok(false);
            }

            // Validate evidence_level
            if !["a", "b"].contains(&entry.evidence_level.as_str()) {
                return Ok(false);
            }

            // Validate anchoring_state
            if !["local_unconfirmed", "anchored"].contains(&entry.anchoring_state.as_str()) {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

#[async_trait]
impl KnowledgeLedger for KnowledgeService {
    async fn index_content(
        &self,
        content_digest: Digest,
        owner_actor_id: &ActorId,
        space_id: Option<&SpaceId>,
        parent_digest: Option<Digest>,
    ) -> LedgerResult<KnowledgeIndexEntry> {
        let entry_id = self.generate_entry_id();

        let mut entity = KnowledgeIndexEntity::new(
            self.tenant_id.clone(),
            entry_id,
            Self::entry_type_to_str(IndexEntryType::ContentDigest).to_string(),
            content_digest.to_hex(),
            owner_actor_id.0.clone(),
        );

        entity.space_id = space_id.map(|s| s.0.clone());
        entity.parent_digest = parent_digest.map(|d| d.to_hex());

        let created = self.create_entry(entity).await?;
        Ok(Self::entity_to_entry(&created))
    }

    async fn get_entry(&self, entry_id: &str) -> LedgerResult<Option<KnowledgeIndexEntry>> {
        let entries = self
            .query_entries(&format!("AND entry_id = '{}'", entry_id), 1)
            .await?;
        Ok(entries.first().map(Self::entity_to_entry))
    }

    async fn get_entries_by_digest(
        &self,
        content_digest: &Digest,
    ) -> LedgerResult<Vec<KnowledgeIndexEntry>> {
        let entries = self
            .query_entries(
                &format!("AND content_digest = '{}'", content_digest.to_hex()),
                100,
            )
            .await?;
        Ok(entries.iter().map(Self::entity_to_entry).collect())
    }

    async fn get_entries_by_space(
        &self,
        space_id: &SpaceId,
        options: QueryOptions,
    ) -> LedgerResult<Vec<KnowledgeIndexEntry>> {
        let limit = options.limit.unwrap_or(100);
        let entries = self
            .query_entries(&format!("AND space_id = '{}'", space_id.0), limit)
            .await?;
        Ok(entries.iter().map(Self::entity_to_entry).collect())
    }

    async fn get_entries_by_actor(
        &self,
        actor_id: &ActorId,
        options: QueryOptions,
    ) -> LedgerResult<Vec<KnowledgeIndexEntry>> {
        let limit = options.limit.unwrap_or(100);
        let entries = self
            .query_entries(&format!("AND owner_actor_id = '{}'", actor_id.0), limit)
            .await?;
        Ok(entries.iter().map(Self::entity_to_entry).collect())
    }

    async fn create_cross_reference(
        &self,
        source_digest: Digest,
        target_digest: Digest,
        ref_type: String,
    ) -> LedgerResult<CrossReference> {
        let ref_id = format!(
            "xref_{}_{}",
            Utc::now().timestamp_micros(),
            self.sequence.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        );

        let entity = CrossReferenceEntity::new(
            self.tenant_id.clone(),
            ref_id.clone(),
            source_digest.to_hex(),
            target_digest.to_hex(),
            ref_type,
        );

        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        // Create the entity first
        let create_query = format!("CREATE {} CONTENT $data", CrossReferenceEntity::TABLE);

        session
            .client()
            .query(&create_query)
            .bind(("data", entity))
            .await
            .map_err(|e| LedgerError::Storage(format!("Create failed: {}", e)))?;

        // Fetch with type::string(id) to convert Thing to String
        let select_query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE ref_id = $ref_id LIMIT 1",
            CrossReferenceEntity::TABLE
        );

        let mut response = session
            .client()
            .query(&select_query)
            .bind(("ref_id", ref_id))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let result: Option<CrossReferenceEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        let created = result.ok_or_else(|| LedgerError::Storage("Create returned no result".to_string()))?;
        Ok(Self::entity_to_crossref(&created))
    }

    async fn get_cross_references(
        &self,
        digest: &Digest,
        as_source: bool,
    ) -> LedgerResult<Vec<CrossReference>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let digest_hex = digest.to_hex();
        let field = if as_source { "source_digest" } else { "target_digest" };

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND {} = $digest ORDER BY created_at DESC LIMIT 100",
            CrossReferenceEntity::TABLE,
            field
        );

        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("digest", digest_hex))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let results: Vec<CrossReferenceEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        Ok(results.iter().map(Self::entity_to_crossref).collect())
    }

    async fn update_evidence_level(
        &self,
        entry_id: &str,
        new_level: EvidenceLevel,
        receipt_id: ReceiptId,
    ) -> LedgerResult<()> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "UPDATE {} SET evidence_level = $level, receipt_id = $receipt WHERE tenant_id = $tenant AND entry_id = $entry_id",
            KnowledgeIndexEntity::TABLE
        );

        let entry_id_owned = entry_id.to_string();
        session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("entry_id", entry_id_owned))
            .bind(("level", Self::evidence_level_to_str(new_level)))
            .bind(("receipt", receipt_id.0))
            .await
            .map_err(|e| LedgerError::Storage(format!("Update failed: {}", e)))?;

        Ok(())
    }

    async fn update_anchoring_state(
        &self,
        entry_id: &str,
        new_state: AnchoringState,
        receipt_id: Option<ReceiptId>,
    ) -> LedgerResult<()> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "UPDATE {} SET anchoring_state = $state, receipt_id = $receipt WHERE tenant_id = $tenant AND entry_id = $entry_id",
            KnowledgeIndexEntity::TABLE
        );

        let entry_id_owned = entry_id.to_string();
        session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("entry_id", entry_id_owned))
            .bind(("state", Self::anchoring_state_to_str(new_state)))
            .bind(("receipt", receipt_id.map(|r| r.0)))
            .await
            .map_err(|e| LedgerError::Storage(format!("Update failed: {}", e)))?;

        Ok(())
    }

    async fn calculate_aggregate(&self, entry_ids: &[String]) -> LedgerResult<Digest> {
        let mut tree = IncrementalMerkleTree::new();

        for entry_id in entry_ids {
            if let Some(entry) = self.get_entry(entry_id).await? {
                tree.add(entry.content_digest);
            }
        }

        Ok(tree.root())
    }
}
