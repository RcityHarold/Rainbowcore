//! Knowledge-Index Ledger - Zero-plaintext content indexes
//!
//! The Knowledge-Index Ledger maintains:
//! - Content digests (never plaintext)
//! - Index structures for efficient lookup
//! - Cross-references between knowledge objects
//! - Scene and space indexes

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use crate::types::{
    Digest, ReceiptId, ActorId, SpaceId, AnchoringState, EvidenceLevel,
};
use super::{Ledger, LedgerResult, QueryOptions};

/// Knowledge index entry type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexEntryType {
    ContentDigest,
    RelationDigest,
    AggregateDigest,
    SceneDigest,
}

/// Knowledge index entry
#[derive(Debug, Clone)]
pub struct KnowledgeIndexEntry {
    pub entry_id: String,
    pub entry_type: IndexEntryType,
    pub content_digest: Digest,
    pub parent_digest: Option<Digest>,
    pub space_id: Option<SpaceId>,
    pub owner_actor_id: ActorId,
    pub created_at: DateTime<Utc>,
    pub evidence_level: EvidenceLevel,
    pub anchoring_state: AnchoringState,
    pub receipt_id: Option<ReceiptId>,
}

/// Cross-reference record
#[derive(Debug, Clone)]
pub struct CrossReference {
    pub ref_id: String,
    pub source_digest: Digest,
    pub target_digest: Digest,
    pub ref_type: String,
    pub created_at: DateTime<Utc>,
    pub receipt_id: Option<ReceiptId>,
}

/// Knowledge-Index Ledger trait
#[async_trait]
pub trait KnowledgeLedger: Ledger {
    /// Index a new content digest
    async fn index_content(
        &self,
        content_digest: Digest,
        owner_actor_id: &ActorId,
        space_id: Option<&SpaceId>,
        parent_digest: Option<Digest>,
    ) -> LedgerResult<KnowledgeIndexEntry>;

    /// Get index entry by ID
    async fn get_entry(&self, entry_id: &str) -> LedgerResult<Option<KnowledgeIndexEntry>>;

    /// Get entries by content digest
    async fn get_entries_by_digest(
        &self,
        content_digest: &Digest,
    ) -> LedgerResult<Vec<KnowledgeIndexEntry>>;

    /// Get entries by space
    async fn get_entries_by_space(
        &self,
        space_id: &SpaceId,
        options: QueryOptions,
    ) -> LedgerResult<Vec<KnowledgeIndexEntry>>;

    /// Get entries by actor
    async fn get_entries_by_actor(
        &self,
        actor_id: &ActorId,
        options: QueryOptions,
    ) -> LedgerResult<Vec<KnowledgeIndexEntry>>;

    /// Create a cross-reference
    async fn create_cross_reference(
        &self,
        source_digest: Digest,
        target_digest: Digest,
        ref_type: String,
    ) -> LedgerResult<CrossReference>;

    /// Get cross-references for a digest
    async fn get_cross_references(
        &self,
        digest: &Digest,
        as_source: bool,
    ) -> LedgerResult<Vec<CrossReference>>;

    /// Update evidence level (after backfill)
    async fn update_evidence_level(
        &self,
        entry_id: &str,
        new_level: EvidenceLevel,
        receipt_id: ReceiptId,
    ) -> LedgerResult<()>;

    /// Update anchoring state
    async fn update_anchoring_state(
        &self,
        entry_id: &str,
        new_state: AnchoringState,
        receipt_id: Option<ReceiptId>,
    ) -> LedgerResult<()>;

    /// Calculate aggregate digest for entries
    async fn calculate_aggregate(
        &self,
        entry_ids: &[String],
    ) -> LedgerResult<Digest>;
}
