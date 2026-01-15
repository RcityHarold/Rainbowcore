//! Disclosure Types
//!
//! Phase 6: Disclosure and Market Layer
//!
//! Provides disclosure tiering, authorization, and audit types.

use super::common::*;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

// ============================================================
// Disclosure Levels
// ============================================================

/// Disclosure level (三层披露)
///
/// Controls what information can be accessed and by whom.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureLevel {
    /// Public aggregated disclosure
    /// - Only aggregated statistics
    /// - No individual details enumerable
    Public,
    /// Organization-level disclosure
    /// - Requires authorization + audit
    /// - Scoped to organization
    Org,
    /// Private self-view
    /// - Only own data
    /// - Direct access without external authorization
    Private,
}

impl DisclosureLevel {
    pub fn name(&self) -> &'static str {
        match self {
            DisclosureLevel::Public => "public",
            DisclosureLevel::Org => "org",
            DisclosureLevel::Private => "private",
        }
    }

    /// Check if this level allows detail enumeration
    pub fn allows_detail_enumeration(&self) -> bool {
        match self {
            DisclosureLevel::Public => false,
            DisclosureLevel::Org => true,
            DisclosureLevel::Private => true,
        }
    }

    /// Check if this level requires audit logging
    pub fn requires_audit(&self) -> bool {
        match self {
            DisclosureLevel::Public => false,
            DisclosureLevel::Org => true,
            DisclosureLevel::Private => false,
        }
    }
}

impl Default for DisclosureLevel {
    fn default() -> Self {
        DisclosureLevel::Public
    }
}

// ============================================================
// Viewer Context (Authorization)
// ============================================================

/// Viewer context for authorized queries
///
/// Encapsulates who is viewing, what scope, and when it expires.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ViewerContext {
    /// Viewer identifier (who is querying)
    pub viewer_id: P3Digest,
    /// Organization scope (if Org level)
    pub org_scope: Option<OrgScope>,
    /// Query scope limitations
    pub query_scope: QueryScope,
    /// Time-to-live for this context
    pub ttl: ContextTTL,
    /// Context creation time
    pub created_at: DateTime<Utc>,
    /// Authorization proof digest
    pub auth_proof_digest: Option<P3Digest>,
}

impl ViewerContext {
    /// Create a new viewer context
    pub fn new(viewer_id: P3Digest, query_scope: QueryScope, ttl_seconds: i64) -> Self {
        Self {
            viewer_id,
            org_scope: None,
            query_scope,
            ttl: ContextTTL::new(ttl_seconds),
            created_at: Utc::now(),
            auth_proof_digest: None,
        }
    }

    /// Create org-level viewer context
    pub fn org(viewer_id: P3Digest, org_scope: OrgScope, query_scope: QueryScope, ttl_seconds: i64) -> Self {
        Self {
            viewer_id,
            org_scope: Some(org_scope),
            query_scope,
            ttl: ContextTTL::new(ttl_seconds),
            created_at: Utc::now(),
            auth_proof_digest: None,
        }
    }

    /// With authorization proof
    pub fn with_auth_proof(mut self, proof: P3Digest) -> Self {
        self.auth_proof_digest = Some(proof);
        self
    }

    /// Check if context is expired
    pub fn is_expired(&self, now: &DateTime<Utc>) -> bool {
        self.ttl.is_expired(&self.created_at, now)
    }

    /// Get disclosure level for this context
    pub fn disclosure_level(&self) -> DisclosureLevel {
        if self.org_scope.is_some() {
            DisclosureLevel::Org
        } else {
            DisclosureLevel::Private
        }
    }
}

/// Organization scope
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrgScope {
    /// Organization ID
    pub org_id: P3Digest,
    /// Allowed actor types within org
    pub actor_types: Vec<String>,
    /// Maximum depth for related data
    pub max_depth: u32,
}

impl OrgScope {
    pub fn new(org_id: P3Digest) -> Self {
        Self {
            org_id,
            actor_types: Vec::new(),
            max_depth: 1,
        }
    }

    pub fn with_actor_types(mut self, types: Vec<String>) -> Self {
        self.actor_types = types;
        self
    }

    pub fn with_max_depth(mut self, depth: u32) -> Self {
        self.max_depth = depth;
        self
    }
}

/// Context time-to-live
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContextTTL {
    /// Duration in seconds
    pub seconds: i64,
}

impl ContextTTL {
    pub fn new(seconds: i64) -> Self {
        Self { seconds }
    }

    /// Check if expired
    pub fn is_expired(&self, created_at: &DateTime<Utc>, now: &DateTime<Utc>) -> bool {
        let expires_at = *created_at + Duration::seconds(self.seconds);
        *now >= expires_at
    }

    /// Default TTL (1 hour)
    pub fn default_ttl() -> Self {
        Self { seconds: 3600 }
    }

    /// Short TTL (5 minutes)
    pub fn short() -> Self {
        Self { seconds: 300 }
    }

    /// Long TTL (24 hours)
    pub fn long() -> Self {
        Self { seconds: 86400 }
    }
}

impl Default for ContextTTL {
    fn default() -> Self {
        Self::default_ttl()
    }
}

// ============================================================
// Query Scope
// ============================================================

/// Query scope for authorized access
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryScope {
    /// Allowed query operations
    pub operations: Vec<QueryOperation>,
    /// Epoch range limitation
    pub epoch_range: Option<EpochRange>,
    /// Actor filter
    pub actor_filter: Option<ActorFilter>,
    /// Result limit
    pub result_limit: Option<u32>,
}

impl QueryScope {
    pub fn new() -> Self {
        Self {
            operations: Vec::new(),
            epoch_range: None,
            actor_filter: None,
            result_limit: None,
        }
    }

    /// Full access scope
    pub fn full() -> Self {
        Self {
            operations: vec![
                QueryOperation::List,
                QueryOperation::Lookup,
                QueryOperation::Explain,
                QueryOperation::Export,
            ],
            epoch_range: None,
            actor_filter: None,
            result_limit: None,
        }
    }

    /// Read-only scope
    pub fn read_only() -> Self {
        Self {
            operations: vec![QueryOperation::List, QueryOperation::Lookup],
            epoch_range: None,
            actor_filter: None,
            result_limit: Some(1000),
        }
    }

    pub fn with_operations(mut self, ops: Vec<QueryOperation>) -> Self {
        self.operations = ops;
        self
    }

    pub fn with_epoch_range(mut self, range: EpochRange) -> Self {
        self.epoch_range = Some(range);
        self
    }

    pub fn with_actor_filter(mut self, filter: ActorFilter) -> Self {
        self.actor_filter = Some(filter);
        self
    }

    pub fn with_result_limit(mut self, limit: u32) -> Self {
        self.result_limit = Some(limit);
        self
    }

    /// Check if operation is allowed
    pub fn allows(&self, operation: &QueryOperation) -> bool {
        self.operations.contains(operation)
    }
}

impl Default for QueryScope {
    fn default() -> Self {
        Self::read_only()
    }
}

/// Query operations
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryOperation {
    /// List resources (paginated)
    List,
    /// Lookup specific resource by ID
    Lookup,
    /// Explain calculation details
    Explain,
    /// Export data (with ticket)
    Export,
    /// Aggregate statistics
    Aggregate,
}

/// Epoch range for query filtering
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochRange {
    /// Start epoch (inclusive)
    pub start: Option<EpochId>,
    /// End epoch (exclusive)
    pub end: Option<EpochId>,
    /// Maximum number of epochs
    pub max_count: Option<u32>,
}

impl EpochRange {
    pub fn new() -> Self {
        Self {
            start: None,
            end: None,
            max_count: None,
        }
    }

    pub fn from_epoch(epoch_id: EpochId) -> Self {
        Self {
            start: Some(epoch_id.clone()),
            end: None,
            max_count: Some(1),
        }
    }

    pub fn range(start: EpochId, end: EpochId) -> Self {
        Self {
            start: Some(start),
            end: Some(end),
            max_count: None,
        }
    }
}

impl Default for EpochRange {
    fn default() -> Self {
        Self::new()
    }
}

/// Actor filter for query filtering
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActorFilter {
    /// Specific actor IDs
    pub actor_ids: Vec<P3Digest>,
    /// Actor type filter
    pub actor_types: Vec<String>,
}

impl ActorFilter {
    pub fn new() -> Self {
        Self {
            actor_ids: Vec::new(),
            actor_types: Vec::new(),
        }
    }

    pub fn by_ids(ids: Vec<P3Digest>) -> Self {
        Self {
            actor_ids: ids,
            actor_types: Vec::new(),
        }
    }

    pub fn by_types(types: Vec<String>) -> Self {
        Self {
            actor_ids: Vec::new(),
            actor_types: types,
        }
    }
}

impl Default for ActorFilter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================
// Query Audit
// ============================================================

/// Query audit record
///
/// Every org-level query must be audited.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryAuditRecord {
    /// Audit ID
    pub audit_id: QueryAuditId,
    /// Viewer context digest
    pub viewer_context_digest: P3Digest,
    /// Query parameters digest
    pub query_params_digest: P3Digest,
    /// Query result digest (without actual data)
    pub result_digest: P3Digest,
    /// Result count
    pub result_count: u32,
    /// Query timestamp
    pub queried_at: DateTime<Utc>,
    /// Query duration (milliseconds)
    pub duration_ms: u64,
    /// Disclosure level used
    pub disclosure_level: DisclosureLevel,
}

impl QueryAuditRecord {
    pub fn new(
        viewer_context_digest: P3Digest,
        query_params_digest: P3Digest,
        result_digest: P3Digest,
        result_count: u32,
        disclosure_level: DisclosureLevel,
    ) -> Self {
        Self {
            audit_id: QueryAuditId::generate(),
            viewer_context_digest,
            query_params_digest,
            result_digest,
            result_count,
            queried_at: Utc::now(),
            duration_ms: 0,
            disclosure_level,
        }
    }

    pub fn with_duration(mut self, duration_ms: u64) -> Self {
        self.duration_ms = duration_ms;
        self
    }

    /// Compute audit digest
    pub fn audit_digest(&self) -> QueryAuditDigest {
        // Combine all fields for audit digest
        let mut data = Vec::new();
        data.extend_from_slice(&self.viewer_context_digest.0);
        data.extend_from_slice(&self.query_params_digest.0);
        data.extend_from_slice(&self.result_digest.0);
        data.extend_from_slice(&self.result_count.to_le_bytes());
        data.extend_from_slice(&self.queried_at.timestamp_millis().to_le_bytes());

        QueryAuditDigest(P3Digest::blake3(&data))
    }
}

/// Query audit ID
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QueryAuditId(pub String);

impl QueryAuditId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn generate() -> Self {
        Self(format!("audit:{}", Utc::now().timestamp_nanos_opt().unwrap_or(0)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Query audit digest
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QueryAuditDigest(pub P3Digest);

impl QueryAuditDigest {
    pub fn new(digest: P3Digest) -> Self {
        Self(digest)
    }

    pub fn as_digest(&self) -> &P3Digest {
        &self.0
    }
}

// ============================================================
// Export Ticket
// ============================================================

/// Export ticket for data export
///
/// Required for exporting data, especially during DSN_DOWN.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExportTicket {
    /// Ticket ID
    pub ticket_id: ExportTicketId,
    /// Viewer context digest (who requested)
    pub viewer_context_digest: P3Digest,
    /// Export scope
    pub export_scope: ExportScope,
    /// Ticket status
    pub status: ExportTicketStatus,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Expires at
    pub expires_at: DateTime<Utc>,
    /// Query audit digest
    pub audit_digest: Option<QueryAuditDigest>,
    /// DSN availability at creation
    pub dsn_available: bool,
}

impl ExportTicket {
    pub fn new(
        viewer_context_digest: P3Digest,
        export_scope: ExportScope,
        ttl_seconds: i64,
        dsn_available: bool,
    ) -> Self {
        let now = Utc::now();
        Self {
            ticket_id: ExportTicketId::generate(),
            viewer_context_digest,
            export_scope,
            status: ExportTicketStatus::Pending,
            created_at: now,
            expires_at: now + Duration::seconds(ttl_seconds),
            audit_digest: None,
            dsn_available,
        }
    }

    pub fn with_audit(mut self, audit: QueryAuditDigest) -> Self {
        self.audit_digest = Some(audit);
        self
    }

    /// Check if ticket is valid
    pub fn is_valid(&self, now: &DateTime<Utc>) -> bool {
        self.status == ExportTicketStatus::Approved && *now < self.expires_at
    }

    /// Check if expired
    pub fn is_expired(&self, now: &DateTime<Utc>) -> bool {
        *now >= self.expires_at
    }

    /// Approve ticket
    pub fn approve(&mut self) {
        self.status = ExportTicketStatus::Approved;
    }

    /// Reject ticket
    pub fn reject(&mut self, reason: impl Into<String>) {
        self.status = ExportTicketStatus::Rejected(reason.into());
    }

    /// Mark as used
    pub fn mark_used(&mut self) {
        self.status = ExportTicketStatus::Used;
    }

    /// Check if plaintext export is allowed
    ///
    /// DSN_DOWN forbids plaintext export
    pub fn allows_plaintext_export(&self) -> bool {
        self.dsn_available
    }
}

/// Export ticket ID
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExportTicketId(pub String);

impl ExportTicketId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn generate() -> Self {
        Self(format!("export:{}", Utc::now().timestamp_nanos_opt().unwrap_or(0)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Export scope
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExportScope {
    /// Data types to export
    pub data_types: Vec<ExportDataType>,
    /// Epoch range
    pub epoch_range: Option<EpochRange>,
    /// Format
    pub format: ExportFormat,
    /// Include plaintext (requires DSN available)
    pub include_plaintext: bool,
}

impl ExportScope {
    pub fn new(data_types: Vec<ExportDataType>) -> Self {
        Self {
            data_types,
            epoch_range: None,
            format: ExportFormat::Json,
            include_plaintext: false,
        }
    }

    pub fn with_epoch_range(mut self, range: EpochRange) -> Self {
        self.epoch_range = Some(range);
        self
    }

    pub fn with_format(mut self, format: ExportFormat) -> Self {
        self.format = format;
        self
    }

    pub fn with_plaintext(mut self, include: bool) -> Self {
        self.include_plaintext = include;
        self
    }
}

/// Export data types
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportDataType {
    /// Epoch summaries
    EpochSummary,
    /// Points calculations
    Points,
    /// Attribution maps
    Attribution,
    /// Distribution records
    Distribution,
    /// Clearing records
    Clearing,
    /// Audit logs
    AuditLogs,
}

/// Export format
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    Json,
    Csv,
    Parquet,
}

impl Default for ExportFormat {
    fn default() -> Self {
        ExportFormat::Json
    }
}

/// Export ticket status
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportTicketStatus {
    /// Pending approval
    Pending,
    /// Approved
    Approved,
    /// Rejected with reason
    Rejected(String),
    /// Used (one-time use)
    Used,
    /// Expired
    Expired,
}

// ============================================================
// Conformance Level
// ============================================================

/// Conformance level for provider certification
///
/// Determines what operations a provider can perform.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceLevel {
    /// L1: Read-only verification and reports
    /// - epoch/manifest/root/verify must pass
    L1,
    /// L2: Can execute weak consequences
    /// - L1 + execute/degraded/unknown_version/idempotency
    L2,
    /// L3: Can handle StrongEconomicActions
    /// - L2 + gates/proof/clearing/fee_split
    L3,
}

impl ConformanceLevel {
    pub fn name(&self) -> &'static str {
        match self {
            ConformanceLevel::L1 => "L1",
            ConformanceLevel::L2 => "L2",
            ConformanceLevel::L3 => "L3",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            ConformanceLevel::L1 => "Read-only verification and reports",
            ConformanceLevel::L2 => "Can execute weak consequences",
            ConformanceLevel::L3 => "Can handle StrongEconomicActions",
        }
    }

    /// Check if this level can perform the given operation
    pub fn can_perform(&self, operation: &ProviderOperation) -> bool {
        match operation {
            ProviderOperation::Verify | ProviderOperation::Report => true,
            ProviderOperation::WeakExecute => *self >= ConformanceLevel::L2,
            ProviderOperation::StrongExecute => *self >= ConformanceLevel::L3,
        }
    }
}

impl Default for ConformanceLevel {
    fn default() -> Self {
        ConformanceLevel::L1
    }
}

/// Provider operations
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderOperation {
    /// Verify epoch/bundle/manifest
    Verify,
    /// Generate reports
    Report,
    /// Execute weak consequences (non-final)
    WeakExecute,
    /// Execute strong consequences (final)
    StrongExecute,
}

// ============================================================
// Provider Types
// ============================================================

/// Provider type
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderType {
    /// Official provider (no special privilege)
    Official,
    /// Third-party provider
    ThirdParty,
    /// Self-hosted provider
    SelfHosted,
}

impl ProviderType {
    pub fn name(&self) -> &'static str {
        match self {
            ProviderType::Official => "official",
            ProviderType::ThirdParty => "third_party",
            ProviderType::SelfHosted => "self_hosted",
        }
    }
}

/// Provider registration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderRegistration {
    /// Provider ID
    pub provider_id: ProviderId,
    /// Provider type
    pub provider_type: ProviderType,
    /// Conformance level
    pub conformance_level: ConformanceLevel,
    /// Registration time
    pub registered_at: DateTime<Utc>,
    /// Last conformance check
    pub last_conformance_check: Option<DateTime<Utc>>,
    /// Conformance check digest
    pub conformance_digest: Option<P3Digest>,
    /// Active status
    pub is_active: bool,
}

impl ProviderRegistration {
    pub fn new(provider_id: ProviderId, provider_type: ProviderType, level: ConformanceLevel) -> Self {
        Self {
            provider_id,
            provider_type,
            conformance_level: level,
            registered_at: Utc::now(),
            last_conformance_check: None,
            conformance_digest: None,
            is_active: true,
        }
    }

    pub fn with_conformance_check(mut self, digest: P3Digest) -> Self {
        self.last_conformance_check = Some(Utc::now());
        self.conformance_digest = Some(digest);
        self
    }

    /// Check if provider can perform operation
    pub fn can_perform(&self, operation: &ProviderOperation) -> bool {
        self.is_active && self.conformance_level.can_perform(operation)
    }

    /// Deactivate provider
    pub fn deactivate(&mut self) {
        self.is_active = false;
    }

    /// Reactivate provider
    pub fn reactivate(&mut self) {
        self.is_active = true;
    }
}

/// Provider material output requirements
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderMaterialRequirements {
    /// Required output materials by conformance level
    pub required_materials: Vec<RequiredMaterial>,
}

impl ProviderMaterialRequirements {
    /// L1 requirements
    pub fn l1() -> Self {
        Self {
            required_materials: vec![
                RequiredMaterial::new("epoch_verification", "Epoch verification result"),
                RequiredMaterial::new("manifest_verification", "Manifest verification result"),
                RequiredMaterial::new("root_verification", "Root verification result"),
            ],
        }
    }

    /// L2 requirements (L1 + execution materials)
    pub fn l2() -> Self {
        let mut reqs = Self::l1();
        reqs.required_materials.extend(vec![
            RequiredMaterial::new("execution_log", "Execution audit log"),
            RequiredMaterial::new("idempotency_proof", "Idempotency verification proof"),
            RequiredMaterial::new("degraded_mode_handling", "Degraded mode handling proof"),
        ]);
        reqs
    }

    /// L3 requirements (L2 + strong action materials)
    pub fn l3() -> Self {
        let mut reqs = Self::l2();
        reqs.required_materials.extend(vec![
            RequiredMaterial::new("gate_verification", "Gate verification proof"),
            RequiredMaterial::new("clearing_proof", "Clearing execution proof"),
            RequiredMaterial::new("fee_split_audit", "Fee split audit trail"),
        ]);
        reqs
    }

    pub fn for_level(level: &ConformanceLevel) -> Self {
        match level {
            ConformanceLevel::L1 => Self::l1(),
            ConformanceLevel::L2 => Self::l2(),
            ConformanceLevel::L3 => Self::l3(),
        }
    }
}

/// Required material specification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequiredMaterial {
    /// Material name
    pub name: String,
    /// Material description
    pub description: String,
}

impl RequiredMaterial {
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
        }
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disclosure_level() {
        assert_eq!(DisclosureLevel::Public.name(), "public");
        assert!(!DisclosureLevel::Public.allows_detail_enumeration());
        assert!(DisclosureLevel::Org.allows_detail_enumeration());
        assert!(DisclosureLevel::Org.requires_audit());
        assert!(!DisclosureLevel::Private.requires_audit());
    }

    #[test]
    fn test_viewer_context() {
        let viewer = ViewerContext::new(
            P3Digest::zero(),
            QueryScope::read_only(),
            3600,
        );

        assert_eq!(viewer.disclosure_level(), DisclosureLevel::Private);
        assert!(!viewer.is_expired(&Utc::now()));
    }

    #[test]
    fn test_viewer_context_org() {
        let org_scope = OrgScope::new(P3Digest::zero());
        let viewer = ViewerContext::org(
            P3Digest::zero(),
            org_scope,
            QueryScope::full(),
            3600,
        );

        assert_eq!(viewer.disclosure_level(), DisclosureLevel::Org);
    }

    #[test]
    fn test_query_scope() {
        let scope = QueryScope::read_only();
        assert!(scope.allows(&QueryOperation::List));
        assert!(scope.allows(&QueryOperation::Lookup));
        assert!(!scope.allows(&QueryOperation::Export));

        let full_scope = QueryScope::full();
        assert!(full_scope.allows(&QueryOperation::Export));
    }

    #[test]
    fn test_export_ticket() {
        let ticket = ExportTicket::new(
            P3Digest::zero(),
            ExportScope::new(vec![ExportDataType::EpochSummary]),
            3600,
            true,
        );

        assert!(!ticket.is_expired(&Utc::now()));
        assert!(ticket.allows_plaintext_export());
    }

    #[test]
    fn test_export_ticket_dsn_down() {
        let ticket = ExportTicket::new(
            P3Digest::zero(),
            ExportScope::new(vec![ExportDataType::EpochSummary]),
            3600,
            false, // DSN_DOWN
        );

        assert!(!ticket.allows_plaintext_export());
    }

    #[test]
    fn test_conformance_level() {
        assert!(ConformanceLevel::L1.can_perform(&ProviderOperation::Verify));
        assert!(!ConformanceLevel::L1.can_perform(&ProviderOperation::WeakExecute));
        assert!(ConformanceLevel::L2.can_perform(&ProviderOperation::WeakExecute));
        assert!(!ConformanceLevel::L2.can_perform(&ProviderOperation::StrongExecute));
        assert!(ConformanceLevel::L3.can_perform(&ProviderOperation::StrongExecute));
    }

    #[test]
    fn test_conformance_level_ordering() {
        assert!(ConformanceLevel::L1 < ConformanceLevel::L2);
        assert!(ConformanceLevel::L2 < ConformanceLevel::L3);
    }

    #[test]
    fn test_provider_registration() {
        let provider = ProviderRegistration::new(
            ProviderId::new("provider:test"),
            ProviderType::ThirdParty,
            ConformanceLevel::L2,
        );

        assert!(provider.can_perform(&ProviderOperation::Verify));
        assert!(provider.can_perform(&ProviderOperation::WeakExecute));
        assert!(!provider.can_perform(&ProviderOperation::StrongExecute));
    }

    #[test]
    fn test_provider_material_requirements() {
        let l1_reqs = ProviderMaterialRequirements::l1();
        assert_eq!(l1_reqs.required_materials.len(), 3);

        let l2_reqs = ProviderMaterialRequirements::l2();
        assert_eq!(l2_reqs.required_materials.len(), 6);

        let l3_reqs = ProviderMaterialRequirements::l3();
        assert_eq!(l3_reqs.required_materials.len(), 9);
    }

    #[test]
    fn test_query_audit_record() {
        let record = QueryAuditRecord::new(
            P3Digest::zero(),
            P3Digest::zero(),
            P3Digest::zero(),
            10,
            DisclosureLevel::Org,
        );

        let digest = record.audit_digest();
        assert!(!digest.as_digest().is_zero());
    }

    #[test]
    fn test_context_ttl() {
        let ttl = ContextTTL::short();
        let created = Utc::now();

        // Not expired immediately
        assert!(!ttl.is_expired(&created, &created));

        // Expired after TTL
        let future = created + Duration::seconds(600);
        assert!(ttl.is_expired(&created, &future));
    }
}
