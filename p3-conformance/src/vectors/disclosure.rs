//! Disclosure Test Vectors
//!
//! Test vectors for disclosure layer conformance testing.
//! These vectors ensure consistent behavior for:
//! - DisclosureLevel (Public/Org/Private)
//! - ViewerContext authorization
//! - QueryScope validation
//! - QueryAuditDigest generation
//! - ExportTicket management
//! - ConformanceLevel (L1/L2/L3)

use p3_core::types::disclosure::{
    ConformanceLevel, DisclosureLevel, ExportDataType, ExportFormat, ExportScope,
    OrgScope, ProviderMaterialRequirements, ProviderOperation, ProviderType,
    QueryOperation, QueryScope, ViewerContext,
};
use p3_core::P3Digest;
use serde::{Deserialize, Serialize};

use super::TestVector;

/// Disclosure level test input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisclosureLevelInput {
    /// Level name
    pub level: String,
    /// Expected allows_detail_enumeration
    pub allows_enumeration: bool,
    /// Expected requires_audit
    pub requires_audit: bool,
}

/// Generate disclosure level test vectors
pub fn disclosure_level_vectors() -> Vec<TestVector<DisclosureLevelInput>> {
    vec![
        TestVector::new(
            "disclosure-level-public",
            "Public level: no enumeration, no audit",
            DisclosureLevelInput {
                level: "public".to_string(),
                allows_enumeration: false,
                requires_audit: false,
            },
        )
        .with_tags(vec!["disclosure", "level", "public"]),
        TestVector::new(
            "disclosure-level-org",
            "Org level: enumeration allowed, audit required",
            DisclosureLevelInput {
                level: "org".to_string(),
                allows_enumeration: true,
                requires_audit: true,
            },
        )
        .with_tags(vec!["disclosure", "level", "org"]),
        TestVector::new(
            "disclosure-level-private",
            "Private level: enumeration allowed, no audit",
            DisclosureLevelInput {
                level: "private".to_string(),
                allows_enumeration: true,
                requires_audit: false,
            },
        )
        .with_tags(vec!["disclosure", "level", "private"]),
    ]
}

/// Query scope test input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryScopeInput {
    /// Operations to include
    pub operations: Vec<String>,
    /// Result limit
    pub result_limit: Option<u32>,
}

/// Generate query scope test vectors
pub fn query_scope_vectors() -> Vec<TestVector<QueryScopeInput>> {
    vec![
        TestVector::new(
            "query-scope-readonly",
            "Read-only scope: list and lookup only",
            QueryScopeInput {
                operations: vec!["list".to_string(), "lookup".to_string()],
                result_limit: Some(1000),
            },
        )
        .with_tags(vec!["disclosure", "scope", "readonly"]),
        TestVector::new(
            "query-scope-full",
            "Full scope: all operations allowed",
            QueryScopeInput {
                operations: vec![
                    "list".to_string(),
                    "lookup".to_string(),
                    "explain".to_string(),
                    "export".to_string(),
                ],
                result_limit: None,
            },
        )
        .with_tags(vec!["disclosure", "scope", "full"]),
        TestVector::new(
            "query-scope-empty",
            "Empty scope: no operations allowed",
            QueryScopeInput {
                operations: vec![],
                result_limit: Some(0),
            },
        )
        .should_fail()
        .with_tags(vec!["disclosure", "scope", "empty", "negative"]),
    ]
}

/// Viewer context test input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewerContextInput {
    /// Viewer ID (hex digest)
    pub viewer_id: String,
    /// Organization ID (hex digest, optional)
    pub org_id: Option<String>,
    /// TTL in seconds
    pub ttl_seconds: i64,
    /// Operations allowed
    pub operations: Vec<String>,
}

/// Generate viewer context test vectors
pub fn viewer_context_vectors() -> Vec<TestVector<ViewerContextInput>> {
    vec![
        TestVector::new(
            "viewer-context-private",
            "Private viewer context without org scope",
            ViewerContextInput {
                viewer_id: P3Digest::blake3(b"viewer:001").to_hex(),
                org_id: None,
                ttl_seconds: 3600,
                operations: vec!["list".to_string(), "lookup".to_string()],
            },
        )
        .with_tags(vec!["disclosure", "context", "private"]),
        TestVector::new(
            "viewer-context-org",
            "Org viewer context with org scope",
            ViewerContextInput {
                viewer_id: P3Digest::blake3(b"viewer:002").to_hex(),
                org_id: Some(P3Digest::blake3(b"org:001").to_hex()),
                ttl_seconds: 7200,
                operations: vec![
                    "list".to_string(),
                    "lookup".to_string(),
                    "explain".to_string(),
                ],
            },
        )
        .with_tags(vec!["disclosure", "context", "org"]),
        TestVector::new(
            "viewer-context-expired",
            "Expired viewer context (TTL = 0)",
            ViewerContextInput {
                viewer_id: P3Digest::blake3(b"viewer:003").to_hex(),
                org_id: None,
                ttl_seconds: 0, // Expired immediately
                operations: vec!["list".to_string()],
            },
        )
        .should_fail()
        .with_tags(vec!["disclosure", "context", "expired", "negative"]),
        TestVector::new(
            "viewer-context-max-ttl",
            "Viewer context with maximum TTL (24h)",
            ViewerContextInput {
                viewer_id: P3Digest::blake3(b"viewer:004").to_hex(),
                org_id: None,
                ttl_seconds: 86400,
                operations: vec!["list".to_string(), "lookup".to_string()],
            },
        )
        .with_tags(vec!["disclosure", "context", "max-ttl"]),
    ]
}

/// Export ticket test input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportTicketInput {
    /// Data types to export
    pub data_types: Vec<String>,
    /// Export format
    pub format: String,
    /// Include plaintext
    pub include_plaintext: bool,
    /// DSN available
    pub dsn_available: bool,
}

/// Generate export ticket test vectors
pub fn export_ticket_vectors() -> Vec<TestVector<ExportTicketInput>> {
    vec![
        TestVector::new(
            "export-ticket-json",
            "JSON export without plaintext",
            ExportTicketInput {
                data_types: vec!["epoch_summary".to_string(), "points".to_string()],
                format: "json".to_string(),
                include_plaintext: false,
                dsn_available: true,
            },
        )
        .with_tags(vec!["disclosure", "export", "json"]),
        TestVector::new(
            "export-ticket-csv-plaintext",
            "CSV export with plaintext (DSN available)",
            ExportTicketInput {
                data_types: vec!["distribution".to_string()],
                format: "csv".to_string(),
                include_plaintext: true,
                dsn_available: true,
            },
        )
        .with_tags(vec!["disclosure", "export", "csv", "plaintext"]),
        TestVector::new(
            "export-ticket-dsn-down",
            "Plaintext export blocked during DSN_DOWN",
            ExportTicketInput {
                data_types: vec!["epoch_summary".to_string()],
                format: "json".to_string(),
                include_plaintext: true,
                dsn_available: false, // DSN_DOWN
            },
        )
        .should_fail()
        .with_tags(vec!["disclosure", "export", "dsn-down", "negative"]),
        TestVector::new(
            "export-ticket-parquet",
            "Parquet export for large datasets",
            ExportTicketInput {
                data_types: vec![
                    "epoch_summary".to_string(),
                    "points".to_string(),
                    "attribution".to_string(),
                    "distribution".to_string(),
                ],
                format: "parquet".to_string(),
                include_plaintext: false,
                dsn_available: true,
            },
        )
        .with_tags(vec!["disclosure", "export", "parquet"]),
    ]
}

/// Conformance level test input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceLevelInput {
    /// Level name (L1/L2/L3)
    pub level: String,
    /// Operations to test
    pub operations: Vec<String>,
    /// Expected results (true = allowed, false = denied)
    pub expected_results: Vec<bool>,
}

/// Generate conformance level test vectors
pub fn conformance_level_vectors() -> Vec<TestVector<ConformanceLevelInput>> {
    vec![
        TestVector::new(
            "conformance-l1",
            "L1: Verify and Report only",
            ConformanceLevelInput {
                level: "L1".to_string(),
                operations: vec![
                    "verify".to_string(),
                    "report".to_string(),
                    "weak_execute".to_string(),
                    "strong_execute".to_string(),
                ],
                expected_results: vec![true, true, false, false],
            },
        )
        .with_tags(vec!["conformance", "level", "l1"]),
        TestVector::new(
            "conformance-l2",
            "L2: Verify, Report, and WeakExecute",
            ConformanceLevelInput {
                level: "L2".to_string(),
                operations: vec![
                    "verify".to_string(),
                    "report".to_string(),
                    "weak_execute".to_string(),
                    "strong_execute".to_string(),
                ],
                expected_results: vec![true, true, true, false],
            },
        )
        .with_tags(vec!["conformance", "level", "l2"]),
        TestVector::new(
            "conformance-l3",
            "L3: All operations allowed",
            ConformanceLevelInput {
                level: "L3".to_string(),
                operations: vec![
                    "verify".to_string(),
                    "report".to_string(),
                    "weak_execute".to_string(),
                    "strong_execute".to_string(),
                ],
                expected_results: vec![true, true, true, true],
            },
        )
        .with_tags(vec!["conformance", "level", "l3"]),
    ]
}

/// Provider material requirements test input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaterialRequirementsInput {
    /// Conformance level
    pub level: String,
    /// Expected material count
    pub expected_count: usize,
    /// Required material names
    pub required_materials: Vec<String>,
}

/// Generate material requirements test vectors
pub fn material_requirements_vectors() -> Vec<TestVector<MaterialRequirementsInput>> {
    vec![
        TestVector::new(
            "materials-l1",
            "L1 requires 3 verification materials",
            MaterialRequirementsInput {
                level: "L1".to_string(),
                expected_count: 3,
                required_materials: vec![
                    "epoch_verification".to_string(),
                    "manifest_verification".to_string(),
                    "root_verification".to_string(),
                ],
            },
        )
        .with_tags(vec!["conformance", "materials", "l1"]),
        TestVector::new(
            "materials-l2",
            "L2 requires 6 materials (L1 + execution)",
            MaterialRequirementsInput {
                level: "L2".to_string(),
                expected_count: 6,
                required_materials: vec![
                    "epoch_verification".to_string(),
                    "manifest_verification".to_string(),
                    "root_verification".to_string(),
                    "execution_log".to_string(),
                    "idempotency_proof".to_string(),
                    "degraded_mode_handling".to_string(),
                ],
            },
        )
        .with_tags(vec!["conformance", "materials", "l2"]),
        TestVector::new(
            "materials-l3",
            "L3 requires 9 materials (L2 + strong actions)",
            MaterialRequirementsInput {
                level: "L3".to_string(),
                expected_count: 9,
                required_materials: vec![
                    "epoch_verification".to_string(),
                    "manifest_verification".to_string(),
                    "root_verification".to_string(),
                    "execution_log".to_string(),
                    "idempotency_proof".to_string(),
                    "degraded_mode_handling".to_string(),
                    "gate_verification".to_string(),
                    "clearing_proof".to_string(),
                    "fee_split_audit".to_string(),
                ],
            },
        )
        .with_tags(vec!["conformance", "materials", "l3"]),
    ]
}

/// Query audit digest test input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryAuditInput {
    /// Viewer context digest (hex)
    pub viewer_context_digest: String,
    /// Query params digest (hex)
    pub query_params_digest: String,
    /// Result digest (hex)
    pub result_digest: String,
    /// Result count
    pub result_count: u32,
}

/// Generate query audit test vectors
pub fn query_audit_vectors() -> Vec<TestVector<QueryAuditInput>> {
    vec![
        TestVector::new(
            "audit-standard",
            "Standard audit record with all components",
            QueryAuditInput {
                viewer_context_digest: P3Digest::blake3(b"context:001").to_hex(),
                query_params_digest: P3Digest::blake3(b"params:001").to_hex(),
                result_digest: P3Digest::blake3(b"result:001").to_hex(),
                result_count: 10,
            },
        )
        .with_tags(vec!["disclosure", "audit", "standard"]),
        TestVector::new(
            "audit-empty-result",
            "Audit record with zero results",
            QueryAuditInput {
                viewer_context_digest: P3Digest::blake3(b"context:002").to_hex(),
                query_params_digest: P3Digest::blake3(b"params:002").to_hex(),
                result_digest: P3Digest::blake3(b"").to_hex(),
                result_count: 0,
            },
        )
        .with_tags(vec!["disclosure", "audit", "empty"]),
        TestVector::new(
            "audit-large-result",
            "Audit record with large result count",
            QueryAuditInput {
                viewer_context_digest: P3Digest::blake3(b"context:003").to_hex(),
                query_params_digest: P3Digest::blake3(b"params:003").to_hex(),
                result_digest: P3Digest::blake3(b"result:large").to_hex(),
                result_count: 10000,
            },
        )
        .with_tags(vec!["disclosure", "audit", "large"]),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disclosure_level_vectors() {
        let vectors = disclosure_level_vectors();
        assert_eq!(vectors.len(), 3);

        // Verify public level
        let public = &vectors[0];
        assert!(!public.input.allows_enumeration);
        assert!(!public.input.requires_audit);

        // Verify org level
        let org = &vectors[1];
        assert!(org.input.allows_enumeration);
        assert!(org.input.requires_audit);

        // Verify private level
        let private = &vectors[2];
        assert!(private.input.allows_enumeration);
        assert!(!private.input.requires_audit);
    }

    #[test]
    fn test_query_scope_vectors() {
        let vectors = query_scope_vectors();
        assert_eq!(vectors.len(), 3);

        // Verify read-only scope
        let readonly = &vectors[0];
        assert_eq!(readonly.input.operations.len(), 2);
        assert_eq!(readonly.input.result_limit, Some(1000));

        // Verify full scope
        let full = &vectors[1];
        assert_eq!(full.input.operations.len(), 4);
        assert!(full.input.result_limit.is_none());

        // Verify empty scope should fail
        let empty = &vectors[2];
        assert!(!empty.should_succeed);
    }

    #[test]
    fn test_viewer_context_vectors() {
        let vectors = viewer_context_vectors();
        assert_eq!(vectors.len(), 4);

        // Verify private context
        let private = &vectors[0];
        assert!(private.input.org_id.is_none());

        // Verify org context
        let org = &vectors[1];
        assert!(org.input.org_id.is_some());

        // Verify expired context should fail
        let expired = &vectors[2];
        assert_eq!(expired.input.ttl_seconds, 0);
        assert!(!expired.should_succeed);
    }

    #[test]
    fn test_export_ticket_vectors() {
        let vectors = export_ticket_vectors();
        assert_eq!(vectors.len(), 4);

        // Verify DSN_DOWN should fail
        let dsn_down = &vectors[2];
        assert!(dsn_down.input.include_plaintext);
        assert!(!dsn_down.input.dsn_available);
        assert!(!dsn_down.should_succeed);
    }

    #[test]
    fn test_conformance_level_vectors() {
        let vectors = conformance_level_vectors();
        assert_eq!(vectors.len(), 3);

        // Verify L1 permissions
        let l1 = &vectors[0];
        assert_eq!(l1.input.expected_results, vec![true, true, false, false]);

        // Verify L2 permissions
        let l2 = &vectors[1];
        assert_eq!(l2.input.expected_results, vec![true, true, true, false]);

        // Verify L3 permissions
        let l3 = &vectors[2];
        assert_eq!(l3.input.expected_results, vec![true, true, true, true]);
    }

    #[test]
    fn test_material_requirements_vectors() {
        let vectors = material_requirements_vectors();
        assert_eq!(vectors.len(), 3);

        // Verify L1 materials
        let l1 = &vectors[0];
        assert_eq!(l1.input.expected_count, 3);

        // Verify L2 materials
        let l2 = &vectors[1];
        assert_eq!(l2.input.expected_count, 6);

        // Verify L3 materials
        let l3 = &vectors[2];
        assert_eq!(l3.input.expected_count, 9);
    }

    #[test]
    fn test_query_audit_vectors() {
        let vectors = query_audit_vectors();
        assert_eq!(vectors.len(), 3);

        // Verify standard audit
        let standard = &vectors[0];
        assert_eq!(standard.input.result_count, 10);

        // Verify empty result
        let empty = &vectors[1];
        assert_eq!(empty.input.result_count, 0);

        // Verify large result
        let large = &vectors[2];
        assert_eq!(large.input.result_count, 10000);
    }

    #[test]
    fn test_disclosure_level_consistency() {
        // Verify DisclosureLevel enum matches test vectors
        assert!(!DisclosureLevel::Public.allows_detail_enumeration());
        assert!(!DisclosureLevel::Public.requires_audit());

        assert!(DisclosureLevel::Org.allows_detail_enumeration());
        assert!(DisclosureLevel::Org.requires_audit());

        assert!(DisclosureLevel::Private.allows_detail_enumeration());
        assert!(!DisclosureLevel::Private.requires_audit());
    }

    #[test]
    fn test_query_scope_consistency() {
        let readonly = QueryScope::read_only();
        assert!(readonly.allows(&QueryOperation::List));
        assert!(readonly.allows(&QueryOperation::Lookup));
        assert!(!readonly.allows(&QueryOperation::Export));

        let full = QueryScope::full();
        assert!(full.allows(&QueryOperation::List));
        assert!(full.allows(&QueryOperation::Lookup));
        assert!(full.allows(&QueryOperation::Explain));
        assert!(full.allows(&QueryOperation::Export));
    }

    #[test]
    fn test_conformance_level_consistency() {
        // L1 can only verify and report
        assert!(ConformanceLevel::L1.can_perform(&ProviderOperation::Verify));
        assert!(ConformanceLevel::L1.can_perform(&ProviderOperation::Report));
        assert!(!ConformanceLevel::L1.can_perform(&ProviderOperation::WeakExecute));
        assert!(!ConformanceLevel::L1.can_perform(&ProviderOperation::StrongExecute));

        // L2 can also weak execute
        assert!(ConformanceLevel::L2.can_perform(&ProviderOperation::WeakExecute));
        assert!(!ConformanceLevel::L2.can_perform(&ProviderOperation::StrongExecute));

        // L3 can do everything
        assert!(ConformanceLevel::L3.can_perform(&ProviderOperation::StrongExecute));
    }

    #[test]
    fn test_material_requirements_consistency() {
        let l1 = ProviderMaterialRequirements::l1();
        assert_eq!(l1.required_materials.len(), 3);

        let l2 = ProviderMaterialRequirements::l2();
        assert_eq!(l2.required_materials.len(), 6);

        let l3 = ProviderMaterialRequirements::l3();
        assert_eq!(l3.required_materials.len(), 9);
    }
}
