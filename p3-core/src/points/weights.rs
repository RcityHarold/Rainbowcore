//! Weights Function Management
//!
//! Manages weights versions and provides weight lookup.

use crate::error::{P3Error, P3Result};
use crate::types::*;
use std::collections::HashMap;

/// Weights registry
pub struct WeightsRegistry {
    /// Registered versions
    versions: HashMap<String, WeightsVersion>,
    /// Active version ID
    active_version: Option<String>,
}

impl WeightsRegistry {
    /// Create new empty registry
    pub fn new() -> Self {
        Self {
            versions: HashMap::new(),
            active_version: None,
        }
    }

    /// Create registry with default v1 weights
    pub fn with_default_v1() -> Self {
        let mut registry = Self::new();
        registry.register_default_v1();
        registry
    }

    /// Register default v1 weights
    fn register_default_v1(&mut self) {
        let content = WeightsContent::default();
        let weights_digest = content.compute_digest();

        let version = WeightsVersion {
            version_id: "weights_v1".to_string(),
            semantic_version: SemanticVersion::v1(),
            valid_from: EpochId::new("epoch:genesis"),
            supersedes: None,
            issuer_ref: "system".to_string(),
            canonicalization_version: CanonVersion::v1(),
            compatibility: CompatibilityVector::v1(),
            weights_digest,
            content,
        };

        self.register(version).ok();
        self.active_version = Some("weights_v1".to_string());
    }

    /// Register a weights version
    pub fn register(&mut self, version: WeightsVersion) -> P3Result<()> {
        // Verify digest
        if !version.verify_digest() {
            return Err(P3Error::InvalidDigest);
        }

        let version_id = version.version_id.clone();
        self.versions.insert(version_id, version);
        Ok(())
    }

    /// Set active version
    pub fn set_active(&mut self, version_id: &str) -> P3Result<()> {
        if !self.versions.contains_key(version_id) {
            return Err(P3Error::VersionNotFound {
                version_id: version_id.to_string(),
            });
        }
        self.active_version = Some(version_id.to_string());
        Ok(())
    }

    /// Get active version
    pub fn get_active(&self) -> Option<&WeightsVersion> {
        self.active_version
            .as_ref()
            .and_then(|id| self.versions.get(id))
    }

    /// Get version by ID
    pub fn get(&self, version_id: &str) -> Option<&WeightsVersion> {
        self.versions.get(version_id)
    }

    /// Get weights content for active version
    pub fn get_active_content(&self) -> Option<&WeightsContent> {
        self.get_active().map(|v| &v.content)
    }

    /// List all registered version IDs
    pub fn list_versions(&self) -> Vec<&str> {
        self.versions.keys().map(|s| s.as_str()).collect()
    }

    /// Check if a version exists
    pub fn has_version(&self, version_id: &str) -> bool {
        self.versions.contains_key(version_id)
    }

    /// Get version reference
    pub fn get_ref(&self, version_id: &str) -> Option<WeightsVersionRef> {
        self.versions.get(version_id).map(|v| v.to_ref())
    }
}

impl Default for WeightsRegistry {
    fn default() -> Self {
        Self::with_default_v1()
    }
}

/// Weights version builder
pub struct WeightsVersionBuilder {
    version_id: String,
    semantic_version: SemanticVersion,
    valid_from: EpochId,
    supersedes: Option<String>,
    issuer_ref: String,
    content: WeightsContent,
}

impl WeightsVersionBuilder {
    /// Create new builder
    pub fn new(version_id: impl Into<String>, valid_from: EpochId) -> Self {
        Self {
            version_id: version_id.into(),
            semantic_version: SemanticVersion::v1(),
            valid_from,
            supersedes: None,
            issuer_ref: "unknown".to_string(),
            content: WeightsContent::default(),
        }
    }

    /// Set semantic version
    pub fn semantic_version(mut self, version: SemanticVersion) -> Self {
        self.semantic_version = version;
        self
    }

    /// Set supersedes
    pub fn supersedes(mut self, version_id: impl Into<String>) -> Self {
        self.supersedes = Some(version_id.into());
        self
    }

    /// Set issuer
    pub fn issuer(mut self, issuer_ref: impl Into<String>) -> Self {
        self.issuer_ref = issuer_ref.into();
        self
    }

    /// Set content
    pub fn content(mut self, content: WeightsContent) -> Self {
        self.content = content;
        self
    }

    /// Set mint base config
    pub fn mint_base(mut self, config: MintBaseConfig) -> Self {
        self.content.f_mint_base = config;
        self
    }

    /// Set use base config
    pub fn use_base(mut self, config: UseBaseConfig) -> Self {
        self.content.f_use_base = config;
        self
    }

    /// Set cap functions
    pub fn caps(mut self, caps: CapFunctions) -> Self {
        self.content.cap_functions = caps;
        self
    }

    /// Set holdback rules
    pub fn holdback(mut self, rules: HoldbackRules) -> Self {
        self.content.holdback_rules = rules;
        self
    }

    /// Build the weights version
    pub fn build(self) -> WeightsVersion {
        let weights_digest = self.content.compute_digest();

        WeightsVersion {
            version_id: self.version_id,
            semantic_version: self.semantic_version,
            valid_from: self.valid_from,
            supersedes: self.supersedes,
            issuer_ref: self.issuer_ref,
            canonicalization_version: CanonVersion::v1(),
            compatibility: CompatibilityVector::v1(),
            weights_digest,
            content: self.content,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal::Decimal;

    #[test]
    fn test_registry_default() {
        let registry = WeightsRegistry::default();
        assert!(registry.get_active().is_some());
        assert!(registry.has_version("weights_v1"));
    }

    #[test]
    fn test_registry_get_content() {
        let registry = WeightsRegistry::default();
        let content = registry.get_active_content().unwrap();
        assert_eq!(content.f_mint_base.new_object_points, Decimal::new(100, 0));
    }

    #[test]
    fn test_registry_set_active() {
        let mut registry = WeightsRegistry::default();

        // Try to set non-existent version
        assert!(registry.set_active("nonexistent").is_err());

        // Set existing version
        assert!(registry.set_active("weights_v1").is_ok());
    }

    #[test]
    fn test_weights_version_builder() {
        let version = WeightsVersionBuilder::new("weights_v2", EpochId::new("epoch:100"))
            .semantic_version(SemanticVersion::new(2, 0, 0))
            .supersedes("weights_v1")
            .issuer("governance")
            .mint_base(MintBaseConfig {
                new_object_points: Decimal::new(200, 0),
                version_update_points: Decimal::new(100, 0),
                duplicate_points: Decimal::ZERO,
            })
            .build();

        assert_eq!(version.version_id, "weights_v2");
        assert_eq!(version.semantic_version.major, 2);
        assert_eq!(version.supersedes, Some("weights_v1".to_string()));
        assert_eq!(version.content.f_mint_base.new_object_points, Decimal::new(200, 0));
    }

    #[test]
    fn test_weights_version_verify_digest() {
        let version = WeightsVersionBuilder::new("test", EpochId::new("epoch:1")).build();
        assert!(version.verify_digest());
    }

    #[test]
    fn test_registry_register() {
        let mut registry = WeightsRegistry::new();

        let version = WeightsVersionBuilder::new("test_v1", EpochId::new("epoch:1"))
            .issuer("test")
            .build();

        assert!(registry.register(version).is_ok());
        assert!(registry.has_version("test_v1"));
    }
}
