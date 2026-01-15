//! Canonicalization Rules
//!
//! Defines the rules for field ordering, string normalization, numeric encoding, etc.

use serde::{Deserialize, Serialize};

/// Field ordering rule
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldOrderRule {
    /// Alphabetical ordering of field names
    Alphabetical,
    /// Fixed field order (specified list)
    Fixed(Vec<String>),
}

impl Default for FieldOrderRule {
    fn default() -> Self {
        Self::Alphabetical
    }
}

/// String normalization rule
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StringNormRule {
    /// Encoding
    pub encoding: Encoding,
    /// Case handling
    pub case: CaseHandling,
    /// Whitespace handling
    pub whitespace: WhitespaceHandling,
}

impl Default for StringNormRule {
    fn default() -> Self {
        Self {
            encoding: Encoding::Utf8,
            case: CaseHandling::Preserve,
            whitespace: WhitespaceHandling::Preserve,
        }
    }
}

/// String encoding
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    Utf8,
    Ascii,
}

/// Case handling
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseHandling {
    Preserve,
    Lower,
    Upper,
}

/// Whitespace handling
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WhitespaceHandling {
    Preserve,
    Trim,
    Collapse,
}

/// Numeric encoding rule
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NumericEncodingRule {
    /// Format
    pub format: NumericFormat,
    /// Precision for decimals
    pub precision: u32,
    /// Rounding mode
    pub rounding: NumericRounding,
}

impl Default for NumericEncodingRule {
    fn default() -> Self {
        Self {
            format: NumericFormat::Decimal,
            precision: 18,
            rounding: NumericRounding::BankersRounding,
        }
    }
}

/// Numeric format
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NumericFormat {
    Decimal,
    Integer,
    Scientific,
}

/// Numeric rounding
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NumericRounding {
    BankersRounding,
    RoundDown,
    RoundUp,
    RoundHalfUp,
}

/// Array processing rule
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArrayRule {
    /// Deduplicate elements
    pub dedup: bool,
    /// Sort key
    pub sort_key: SortKey,
    /// Conflict handling
    pub conflict_handling: ConflictHandling,
}

impl Default for ArrayRule {
    fn default() -> Self {
        Self {
            dedup: false,
            sort_key: SortKey::None,
            conflict_handling: ConflictHandling::Reject,
        }
    }
}

/// Sort key for arrays
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SortKey {
    None,
    Natural,
    ByField(String),
    ByDigest,
}

/// Conflict handling
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictHandling {
    Reject,
    KeepFirst,
    KeepLast,
    Merge,
}

/// Hash algorithm
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashAlgorithm {
    Blake3,
    Sha256,
}

impl Default for HashAlgorithm {
    fn default() -> Self {
        Self::Blake3
    }
}

/// Domain separation tags
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainTags {
    /// Default domain tag
    pub default_tag: String,
    /// Manifest domain tag
    pub manifest_tag: String,
    /// Event set domain tag
    pub event_set_tag: String,
    /// Version domain tag
    pub version_tag: String,
    /// Result root domain tag
    pub result_root_tag: String,
}

impl Default for DomainTags {
    fn default() -> Self {
        Self {
            default_tag: "p3:default".to_string(),
            manifest_tag: "p3:manifest".to_string(),
            event_set_tag: "p3:event_set".to_string(),
            version_tag: "p3:version".to_string(),
            result_root_tag: "p3:result_root".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_rules() {
        let field_rule = FieldOrderRule::default();
        assert_eq!(field_rule, FieldOrderRule::Alphabetical);

        let string_rule = StringNormRule::default();
        assert_eq!(string_rule.encoding, Encoding::Utf8);

        let numeric_rule = NumericEncodingRule::default();
        assert_eq!(numeric_rule.precision, 18);

        let array_rule = ArrayRule::default();
        assert!(!array_rule.dedup);

        let hash = HashAlgorithm::default();
        assert_eq!(hash, HashAlgorithm::Blake3);
    }

    #[test]
    fn test_domain_tags() {
        let tags = DomainTags::default();
        assert!(tags.default_tag.starts_with("p3:"));
        assert!(tags.manifest_tag.starts_with("p3:"));
    }
}
