//! Payload Selector Types
//!
//! Minimal disclosure selectors for ticketed forensic access.
//! Selectors determine what portion of a sealed payload can be accessed.

use serde::{Deserialize, Serialize};

/// Payload Selector - Minimal disclosure unit
///
/// Determines what portion of a sealed payload the ticket holder can access.
/// Default is Span (fragment-level), which provides good balance between
/// privacy and utility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadSelector {
    /// Selector type
    pub selector_type: SelectorType,

    /// Selector expression
    pub selector_expr: String,

    /// Selector version
    pub version: String,
}

impl Default for PayloadSelector {
    fn default() -> Self {
        Self::digest_only()
    }
}

impl PayloadSelector {
    /// Create a full selector (use with caution)
    pub fn full() -> Self {
        Self {
            selector_type: SelectorType::Full,
            selector_expr: "*".to_string(),
            version: "v1".to_string(),
        }
    }

    /// Create a span (fragment) selector - recommended default
    pub fn span(start: usize, end: usize) -> Self {
        Self {
            selector_type: SelectorType::Span,
            selector_expr: format!("{}:{}", start, end),
            version: "v1".to_string(),
        }
    }

    /// Create a byte range selector
    pub fn byte_range(start_byte: u64, end_byte: u64) -> Self {
        Self {
            selector_type: SelectorType::ByteRange,
            selector_expr: format!("{}-{}", start_byte, end_byte),
            version: "v1".to_string(),
        }
    }

    /// Create a field selector for structured payloads
    pub fn fields(field_paths: Vec<&str>) -> Self {
        Self {
            selector_type: SelectorType::Field,
            selector_expr: field_paths.join(","),
            version: "v1".to_string(),
        }
    }

    /// Create a digest-only selector (most restrictive)
    pub fn digest_only() -> Self {
        Self {
            selector_type: SelectorType::DigestOnly,
            selector_expr: "digest".to_string(),
            version: "v1".to_string(),
        }
    }

    /// Create a redacted selector (returns structure with sensitive data removed)
    pub fn redacted(redaction_policy: &str) -> Self {
        Self {
            selector_type: SelectorType::Redacted,
            selector_expr: redaction_policy.to_string(),
            version: "v1".to_string(),
        }
    }

    /// Check if this selector is a subset of another
    pub fn is_subset_of(&self, other: &PayloadSelector) -> bool {
        match (&self.selector_type, &other.selector_type) {
            // Full contains everything
            (_, SelectorType::Full) => true,
            // DigestOnly is subset of everything
            (SelectorType::DigestOnly, _) => true,
            // Full is not subset of anything except Full
            (SelectorType::Full, _) => false,
            // Same type requires expression comparison
            (a, b) if a == b => self.expr_is_subset(&self.selector_expr, &other.selector_expr),
            // Different types - need specific logic
            _ => false,
        }
    }

    /// Check if expression a is subset of expression b (simplified)
    fn expr_is_subset(&self, a: &str, b: &str) -> bool {
        // Simple equality check for now
        // TODO: Implement proper subset logic for ranges and fields
        a == b || b == "*"
    }

    /// Get the disclosure level (0-100, higher = more disclosure)
    pub fn disclosure_level(&self) -> u8 {
        match self.selector_type {
            SelectorType::DigestOnly => 0,
            SelectorType::Redacted => 20,
            SelectorType::Field => 40,
            SelectorType::Span => 60,
            SelectorType::ByteRange => 70,
            SelectorType::Full => 100,
        }
    }

    /// Check if this selector requires full decryption
    pub fn requires_full_decryption(&self) -> bool {
        matches!(self.selector_type, SelectorType::Full)
    }

    /// Parse span expression into (start, end)
    pub fn parse_span(&self) -> Option<(usize, usize)> {
        if self.selector_type != SelectorType::Span {
            return None;
        }
        let parts: Vec<&str> = self.selector_expr.split(':').collect();
        if parts.len() != 2 {
            return None;
        }
        let start = parts[0].parse().ok()?;
        let end = parts[1].parse().ok()?;
        Some((start, end))
    }

    /// Parse byte range expression into (start, end)
    pub fn parse_byte_range(&self) -> Option<(u64, u64)> {
        if self.selector_type != SelectorType::ByteRange {
            return None;
        }
        let parts: Vec<&str> = self.selector_expr.split('-').collect();
        if parts.len() != 2 {
            return None;
        }
        let start = parts[0].parse().ok()?;
        let end = parts[1].parse().ok()?;
        Some((start, end))
    }

    /// Parse field paths
    pub fn parse_fields(&self) -> Option<Vec<String>> {
        if self.selector_type != SelectorType::Field {
            return None;
        }
        Some(self.selector_expr.split(',').map(|s| s.to_string()).collect())
    }
}

/// Selector type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectorType {
    /// Full payload (use with caution)
    Full,
    /// Fragment/span level (v1 default, recommended)
    Span,
    /// Byte range access
    ByteRange,
    /// Field-level for structured payloads (optional enhancement)
    Field,
    /// Digest only - no content, only verification (most restrictive)
    DigestOnly,
    /// Redacted - structure preserved, sensitive data removed
    Redacted,
}

/// Selector validation result
#[derive(Debug, Clone)]
pub enum SelectorValidation {
    /// Selector is valid
    Valid,
    /// Selector is invalid - expression error
    InvalidExpression(String),
    /// Selector exceeds allowed scope
    ExceedsScope(String),
    /// Selector type not supported for this payload
    TypeNotSupported(String),
}

impl SelectorValidation {
    pub fn is_valid(&self) -> bool {
        matches!(self, SelectorValidation::Valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_selector_creation() {
        let full = PayloadSelector::full();
        assert_eq!(full.selector_type, SelectorType::Full);
        assert_eq!(full.selector_expr, "*");

        let span = PayloadSelector::span(0, 100);
        assert_eq!(span.selector_type, SelectorType::Span);
        assert_eq!(span.selector_expr, "0:100");

        let digest = PayloadSelector::digest_only();
        assert_eq!(digest.selector_type, SelectorType::DigestOnly);
    }

    #[test]
    fn test_selector_subset() {
        let full = PayloadSelector::full();
        let span = PayloadSelector::span(0, 100);
        let digest = PayloadSelector::digest_only();

        // DigestOnly is subset of everything
        assert!(digest.is_subset_of(&full));
        assert!(digest.is_subset_of(&span));
        assert!(digest.is_subset_of(&digest));

        // Everything is subset of Full
        assert!(span.is_subset_of(&full));
        assert!(full.is_subset_of(&full));

        // Full is not subset of Span
        assert!(!full.is_subset_of(&span));
    }

    #[test]
    fn test_disclosure_level() {
        assert_eq!(PayloadSelector::digest_only().disclosure_level(), 0);
        assert_eq!(PayloadSelector::full().disclosure_level(), 100);
        assert!(PayloadSelector::span(0, 100).disclosure_level() > PayloadSelector::digest_only().disclosure_level());
    }

    #[test]
    fn test_parse_span() {
        let span = PayloadSelector::span(10, 50);
        let (start, end) = span.parse_span().unwrap();
        assert_eq!(start, 10);
        assert_eq!(end, 50);

        let full = PayloadSelector::full();
        assert!(full.parse_span().is_none());
    }

    #[test]
    fn test_parse_fields() {
        let fields = PayloadSelector::fields(vec!["name", "email", "id"]);
        let parsed = fields.parse_fields().unwrap();
        assert_eq!(parsed, vec!["name", "email", "id"]);
    }
}
