//! Canonicalization module for L0
//!
//! L0 uses soulbase_crypto for canonicalization of JSON objects.
//! This module provides L0-specific extensions and domain tags.

mod l0_canon;

pub use l0_canon::*;

// Re-export soulbase canonicalizer
pub use soulbase_crypto::{Canonicalizer, JsonCanonicalizer};
