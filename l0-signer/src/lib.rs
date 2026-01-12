//! L0 Threshold Signing Service
//!
//! Implements the 5/9 threshold signing for batch and epoch snapshots.
//!
//! Protocol phases:
//! 1. Batch aggregation (P1-P3)
//! 2. Threshold signing
//! 3. Epoch aggregation
//! 4. Chain anchoring (P4)
//!
//! DKG (Distributed Key Generation):
//! - Feldman's VSS-based protocol
//! - Share splitting and reconstruction
//! - Multi-signer coordination
//!
//! BLS Threshold Signatures:
//! - BLS12-381 curve signatures
//! - Signature aggregation
//! - 5/9 threshold verification
//!
//! Signature Integrity (ISSUE-017):
//! - Full signature chain verification
//! - Signer accountability tracking
//! - Replay protection
//! - Freshness validation

pub mod bls;
pub mod crypto;
pub mod dkg;
pub mod error;
pub mod integrity;
pub mod session;
pub mod signer;
pub mod signer_set;

pub use bls::*;
pub use crypto::*;
pub use dkg::*;
pub use error::*;
pub use integrity::*;
pub use session::*;
pub use signer::*;
pub use signer_set::*;
