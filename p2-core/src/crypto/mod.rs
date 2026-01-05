//! P2 Cryptographic Operations
//!
//! Encryption and key management for sealed payloads.

pub mod envelope;

pub use envelope::{EnvelopeEncryption, SealedEnvelope};
