//! P2 Cryptographic Operations
//!
//! Encryption and key management for sealed payloads.
//!
//! # Modules
//!
//! - **envelope**: Envelope encryption (DEK + KEK)
//! - **kdf**: Key derivation functions (HKDF, PBKDF2)
//! - **key_rotation**: Key versioning and rotation
//! - **key_store**: Key management system abstraction (Vault, KMS, etc.)

pub mod envelope;
pub mod kdf;
pub mod key_rotation;
pub mod key_store;

pub use envelope::{EnvelopeEncryption, SealedEnvelope};
pub use kdf::{
    derive_key, KdfAlgorithm, KdfParams, KeyContext, KeyDerivation,
};
pub use key_rotation::{
    KeyManager, KeyMetadata, KeyRotationStats, KeyStatus, KeyType,
    ReEncryptionJob, ReEncryptionStatus, RotationConfig,
};
pub use key_store::{
    KeyInfo, KeyMaterial, KeyStore, KeyStoreError, KeyStoreStatus,
    LocalKeyStore, VaultConfig, VaultKeyStore, KEY_SIZE,
};
