//! L0 Network Layer
//!
//! Provides P2P communication between L0 nodes.
//!
//! Node roles:
//! - Read/Verify Nodes: Read data, verify receipts
//! - Observer Signers: Participate in threshold signing (non-voting)
//! - Certified Signers: 9 nodes with 5/9 threshold voting

use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    #[error("Timeout: {0}")]
    Timeout(String),
    #[error("Protocol error: {0}")]
    ProtocolError(String),
}

/// Node role in the L0 network
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRole {
    /// Read-only node for verification
    ReadVerify,
    /// Observer signer (non-voting)
    ObserverSigner,
    /// Certified signer (voting)
    CertifiedSigner,
}
