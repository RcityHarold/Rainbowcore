//! L0 Network Layer
//!
//! Provides P2P communication between L0 nodes.
//!
//! Node roles:
//! - Read/Verify Nodes: Read data, verify receipts
//! - Observer Signers: Participate in threshold signing (non-voting)
//! - Certified Signers: 9 nodes with 5/9 threshold voting
//!
//! This module provides:
//! - Message types for L0 protocol
//! - Node connection management
//! - P2P transport (TCP-based)
//! - Node discovery
//! - Message routing
//! - Distributed signing coordination

pub mod error;
pub mod message;
pub mod node;
pub mod router;
pub mod signing;
pub mod transport;

pub use error::*;
pub use message::*;
pub use node::*;
pub use router::*;
pub use signing::*;
pub use transport::*;
