//! P2 API Middleware
//!
//! Security and operational middleware for the P2 API.

pub mod auth;
pub mod node_admission;
pub mod rate_limit;
pub mod rbac;
pub mod ticket;

pub use auth::{require_auth, AuthClaims, JwtConfig};
pub use node_admission::{
    require_node_admission, inject_node_id, can_perform_cross_node_ops,
    X_SOURCE_NODE_ID, X_CROSS_NODE_OP,
};
pub use rate_limit::{RateLimitConfig, RateLimiter};
pub use rbac::{Permission, RbacConfig, Role, require_permission};
pub use ticket::{require_ticket, TicketContext};
