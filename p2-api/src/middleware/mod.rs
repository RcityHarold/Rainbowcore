//! P2 API Middleware
//!
//! Security and operational middleware for the P2 API.

pub mod auth;
pub mod rate_limit;
pub mod rbac;
pub mod ticket;

pub use auth::{require_auth, AuthClaims, JwtConfig};
pub use rate_limit::{RateLimitConfig, RateLimiter};
pub use rbac::{Permission, RbacConfig, Role, require_permission};
pub use ticket::{require_ticket, TicketContext};
