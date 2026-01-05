//! RBAC (Role-Based Access Control) Middleware
//!
//! Enforces role-based permissions for API operations.

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use super::auth::AuthClaims;
use crate::error::ErrorResponse;

/// Permission enumeration for P2 API operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    // Payload operations
    PayloadRead,
    PayloadWrite,
    PayloadDelete,
    PayloadMigrate,

    // Evidence operations
    EvidenceCreate,
    EvidenceRead,
    EvidenceExport,

    // Ticket operations
    TicketIssue,
    TicketRevoke,
    TicketRead,

    // Snapshot operations
    SnapshotCreate,
    SnapshotRead,

    // Audit operations
    AuditRead,
    AuditExport,

    // Admin operations
    AdminStats,
    AdminConfig,
    AdminBackfill,

    // System operations
    SystemHealth,
}

/// Role enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Public access (minimal permissions)
    Public,
    /// Regular user
    User,
    /// Data subject (owner of their data)
    DataSubject,
    /// Forensic investigator
    Investigator,
    /// System operator
    Operator,
    /// Administrator
    Admin,
    /// Super administrator
    SuperAdmin,
}

impl Role {
    /// Get default permissions for this role
    pub fn default_permissions(&self) -> HashSet<Permission> {
        let mut perms = HashSet::new();

        match self {
            Role::Public => {
                perms.insert(Permission::SystemHealth);
            }
            Role::User => {
                perms.insert(Permission::SystemHealth);
                perms.insert(Permission::PayloadRead);
                perms.insert(Permission::EvidenceRead);
                perms.insert(Permission::TicketRead);
            }
            Role::DataSubject => {
                perms.insert(Permission::SystemHealth);
                perms.insert(Permission::PayloadRead);
                perms.insert(Permission::PayloadWrite);
                perms.insert(Permission::EvidenceRead);
                perms.insert(Permission::TicketRead);
                perms.insert(Permission::SnapshotRead);
            }
            Role::Investigator => {
                perms.insert(Permission::SystemHealth);
                perms.insert(Permission::PayloadRead);
                perms.insert(Permission::EvidenceRead);
                perms.insert(Permission::EvidenceExport);
                perms.insert(Permission::TicketRead);
                perms.insert(Permission::AuditRead);
            }
            Role::Operator => {
                perms.insert(Permission::SystemHealth);
                perms.insert(Permission::PayloadRead);
                perms.insert(Permission::PayloadMigrate);
                perms.insert(Permission::EvidenceRead);
                perms.insert(Permission::TicketRead);
                perms.insert(Permission::AuditRead);
                perms.insert(Permission::AdminStats);
                perms.insert(Permission::AdminBackfill);
            }
            Role::Admin => {
                perms.insert(Permission::SystemHealth);
                perms.insert(Permission::PayloadRead);
                perms.insert(Permission::PayloadWrite);
                perms.insert(Permission::PayloadDelete);
                perms.insert(Permission::PayloadMigrate);
                perms.insert(Permission::EvidenceCreate);
                perms.insert(Permission::EvidenceRead);
                perms.insert(Permission::EvidenceExport);
                perms.insert(Permission::TicketIssue);
                perms.insert(Permission::TicketRevoke);
                perms.insert(Permission::TicketRead);
                perms.insert(Permission::SnapshotCreate);
                perms.insert(Permission::SnapshotRead);
                perms.insert(Permission::AuditRead);
                perms.insert(Permission::AuditExport);
                perms.insert(Permission::AdminStats);
                perms.insert(Permission::AdminBackfill);
            }
            Role::SuperAdmin => {
                // Super admin has all permissions
                perms.insert(Permission::PayloadRead);
                perms.insert(Permission::PayloadWrite);
                perms.insert(Permission::PayloadDelete);
                perms.insert(Permission::PayloadMigrate);
                perms.insert(Permission::EvidenceCreate);
                perms.insert(Permission::EvidenceRead);
                perms.insert(Permission::EvidenceExport);
                perms.insert(Permission::TicketIssue);
                perms.insert(Permission::TicketRevoke);
                perms.insert(Permission::TicketRead);
                perms.insert(Permission::SnapshotCreate);
                perms.insert(Permission::SnapshotRead);
                perms.insert(Permission::AuditRead);
                perms.insert(Permission::AuditExport);
                perms.insert(Permission::AdminStats);
                perms.insert(Permission::AdminConfig);
                perms.insert(Permission::AdminBackfill);
                perms.insert(Permission::SystemHealth);
            }
        }

        perms
    }

    /// Parse role from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "public" => Some(Role::Public),
            "user" => Some(Role::User),
            "data_subject" | "datasubject" => Some(Role::DataSubject),
            "investigator" => Some(Role::Investigator),
            "operator" => Some(Role::Operator),
            "admin" => Some(Role::Admin),
            "super_admin" | "superadmin" => Some(Role::SuperAdmin),
            _ => None,
        }
    }
}

/// RBAC configuration
#[derive(Debug, Clone)]
pub struct RbacConfig {
    /// Custom role-permission mappings (overrides defaults)
    pub role_permissions: HashMap<Role, HashSet<Permission>>,
    /// Whether to allow unauthenticated access for public endpoints
    pub allow_public: bool,
}

impl Default for RbacConfig {
    fn default() -> Self {
        Self {
            role_permissions: HashMap::new(),
            allow_public: true,
        }
    }
}

impl RbacConfig {
    /// Get permissions for a role
    pub fn get_permissions(&self, role: Role) -> HashSet<Permission> {
        self.role_permissions
            .get(&role)
            .cloned()
            .unwrap_or_else(|| role.default_permissions())
    }

    /// Add custom permission to a role
    pub fn add_permission(&mut self, role: Role, permission: Permission) {
        self.role_permissions
            .entry(role)
            .or_insert_with(|| role.default_permissions())
            .insert(permission);
    }

    /// Remove permission from a role
    pub fn remove_permission(&mut self, role: Role, permission: Permission) {
        if let Some(perms) = self.role_permissions.get_mut(&role) {
            perms.remove(&permission);
        }
    }
}

/// RBAC error
#[derive(Debug)]
pub enum RbacError {
    /// No authentication found
    Unauthenticated,
    /// Missing required permission
    Forbidden(Permission),
    /// Invalid role
    InvalidRole(String),
}

impl IntoResponse for RbacError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            RbacError::Unauthenticated => (
                StatusCode::UNAUTHORIZED,
                "UNAUTHENTICATED",
                "Authentication required".to_string(),
            ),
            RbacError::Forbidden(perm) => (
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                format!("Missing required permission: {:?}", perm),
            ),
            RbacError::InvalidRole(role) => (
                StatusCode::FORBIDDEN,
                "INVALID_ROLE",
                format!("Invalid role: {}", role),
            ),
        };

        let body = ErrorResponse {
            code: code.to_string(),
            message,
            request_id: None,
            details: None,
        };

        (status, Json(body)).into_response()
    }
}

/// RBAC state
#[derive(Clone)]
pub struct RbacState {
    pub config: Arc<RbacConfig>,
}

impl RbacState {
    pub fn new(config: RbacConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    /// Check if claims have the required permission
    pub fn has_permission(&self, claims: &AuthClaims, permission: Permission) -> bool {
        for role_str in &claims.roles {
            if let Some(role) = Role::from_str(role_str) {
                let perms = self.config.get_permissions(role);
                if perms.contains(&permission) {
                    return true;
                }
            }
        }
        false
    }
}

/// Require permission middleware factory
pub fn require_permission(
    permission: Permission,
) -> impl Fn(
    State<RbacState>,
    Request,
    Next,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, RbacError>> + Send>>
       + Clone
       + Send {
    move |State(state): State<RbacState>, request: Request, next: Next| {
        let permission = permission;
        Box::pin(async move {
            // Get claims from extensions (set by auth middleware)
            let claims = request
                .extensions()
                .get::<AuthClaims>()
                .ok_or(RbacError::Unauthenticated)?;

            // Check permission
            if !state.has_permission(claims, permission) {
                return Err(RbacError::Forbidden(permission));
            }

            Ok(next.run(request).await)
        })
    }
}

/// Check multiple permissions (any)
pub fn require_any_permission(
    permissions: Vec<Permission>,
) -> impl Fn(
    State<RbacState>,
    Request,
    Next,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, RbacError>> + Send>>
       + Clone
       + Send {
    move |State(state): State<RbacState>, request: Request, next: Next| {
        let permissions = permissions.clone();
        Box::pin(async move {
            let claims = request
                .extensions()
                .get::<AuthClaims>()
                .ok_or(RbacError::Unauthenticated)?;

            let has_any = permissions.iter().any(|p| state.has_permission(claims, *p));

            if !has_any {
                return Err(RbacError::Forbidden(permissions[0]));
            }

            Ok(next.run(request).await)
        })
    }
}

/// Check multiple permissions (all)
pub fn require_all_permissions(
    permissions: Vec<Permission>,
) -> impl Fn(
    State<RbacState>,
    Request,
    Next,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, RbacError>> + Send>>
       + Clone
       + Send {
    move |State(state): State<RbacState>, request: Request, next: Next| {
        let permissions = permissions.clone();
        Box::pin(async move {
            let claims = request
                .extensions()
                .get::<AuthClaims>()
                .ok_or(RbacError::Unauthenticated)?;

            for perm in &permissions {
                if !state.has_permission(claims, *perm) {
                    return Err(RbacError::Forbidden(*perm));
                }
            }

            Ok(next.run(request).await)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_default_permissions() {
        let admin_perms = Role::Admin.default_permissions();
        assert!(admin_perms.contains(&Permission::PayloadRead));
        assert!(admin_perms.contains(&Permission::PayloadWrite));
        assert!(admin_perms.contains(&Permission::AdminStats));

        let user_perms = Role::User.default_permissions();
        assert!(user_perms.contains(&Permission::PayloadRead));
        assert!(!user_perms.contains(&Permission::PayloadWrite));
        assert!(!user_perms.contains(&Permission::AdminStats));
    }

    #[test]
    fn test_role_from_str() {
        assert_eq!(Role::from_str("admin"), Some(Role::Admin));
        assert_eq!(Role::from_str("ADMIN"), Some(Role::Admin));
        assert_eq!(Role::from_str("super_admin"), Some(Role::SuperAdmin));
        assert_eq!(Role::from_str("invalid"), None);
    }

    #[test]
    fn test_rbac_state_has_permission() {
        let config = RbacConfig::default();
        let state = RbacState::new(config);

        let admin_claims = AuthClaims {
            sub: "user:admin".to_string(),
            exp: 0,
            iat: 0,
            iss: None,
            aud: None,
            roles: vec!["admin".to_string()],
            actor_type: None,
            org_id: None,
        };

        let user_claims = AuthClaims {
            sub: "user:regular".to_string(),
            exp: 0,
            iat: 0,
            iss: None,
            aud: None,
            roles: vec!["user".to_string()],
            actor_type: None,
            org_id: None,
        };

        assert!(state.has_permission(&admin_claims, Permission::PayloadWrite));
        assert!(state.has_permission(&admin_claims, Permission::AdminStats));

        assert!(state.has_permission(&user_claims, Permission::PayloadRead));
        assert!(!state.has_permission(&user_claims, Permission::PayloadWrite));
        assert!(!state.has_permission(&user_claims, Permission::AdminStats));
    }

    #[test]
    fn test_custom_permissions() {
        let mut config = RbacConfig::default();
        config.add_permission(Role::User, Permission::PayloadWrite);

        let state = RbacState::new(config);

        let user_claims = AuthClaims {
            sub: "user:regular".to_string(),
            exp: 0,
            iat: 0,
            iss: None,
            aud: None,
            roles: vec!["user".to_string()],
            actor_type: None,
            org_id: None,
        };

        // Now user should have PayloadWrite
        assert!(state.has_permission(&user_claims, Permission::PayloadWrite));
    }
}
