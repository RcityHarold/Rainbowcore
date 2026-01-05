//! Ticket Verification Middleware
//!
//! Validates access tickets for payload operations.
//! All payload access MUST go through a valid ticket.

use axum::{
    extract::{Path, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

use crate::error::ErrorResponse;
use p2_core::ledger::TicketLedger;
use p2_core::types::{AccessTicket, PayloadSelector, TicketPermission};

/// Ticket context stored in request extensions
#[derive(Debug, Clone)]
pub struct TicketContext {
    /// The validated ticket
    pub ticket: AccessTicket,
    /// Requested resource ref
    pub resource_ref: String,
    /// Requested permission
    pub permission: TicketPermission,
}

/// Ticket validation error
#[derive(Debug)]
pub enum TicketError {
    /// Missing ticket ID
    MissingTicket,
    /// Ticket not found
    NotFound(String),
    /// Ticket expired
    Expired,
    /// Ticket revoked
    Revoked,
    /// Ticket used (one-time)
    AlreadyUsed,
    /// Insufficient permission
    InsufficientPermission(TicketPermission),
    /// Resource not covered
    ResourceNotCovered(String),
    /// Internal error
    Internal(String),
}

impl IntoResponse for TicketError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            TicketError::MissingTicket => (
                StatusCode::BAD_REQUEST,
                "MISSING_TICKET",
                "Ticket ID is required for this operation".to_string(),
            ),
            TicketError::NotFound(id) => (
                StatusCode::NOT_FOUND,
                "TICKET_NOT_FOUND",
                format!("Ticket not found: {}", id),
            ),
            TicketError::Expired => (
                StatusCode::FORBIDDEN,
                "TICKET_EXPIRED",
                "Ticket has expired".to_string(),
            ),
            TicketError::Revoked => (
                StatusCode::FORBIDDEN,
                "TICKET_REVOKED",
                "Ticket has been revoked".to_string(),
            ),
            TicketError::AlreadyUsed => (
                StatusCode::FORBIDDEN,
                "TICKET_USED",
                "One-time ticket has already been used".to_string(),
            ),
            TicketError::InsufficientPermission(perm) => (
                StatusCode::FORBIDDEN,
                "INSUFFICIENT_PERMISSION",
                format!("Ticket does not have {:?} permission", perm),
            ),
            TicketError::ResourceNotCovered(ref_id) => (
                StatusCode::FORBIDDEN,
                "RESOURCE_NOT_COVERED",
                format!("Resource {} is not covered by this ticket", ref_id),
            ),
            TicketError::Internal(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                msg,
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

/// Ticket validation state
#[derive(Clone)]
pub struct TicketState<T: TicketLedger> {
    pub ledger: Arc<T>,
}

impl<T: TicketLedger> TicketState<T> {
    pub fn new(ledger: Arc<T>) -> Self {
        Self { ledger }
    }
}

/// Validate a ticket for a specific operation
pub async fn validate_ticket<T: TicketLedger>(
    ledger: &T,
    ticket_id: &str,
    resource_ref: &str,
    permission: TicketPermission,
) -> Result<AccessTicket, TicketError> {
    // Get the ticket
    let ticket = ledger
        .get_ticket(ticket_id)
        .await
        .map_err(|e| TicketError::Internal(e.to_string()))?
        .ok_or_else(|| TicketError::NotFound(ticket_id.to_string()))?;

    // Check validity
    if !ticket.is_valid() {
        return match ticket.status {
            p2_core::types::TicketStatus::Revoked => Err(TicketError::Revoked),
            p2_core::types::TicketStatus::Used => Err(TicketError::AlreadyUsed),
            p2_core::types::TicketStatus::Expired => Err(TicketError::Expired),
            _ => {
                if ticket.valid_until < chrono::Utc::now() {
                    Err(TicketError::Expired)
                } else {
                    Err(TicketError::Internal("Ticket is invalid".to_string()))
                }
            }
        };
    }

    // Check permission
    if !ticket.has_permission(permission) {
        return Err(TicketError::InsufficientPermission(permission));
    }

    // Check resource coverage
    let covered_resources: Vec<&str> = ticket.target_resource_ref.split(',').collect();
    if !covered_resources.contains(&resource_ref) {
        return Err(TicketError::ResourceNotCovered(resource_ref.to_string()));
    }

    Ok(ticket)
}

/// Require ticket middleware factory
///
/// Creates a middleware that validates tickets for payload access.
///
/// # Usage
/// ```ignore
/// use axum::middleware;
/// use p2_api::middleware::ticket::{require_ticket, TicketState};
///
/// let ticket_state = TicketState::new(ticket_ledger);
///
/// let app = Router::new()
///     .route("/payloads/:ref_id", get(read_payload))
///     .layer(middleware::from_fn_with_state(
///         ticket_state,
///         require_ticket(TicketPermission::Read),
///     ));
/// ```
pub fn require_ticket<T: TicketLedger + 'static>(
    permission: TicketPermission,
) -> impl Fn(
    State<TicketState<T>>,
    Request,
    Next,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, TicketError>> + Send>>
       + Clone
       + Send {
    move |State(state): State<TicketState<T>>, mut request: Request, next: Next| {
        let permission = permission;
        Box::pin(async move {
            // Extract ticket_id from header or query
            let ticket_id = request
                .headers()
                .get("X-Access-Ticket")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string())
                .or_else(|| {
                    // Try to get from query params
                    request
                        .uri()
                        .query()
                        .and_then(|q| {
                            url::form_urlencoded::parse(q.as_bytes())
                                .find(|(k, _)| k == "ticket_id")
                                .map(|(_, v)| v.to_string())
                        })
                })
                .ok_or(TicketError::MissingTicket)?;

            // Extract resource ref from path
            let resource_ref = request
                .uri()
                .path()
                .rsplit('/')
                .next()
                .unwrap_or("")
                .to_string();

            // Validate ticket
            let ticket = validate_ticket(&*state.ledger, &ticket_id, &resource_ref, permission).await?;

            // Store context in extensions
            let context = TicketContext {
                ticket,
                resource_ref,
                permission,
            };
            request.extensions_mut().insert(context);

            Ok(next.run(request).await)
        })
    }
}

/// Check ticket permission helper for use in handlers
pub async fn check_ticket_permission<T: TicketLedger>(
    ledger: &T,
    ticket_id: &str,
    resource_ref: &str,
    permission: TicketPermission,
    selector: &PayloadSelector,
) -> Result<AccessTicket, TicketError> {
    // Validate basic ticket
    let ticket = validate_ticket(ledger, ticket_id, resource_ref, permission).await?;

    // Check selector scope
    if !ticket.selector_within_scope(selector) {
        return Err(TicketError::ResourceNotCovered(format!(
            "Selector {:?} exceeds ticket scope",
            selector
        )));
    }

    Ok(ticket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use chrono::{Duration, Utc};
    use l0_core::types::{ActorId, Digest};
    use p2_core::error::P2Result;
    use p2_core::types::TicketRequest;
    use std::collections::HashMap;
    use tokio::sync::RwLock;

    struct MockTicketLedger {
        tickets: RwLock<HashMap<String, AccessTicket>>,
    }

    impl MockTicketLedger {
        fn new() -> Self {
            Self {
                tickets: RwLock::new(HashMap::new()),
            }
        }

        async fn add_ticket(&self, ticket: AccessTicket) {
            self.tickets
                .write()
                .await
                .insert(ticket.ticket_id.clone(), ticket);
        }
    }

    #[async_trait]
    impl TicketLedger for MockTicketLedger {
        async fn issue_ticket(
            &self,
            _request: TicketRequest,
            _issuer: &ActorId,
        ) -> P2Result<AccessTicket> {
            unimplemented!()
        }

        async fn get_ticket(&self, ticket_id: &str) -> P2Result<Option<AccessTicket>> {
            Ok(self.tickets.read().await.get(ticket_id).cloned())
        }

        async fn use_ticket(&self, _ticket_id: &str) -> P2Result<AccessTicket> {
            unimplemented!()
        }

        async fn revoke_ticket(&self, _ticket_id: &str, _reason: &str) -> P2Result<()> {
            unimplemented!()
        }

        async fn list_tickets_by_holder(
            &self,
            _holder: &ActorId,
            _include_expired: bool,
        ) -> P2Result<Vec<AccessTicket>> {
            unimplemented!()
        }

        async fn list_tickets_for_resource(
            &self,
            _resource_ref: &str,
        ) -> P2Result<Vec<AccessTicket>> {
            unimplemented!()
        }

        async fn check_permission(
            &self,
            _ticket_id: &str,
            _permission: TicketPermission,
            _selector: &PayloadSelector,
        ) -> P2Result<bool> {
            unimplemented!()
        }
    }

    fn create_test_ticket(ticket_id: &str, resource_ref: &str, permissions: Vec<TicketPermission>) -> AccessTicket {
        AccessTicket::new(
            ticket_id.to_string(),
            "consent:test".to_string(),
            ActorId::new("holder:test"),
            ActorId::new("issuer:test"),
            resource_ref.to_string(),
            permissions,
            PayloadSelector::full(),
            Utc::now() + Duration::hours(1),
            Digest::zero(),
        )
    }

    #[tokio::test]
    async fn test_validate_ticket_success() {
        let ledger = MockTicketLedger::new();
        let ticket = create_test_ticket("ticket:001", "payload:001", vec![TicketPermission::Read]);
        ledger.add_ticket(ticket).await;

        let result = validate_ticket(&ledger, "ticket:001", "payload:001", TicketPermission::Read).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_ticket_not_found() {
        let ledger = MockTicketLedger::new();

        let result = validate_ticket(&ledger, "ticket:999", "payload:001", TicketPermission::Read).await;
        assert!(matches!(result, Err(TicketError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_validate_ticket_insufficient_permission() {
        let ledger = MockTicketLedger::new();
        let ticket = create_test_ticket("ticket:001", "payload:001", vec![TicketPermission::Read]);
        ledger.add_ticket(ticket).await;

        let result = validate_ticket(&ledger, "ticket:001", "payload:001", TicketPermission::Export).await;
        assert!(matches!(result, Err(TicketError::InsufficientPermission(_))));
    }

    #[tokio::test]
    async fn test_validate_ticket_resource_not_covered() {
        let ledger = MockTicketLedger::new();
        let ticket = create_test_ticket("ticket:001", "payload:001", vec![TicketPermission::Read]);
        ledger.add_ticket(ticket).await;

        let result = validate_ticket(&ledger, "ticket:001", "payload:999", TicketPermission::Read).await;
        assert!(matches!(result, Err(TicketError::ResourceNotCovered(_))));
    }
}
