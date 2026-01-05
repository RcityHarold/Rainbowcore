//! Rate Limiting Middleware
//!
//! Implements token bucket rate limiting for API requests.

use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::error::ErrorResponse;

/// Rate limit configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per window
    pub max_requests: u32,
    /// Window duration
    pub window: Duration,
    /// Burst capacity (token bucket)
    pub burst_capacity: u32,
    /// Whether to rate limit by IP
    pub by_ip: bool,
    /// Whether to rate limit by user (from auth)
    pub by_user: bool,
    /// Exempt IPs (e.g., internal services)
    pub exempt_ips: Vec<String>,
    /// Exempt user roles
    pub exempt_roles: Vec<String>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            window: Duration::from_secs(60),
            burst_capacity: 20,
            by_ip: true,
            by_user: true,
            exempt_ips: vec![
                "127.0.0.1".to_string(),
                "::1".to_string(),
            ],
            exempt_roles: vec!["super_admin".to_string()],
        }
    }
}

impl RateLimitConfig {
    /// Create a strict rate limit config
    pub fn strict() -> Self {
        Self {
            max_requests: 30,
            window: Duration::from_secs(60),
            burst_capacity: 5,
            ..Default::default()
        }
    }

    /// Create a permissive rate limit config
    pub fn permissive() -> Self {
        Self {
            max_requests: 1000,
            window: Duration::from_secs(60),
            burst_capacity: 100,
            ..Default::default()
        }
    }

    /// Check if IP is exempt
    pub fn is_ip_exempt(&self, ip: &str) -> bool {
        self.exempt_ips.iter().any(|e| e == ip)
    }

    /// Check if role is exempt
    pub fn is_role_exempt(&self, roles: &[String]) -> bool {
        roles.iter().any(|r| self.exempt_roles.contains(r))
    }
}

/// Token bucket for rate limiting
#[derive(Debug)]
struct TokenBucket {
    /// Available tokens
    tokens: f64,
    /// Last refill time
    last_refill: Instant,
    /// Maximum tokens (burst capacity)
    max_tokens: f64,
    /// Refill rate (tokens per second)
    refill_rate: f64,
}

impl TokenBucket {
    fn new(max_tokens: u32, refill_rate: f64) -> Self {
        Self {
            tokens: max_tokens as f64,
            last_refill: Instant::now(),
            max_tokens: max_tokens as f64,
            refill_rate,
        }
    }

    /// Try to consume a token, returns true if successful
    fn try_consume(&mut self) -> bool {
        self.refill();

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let new_tokens = elapsed * self.refill_rate;

        self.tokens = (self.tokens + new_tokens).min(self.max_tokens);
        self.last_refill = now;
    }

    /// Get remaining tokens
    fn remaining(&mut self) -> u32 {
        self.refill();
        self.tokens as u32
    }

    /// Get time until next token is available
    fn retry_after(&self) -> Duration {
        if self.tokens >= 1.0 {
            Duration::ZERO
        } else {
            let tokens_needed = 1.0 - self.tokens;
            Duration::from_secs_f64(tokens_needed / self.refill_rate)
        }
    }
}

/// Rate limiter state
#[derive(Clone)]
pub struct RateLimiter {
    config: Arc<RateLimitConfig>,
    buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config: Arc::new(config),
            buckets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get or create a bucket for the given key
    async fn get_bucket(&self, key: &str) -> (bool, u32, Duration) {
        let mut buckets = self.buckets.write().await;

        let refill_rate =
            self.config.max_requests as f64 / self.config.window.as_secs_f64();

        let bucket = buckets.entry(key.to_string()).or_insert_with(|| {
            TokenBucket::new(self.config.burst_capacity, refill_rate)
        });

        let allowed = bucket.try_consume();
        let remaining = bucket.remaining();
        let retry_after = bucket.retry_after();

        (allowed, remaining, retry_after)
    }

    /// Clean up expired buckets
    pub async fn cleanup(&self) {
        let mut buckets = self.buckets.write().await;
        let expiry = Instant::now() - self.config.window * 2;

        buckets.retain(|_, bucket| bucket.last_refill > expiry);
    }

    /// Get the rate limit key for a request
    fn get_key(&self, ip: Option<&str>, user_id: Option<&str>) -> String {
        match (self.config.by_user, self.config.by_ip, user_id, ip) {
            (true, _, Some(user), _) => format!("user:{}", user),
            (_, true, _, Some(ip)) => format!("ip:{}", ip),
            _ => "global".to_string(),
        }
    }
}

/// Rate limit error
#[derive(Debug)]
pub struct RateLimitError {
    /// Retry after duration
    pub retry_after: Duration,
    /// Remaining requests
    pub remaining: u32,
    /// Rate limit (max requests per window)
    pub limit: u32,
}

impl IntoResponse for RateLimitError {
    fn into_response(self) -> Response {
        let body = ErrorResponse {
            code: "RATE_LIMITED".to_string(),
            message: format!(
                "Rate limit exceeded. Retry after {} seconds",
                self.retry_after.as_secs()
            ),
            request_id: None,
            details: Some(serde_json::json!({
                "retry_after_seconds": self.retry_after.as_secs(),
                "remaining": self.remaining,
                "limit": self.limit,
            })),
        };

        let mut response = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();

        // Add rate limit headers
        let headers = response.headers_mut();
        headers.insert(
            "X-RateLimit-Limit",
            self.limit.to_string().parse().unwrap(),
        );
        headers.insert(
            "X-RateLimit-Remaining",
            self.remaining.to_string().parse().unwrap(),
        );
        headers.insert(
            "Retry-After",
            self.retry_after.as_secs().to_string().parse().unwrap(),
        );

        response
    }
}

/// Rate limit middleware
pub async fn rate_limit(
    State(limiter): State<RateLimiter>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    request: Request,
    next: Next,
) -> Result<Response, RateLimitError> {
    // Get IP address
    let ip = connect_info
        .map(|ci| ci.0.ip().to_string())
        .or_else(|| {
            request
                .headers()
                .get("X-Forwarded-For")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        });

    // Check IP exemption
    if let Some(ref ip_str) = ip {
        if limiter.config.is_ip_exempt(ip_str) {
            return Ok(next.run(request).await);
        }
    }

    // Get user ID from auth claims
    let user_id = request
        .extensions()
        .get::<super::auth::AuthClaims>()
        .map(|c| c.sub.clone());

    // Check role exemption
    if let Some(claims) = request.extensions().get::<super::auth::AuthClaims>() {
        if limiter.config.is_role_exempt(&claims.roles) {
            return Ok(next.run(request).await);
        }
    }

    // Get rate limit key
    let key = limiter.get_key(ip.as_deref(), user_id.as_deref());

    // Check rate limit
    let (allowed, remaining, retry_after) = limiter.get_bucket(&key).await;

    if !allowed {
        return Err(RateLimitError {
            retry_after,
            remaining,
            limit: limiter.config.max_requests,
        });
    }

    // Add rate limit headers to response
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        "X-RateLimit-Limit",
        limiter.config.max_requests.to_string().parse().unwrap(),
    );
    headers.insert(
        "X-RateLimit-Remaining",
        remaining.to_string().parse().unwrap(),
    );

    Ok(response)
}

/// Start background cleanup task
pub fn start_cleanup_task(limiter: RateLimiter, interval: Duration) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(interval);
        loop {
            interval.tick().await;
            limiter.cleanup().await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket() {
        let mut bucket = TokenBucket::new(10, 1.0);

        // Should allow initial burst
        for _ in 0..10 {
            assert!(bucket.try_consume());
        }

        // Should be depleted
        assert!(!bucket.try_consume());
    }

    #[test]
    fn test_rate_limit_config_exemption() {
        let config = RateLimitConfig::default();

        assert!(config.is_ip_exempt("127.0.0.1"));
        assert!(config.is_ip_exempt("::1"));
        assert!(!config.is_ip_exempt("192.168.1.1"));

        assert!(config.is_role_exempt(&["super_admin".to_string()]));
        assert!(!config.is_role_exempt(&["user".to_string()]));
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let config = RateLimitConfig {
            max_requests: 10,
            window: Duration::from_secs(60),
            burst_capacity: 5,
            by_ip: true,
            by_user: false,
            exempt_ips: vec![],
            exempt_roles: vec![],
        };

        let limiter = RateLimiter::new(config);

        // First 5 requests should succeed (burst)
        for i in 0..5 {
            let (allowed, remaining, _) = limiter.get_bucket("test").await;
            assert!(allowed, "Request {} should be allowed", i);
            assert_eq!(remaining, 4 - i as u32);
        }

        // 6th request should fail (burst exceeded)
        let (allowed, _, retry_after) = limiter.get_bucket("test").await;
        assert!(!allowed);
        assert!(retry_after > Duration::ZERO);
    }

    #[test]
    fn test_get_key() {
        let config = RateLimitConfig {
            by_ip: true,
            by_user: true,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        // User takes precedence
        assert_eq!(
            limiter.get_key(Some("192.168.1.1"), Some("user:123")),
            "user:user:123"
        );

        // Fall back to IP
        assert_eq!(
            limiter.get_key(Some("192.168.1.1"), None),
            "ip:192.168.1.1"
        );

        // Fall back to global
        let config2 = RateLimitConfig {
            by_ip: false,
            by_user: false,
            ..Default::default()
        };
        let limiter2 = RateLimiter::new(config2);
        assert_eq!(limiter2.get_key(Some("192.168.1.1"), Some("user:123")), "global");
    }
}
