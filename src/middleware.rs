//! Rate limiting middleware for Armature
//!
//! This module provides middleware that can be used with the Armature framework
//! to add rate limiting to your application.

use crate::RateLimiter;
use crate::error::RateLimitHeaders;
use crate::extractor::{KeyExtractor, RequestInfo, api_key_bucket, key_fingerprint};
use armature_core::VerifiedIdentity;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, info, trace, warn};

/// Rate limiting middleware for Armature applications
pub struct RateLimitMiddleware {
    /// The rate limiter instance
    limiter: Arc<RateLimiter>,
    /// Key extraction strategy
    key_extractor: KeyExtractor,
    /// Whether to add rate limit headers to responses
    include_headers: bool,
    /// Custom message for rate limit exceeded responses
    error_message: String,
    /// Keys that bypass rate limiting
    bypass_keys: Vec<String>,
    /// When the store errors: `true` fails open (allow the request), `false`
    /// fails closed (deny). Mirrors `RateLimitConfig::skip_on_error`.
    skip_on_error: bool,
    /// Number of trusted reverse proxies in front of the app, passed to
    /// `HttpRequest::client_address`; `0` (default) keys on the socket peer and
    /// ignores forwarding headers. Mirrors `RateLimitConfig::trusted_proxy_depth`.
    trusted_proxy_depth: usize,
    /// Count of store errors that were let through because `skip_on_error` is
    /// `true`, observed by this middleware instance. Incremented every time
    /// [`RateLimiter::check`] returns `Err` and the fail-open path is taken.
    /// This is the minimum observable signal for the default fail-open
    /// posture: with zero counters or logs, a backend outage silently
    /// disables rate limiting (an abuse/brute-force control on endpoints like
    /// login, password reset, or OTP) with nothing to detect it happened. See
    /// [`Self::skip_on_error_count`]. Mirrors
    /// `AuditMiddleware::write_failures` (armature-audit).
    skip_on_error_count: AtomicU64,
    /// What to do with a request no key could be derived from. See
    /// [`UnkeyedRequestPolicy`].
    unkeyed_policy: UnkeyedRequestPolicy,
    /// Count of requests let through because no rate limit key could be
    /// extracted, observed by this middleware instance. See
    /// [`Self::unkeyed_allow_count`].
    unkeyed_allow_count: AtomicU64,
}

/// What the middleware does with a request the key extractor cannot key.
///
/// A request is unkeyed when the extractor has nothing to work with: no socket
/// peer address (a hand-built request, or a transport without one), no
/// verified `VerifiedIdentity` under [`KeyExtractor::UserId`], or no *validated* API
/// key under [`KeyExtractor::ApiKey`]. Letting such requests through would make
/// the abuse control trivially bypassable — omit the credential and you are
/// never counted — so the default is [`UnkeyedRequestPolicy::Deny`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnkeyedRequestPolicy {
    /// Let the request through unchecked, counting it in
    /// [`RateLimitMiddleware::unkeyed_allow_count`].
    ///
    /// Opt in only where an unkeyed request is legitimately expected and
    /// another layer protects the route (e.g. a `UserId`-keyed limiter on a
    /// surface that also serves anonymous traffic, stacked behind an
    /// IP-keyed one). Never use it on authentication endpoints (login,
    /// password reset, OTP), where it turns the limiter off for any caller
    /// that withholds the key.
    Allow,
    /// Reject the request with the same 429 response an exceeded limit
    /// produces. The default: a missing key fails closed.
    #[default]
    Deny,
}

impl RateLimitMiddleware {
    /// Create a new rate limit middleware
    pub fn new(limiter: Arc<RateLimiter>) -> Self {
        let config = limiter.config().clone();
        Self {
            limiter,
            key_extractor: KeyExtractor::Ip,
            include_headers: config.include_headers,
            skip_on_error: config.skip_on_error,
            error_message: config
                .error_message
                .unwrap_or_else(|| "Rate limit exceeded".to_string()),
            bypass_keys: config.bypass_keys,
            trusted_proxy_depth: config.trusted_proxy_depth,
            skip_on_error_count: AtomicU64::new(0),
            unkeyed_policy: UnkeyedRequestPolicy::default(),
            unkeyed_allow_count: AtomicU64::new(0),
        }
    }

    /// Choose what happens to requests no rate limit key can be derived from.
    ///
    /// Defaults to [`UnkeyedRequestPolicy::Deny`]. See that type for when
    /// [`UnkeyedRequestPolicy::Allow`] is acceptable.
    pub fn with_unkeyed_policy(mut self, policy: UnkeyedRequestPolicy) -> Self {
        self.unkeyed_policy = policy;
        self
    }

    /// Set the number of trusted reverse proxies in front of the app.
    ///
    /// Passed to `HttpRequest::client_address`. Defaults to `0`: the socket
    /// peer is the client and `X-Forwarded-For` is ignored. See
    /// [`crate::config::RateLimitConfig::trusted_proxy_depth`].
    pub fn with_trusted_proxy_depth(mut self, depth: usize) -> Self {
        self.trusted_proxy_depth = depth;
        self
    }

    /// Create middleware with a custom key extractor
    pub fn with_extractor(mut self, extractor: KeyExtractor) -> Self {
        self.key_extractor = extractor;
        self
    }

    /// Set whether to include rate limit headers
    pub fn with_headers(mut self, include: bool) -> Self {
        self.include_headers = include;
        self
    }

    /// Set custom error message
    pub fn with_error_message(mut self, message: impl Into<String>) -> Self {
        self.error_message = message.into();
        self
    }

    /// Add bypass keys
    pub fn with_bypass_keys(mut self, keys: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.bypass_keys.extend(keys.into_iter().map(|k| k.into()));
        self
    }

    /// Check if a request should be rate limited
    ///
    /// Returns Ok with headers if allowed, Err with response if rate limited.
    pub async fn check(&self, info: &RequestInfo) -> RateLimitCheckResponse {
        // Extract key
        let key = match self.key_extractor.extract(info) {
            Some(k) => k,
            None => {
                return match self.unkeyed_policy {
                    UnkeyedRequestPolicy::Allow => {
                        // Counted, not just logged: an unkeyed request is a
                        // request that was not rate limited at all, and under
                        // the default configuration that is every request. A
                        // deployment needs a number it can alarm on to notice
                        // that its abuse control is inert.
                        self.unkeyed_allow_count.fetch_add(1, Ordering::Relaxed);
                        warn!(
                            extractor = self.key_extractor.description(),
                            "no rate limit key could be extracted — request allowed through unchecked"
                        );
                        RateLimitCheckResponse::Allowed { headers: None }
                    }
                    UnkeyedRequestPolicy::Deny => {
                        warn!(
                            extractor = self.key_extractor.description(),
                            "no rate limit key could be extracted — request denied"
                        );
                        RateLimitCheckResponse::Limited {
                            headers: None,
                            message: self.error_message.clone(),
                            retry_after: None,
                        }
                    }
                };
            }
        };

        // Rate-limit keys can be credentials (API-key digests, user ids, custom
        // header values): only a short digest prefix is ever logged.
        let key_fp = key_fingerprint(&key);
        trace!(key = %key_fp, "Checking rate limit");

        // Check bypass. A bypass entry configured as a raw API key matches the
        // digest bucket `KeyExtractor::ApiKey` produces for it.
        if self
            .bypass_keys
            .iter()
            .any(|b| *b == key || api_key_bucket(b) == key)
        {
            debug!(key = %key_fp, "Key is in bypass list, allowing request");
            return RateLimitCheckResponse::Allowed { headers: None };
        }

        // Check rate limit
        match self.limiter.check(&key).await {
            Ok(result) => {
                let headers = if self.include_headers {
                    Some(RateLimitHeaders::allowed(
                        result.limit,
                        result.remaining,
                        result.reset_at,
                    ))
                } else {
                    None
                };

                if result.allowed {
                    trace!(key = %key_fp, remaining = result.remaining, "Request allowed");
                    RateLimitCheckResponse::Allowed { headers }
                } else {
                    info!(key = %key_fp, retry_after = ?result.retry_after, "Rate limit exceeded");
                    RateLimitCheckResponse::Limited {
                        headers: if self.include_headers {
                            Some(RateLimitHeaders::denied(
                                result.limit,
                                result.reset_at,
                                result.retry_after.map(|d| d.as_secs()).unwrap_or(1),
                            ))
                        } else {
                            None
                        },
                        message: self.error_message.clone(),
                        retry_after: result.retry_after.map(|d| d.as_secs()),
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "Rate limit check failed");
                if self.skip_on_error {
                    // Fail open: the store is unavailable but the deployment has
                    // opted to let traffic through rather than reject it. This is
                    // silent to a caller that isn't watching logs/metrics, so
                    // record it and warn loudly: rate limiting is commonly relied
                    // on as an abuse/brute-force control (login, password reset,
                    // OTP endpoints), and a backend outage bypasses it for
                    // everyone on the default `skip_on_error: true`.
                    self.skip_on_error_count.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        error = %e,
                        "rate limiter backend error, skip_on_error is enabled — request was allowed through unchecked"
                    );
                    RateLimitCheckResponse::Allowed { headers: None }
                } else {
                    // Fail closed: `skip_on_error(false)` means a store error
                    // must deny the request, not silently disable rate limiting.
                    RateLimitCheckResponse::Limited {
                        headers: None,
                        message: self.error_message.clone(),
                        retry_after: None,
                    }
                }
            }
        }
    }

    /// Extract request info from common HTTP request types
    pub fn extract_request_info(
        ip: Option<IpAddr>,
        path: &str,
        method: &str,
        user_id: Option<&str>,
        headers: &[(String, String)],
    ) -> RequestInfo {
        let mut info = RequestInfo::new(path, method);

        if let Some(ip) = ip {
            info = info.with_ip(ip);
        }

        if let Some(uid) = user_id {
            info = info.with_user_id(uid);
        }

        for (name, value) in headers {
            info = info.with_header(name.clone(), value.clone());
        }

        // Try to extract API key from common headers
        for (name, value) in headers {
            let name_lower = name.to_lowercase();
            if name_lower == "x-api-key" || name_lower == "authorization" {
                info = info.with_api_key(value.clone());
                break;
            }
        }

        info
    }

    /// Get the underlying rate limiter
    pub fn limiter(&self) -> &RateLimiter {
        &self.limiter
    }

    /// Number of store errors observed by this middleware instance that were
    /// let through because `skip_on_error` is `true`.
    ///
    /// Incremented every time a backend/store error occurs and the fail-open
    /// path is taken, independent of whether headers or logging are enabled.
    /// Wire this into whatever metrics system the application uses (e.g.
    /// export it as a `ratelimit_skip_on_error_total` counter) to get an
    /// observable signal that rate limiting was bypassed due to a backend
    /// outage, even under the default fail-open configuration. See
    /// [`crate::config::RateLimitConfig::skip_on_error`].
    pub fn skip_on_error_count(&self) -> u64 {
        self.skip_on_error_count.load(Ordering::Relaxed)
    }

    /// Number of requests this middleware instance let through unchecked
    /// because no rate limit key could be extracted.
    ///
    /// Export this alongside [`Self::skip_on_error_count`] (e.g. as
    /// `ratelimit_unkeyed_allow_total`). A non-zero and growing value under
    /// [`UnkeyedRequestPolicy::Allow`] means rate limiting is not being applied
    /// to that traffic at all — most often because the default
    /// [`KeyExtractor::Ip`] has no IP to work with (see
    /// [`Self::with_trusted_proxy_depth`]).
    pub fn unkeyed_allow_count(&self) -> u64 {
        self.unkeyed_allow_count.load(Ordering::Relaxed)
    }
}

/// Response from rate limit check
#[derive(Debug)]
pub enum RateLimitCheckResponse {
    /// Request is allowed
    Allowed {
        /// Rate limit headers to include in response
        headers: Option<RateLimitHeaders>,
    },
    /// Request is rate limited
    Limited {
        /// Rate limit headers to include in response
        headers: Option<RateLimitHeaders>,
        /// Error message
        message: String,
        /// Seconds until the client should retry
        retry_after: Option<u64>,
    },
}

impl RateLimitCheckResponse {
    /// Check if the request is allowed
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }

    /// Check if the request is limited
    pub fn is_limited(&self) -> bool {
        matches!(self, Self::Limited { .. })
    }

    /// Get the headers if any
    pub fn headers(&self) -> Option<&RateLimitHeaders> {
        match self {
            Self::Allowed { headers } => headers.as_ref(),
            Self::Limited { headers, .. } => headers.as_ref(),
        }
    }

    /// Get the error message if limited
    pub fn message(&self) -> Option<&str> {
        match self {
            Self::Limited { message, .. } => Some(message),
            _ => None,
        }
    }

    /// Get the retry-after value if limited
    pub fn retry_after(&self) -> Option<u64> {
        match self {
            Self::Limited { retry_after, .. } => *retry_after,
            _ => None,
        }
    }
}

/// Implement the armature_core::Middleware trait for RateLimitMiddleware
/// This allows it to be used in a MiddlewareChain
#[async_trait::async_trait]
impl armature_core::Middleware for RateLimitMiddleware {
    async fn handle(
        &self,
        req: armature_core::HttpRequest,
        next: Box<
            dyn FnOnce(
                    armature_core::HttpRequest,
                ) -> std::pin::Pin<
                    Box<
                        dyn std::future::Future<
                                Output = Result<armature_core::HttpResponse, armature_core::Error>,
                            > + Send,
                    >,
                > + Send,
        >,
    ) -> Result<armature_core::HttpResponse, armature_core::Error> {
        // The client address comes from `client_address`, the one place that
        // decides between the socket peer and the forwarded chain: depth 0 is
        // the socket peer (forwarding headers ignored), depth N reads the Nth
        // hop from the right across every `X-Forwarded-For` line. `X-Real-IP`
        // is never consulted — it is a client-settable header like any other.
        let ip = req.client_address(self.trusted_proxy_depth);

        // Build the key-extraction input from the few fields that are actually
        // read. The routing path (query string excluded) identifies the
        // endpoint; the path extractors normalize it further.
        let mut info = RequestInfo::new(req.path_only(), req.method_str());

        if let Some(ip) = ip {
            info = info.with_ip(ip);
        }

        // Only a principal an authentication layer has verified. A header such
        // as `X-User-Id` is set by the caller, who could otherwise pick a fresh
        // bucket per request or exhaust a victim's.
        if let Some(identity) = req.extension::<VerifiedIdentity>() {
            info = info.with_user_id(identity.subject.clone());
        }

        if let Some(name) = self.key_extractor.required_header()
            && let Some(value) = req.headers.get(name)
        {
            info = info.with_header(name, value);
        }

        // Check rate limit
        match self.check(&info).await {
            RateLimitCheckResponse::Allowed { headers } => {
                // Request is allowed, call next handler
                let mut response = next(req).await?;

                // Add rate limit headers if present
                if let Some(h) = headers {
                    response
                        .headers
                        .insert("X-RateLimit-Limit".to_string(), h.limit.to_string());
                    response
                        .headers
                        .insert("X-RateLimit-Remaining".to_string(), h.remaining.to_string());
                    response
                        .headers
                        .insert("X-RateLimit-Reset".to_string(), h.reset.to_string());
                }

                Ok(response)
            }
            RateLimitCheckResponse::Limited {
                headers,
                message,
                retry_after,
            } => {
                // Request is rate limited
                let mut response = armature_core::HttpResponse::new(429).with_body(
                    serde_json::json!({
                        "error": "Too Many Requests",
                        "message": message
                    })
                    .to_string()
                    .into_bytes(),
                );

                response
                    .headers
                    .insert("Content-Type".to_string(), "application/json".to_string());

                if let Some(retry) = retry_after {
                    response
                        .headers
                        .insert("Retry-After".to_string(), retry.to_string());
                }

                if let Some(h) = headers {
                    response
                        .headers
                        .insert("X-RateLimit-Limit".to_string(), h.limit.to_string());
                    response
                        .headers
                        .insert("X-RateLimit-Remaining".to_string(), "0".to_string());
                    response
                        .headers
                        .insert("X-RateLimit-Reset".to_string(), h.reset.to_string());
                }

                Ok(response)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::Algorithm;
    use std::net::Ipv4Addr;

    async fn create_test_limiter() -> Arc<RateLimiter> {
        Arc::new(
            RateLimiter::builder()
                .algorithm(Algorithm::TokenBucket {
                    capacity: 5,
                    refill_rate: 1.0,
                })
                .build()
                .await
                .unwrap(),
        )
    }

    #[tokio::test]
    async fn test_middleware_allows_requests() {
        let limiter = create_test_limiter().await;
        let middleware = RateLimitMiddleware::new(limiter);

        let info =
            RequestInfo::new("/api/test", "GET").with_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        let response = middleware.check(&info).await;
        assert!(response.is_allowed());
        assert!(response.headers().is_some());
    }

    #[tokio::test]
    async fn test_middleware_limits_requests() {
        let limiter = create_test_limiter().await;
        let middleware = RateLimitMiddleware::new(limiter);

        let info =
            RequestInfo::new("/api/test", "GET").with_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        // Use up all tokens
        for _ in 0..5 {
            middleware.check(&info).await;
        }

        // Next request should be limited
        let response = middleware.check(&info).await;
        assert!(response.is_limited());
        assert!(response.message().is_some());
    }

    #[tokio::test]
    async fn test_bypass_keys() {
        let limiter = create_test_limiter().await;
        let middleware = RateLimitMiddleware::new(limiter).with_bypass_keys(["admin_key"]);

        let info =
            RequestInfo::new("/api/test", "GET").with_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        // Use up all tokens
        for _ in 0..10 {
            middleware.check(&info).await;
        }

        // Need to use API key extractor for this
        let middleware_api = RateLimitMiddleware::new(Arc::new(
            RateLimiter::builder()
                .token_bucket(1, 0.001)
                .bypass_key("admin_key")
                .build()
                .await
                .unwrap(),
        ))
        .with_extractor(KeyExtractor::api_key("X-API-Key", |k: &str| {
            k == "admin_key"
        }))
        .with_bypass_keys(["admin_key"]);

        let bypass_info =
            RequestInfo::new("/api/test", "GET").with_header("X-API-Key", "admin_key");

        let response = middleware_api.check(&bypass_info).await;
        assert!(response.is_allowed());
    }

    #[tokio::test]
    async fn test_custom_error_message() {
        let limiter = Arc::new(
            RateLimiter::builder()
                .token_bucket(1, 0.001)
                .build()
                .await
                .unwrap(),
        );
        let middleware =
            RateLimitMiddleware::new(limiter).with_error_message("Custom rate limit message");

        let info =
            RequestInfo::new("/api/test", "GET").with_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        // Use up token
        middleware.check(&info).await;

        // Next request should have custom message
        let response = middleware.check(&info).await;
        assert!(response.is_limited());
        assert_eq!(response.message(), Some("Custom rate limit message"));
    }

    #[tokio::test]
    async fn test_extract_request_info() {
        let headers = vec![
            ("X-API-Key".to_string(), "test_key".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];

        let info = RateLimitMiddleware::extract_request_info(
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            "/api/users",
            "POST",
            Some("user_123"),
            &headers,
        );

        assert_eq!(info.ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(info.path, "/api/users");
        assert_eq!(info.method, "POST");
        assert_eq!(info.user_id, Some("user_123".to_string()));
        assert_eq!(info.api_key, Some("test_key".to_string()));
    }

    /// Regression: with the client's originating IP trusted (all 3 proxies
    /// configured), a multi-hop `X-Forwarded-For` must actually enforce the
    /// limit on that client (429 once exhausted). Previously the whole header
    /// was parsed as a single `IpAddr`, failed, dropped the key to `None`, and
    /// failed **open** — proxied IP rate limiting was silently disabled.
    #[tokio::test]
    async fn test_multi_hop_xff_rate_limits_on_client() {
        use armature_core::Middleware;

        let limiter = Arc::new(
            RateLimiter::builder()
                .token_bucket(1, f64::EPSILON)
                .build()
                .await
                .unwrap(),
        );
        // Trust all 3 hops so the leftmost (originating client) is the key.
        let middleware = RateLimitMiddleware::new(limiter).with_trusted_proxy_depth(3);

        let make_req = || {
            let mut req = armature_core::HttpRequest::new("GET", "/api/test".to_string());
            req.headers.insert(
                "x-forwarded-for",
                "203.0.113.5, 70.41.3.18, 150.172.238.178",
            );
            req
        };

        // First request consumes the single token -> allowed.
        let r1 = middleware
            .handle(
                make_req(),
                Box::new(|_r| Box::pin(async { Ok(armature_core::HttpResponse::ok()) })),
            )
            .await
            .unwrap();
        assert_eq!(r1.status, 200);

        // Second request must be rate limited on the client's IP.
        let r2 = middleware
            .handle(
                make_req(),
                Box::new(|_r| Box::pin(async { Ok(armature_core::HttpResponse::ok()) })),
            )
            .await
            .unwrap();
        assert_eq!(
            r2.status, 429,
            "proxied client must be rate limited, not failed open"
        );
    }

    /// Security regression: an attacker who can set `X-Forwarded-For` used to
    /// mint a fresh bucket per request by rotating the (spoofable) first hop,
    /// because the middleware unconditionally trusted it. With one trusted proxy
    /// configured, the client is read from the *rightmost* hop (added by our
    /// proxy), so rotating the leftmost hop no longer creates a fresh bucket and
    /// the shared client still gets rate limited.
    #[tokio::test]
    async fn test_spoofed_first_hop_shares_bucket_with_trusted_proxy() {
        use armature_core::Middleware;

        let limiter = Arc::new(
            RateLimiter::builder()
                .token_bucket(1, f64::EPSILON)
                .build()
                .await
                .unwrap(),
        );
        let middleware = RateLimitMiddleware::new(limiter).with_trusted_proxy_depth(1);

        let make_req = |xff: &'static str| {
            let mut req = armature_core::HttpRequest::new("GET", "/api/test".to_string());
            req.headers.insert("x-forwarded-for", xff);
            req
        };

        // Attacker rotates the leftmost hop; the rightmost (10.0.0.1) is our
        // proxy's observed client address and is the same both times.
        let r1 = middleware
            .handle(
                make_req("203.0.113.1, 10.0.0.1"),
                Box::new(|_r| Box::pin(async { Ok(armature_core::HttpResponse::ok()) })),
            )
            .await
            .unwrap();
        assert_eq!(r1.status, 200);

        let r2 = middleware
            .handle(
                make_req("203.0.113.2, 10.0.0.1"),
                Box::new(|_r| Box::pin(async { Ok(armature_core::HttpResponse::ok()) })),
            )
            .await
            .unwrap();
        assert_eq!(
            r2.status, 429,
            "rotating the spoofable first hop must not mint a fresh bucket"
        );
    }

    fn ok_next() -> armature_core::middleware::Next {
        Box::new(|_r| Box::pin(async { Ok(armature_core::HttpResponse::ok()) }))
    }

    fn peer(ip: &str) -> Option<std::net::SocketAddr> {
        Some(std::net::SocketAddr::new(ip.parse().unwrap(), 40000))
    }

    /// Security regression (H11): the default middleware used to have no IP to
    /// key on (depth 0 → no address → unkeyed → allowed), so it limited
    /// nothing. It now keys on the socket peer.
    #[tokio::test]
    async fn test_default_middleware_limits_on_socket_peer() {
        use armature_core::Middleware;

        let limiter = Arc::new(
            RateLimiter::builder()
                .token_bucket(1, f64::EPSILON)
                .build()
                .await
                .unwrap(),
        );
        let middleware = RateLimitMiddleware::new(limiter);
        assert_eq!(middleware.trusted_proxy_depth, 0);

        // Rotating forwarding headers must not mint fresh buckets at depth 0.
        let make_req = |xff: &str| {
            let mut req = armature_core::HttpRequest::new("GET", "/api/test".to_string())
                .with_peer(peer("198.51.100.7"));
            req.headers.insert("x-forwarded-for", xff.to_string());
            req.headers.insert("x-real-ip", xff.to_string());
            req
        };

        let r1 = middleware
            .handle(make_req("203.0.113.1"), ok_next())
            .await
            .unwrap();
        assert_eq!(r1.status, 200);
        let r2 = middleware
            .handle(make_req("203.0.113.2"), ok_next())
            .await
            .unwrap();
        assert_eq!(r2.status, 429, "the default middleware must actually limit");

        // A different peer has its own bucket.
        let mut other = armature_core::HttpRequest::new("GET", "/api/test".to_string())
            .with_peer(peer("198.51.100.8"));
        other.headers.insert("x-forwarded-for", "203.0.113.1");
        let r3 = middleware.handle(other, ok_next()).await.unwrap();
        assert_eq!(r3.status, 200);
        assert_eq!(middleware.unkeyed_allow_count(), 0);
    }

    /// Security regression (H11/M40): `X-Real-IP` was trusted as a fallback
    /// and only the first `X-Forwarded-For` line was read. With a trusted proxy
    /// that appends its own line, the client is the rightmost hop across all
    /// lines, and `X-Real-IP` is ignored.
    #[tokio::test]
    async fn test_xff_read_across_lines_and_x_real_ip_ignored() {
        use armature_core::Middleware;

        let limiter = Arc::new(
            RateLimiter::builder()
                .token_bucket(1, f64::EPSILON)
                .build()
                .await
                .unwrap(),
        );
        let middleware = RateLimitMiddleware::new(limiter).with_trusted_proxy_depth(1);

        let make_req = |spoofed: &str| {
            let mut req = armature_core::HttpRequest::new("GET", "/api/test".to_string())
                .with_peer(peer("10.0.0.2"));
            // Client-supplied line, then the trusted proxy's own line.
            req.headers.append("x-forwarded-for", spoofed.to_string());
            req.headers
                .append("x-forwarded-for", "192.0.2.50".to_string());
            req.headers.insert("x-real-ip", spoofed.to_string());
            req
        };

        let r1 = middleware
            .handle(make_req("203.0.113.1"), ok_next())
            .await
            .unwrap();
        assert_eq!(r1.status, 200);
        let r2 = middleware
            .handle(make_req("203.0.113.9"), ok_next())
            .await
            .unwrap();
        assert_eq!(
            r2.status, 429,
            "spoofed first line / X-Real-IP must not select the bucket"
        );

        // With only X-Real-IP (no XFF), depth 1 has no trustworthy address.
        let mut only_real_ip = armature_core::HttpRequest::new("GET", "/api/test".to_string())
            .with_peer(peer("10.0.0.2"));
        only_real_ip.headers.insert("x-real-ip", "203.0.113.77");
        let r3 = middleware.handle(only_real_ip, ok_next()).await.unwrap();
        assert_eq!(
            r3.status, 429,
            "unkeyed (no XFF) is denied, X-Real-IP unused"
        );
    }

    /// Security regression (H11): `UserId` was keyed on the client-supplied
    /// `X-User-Id` header. Only a verified `VerifiedIdentity` keys the request now.
    #[tokio::test]
    async fn test_user_id_only_from_verified_identity() {
        use armature_core::Middleware;

        let limiter = Arc::new(
            RateLimiter::builder()
                .token_bucket(1, f64::EPSILON)
                .build()
                .await
                .unwrap(),
        );
        let middleware = RateLimitMiddleware::new(limiter).with_extractor(KeyExtractor::UserId);

        // Header only: unkeyed → denied by default, never a fresh bucket.
        for i in 0..3 {
            let mut req = armature_core::HttpRequest::new("POST", "/login".to_string());
            req.headers.insert("x-user-id", format!("forged-{i}"));
            let res = middleware.handle(req, ok_next()).await.unwrap();
            assert_eq!(res.status, 429, "a forged X-User-Id must not key a bucket");
        }

        let make_req = |forged: &str| {
            let mut req = armature_core::HttpRequest::new("POST", "/login".to_string());
            req.headers.insert("x-user-id", forged.to_string());
            req.insert_extension(VerifiedIdentity::new("real-user"));
            req
        };
        let r1 = middleware.handle(make_req("a"), ok_next()).await.unwrap();
        assert_eq!(r1.status, 200);
        let r2 = middleware.handle(make_req("b"), ok_next()).await.unwrap();
        assert_eq!(
            r2.status, 429,
            "the verified user shares one bucket whatever the header says"
        );
    }

    /// The unkeyed policy defaults to deny; `Allow` is an explicit opt-in that
    /// is counted.
    #[tokio::test]
    async fn test_unkeyed_allow_policy_is_opt_in_and_counted() {
        use armature_core::Middleware;

        let limiter = Arc::new(
            RateLimiter::builder()
                .token_bucket(1, f64::EPSILON)
                .build()
                .await
                .unwrap(),
        );
        let middleware =
            RateLimitMiddleware::new(limiter).with_unkeyed_policy(UnkeyedRequestPolicy::Allow);
        assert_eq!(UnkeyedRequestPolicy::default(), UnkeyedRequestPolicy::Deny);

        for expected in 1..=3u64 {
            let req = armature_core::HttpRequest::new("GET", "/api/test".to_string());
            let res = middleware.handle(req, ok_next()).await.unwrap();
            assert_eq!(res.status, 200);
            assert_eq!(middleware.unkeyed_allow_count(), expected);
        }
    }

    /// The unkeyed case is a policy choice: a deployment that expects a key to
    /// always be present can make its absence a rejection instead of a bypass.
    #[tokio::test]
    async fn test_unkeyed_deny_policy_rejects() {
        use armature_core::Middleware;

        let limiter = Arc::new(
            RateLimiter::builder()
                .token_bucket(10, 1.0)
                .build()
                .await
                .unwrap(),
        );
        // Deny is the default; no opt-in needed.
        let middleware = RateLimitMiddleware::new(limiter);

        let req = armature_core::HttpRequest::new("GET", "/api/test".to_string());
        let res = middleware
            .handle(
                req,
                Box::new(|_r| Box::pin(async { Ok(armature_core::HttpResponse::ok()) })),
            )
            .await
            .unwrap();

        assert_eq!(res.status, 429);
        assert_eq!(middleware.unkeyed_allow_count(), 0);
    }

    /// The header the configured extractor names is still reachable even though
    /// the middleware no longer copies the whole header map per request.
    #[tokio::test]
    async fn test_extractor_header_is_available_from_request() {
        use armature_core::Middleware;

        let limiter = Arc::new(
            RateLimiter::builder()
                .token_bucket(1, f64::EPSILON)
                .build()
                .await
                .unwrap(),
        );
        let middleware = RateLimitMiddleware::new(limiter)
            .with_extractor(KeyExtractor::api_key("X-API-Key", |k: &str| {
                k == "sk_live_abc"
            }));

        let make_req = || {
            let mut req = armature_core::HttpRequest::new("GET", "/api/test".to_string());
            req.headers.insert("x-api-key", "sk_live_abc");
            req
        };

        let r1 = middleware
            .handle(
                make_req(),
                Box::new(|_r| Box::pin(async { Ok(armature_core::HttpResponse::ok()) })),
            )
            .await
            .unwrap();
        assert_eq!(r1.status, 200);

        let r2 = middleware
            .handle(
                make_req(),
                Box::new(|_r| Box::pin(async { Ok(armature_core::HttpResponse::ok()) })),
            )
            .await
            .unwrap();
        assert_eq!(r2.status, 429, "the API key must key the bucket");
        assert_eq!(
            middleware.unkeyed_allow_count(),
            0,
            "the request was keyed, not bypassed"
        );
    }

    /// A store that always errors, used to exercise the fail-open/closed path.
    struct ErrorStore;

    #[async_trait::async_trait]
    impl crate::stores::RateLimitStore for ErrorStore {
        async fn token_bucket_check(
            &self,
            _key: &str,
            _capacity: u64,
            _refill_rate: f64,
        ) -> crate::error::RateLimitResult<(bool, u64)> {
            Err(crate::error::RateLimitError::store("store down"))
        }
        async fn sliding_window_check(
            &self,
            _key: &str,
            _max_requests: u64,
            _window: std::time::Duration,
        ) -> crate::error::RateLimitResult<(bool, u64)> {
            Err(crate::error::RateLimitError::store("store down"))
        }
        async fn fixed_window_check(
            &self,
            _key: &str,
            _max_requests: u64,
            _window: std::time::Duration,
        ) -> crate::error::RateLimitResult<(bool, u64)> {
            Err(crate::error::RateLimitError::store("store down"))
        }
        async fn reset(&self, _key: &str) -> crate::error::RateLimitResult<()> {
            Ok(())
        }
        async fn remaining(&self, _key: &str) -> crate::error::RateLimitResult<u64> {
            Ok(0)
        }
        fn store_type(&self) -> &'static str {
            "error"
        }
    }

    /// Regression: `skip_on_error(false)` must fail **closed** — a store error
    /// denies the request. Previously the middleware always failed open.
    #[tokio::test]
    async fn test_skip_on_error_false_fails_closed() {
        use crate::config::RateLimitConfig;

        let config = RateLimitConfig {
            skip_on_error: false,
            ..Default::default()
        };
        let limiter = Arc::new(RateLimiter::new(
            Arc::new(ErrorStore),
            config.algorithm.clone(),
            config,
        ));
        let middleware = RateLimitMiddleware::new(limiter);

        let info =
            RequestInfo::new("/api/test", "GET").with_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        let response = middleware.check(&info).await;
        assert!(
            response.is_limited(),
            "skip_on_error(false) must deny on store error"
        );
    }

    /// Complement: `skip_on_error(true)` (the default) still fails open.
    #[tokio::test]
    async fn test_skip_on_error_true_fails_open() {
        use crate::config::RateLimitConfig;

        let config = RateLimitConfig {
            skip_on_error: true,
            ..Default::default()
        };
        let limiter = Arc::new(RateLimiter::new(
            Arc::new(ErrorStore),
            config.algorithm.clone(),
            config,
        ));
        let middleware = RateLimitMiddleware::new(limiter);

        let info =
            RequestInfo::new("/api/test", "GET").with_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        let response = middleware.check(&info).await;
        assert!(
            response.is_allowed(),
            "skip_on_error(true) must allow on store error"
        );
    }

    /// Observability: every fail-open bypass caused by a backend error must be
    /// counted via `skip_on_error_count`, so an operator can detect that rate
    /// limiting was silently disabled during a backend outage.
    #[tokio::test]
    async fn test_skip_on_error_count_increments_on_backend_error() {
        use crate::config::RateLimitConfig;

        let config = RateLimitConfig {
            skip_on_error: true,
            ..Default::default()
        };
        let limiter = Arc::new(RateLimiter::new(
            Arc::new(ErrorStore),
            config.algorithm.clone(),
            config,
        ));
        let middleware = RateLimitMiddleware::new(limiter);

        let info =
            RequestInfo::new("/api/test", "GET").with_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        assert_eq!(middleware.skip_on_error_count(), 0);

        let response = middleware.check(&info).await;
        assert!(response.is_allowed());
        assert_eq!(
            middleware.skip_on_error_count(),
            1,
            "a fail-open bypass must be counted"
        );

        // A second backend error increments the counter again.
        middleware.check(&info).await;
        assert_eq!(middleware.skip_on_error_count(), 2);
    }

    #[test]
    fn test_response_methods() {
        let allowed = RateLimitCheckResponse::Allowed { headers: None };
        assert!(allowed.is_allowed());
        assert!(!allowed.is_limited());
        assert!(allowed.message().is_none());
        assert!(allowed.retry_after().is_none());

        let limited = RateLimitCheckResponse::Limited {
            headers: None,
            message: "Too many requests".to_string(),
            retry_after: Some(60),
        };
        assert!(!limited.is_allowed());
        assert!(limited.is_limited());
        assert_eq!(limited.message(), Some("Too many requests"));
        assert_eq!(limited.retry_after(), Some(60));
    }
}
