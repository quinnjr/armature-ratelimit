//! Key extraction for rate limiting
//!
//! This module provides different strategies for extracting rate limit keys
//! from incoming requests.

use std::net::IpAddr;
use std::sync::Arc;

/// Type alias for key extractor function
pub type KeyExtractorFn = Box<dyn Fn(&RequestInfo) -> Option<String> + Send + Sync>;

/// Information about an incoming request used for key extraction
#[derive(Debug, Clone)]
pub struct RequestInfo {
    /// Client IP address
    pub ip: Option<IpAddr>,
    /// Request path
    pub path: String,
    /// Request method (GET, POST, etc.)
    pub method: String,
    /// User ID (if authenticated)
    pub user_id: Option<String>,
    /// API key (from header or query)
    pub api_key: Option<String>,
    /// Custom headers that might be useful for key extraction
    pub headers: Vec<(String, String)>,
}

impl RequestInfo {
    /// Create a new request info
    pub fn new(path: impl Into<String>, method: impl Into<String>) -> Self {
        Self {
            ip: None,
            path: path.into(),
            method: method.into(),
            user_id: None,
            api_key: None,
            headers: Vec::new(),
        }
    }

    /// Set the IP address
    pub fn with_ip(mut self, ip: IpAddr) -> Self {
        self.ip = Some(ip);
        self
    }

    /// Set the user ID
    pub fn with_user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// Set the API key
    pub fn with_api_key(mut self, api_key: impl Into<String>) -> Self {
        self.api_key = Some(api_key.into());
        self
    }

    /// Add a header
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Get a header value by name (case-insensitive)
    ///
    /// Compares in place rather than lower-casing both sides: this runs on the
    /// request path for every extractor lookup, and the allocations it used to
    /// make were pure overhead for an ASCII case fold.
    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Full lowercase-hex SHA-256 digest of a rate-limit key.
///
/// Used wherever a key leaves process memory or could be read by someone other
/// than the request's author: API-key bucket names, Redis key names. A bucket
/// keyed on the raw value would put a live credential into the store's key
/// space (and into any `KEYS`/`SCAN` output, slowlog, or replica), so only the
/// digest is ever stored.
pub fn key_digest(key: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(key.as_bytes());
    let mut out = String::with_capacity(64);
    for byte in digest.iter() {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Short, non-reversible fingerprint of a rate-limit key for log fields.
///
/// The first 12 hex characters of [`key_digest`]: enough to correlate log lines
/// for the same caller, useless for recovering an API key, token or user id.
/// Rate-limit keys must never be logged verbatim.
pub fn key_fingerprint(key: &str) -> String {
    let mut digest = key_digest(key);
    digest.truncate(12);
    digest
}

/// The bucket an API key is counted in: `apikey:` + [`key_digest`] of the key.
pub fn api_key_bucket(api_key: &str) -> String {
    format!("apikey:{}", key_digest(api_key))
}

/// The bucket identity of a client address.
///
/// IPv4 addresses are used as-is. IPv6 addresses are truncated to their /64
/// prefix: a single subscriber is routinely delegated a whole /64 (or more), so
/// keying per /128 hands every client 2^64 fresh buckets for free. IPv4-mapped
/// IPv6 addresses (`::ffff:a.b.c.d`) are keyed as the IPv4 address they carry,
/// so a dual-stack listener does not split one client across two buckets.
pub fn ip_bucket(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.to_string();
            }
            let prefix = u128::from(v6) & (!0u128 << 64);
            format!("{}/64", std::net::Ipv6Addr::from(prefix))
        }
    }
}

/// Normalize a request path for per-endpoint bucketing.
///
/// The query string and fragment are dropped, empty segments (`//`) and `.`
/// segments are removed, `..` pops the previous segment (never above the root),
/// and a trailing slash is not significant. Without this, `//login`,
/// `/./login`, `/x/../login` and `/login/` would each mint a fresh bucket for
/// the same endpoint under [`KeyExtractor::IpAndPath`] /
/// [`KeyExtractor::UserIdAndPath`].
pub fn normalize_path(path: &str) -> String {
    let path = path.split(['?', '#']).next().unwrap_or("");
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            s => segments.push(s),
        }
    }
    let mut out = String::with_capacity(path.len() + 1);
    out.push('/');
    out.push_str(&segments.join("/"));
    out
}

/// Decides whether a presented API key is genuine.
///
/// [`KeyExtractor::ApiKey`] only keys a request on an API key this validator
/// accepts. Keying on whatever value a caller sends lets every request carry a
/// fresh random "key", mint a fresh bucket, and never be limited (while growing
/// the store without bound). A key that fails validation yields no rate-limit
/// key, so the request falls to the middleware's
/// [`crate::UnkeyedRequestPolicy`] (deny by default).
///
/// The check runs on every request, so it should be an in-memory lookup (e.g.
/// a set of key digests). When keys are verified asynchronously against a
/// database, do that in an authentication layer that attaches an
/// `armature_core::VerifiedIdentity`, and rate limit with [`KeyExtractor::UserId`].
#[derive(Clone)]
pub struct ApiKeyValidator(Arc<dyn Fn(&str) -> bool + Send + Sync>);

impl ApiKeyValidator {
    /// Wrap a validation function.
    pub fn new(f: impl Fn(&str) -> bool + Send + Sync + 'static) -> Self {
        Self(Arc::new(f))
    }

    /// Whether `key` is a valid API key.
    pub fn is_valid(&self, key: &str) -> bool {
        (self.0)(key)
    }
}

impl std::fmt::Debug for ApiKeyValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApiKeyValidator(..)")
    }
}

/// Key extraction strategies
///
/// Every variant here is a strategy this enum can actually evaluate. Custom
/// logic lives in [`KeyExtractorFn`] / [`KeyExtractorBuilder`] instead: a
/// variant that merely carried a description could not call anything, so it
/// always yielded no key — and a missing key is the fail-open path that
/// disables rate limiting for the request.
#[derive(Debug, Clone, Default)]
pub enum KeyExtractor {
    /// Key on the client address (IPv6 bucketed by /64, see [`ip_bucket`]).
    ///
    /// [`crate::RateLimitMiddleware`] fills the address from
    /// `HttpRequest::client_address(trusted_proxy_depth)`: the socket peer by
    /// default, or the forwarded client when a proxy depth is configured.
    #[default]
    Ip,
    /// Key on the authenticated user ID.
    ///
    /// [`crate::RateLimitMiddleware`] fills it **only** from the
    /// `armature_core::VerifiedIdentity` request extension an authentication
    /// layer (e.g. `armature_auth::JwtAuthMiddleware`) attaches after verifying
    /// a credential, never from a request header, so the rate-limit middleware
    /// must run after authentication.
    UserId,
    /// Key on an API key header value that `validator` accepts, stored as its
    /// SHA-256 digest (see [`api_key_bucket`]).
    ApiKey {
        /// Header name for API key
        header_name: String,
        /// Accepts only genuine API keys; see [`ApiKeyValidator`].
        validator: ApiKeyValidator,
    },
    /// Extract key from a custom header
    ///
    /// The header is client-controlled: use it only for values that an earlier
    /// layer has verified or overwritten (e.g. a tenant header set by your own
    /// gateway), never as the sole abuse control on a public endpoint.
    Header {
        /// Header name to extract
        name: String,
    },
    /// Combine client address and normalized path for per-endpoint limiting
    IpAndPath,
    /// Combine user ID and normalized path for per-endpoint limiting
    UserIdAndPath,
}

impl KeyExtractor {
    /// Create an IP-based key extractor
    pub fn ip() -> Self {
        Self::Ip
    }

    /// Create a user ID-based key extractor
    pub fn user_id() -> Self {
        Self::UserId
    }

    /// Create an API key-based extractor that keys only on keys `validator`
    /// accepts.
    ///
    /// ```
    /// use armature_ratelimit::KeyExtractor;
    ///
    /// let extractor = KeyExtractor::api_key("X-API-Key", |key: &str| key == "sk_live_known");
    /// ```
    pub fn api_key(
        header_name: impl Into<String>,
        validator: impl Fn(&str) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self::ApiKey {
            header_name: header_name.into(),
            validator: ApiKeyValidator::new(validator),
        }
    }

    /// Create a header-based extractor
    pub fn header(name: impl Into<String>) -> Self {
        Self::Header { name: name.into() }
    }

    /// Create an IP and path extractor
    pub fn ip_and_path() -> Self {
        Self::IpAndPath
    }

    /// Create a user ID and path extractor
    pub fn user_id_and_path() -> Self {
        Self::UserIdAndPath
    }

    /// Extract the key from request info
    pub fn extract(&self, info: &RequestInfo) -> Option<String> {
        match self {
            Self::Ip => info.ip.map(ip_bucket),
            Self::UserId => info.user_id.clone(),
            Self::ApiKey {
                header_name,
                validator,
            } => info
                .get_header(header_name)
                .filter(|key| !key.is_empty() && validator.is_valid(key))
                .map(api_key_bucket),
            Self::Header { name } => info.get_header(name).map(|s| s.to_string()),
            Self::IpAndPath => info
                .ip
                .map(|ip| format!("{}:{}", ip_bucket(ip), normalize_path(&info.path))),
            Self::UserIdAndPath => info
                .user_id
                .as_ref()
                .map(|uid| format!("{}:{}", uid, normalize_path(&info.path))),
        }
    }

    /// The request header this extractor reads, if any.
    ///
    /// Lets a caller populate only the header it will actually look at instead
    /// of copying the whole header map into [`RequestInfo`] on every request.
    pub fn required_header(&self) -> Option<&str> {
        match self {
            Self::ApiKey { header_name, .. } => Some(header_name),
            Self::Header { name } => Some(name),
            _ => None,
        }
    }

    /// Get a description of this extractor
    pub fn description(&self) -> &str {
        match self {
            Self::Ip => "IP address",
            Self::UserId => "User ID",
            Self::ApiKey { .. } => "API key",
            Self::Header { .. } => "Custom header",
            Self::IpAndPath => "IP + Path",
            Self::UserIdAndPath => "User ID + Path",
        }
    }
}

/// Builder for creating complex key extractors
pub struct KeyExtractorBuilder {
    extractors: Vec<KeyExtractor>,
    fallback_to_ip: bool,
}

impl KeyExtractorBuilder {
    /// Create a new key extractor builder
    pub fn new() -> Self {
        Self {
            extractors: Vec::new(),
            fallback_to_ip: true,
        }
    }

    /// Add an extractor (extractors are tried in order)
    pub fn with_extractor(mut self, extractor: KeyExtractor) -> Self {
        self.extractors.push(extractor);
        self
    }

    /// Try user ID first
    pub fn prefer_user_id(self) -> Self {
        self.with_extractor(KeyExtractor::UserId)
    }

    /// Try a validated API key first (see [`KeyExtractor::api_key`])
    pub fn prefer_api_key(
        self,
        header_name: impl Into<String>,
        validator: impl Fn(&str) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.with_extractor(KeyExtractor::api_key(header_name, validator))
    }

    /// Disable fallback to IP if other extractors fail
    pub fn no_ip_fallback(mut self) -> Self {
        self.fallback_to_ip = false;
        self
    }

    /// Build the extractor function
    pub fn build(self) -> impl Fn(&RequestInfo) -> Option<String> + Send + Sync {
        let extractors = self.extractors;
        let fallback_to_ip = self.fallback_to_ip;

        move |info: &RequestInfo| {
            // Try each extractor in order
            for extractor in &extractors {
                if let Some(key) = extractor.extract(info) {
                    return Some(key);
                }
            }

            // Fallback to IP if enabled
            if fallback_to_ip && let Some(ip) = info.ip {
                return Some(ip_bucket(ip));
            }

            None
        }
    }
}

impl Default for KeyExtractorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn sample_request() -> RequestInfo {
        RequestInfo::new("/api/users", "GET")
            .with_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
            .with_user_id("user_123")
            .with_api_key("sk_test_abc123")
            .with_header("X-API-Key", "sk_test_abc123")
            .with_header("X-Tenant-ID", "tenant_456")
    }

    #[test]
    fn test_ip_extractor() {
        let extractor = KeyExtractor::ip();
        let request = sample_request();

        let key = extractor.extract(&request).unwrap();
        assert_eq!(key, "192.168.1.1");
    }

    #[test]
    fn test_user_id_extractor() {
        let extractor = KeyExtractor::user_id();
        let request = sample_request();

        let key = extractor.extract(&request).unwrap();
        assert_eq!(key, "user_123");
    }

    #[test]
    fn test_api_key_extractor() {
        let extractor = KeyExtractor::api_key("X-API-Key", |k: &str| k == "sk_test_abc123");
        let request = sample_request();

        let key = extractor.extract(&request).unwrap();
        assert_eq!(key, api_key_bucket("sk_test_abc123"));
        assert!(
            !key.contains("sk_test_abc123"),
            "the raw API key must never be the bucket name"
        );
    }

    /// Security regression (H11): an unvalidated API key used to mint a fresh
    /// bucket per random value, so a caller rotating junk keys was never
    /// limited. Only keys the validator accepts produce a key at all.
    #[test]
    fn test_api_key_extractor_rejects_unvalidated_keys() {
        let extractor = KeyExtractor::api_key("X-API-Key", |k: &str| k == "sk_live_known");
        for junk in ["random-1", "random-2", ""] {
            let request = RequestInfo::new("/api", "GET").with_header("X-API-Key", junk);
            assert_eq!(extractor.extract(&request), None, "junk key {junk:?} keyed");
        }
        let request = RequestInfo::new("/api", "GET").with_header("X-API-Key", "sk_live_known");
        assert_eq!(
            extractor.extract(&request),
            Some(api_key_bucket("sk_live_known"))
        );
    }

    #[test]
    fn test_key_digest_and_fingerprint() {
        let digest = key_digest("abc");
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(key_fingerprint("abc"), "ba7816bf8f01");
    }

    /// Security regression (H11): IPv6 was keyed per /128, so one subscriber
    /// with a delegated /64 had 2^64 buckets.
    #[test]
    fn test_ipv6_bucketed_by_64() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff:ffff:ffff:ffff".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(ip_bucket(a), ip_bucket(b));
        assert_eq!(ip_bucket(a), "2001:db8:1:2::/64");
        assert_ne!(ip_bucket(a), ip_bucket(c));

        let mapped: IpAddr = "::ffff:192.0.2.7".parse().unwrap();
        assert_eq!(ip_bucket(mapped), "192.0.2.7");

        let extractor = KeyExtractor::ip();
        assert_eq!(
            extractor.extract(&RequestInfo::new("/", "GET").with_ip(a)),
            extractor.extract(&RequestInfo::new("/", "GET").with_ip(b)),
        );
    }

    /// Security regression (H11): `IpAndPath` keyed on the raw path, so
    /// `//login`, `/./login` and `/x/../login` each got a fresh bucket.
    #[test]
    fn test_path_normalization_shares_bucket() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let extractor = KeyExtractor::ip_and_path();
        let expected = "192.0.2.1:/login".to_string();
        for path in [
            "/login",
            "//login",
            "/./login",
            "/x/../login",
            "/login/",
            "/login?a=1",
            "/../../login",
        ] {
            let info = RequestInfo::new(path, "POST").with_ip(ip);
            assert_eq!(extractor.extract(&info), Some(expected.clone()), "{path}");
        }
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("/a//b/./c/../d"), "/a/b/d");

        let by_user = KeyExtractor::user_id_and_path();
        let info = RequestInfo::new("//api//users/", "GET").with_user_id("u1");
        assert_eq!(by_user.extract(&info), Some("u1:/api/users".to_string()));
    }

    #[test]
    fn test_header_extractor() {
        let extractor = KeyExtractor::header("X-Tenant-ID");
        let request = sample_request();

        let key = extractor.extract(&request).unwrap();
        assert_eq!(key, "tenant_456");
    }

    #[test]
    fn test_ip_and_path_extractor() {
        let extractor = KeyExtractor::ip_and_path();
        let request = sample_request();

        let key = extractor.extract(&request).unwrap();
        assert_eq!(key, "192.168.1.1:/api/users");
    }

    #[test]
    fn test_user_id_and_path_extractor() {
        let extractor = KeyExtractor::user_id_and_path();
        let request = sample_request();

        let key = extractor.extract(&request).unwrap();
        assert_eq!(key, "user_123:/api/users");
    }

    #[test]
    fn test_builder() {
        let extractor = KeyExtractorBuilder::new()
            .prefer_user_id()
            .prefer_api_key("X-API-Key", |k: &str| k == "sk_test_abc123")
            .build();

        let request = sample_request();
        let key = extractor(&request).unwrap();
        assert_eq!(key, "user_123"); // User ID is preferred

        // Without user ID, falls back to API key
        let request_no_user = RequestInfo::new("/api/users", "GET")
            .with_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
            .with_header("X-API-Key", "sk_test_abc123");

        let key = extractor(&request_no_user).unwrap();
        assert_eq!(key, api_key_bucket("sk_test_abc123"));

        // Without user ID or API key, falls back to IP
        let request_ip_only = RequestInfo::new("/api/users", "GET")
            .with_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));

        let key = extractor(&request_ip_only).unwrap();
        assert_eq!(key, "192.168.1.1");
    }

    #[test]
    fn test_builder_no_ip_fallback() {
        let extractor = KeyExtractorBuilder::new()
            .prefer_user_id()
            .no_ip_fallback()
            .build();

        // Without user ID, returns None
        let request = RequestInfo::new("/api/users", "GET")
            .with_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));

        assert!(extractor(&request).is_none());
    }

    #[test]
    fn test_request_info_builder() {
        let info = RequestInfo::new("/api/test", "POST")
            .with_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .with_user_id("u123")
            .with_header("Content-Type", "application/json");

        assert_eq!(info.path, "/api/test");
        assert_eq!(info.method, "POST");
        assert_eq!(info.ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(info.user_id, Some("u123".to_string()));
        assert_eq!(info.get_header("content-type"), Some("application/json"));
    }
}
