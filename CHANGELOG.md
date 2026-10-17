# Changelog — `armature-ratelimit`

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Earlier changes are recorded in the workspace [`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

### Security

- `RateLimitMiddleware` derives the client address from `HttpRequest::client_address(trusted_proxy_depth)`. With the default depth `0` it now keys on the **socket peer** (previously it had no address and limited nothing); with a depth it reads the forwarded chain across every `X-Forwarded-For` line instead of only the first. `X-Real-IP` is no longer consulted.
- `KeyExtractor::UserId` / `UserIdAndPath` key only on the `armature_core::VerifiedIdentity` request extension an authentication layer attaches after verifying a credential; the client-supplied `X-User-Id` header is ignored.
- API-key buckets are created only for keys an `ApiKeyValidator` accepts and are named `apikey:<sha256>`; rotating junk keys no longer mints unlimited buckets.
- IPv6 clients are bucketed by /64 (IPv4-mapped addresses as IPv4); `IpAndPath` / `UserIdAndPath` normalize the path (`//`, `.`, `..`, trailing `/`, query), so path variants share one bucket.
- Rate-limit keys are never logged verbatim (12-hex-char SHA-256 fingerprint only), and the Redis store names its keys by the key's SHA-256 digest. The Redis connection URL (which may hold a password) is no longer logged.

### Changed

- **Breaking:** `UnkeyedRequestPolicy` defaults to `Deny` (was `Allow`): a request no key can be derived from gets a 429. Opt back in with `.with_unkeyed_policy(UnkeyedRequestPolicy::Allow)` only where another layer protects the route.
- **Breaking:** `KeyExtractor::ApiKey` gained a `validator: ApiKeyValidator` field; `KeyExtractor::api_key(header, validator)` and `KeyExtractorBuilder::prefer_api_key(header, validator)` take a `Fn(&str) -> bool`. Migration: pass a check against your known keys (e.g. a set lookup).
- **Breaking:** `UserId` / `UserIdAndPath` keying requires the rate-limit middleware to run after the authentication middleware that inserts `VerifiedIdentity`; without it those requests are unkeyed (and denied by default).
- **Breaking:** existing Redis rate-limit state is not carried over (key names are now digests); buckets start fresh after upgrading.

### Added

- `extractor::{key_digest, key_fingerprint, api_key_bucket, ip_bucket, normalize_path}` helpers and `ApiKeyValidator`.
- Dependency: `sha2` 0.11.

## [0.5.0] - 2026-09-15

### Changed

- **Breaking:** requires `armature-core` 0.10 (was `0.9`); its types appear in this crate's API, so the requirement change is breaking here and the minor moves. Part of the `armature-core` 0.10 release train.
- Dependencies bumped to their latest releases: `http` 1.4 → 1.5, `redis` 1.3 → 1.7, `tokio` 1.52 → 1.53, `tokio` 1.52 → 1.53.

## [0.4.0] - 2026-08-05

### Changed

- **Requires `armature-core` 0.9 (breaking).** The requirement moved `0.8` →
  `0.9`. `armature-core 0.9.0` itself moves `armature-h1` across a breaking
  0.x boundary; because `armature-core` types appear in this crate's own
  public API, the requirement change is breaking here too and the minor moves
  with it. Under Cargo's 0.x caret rules the 0.8 and 0.9 types are distinct
  and do not unify, so a consumer holding an `armature-core 0.8` type cannot
  pass it to this crate. Part of the `armature-core 0.9.0` release train; see
  `armature-core`'s CHANGELOG for the publish order.

## [0.3.1] - 2026-08-04

### Fixed

- Requirements on sibling armature crates name a minor instead of `0`. Under
  Cargo's 0.x rules `version = "0"` matches any release ever made, and edition
  2024 selects the MSRV-aware resolver, so a consumer declaring an older
  `rust-version` was handed the oldest version satisfying it — resolving
  `armature-core = "0"` on Rust 1.89 produced `armature-core 0.2.3` while an
  explicit `armature-core = "0.8"` elsewhere in the same graph pulled 0.8.2.
  Two copies of core, and a build failing on symbols the older one lacks. Each
  0.x minor in this family is a breaking change, so the requirement now names
  one. No API change.
