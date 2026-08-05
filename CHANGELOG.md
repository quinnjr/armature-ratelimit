# Changelog — `armature-ratelimit`

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Earlier changes are recorded in the workspace [`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

### Added

- Adopted the `ratelimit` criterion benchmark (token bucket, sliding window, concurrent and hot-key workloads) from the root package's `benches/`. Run it with `cargo bench -p armature-ratelimit --bench ratelimit`. The crate now sets `autobenches = false`, so a new file under `benches/` needs an explicit `[[bench]]` entry. `criterion` also gains the `async_tokio` feature: the limiter benchmarks use `Bencher::to_async`, which is feature-gated, so without it this bench does not compile outside the workspace.

### Fixed

- **Breaking:** an unkeyed request is now governed by an explicit `UnkeyedRequestPolicy` and counted in `unkeyed_allow_count`. The default middleware could never extract a key, so it allowed every request with only a log line and no counter — an inert security control.
- **Breaking:** `KeyExtractor::Custom` is removed. It carried a description string and no function, so selecting it silently disabled rate limiting through the unkeyed path; `KeyExtractorFn`/`KeyExtractorBuilder` are the working mechanism.
- **Breaking:** `MemoryStore::new()` defaults to a bounded `max_keys` and a shorter idle TTL. The documented protection against a key-rotating client did not hold under the previous unbounded default.
- Eviction at the cap is amortized over a batch instead of a full scan per new key, so the attacker the cap targets can no longer convert memory pressure into CPU pressure.
- Rate-limit keys use `path_only()`, closing a bucket-minting bypass via query strings.

### Changed — `0.2.1` → `0.2.2`

- Migrated onto `armature-core` `0.8`'s `Bytes`-backed request and response types. No behavior change beyond what that migration implies; see [`armature-core/CHANGELOG.md`](../armature-core/CHANGELOG.md).

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
