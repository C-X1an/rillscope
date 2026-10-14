# Dependency decisions

Checked 2026-10-14. Exact selected versions below are from official release or package documentation, not proof of a successful build or a clean security scan. Revalidate availability, compatibility, transitive licenses and RustSec when adding the frontend dependencies. The initial Rust kernel deliberately uses only std; its Cargo.lock has no registry graph. Do not manufacture checksums or a lockfile for unresolved third-party dependencies.

## Rust 1.99.0
status: selected toolchain; not installed in this environment
license: MIT OR Apache-2.0 (toolchain components have their own notices)
source: https://blog.rust-lang.org/releases/
reason: Official release index lists 2026-10-01 stable; do not treat 1.99.1 pre-release or future dates as released.

## serde 1.0.229
status: planned frontend dependency, not in dependency-free kernel seed
license: MIT OR Apache-2.0
source: https://docs.rs/crate/serde/1.0.229
reason: Explicit typed serialization; deny unknown fields.

## serde_json 1.0.151
status: planned frontend dependency, not yet resolved
license: MIT OR Apache-2.0
source: https://docs.rs/crate/serde_json/1.0.151
reason: JSON transport only; bounded bytes/depth and duplicate key handling must be verified.

## sqlparser 0.62.0
status: planned SQL syntax parser; not execution engine
license: Apache-2.0
source: https://docs.rs/crate/sqlparser/0.62.0
reason: Reuse mature syntax parsing; lower only documented AST variants; own binder/optimizer/operators.

## proptest 1.11.0
status: optional dev-only after seeded independent generator
license: MIT OR Apache-2.0
source: https://docs.rs/crate/proptest/1.11.0
reason: Shrinking property cases; no need to add for deterministic reference tests.

## cargo-audit 0.22.2
status: planned verification tool
license: MIT OR Apache-2.0
source: https://docs.rs/crate/cargo-audit/0.22.2
reason: RustSec advisory check; unavailable network must be BLOCKED, not PASS.

## cargo-deny 0.20.2
status: planned verification tool
license: MIT OR Apache-2.0
source: https://docs.rs/crate/cargo-deny/0.20.2
reason: License/source/dependency policy; inspect resolved graph.

## cargo-fuzz 0.13.2
status: optional extended verification, nightly pin required when used
license: MIT OR Apache-2.0
source: https://docs.rs/crate/cargo-fuzz/0.13.2
reason: Real libFuzzer campaigns beyond deterministic malformed corpus; no duration claims without execution.

## Python 3.11+ API contract; actual here 3.13.5
status: available
license: PSF-2.0
source: https://docs.python.org/3/library/sqlite3.html
reason: Stdlib independent SQLite oracle, test harness, report/evidence tooling.

## SQLite runtime sqlite3.sqlite_version recorded during tests
status: available through Python; record actual version
license: public domain dedication by SQLite authors
source: https://sqlite.org/copyright.html
reason: Independent authorized-relation semantics; constrain numeric/collation differences.

## API use rules and compatibility
Use explicit serde derives with `deny_unknown_fields`, custom duplicate-field handling and bounded input validation; avoid a permissive arbitrary Value path that loses structural constraints. sqlparser is only syntax: unmatched constructs reject; inspect the pinned 0.62.0 AST rather than copying outdated examples. Keep parser recursion bounded. No clap needed for a tiny CLI, no Tokio needed for one synchronous process, no Arrow/Parquet needed for the initial typed in-memory contract, no database/LLM/network client in the production dependency graph. SQLite is test-only. Benchmark tools cannot silently use the oracle to produce product results.

## Dependency resolution gate
1. Install pinned released toolchain from official sources in an isolated development environment.
2. Add only the currently needed pinned direct dependencies, generate Cargo.lock with Cargo, inspect source/feature/license tree, and run advisory checks.
3. Record actual versions, hashes, platform, command exits and licenses. Commit the lockfile only after resolution.
4. A known vulnerable necessary dependency requires an evidence-backed time-bounded waiver reviewed independently; no automatic ignore-all. Prefer patch/update/removal over suppression.
5. Never claim no vulnerabilities merely because std-only seed has no third-party graph; toolchain/OS still matter.

Available environment observation: rustc/cargo/rustup absent from PATH; direct DNS to static.rust-lang.org failed. Web reads of documentation succeeded; toolchain download did not. This is an execution-environment dependency, not a human-only requirement or permission to weaken compiler acceptance. Continue reference/harness/documentation and retry in the Codex runtime with network access.
