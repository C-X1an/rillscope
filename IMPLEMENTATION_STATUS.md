# Implementation status

RillScope is an experimental original Rust restricted-query compiler and executor. Full release readiness remains incomplete; no production use is claimed.

| Layer | Current implementation and recorded evidence |
|---|---|
| Exact nullable Int64, Boolean, UTF-8 columns and checked expressions | Implemented; owned primitive arrays/UTF-8 buffers and validity bitmaps |
| Immutable validated catalog/context | Implemented; raw-content digests and exact object identity; malformed schemas/values rejected |
| Closed JSON and restricted SQL frontends | Implemented; bounded bytes/depth/nodes; decoded duplicate keys rejected; unsupported SQL effects/statements denied |
| Binder and trusted policy lowering | Implemented; all expression positions bind before scan execution |
| Opaque VerifiedPlan and independent traversal | Implemented; schema/types/provenance/grants/source identities recomputed; known-bad unit plans rejected |
| Original pull-based batch engine | Implemented scan/filter/project, duplicate-preserving hash join, nullable aggregation, stable bounded sort, limit |
| Work, logical reservations, cancellation and collector | Implemented; finite charges, RAII release, typed failures and complete result publication |
| Optimizer | Implemented projection pruning and pure filter pushdown, with no push beneath PolicyScan; bounded 16-pass convergence and optimization-off mode |
| Local source checks | PASS at recorded revisions: Rust 1.99 GNU Windows build/fmt/Clippy/check; 29 unit tests; 19 real CLI tests |
| Generated semantic / malformed corpus | PASS at recorded revisions: 1,000 Rust optimization on/off cases versus physically scoped SQLite; 1,000 finite malformed inputs; raw verdicts preserved |
| Actual process failure | PASS: CLI killed after a real join checkpoint; catalog raw SHA-256 unchanged; independent rerun succeeded |
| Linux | Cross-target static check PASS; actual Linux runtime and signal latency NOT RUN |
| Selected Rust mutations | Harness implemented; execution NOT RUN until the audited candidate is committed |
| Rust demo, adapter and browser review | NOT RUN / pending |
| Rust benchmarks and reference-host targets | NOT YET MEASURED |
| Fresh complete Rust checkout / independent review | NOT RUN / pending |
| Public remote repository / CI | NOT RUN; portable gh installed but CLI authentication absent |

Recorded checks do not prove complete correctness or complete vulnerability coverage. The 1,000-case generator uses ten small-catalog families; the malformed campaign is finite seeded testing, not a libFuzzer-duration claim. Hardware capacities in PRD remain design capacities unless measured separately. Logical reservations are distinct from process RSS and OS containment.

SQL identifiers are normalized to lowercase. Complex unnamed selected expressions receive `_exprN`; use explicit aliases for durable output names. SQL NULL literals infer the other operand's type; a standalone NULL defaults to nullable Int64. GROUP BY selection uses documented group expressions/aggregates. JSON always requires an explicit type for NULL literals. These rules preserve the locked closed language; full SQL compatibility is outside scope.

The original dependency-free kernel and its ten tests remain in `src/seed.rs` as a test-only historical fixture. Production queries use the full opaque VerifiedPlan path. Python reference tooling remains an independent semantic aid and never establishes Rust correctness.
