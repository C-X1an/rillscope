# Implementation status

The e7f9426 Linux CI run completed all four jobs, including the full additional 40-case nullable-sort campaign. A subsequent independent inspection identified further release-verifier freshness, metric-type and Linux descendant-ownership gaps. New regression tests are being committed before fixes to retain a real failing control. Final acceptance remains incomplete; the existing Rust compiler/executor source is unchanged.

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
| Optimizer | Implemented projection pruning and pure filter pushdown, with no push beneath PolicyScan; predicts growth before cloning; bounded traversal and 16-pass convergence, with E_PLAN for nonconvergence |
| Local source checks | PASS at recorded revisions: Rust 1.99 GNU Windows build/fmt/Clippy/check; 36 Rust unit tests; 31 real CLI/adapter/report tests |
| Generated semantic / malformed corpus | PASS at recorded revisions: 1,000 cases comparing both JSON and SQL, optimizer on/off, with scoped SQLite; 2,000 finite malformed inputs (1,000 JSON + 1,000 SQL); raw verdicts preserved |
| Actual process failure | PASS: CLI killed after a real join checkpoint; catalog raw SHA-256 unchanged; independent rerun succeeded |
| Linux | Actual shared Ubuntu runner at commit 427aaf9 passed native checks, semantic/malformed/mutation campaigns, export security, pilot and SIGINT cancellation; dedicated reference-host targets remain unmeasured |
| Selected Rust mutations | Ten actual Rust PASS-FAIL-PASS controls at 3ecfb02e; actual HTML escape PASS-FAIL-PASS at 427aaf9, including a fresh source-bound build at each stage |
| Rust demo, adapter and browser review | PASS: actual alpha/denial/beta Rust calls with scoped SQLite; two adapter/HTML tests; real Chrome desktop/narrow captures and keyboard inspection |
| Rust benchmarks and reference-host targets | Source-bound schema-3 release pilots passed. Complete 410-case available-host capture is running from frozen 3ecfb02e; stronger current artifact validation and an additional NULL-sort campaign are required. Dedicated Linux target measurements remain pending |
| Independent review | Independent source inspections at pinned revisions identified defects before integrator reproduction/fixes. Reviewers executed no commands. Follow-up427 findings concern evidence qualification, Linux command lifetime, sorting experiment definitions and a publication-boundary question; final closure remains pending |
| Resolved licenses / online dependency policy | Actual graph: 26 registry packages and 27 preserved notice files; inventory and online advisory/policy scans PASS at recorded revision/database time |
| Fresh complete Rust checkout | Actual frozen427aaf9 Windows checkout: bootstrap/demo/reference/property/malformed/mutation/online policy PASS; aggregate verify/security FAIL on symlink setup, reference benchmark unavailable. Final corrected-source full reproduction remains incomplete |
| Public remote repository / CI | [Public repository](https://github.com/C-X1an/rillscope) created after a 220-file export and 347-object history audit. New revisions receive separate audits. [427aaf9 CI](https://github.com/C-X1an/rillscope/actions/runs/38877711666) PASS; subsequent explicit regression controls at 3b52928 fail as expected and precede integrator fixes. No release is published |

Recorded checks do not prove complete correctness or complete vulnerability coverage. The 1,000-case generator uses ten small-catalog families; the malformed campaign is finite seeded testing, not a libFuzzer-duration claim. The reproduced SQL nesting stack overflow, optimizer expansion rejection, grouped qualification error, unsupported SQL ordering acceptance and missing expression reservations have regression tests. Reservations cover expression temporaries; sort reordering now charges/checks every row. Hardware capacities in PRD remain design capacities unless measured separately. Logical reservations are distinct from process RSS and OS containment.

SQL identifiers are normalized to lowercase. Complex unnamed selected expressions receive `_exprN`; use explicit aliases for durable output names. SQL NULL literals infer the other operand's type; a standalone NULL defaults to nullable Int64. GROUP BY selection uses documented group expressions/aggregates. JSON always requires an explicit type for NULL literals. These rules preserve the locked closed language; full SQL compatibility is outside scope.

The original dependency-free kernel and its ten tests remain in `src/seed.rs` as a test-only historical fixture. Production queries use the full opaque VerifiedPlan path. Python reference tooling remains an independent semantic aid and never establishes Rust correctness.
