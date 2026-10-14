# Implementation status
This is a development seed, not a finished Rust query engine.

| Layer | Status |
|---|---|
| Restricted JSON semantic reference | Implemented in Python; source-level tests and seeded SQLite differential harness available |
| Typed Rust nullable columns, Boolean logic and checked arithmetic | Source implemented; compilation/tests NOT RUN in the authoring environment |
| Rust host-bound verified scan, tenant filtering, work/cancel/output caps | Source implemented; general plan verification and memory accounting not yet implemented |
| Rust binder, SQL parser, full IR, optimizer, general operators and full CLI | NOT IMPLEMENTED |
| Independent physical-plan verifier | Architecture/acceptance specified; NOT IMPLEMENTED (scan validation is not equivalent) |
| Rust logical memory reservations / process limits | NOT IMPLEMENTED |
| Real Rust differential/fuzz/mutation/E2E/performance suite | NOT RUN / incomplete |
| Public remote GitHub repository / CI | Not created/executed in this session |
| Independent external assessment | NOT RUN |

The executable reference is intentionally a simple row interpreter with nested-loop joins and row/work/output limits. It has no SQL parser, optimizer, independent physical-plan verifier, memory reservation or cancellation implementation. It is not safe to deploy as a multi-user security service. Its counters are reference work units, not Rust throughput or RSS measurements. It can explore the semantics while the original Rust batch engine is completed.

Architecture and acceptance files describe the intended finished system, not a claim that every component exists. Reference tests do not satisfy Rust acceptance criteria. Full verification fails explicitly while required product gates are incomplete; no skipped checks are silently reported as passing.
