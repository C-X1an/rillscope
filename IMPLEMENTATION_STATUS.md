# Implementation status

The Rust compiler/executor is implemented. This is an experimental engineering delivery with [AC-008 visual/keyboard inspection unverified](TEST_SPEC_EXCEPTION_AC-008.md); full strict acceptance and production readiness remain unestablished.

| Area | Implemented behavior |
| --- | --- |
| Values and catalog | Nullable Int64/Boolean/UTF-8 columns, immutable validated catalog/context, exact content and object identities |
| Frontends | Closed bounded JSON and restricted SQL; duplicate/unknown keys and unsupported effects rejected |
| Authority | All-position binding, trusted PolicyScans and an opaque VerifiedPlan; independent traversal recomputes schema/provenance/grants |
| Execution | Pull-based batches, filter/project, duplicate-preserving hash join, nullable aggregation, stable sort and limit |
| Limits and failure | Checked work/logical reservations, row/byte caps, cooperative cancellation and complete-result serialization |
| Optimization | Projection pruning and pure filter pushdown with bounded growth/convergence; no push below PolicyScan |
| CLI and demo | `run`, `explain`, `--version`, fixed-scope adapter and offline Rust/SQLite report |
| Verification | Native/static, reference, integration, property, malformed, mutation, transport and source-custody checks |

Recorded tests and measurements are summarized in [verification](VERIFICATION_REPORT.md), [claims](CLAIMS_EVIDENCE.md) and [benchmarks](BENCHMARKS.md). Raw development logs and superseded evidence are private. A finite corpus is not complete correctness or security proof. The final review shares implementation history.

Logical reservations do not impose process RSS limits or OS isolation. The trusted host already has catalog access. See the [threat model](THREAT_MODEL.md) and [limitations](LIMITATIONS.md).
