# RillScope product requirements

Version: 1.0 | research_as_of: 2026-10-14 | Status: implementation contract, not a completion claim

## Product thesis and user
RillScope is an experimental query compiler and bounded executor that makes the interaction between query optimization and scoped data access inspectable. The primary user is a developer exposing a small read-only analytical tool to an untrusted client, including an agent. The secondary user is an engineer reviewing or learning compiler/execution internals. There is no chatbot and no LLM dependency.

The user wants to submit a documented query, receive a well-typed result or precise safe error, inspect the transformed plan, and reproduce why a prohibited query was rejected. A reviewer wants to compare an optimized execution with independent results over only the authorized relations.

## Jobs and detailed stories
US-01: A platform developer supplies a catalog, tenant and column allowlist through a trusted host configuration, then exposes only the query field to a tool client. The client cannot select another configuration or tenant.
US-02: A reviewer runs the same sales query under two independently configured contexts and sees only the appropriate rows, including through join/aggregate paths.
US-03: A compiler developer toggles optimization and inspects rule trace, operator counters and the exact authorized result without a change in semantics.
US-04: A malicious client references a forbidden column in a predicate rather than projection. Binding rejects it before execution and emits no hidden data.
US-05: A developer submits a query that exceeds a work or logical-memory budget. It returns a typed error, not truncated rows labeled success.
US-06: A maintainer reproduces a reported NULL/duplicate-row failure from a minimized public-safe fixture and checks the fix against an independent oracle.
US-07: A reviewer opens the offline report without internet, scripts or external fonts and can understand its result, plan and limitations.

## Requirements
- **FR-001 [critical]** Accept a versioned restricted relational JSON query and reject unknown fields/operators.
- **FR-002 [high]** Parse the documented read-only SELECT subset into the same unresolved relational representation.
- **FR-003 [critical]** Bind identifiers to stable column IDs; reject unknown/ambiguous columns and ill-typed expressions.
- **FR-004 [critical]** Execute scan/filter/project/inner equijoin/group aggregate/order/limit using original Rust column-batch operators.
- **FR-005 [critical]** Implement nullable Int64, Boolean and UTF-8 with three-valued predicates and bag semantics.
- **FR-006 [critical]** Apply projection pruning and safe predicate pushdown within policy-safe boundaries, with an optimization-off mode.
- **FR-007 [high]** Expose a redacted explain trace of binding, logical rewrites and verified physical operators.
- **FR-008 [high]** Provide a deterministic CLI demo plus escaped offline HTML inspector and a fixed-scope agent adapter.
- **FR-009 [high]** Load operator-supplied immutable catalogs with explicit schemas; validate values before query execution.
- **SEC-001 [critical]** Every base scan must enforce the trusted context tenant predicate before user expressions; query cannot supply authority.
- **SEC-002 [critical]** Deny forbidden columns in projection, filter, join, grouping, aggregate and sorting expressions.
- **SEC-003 [critical]** Only an independently validated physical plan may enter execution; unknown or missing policy provenance is rejected.
- **SEC-004 [critical]** No query-accessible filesystem/network/extension/UDF/native-code/DDL/DML facility.
- **SEC-005 [high]** Keep hidden values, raw predicates, tokens and unfiltered row counts out of ordinary errors/explain/logs.
- **SEC-006 [critical]** Bound query bytes, depth, node count, string size and finite work; fail closed on limit exhaustion.
- **SEC-007 [critical]** No private user/employer material, live credentials or unnecessary internal execution files in public export.
- **REL-001 [critical]** A query observes one immutable catalog snapshot and one trusted policy revision throughout execution.
- **REL-002 [critical]** Budget, cancellation and execution errors produce one typed failure and no partial successful result.
- **REL-003 [high]** Identical valid input/context/snapshot produces semantically identical results; unordered rows are compared as bags.
- **REL-004 [high]** A terminated query cannot corrupt catalog data or affect a subsequent independent invocation.
- **PERF-001 [high]** Produce reproducible synthetic timing/memory/work profiles across operator workloads and optimization modes.
- **PERF-002 [target]** On the documented reference host, target p95 under 1 second for a warm 100k-row filter/project with no output serialization in the execution-only timer.
- **PERF-003 [target]** Cancellation observation target <=100ms on the documented reference host with cooperative checks every batch and every 1024 inner-loop steps.
- **NFR-001 [critical]** Build, format, lint and test from an isolated fresh checkout using locked dependency resolution.
- **NFR-002 [high]** No unsafe Rust in first-party code; all public APIs return explicit typed errors instead of panic for invalid user input.
- **NFR-003 [critical]** Machine-capture important commands, inputs/source identity, timestamps, exits and output hashes.
- **NFR-004 [critical]** Maintain test/claim/acceptance traceability and distinguish targets, observations, tested/design capacity and production use.
- **NFR-005 [high]** Demo and standard verification need no credentials, purchased service or hosted model.
- **NFR-006 [medium]** Documentation and inspector are keyboard-readable, semantically structured and understandable without color.
- **NFR-007 [high]** Public source is MIT licensed with dependency and dataset notices; no production readiness assertion.

## Invariants
I1: No execution leaf can read a base relation except a context-bound `PolicyScan`; an ordinary `Scan` exists only in unresolved input, never executable form.
I2: Every user column reference must belong to its scoped relation and the allowlist, regardless of its syntactic location.
I3: Optimization preserves result schema, NULL behavior, duplicates and authorized row semantics; the physical verifier does not trust optimizer assertions.
I4: A `VerifiedPlan` is constructed only by the verifier and is not deserializable or publicly constructible from arbitrary input.
I5: Context and catalog snapshot are immutable per query. No plan/result cache exists in core, removing cross-context reuse as a first-release attack surface.
I6: Errors never become successful partial results. Result buffers have explicit row/byte limits; reaching either is an error unless an explicit semantic LIMIT already reduced the result.
I7: Catalog/policy loading is trusted operator activity, not a query feature. Same-user process access and a malicious host operator are outside authorization claims.

## Core scope and supported environment
One local Rust library/CLI, Linux x86_64 first; macOS/Windows compatibility is optional until tested. Python 3.11+ is used for independent SQLite oracles, evidence capture and static HTML. Rust is pinned after dependency research. One immutable in-memory snapshot, at most four base tables per query; SQL input is limited to at most one INNER equijoin in v1. No service is needed. JSON IR allows the documented operator tree but never executable policy nodes. Queries run serially per invocation; external callers can run separate limited processes.

Default design limits: query <=64 KiB UTF-8; depth <=32; <=256 nodes; <=64 selected/output columns; <=4 scans; <=16 group keys; strings <=4096 bytes; <=1 million rows per trusted loaded table and <=256 MiB catalog input bytes; 1024 rows per batch; <=64 MiB logical query reservations; <=10 million charged work units; <=10,000 result rows; <=1 MiB serialized output. Values may be tightened by trusted configuration, never loosened by query input. Design capacities are not tested capacities.

Int64 arithmetic is checked. NULL propagates through arithmetic/comparison; predicates keep only TRUE. Equality joins do not match NULL. COUNT(*) counts rows; COUNT(expr) excludes NULL; SUM ignores NULL and is NULL for an empty input; COUNT is zero for an empty ungrouped input. Grouping treats NULL keys as one group. Ascending/descending sort supports explicit NULLS FIRST/LAST; default is NULLS LAST for both directions, a documented deliberate dialect choice. String ordering is UTF-8 byte lexical, no collation or Unicode normalization. Unordered results have no guaranteed presentation order.

## Performance, reliability and security targets
PERF-002/003 are targets, not promised measurements or blockers that permit weakening correctness. Target context: a dedicated 4-core x86_64 Linux system, 8 GiB RAM, release build, stored-input generation excluded; record actual CPU/toolchain, never fabricate this host. Test both execution-only and end-to-end CLI timing. Full benchmark uses 30 paired measured repetitions after 5 warmups; micro/smoke results are not substitutes. No availability SLA, production traffic, users or distributed capacity is claimed.

Correctness target: zero observed mismatches in the locked finite suite, including at least 1,000 generated small-catalog oracle cases. Security target: all selected denial/invariant mutations are detected. This is not complete vulnerability coverage. Logical memory accounting is distinct from RSS and OS enforcement; Linux process/cgroup containment is a separate optional profile, not an intrinsic library promise.

## Privacy, retention, portability and accessibility
Synthetic catalog fixtures only. Raw query/result logs are off by default. CLI input/output is operator-controlled and may be sensitive; ignored local runs require manual retention decisions, default no retention beyond explicitly requested files. Public export contains only sanitized synthetic evidence. Raw verification artifacts remain outside the public worktree unless reviewed. Store/copy of the read-only catalog is portable JSON with an explicit schema version; binary storage engine and migrations are out of scope. JSON/schema versions reject unknown major versions. Inspector uses semantic headings/tables, text labels, high contrast and no scripts/external resources.

## Edge cases and failure modes
Empty tables, duplicate keys, all-NULL aggregate, overflow, invalid UTF-8, ambiguous join columns, denied column used only in WHERE/ORDER, cyclic or deeply nested input, huge literals, unknown relation, forged policy node, output expansion in many-to-many joins, skewed group state, budget exhaustion in an inner loop, cancellation before start/during operator/before result publication, catalog mismatched schema, hidden tenant values in errors, and optimizer schema drift each require tests.

## Non-goals and optional future scope
Non-goals: full SQL/PostgreSQL/DuckDB compatibility; database storage, transactions/WAL; distributed query/consensus; arbitrary data ingestion from the network; extensions/UDFs; arbitrary generated native code; JIT/GPU; spill-to-disk; a hosted multi-tenant execution service; OIDC; Kubernetes; model training; differential privacy; eliminating timing/inference side channels; proving a verifier cannot contain bugs. Future scope only after core gates: Arrow IPC interchange, more joins, cost-based join ordering, spill with encryption/lifecycle controls, or a real authenticated local service. Every addition needs an ADR/removal test, not automatic scope growth.
