# Locked acceptance specification

acceptance_spec_locked: true
version: 1.0
locked_before_product_implementation: true

This specification is canonical behavior, not a record of passing tests. Tests may become stricter; criteria may not be silently weakened/deleted. `spec/acceptance.json` carries the same machine-readable rows. The lock hashes cover both files and the PRD/API/architecture contract. Corrections require a TEST_SPEC_EXCEPTION_<ID>.md with evidence, impact and independent review. Performance targets remain targets; report failure to meet them honestly without rewriting the target.

A meaningful test must execute the product path for product claims. The independent Python reference is an oracle/prototype, not a substitute for Rust acceptance. No skipped/xfail criterion can establish completion.
## AC-001 / FR-001
**Precondition:** Valid catalog/context; input schema v1  
**Input:** Unknown key, unknown version and injected policy_scan operator  
**Behavior:** Reject before any scan  
**Expected:** E_INPUT or E_UNSUPPORTED; no rows  
**Tolerance:** exact  
**Test Level:** contract  
**Evidence:** CLI JSON and scan counter  

## AC-002 / FR-002
**Precondition:** Valid catalog/context  
**Input:** SELECT id, amount FROM sales WHERE amount > 10 ORDER BY id LIMIT 10  
**Behavior:** Parse and lower to same semantics as equivalent JSON tree  
**Expected:** Same typed ordered rows as independent SQLite view query  
**Tolerance:** exact  
**Test Level:** acceptance  
**Evidence:** paired inputs/results  

## AC-003 / FR-003
**Precondition:** Typed catalog with join aliases  
**Input:** Unknown column, ambiguous id, compare text to integer  
**Behavior:** Bind/type-check before execution  
**Expected:** E_BIND or E_TYPE; zero executed scans  
**Tolerance:** exact  
**Test Level:** contract  
**Evidence:** error envelopes  

## AC-004 / FR-004
**Precondition:** Two synthetic scoped tables with duplicate join keys  
**Input:** Inner equijoin then grouping COUNT and SUM  
**Behavior:** Own engine computes bag multiplicity correctly  
**Expected:** Equal to SQLite on physically prefiltered authorized tables  
**Tolerance:** exact integers/bags  
**Test Level:** integration  
**Evidence:** oracle comparisons  

## AC-005 / FR-005
**Precondition:** NULL and empty fixtures  
**Input:** 3VL truth table, null equijoin, all-null/empty SUM/COUNT  
**Behavior:** Apply documented nullable semantics  
**Expected:** Locked expected fixtures including no NULL join matches  
**Tolerance:** exact  
**Test Level:** unit+acceptance  
**Evidence:** case results  

## AC-006 / FR-006
**Precondition:** Generated supported plans across selectivities  
**Input:** Run optimizer enabled and disabled  
**Behavior:** Rewrites preserve result and schema  
**Expected:** Zero mismatches across >=1000 generated cases  
**Tolerance:** exact bags  
**Test Level:** property+differential  
**Evidence:** seeds and all verdicts  

## AC-007 / FR-007
**Precondition:** Context restricts one hidden column and one tenant  
**Input:** Explain allowed query  
**Behavior:** Expose safe rule/operator names without hidden values/statistics  
**Expected:** No hidden canary string or unfiltered row count  
**Tolerance:** exact  
**Test Level:** security  
**Evidence:** explain output and canary check  

## AC-008 / FR-008
**Precondition:** Fresh checkout with supported runtime  
**Input:** make demo then open generated report  
**Behavior:** Drive actual Rust CLI, not reference implementation masquerading as product  
**Expected:** Allowed query, denied query, second tenant and matching oracle visible  
**Tolerance:** exact; browser visual review manual record  
**Test Level:** e2e  
**Evidence:** commands and report hash  

## AC-009 / FR-009
**Precondition:** Trusted operator catalog load  
**Input:** Bad type, mismatched column lengths, invalid value/duplicate schema column  
**Behavior:** Reject catalog before query  
**Expected:** E_CATALOG; no panic  
**Tolerance:** exact  
**Test Level:** contract  
**Evidence:** invalid fixtures  

## AC-010 / SEC-001
**Precondition:** Catalog has tenant A and B with distinct canaries  
**Input:** Nested filter/project/join/aggregate for tenant A  
**Behavior:** All base scans enforce A scope  
**Expected:** No contribution from B; compare independently materialized A relations  
**Tolerance:** exact  
**Test Level:** security+acceptance  
**Evidence:** tenant-paired fixtures  

## AC-011 / SEC-002
**Precondition:** salary forbidden; id/amount allowed  
**Input:** salary in each of project/filter/join/group/aggregate/sort  
**Behavior:** Reject every reference before execution  
**Expected:** E_FORBIDDEN without value; zero scan execution  
**Tolerance:** all six contexts  
**Test Level:** security  
**Evidence:** denial matrix  

## AC-012 / SEC-003
**Precondition:** Physical verifier test API within test module  
**Input:** Missing policy scan, wrong context/revision or forged column provenance  
**Behavior:** Verifier fails; execute requires VerifiedPlan  
**Expected:** E_PLAN; unsafe plan never executes  
**Tolerance:** exact  
**Test Level:** unit+negative-control  
**Evidence:** known-bad plans  

## AC-013 / SEC-004
**Precondition:** Valid operator context  
**Input:** COPY/ATTACH/CREATE/UPDATE; read_csv/http/extension/UDF and multiple statements  
**Behavior:** Reject unsupported construct at front end  
**Expected:** E_UNSUPPORTED; no query-triggered network or file effects  
**Tolerance:** exact; sandbox syscall tracing optional separate  
**Test Level:** security  
**Evidence:** inputs and error outputs  

## AC-014 / SEC-005
**Precondition:** Canaries in hidden columns, hidden tenant and fake secret config  
**Input:** Trigger type/bind/budget errors and explain  
**Behavior:** Emit typed safe errors  
**Expected:** No canary appears in stdout/stderr/report  
**Tolerance:** exact  
**Test Level:** security  
**Evidence:** canary scan  

## AC-015 / SEC-006
**Precondition:** Default limits  
**Input:** Oversized/deep input and exploding join under tiny work budget  
**Behavior:** Refuse input or stop at charged budget  
**Expected:** E_LIMIT/E_BUDGET, bounded counters, no successful partial result  
**Tolerance:** work <= configured limit; check each 1024 inner steps  
**Test Level:** system  
**Evidence:** process outputs/counters  

## AC-016 / SEC-007
**Precondition:** Public export staging generated from exact allowlist  
**Input:** Add symlink, .env, private resume marker and unlisted file  
**Behavior:** Exporter rejects forbidden/symlink files and never includes private paths  
**Expected:** Nonzero failure for forbidden listed material; public zip contains only allowlisted regular files  
**Tolerance:** exact  
**Test Level:** security  
**Evidence:** export manifests/negative controls  

## AC-017 / REL-001
**Precondition:** Two contexts/revisions and immutable snapshots  
**Input:** Compile under A/r1 then attempt execute with B/r2 or different snapshot  
**Behavior:** Reject mismatch; one snapshot for whole query  
**Expected:** E_PLAN/E_CONTEXT; no mixed result  
**Tolerance:** exact  
**Test Level:** integration  
**Evidence:** snapshot/context tests  

## AC-018 / REL-002
**Precondition:** Low result row/byte cap; cancellation hook  
**Input:** Produce too many rows; cancel before final publication  
**Behavior:** One failure object, no partial success record  
**Expected:** E_OUTPUT_LIMIT or E_CANCELLED  
**Tolerance:** exact  
**Test Level:** system  
**Evidence:** stdout framing checks  

## AC-019 / REL-003
**Precondition:** Stable input/context/snapshot  
**Input:** Run selected fixtures ten times  
**Behavior:** Compare schema and bag/ordered result as specified  
**Expected:** Ten identical semantic digests  
**Tolerance:** exact  
**Test Level:** reproducibility  
**Evidence:** digests and inputs  

## AC-020 / REL-004
**Precondition:** Read-only original catalog hashed  
**Input:** Kill real CLI process during join; rerun independent query  
**Behavior:** Catalog remains unchanged and next query succeeds  
**Expected:** Catalog hash unchanged; oracle match  
**Tolerance:** exact  
**Test Level:** fault-injection  
**Evidence:** process termination receipts  

## AC-021 / PERF-001
**Precondition:** Recorded actual hardware/toolchain; release build  
**Input:** 30 paired repetitions per chosen workload after 5 warmups  
**Behavior:** Capture raw wall/CPU/RSS/work/result digest and report distributions  
**Expected:** No omitted failures, clear timing boundaries, correct digest every run  
**Tolerance:** no fixed speed threshold  
**Test Level:** performance  
**Evidence:** raw samples and method  

## AC-022 / PERF-002
**Precondition:** Documented dedicated reference host only  
**Input:** 100k-row warm filter/project workload  
**Behavior:** Measure execution-only p95 and end-to-end separately  
**Expected:** Report target met or missed; never relabel p50 as p95  
**Tolerance:** TARGET p95 <1s, not an observed fact  
**Test Level:** performance  
**Evidence:** raw 30-repetition distribution  

## AC-023 / PERF-003
**Precondition:** Actual Linux reference host  
**Input:** Cancel long-running supported query at controlled checkpoint  
**Behavior:** Observe and cleanly return cancellation  
**Expected:** Report latency and target result  
**Tolerance:** TARGET <=100ms; correctness still mandatory  
**Test Level:** performance+system  
**Evidence:** cancellation timestamps  

## AC-024 / NFR-001
**Precondition:** Fresh isolated committed checkout  
**Input:** make bootstrap && make verify && make demo  
**Behavior:** Resolve locked dependencies, format/lint/build/tests/demo  
**Expected:** All commands execute successfully; no dirty-cache reliance  
**Tolerance:** exact  
**Test Level:** clean-environment  
**Evidence:** checkout/source hashes and command receipts  

## AC-025 / NFR-002
**Precondition:** First-party Rust source  
**Input:** Clippy/static checks plus invalid-input corpus  
**Behavior:** Forbid unsafe and no panic on malformed bounded inputs  
**Expected:** Static gate succeeds; invalid corpus typed errors  
**Tolerance:** exact  
**Test Level:** static+fuzz  
**Evidence:** compiler/logs and corpus  

## AC-026 / NFR-003
**Precondition:** Evidence runner invoked with synthetic inputs  
**Input:** Success, nonzero exit, timeout and missing executable  
**Behavior:** Record actual command status and complete provenance  
**Expected:** PASS only exit0; FAIL/nonzero; BLOCKED missing executable; output hashes verify  
**Tolerance:** exact  
**Test Level:** unit  
**Evidence:** runner self-tests  

## AC-027 / NFR-004
**Precondition:** Claims table and evidence manifests  
**Input:** Audit every non-target public claim  
**Behavior:** Require claim-specific real evidence and source identity  
**Expected:** No unmeasured public metric; all claims linked or NOT RUN  
**Tolerance:** exact  
**Test Level:** audit  
**Evidence:** claims audit  

## AC-028 / NFR-005
**Precondition:** No model keys/cloud credentials  
**Input:** Run build-independent reference demo; later real core demo  
**Behavior:** Core path requests no external service  
**Expected:** No required API keys or billing  
**Tolerance:** exact  
**Test Level:** e2e  
**Evidence:** environment allowlist  

## AC-029 / NFR-006
**Precondition:** Generated report  
**Input:** Read headings/table labels and keyboard navigation offline  
**Behavior:** No script/dependency; escaped supplied labels  
**Expected:** Readable semantic HTML; malicious label displayed as text  
**Tolerance:** exact; human-readable visual check recorded separately  
**Test Level:** accessibility+security  
**Evidence:** HTML test and inspection  

## AC-030 / NFR-007
**Precondition:** Resolved dependencies and public fixtures  
**Input:** License/notice scan and release wording review  
**Behavior:** Identify actual licenses and reject unsupported maturity claims  
**Expected:** MIT own source; notices present; no invented production claims  
**Tolerance:** exact  
**Test Level:** audit  
**Evidence:** license report
