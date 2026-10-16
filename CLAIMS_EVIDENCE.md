# Claims and evidence
Public claims must never exceed the linked implementation/environment evidence. A documented target is not an observed result.
| Claim | Requirement | Required evidence | Evidence path | Status |
|---|---|---|---|---|
| C-001: Reject before any scan | FR-001 / AC-001 | CLI JSON and scan counter | [review-final-source-core](verification/product/runs/review-final-source-core.json) | PASS |
| C-002: Parse and lower to same semantics as equivalent JSON tree | FR-002 / AC-002 | paired inputs/results | [review-final-source-core](verification/product/runs/review-final-source-core.json) | PASS |
| C-003: Bind/type-check before execution | FR-003 / AC-003 | error envelopes | [review-final-source-core](verification/product/runs/review-final-source-core.json), [ambiguous-zero-scan](verification/product/runs/ambiguous-zero-scan.json) | PASS |
| C-004: Own engine computes bag multiplicity correctly | FR-004 / AC-004 | oracle comparisons | [review-final-source-core](verification/product/runs/review-final-source-core.json) | PASS |
| C-005: Apply documented nullable semantics | FR-005 / AC-005 | case results | [review-final-source-core](verification/product/runs/review-final-source-core.json) | PASS |
| C-006: Rewrites preserve result and schema | FR-006 / AC-006 | seeds and all verdicts | [review-followup-differential](verification/product/runs/review-followup-differential.json) | PASS |
| C-007: Expose safe rule/operator names without hidden values/statistics | FR-007 / AC-007 | explain output and canary check | [review-final-source-core](verification/product/runs/review-final-source-core.json) | PASS |
| C-008: Drive actual Rust CLI, not reference implementation masquerading as product | FR-008 / AC-008 | commands and report hash | [rust-demo](verification/product/runs/rust-demo.json) | NOT RUN |
| C-009: Reject catalog before query | FR-009 / AC-009 | invalid fixtures | [review-final-source-core](verification/product/runs/review-final-source-core.json) | PASS |
| C-010: All base scans enforce A scope | SEC-001 / AC-010 | tenant-paired fixtures | [review-final-source-core](verification/product/runs/review-final-source-core.json) | PASS |
| C-011: Reject every reference before execution | SEC-002 / AC-011 | denial matrix | [review-final-source-core](verification/product/runs/review-final-source-core.json) | PASS |
| C-012: Verifier fails; execute requires VerifiedPlan | SEC-003 / AC-012 | known-bad plans | [review-final-source-core](verification/product/runs/review-final-source-core.json), [eight-rust-controls](verification/product/runs/eight-rust-controls.json) | PASS |
| C-013: Reject unsupported construct at front end | SEC-004 / AC-013 | inputs and error outputs | [review-final-source-core](verification/product/runs/review-final-source-core.json) | PASS |
| C-014: Emit typed safe errors | SEC-005 / AC-014 | canary scan | [review-final-source-core](verification/product/runs/review-final-source-core.json) | PASS |
| C-015: Refuse input or stop at charged budget | SEC-006 / AC-015 | process outputs/counters | [review-final-source-core](verification/product/runs/review-final-source-core.json), [eight-rust-controls](verification/product/runs/eight-rust-controls.json), [source-bound-pilot-v2](verification/product/runs/source-bound-pilot-v2.json) | PASS |
| C-016: Exporter rejects forbidden/symlink files and never includes private paths | SEC-007 / AC-016 | export manifests/negative controls | Windows actual symlink setup failed with privilege error 1314; other exporter controls do not substitute for it | BLOCKED |
| C-017: Reject mismatch; one snapshot for whole query | REL-001 / AC-017 | snapshot/context tests | [review-final-source-core](verification/product/runs/review-final-source-core.json) | PASS |
| C-018: One failure object, no partial success record | REL-002 / AC-018 | stdout framing checks | [review-final-source-core](verification/product/runs/review-final-source-core.json) | PASS |
| C-019: Compare schema and bag/ordered result as specified | REL-003 / AC-019 | digests and inputs | [review-final-source-core](verification/product/runs/review-final-source-core.json) | PASS |
| C-020: Catalog remains unchanged and next query succeeds | REL-004 / AC-020 | process termination receipts | [review-final-source-core](verification/product/runs/review-final-source-core.json) | PASS |
| C-021: Capture raw wall/CPU/RSS/work/result digest and report distributions | PERF-001 / AC-021 | raw samples and method | [source-bound-pilot-v2](verification/product/runs/source-bound-pilot-v2.json) | NOT YET MEASURED |
| C-022: Measure execution-only p95 and end-to-end separately | PERF-002 / AC-022 | raw 30-repetition distribution | Actual dedicated 4-core/8-GiB Linux reference host unavailable; no target result claimed | BLOCKED |
| C-023: Observe and cleanly return cancellation | PERF-003 / AC-023 | cancellation timestamps | Actual Linux reference host required; prepared signal campaign and Windows hard-kill evidence are not substitutes | BLOCKED |
| C-024: Resolve locked dependencies, format/lint/build/tests/demo | NFR-001 / AC-024 | checkout/source hashes and command receipts | [fresh-rust-candidate-failed](verification/product/runs/fresh-rust-candidate-failed.json) | FAIL |
| C-025: Forbid unsafe and no panic on malformed bounded inputs | NFR-002 / AC-025 | compiler/logs and corpus | [review-final-source-core](verification/product/runs/review-final-source-core.json), [review-followup-malformed](verification/product/runs/review-followup-malformed.json) | PASS |
| C-026: Record actual command status and complete provenance | NFR-003 / AC-026 | runner self-tests | [review-final-source-core](verification/product/runs/review-final-source-core.json) | PASS |
| C-027: Require claim-specific real evidence and source identity | NFR-004 / AC-027 | claims audit | Public status/link/digest audit and final independent wording review pending | NOT RUN |
| C-028: Core path requests no external service | NFR-005 / AC-028 | environment allowlist | [review-final-source-core](verification/product/runs/review-final-source-core.json), [rust-demo](verification/product/runs/rust-demo.json) | PASS |
| C-029: No script/dependency; escaped supplied labels | NFR-006 / AC-029 | HTML test and inspection | [review-final-source-core](verification/product/runs/review-final-source-core.json), [rust-demo](verification/product/runs/rust-demo.json), [html-escape-control](verification/product/runs/html-escape-control.json) | PASS |
| C-030: Identify actual licenses and reject unsupported maturity claims | NFR-007 / AC-030 | license report | [review-followup-license](verification/product/runs/review-followup-license.json) | NOT RUN |
