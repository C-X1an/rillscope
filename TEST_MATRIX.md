# Test matrix
Tests listed here are required design paths. Current execution status is in VERIFICATION_REPORT.md; future paths are not implied to exist or have run.
| Requirement | Acceptance | Required test and evidence | Negative control |
|---|---|---|---|
| FR-001 | AC-001 | contract: Unknown key, unknown version and injected policy_scan operator; CLI JSON and scan counter | inject unknown op/field; decoder must reject |
| FR-002 | AC-002 | acceptance: SELECT id, amount FROM sales WHERE amount > 10 ORDER BY id LIMIT 10; paired inputs/results | introduce unsupported SQL function; lowering must reject |
| FR-003 | AC-003 | contract: Unknown column, ambiguous id, compare text to integer; error envelopes | allow unknown column; test must fail |
| FR-004 | AC-004 | integration: Inner equijoin then grouping COUNT and SUM; oracle comparisons | drop duplicate join matches |
| FR-005 | AC-005 | unit+acceptance: 3VL truth table, null equijoin, all-null/empty SUM/COUNT; case results | treat NULL equality as true |
| FR-006 | AC-006 | property+differential: Run optimizer enabled and disabled; seeds and all verdicts | push filter below policy or lose needed key |
| FR-007 | AC-007 | security: Explain allowed query; explain output and canary check | include forbidden value in explain |
| FR-008 | AC-008 | e2e: make demo then open generated report; commands and report hash | unescape HTML metacharacters |
| FR-009 | AC-009 | contract: Bad type, mismatched column lengths, invalid value/duplicate schema column; invalid fixtures | accept catalog type mismatch |
| SEC-001 | AC-010 | security+acceptance: Nested filter/project/join/aggregate for tenant A; tenant-paired fixtures | replace tenant match with true |
| SEC-002 | AC-011 | security: salary in each of project/filter/join/group/aggregate/sort; denial matrix | bypass forbidden column check |
| SEC-003 | AC-012 | unit+negative-control: Missing policy scan, wrong context/revision or forged column provenance; known-bad plans | accept forged raw scan |
| SEC-004 | AC-013 | security: COPY/ATTACH/CREATE/UPDATE; read_csv/http/extension/UDF and multiple statements; inputs and error outputs | accept read_file syntax |
| SEC-005 | AC-014 | security: Trigger type/bind/budget errors and explain; canary scan | print raw hidden cell |
| SEC-006 | AC-015 | system: Oversized/deep input and exploding join under tiny work budget; process outputs/counters | disable work/depth limit |
| SEC-007 | AC-016 | security: Add symlink, .env, private resume marker and unlisted file; export manifests/negative controls | insert private canary into export |
| REL-001 | AC-017 | integration: Compile under A/r1 then attempt execute with B/r2 or different snapshot; snapshot/context tests | mix policy revisions |
| REL-002 | AC-018 | system: Produce too many rows; cancel before final publication; stdout framing checks | return partial success after budget fail |
| REL-003 | AC-019 | reproducibility: Run selected fixtures ten times; digests and inputs | deduplicate bag rows |
| REL-004 | AC-020 | fault-injection: Kill real CLI process during join; rerun independent query; process termination receipts | modify input catalog in executor |
| PERF-001 | AC-021 | performance: 30 paired repetitions per chosen workload after 5 warmups; raw samples and method | delete slow samples; audit must reject |
| PERF-002 | AC-022 | performance: 100k-row warm filter/project workload; raw 30-repetition distribution | include fixture generation in only one baseline timer |
| PERF-003 | AC-023 | performance+system: Cancel long-running supported query at controlled checkpoint; cancellation timestamps | remove cooperative checks |
| NFR-001 | AC-024 | clean-environment: make bootstrap && make verify && make demo; checkout/source hashes and command receipts | remove required dependency lock |
| NFR-002 | AC-025 | static+fuzz: Clippy/static checks plus invalid-input corpus; compiler/logs and corpus | panic on malformed input |
| NFR-003 | AC-026 | unit: Success, nonzero exit, timeout and missing executable; runner self-tests | alter a captured stdout byte |
| NFR-004 | AC-027 | audit: Audit every non-target public claim; claims audit | claim unrun acceptance PASS |
| NFR-005 | AC-028 | e2e: Run build-independent reference demo; later real core demo; environment allowlist | require missing live API key |
| NFR-006 | AC-029 | accessibility+security: Read headings/table labels and keyboard navigation offline; HTML test and inspection | remove meaningful headings / unsafe HTML |
| NFR-007 | AC-030 | audit: License/notice scan and release wording review; license report | remove dependency notice |
