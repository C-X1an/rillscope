# Limits and non-goals
The full Rust query engine is not implemented or validated. This seed is not production ready, an audited security product, a general SQL database, a prompt-injection solution or an operating-system sandbox.

The intended boundary is query-result access under a trusted host, immutable catalog/context and a restricted expression language. The host/OS user already has raw data access. No timing/covert-channel protection, inference privacy or differential privacy is promised. Aggregates over authorized rows can still disclose facts about that authorized population. Work counters may indirectly disclose execution cost; no noninterference theorem is claimed.

No query UDFs, extension loading, file/network functions, DDL/DML, recursive SQL, arbitrary subqueries, distributed query execution, transactions, plan cache, external user authentication, parallel query scheduling or spill-to-disk exist. The agent adapter must never expose operator context/catalog paths as untrusted tool parameters.

The Python reference is JSON-only, row-based and materializing. It intentionally uses nested-loop joins as a simple semantic model. It has structural/work/intermediate-row/output bounds, not memory/RSS accounting, cancellation, a physical plan verifier or an optimizer. It may fail a larger legitimate query sooner than a future streaming implementation. It is not a deployable access-control service.

The Rust source seed includes nullable owned columns and scoped scan checks, but no full parser/binder/plan/executor, independent general verifier or memory reservations. Its scan checker cannot stand in for the acceptance contract's physical-plan validation.

A local hash record detects changed output bytes relative to the saved hash. A privileged writer can replace both; source identity, independent review, trusted CI and release history provide additional provenance, not absolute anti-fraud. A finite test corpus and caught mutants are evidence of selected behavior, not proof of all inputs.
