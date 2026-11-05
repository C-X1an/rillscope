# Trusted synthetic instrumentation

Ordinary query inputs cannot install an observer, change limits, select a context, or name files. The library's `Budget::set_observer` is a trusted host hook receiving only static stage names; an observer error aborts the query.

For operator-loaded catalogs whose snapshot label starts with `synthetic-`, two explicit host environment settings support real process tests:

- `RILLSCOPE_TEST_PHASE_FILE` selects an operator-owned marker file. The first actual matching hash-join inner step writes `join_inner` once. The test waits for that marker and a live PID before terminating its own CLI process.
- `RILLSCOPE_TEST_CANCEL_BEFORE_PUBLISH=1` requests cancellation at the final collection checkpoint. The CLI emits one `E_CANCELLED` object and no successful rows.
- `RILLSCOPE_TEST_SCAN_COUNTER_FILE` writes an operator-selected synthetic receipt: zero after validated catalog loading, incremented only at the actual execution scan-opening checkpoint. Contract tests verify a positive scan control and zero scans for frontend/binding denials. It contains no table rows or values and is never ordinary result metadata.

The host controls the catalog and environment. These settings are never tool-client arguments, query fields, or language functions. A fixed-scope adapter must not forward them. They are test instrumentation, not an authorization mechanism or a service. SIGINT/SIGTERM handlers on Unix separately request cooperative cancellation; Linux runtime/latency results must be measured on an actual Linux host.
