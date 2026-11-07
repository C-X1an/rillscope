# Offline Rust report

Run `make bootstrap build demo` from the repository root and open the generated `.local-runs/.../report.html` path. The demo calls the actual Rust CLI through the fixed-scope adapter and compares authorized relations independently in SQLite.

The synthetic cases are alpha `[[3,40]]`, a forbidden-column `E_FORBIDDEN` response, and beta `[[1,999]]`. Expand the redacted plan to inspect PolicyScan and operator structure. The report is escaped, script-free and offline.

[Recorded report](rust-report.html), [original historical desktop screenshot](rust-desktop.jpg) and [focused historical crop](rust-execution-focus.jpg) provide the underlying execution record. The [README's three-outcome visual summary](../assets/execution-proof.svg) is an editorial transcription of the recorded Rust/SQLite results, not a product-interface screenshot or a replacement for the authentic evidence. The crop is taken directly from the original screenshot without changing its result text or state; it highlights the authorized aggregate and the denied column. The separate beta result remains in the complete report.

These historical assets do not qualify a new visual/keyboard inspection. Current AC-008 remains unverified under the [delivery exception](../../TEST_SPEC_EXCEPTION_AC-008.md).
