# AC-008 delivery exception

Decision date: 2026-11-01 (Asia/Singapore).

The maintainer authorized completing and publishing the available engineering work while skipping the unavailable browser inspection. This exception applies only to the current demo's visual and keyboard review.

AC-008 remains **NOT RUN / unverified** for that inspection. No screenshot, keyboard observation, inspector identity or browser PASS is supplied by this decision. The acceptance specification, locked hashes, demo verifier and strict release audit retain their original requirements. `make release-verify` must continue to reject missing AC-008 evidence.

The Rust demo's execution, source/build/receipt identities, generated report, allowed and denied queries, second tenant and independent SQLite outcomes are separately recorded automated evidence. They do not establish a visual review. The historical browser review remains dated and does not qualify the current report.

This decision permits the remaining documentation, fresh-checkout validation, findings-first review, fixes/retests and audited public publication to proceed in their existing order. Those activities still need their own actual evidence. It does not waive a failing product test, change a benchmark case, seed, repetition or deadline, authorize a browser-security workaround, or establish full strict acceptance or production readiness.

The public delivery remains experimental. See [implementation status](IMPLEMENTATION_STATUS.md), [verification report](VERIFICATION_REPORT.md), [claims and evidence](CLAIMS_EVIDENCE.md), [reference measurements](BENCHMARKS.md) and [limitations](LIMITATIONS.md).

To remove this exception later, perform a genuine inspection of a source-matching fresh Rust demo, retain its actual screenshots and keyboard observations, and run the unchanged `scripts/verify_demo_evidence.py` with the real fresh checkout, demo, receipt and browser record. Then regenerate and audit the current AC-008 evidence. Until that evidence exists, keep the original criterion unverified.
