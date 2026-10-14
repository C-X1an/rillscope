# Contributor instructions
Read ACCEPTANCE_SPEC.md, PRD.md, ARCHITECTURE.md, API_SPEC.md and THREAT_MODEL.md before changing behavior. The acceptance contract is hash-pinned; do not weaken tests to fit implementation. Preserve public source/tests and record actual execution only.

Use `make verify-reference` for the executable Python reference; use `make bootstrap build fmt lint check test` for the Rust kernel. Full `make verify` is intentionally stricter and fails while required engine features/evidence remain unfinished. Reference output is not Rust proof. Do not claim production readiness or expose query clients to operator context/file controls.

No first-party unsafe Rust; closed decoding and typed errors; policy enforcement precedes user expression evaluation. Keep modules small, pin resolved dependencies and preserve licenses. Never commit secrets, personal data, raw private logs or unreviewed generated artifacts. See CONTRIBUTING.md and VERIFICATION_REPORT.md.
