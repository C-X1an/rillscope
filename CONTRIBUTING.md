# Contributing
Start with [implementation status](IMPLEMENTATION_STATUS.md), then the locked [acceptance contract](ACCEPTANCE_SPEC.md). Architectural targets are not completed features.

Use a separate branch/worktree per change. Preserve one active writer per module; coordinate changes to Cargo manifests, root exports and CI. Add a failing test before changing semantics. Unit tests alone do not establish tenant safety, optimizer soundness or clean reproducibility.

```sh
make verify-reference
make mutation-reference
make bootstrap build fmt lint check test
```

`make format` applies rustfmt; `make fmt` checks it. The dependency-free Python checker is syntax/whitespace checking, not a substitute for full static typing. Rust check/Clippy require the pinned toolchain. Do not change the toolchain silently to manufacture a passing run. Add external crates only with a real resolved lockfile and license/security review.

Invalid input returns explicit errors. No first-party unsafe Rust. No silent skip, xfail, weakened assertion, fake integration, edited benchmark or invented usage claim. An objectively incorrect locked criterion requires a preserved exception record and independent review; never regenerate its hash merely to hide failure.

Run a negative control against critical fixes and preserve the original/failing/restored outcomes. Keep synthetic data, complete benchmark samples and source identities. Clean checkout reproduction is required before a release. Distinguish same-session self-review from independent review.

Never commit credentials, personal/employment material, raw private logs or generated reports containing sensitive data. Use [SECURITY.md](SECURITY.md) for vulnerability reporting. Original contributions are MIT-licensed; third-party components retain their own licenses.
