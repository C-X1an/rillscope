# Local operation and reproduction

RillScope is a local CLI/library and offline report, with no hosted tenant-query service. The host supplies immutable catalog/context files; a client supplies only a restricted query. Do not expose catalog/context paths or test hooks as untrusted tool arguments.

## Build and run

Install Git, Make, Python 3.11+ and rustup, then run:

```sh
make bootstrap build
target/debug/rillscope run --catalog examples/catalog.json --context examples/context.json --query examples/query.json
make demo
```

Open the printed `.local-runs/.../report.html` locally. It is script-free and offline. `explain` returns redacted plan/schema/rule information, and `--query -` accepts stdin. See the [API](API_SPEC.md) for formats and typed failures.

## Check

```sh
make fmt lint check test verify-reference
make integration acceptance property fuzz security
make publication-check
make security-online
```

Online dependency checks use the actual advisory database at execution time. A Windows symlink-creation setup case requires legitimate local permission; Linux CI can execute that unchanged case. A missing permission is not a passing result. Keep generated captures, build targets and raw logs outside Git.

## Full reference recipe

`make verify` executes the ordered required gates. `make clean-verify` uses one fresh committed clone/target and runs bootstrap, verify and demo. The full benchmark requires actual source-bound dedicated-reference allocation and before/after conditions, described in [reference allocation](docs/reference-allocation.md). Ordinary shared-runner CI and `make benchmark-pilot` do not establish that allocation.

Keep every declared case, seed, warmup, repetition, timeout, expected error and original receipt. Run the unchanged artifact checkers against the captured records. `make release-verify` additionally rejects incomplete or stale published acceptance evidence, including missing visual inspection. Never substitute the Python reference for native Rust execution.

## Failure and authority

Errors return typed envelopes without successful partial rows. Broken stdout or hard termination can prevent complete transport; callers must reject truncated JSON and nonzero exits. Cooperative cancellation uses the [documented terminal-decision boundary](TEST_SPEC_EXCEPTION_AC-018.md). Resource reservations are logical accounting rather than OS isolation.

Catalog/context input is trusted host configuration. Use a separate OS/process boundary when the surrounding service needs one; this project does not supply authentication, timing privacy or a network sandbox. [Security](SECURITY.md) and [limits](LIMITATIONS.md) define the supported boundary.
