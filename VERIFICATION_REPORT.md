# Verification report

## Complete canonical native evidence, 2026-10-29

[Native run 18](https://github.com/C-X1an/rillscope/actions/runs/40887422611), commit `789814ff`, completed collection and strict original-record validation. A separate unmodified local replay passed all 12 stages and reproduced its original report exactly: 43,050 grid observations, 4,200 deciding-NULL observations, 175 cancellation observations, 19,800 independent semantic comparisons, native executable custody and the fresh checkout's 18 gates/22 receipts. The [curated record](verification/product/runs/mc65-native18-complete-reference-and-fresh.json) binds the original 357-file execution/source identity; the retained original report additionally authenticates the complete 646-file public seed. Later documentation/evidence updates retain exact execution and verification dependency bytes.

The dedicated reference allocation was one four-vCPU, 8-GiB Linux KVM guest for this campaign. Physical host sharing and hypervisor scheduling remain possible, and sampled conditions do not establish uninterrupted residency. [Benchmark results](BENCHMARKS.md) report every seed's distributions and cancellation upper bounds. Required main-chat review follows the user's routing instruction and shares implementation history; it does not invent a separate reviewer. One complete method execution is observed, without a future-capacity or production guarantee. AC-008 still lacks actual manual visual/keyboard observations, libFuzzer remains not run, and the final DAG/release remain incomplete. All historical failures below retain their original outcomes.

## Earlier Rust development records

The original compiler/executor and fixed-scope inspector are implemented. [Curated product run summaries](verification/product/artifact-catalog.json) preserve actual exit/status, raw output digests, source-file hashes, environment and selected test/campaign observations without publishing private commands or internal logs. The [criterion index](verification/product/index.json) and [claims table](CLAIMS_EVIDENCE.md) distinguish recorded scoped successes from incomplete locked requirements. `python3 scripts/release_audit.py` checks status/link/hash consistency; `--require-all` additionally refuses unproved or historical release coverage. It does not execute product queries or provide independent authentication.

Recorded Windows checks include36 Rust unit tests,31 actual CLI/adapter/report tests,1000 JSON/SQL optimizer/SQLite cases and2000 finite malformed inputs against source-bound compiled bytes. Reference/evidence suite counts are preserved in their dated summaries. Ten selected Rust mutation controls passed at3ecfb02e, and the HTML escape control passed at427aaf9 with source-bound builds at each stage. Schema-3 pilots retained630 observations; shared-Linux nullable-sort supplements retained4200 observations and2400 independent comparisons each. The full frozen3ecfb02e Windows capture completed410 cases/43050 observations and failed qualification with3 process timeouts; its17400 measured semantic comparisons and every failed attempt remain retained. Current strong validation of all43050 records confirmed the same failures and current Rust-source match. The separate complete shared-Linux attempt was cancelled while packaging; no capture artifact was uploaded, the log endpoint returned404, and its observation count is unknown. Runtime/retention repair remains required. Validation checks complete summary identity, required schema/build proof, deterministic inputs and prescribed successful comparisons. No qualifying full-grid PASS or dedicated reference target is claimed.

Independent source inspections produced findings before integrator fixes/retests. Earlier bundled reviewers executed no commands; native follow-ups used read-only source/artifact inspection and no tests/builds. The427aaf9 fresh Windows checkout passed bootstrap, demo, reference, property, finite malformed inputs, mutation controls and online dependency policy. Its aggregate verify/security result was FAIL because Windows symlink setup returned privilege error1314; the required reference benchmark was unavailable. [e7f9426 Linux CI](https://github.com/C-X1an/rillscope/actions/runs/38944156500) passed all four jobs. At[72f31071](https://github.com/C-X1an/rillscope/actions/runs/38958921426) the reference, dependency and product jobs passed, including actual new-session descendant cleanup and real exporter symbolic-link controls; the overall workflow failed on the GDB source-path launch before Rust execution. A stronger report verifier binds the genuine fresh demo to captured report/results/manifest hashes; targeted stale-receipt and artifact corruption controls reject the reproduced substitutions. At[d8e1312c](https://github.com/C-X1an/rillscope/actions/runs/39020186943/job/117360281667), five actual final-decision observations and the behavioral mutation passed; independent instruction/source assessment and current ordinary output/cancellation tests preceded the[explicit clarification disposition](TEST_SPEC_EXCEPTION_AC-018.md). Corrected-source complete fresh reproduction, full collection qualification and dedicated reference targets remain incomplete. No full phase, completed release, production use or performance advantage is claimed.

## Historical reference handoff

Historical reference handoff recorded 2026-10-14. The entries below describe the original reference-only authoring environment. Current Rust progress is recorded in IMPLEMENTATION_STATUS.md; independent release readiness and remote CI remain pending. No production use is claimed.

## Source identity

The runs below share source fingerprint `9233be9f70f58433f3b944b7ce72a0f959ac273ad1e3cfcb1eb1a64cc522b369`. The receipt contains the exact per-file hashes and the command's pre/post identity. The authoring runs preceded Git initialization, so their Git commit is null rather than invented. A subsequent clean committed-checkout reference run is documented below when available.

The fingerprint covers implementation/test/tooling files and locked contracts; it deliberately excludes generated verification artifacts, build/cache directories and most presentation prose. Inspect the file list rather than assuming it hashes the entire repository. Output hashes detect alteration relative to the receipt; they do not authenticate against a privileged person replacing both receipt and output. Independent reruns remain necessary.

## Executed checks

| Run | Status | Exit | Meaning |
|:--|:--|--:|:--|
| [release-reference](verification/public/release-reference/receipt.json) | PASS | 0 | 32 reference/tooling tests; one contains 1,000 seeded SQLite comparisons |
| [release-mutations](verification/public/release-mutations/receipt.json) | PASS | 0 | Three reference mutations: baseline PASS, defect FAIL, restored PASS |
| [release-benchmark](verification/public/release-benchmark/receipt.json) | PASS | 0 | 30 measured reference samples after three warm-ups |
| [release-browser](verification/public/release-browser/receipt.json) | PASS | 0 | Two Chromium viewports; seven selected checks each |
| [release-demo](verification/public/release-demo/receipt.json) | PASS | 0 | Three actual reference outcomes: allowed, forbidden, budget exhausted |
| [release-rust](verification/public/release-rust/receipt.json) | BLOCKED | 77 | cargo unavailable; no Rust test executed |
| [release-acceptance](verification/public/release-acceptance/receipt.json) | FAIL | 78 | Explicit incomplete gate; no full acceptance test passed |

The exit-78 gate is an intentional refusal to claim completion, but it remains **FAIL / INCOMPLETE**, not PASS. The missing cargo executable is **BLOCKED**, not a successful Rust test. The 32 passing tests do not imply all 30 canonical Rust acceptance criteria are implemented.

## Test-the-tests

[Mutation raw output](verification/public/release-mutations/stdout.txt) preserves the original file hash, temporary targeted mutation, individual test exit codes and failure messages. Defects bypassed tenant filtering, treated NULL equality as true and deduplicated a duplicate-preserving join. All were detected in disposable copies; the original source was unchanged. These are three selected negative controls, not a comprehensive mutation score.

## Browser and demo

The reference demo actually produced count 3 and sum 40, rejected a forbidden column and rejected work exhaustion. See [recorded outputs](verification/public/reference-demo-results.json) and [offline report](docs/demo/reference-report.html). Chromium rendered the exact HTML bytes in memory at desktop/mobile sizes. File-URL navigation was blocked by an administrator policy and was not bypassed or claimed tested. Both PNGs were visually inspected. Internal code blocks can scroll on mobile; no page-level horizontal overflow was observed. This is not a full accessibility or cross-browser audit.

## Findings corrected during authoring

A final run exposed unclosed SQLite oracle connections: a transaction context manager does not close its connection. The harness now uses `contextlib.closing`; the recorded current reference run contains no ResourceWarnings. Earlier receipts and the initial file-navigation failure are retained in the private handoff, not rewritten into successes.

## Not established

Rust compilation, rustfmt/Clippy, SQL frontend, optimizer, general physical-plan verification, vector/hash operators, allocation accounting, cancellation integration, fuzz campaigns, comprehensive security review, Rust benchmarks, isolated-VM reproduction, independent human/agent verification and public GitHub CI remain unverified or unfinished. The initially read-only independent-verifier phase is specified but was not executed by another reviewer here.

## Reproduce

```sh
make verify-reference
make mutation-reference
make demo-reference
make benchmark-reference
# On a clean committed checkout:
make clean-verify
# Full product gate; intentionally not green yet:
make verify
```

No weakened tests, silently skipped gates or fabricated performance numbers are permitted. [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) and [CLAIMS_EVIDENCE.md](CLAIMS_EVIDENCE.md) keep delivered reference behavior distinct from the intended Rust contract.

## Clean committed checkout

[Run release-clean-clone](verification/public/release-clean-clone/receipt.json) cloned clean commit `bc25b82a86d147f572b240c37006c82c363960fb` with `git clone --no-local` into a fresh temporary directory and ran `make verify-reference`. The result was PASS for the same 32 tests, contract hashes and Python syntax/whitespace checks. No dependencies were supplied from the original working tree. It used the same operating-system image and Python installation, so this is clean-checkout reproduction, **not an independent-machine or isolated-VM proof**. Rust verification remained false.

