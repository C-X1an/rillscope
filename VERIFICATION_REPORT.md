# Verification

RillScope is experimental software. Full strict acceptance and production readiness remain unestablished.

The published evidence index records 29 PASS criteria and 1 BLOCKED criterion, AC-008. The [explicit delivery exception](TEST_SPEC_EXCEPTION_AC-008.md) leaves current visual/keyboard inspection unverified. The unchanged strict audit must continue to fail until genuine qualifying evidence exists.

| Recorded execution | Scope |
| --- | --- |
|48 Rust tests, fmt/Clippy/check| Actual native checks; Python results do not establish Rust correctness |
|814 reference/tooling tests| Executed semantic, provenance, lifecycle and verifier cases |
|31 integration, 31 acceptance, 31 security-contract cases| Actual restricted Rust CLI behavior |
|1,000 property cases| Seed 610103, JSON/SQL and optimizer on/off with SQLite outcomes |
|2,000 malformed cases| Seed 61425, 1,000 JSON plus 1,000 SQL; finite corpus |
|Selected mutation/transport controls| Preserved failing and restored outcomes; no weakened assertions |
|Complete reference campaign|47,425 observations / 19,800 semantic comparisons; [methods and distributions](BENCHMARKS.md) |
|Fresh reproduction| Original complete bootstrap/verify/demo recipe, 18 nested gates / 22 receipts; all current executable/recipe dependency hashes still match |

The [claims table](CLAIMS_EVIDENCE.md), [evidence index](verification/product/index.json) and its small set of linked summaries retain original source-file and output hashes. Each remaining summary supports a current criterion or published benchmark table. Raw command logs, redundant/superseded records, development chronology and original Git/PR/CI history are private. Historical run/commit identifiers in required evidence remain factual provenance; they do not promise public access to retired execution URLs.

The final review was conducted in the main chat as directed and shares implementation history. No fresh independent actor, production certification or complete vulnerability coverage is claimed. The historical report screenshot does not establish a current browser inspection. libFuzzer is NOT RUN.

Local Windows reference failures from deep fixture paths were resolved by the unchanged shorter-checkout 814-test run. The Windows symlink fixture could not create its setup link without privilege; the unchanged case passed actual Linux CI. Original failed outcomes are preserved privately.

Run `make verify-reference` and the checks in [CONTRIBUTING.md](CONTRIBUTING.md). `make verify` includes the full guarded reference method; `make clean-verify` runs it in a fresh committed checkout. `make release-verify` additionally requires every locked criterion. [Limits](LIMITATIONS.md) and the [threat model](THREAT_MODEL.md) apply.
