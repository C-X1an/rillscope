# Benchmarks: methodology before claims

## Observed reference harness smoke run

Status: **MEASURED, Python reference only**. Run `release-benchmark`, 2026-10-14. Source fingerprint `9233be9f70f58433f3b944b7ce72a0f959ac273ad1e3cfcb1eb1a64cc522b369`.

| Property | Recorded value |
|:--|:--|
| Input | 1,000 synthetic rows; 500 authorized output rows |
| Warm-up / measurements | 3 / 30 |
| Median | 4.552846 ms |
| Minimum / maximum | 3.634998 / 8.556830 ms |
| Environment | Python 3.13.5, Linux, shared container |

The timer includes deep copy, catalog validation, binding, row execution and output-byte-limit serialization. It excludes fixture generation and printing. All 30 samples, including the slowest, are preserved in [raw output](verification/public/release-benchmark/stdout.txt); [receipt](verification/public/release-benchmark/receipt.json) records timing, environment and hashes. This small run establishes that the harness actually runs. It does not establish Rust performance, speedup, memory containment, production throughput or any target achievement. No confidence interval or tail-latency claim is made from this smoke run.

```sh
make benchmark-reference
```

## Original Rust experiment runner

Status: **instrumentation pilot measured; full grid and reference targets pending**. The synthetic-only [Rust measurement binary](src/bin/rillscope-measure.rs) calls the original library compiler and executor. The [runner](benchmarks/run.py) predeclares 82 workload descriptions and five seeds: 410 cases, each with five warmups and 30 randomized paired repetitions of Rust optimization on/off and a separate SQLite process. Every warmup, error, timeout, work/output rejection, output digest, CPU time, RSS and logical reservation is retained. Successful results must match the independently materialized authorized SQLite relation. Failure observations remain in all-outcome distributions; execution-only success distributions are labeled separately.

An initial six-case instrument pilot retained all 630 observations but failed source stability because the minimal Windows child environment omitted `SystemDrive` and OS cache files appeared in the checkout. Those files and raw records were preserved privately. Adding only the necessary OS environment variables resolved the issue: a new 630-observation pilot passed with stable source/inputs and no invalid observations. These are instrument checks, not full-grid or reference-host performance claims. Subsequent source revisions and runs retain their own identities.

The locked PRD caps batches at 1024 and allows trusted callers only to tighten limits. The earlier supporting suggestion of 4096 is therefore exercised as an expected `E_CONTEXT` rejection control; it does not authorize relaxing the product limit. Throughput runs use 128 and 1024. This preserves the locked contract.

An independent performance source inspection subsequently found insufficient summary/build/error validation and incorrectly realized workload dimensions. Those findings have explicit failing integrator probes and fixes. Group cardinality now counts distinct authorized group values including NULL, and the 100,000-group case uses 200,000 input rows to realize that dimension. Join key coverage is guaranteed in authorized rows; the composite component independently distinguishes collisions. The equal-sort variant has equal complete keys. Actual realized shapes are retained in each case. Historical pilot PASS records remain dated instrument evidence rather than qualifying current performance claims.

Current instrumentation requires a successful actual Cargo build receipt from a new target directory, with source/lock/toolchain, observed optimization profile and executable digests. Every process attempt is journaled before the next mode starts; pairing verdicts are separate. Failed terminal objects cannot contain rows/schema, and exit codes must match the API. The checker validates case and top-level summaries against retained samples. Source-bound schema-2 pilot validation has passed; the complete grid is still NOT RUN. Failed cold builds and failed long-path attempts are retained. Compact owned artifact paths resolve the observed Windows GNU/Python path limits without changing OS policy.

```sh
make benchmark-pilot      # fixed instrument controls; explicitly not the full grid
make benchmark-local      # all 410 cases on the actual available host
python3 benchmarks/verify.py .local-runs/bench/<run>/grid
make benchmark            # dedicated reference preflight, full grid, Linux cancel campaign
```

`benchmark-local` is deliberately explicit about host scope. The current available machine is Windows with a 13th Gen Intel Core i9-13900H, 20 logical processors and approximately 32 GiB visible RAM. It is not the dedicated 4-core/8-GiB Linux reference host. `make benchmark` returns BLOCKED/77 until actual Linux runtime and documented dedicated allocation are available. Set `RILLSCOPE_REFERENCE_HOST_RECEIPT` to the operator's private allocation/inspection record on that host; hardware is checked again rather than trusted from prose. No VM purchase or billing activation is performed.

The whole-process timer includes process startup, loading, parsing/binding/verification, evaluation, serialization, instrumentation writes and shutdown. Rust's execution-only timer surrounds operator evaluation and row collection, excluding input load, compilation, output-byte dry counting and serialization. SQLite's execution-only timer covers query execution and row collection; its separate materialization timer includes physically selecting authorized rows/columns and inserting them. Windows CPU/RSS uses the owned process handle; Linux uses GNU `time`. Logical reservations are not OS RSS containment. Missing metrics are errors, never zero-filled observations.

Rust `load_ns` includes catalog/context validation and query decoding/parsing; `compile_ns` covers binding, optimization and physical verification. SQLite's `execute` timer includes SQL preparation. OS CPU clocks have coarser resolution than the monotonic wall clock, so an observed zero CPU tick is not proof of zero work. The independent evidence checker rechecks all retained outcomes and summaries; a disposable one-sample corruption control must fail and restore successfully.

The Linux [cancellation campaign](benchmarks/cancellation.py) observes a real owned CLI join checkpoint, sends SIGINT and records signal-to-terminal/exit latency for five seeds with five warmups and 30 measurements each. That interval is an upper bound on cooperative observation, and every failure is retained. A Windows hard-kill test does not substitute for it. p99 from 30 samples remains a poorly resolved descriptive order statistic. No target, production throughput or advantage over SQLite is claimed before the corresponding complete records exist.
