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

## Unmeasured Rust experiments

Status: **NOT YET MEASURED**. The canonical evaluation plan in [EVALUATION.md](EVALUATION.md) specifies workload dimensions, five independent seeds, warm-up, repeated paired runs, randomized on/off ordering, distributions and raw-output retention. Compare optimized/unoptimized plans within RillScope on identical source and inputs. Compare common supported semantics with a separate SQLite baseline; do not compare unsupported SQL features or call a row interpreter a vector engine.

Measure batch sizes 128/1024/4096, selectivity, join skew/cardinality, grouping cardinality, bytes, work counters, allocated/reserved bytes, cancellation latency and externally measured RSS separately. Report failing runs and budget rejections. Keep design capacity, tested capacity, observed capacity and real usage distinct.

`make benchmark` deliberately returns an incomplete-gate error until the real Rust workload runner and evidence checks are implemented. A passing `benchmark-reference` must never substitute for it.
