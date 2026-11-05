# Benchmarks: recorded methods and measurements

## Complete native Linux campaign, 2026-10-29

The recorded native campaign 18 completed collection and strict validation at commit `789814fffdcf7ea8ee2223904ac6d38e90c6a647`, source fingerprint `7d459580f37a0c26ca75f59d32ce6d2335b63a0f675f3995f7a7d5ef44ec7f66`. A separate complete local replay reproduced the original validator report exactly: all 12 stages passed. The [curated observations](verification/product/runs/reference-measurements.json) retain source-file identities, original output digests, target distributions and acceptance associations. Original artifact SHA-256: `7f4e39b7a501a60d4d062e2039a5bea28dfb4d04b0696afdbb5267b1fb58d89a`.

The reference system was a newly created KVM guest assigned exclusively to this campaign: four x86_64 virtual CPUs, 8 GiB configured RAM, AMD EPYC 9V45 CPU model, Linux 6.8.0-142-generic and the pinned Rust 1.99.0 release build. The provider's physical host and hypervisor scheduling may be shared. The original controller reservation, guest allocation, native executable bytes, source inventories, command receipts and both sides of the artifact transfers were checked. Recorded conditions include 20,117 host samples and 5,005 guest samples; maximum required host and guest gaps were 0.547 and 2.010 seconds. Sampling does not prove uninterrupted residency or physical exclusivity.

The unchanged full grid retained 410 seeded cases and 43,050 observations, including all 290 required-success cases and 17,400 independent semantic comparisons. The deciding-NULL sort supplement retained 40 cases, 4,200 observations and 2,400 comparisons. The cancellation campaign retained 175 observations, including 150 measured observations. Every observation was checked; there were zero invalid observations. Expected output/work/capacity rejections remain classified outcomes, rather than omitted failures. Each grid case used five warmups and 30 measured paired repetitions of optimization on/off and an independently materialized SQLite execution; input generation stayed outside the declared timers.

For the 100,000-row warm filter/project target, every seed met execution-only p95 below one second. End-to-end CLI time is reported separately; each row has 30 measured samples and 60 independent semantic comparisons.

| Seed | Execution p50 (ms) | Execution p95 (ms) | Execution p99 (ms) | End-to-end p95 (ms) |
|:--|--:|--:|--:|--:|
| 20261014 | 16.2897340 | 16.647325 | 17.201604 | 47.261215 |
| 20261015 | 16.4936565 | 16.923833 | 18.398225 | 47.319744 |
| 20261016 | 16.3701550 | 19.087869 | 19.740187 | 48.194078 |
| 20261017 | 16.1311575 | 17.013319 | 17.691175 | 45.894020 |
| 20261018 | 16.3367945 | 17.063094 | 17.725758 | 48.151794 |

All 150 measured cancellation signal-to-exit upper bounds met the 100 ms target: p50 0.436927 ms, p95 0.500458 ms, p99 0.634710 ms and maximum 0.693420 ms. These bounds include process exit and are not direct measurements of the executor's internal cancellation-check instant. The [cancellation and resource summary](verification/product/runs/benchmark-distributions.json) retains min/max, median absolute deviation, sample counts, observer gaps and the original standalone pending-context verdict. The separate complete assessment supplies the reference context.

The same run's fresh isolated committed checkout passed `make bootstrap`, `make verify` and `make demo`, with a new enforced Cargo target directory, all 18 nested gates and 22 original command receipts. The enclosing collection took 10,342.098 seconds; original strict validation took 990.825 seconds and the separate local records replay took 987.493 seconds. This demonstrates one complete execution within the existing budgets; it does not guarantee future provider capacity or a general optimization speedup.

## Reproduce the method

The source and locked case/seed/repetition contracts remain public. `make benchmark-pilot` runs instrumentation checks; `make benchmark-sort-null` runs the deciding-NULL supplement. `make benchmark` is the guarded full method. Ordinary shared-runner execution is not dedicated-reference qualification. Follow [reference allocation](docs/reference-allocation.md) for genuine operator/allocation evidence and the documented before/after conditions. Full public workflow entrypoints remain in [.github/workflows](.github/workflows).

No case, seed, warmup, repetition or expected rejection was removed for publication cleanup. The original engine, measurement code, test assertions, CI recipes and dependency inputs are byte-identical to the recorded campaign's corresponding inputs. This document reports those historical measurements, not a new campaign or a general speedup over SQLite.

The review shares implementation history. Original pending-review flags, failed attempts and raw execution records are preserved privately; the current linked summaries provide the public scope and distribution support. Historical execution identifiers predate the clean public repository history. Current visual/keyboard inspection and libFuzzer remain NOT RUN, and full strict acceptance remains unestablished.
