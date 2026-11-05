# Evaluation and benchmark plan

## Claims and levels
Correctness: supported queries match independent reference semantics on authorized relations. Policy: every tested path enforces row/column scope and rejects malformed plans. Execution: core operators are original Rust, not forwarding to SQLite/DuckDB. Performance: report actual distributions/ablations, not an unqualified faster-engine claim. No production users or real traffic are assumed.

Levels: unit (3VL/type/budget), contract (JSON/SQL/error), integration (real frontend through Rust operators), acceptance (locked AC IDs), system/E2E (actual CLI/report/process termination), property (generated plans/catalogs), fuzz (bounded malformed inputs), selected mutation/negative controls, security, performance and isolated clean checkout. The Python reference/prototype is labeled separately and cannot establish Rust product acceptance.

## Independent oracles
Use Python's SQLite stdlib over physically prefiltered authorized tables created by an oracle-owned materializer. The materializer selects the context rows and visible columns before issuing SQL, rather than injecting the same policy expression as production. Generate expected ordered rows only when ORDER BY makes order explicit; otherwise compare canonical typed row multisets, preserving duplicates. Constrain generated values to avoid SQLite's overflow/coercion semantics differing from the specified checked Int64 dialect; separately test overflow using locked expected errors. Explicitly encode the chosen NULL ordering for SQLite comparisons.

A second metamorphic oracle partitions predicate truth into TRUE, FALSE and NULL and requires bag union to equal the unpartitioned authorized result. Test optimizer on/off on the same inputs, but never call agreement between two paths in one engine independent correctness. SQLancer [S18] is methodological prior art; no unsupported claim of full SQLancer integration.

## Workload families and experiment definitions
|Experiment|Claim|Generator/workload|Environment/hardware|Warmup/repetitions|Concurrency|Instrument|Summary/raw path|Failure interpretation|
|---|---|---|---|---|---|---|---|---|
|B01 filter/project|Batch and pruning tradeoff|10k/100k/1m rows, selectivity 0/1/10/50/100%, NULL 0/10%|Actual Linux CPU/RAM/toolchain recorded; release build|5 warmup +30 paired mode runs|1|monotonic timers, CPU, max RSS, work counters|p50/p95/p99 descriptive; .local-runs/bench/B01/*.jsonl|Mismatch invalidates timing; noise reported|
|B02 join|Hash join behavior under duplicates/skew|1k/10k keys; uniform and heavy-key distributions; duplicates; many-to-many near cap|Same host and snapshot across modes|5+30|1|build/probe rows, reservation peak, wall/CPU|raw samples + percentiles|Budget failure is a real outcome, not dropped|
|B03 aggregate|Grouping/state growth|0/10/1000/100k groups, NULL keys, empty/all-null|Same host|5+30|1|group count, memory reservations, wall|raw samples and state curve|Integer overflow reported, not clamped|
|B04 sort/limit|Bounded ordering cost|10k/100k rows, ordered/reverse/random, equal keys|Same host|5+30|1|comparisons, RSS, time|raw samples and relative comparisons|No limit pushdown that changes semantics|
|B05 optimizer ablation|Rewrites benefit supported workloads|Same plans with optimizer off/on, fixed seed and catalog digest|Same process harness where possible; CLI end-to-end separately|5+30 paired randomized order|1|compile/execute/serialize timings separately|paired medians; bootstrap CI optional with fixed seed|Publish regressions; never cherry-pick fastest|
|B06 budget/cancel|Finite work and cancellation|Exploding join/tiny budget and deliberate cancel checkpoint|Actual Linux host recorded|5+30 cancel observations|1 then optional 4 processes|monotonic event timestamps, process exit, counters|latencies and all failures|Cooperative target not OS hard guarantee|
|B07 independent baseline|Contextual efficiency, not replacement superiority|Equivalent authorized materialized tables in SQLite; optional DuckDB|Same host/inputs; baseline versions recorded|5+30|1|own and baseline wall; both execution-only and end-to-end|all raw samples, query/result digest|Different semantics/input work invalidate comparison|

Default benchmark generation seed: 20261014. Corpus generation and loading are outside execution-only measurement but included in a separately labeled end-to-end run. Clock is monotonic. Run other heavy processes separately, record CPU governor/virtualization/available memory when readable, do not invent unavailable metadata. Record source SHA and dirty digest, compiler profile, dependency lock SHA, OS/CPU, versions, workload seed/schema/catalog/result digests, warmups and every timed run.

p99 from 30 observations is poorly resolved; label it a descriptive order statistic, not a strong tail guarantee. For meaningful tail estimates collect at least 1000 samples and explain autocorrelation. Do not average percentiles. Report dispersion and repeat unstable experiments without discarding original runs. Failure/timeout samples are retained and summarized separately; no throughput metric derived only from successful cherry-picked cases.

## Targets, capacity and claims
TARGET B01 execution-only p95 <1s on the specified reference configuration at 100k rows; TARGET cancellation observation <=100ms. Neither is measured until the corresponding environment and raw records exist. DESIGN CAPACITY: catalog/plan/budget limits in PRD. TESTED CAPACITY: largest exact documented test input. OBSERVED CAPACITY: actual completed workload under the measured conditions. REAL USER/PRODUCTION SCALE: none claimed.

## Test-the-tests
For AC-010/011/012/015/029 run PASS -> isolated intentional defect -> expected FAIL -> restore -> PASS. Capture commands, patch hashes, restored source identity and failure messages. A failing test for an unrelated syntax error is not a successful negative control. Fuzzing must preserve seeds/corpus and report actual duration/iterations; do not label a deterministic small corpus fuzzed for hours.

## Completion review
Independent verifier receives requirements, source, actual commands and evidence, initially read-only. It asks what could pass while broken, checks independent materialization, generated NULL/duplicate coverage, budgets on inner loops and data leakage in explain. The integrator fixes findings only after the report. Clean environment verification must use a fresh source checkout; passing in the original workspace is insufficient.

Machine-captured receipts and hashes make results auditable but cannot prevent an equally privileged actor from rewriting both output and hash. A separate clean rerun/CI source binding is the stronger trust anchor. Never claim fabricated results are cryptographically impossible under a fully autonomous writer.
