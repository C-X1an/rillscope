# Deployment and operations

## Supported local mode
No cloud account, model key or database service. Install the pinned Rust toolchain plus Python3.11+, Git and Make, resolve approved dependencies, then run the documented bootstrap/verify/demo targets. The Python reference demo runs without Rust and is explicitly not the product demo. Never expose local context/file flags to an untrusted caller.

## Environment boundary
Trusted input files are read-only. Query is bounded stdin/file content. Outputs go under a new ignored `.local-runs/` directory; do not overwrite existing run evidence. No credentials are generated or printed. Operator changes context by starting a new invocation; a long-lived embedding host must handle immediate cancellation/revocation itself. No process-global plan/result cache.

## CI
Public standard GitHub-hosted Linux runner, read-only `contents` permission, pull_request/push triggers, no pull_request_target execution of untrusted code, no secrets, no self-hosted public PR runner. Pin action commits to an observed upstream SHA; avoid invented SHAs. Check phase/spec integrity, Python tools, Rust fmt/clippy/test, contract/property/negative-controls and smoke demo. Run heavier benchmarks/fuzz/online advisory checks on an explicitly triggered workflow after core support exists. Do not let a tools-only green job imply full product acceptance. Job names must say seed vs full verification.

## Release and publication
Only `public-repo/` is a public Git worktree. Preserve all meaningful tests and public reproducibility docs. Private resume, hiring analysis, task orchestration, machine profiles, secret-bearing logs and general user context stay in sibling `private/`. Export from an exact allowlist into a fresh directory and create a new Git history there; do not publish the full workspace or rewrite an unrelated repository. Reject symlinks and private path/content patterns. Re-run secret/privacy audit on tracked content and history. If repo name already exists, inspect owner/history before modifying and never overwrite unrelated content.

Release gate: full acceptance satisfied or release explicitly labeled experimental seed with failed/unrun criteria visible. Do not create a stable/production tag for seed code. No fake shields. Enable private vulnerability reporting and protect main using the actual required workflow names when permissions permit. Lack of administration access becomes a narrowly scoped human-action record, not a reason to stop coding.

## Hosted demo
Default: sanitized static HTML, not a live query service. GitHub Pages can host the public educational portfolio artifact within its usage limits; no passwords, commerce or user data. Publish only the already generated synthetic report and public documentation, not the workspace. An optional VM is useful for reproducible benchmarks, not always-on traffic. Public dynamic query hosting is out of scope and must not be enabled merely because a VM exists.

## Observability and health
Health is `rillscope --version` plus a known synthetic smoke query and expected result digest, not a dummy /health route. Track phase/error, safe work/reservation counts and total/compile/execute timings in trusted synthetic benchmark mode. Avoid hidden row counts/literals in client explain/logs. No OpenTelemetry service needed for one local CLI. CPU/RSS profiles are captured as artifacts for experiments, not continuously uploaded telemetry.

## Runbooks
RB-01 build failure: preserve compiler/toolchain/dependency output; inspect lockfile/platform; fix implementation or dependency incompatibility; do not edit acceptance to green.
RB-02 semantic mismatch: preserve seed/catalog/query/context/both outputs; minimize within supported semantics; identify NULL, duplicates, overflow or rewrite; add regression and rerun independent oracle.
RB-03 policy leak: stop publication/demo of affected path; retain synthetic reproducer; fix scope/provenance; rerun all position/tenant tests and chosen mutation controls.
RB-04 budget/cancel defect: record counters and timing; check every allocation/inner loop; distinguish logical budget from RSS; use OS-limited disposable process before adversarial resource experiments.
RB-05 dependency advisory: confirm package/version/features and reachable use, prefer update/removal, preserve previous lock and rerun; no blanket ignore.
RB-06 failed deployment: keep local demo working; record provider error without secrets; retry only safe idempotent operation; do not purchase service or change user billing.
RB-07 private file found in staging: reject export, remove from staged copy, rotate only actual exposed credentials via authorized process, rebuild fresh public history. Never assume deleting current file cleans history.

## Backup / recovery / rollback
Catalog is immutable input; back up operator source files and context in an appropriate private location, not public fixtures. No write-ahead log, schema migration or database backup mechanism needed. Generated reports can be regenerated; preserve benchmark inputs/receipts for reproducibility. Rollback uses previous source/tag and compatible schema version; reject unsupported versions instead of interpreting silently. Release archive manifests contain hashes of all public files.

## Retention and cost hygiene
Local test artifacts are explicit new directories, private by default. Public CI keeps only synthetic small logs with short retention (7 days for transient artifacts); selected release evidence remains versioned with source identity. Do not include a giant benchmark dataset in Git. Generate deterministically. Turn off optional VMs after the approved benchmark window and remove unattached paid resources only with appropriate authorization; the handoff does not create any paid resource.
