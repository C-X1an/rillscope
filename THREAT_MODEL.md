# RillScope threat model

Method: STRIDE plus misuse cases, with explicit data/control trust boundaries. This is a design review, not certification or proof that the implementation is secure.

Assets: scoped row/column data, immutable policy/catalog identity, result correctness, host resources, public repository privacy, build integrity and evidence credibility. Actors: trusted operator/embedding host; untrusted query client/agent; malicious dataset producer only if operator mistakenly trusts an input; dependency/CI attacker; maintainer or agent able to edit local artifacts. Zones: query syntax; trusted configuration/catalog; compiler/verifier/executor process; local output; public export/CI.

Privileges: the CLI runs with its OS user's privileges. It does not isolate one OS user from itself. Public hosted deployment, arbitrary user uploads, identity provisioning, native guest code, and tenant-owned processes are not core supported environments. Never expose `--context` or file paths as untrusted tool arguments. No bearer tokens, PKI or cryptography are implemented because there is no core remote endpoint.

|ID|Precondition|Threat|Impact|Likelihood|Mitigation|Residual risk|Test/evidence|
|---|---|---|---|---|---|---|---|
|TH-001|Client can submit arbitrary query|Spoof tenant/context|Cross-tenant read|high|No tenant/context field in query; fixed host context; private VerifiedPlan identities|Malicious trusted host is out of scope|AC-001 AC-010 AC-017|
|TH-002|Optimizer rewrites a valid plan|Remove/bypass policy leaf|Unauthorized rows influence results|high|PolicyScan only executable source; independent leaf/provenance verifier|Compiler and verifier may share mistaken assumptions|AC-006 AC-012; barrier-removal mutant|
|TH-003|Hidden column exists|Reference secret only in filter/join/sort|Inference or direct disclosure|high|Bind all expression positions against allowlist|Authorized aggregates can still reveal information legitimately in scope|AC-011; omitted-filter-check mutant|
|TH-004|Nullable/duplicate inputs|Wrong comparison/join/group rewrite|Incorrect results mistaken for access compliance|high|3VL and bag contract; independent SQLite and partition oracles|Finite test coverage only|AC-004 AC-005 AC-006|
|TH-005|Large/deep malicious query|Stack/memory/CPU exhaustion|Crash or denial of service|high|Bytes/depth/node limits before recursive compilation; bounded work/results and logical reservations|OS allocation, parser implementation, runtime overhead not perfectly bounded|AC-015 AC-018; process resource measurements|
|TH-006|SQL contains effectful functions or multiple statements|Filesystem/network/command effect|Exfiltration or code execution|high|Closed language, reject unknown operators/functions/statements; no raw SQL sent to runtime DB|Operator CLI file access remains trusted|AC-013; canary file/socket observation|
|TH-007|Errors/explain include diagnostic data|Hidden-value leakage|Confidentiality loss|medium|Closed value-free errors; redact query/value and hidden stats|Timing, exit behavior and authorized counts remain side channels|AC-007 AC-014|
|TH-008|Forged serialized physical plan or reused handle|Confused deputy / stale context|Execute under wrong snapshot/scope|medium|No physical Deserialize; private constructor; match revision/snapshot identity|Trusted caller with internal code authority can violate assumptions|AC-012 AC-017|
|TH-009|Skewed many-to-many join|Explosive intermediate/results|Resource exhaustion|high|Charge before insertion/emission and in inner loops; bounded output collector|Logical budget is not RSS; hard limits need OS profile|AC-015 AC-018; budget mutant|
|TH-010|Malicious report labels|HTML injection / external fetch|Browser compromise or data leak|medium|HTML escaping, no scripts, no external resources, text-only labels|User must not replace report with arbitrary HTML|AC-029; script canary|
|TH-011|Dependency/build/PR is malicious|Supply-chain or CI credential theft|Compromise maintainer/release|medium|Pinned lockfiles/action SHAs; read-only PR tokens; no secrets or self-hosted runners for untrusted PRs; license/advisory scans|Registry/toolchain compromise remains|NFR-001 SEC-007; CI/release review|
|TH-012|Agent can edit evidence and source|Fabricate or tamper results|Misleading portfolio claims|high|Machine receipts, hashes, independent clean rerun, verifier findings before fixes, CI source binding|Same-privilege actor can rewrite local hashes; external trust needed for stronger provenance|AC-026 AC-027; runner/lock negative controls|
|TH-013|Public export includes internal files|Private resume/secret/employer leak|Privacy/reputation harm|high|Separate directories, exact allowlist, symlink rejection, content scan, clean publication history|Pattern scanning can miss novel secrets; manual review remains required|AC-016; export mutation suite|
|TH-014|LLM prompt injection in query/data|Client asks to bypass policy|Tool misuse|high|Query has no authority and no effectful tools; context fixed by trusted host|Does not detect malicious intent or sanitize other agent tools|AC-010 AC-011 AC-013|
|TH-015|Cancellation races with publication|Return partial success after cancel/fail|Reliability/data-integrity issue|medium|One terminal envelope; check cancellation before publication; no streaming partial-success protocol|Hard kill can yield no envelope|AC-018 AC-020|

## What isolation means here
For a fixed trusted context and supported pure query, results must equal evaluation over the operator's authorized rows and permitted columns. This is result-value access control, not differential privacy, noninterference of timings, resistance to statistical inference, or a host sandbox. Counts/aggregates of authorized data are intentionally observable. Query planning and errors should avoid hidden values, but not every side channel is eliminated. Do not describe the project merely as secure, zero-trust or production-grade.

## Negative controls
In disposable workspaces remove one policy check, omit authorization of WHERE, permit a forged physical scan, bypass an inner-loop budget charge, and fail to escape report labels. The corresponding selected tests must first pass, then fail for the expected reason on the mutant, then pass after restoration. Never ship the mutant. Mutations demonstrate those tests can detect those defects, not a broad mutation-coverage percentage.

## Review and reporting
Independent verifier begins read-only and produces findings before the integrator edits implementation. Material findings require a regression test and rerun. Unknown vulnerabilities are not invented; report observed issues with a minimized synthetic reproducer. No confidential data or live credentials belong in reports.
