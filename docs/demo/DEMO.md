# PHASE 14 - UX and demo strategy

## Local and offline paths
Core reviewer path: `make bootstrap`, `make demo`. Demo must call the actual compiled Rust CLI, not the Python reference. A separate `make demo-reference` is explicitly labeled a reference/prototype and does not establish implementation acceptance. Both use the deterministic synthetic sales/catalog fixture and no credentials. Static HTML contains no scripts, external images/fonts or network requests. Hosted option is the same sanitized static report, not an untrusted public query endpoint.

## 30 seconds
Read the thesis, run an allowed tenant-A sales query, then a query referencing a forbidden margin column. See scoped results and E_FORBIDDEN. Product status is shown without an invented green badge.

## Two minutes
Run the same query under tenant-B host context. Compare each to physically separated SQLite oracle tables. Open the plan inspector to see PolicyScan, Filter, Aggregate and the optimizer trace. Turn optimization off and confirm semantic result equality. Explain why the agent never selects the context.

## Five-minute engineering walkthrough
Run a duplicate-key join with nullable amounts. Inspect COUNT and SUM, then force a tiny work budget and observe a typed failure with no partial success. In a disposable mutation test, remove one verifier policy requirement and show the dedicated security test detects it, followed by restored PASS. Show benchmark distributions only after actual execution and separate execution from end-to-end timing. End on limitations: no full SQL, no timing secrecy, no hosted tenant service, no DB replacement claim.

## Inspection UX
Report panels: run/source identity; input query (synthetic only); trusted context label without secrets; result or error; bound schema; logical/physical plan; applied rules; authorized operator counters; independent comparison; limitations. Never expose hidden values/unfiltered counts in an untrusted explain response. A trusted local developer diagnostic mode may expose more only with an explicit separate flag and warning, and is excluded from hosted output.

## Screenshots after actual execution
Capture actual generated flows and plots only after their executions. No fabricated terminal output, mock UI screenshots, pass badges or charts with invented numbers. The2026-10-14 reference handoff retained the two Chromium captures described below. The implemented Rust report has four actual Chrome captures and a[visual/keyboard record](rust-visual-review.json), including authorized/denied tenant outcomes, a narrow layout and the expanded redacted plan. These are selected agent inspections, not a user study, complete accessibility audit or release-readiness evidence. A fresh demo capture and its current source/artifact binding remain separately checked. Accessibility checks cover semantic headings/table headers, readable labels, keyboard access and results that do not rely on color alone.

## Recorded reference display

`reference-report.html`, `desktop.png` and `mobile.png` were produced from actual Python-reference executions. Chromium 144.0.7559.96 rendered the same HTML bytes in memory at 1440 x 1000 and 390 x 844. File-URL navigation was blocked by the authoring browser's administrator policy; no policy was disabled, and file-URL loading was not verified. This is selected layout/semantic QA, not a full accessibility audit. The page makes no external requests.

Optional browser reproduction (Playwright and Chromium required):

```sh
python3 scripts/browser_reference.py --report docs/demo/reference-report.html --out .local-runs/my-browser-check
```

The browser harness uses `--no-sandbox` only for rendering this trusted local generated report inside an already isolated runner. Do not repurpose it to visit untrusted sites. The core reference tests do not require a browser dependency.
