# Architecture decisions

The [locked architecture](ARCHITECTURE.md) controls the design.

- Build an original small Rust engine; SQLite remains an independently materialized semantic oracle.
- Keep authority in trusted immutable catalog/context objects and mandatory PolicyScans. Queries cannot choose the tenant or hidden columns.
- Verify the bound physical plan before execution; only an opaque capability reaches the executor.
- Preserve nullable types and duplicate rows. Bound optimizer growth, work, logical reservations and output before publishing a complete result.
- Deliver a local CLI/library and offline report. External authentication, distributed services, spill, arbitrary SQL effects and OS isolation remain outside scope.

Revisit scope only with explicit contracts, independent expected outcomes and measured evidence. [Limitations](LIMITATIONS.md) describe the current tradeoffs.
