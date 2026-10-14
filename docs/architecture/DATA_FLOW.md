# Data flow: authority before user expressions

This companion diagram expands the combined trust/data-flow view in the locked architecture. It adds no new module or requirement. It describes the target Rust design, not delivered reference memory-accounting behavior.

```mermaid
flowchart LR
  Catalog[Trusted immutable raw catalog] --> Scan[PolicyScan: host-selected tenant]
  Context[Trusted context: tenant and visible columns] --> Scan
  Query[Untrusted query] --> Bind[Bind and authorize every reference]
  Bind --> Plan[Optimize, plan and independently verify]
  Plan --> Scan
  Scan --> Authorized[Only authorized rows and columns]
  Authorized --> Pipeline[Filter and project batches]
  Pipeline --> Breakers[Bounded join, grouping and sort]
  Breakers --> Collector[Bounded complete-result collector]
  Collector --> Result[One complete result]
  Pipeline --> Error[Typed error: no partial success]
  Breakers --> Error
  Collector --> Error
  Result --> Inspector[Escaped offline inspector]
  Error --> Inspector
```

Policy columns may be read internally by the trusted scan while remaining unavailable to user expressions. Binding checks columns in projections, predicates, join keys, aggregates and sort keys. The plan verifier is structural defense-in-depth; it is not a theorem prover. Work reservations and the final collector must reject exhaustion without publishing a partial successful result. Trusted host data, timing and aggregate-inference privacy remain outside the claimed boundary.
