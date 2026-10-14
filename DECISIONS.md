# Architecture decision index

The [eight architecture decision records](docs/adr/README.md) explain the chosen scope, original engine, independent oracle, policy boundary, resource model, local deployment, public evidence and implementation approach. Each records context, alternatives, consequences, risks and revisit conditions.

The [locked architecture](ARCHITECTURE.md) is authoritative for the current design. Its [data-flow companion](docs/architecture/DATA_FLOW.md) expands the movement of raw data, authorized batches and complete results without changing the contract. Supporting diagrams must not silently introduce a network service, new authority source or weaker policy boundary.
