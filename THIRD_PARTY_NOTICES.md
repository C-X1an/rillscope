# Third-party notices and data provenance
Original project code is MIT-licensed. No third-party source code is vendored in this seed.

The Rust seed has no external runtime crates. Planned parser/serialization/test dependencies in DEPENDENCIES.md are design selections, not a claim that Cargo resolved or installed them. Add each resolved dependency's actual license and notices when integrated.

The Python reference uses the Python standard library and the installed SQLite module. Those runtimes are not relicensed by this repository; their upstream terms apply. SQLite is an independent semantic oracle, not the product's execution engine.

GitHub CI invokes actions/checkout at an inspected immutable v7.0.1 commit. That action retains its own MIT license. CI does not copy the action into the source tree.

All catalog rows, tenant names, identifiers and query workloads in examples/tests are synthetic. There are no employer datasets, resume extracts, production usage records or real client credentials. Values named "secret" or "private-a" are deliberately synthetic authorization fixtures, not secrets from a real service.
