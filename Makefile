PYTHON ?= python3
CARGO ?= cargo
.PHONY: bootstrap build fmt format lint check test verify-reference demo-reference benchmark-reference mutation-reference contracts integration acceptance security security-online property fuzz mutation benchmark benchmark-local benchmark-pilot demo clean-verify verify release-verify
bootstrap:
	@command -v rustup >/dev/null || { echo 'BLOCKED: rustup unavailable; install from official Rust source in a permitted environment'; exit 77; }
	rustup toolchain install 1.99.0 --profile minimal --component rustfmt --component clippy
	$(CARGO) metadata --locked --format-version 1 --no-deps
build:
	$(PYTHON) scripts/product_build.py
fmt:
	$(CARGO) fmt --all -- --check
format:
	$(CARGO) fmt --all
lint:
	$(CARGO) clippy --all-targets --locked -- -D warnings
check:
	$(CARGO) check --all-targets --locked
	$(PYTHON) scripts/lint_reference.py
test:
	$(CARGO) test --locked
contracts:
	$(PYTHON) scripts/check_contracts.py
verify-reference: contracts
	$(PYTHON) scripts/lint_reference.py
	$(PYTHON) -m unittest discover -s tests -v
mutation-reference:
	$(PYTHON) scripts/mutation_reference.py
demo-reference:
	$(PYTHON) scripts/demo_reference.py --out .local-runs/demo-$$(date +%s)-$$$$
benchmark-reference:
	$(PYTHON) scripts/benchmark_reference.py
integration acceptance security property fuzz mutation benchmark demo:
	$(PYTHON) scripts/required_gate.py $@
integration acceptance security property fuzz demo: build
security-online:
	cargo audit
	cargo deny check
benchmark-local:
	$(PYTHON) benchmarks/dispatch.py --profile full
benchmark-pilot:
	$(PYTHON) benchmarks/dispatch.py --profile instrumentation-pilot
clean-verify:
	$(PYTHON) scripts/clean_verify.py
verify: contracts build fmt lint check test integration acceptance security security-online property fuzz mutation benchmark demo clean-verify
release-verify: verify
	$(PYTHON) scripts/release_audit.py --require-all
.PHONY: typecheck unit teardown
typecheck: check
unit: test
teardown:
	$(PYTHON) scripts/teardown.py
