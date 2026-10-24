# Reference allocation preflight

AC-022 and AC-023 require an actual documented dedicated Linux reference host.
A four-CPU8GiB virtual guest is compatible with that resource description.
Hardware inspection alone cannot establish dedication. The actual allocation
operator must retain a truthful positive allocation document and its original
supporting evidence before any measured campaign. No past run can acquire a
missing preflight retroactively.

`benchmarks/reference_allocation.py` binds that private document and evidence to
the actual clean committed source, Linux boot, CPU identity, measured effective
CPU/affinity and memory limits. It repeats the checks before writing a new
private receipt. Input replacement, duplicate JSON keys, changed source/boot,
future inspection clocks and expired allocation leases fail explicitly. The
operator JSON is bounded to64KiB and eight nesting levels. Original supporting
evidence must be nonempty and is bounded to2MiB; its exact digest is retained.

The closed operator document has these fields:

| Field | Required actual value |
| --- | --- |
| `schema_version` | integer1 |
| `source` | `actual host allocation and inspection` |
| `dedicated` | boolean true, asserted by the actual allocation operator |
| `operator` | documented operator identity, at most256 UTF-8 bytes |
| `allocation_id` |32 lowercase hexadecimal digits identifying the allocation |
| `evidence_sha256` | SHA256 of the retained original supporting evidence |
| `commit`, `source_sha256` | exact current clean committed source identity |
| `boot_id` | actual Linux boot UUID |
| `inspected_monotonic_ns`, `expires_monotonic_ns` | actual inspection and lease-end clocks in this boot |
| `system`, `machine`, `logical_processors`, `cpu_model` | actual Linux/x86_64/four-CPU configuration and CPU identity |
| `configured_memory_bytes` |8589934592; actual visible memory and limits are checked separately |

Keep operator identity, allocation documents, original evidence and generated
receipts outside public Git. The helper accepts receipts inside `.local-runs/`
or an operator-controlled private directory. It never invents an allocation,
books resources, changes accounts or starts billing.

On the genuinely allocated Linux host, before collection:

```sh
python3 benchmarks/reference_allocation.py \
  --allocation /private/actual-allocation.json \
  --evidence /private/original-allocation-evidence.txt \
  --out .local-runs/reference-allocation/receipt.json
RILLSCOPE_REFERENCE_HOST_RECEIPT="$PWD/.local-runs/reference-allocation/receipt.json" make benchmark
```

The receipt is an input to the existing reference gate. `RECORDED` is a
preflight outcome; its `reference_qualified` field remains false. Complete
source-bound grid/cancellation observations, stable experiment environments,
all-record validation and target reporting remain mandatory. The separate
AC-024 recipe remains a fresh committed `make bootstrap`, `make verify`,
`make demo`; a preflight or a source checkout is not that execution. Run the
canonical fresh recipe on the actually allocated host with the private receipt
available through the same environment variable, and preserve every failure.

The gate checks a structured receipt again before building and at experiment
completion. A changed source, another boot, changed effective resources or an
expired lease blocks qualification. Original operator receipts retain their
existing hardware/allocation checks. A structured receipt with malformed or
missing binding fields cannot use that legacy path.

Synthetic unit documents test rejection and binding logic only. They are not
allocation evidence and must never be used for an actual benchmark claim.
