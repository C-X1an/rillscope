#!/usr/bin/env python3
"""Small reference harness smoke measurements, NOT Rust performance targets."""
from pathlib import Path
import json
import platform
import statistics
import sys
import time
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from tools.reference.engine import evaluate
from tests.test_reference import fixture, scan, project, query
rows = [['alpha' if i % 2 == 0 else 'beta', i, i % 7, 'synthetic'] for i in range(1000)]
cat, ctx = fixture(rows); q = query(project(scan(), 'id', 'amount'))
for _ in range(3): evaluate(cat, ctx, q)
samples = []
for _ in range(30):
    start = time.perf_counter_ns(); result = evaluate(cat, ctx, q); samples.append(time.perf_counter_ns() - start)
    assert result['status'] == 'ok' and len(result['rows']) == 500
print(json.dumps({'implementation': 'python-reference', 'workload': '1000 input rows; 500 authorized output rows',
                  'timer_includes': 'deep copy, catalog validation, bind, row execution, byte-limit serialization',
                  'timer_excludes': 'fixture generation, output print', 'warmups': 3, 'repetitions': 30,
                  'samples_nanoseconds': samples, 'median_nanoseconds': statistics.median(samples),
                  'min_nanoseconds': min(samples), 'max_nanoseconds': max(samples),
                  'python': platform.python_version(), 'system': platform.system(),
                  'caveat': 'Shared container; only harness smoke evidence. No Rust p95, speedup, memory, production scale or target achievement claim.'}, indent=2))
