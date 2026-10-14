#!/usr/bin/env python3
"""Explicitly fail incomplete required product gates; never silently skip them."""
import json
import sys
from pathlib import Path
import subprocess
import time
name = sys.argv[1] if len(sys.argv) == 2 else 'unknown'
root = Path(__file__).resolve().parents[1]
out = root / '.local-runs' / (name + '-' + str(time.time_ns()))
commands = {
    'integration': [sys.executable, 'tests/acceptance_locked/test_product.py', '-v'],
    'acceptance': [sys.executable, 'tests/acceptance_locked/test_product.py', '-v'],
    'security': [sys.executable, 'tests/acceptance_locked/test_product.py', '-v'],
    'property': [sys.executable, 'tests/property/differential.py', '--out', str(out)],
    'fuzz': [sys.executable, 'tests/security/malformed.py', '--out', str(out)],
    'mutation': [sys.executable, 'scripts/mutation.py', '--out', str(out)],
}
if name in commands:
    print(json.dumps({'gate': name, 'command': commands[name], 'scope': 'actual Rust CLI contract/semantic checks; release readiness also requires the separate locked release audit'}), flush=True)
    raise SystemExit(subprocess.call(commands[name], cwd=root))
print(json.dumps({'gate': name, 'status': 'INCOMPLETE', 'reason': 'Full Rust implementation and evidence for this gate are not yet present. Implement the gate against locked acceptance criteria; do not replace with a constant success.'}))
raise SystemExit(78)
