#!/usr/bin/env python3
"""Explicitly fail incomplete required product gates; never silently skip them."""
import json
import os
import sys
from pathlib import Path
import subprocess
import time
name = sys.argv[1] if len(sys.argv) == 2 else 'unknown'
root = Path(__file__).resolve().parents[1]
out = root / '.local-runs' / (name + '-' + str(time.time_ns()))
commands = {
    'integration': [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests/acceptance_locked', '-v'],
    'acceptance': [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests/acceptance_locked', '-v'],
    'security': [sys.executable, 'tests/security/test_export.py', '-v'],
    'property': [sys.executable, 'tests/property/differential.py', '--out', str(out)],
    'fuzz': [sys.executable, 'tests/security/malformed.py', '--out', str(out)],
    'mutation': [sys.executable, 'scripts/mutation.py', '--out', str(out)],
    'demo': [sys.executable, 'scripts/demo.py', '--out', str(out)],
    'benchmark': [sys.executable, 'benchmarks/reference_gate.py', '--out', str(out)],
}
if name in commands:
    if name == 'benchmark' and os.environ.get('RILLSCOPE_REFERENCE_HOST_RECEIPT'):
        commands[name].extend(['--host-receipt', os.environ['RILLSCOPE_REFERENCE_HOST_RECEIPT']])
    selected = [commands[name]]
    if name == 'security':
        selected = [[sys.executable, '-m', 'unittest', 'discover', '-s', 'tests/acceptance_locked', '-v'],
                    commands[name], [sys.executable, 'scripts/license_audit.py']]
    if name == 'mutation':
        selected.append([sys.executable, 'scripts/html_mutation.py', '--out', str(out.with_name(out.name + '-html'))])
    failures = []
    for command in selected:
        print(json.dumps({'gate': name, 'command': command, 'scope': 'executed contract/security checks; full release also requires locked release evidence'}), flush=True)
        code = subprocess.call(command, cwd=root)
        if code: failures.append(code)
    raise SystemExit(failures[0] if failures else 0)
print(json.dumps({'gate': name, 'status': 'INCOMPLETE', 'reason': 'Full Rust implementation and evidence for this gate are not yet present. Implement the gate against locked acceptance criteria; do not replace with a constant success.'}))
raise SystemExit(78)
