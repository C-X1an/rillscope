#!/usr/bin/env python3
"""Verify reference from a clean committed clone; full Rust release remains separate."""
from pathlib import Path
import json
import subprocess
import sys
import tempfile
ROOT = Path(__file__).resolve().parents[1]
p = subprocess.run(['git', 'status', '--porcelain'], cwd=ROOT, capture_output=True, text=True)
if p.returncode or p.stdout.strip():
    print('FAIL: commit all public source changes before clean verification', file=sys.stderr); raise SystemExit(1)
with tempfile.TemporaryDirectory(prefix='rillscope-clean-') as folder:
    clone = Path(folder) / 'repo'
    subprocess.run(['git', 'clone', '--no-local', str(ROOT), str(clone)], check=True, capture_output=True)
    p = subprocess.run(['make', 'verify-reference'], cwd=clone, capture_output=True, text=True)
    print(p.stdout); print(p.stderr, file=sys.stderr)
    print(json.dumps({'mode': 'clean-clone-reference', 'status': 'PASS' if p.returncode == 0 else 'FAIL',
                      'rust_release_verified': False}))
    raise SystemExit(p.returncode)
