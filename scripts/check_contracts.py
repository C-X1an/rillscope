#!/usr/bin/env python3
"""Verify immutable acceptance document hashes against the original lock."""
import hashlib
import json
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]

def main():
    lock = json.loads((ROOT / 'verification/spec-lock.json').read_text())
    mapping = lock.get('files', lock.get('sha256', {}))
    if not mapping:
        print('FAIL: unsupported or empty lock schema', file=sys.stderr); return 1
    failures = []
    for name, expected in mapping.items():
        actual = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        if actual != expected: failures.append(name)
    print(json.dumps({'locked_files': len(mapping), 'mismatches': failures}))
    return int(bool(failures))
if __name__ == '__main__': raise SystemExit(main())
