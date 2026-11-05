#!/usr/bin/env python3
"""Build and verify the debug executable used by functional product campaigns."""
import json
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from build import build_product, verify_build

BINARY = ROOT / 'target/debug' / ('rillscope.exe' if os.name == 'nt' else 'rillscope')
POINTER = ROOT / 'target/debug/rillscope.build.json'


def bound_binary():
    if not POINTER.is_file(): raise ValueError('functional executable has no build receipt; run make build')
    reference = json.loads(POINTER.read_bytes())
    receipt = (ROOT / reference['receipt']).resolve()
    if not receipt.is_relative_to(ROOT / '.local-runs'): raise ValueError('build receipt escaped owned evidence')
    return verify_build(receipt, BINARY, name='rillscope', profile='dev')


def main():
    out = ROOT / '.local-runs/build' / ('dev-' + str(time.time_ns()))
    result = build_product(out, profile='dev')
    POINTER.write_text(json.dumps({'receipt': (out / 'build.json').relative_to(ROOT).as_posix()}) + '\n', encoding='utf-8')
    bound_binary()
    print(json.dumps({'status': result['status'], 'source_sha256': result['source']['sha256'],
                      'binary_sha256': result['bins']['rillscope']['sha256'], 'build_receipt': out.relative_to(ROOT).as_posix() + '/build.json'}))
    return 0


if __name__ == '__main__': raise SystemExit(main())
