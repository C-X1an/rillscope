#!/usr/bin/env python3
"""Actual source-bound release build, full declared run, and evidence checks."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from build import build_release


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--profile', choices=('full', 'instrumentation-pilot', 'cancellation-only','sort-null-supplement'), required=True)
    args = parser.parse_args()
    label = {'full': 'f', 'instrumentation-pilot': 'p', 'cancellation-only': 'c','sort-null-supplement':'s'}[args.profile]
    # Keep actual case/measurement paths below legacy Windows component-tool limits.
    # The complete experiment name/dimensions remain in each manifest and case record.
    out = ROOT / '.local-runs/bench' / (label + '-' + str(time.time_ns()))
    build = build_release(out / 'build')
    if args.profile == 'cancellation-only':
        code = subprocess.call([sys.executable, str(ROOT / 'benchmarks/cancellation.py'), '--binary', str(ROOT / build['bins']['rillscope']['path']),
                    '--build-receipt', str(out / 'build/build.json'), '--out', str(out / 'cancel')], cwd=ROOT)
        if code: return code
        from cancellation import verify_cancellation
        result = verify_cancellation(out / 'cancel')
        print(json.dumps(result, indent=2))
        if result['status'] != 'PASS': return 1
        return subprocess.call([sys.executable, str(ROOT / 'benchmarks/cancellation_control.py'), str(out / 'cancel'), '--out', str(out / 'cancel-control')], cwd=ROOT)
    binary = ROOT / build['bins']['rillscope-measure']['path']
    command = [sys.executable, str(ROOT / 'benchmarks/run.py'), '--binary', str(binary),
               '--build-receipt', str(out / 'build/build.json'), '--profile', args.profile, '--out', str(out / 'grid')]
    code = subprocess.call(command, cwd=ROOT)
    if code: return code
    return subprocess.call([sys.executable, str(ROOT / 'benchmarks/verify.py'), str(out / 'grid')], cwd=ROOT)


if __name__ == '__main__': raise SystemExit(main())
