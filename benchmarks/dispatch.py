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
from reference_gate import retain_capture
import reference_measurement_barrier as measurement


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--profile', choices=('full', 'instrumentation-pilot', 'cancellation-only','sort-null-supplement'), required=True)
    parser.add_argument('--capture-only',action='store_true',
                        help='full collection only; artifact validation and reference qualification remain separate')
    args = parser.parse_args()
    if args.capture_only and args.profile != 'full': parser.error('--capture-only requires the complete full profile')
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
    stage = {'full': 'grid', 'sort-null-supplement': 'sort-null'}.get(args.profile)
    code = measurement.collect(stage, lambda: subprocess.call(command, cwd=ROOT)) if stage else subprocess.call(command, cwd=ROOT)
    # Export the original supplement (including a failed/partial collection)
    # before validation. Its canonical validator remains mandatory on success.
    retained = retain_capture(out, 'grid', export_stage='sort-null') if args.profile == 'sort-null-supplement' else 0
    if code: return code
    if retained: return retained
    if args.capture_only: return 0
    return subprocess.call([sys.executable, str(ROOT / 'benchmarks/verify.py'), str(out / 'grid')], cwd=ROOT)


if __name__ == '__main__': raise SystemExit(main())
